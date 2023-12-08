use std::net::Ipv4Addr;

use crate::dhcp_proxy::dhcp_service::DhcpServiceErrorKind::{
    Bug, InvalidArgument, NoLease, Timeout,
};

use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, NetworkConfig};
use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::core_utils;
use crate::network::netlink::Route;
use crate::wrap;
use log::debug;
use mozim::{DhcpV4ClientAsync, DhcpV4Config, DhcpV4Lease as MozimV4Lease};
use tokio_stream::StreamExt;

use tonic::{Code, Status};

/// The kind of DhcpServiceError that can be caused when finding a dhcp lease
pub enum DhcpServiceErrorKind {
    Timeout,
    InvalidArgument,
    InvalidDhcpServerReply,
    NoLease,
    Bug,
    LeaseExpired,
    Unimplemented,
}

/// A DhcpServiceError is an error caused in the process of finding a dhcp lease
pub struct DhcpServiceError {
    kind: DhcpServiceErrorKind,
    msg: String,
}

impl DhcpServiceError {
    pub fn new(kind: DhcpServiceErrorKind, msg: String) -> Self {
        DhcpServiceError { kind, msg }
    }
}

/// DHCP service is responsible for creating, handling, and managing the dhcp lease process.
pub struct DhcpV4Service {
    client: DhcpV4ClientAsync,
    network_config: NetworkConfig,
    previous_lease: Option<MozimV4Lease>,
}

impl DhcpV4Service {
    pub fn new(nc: NetworkConfig, timeout: u32) -> Result<Self, DhcpServiceError> {
        let mut config = DhcpV4Config::new_proxy(&nc.host_iface, &nc.container_mac_addr);
        config.set_timeout(timeout);
        let client = match DhcpV4ClientAsync::init(config, None) {
            Ok(client) => Ok(client),
            Err(err) => Err(DhcpServiceError::new(InvalidArgument, err.to_string())),
        }?;
        Ok(Self {
            client,
            network_config: nc,
            previous_lease: None,
        })
    }

    /// Performs a DHCP DORA on a ipv4 network configuration.
    /// # Arguments
    ///
    /// * `client`: a IPv4 mozim dhcp client. When this method is called, it takes ownership of client.
    ///
    /// returns: Result<Lease, DhcpSearchError>. Either finds a lease successfully, finds no lease, or fails
    ///
    pub async fn get_lease(&mut self) -> Result<NetavarkLease, DhcpServiceError> {
        if let Some(lease_result) = self.client.next().await {
            match lease_result {
                Ok(lease) => {
                    let mut netavark_lease =
                        <NetavarkLease as From<MozimV4Lease>>::from(lease.clone());
                    netavark_lease.add_domain_name(&self.network_config.domain_name);
                    netavark_lease.add_mac_address(&self.network_config.container_mac_addr);
                    debug!(
                        "found a lease for {:?}, {:?}",
                        &self.network_config.container_mac_addr, &netavark_lease
                    );
                    self.previous_lease = Some(lease);
                    return Ok(netavark_lease);
                }
                Err(err) => {
                    return Err(match err.kind() {
                        mozim::ErrorKind::Timeout => {
                            DhcpServiceError::new(Timeout, err.to_string())
                        }
                        mozim::ErrorKind::InvalidArgument => {
                            DhcpServiceError::new(InvalidArgument, err.to_string())
                        }
                        mozim::ErrorKind::NoLease => {
                            DhcpServiceError::new(NoLease, err.to_string())
                        }
                        mozim::ErrorKind::Bug => DhcpServiceError::new(Bug, err.to_string()),
                        _ => DhcpServiceError::new(Bug, err.to_string()),
                    })
                }
            }
        }

        Err(DhcpServiceError::new(
            Timeout,
            "Could not find a lease within the timeout limit".to_string(),
        ))
    }
}

impl std::fmt::Display for DhcpServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<DhcpServiceError> for Status {
    fn from(err: DhcpServiceError) -> Self {
        match err.kind {
            Timeout => Status::new(Code::Aborted, err.msg),
            InvalidArgument => Status::new(Code::InvalidArgument, err.msg),
            NoLease => Status::new(Code::NotFound, err.msg),
            Bug => Status::new(Code::Internal, err.msg),
            _ => Status::new(Code::Internal, err.msg),
        }
    }
}

pub async fn process_client_stream(mut client: DhcpV4Service) {
    while let Some(lease) = client.client.next().await {
        match lease {
            Ok(lease) => {
                log::info!(
                    "got new lease for mac {}: {:?}",
                    &client.network_config.container_mac_addr,
                    &lease
                );
                // get previous lease and check if ip addr changed, if not we do not have to do anything
                if let Some(old_lease) = &client.previous_lease {
                    if old_lease.yiaddr != lease.yiaddr
                        || old_lease.subnet_mask != lease.subnet_mask
                        || old_lease.gateways != lease.gateways
                    {
                        // ips do not match, remove old ones and assign new ones.
                        log::info!(
                            "ip or gateway for mac {} changed, update address",
                            &client.network_config.container_mac_addr
                        );
                        match update_lease_ip(
                            &client.network_config.ns_path,
                            &client.network_config.container_iface,
                            old_lease,
                            &lease,
                        ) {
                            Ok(_) => {}
                            Err(err) => {
                                log::error!("{err}");
                                continue;
                            }
                        }
                    }
                }
                client.previous_lease = Some(lease)
            }
            Err(err) => log::error!(
                "Failed to renew lease for {}: {err}",
                &client.network_config.container_mac_addr
            ),
        }
    }
}

fn update_lease_ip(
    netns: &str,
    interface: &str,
    old_lease: &MozimV4Lease,
    new_lease: &MozimV4Lease,
) -> NetavarkResult<()> {
    let (_, netns) =
        core_utils::open_netlink_sockets(netns).wrap("failed to open netlink socket in netns")?;
    let mut sock = netns.netlink;
    let old_net = wrap!(
        ipnet::Ipv4Net::with_netmask(old_lease.yiaddr, old_lease.subnet_mask),
        "create ipnet from old lease"
    )?;
    let new_net = wrap!(
        ipnet::Ipv4Net::with_netmask(new_lease.yiaddr, new_lease.subnet_mask),
        "create ipnet from new lease"
    )?;

    if new_net != old_net {
        let link = sock
            .get_link(crate::network::netlink::LinkID::Name(interface.to_string()))
            .wrap("get interface in netns")?;
        sock.add_addr(link.header.index, &ipnet::IpNet::V4(new_net))
            .wrap("add new addr")?;
        sock.del_addr(link.header.index, &ipnet::IpNet::V4(old_net))
            .wrap("remove old addrs")?;
    }
    if new_lease.gateways != old_lease.gateways {
        if let Some(gws) = &old_lease.gateways {
            let old_gw = gws.first();
            if let Some(gw) = old_gw {
                let route = Route::Ipv4 {
                    dest: ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                    gw: *gw,
                    metric: None,
                };
                match sock.del_route(&route) {
                    Ok(_) => {}
                    Err(err) => match err.unwrap() {
                        // special case do not error if route does not exists
                        NetavarkError::Netlink(e) if -e.raw_code() == libc::ESRCH => {}
                        _ => return Err(err).wrap("delete old default route"),
                    },
                };
            }
        }
        if let Some(gws) = &new_lease.gateways {
            let new_gw = gws.first();
            if let Some(gw) = new_gw {
                let route = Route::Ipv4 {
                    dest: ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                    gw: *gw,
                    metric: None,
                };
                sock.add_route(&route)?;
            }
        }
    }

    Ok(())
}
