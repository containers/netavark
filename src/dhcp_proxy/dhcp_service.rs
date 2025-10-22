use std::{net::Ipv4Addr, sync::Arc};

use log::debug;
use mozim::{DhcpV4Client, DhcpV4Config, DhcpV4Lease as MozimV4Lease, DhcpV4State};
use tokio::sync::Mutex;
use tonic::{Code, Status};

use crate::{
    dhcp_proxy::{
        dhcp_service::DhcpServiceErrorKind::{Bug, InvalidArgument, NoLease, Timeout},
        lib::g_rpc::{Lease as NetavarkLease, NetworkConfig},
    },
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::{core_utils, netlink::Route},
    wrap,
};

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

/// DHCP service is responsible for creating, handling, and managing the dhcp
/// lease process.
#[derive(Debug)]
pub struct DhcpV4Service {
    client: DhcpV4Client,
    network_config: NetworkConfig,
    previous_lease: Option<MozimV4Lease>,
}

impl DhcpV4Service {
    pub async fn new(nc: NetworkConfig, timeout: u32) -> Result<Self, DhcpServiceError> {
        let mut config = DhcpV4Config::new_proxy(&nc.host_iface, &nc.container_mac_addr)
            .map_err(|e| DhcpServiceError::new(InvalidArgument, e.to_string()))?;
        config.set_timeout_sec(timeout);

        // Sending the hostname to the DHCP server is optional but it can be
        // useful in environments where DDNS is used to create or update
        // DNS records.
        if !nc.host_name.is_empty() {
            config.set_host_name(&nc.host_name);
        };

        // DHCP servers use the "client id", which is usually the MAC address,
        // to keep track of leases but each time the container starts, it gets
        // a new, random, MAC address so there's a good chance that the
        // container won't get the same IP address if it restarts. This
        // can be an issue if a container provides a service and needs
        // to be restarted because, even if DDNS is in use and the
        // container has a DNS A record, a client may still have the old
        // IP address cached until the DNS TTL expires.
        //
        // Since the container id remains constant for life of the container
        // and it should be globally unique, we can use it as the client id to
        // ensure the container gets the same IP address each time it starts.

        // The client id is a byte array so we need to convert the container id
        // to a byte array.  The client_id_type of "0" means the client id
        // is not a hardware address.
        config.set_client_id(0, nc.container_id.as_bytes());

        let client = match DhcpV4Client::init(config, None).await {
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
    /// * `client`: a IPv4 mozim dhcp client. When this method is called, it
    ///   takes ownership of client.
    ///
    /// returns: Result<Lease, DhcpSearchError>. Either finds a lease
    /// successfully, finds no lease, or fails
    pub async fn get_lease(&mut self) -> Result<NetavarkLease, DhcpServiceError> {
        loop {
            let state = self.client.run().await;
            match state {
                Ok(DhcpV4State::Done(lease)) => {
                    let mut netavark_lease =
                        <NetavarkLease as From<MozimV4Lease>>::from((*lease).clone());
                    netavark_lease.add_domain_name(&self.network_config.domain_name);
                    netavark_lease.add_mac_address(&self.network_config.container_mac_addr);
                    debug!(
                        "found a lease for {:?}, {:?}",
                        &self.network_config.container_mac_addr, &netavark_lease
                    );
                    self.previous_lease = Some(*lease);
                    return Ok(netavark_lease);
                }
                Ok(state) => {
                    log::debug!(
                        "DHCPv4 proxy on {} for {} enter {state} state",
                        self.network_config.host_iface,
                        self.network_config.container_mac_addr
                    );
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
                    });
                }
            }
        }
    }

    /// Sends a DHCPRELEASE message for the given lease.
    /// This is a "best effort" operation and should not block teardown.
    pub async fn release_lease(&mut self) -> Result<(), DhcpServiceError> {
        if let Some(lease) = &self.previous_lease {
            debug!(
                "Attempting to release lease for MAC: {}",
                &self.network_config.container_mac_addr
            );
            // Directly call the release function on the underlying mozim
            // client.
            self.client
                .release(lease)
                .await
                .map_err(|e| DhcpServiceError::new(Bug, e.to_string()))
        } else {
            // No previous lease recorded; nothing to release. Best-effort ->
            // succeed silently.
            debug!(
                "No previous lease to release for MAC: {}",
                &self.network_config.container_mac_addr
            );
            Ok(())
        }
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

pub async fn process_client_stream(service_arc: Arc<Mutex<DhcpV4Service>>) {
    let mut client = service_arc.lock().await;
    loop {
        let lease_result = client.client.run().await;
        match lease_result {
            Ok(DhcpV4State::Done(lease)) => {
                log::info!(
                    "got new lease for mac {}: {:?}",
                    &client.network_config.container_mac_addr,
                    &lease
                );

                if let Some(old_lease) = &client.previous_lease {
                    if old_lease.yiaddr != lease.yiaddr
                        || old_lease.subnet_mask != lease.subnet_mask
                        || old_lease.gateways != lease.gateways
                    {
                        log::info!(
                            "ip or gateway for mac {} changed, update address",
                            &client.network_config.container_mac_addr
                        );
                        if let Err(err) = update_lease_ip(
                            &client.network_config.ns_path,
                            &client.network_config.container_iface,
                            old_lease,
                            &lease,
                        ) {
                            log::error!("{err}");
                        }
                    }
                }
                client.previous_lease = Some(*lease);
            }
            Ok(state) => {
                log::debug!(
                    "DHCPv4 proxy on {} for {} enter {state} state",
                    client.network_config.host_iface,
                    client.network_config.container_mac_addr
                );
            }
            Err(err) => {
                log::error!(
                    "Failed to acquire DHCPv4 lease for {}: {err}",
                    &client.network_config.container_mac_addr
                );
                log::info!(
                    "Retrying DHCPv4 proxy for {}",
                    &client.network_config.container_mac_addr
                );
                client.client.clean_up();
            }
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
