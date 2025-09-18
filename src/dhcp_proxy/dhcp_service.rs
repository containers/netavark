use std::net::Ipv4Addr;

use crate::dhcp_proxy::dhcp_service::DhcpServiceErrorKind::{
    Bug, InvalidArgument, NoLease, Timeout,
};

use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, NetworkConfig};
use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::core_utils;
use crate::network::netlink::Route;
use log::debug;
use mozim::{
    DhcpV4ClientAsync, DhcpV4Config, DhcpV4Lease as MozimV4Lease, DhcpV6ClientAsync, DhcpV6Config,
    DhcpV6IaType, DhcpV6Lease as MozimV6Lease,
};
use std::sync::Arc;
use tokio::sync::Mutex;
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
#[derive(Debug)]
pub enum DhcpService {
    V4(DhcpV4Service),
    V6(DhcpV6Service),
}
// Add helper methods to the enum for cleaner access
impl DhcpService {
    fn get_net_config(&self) -> &NetworkConfig {
        match self {
            DhcpService::V4(c) => &c.network_config,
            DhcpService::V6(c) => &c.network_config,
        }
    }

    fn get_previous_lease(&self) -> Option<MozimLease> {
        match self {
            // Get the v4 lease, clone it, and wrap it in the V4 enum variant.
            DhcpService::V4(c) => c
                .previous_lease
                .as_ref()
                .map(|lease| MozimLease::V4(lease.clone())),
            // Get the v6 lease, clone it, and wrap it in the V6 enum variant.
            DhcpService::V6(c) => c
                .previous_lease
                .as_ref()
                .map(|lease| MozimLease::V6(lease.clone())),
        }
    }

    fn set_previous_lease(&mut self, lease: MozimLease) {
        match self {
            DhcpService::V4(c) => {
                // We only store the lease if it's the correct V4 variant.
                if let MozimLease::V4(v4_lease) = lease {
                    c.previous_lease = Some(v4_lease);
                } else {
                    log::error!("Attempted to set a non-V4 lease on a V4 service");
                }
            }
            DhcpService::V6(c) => {
                // We only store the lease if it's the correct V6 variant.
                if let MozimLease::V6(v6_lease) = lease {
                    c.previous_lease = Some(v6_lease);
                } else {
                    log::error!("Attempted to set a non-V6 lease on a V6 service");
                }
            }
        }
    }
    pub fn release_lease(&mut self) -> Result<(), DhcpServiceError> {
        match self {
            DhcpService::V4(c) => c.release_lease(),
            DhcpService::V6(c) => c.release_lease(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MozimLease {
    V4(MozimV4Lease),
    V6(MozimV6Lease),
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
#[derive(Debug)]
pub struct DhcpV4Service {
    client: DhcpV4ClientAsync,
    network_config: NetworkConfig,
    previous_lease: Option<MozimV4Lease>,
}

impl DhcpV4Service {
    pub fn new(nc: NetworkConfig, timeout: u32) -> Result<Self, DhcpServiceError> {
        let mut config = DhcpV4Config::new_proxy(&nc.host_iface, &nc.container_mac_addr);
        config.set_timeout(timeout);

        // Sending the hostname to the DHCP server is optional but it can be useful
        // in environments where DDNS is used to create or update DNS records.
        if !nc.host_name.is_empty() {
            config.set_host_name(&nc.host_name);
        };

        // DHCP servers use the "client id", which is usually the MAC address,
        // to keep track of leases but each time the container starts, it gets
        // a new, random, MAC address so there's a good chance that the container
        // won't get the same IP address if it restarts. This can be an issue if
        // a container provides a service and needs to be restarted because, even
        // if DDNS is in use and the container has a DNS A record, a client may
        // still have the old IP address cached until the DNS TTL expires.
        //
        // Since the container id remains constant for life of the container
        // and it should be globally unique, we can use it as the client id to
        // ensure the container gets the same IP address each time it starts.

        // The client id is a byte array so we need to convert the container id
        // to a byte array.  The client_id_type of "0" means the client id
        // is not a hardware address.
        config.set_client_id(0, nc.container_id.as_bytes());

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

    /// Sends a DHCPRELEASE message for the given lease.
    /// This is a "best effort" operation and should not block teardown.
    pub fn release_lease(&mut self) -> Result<(), DhcpServiceError> {
        if let Some(lease) = &self.previous_lease {
            debug!(
                "Attempting to release lease for MAC: {}",
                &self.network_config.container_mac_addr
            );
            // Directly call the release function on the underlying mozim client.
            self.client
                .release(lease)
                .map_err(|e| DhcpServiceError::new(Bug, e.to_string()))
        } else {
            // No previous lease recorded; nothing to release. Best-effort -> succeed silently.
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

pub async fn process_client_stream(service_arc: Arc<Mutex<DhcpService>>) {
    let mut client = service_arc.lock().await;
    while let Some(lease_result) = match &mut *client {
        DhcpService::V4(c) => c.client.next().await.map(|r| r.map(MozimLease::V4)),
        DhcpService::V6(c) => c.client.next().await.map(|r| r.map(MozimLease::V6)),
    } {
        match lease_result {
            Ok(lease) => {
                let net_config = client.get_net_config();
                log::info!(
                    "Got new lease for mac {}: {:?}",
                    &net_config.container_mac_addr,
                    &lease
                );
                // get previous lease and check if ip addr changed, if not we do not have to do anything
                if let Some(old_lease) = client.get_previous_lease() {
                    if lease_has_changed(&old_lease, &lease) {
                        log::info!(
                            "ip or gateway for mac {} changed, updating address",
                            &net_config.container_mac_addr
                        );
                        if let Err(e) = update_lease_ip(
                            &net_config.ns_path,
                            &net_config.container_iface,
                            &old_lease,
                            &lease,
                        ) {
                            log::error!("Failed to update lease IP: {e}");
                            continue;
                        }
                    }
                }
                // Use the helper that unwraps and sets the specific lease
                client.set_previous_lease(lease);
            }
            Err(err) => {
                log::error!(
                    "Failed to renew lease for {}: {}",
                    &client.get_net_config().container_mac_addr,
                    err
                );
            }
        }
    }
}

/// Helper to compare the unified `MozimLease` enum.
fn lease_has_changed(old: &MozimLease, new: &MozimLease) -> bool {
    match (old, new) {
        (MozimLease::V4(old_v4), MozimLease::V4(new_v4)) => {
            old_v4.yiaddr != new_v4.yiaddr
                || old_v4.subnet_mask != new_v4.subnet_mask
                || old_v4.gateways != new_v4.gateways
        }
        (MozimLease::V6(old_v6), MozimLease::V6(new_v6)) => {
            old_v6.addr != new_v6.addr || old_v6.prefix_len != new_v6.prefix_len
        }
        _ => true, // could have used unreachable!()
    }
}

fn update_lease_ip(
    netns: &str,
    interface: &str,
    old_lease: &MozimLease,
    new_lease: &MozimLease,
) -> NetavarkResult<()> {
    let (_, netns) =
        core_utils::open_netlink_sockets(netns).wrap("failed to open netlink socket in netns")?;
    let mut sock = netns.netlink;
    match (old_lease, new_lease) {
        (MozimLease::V4(old_v4), MozimLease::V4(new_v4)) => {
            let old_net = ipnet::Ipv4Net::with_netmask(old_v4.yiaddr, old_v4.subnet_mask)?;
            let new_net = ipnet::Ipv4Net::with_netmask(new_v4.yiaddr, new_v4.subnet_mask)?;

            // Update the IP address if it has changed
            if new_net != old_net {
                let link = sock
                    .get_link(crate::network::netlink::LinkID::Name(interface.to_string()))
                    .wrap("get interface in netns")?;
                sock.add_addr(link.header.index, &ipnet::IpNet::V4(new_net))
                    .wrap("add new addr")?;
                sock.del_addr(link.header.index, &ipnet::IpNet::V4(old_net))
                    .wrap("remove old addrs")?;
            }

            // Update the default gateway ONLY for IPv4 if it has changed
            if new_v4.gateways != old_v4.gateways {
                if let Some(gws) = &old_v4.gateways {
                    if let Some(gw) = gws.first() {
                        let route = Route::Ipv4 {
                            dest: ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                            gw: *gw,
                            metric: None,
                        };
                        match sock.del_route(&route) {
                            Ok(_) => {}
                            Err(err) => match err.unwrap() {
                                NetavarkError::Netlink(e) if -e.raw_code() == libc::ESRCH => {}
                                _ => return Err(err).wrap("delete old default route"),
                            },
                        };
                    }
                }
                if let Some(gws) = &new_v4.gateways {
                    if let Some(gw) = gws.first() {
                        let route = Route::Ipv4 {
                            dest: ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                            gw: *gw,
                            metric: None,
                        };
                        sock.add_route(&route)?;
                    }
                }
            }
        }
        (MozimLease::V6(old_v6), MozimLease::V6(new_v6)) => {
            let old_net = ipnet::Ipv6Net::new(old_v6.addr, old_v6.prefix_len)?;
            let new_net = ipnet::Ipv6Net::new(new_v6.addr, new_v6.prefix_len)?;

            // Update the IP address if it has changed
            if new_net != old_net {
                let link = sock
                    .get_link(crate::network::netlink::LinkID::Name(interface.to_string()))
                    .wrap("get interface in netns")?;
                sock.add_addr(link.header.index, &ipnet::IpNet::V6(new_net))?;
                sock.del_addr(link.header.index, &ipnet::IpNet::V6(old_net))?;
            }
            // NO gateway logic for IPv6. This is intentional.
        }
        _ => return Err(NetavarkError::msg("Lease type mismatch during IP update")),
    }
    Ok(())
}

/// DHCPv6 implementation
/// DHCP service is responsible for creating, handling, and managing the dhcp lease process.
#[derive(Debug)]
pub struct DhcpV6Service {
    client: DhcpV6ClientAsync,
    network_config: NetworkConfig,
    previous_lease: Option<MozimV6Lease>,
}

impl DhcpV6Service {
    // for netavark ia_type will be NonTemporaryAddresses
    pub fn new(
        nc: NetworkConfig,
        timeout: u32,
        ia_type: DhcpV6IaType,
    ) -> Result<Self, DhcpServiceError> {
        let mut config = DhcpV6Config::new(&nc.host_iface, ia_type);
        config.set_timeout(timeout);

        // Sending the hostname to the DHCP server is optional but it can be useful
        // in environments where DDNS is used to create or update DNS records.
        if !nc.host_name.is_empty() {
            // Note: Currently mozim's DhcpV6Config does not have a method to set host name via the FQDN option
            // If it gets added in the future, add it here
        };

        // Similar to DHCPv4, we should set a unique identifier for the client
        // Since the container id remains constant for life of the container
        // and it should be globally unique, we can use it to create a DUID
        // using Dhcpv6Duid::Ll (link-layer based) with the container's MAC address

        // We MUST use DUID-LL (Link-Layer) to generate the DHCP Unique Identifier.
        // A container's identity needs to be stable across restarts and migrations to
        // receive a persistent IP address.
        //
        // DUID-LL is the only type that is purely deterministic, generated solely from
        // the container's static MAC address. This ensures that if a container is
        // recreated with the same MAC, it will always produce the same DUID.
        //
        // Other types like DUID-LLT are unsuitable because they include a timestamp,
        // which would generate a new DUID on every container restart, breaking lease
        // persistence as when the conatainer shifts to a different host on the same network
        let client = match DhcpV6ClientAsync::init(config, None) {
            Ok(client) => Ok(client),
            Err(err) => Err(DhcpServiceError::new(InvalidArgument, err.to_string())),
        }?;
        // since it uses DUID instead of MAC address for lease tracking so
        //doesnt matter if use proxy or not to send the message to the dhcp
        // server - but for the sake of following the template we are using the
        // proxy by sending grpc request to it via the uds port
        Ok(Self {
            client,
            network_config: nc,
            previous_lease: None,
        })
    }

    pub async fn get_lease(&mut self) -> Result<NetavarkLease, DhcpServiceError> {
        if let Some(lease_result) = self.client.next().await {
            match lease_result {
                Ok(lease) => {
                    let mut netavark_lease =
                        <NetavarkLease as From<MozimV6Lease>>::from(lease.clone());
                    // the domain name is also filled in the from function
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
    /// Sends a DHCPRELEASE message for the given IPv6 lease.
    /// This is a "best effort" operation and should not block teardown.
    pub fn release_lease(&mut self) -> Result<(), DhcpServiceError> {
        // We must check the specific MozimV6Lease from the previous_lease field.
        if let Some(lease) = &self.previous_lease {
            debug!(
                "Attempting to release lease for MAC: {}",
                &self.network_config.container_mac_addr
            );
            // Directly call the release function on the underlying mozim client.
            self.client
                .release(lease)
                .map_err(|e| DhcpServiceError::new(Bug, e.to_string()))
        } else {
            // No previous lease, or a type mismatch (which shouldn't happen).
            debug!(
                "No previous IPv6 lease to release for MAC: {}",
                &self.network_config.container_mac_addr
            );
            Ok(())
        }
    }
}
