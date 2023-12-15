use crate::error::{NetavarkError, NetavarkResult};
use crate::network::types::NetAddress;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dhcp_proxy::lib::g_rpc::NetworkConfig;
use crate::dhcp_proxy::proxy_conf::DEFAULT_UDS_PATH;

pub type DhcpLeaseInfo = (Vec<NetAddress>, Option<Vec<IpAddr>>, Option<Vec<String>>);

/// dhcp performs the connection to the nv-proxy over grpc where it
/// requests it to perform a lease via the host's network interface
/// but passes it the network interface from the container netns.:w
///
///
/// # Arguments
///
/// * `host_network_interface`:  host interface name in &str
/// * `container_network_interface`: container network interface (eth0)
/// * `ns_path`: path to the container netns
/// * `container_macvlan_mac`: mac address of the container network interface above.
///
/// returns: Result<Vec<NetAddress, Global>, NetavarkError>
///
/// # Examples
///
/// ```
///
/// ```
pub fn get_dhcp_lease(
    host_network_interface: &str,
    container_network_interface: &str,
    ns_path: &str,
    container_macvlan_mac: &str,
) -> NetavarkResult<DhcpLeaseInfo> {
    let nvp_config = NetworkConfig {
        host_iface: host_network_interface.to_string(),
        // TODO add in domain name support
        domain_name: "".to_string(),
        //  TODO add in host name support
        host_name: "".to_string(),
        version: 0,
        ns_path: ns_path.to_string(),
        container_iface: container_network_interface.to_string(),
        container_mac_addr: container_macvlan_mac.to_string(),
    };
    let lease = match tokio::task::LocalSet::new().block_on(
        match &tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                return Err(NetavarkError::msg(format!("unable to build thread: {e}")));
            }
        },
        nvp_config.get_lease(DEFAULT_UDS_PATH),
    ) {
        Ok(l) => l,
        Err(e) => {
            return Err(NetavarkError::msg(format!("unable to obtain lease: {e}")));
        }
    };

    // Note: technically DHCP can return multiple gateways but
    // we are just plucking the one. gw may also not exist.
    let gw = if !lease.gateways.is_empty() {
        match IpAddr::from_str(&lease.gateways[0]) {
            Ok(g) => Some(g),
            Err(e) => {
                return Err(NetavarkError::msg(format!("bad gateway address: {e}")));
            }
        }
    } else {
        None
    };

    let dns_servers = if !lease.dns_servers.is_empty() {
        let servers = lease
            .dns_servers
            .into_iter()
            .map(|d| match IpAddr::from_str(&d) {
                Ok(d) => Ok(d),
                Err(e) => Err(NetavarkError::msg(format!("bad dns address: {e}"))),
            })
            .collect::<Result<Vec<IpAddr>, NetavarkError>>()?;
        Some(servers)
    } else {
        None
    };
    let domain_name = if !lease.domain_name.is_empty() {
        Some(vec![lease.domain_name])
    } else {
        None
    };

    let ip_addr = match IpAddr::from_str(&lease.yiaddr) {
        Ok(i) => i,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    let subnet_mask = match std::net::Ipv4Addr::from_str(&lease.subnet_mask) {
        Ok(s) => s,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };

    let prefix_len = u32::from(subnet_mask).count_ones();
    let ip = match IpNet::new(ip_addr, prefix_len as u8) {
        Ok(i) => i,
        Err(e) => return Err(NetavarkError::msg(e.to_string())),
    };
    let ns = NetAddress {
        gateway: gw,
        ipnet: ip,
    };

    Ok((vec![ns], dns_servers, domain_name))
}

pub fn release_dhcp_lease(
    host_network_interface: &str,
    container_network_interface: &str,
    ns_path: &str,
    container_macvlan_mac: &str,
) -> NetavarkResult<()> {
    let nvp_config = NetworkConfig {
        host_iface: host_network_interface.to_string(),
        // TODO add in domain name support
        domain_name: "".to_string(),
        //  TODO add in host name support
        host_name: "".to_string(),
        version: 0,
        ns_path: ns_path.to_string(),
        container_iface: container_network_interface.to_string(),
        container_mac_addr: container_macvlan_mac.to_string(),
    };
    match tokio::task::LocalSet::new().block_on(
        match &tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                return Err(NetavarkError::msg(format!("unable to build thread: {e}")));
            }
        },
        nvp_config.drop_lease(DEFAULT_UDS_PATH),
    ) {
        Ok(_) => {}
        Err(e) => {
            return Err(NetavarkError::Message(e.to_string()));
        }
    };
    Ok(())
}
