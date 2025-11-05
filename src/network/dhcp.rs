use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::types::NetAddress;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dhcp_proxy::lib::g_rpc::NetworkConfig;
use crate::dhcp_proxy::proxy_conf::DEFAULT_UDS_PATH;

use super::driver::DriverInfo;
use super::{core_utils, netlink};

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
    container_hostname: &str,
    container_id: &str,
) -> NetavarkResult<DhcpLeaseInfo> {
    let nvp_config = NetworkConfig {
        host_iface: host_network_interface.to_string(),
        // TODO add in domain name support
        domain_name: "".to_string(),
        host_name: container_hostname.to_string(),
        version: 0,
        ns_path: ns_path.to_string(),
        container_iface: container_network_interface.to_string(),
        container_mac_addr: container_macvlan_mac.to_string(),
        container_id: container_id.to_string(),
    };
    let lease = match tokio::task::LocalSet::new().block_on(
        match &tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
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
        host_name: "".to_string(),
        version: 0,
        ns_path: ns_path.to_string(),
        container_iface: container_network_interface.to_string(),
        container_mac_addr: container_macvlan_mac.to_string(),
        container_id: "".to_string(),
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

pub fn dhcp_teardown(info: &DriverInfo, sock: &mut netlink::Socket) -> NetavarkResult<()> {
    let ipam = core_utils::get_ipam_addresses(info.per_network_opts, info.network)?;
    let if_name = info.per_network_opts.interface_name.clone();

    // If we are using DHCP, we need to at least call to the proxy so that
    // the proxy's cache can get updated and the current lease can be released.
    if ipam.dhcp_enabled {
        let dev = sock.get_link(netlink::LinkID::Name(if_name)).wrap(format!(
            "get container interface {}",
            &info.per_network_opts.interface_name
        ))?;

        let container_mac_address = core_utils::get_mac_address(dev.attributes)?;
        release_dhcp_lease(
            &info.network.network_interface.clone().unwrap_or_default(),
            &info.per_network_opts.interface_name,
            info.netns_path,
            &container_mac_address,
        )?
    }
    Ok(())
}
