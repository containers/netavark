use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::internal_types::IPAMAddresses;
use crate::network::types::NetAddress;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig};
use crate::dhcp_proxy::proxy_conf::DEFAULT_UDS_PATH;

use super::driver::DriverInfo;
use super::{core_utils, netlink};

pub type DhcpLeaseInfo = (Vec<NetAddress>, Option<Vec<IpAddr>>, Option<Vec<String>>);
type SingleParsedLeaseInfo = (NetAddress, Option<Vec<IpAddr>>, Option<Vec<String>>);
/// Performs DHCP lease requests for a container by connecting to the netavark-dhcp-proxy daemon.
///
/// This function acts as a client to the gRPC proxy. It is "dual-stack aware" and will
/// perform sequential lease requests for both IPv4 and IPv6 if the network is configured
/// for it. It first requests an IPv4 lease, and then, if `ipam.ipv6_enabled` is true,
/// it makes a second request for an IPv6 lease.
///
/// # Arguments
///
/// * `host_network_interface`: The name of the host network interface the proxy should listen on (e.g., "br0").
/// * `container_network_interface`: The name of the interface inside the container's namespace (e.g., "eth0").
/// * `ns_path`: The filesystem path to the container's network namespace.
/// * `container_macvlan_mac`: The MAC address of the container's interface for which the lease is requested.
/// * `container_hostname`: The hostname of the container, to be sent in the DHCP request.
/// * `container_id`: The unique ID of the container.
/// * `ipam`: A reference to the IPAM configuration, which contains the crucial `ipv6_enabled` flag.
///
/// # Returns
///
/// A `NetavarkResult` containing `DhcpLeaseInfo`. This struct holds the combined results
/// of all successful DHCP leases, including a list of acquired subnets (both IPv4 and IPv6),
/// DNS servers, and the domain name.
///
pub fn get_dhcp_lease(
    host_network_interface: &str,
    container_network_interface: &str,
    ns_path: &str,
    container_macvlan_mac: &str,
    container_hostname: &str,
    container_id: &str,
    ipam: &IPAMAddresses,
) -> NetavarkResult<DhcpLeaseInfo> {
    // Create containers to hold the combined results from all leases.
    let mut subnets: Vec<NetAddress> = Vec::new();

    // --- Perform DHCPv4 Lease ---
    // For now, we assume IPv4 is always desired unless explicitly disabled in future logic.
    // You could make this conditional based on `ipam.container_addresses` if needed.
    let nvp_config_v4 = NetworkConfig {
        version: 0, // Explicitly set for IPv4
        host_iface: host_network_interface.to_string(),
        domain_name: "".to_string(),
        host_name: container_hostname.to_string(),
        ns_path: ns_path.to_string(),
        container_iface: container_network_interface.to_string(),
        container_mac_addr: container_macvlan_mac.to_string(),
        container_id: container_id.to_string(),
    };

    // If IPv4 fails but IPv6 is requested, should we continue or fail all?
    // For now, we'll let it continue.
    let v4_lease = match get_lease_from_proxy(nvp_config_v4) {
        Ok(l) => l,
        Err(e) => {
            return Err(NetavarkError::msg(format!("unable to obtain lease: {e}")));
        }
    };
    // Parse the v4 lease and add it to our results.
    let (v4_subnet, mut all_dns_servers, mut all_domain_names) = parse_lease(v4_lease)?;
    subnets.push(v4_subnet);

    // --- Conditionally Perform DHCPv6 Lease ---
    if ipam.ipv6_enabled {
        let nvp_config_v6 = NetworkConfig {
            version: 1, // Explicitly set for IPv6
            host_iface: host_network_interface.to_string(),
            domain_name: "".to_string(),
            host_name: container_hostname.to_string(),
            ns_path: ns_path.to_string(),
            container_iface: container_network_interface.to_string(),
            container_mac_addr: container_macvlan_mac.to_string(),
            container_id: container_id.to_string(),
        };

        let v6_lease = get_lease_from_proxy(nvp_config_v6)?;
        let (v6_subnet, v6_dns, v6_domain) = parse_lease(v6_lease)?;
        subnets.push(v6_subnet);
        // Merge the DNS info. Prioritize IPv4, but use IPv6 if IPv4 didn't provide any.
        if all_dns_servers.is_none() || all_dns_servers.as_deref().unwrap_or_default().is_empty() {
            all_dns_servers = v6_dns;
        }

        // Merge the domain info similarly.
        if all_domain_names.is_none() || all_domain_names.as_deref().unwrap_or_default().is_empty()
        {
            all_domain_names = v6_domain;
        }
    }

    Ok((subnets, all_dns_servers, all_domain_names))
}

// pub fn get_dhcp_lease(
//     host_network_interface: &str,
//     container_network_interface: &str,
//     ns_path: &str,
//     container_macvlan_mac: &str,
//     container_hostname: &str,
//     container_id: &str,
//     ipam: &IPAMAddresses,
// ) -> NetavarkResult<DhcpLeaseInfo> {
//     let nvp_config = NetworkConfig {
//         host_iface: host_network_interface.to_string(),
//         // TODO add in domain name support
//         domain_name: "".to_string(),
//         host_name: container_hostname.to_string(),
//         version: 1,
//         ns_path: ns_path.to_string(),
//         container_iface: container_network_interface.to_string(),
//         container_mac_addr: container_macvlan_mac.to_string(),
//         container_id: container_id.to_string(),
//     };
//     let lease = match tokio::task::LocalSet::new().block_on(
//         match &tokio::runtime::Builder::new_current_thread()
//             .enable_io()
//             .build()
//         {
//             Ok(r) => r,
//             Err(e) => {
//                 return Err(NetavarkError::msg(format!("unable to build thread: {e}")));
//             }
//         },
//         nvp_config.get_lease(DEFAULT_UDS_PATH),
//     ) {
//         Ok(l) => l,
//         Err(e) => {
//             return Err(NetavarkError::msg(format!("unable to obtain lease: {e}")));
//         }
//     };

//     // Note: technically DHCP can return multiple gateways but
//     // we are just plucking the one. gw may also not exist.
//     let gw = if !lease.gateways.is_empty() {
//         match IpAddr::from_str(&lease.gateways[0]) {
//             Ok(g) => Some(g),
//             Err(e) => {
//                 return Err(NetavarkError::msg(format!("bad gateway address: {e}")));
//             }
//         }
//     } else {
//         None
//     };

//     let dns_servers = if !lease.dns_servers.is_empty() {
//         let servers = lease
//             .dns_servers
//             .into_iter()
//             .map(|d| match IpAddr::from_str(&d) {
//                 Ok(d) => Ok(d),
//                 Err(e) => Err(NetavarkError::msg(format!("bad dns address: {e}"))),
//             })
//             .collect::<Result<Vec<IpAddr>, NetavarkError>>()?;
//         Some(servers)
//     } else {
//         None
//     };
//     let domain_name = if !lease.domain_name.is_empty() {
//         Some(vec![lease.domain_name])
//     } else {
//         None
//     };

//     let ip_addr = match IpAddr::from_str(&lease.yiaddr) {
//         Ok(i) => i,
//         Err(e) => return Err(NetavarkError::Message(e.to_string())),
//     };
//     let subnet_mask = match std::net::Ipv4Addr::from_str(&lease.subnet_mask) {
//         Ok(s) => s,
//         Err(e) => return Err(NetavarkError::Message(e.to_string())),
//     };

//     let prefix_len = u32::from(subnet_mask).count_ones();
//     let ip = match IpNet::new(ip_addr, prefix_len as u8) {
//         Ok(i) => i,
//         Err(e) => return Err(NetavarkError::msg(e.to_string())),
//     };
//     let ns = NetAddress {
//         gateway: gw,
//         ipnet: ip,
//     };

//     Ok((vec![ns], dns_servers, domain_name))
// }

// Helper function to avoid code duplication for the proxy call and runtime setup.
fn get_lease_from_proxy(config: NetworkConfig) -> NetavarkResult<Lease> {
    tokio::task::LocalSet::new().block_on(
        match &tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                return Err(NetavarkError::msg(format!("unable to build thread: {e}")));
            }
        },
        config.get_lease(DEFAULT_UDS_PATH),
    )
}

// Helper function to generalize lease parsing for both v4 and v6.
// Not using DhcpLeaseInfo type as here only a single net_address is returned each time
fn parse_lease(lease: Lease) -> NetavarkResult<SingleParsedLeaseInfo> {
    let ip_addr = IpAddr::from_str(&lease.yiaddr)?;

    // This is the core logic that now handles both lease types correctly.
    let ipnet = if lease.is_v6 {
        // For IPv6, the `subnet_mask` field contains the prefix length.
        let prefix_len = lease
            .subnet_mask
            .parse::<u8>()
            .map_err(|e| NetavarkError::msg(format!("invalid ipv6 prefix length: {e}")))?;
        IpNet::new(ip_addr, prefix_len)?
    } else {
        // For IPv4, the `subnet_mask` field is a standard dotted-quad mask.
        let mask = std::net::Ipv4Addr::from_str(&lease.subnet_mask)?;
        let prefix_len = u32::from(mask).count_ones();
        IpNet::new(ip_addr, prefix_len as u8)?
    };

    // Gateways are typically only present in IPv4 leases.
    let gw = if !lease.gateways.is_empty() {
        Some(IpAddr::from_str(&lease.gateways[0])?)
    } else {
        None
    };

    let net_address = NetAddress { gateway: gw, ipnet };

    // Parse DNS servers, which can be present in both lease types.
    let dns_servers = if !lease.dns_servers.is_empty() {
        let servers = lease
            .dns_servers
            .into_iter()
            .map(|d| IpAddr::from_str(&d))
            .collect::<Result<Vec<IpAddr>, _>>()?;
        Some(servers)
    } else {
        None
    };

    // Parse domain name.
    let domain_name = if !lease.domain_name.is_empty() {
        Some(vec![lease.domain_name])
    } else {
        None
    };

    Ok((net_address, dns_servers, domain_name))
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
