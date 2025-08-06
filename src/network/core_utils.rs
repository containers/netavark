use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::{constants, internal_types, types};
use crate::wrap;
use ipnet::IpNet;
use netlink_packet_route::link::{IpVlanMode, LinkMessage, MacVlanMode};
use nix::sched;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::prelude::*;
use std::path::Path;
use std::str::FromStr;

use super::netlink;

use netlink_packet_route::link::LinkAttribute;

pub struct CoreUtils {
    pub networkns: String,
}

pub fn get_netavark_dns_port() -> Result<u16, NetavarkError> {
    match env::var("NETAVARK_DNS_PORT") {
        Ok(port_string) => match port_string.parse() {
            Ok(port) => Ok(port),
            Err(e) => Err(NetavarkError::Message(format!(
                "Invalid NETAVARK_DNS_PORT {port_string}: {e}"
            ))),
        },
        Err(_) => Ok(53),
    }
}

pub fn parse_option<T>(
    opts: &Option<HashMap<String, String>>,
    name: &str,
) -> NetavarkResult<Option<T>>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    let val = match opts.as_ref().and_then(|map| map.get(name)) {
        Some(val) => match val.parse::<T>() {
            Ok(mtu) => mtu,
            Err(err) => {
                return Err(NetavarkError::Message(format!(
                    "unable to parse \"{name}\": {err}"
                )));
            }
        },
        // if no option is set return None
        None => return Ok(None),
    };
    Ok(Some(val))
}

pub fn get_ipam_addresses<'a>(
    per_network_opts: &'a types::PerNetworkOptions,
    network: &'a types::Network,
) -> NetavarkResult<internal_types::IPAMAddresses> {
    let addresses = match network
        .ipam_options
        .as_ref()
        .and_then(|map| map.get("driver").cloned())
        .as_deref()
    {
        // when option is none default to host local
        Some(constants::IPAM_HOSTLOCAL) | None => {
            // static ip vector
            let mut container_addresses = Vec::new();
            // gateway ip vector
            let mut gateway_addresses = Vec::new();
            // network addresses for response
            let mut net_addresses: Vec<types::NetAddress> = Vec::new();
            // bool for ipv6
            let mut ipv6_enabled = false;

            // nameservers which can be configured for this container
            let mut nameservers: Vec<IpAddr> = Vec::new();

            let static_ips = match per_network_opts.static_ips.as_ref() {
                None => return Err(NetavarkError::msg("no static ips provided")),
                Some(i) => i,
            };

            // prepare a vector of static aps with appropriate cidr
            for (idx, subnet) in network.subnets.iter().flatten().enumerate() {
                let subnet_mask_cidr = subnet.subnet.prefix_len();
                if let Some(gw) = subnet.gateway {
                    let gw_net = match ipnet::IpNet::new(gw, subnet_mask_cidr) {
                        Ok(dest) => dest,
                        Err(err) => {
                            return Err(NetavarkError::msg(format!(
                                "failed to parse address {gw}/{subnet_mask_cidr}: {err}"
                            )))
                        }
                    };
                    gateway_addresses.push(gw_net);
                    nameservers.push(gw);
                }

                // for dual-stack network.ipv6_enabled could be false do explicit check
                if subnet.subnet.addr().is_ipv6() {
                    ipv6_enabled = true;
                }

                // Build up response information
                let container_address: ipnet::IpNet =
                    match format!("{}/{}", static_ips[idx], subnet_mask_cidr).parse() {
                        Ok(i) => i,
                        Err(e) => {
                            return Err(NetavarkError::SubnetParse(e));
                        }
                    };
                // Add the IP to the address_vector
                container_addresses.push(container_address);
                net_addresses.push(types::NetAddress {
                    gateway: subnet.gateway,
                    ipnet: container_address,
                });
            }

            let routes: Vec<netlink::Route> = match create_route_list(&network.routes) {
                Ok(r) => r,
                Err(e) => {
                    return Err(e);
                }
            };

            internal_types::IPAMAddresses {
                container_addresses,
                dhcp_enabled: false,
                gateway_addresses,
                routes,
                net_addresses,
                nameservers,
                ipv6_enabled,
            }
        }
        Some(constants::IPAM_NONE) => {
            // no ipam just return empty vectors
            internal_types::IPAMAddresses {
                container_addresses: vec![],
                dhcp_enabled: false,
                gateway_addresses: vec![],
                routes: vec![],
                net_addresses: vec![],
                nameservers: vec![],
                ipv6_enabled: false,
            }
        }
        Some(constants::IPAM_DHCP) => internal_types::IPAMAddresses {
            container_addresses: vec![],
            dhcp_enabled: true,
            gateway_addresses: vec![],
            routes: vec![],
            ipv6_enabled: false,
            net_addresses: vec![],
            nameservers: vec![],
        },
        Some(driver) => {
            return Err(NetavarkError::msg(format!(
                "unsupported ipam driver {driver}"
            )));
        }
    };

    Ok(addresses)
}

impl CoreUtils {
    pub fn encode_address_to_hex(bytes: &[u8]) -> String {
        let address: String = bytes
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(":");

        address
    }

    pub fn decode_address_from_hex(input: &str) -> NetavarkResult<Vec<u8>> {
        let bytes: Result<Vec<u8>, _> = input
            .split([':', '-'])
            .map(|b| u8::from_str_radix(b, 16))
            .collect();

        let result = match bytes {
            Ok(bytes) => {
                if bytes.len() != 6 {
                    return Err(NetavarkError::msg(format!(
                        "invalid mac length for address: {input}"
                    )));
                }
                bytes
            }
            Err(e) => {
                return Err(NetavarkError::msg(format!(
                    "unable to parse mac address {input}: {e}"
                )));
            }
        };

        Ok(result)
    }

    pub fn get_macvlan_mode_from_string(mode: Option<&str>) -> NetavarkResult<MacVlanMode> {
        match mode {
            // default to bridge when unset
            None | Some("") | Some("bridge") => Ok(MacVlanMode::Bridge),
            Some("private") => Ok(MacVlanMode::Private),
            Some("vepa") => Ok(MacVlanMode::Vepa),
            Some("passthru") => Ok(MacVlanMode::Passthrough),
            Some("source") => Ok(MacVlanMode::Source),
            // default to bridge
            Some(name) => Err(NetavarkError::msg(format!(
                "invalid macvlan mode \"{name}\""
            ))),
        }
    }

    pub fn get_ipvlan_mode_from_string(mode: Option<&str>) -> NetavarkResult<IpVlanMode> {
        match mode {
            // default to l2 when unset
            None | Some("") | Some("l2") => Ok(IpVlanMode::L2),
            Some("l3") => Ok(IpVlanMode::L3),
            Some("l3s") => Ok(IpVlanMode::L3S),
            Some(name) => Err(NetavarkError::msg(format!(
                "invalid ipvlan mode \"{name}\""
            ))),
        }
    }

    pub fn create_network_hash(network_name: &str, length: usize) -> String {
        let mut hasher = Sha512::new();
        hasher.update(network_name.as_bytes());
        let result = hasher.finalize();
        let hash_string = format!("{result:X}");
        let response = &hash_string[0..length];
        response.to_string()
    }
}

pub fn join_netns<Fd: AsFd>(fd: Fd) -> NetavarkResult<()> {
    match sched::setns(fd, sched::CloneFlags::CLONE_NEWNET) {
        Ok(_) => Ok(()),
        Err(e) => Err(NetavarkError::wrap(
            "setns",
            NetavarkError::Io(io::Error::from(e)),
        )),
    }
}

/// safe way to join the namespace and join back to the host after the task is done
/// This first arg should be the hostns fd, the second is the container ns fd.
/// The third and last the closure that should be executed in the ns.
#[macro_export]
macro_rules! exec_netns {
    ($host:expr, $netns:expr, $exec:expr) => {{
        join_netns($netns)?;
        let result = $exec;
        join_netns($host)?;
        result
    }};
}

pub struct NamespaceOptions<N: netlink::Namespace> {
    /// Note we have to return the File object since the fd is only valid
    /// as long as the File object is valid
    pub file: File,
    pub netlink: netlink::Socket<N>,
}

pub fn open_netlink_sockets(
    netns_path: &str,
) -> NetavarkResult<(
    NamespaceOptions<netlink::HostNS>,
    NamespaceOptions<netlink::ContainerNS>,
)> {
    let netns = open_netlink_socket(netns_path).wrap("open container netns")?;
    let hostns = open_netlink_socket("/proc/self/ns/net").wrap("open host netns")?;

    let host_socket = netlink::Socket::<netlink::HostNS>::new().wrap("host netlink socket")?;
    let netns_sock = exec_netns!(
        hostns.as_fd(),
        netns.as_fd(),
        netlink::Socket::<netlink::ContainerNS>::new().wrap("netns netlink socket")
    )?;

    Ok((
        NamespaceOptions {
            file: hostns,
            netlink: host_socket,
        },
        NamespaceOptions {
            file: netns,
            netlink: netns_sock,
        },
    ))
}

fn open_netlink_socket(netns_path: &str) -> NetavarkResult<File> {
    wrap!(File::open(netns_path), format!("open {netns_path}"))
}

pub fn add_default_routes(
    sock: &mut netlink::Socket<netlink::ContainerNS>,
    gws: &[ipnet::IpNet],
    metric: Option<u32>,
) -> NetavarkResult<()> {
    let mut ipv4 = false;
    let mut ipv6 = false;
    for addr in gws {
        let route = match addr {
            ipnet::IpNet::V4(v4) => {
                if ipv4 {
                    continue;
                }
                ipv4 = true;

                netlink::Route::Ipv4 {
                    dest: ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0)?,
                    gw: v4.addr(),
                    metric,
                }
            }
            ipnet::IpNet::V6(v6) => {
                if ipv6 {
                    continue;
                }
                ipv6 = true;

                netlink::Route::Ipv6 {
                    dest: ipnet::Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0)?,
                    gw: v6.addr(),
                    metric,
                }
            }
        };
        sock.add_route(&route)
            .wrap(format!("add default route {}", &route))?;
    }
    Ok(())
}

pub fn create_route_list(
    routes: &Option<Vec<types::Route>>,
) -> NetavarkResult<Vec<netlink::Route>> {
    match routes {
        Some(rs) => rs
            .iter()
            .map(|r| {
                let gw = r.gateway;
                let dst = r.destination;
                let mtr = r.metric;
                match (gw, dst) {
                    (IpAddr::V4(gw4), IpNet::V4(dst4)) => Ok(netlink::Route::Ipv4 {
                        dest: dst4,
                        gw: gw4,
                        metric: mtr,
                    }),
                    (IpAddr::V6(gw6), IpNet::V6(dst6)) => Ok(netlink::Route::Ipv6 {
                        dest: dst6,
                        gw: gw6,
                        metric: mtr,
                    }),
                    (IpAddr::V4(gw4), IpNet::V6(dst6)) => Err(NetavarkError::Message(format!(
                        "Route with ipv6 destination and ipv4 gateway ({dst6} via {gw4})"
                    ))),

                    (IpAddr::V6(gw6), IpNet::V4(dst4)) => Err(NetavarkError::Message(format!(
                        "Route with ipv4 destination and ipv6 gateway ({dst4} via {gw6})"
                    ))),
                }
            })
            .collect(),
        None => Ok(vec![]),
    }
}

pub fn get_mac_address(v: Vec<LinkAttribute>) -> NetavarkResult<String> {
    for nla in v.into_iter() {
        if let LinkAttribute::Address(ref addr) = nla {
            return Ok(CoreUtils::encode_address_to_hex(addr));
        }
    }
    Err(NetavarkError::msg(
        "failed to get the the container mac address",
    ))
}

/// check if systemd is booted, see sd_booted(3)
pub fn is_using_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// Returns the *first* interface with a default route or an error if no default route interface exists.
pub fn get_default_route_interface(host: &mut netlink::Socket) -> NetavarkResult<LinkMessage> {
    let routes = host.dump_routes().wrap("dump routes")?;

    for route in routes {
        let mut dest = false;
        let mut out_if = 0;
        for nla in route.attributes {
            if let netlink_packet_route::route::RouteAttribute::Destination(_) = nla {
                dest = true;
            }
            if let netlink_packet_route::route::RouteAttribute::Oif(oif) = nla {
                out_if = oif;
            }
        }

        // if there is no dest we have a default route
        // return the output interface for this route
        if !dest && out_if > 0 {
            return host.get_link(netlink::LinkID::ID(out_if));
        }
    }
    Err(NetavarkError::msg("failed to get default route interface"))
}

pub fn get_mtu_from_iface_attributes(attributes: &[LinkAttribute]) -> NetavarkResult<u32> {
    for nla in attributes.iter() {
        if let LinkAttribute::Mtu(mtu) = nla {
            return Ok(*mtu);
        }
    }
    // It should be impossible that the interface has no MTU set, so return an error in such case.
    Err(NetavarkError::msg(
        "no MTU attribute in netlink message, possible kernel issue",
    ))
}
