use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::network::{constants, internal_types, types};
use crate::wrap;
use ipnet::IpNet;
use log::debug;
use netlink_packet_route::link::{IpVlanMode, MacVlanMode};
use nix::sched;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, Error};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::prelude::*;
use std::str::FromStr;
use sysctl::{Sysctl, SysctlError};

use super::netlink;

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
) -> Result<internal_types::IPAMAddresses, std::io::Error> {
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
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "no static ips provided",
                    ))
                }
                Some(i) => i,
            };

            // prepare a vector of static aps with appropriate cidr
            for (idx, subnet) in network.subnets.iter().flatten().enumerate() {
                let subnet_mask_cidr = subnet.subnet.prefix_len();
                if let Some(gw) = subnet.gateway {
                    let gw_net = match ipnet::IpNet::new(gw, subnet_mask_cidr) {
                        Ok(dest) => dest,
                        Err(err) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("failed to parse address {gw}/{subnet_mask_cidr}: {err}"),
                            ))
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
                            return Err(Error::new(std::io::ErrorKind::Other, e));
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
                    return Err(Error::new(std::io::ErrorKind::Other, e));
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unsupported ipam driver {driver}"),
            ));
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

    pub fn decode_address_from_hex(input: &str) -> Result<Vec<u8>, std::io::Error> {
        let bytes: Result<Vec<u8>, _> = input
            .split(|c| c == ':' || c == '-')
            .map(|b| u8::from_str_radix(b, 16))
            .collect();

        let result = match bytes {
            Ok(bytes) => {
                if bytes.len() != 6 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid mac length for address: {input}"),
                    ));
                }
                bytes
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to parse mac address {input}: {e}"),
                ));
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

    /// Set a sysctl value by value's namespace.
    pub fn apply_sysctl_value(
        ns_value: impl AsRef<str>,
        val: impl AsRef<str>,
    ) -> Result<String, SysctlError> {
        let ns_value = ns_value.as_ref();
        let val = val.as_ref();
        debug!("Setting sysctl value for {} to {}", ns_value, val);
        let ctl = sysctl::Ctl::new(ns_value)?;
        match ctl.value_string() {
            Ok(result) => {
                if result == val {
                    return Ok(result);
                }
            }
            Err(e) => return Err(e),
        }
        ctl.set_value_string(val)
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
/// The third is the result variable name and the last the closure that should be
/// executed in the ns.
#[macro_export]
macro_rules! exec_netns {
    ($host:expr, $netns:expr, $result:ident, $exec:expr) => {
        join_netns($netns)?;
        let $result = $exec;
        join_netns($host)?;
    };
}

pub struct NamespaceOptions {
    /// Note we have to return the File object since the fd is only valid
    /// as long as the File object is valid
    pub file: File,
    pub netlink: netlink::Socket,
}

pub fn open_netlink_sockets(
    netns_path: &str,
) -> NetavarkResult<(NamespaceOptions, NamespaceOptions)> {
    let netns = open_netlink_socket(netns_path).wrap("open container netns")?;
    let hostns = open_netlink_socket("/proc/self/ns/net").wrap("open host netns")?;

    let host_socket = netlink::Socket::new().wrap("host netlink socket")?;
    exec_netns!(
        hostns.as_fd(),
        netns.as_fd(),
        res,
        netlink::Socket::new().wrap("netns netlink socket")
    );

    let netns_sock = res?;
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
    sock: &mut netlink::Socket,
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

pub fn disable_ipv6_autoconf(if_name: &str) -> NetavarkResult<()> {
    // make sure autoconf is off, we want manual config only
    if let Err(err) =
        CoreUtils::apply_sysctl_value(format!("/proc/sys/net/ipv6/conf/{if_name}/autoconf"), "0")
    {
        match err {
            SysctlError::NotFound(_) => {
                // if the sysctl is not found we likely run on a system without ipv6
                // just ignore that case
            }

            // if we have a read only /proc we ignore it as well
            SysctlError::IoError(ref e) if e.raw_os_error() == Some(libc::EROFS) => {}

            _ => {
                return Err(NetavarkError::wrap(
                    "failed to set autoconf sysctl",
                    NetavarkError::Sysctl(err),
                ));
            }
        }
    };
    Ok(())
}
