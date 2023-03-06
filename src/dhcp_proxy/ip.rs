/*
   This file is intended to support netavark-dhcp-proxy configuring the IP information
   that it got from the dhcp server.

   Long term this file/function should move into netavark
*/

pub use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, Lease};
pub use crate::dhcp_proxy::types::{CustomErr, ProxyError};
use crate::network::core_utils;
use crate::network::netlink;
use crate::network::netlink::Socket;
use ipnet::IpNet;
use log::debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

trait IpConv {
    fn to_v4(&self) -> Result<&Ipv4Addr, ProxyError>;
    fn to_v6(&self) -> Result<&Ipv6Addr, ProxyError>;
}

// Simple implementation for converting from IPAddr to
// specific IP type
impl IpConv for IpAddr {
    fn to_v4(&self) -> Result<&Ipv4Addr, ProxyError> {
        match self {
            IpAddr::V4(ip) => Ok(ip),
            IpAddr::V6(_) => Err(ProxyError::new(
                "invalid value for ipv4 conversion".to_string(),
            )),
        }
    }

    fn to_v6(&self) -> Result<&Ipv6Addr, ProxyError> {
        match self {
            IpAddr::V4(_) => Err(ProxyError::new(
                "invalid value for ipv6 conversion".to_string(),
            )),
            IpAddr::V6(ip) => Ok(ip),
        }
    }
}

/*
   Information that came back in the DHCP lease like name_servers,
   domain and host names, etc. will be implemented in podman; not here.
*/

#[derive(Clone, Debug)]
struct MacVLAN {
    address: IpAddr,
    gateways: Vec<IpNet>,
    interface: String,
    // Unset right now
    // mtu: u32,
    prefix_length: u8,
}

trait Address<T> {
    fn new(l: &Lease, interface: &str) -> Result<Self, ProxyError>
    where
        Self: Sized;
    fn add_ip(&self, nls: &mut Socket) -> Result<(), ProxyError>;
    fn add_gws(&self, nls: &mut Socket) -> Result<(), ProxyError>;
    fn remove(self) -> Result<(), ProxyError>;
}

fn handle_gws(g: Vec<String>, netmask: &str) -> Result<Vec<IpNet>, ProxyError> {
    // TODO Need unit test
    let mut gws = Vec::new();
    for route in g {
        // TODO FIX for ipv6
        let sub_mask = match Ipv4Addr::from_str(netmask) {
            Ok(n) => n,
            Err(e) => return Err(ProxyError::new(e.to_string())),
        };
        let prefix = u32::from(sub_mask).count_ones();
        let ip = match Ipv4Addr::from_str(&route) {
            Ok(i) => i,
            Err(e) => return Err(ProxyError::new(e.to_string())),
        };
        let gw = match IpNet::new(IpAddr::from(ip), prefix as u8) {
            Ok(r) => r,
            Err(e) => return Err(ProxyError::new(format!("{e}:'{route}'"))),
        };
        gws.push(gw);
    }
    Ok(gws)
}

#[test]
fn test_bad_gw_handle_gws() {
    let gws = vec!["192.168.1.1".to_string(), "10.10.10".into()];
    let netmask = "255.255.255.0";
    assert!(handle_gws(gws, netmask).is_err())
}

#[test]
fn test_bad_subnet_handle_gws() {
    let gws = vec!["192.168.1.1".to_string(), "10.10.10.1".into()];
    let netmask = "255.255.255";
    assert!(handle_gws(gws, netmask).is_err())
}

#[test]
fn test_handle_gws() {
    let gws = vec!["192.168.1.1".to_string(), "10.10.10.1".into()];
    let netmask = "255.255.255.0";
    assert!(handle_gws(gws, netmask).is_ok())
}
// IPV4 implementation
impl Address<Ipv4Addr> for MacVLAN {
    fn new(l: &NetavarkLease, interface: &str) -> Result<MacVLAN, ProxyError> {
        debug!("new ipv4 macvlan for {}", interface);
        let address = match IpAddr::from_str(&l.yiaddr) {
            Ok(a) => a,
            Err(e) => {
                return Err(ProxyError::new(format!("bad address: {e}")));
            }
        };
        let gateways = match handle_gws(l.gateways.clone(), &l.subnet_mask) {
            Ok(g) => g,
            Err(e) => {
                return Err(ProxyError::new(format!("bad gateways: {}", e.to_string())));
            }
        };
        let prefix_length = match get_prefix_length_v4(&l.subnet_mask) {
            Ok(u) => u as u8,
            Err(e) => return Err(ProxyError::new(e.to_string())),
        };
        Ok(MacVLAN {
            address,
            gateways,
            interface: interface.to_string(),
            // Disabled for now
            // mtu: l.mtu,
            prefix_length,
        })
    }

    //  add the ip address to the container namespace
    fn add_ip(&self, nls: &mut Socket) -> Result<(), ProxyError> {
        debug!("adding network information for {}", self.interface);
        let ip = IpNet::new(self.address, self.prefix_length)?;
        let dev = nls.get_link(netlink::LinkID::Name(self.interface.clone()))?;
        match nls.add_addr(dev.header.index, &ip) {
            Ok(_) => Ok(()),
            Err(e) => Err(ProxyError::new(e.to_string())),
        }
    }

    // add one or more routes to the container namespace
    fn add_gws(&self, nls: &mut Socket) -> Result<(), ProxyError> {
        debug!("adding gateways to {}", self.interface);
        match core_utils::add_default_routes(nls, &self.gateways, None) {
            Ok(_) => Ok(()),
            Err(e) => Err(ProxyError::new(e.to_string())),
        }
    }

    /*
       For now, nv will remove the interface; this causes all IP stuff
       to fold.
    */
    fn remove(self) -> Result<(), ProxyError> {
        debug!("removing interface {}", self.interface);
        todo!()
    }
}

// setup takes the DHCP lease and some additional information and
// applies the TCP/IP information to the namespace.
pub fn setup(lease: &NetavarkLease, interface: &str, ns_path: &str) -> Result<(), ProxyError> {
    debug!("setting up {}", interface);
    let vlan = match MacVLAN::new(lease, interface) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };
    let (_, mut netns) = core_utils::open_netlink_sockets(ns_path)?;
    vlan.add_ip(&mut netns.netlink)?;
    vlan.add_gws(&mut netns.netlink)
}

// teardown is likely unnecessary but holding place here
pub fn teardown() -> Result<(), ProxyError> {
    todo!()
}

/// get_prefix_lengh takes a subnet mask in str form and
/// returns its prefix length by counting ones.
///
/// # Arguments
///
/// * `netmask`: str form of subnet mask (i.e. 255.255.255.0)
///
/// returns: Result<u32, ProxyError>
///
/// # Examples
///
/// ```
///
/// ```
fn get_prefix_length_v4(netmask: &str) -> Result<u32, ProxyError> {
    let sub_mask = match Ipv4Addr::from_str(netmask) {
        Ok(n) => n,
        Err(e) => return Err(ProxyError::new(e.to_string())),
    };
    Ok(u32::from(sub_mask).count_ones())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_24() {
        assert_eq!(get_prefix_length_v4("255.255.255.0").unwrap(), 24_u32)
    }

    #[test]
    fn test_16() {
        assert_eq!(get_prefix_length_v4("255.255.0.0").unwrap(), 16_u32)
    }

    #[test]
    fn test_25() {
        assert_eq!(get_prefix_length_v4("255.255.255.128").unwrap(), 25_u32)
    }

    #[test]
    fn test_bad_input() {
        assert!(get_prefix_length_v4("255.255.128").is_err())
    }
}
