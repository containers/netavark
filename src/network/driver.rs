use crate::{
    dns::aardvark::AardvarkEntry,
    error::{NetavarkError, NetavarkResult},
    firewall::FirewallDriver,
};

use std::net::IpAddr;

use super::{
    bridge::Bridge,
    constants, netlink,
    types::{Network, PerNetworkOptions, PortMapping, StatusBlock},
    vlan::Vlan,
};
use std::os::unix::io::RawFd;

pub struct DriverInfo<'a> {
    pub firewall: &'a dyn FirewallDriver,
    pub container_id: &'a String,
    pub container_name: &'a String,
    pub container_dns_servers: &'a Option<Vec<IpAddr>>,
    pub netns_host: RawFd,
    pub netns_container: RawFd,
    pub netns_path: &'a str,
    pub network: &'a Network,
    pub per_network_opts: &'a PerNetworkOptions,
    pub port_mappings: &'a Option<Vec<PortMapping>>,
    pub dns_port: u16,
}

pub trait NetworkDriver {
    /// validate the driver options
    fn validate(&mut self) -> NetavarkResult<()>;
    /// setup the network interfaces/firewall rules for this driver
    fn setup(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<(StatusBlock, Option<AardvarkEntry>)>;
    /// teardown the network interfaces/firewall rules for this driver
    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<()>;

    /// return the network name
    fn network_name(&self) -> String;
}

pub fn get_network_driver(info: DriverInfo) -> NetavarkResult<Box<dyn NetworkDriver + '_>> {
    match info.network.driver.as_str() {
        constants::DRIVER_BRIDGE => Ok(Box::new(Bridge::new(info))),
        constants::DRIVER_IPVLAN | constants::DRIVER_MACVLAN => Ok(Box::new(Vlan::new(info))),

        _ => Err(NetavarkError::Message(format!(
            "unknown network driver {}",
            info.network.driver
        ))),
    }
}
