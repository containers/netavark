use crate::{
    dns::aardvark::AardvarkEntry,
    error::{NetavarkError, NetavarkResult},
    firewall::FirewallDriver,
};

use std::{net::IpAddr, path::Path};

use super::{
    bridge::Bridge,
    constants, netlink,
    plugin::PluginDriver,
    types::{Network, PerNetworkOptions, PortMapping, StatusBlock},
    vlan::Vlan,
};
use std::os::unix::fs::PermissionsExt;
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

pub fn get_network_driver<'a>(
    info: DriverInfo<'a>,
    plugins_directories: &Option<Vec<String>>,
) -> NetavarkResult<Box<dyn NetworkDriver + 'a>> {
    match info.network.driver.as_str() {
        constants::DRIVER_BRIDGE => Ok(Box::new(Bridge::new(info))),
        constants::DRIVER_IPVLAN | constants::DRIVER_MACVLAN => Ok(Box::new(Vlan::new(info))),

        name => {
            if let Some(dirs) = plugins_directories {
                for path in dirs.iter() {
                    let path = Path::new(path).join(name);
                    if let Ok(meta) = path.metadata() {
                        if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                            return Ok(Box::new(PluginDriver::new(path, info)));
                        }
                    }
                }
            }

            Err(NetavarkError::Message(format!(
                "unknown network driver \"{}\"",
                info.network.driver
            )))
        }
    }
}
