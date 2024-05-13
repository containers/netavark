use crate::commands::get_config_dir;
use crate::dns::aardvark::{Aardvark, AardvarkEntry};
use crate::error::{NetavarkError, NetavarkErrorList, NetavarkResult};
use crate::network::constants::DRIVER_BRIDGE;
use crate::network::core_utils;
use crate::network::driver::{get_network_driver, DriverInfo};

use crate::{firewall, network};
use clap::builder::NonEmptyStringValueParser;
use clap::Parser;
use log::debug;
use std::ffi::OsString;
use std::os::fd::AsFd;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct Teardown {
    /// Network namespace path
    #[clap(required = true, value_parser = NonEmptyStringValueParser::new())]
    network_namespace_path: String,
}

impl Teardown {
    /// The teardown command is the inverse of the setup command, undoing any configuration applied. Some interfaces may not be deleted (bridge interfaces, for example, will not be removed).
    pub fn new(network_namespace_path: String) -> Self {
        Self {
            network_namespace_path,
        }
    }

    pub fn exec(
        &self,
        input_file: Option<OsString>,
        config_dir: Option<OsString>,
        firewall_driver: Option<String>,
        aardvark_bin: OsString,
        plugin_directories: Option<Vec<OsString>>,
        rootless: bool,
    ) -> NetavarkResult<()> {
        debug!("{:?}", "Tearing down..");
        let network_options = network::types::NetworkOptions::load(input_file)?;

        let mut error_list = NetavarkErrorList::new();

        let dns_port = core_utils::get_netavark_dns_port()?;
        let config_dir = get_config_dir(config_dir, "teardown")?;

        let mut aardvark_entries = Vec::new();
        for (key, network) in &network_options.network_info {
            if network.dns_enabled && network.driver == DRIVER_BRIDGE {
                aardvark_entries.push(AardvarkEntry {
                    network_name: key,
                    network_gateways: Vec::new(),
                    network_dns_servers: &None,
                    container_id: &network_options.container_id,
                    container_ips_v4: Vec::new(),
                    container_ips_v6: Vec::new(),
                    container_names: Vec::new(),
                    container_dns_servers: &None,
                    is_internal: network.internal,
                });
            }
        }

        if !aardvark_entries.is_empty() {
            // stop dns server first before netavark clears the interface
            let path = Path::new(&config_dir).join("aardvark-dns");

            let aardvark_interface = Aardvark::new(path, rootless, aardvark_bin, dns_port);
            if let Err(err) = aardvark_interface.delete_from_netavark_entries(aardvark_entries) {
                error_list.push(NetavarkError::wrap("remove aardvark entries", err));
            }
        }

        let firewall_driver = match firewall::get_supported_firewall_driver(firewall_driver) {
            Ok(driver) => driver,
            Err(e) => return Err(e),
        };

        let (mut hostns, mut netns) =
            core_utils::open_netlink_sockets(&self.network_namespace_path)?;

        for (net_name, network) in network_options.network_info.iter() {
            let per_network_opts = match network_options.networks.get(net_name) {
                Some(opts) => opts,
                None => {
                    error_list.push(NetavarkError::Message(format!(
                        "network options for network {net_name} not found"
                    )));
                    continue;
                }
            };

            let driver = match get_network_driver(
                DriverInfo {
                    firewall: firewall_driver.as_ref(),
                    container_id: &network_options.container_id,
                    container_name: &network_options.container_name,
                    container_dns_servers: &network_options.dns_servers,
                    netns_host: hostns.file.as_fd(),
                    netns_container: netns.file.as_fd(),
                    netns_path: &self.network_namespace_path,
                    network,
                    per_network_opts,
                    port_mappings: &network_options.port_mappings,
                    dns_port,
                    config_dir: Path::new(&config_dir),
                    rootless,
                },
                &plugin_directories,
            ) {
                Ok(driver) => driver,
                Err(err) => {
                    error_list.push(err);
                    continue;
                }
            };

            match driver.teardown((&mut hostns.netlink, &mut netns.netlink)) {
                Ok(_) => {}
                Err(err) => {
                    error_list.push(err);
                    continue;
                }
            };
        }

        if !error_list.is_empty() {
            return Err(NetavarkError::List(error_list));
        }

        debug!("{:?}", "Teardown complete");
        Ok(())
    }
}
