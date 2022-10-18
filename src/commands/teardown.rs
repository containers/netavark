use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkErrorList, NetavarkResult};
use crate::network::core_utils;
use crate::network::driver::{get_network_driver, DriverInfo};

use crate::{firewall, network};
use clap::Parser;
use log::debug;
use std::env;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct Teardown {
    /// Network namespace path
    #[clap(forbid_empty_values = true, required = true)]
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
        input_file: String,
        config_dir: String,
        aardvark_bin: String,
        rootless: bool,
    ) -> NetavarkResult<()> {
        debug!("{:?}", "Tearing down..");
        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => {
                return Err(NetavarkError::Message(format!(
                    "failed to load network options: {}",
                    e
                )));
            }
        };

        let mut error_list = NetavarkErrorList::new();

        let dns_port = match env::var("NETAVARK_DNS_PORT") {
            Ok(port_string) => match port_string.parse() {
                Ok(port) => port,
                Err(e) => {
                    error_list.push(NetavarkError::Message(format!(
                        "Invalid NETAVARK_DNS_PORT {}: {}",
                        port_string, e
                    )));
                    // default to 53 if there is a error here, we should not prevent cleanup because of it
                    53
                }
            },
            Err(_) => 53,
        };

        if Path::new(&aardvark_bin).exists() {
            // stop dns server first before netavark clears the interface
            let path = Path::new(&config_dir).join("aardvark-dns");
            if let Ok(path_string) = path.into_os_string().into_string() {
                let mut aardvark_interface =
                    Aardvark::new(path_string, rootless, aardvark_bin, dns_port);
                if let Err(err) =
                    aardvark_interface.delete_from_netavark_entries(network_options.clone())
                {
                    error_list.push(err.into());
                }
            } else {
                error_list.push(NetavarkError::msg(
                    "Unable to parse aardvark config directory",
                ));
            }
        }

        let firewall_driver = match firewall::get_supported_firewall_driver() {
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
                        "network options for network {} not found",
                        net_name
                    )));
                    continue;
                }
            };

            let driver = match get_network_driver(DriverInfo {
                firewall: firewall_driver.as_ref(),
                container_id: &network_options.container_id,
                container_name: &network_options.container_name,
                container_dns_servers: &network_options.dns_servers,
                netns_host: hostns.fd,
                netns_container: netns.fd,
                network,
                per_network_opts,
                port_mappings: &network_options.port_mappings,
                dns_port,
            }) {
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
