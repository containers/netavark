use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkErrorList, NetavarkResult};
use crate::network::core_utils;
use crate::network::driver::{get_network_driver, DriverInfo};

use crate::{firewall, network};
use clap::Parser;
use log::debug;
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
        input_file: Option<String>,
        config_dir: &str,
        aardvark_bin: String,
        rootless: bool,
    ) -> NetavarkResult<()> {
        debug!("{:?}", "Tearing down..");
        let network_options = network::types::NetworkOptions::load(input_file)?;

        let mut error_list = NetavarkErrorList::new();

        let dns_port = core_utils::get_netavark_dns_port()?;

        if Path::new(&aardvark_bin).exists() {
            // stop dns server first before netavark clears the interface
            let path = Path::new(&config_dir).join("aardvark-dns");
            if let Ok(path_string) = path.into_os_string().into_string() {
                let aardvark_interface =
                    Aardvark::new(path_string, rootless, aardvark_bin, dns_port);
                if let Err(err) = aardvark_interface.delete_from_netavark_entries(&network_options)
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
                netns_path: &self.network_namespace_path,
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
