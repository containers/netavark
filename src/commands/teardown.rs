use crate::error::NetavarkError;
use crate::firewall::iptables::MAX_HASH_SIZE;
use crate::network::core_utils::CoreUtils;
use crate::network::internal_types::{TearDownNetwork, TeardownPortForward};
use crate::{firewall, network};
use clap::{self, Clap};
use log::debug;
use std::error::Error;

#[derive(Clap, Debug)]
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

    pub fn exec(&self, input_file: String) -> Result<(), Box<dyn Error>> {
        debug!("{:?}", "Tearing down..");
        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => {
                return Err(Box::new(NetavarkError {
                    error: format!("{}", e),
                    errno: 1,
                }));
            }
        };

        let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => panic!("{}", e.to_string()),
        };

        for (net_name, network) in network_options.network_info {
            debug!(
                "Setting up network {} with driver {}",
                net_name, network.driver
            );
            let interface_name: String = match network.network_interface.clone() {
                None => "".to_string(),
                Some(name) => name,
            };
            let count = CoreUtils::bridge_count_connected_interfaces(&interface_name)?;
            let complete_teardown = count.len() == 1;

            match network.driver.as_str() {
                "bridge" => {
                    let per_network_opts =
                        network_options.networks.get(&net_name).ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("network options for network {} not found", net_name),
                            )
                        })?;
                    //Remove container interfaces
                    network::core::Core::remove_interface_per_podman_network(
                        per_network_opts,
                        &network,
                        &self.network_namespace_path,
                    )?;
                    // Teardown basic firewall port forwarding

                    let id_network_hash = network::core_utils::CoreUtils::create_network_hash(
                        &net_name,
                        MAX_HASH_SIZE,
                    );

                    let port_bindings = network_options.port_mappings.clone();
                    match port_bindings {
                        None => {}
                        Some(i) => {
                            let td = TeardownPortForward {
                                network: network.clone(),
                                container_id: network_options.container_id.clone(),
                                port_mappings: i,
                                network_name: net_name,
                                id_network_hash,
                                options: (*per_network_opts).clone(),
                                complete_teardown,
                            };
                            firewall_driver.teardown_port_forward(td)?;
                        }
                    }
                    if complete_teardown {
                        let ctd = TearDownNetwork {
                            net: network,
                            complete_teardown,
                        };
                        firewall_driver.teardown_network(ctd)?;
                        // Teardown the interface now
                        network::core_utils::CoreUtils::remove_interface(&interface_name)?;
                    }
                }
                "macvlan" => {
                    let per_network_opts =
                        network_options.networks.get(&net_name).ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("network options for network {} not found", net_name),
                            )
                        })?;
                    //Remove container interfaces
                    network::core::Core::remove_interface_per_podman_network(
                        per_network_opts,
                        &network,
                        &self.network_namespace_path,
                    )?;
                }
                // unknown driver
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unknown network driver {}", network.driver),
                    )
                    .into());
                }
            }
        }

        debug!("{:?}", "Teardown complete");
        Ok(())
    }
}
