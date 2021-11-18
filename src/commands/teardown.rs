use crate::error::NetavarkError;
use crate::firewall::iptables::MAX_HASH_SIZE;
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
                            firewall_driver.teardown_port_forward(
                                network.clone(),
                                &network_options.container_id,
                                i,
                                &net_name,
                                &id_network_hash,
                                per_network_opts,
                                // &id_network_hash.as_str()[0..MAX_HASH_SIZE],
                            )?;
                        }
                    }

                    // TODO teardown firewall if no interfaces connected to bridge!
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
