//! Configures the given network namespace with provided specs
use crate::error::{NetavarkError, NetavarkErrorCode};
use crate::firewall;
use crate::firewall::iptables::MAX_HASH_SIZE;
use crate::network;
use crate::network::core_utils::CoreUtils;
use crate::network::internal_types::{SetupNetwork, SetupPortForward};
use crate::network::{core_utils, types};
use anyhow::anyhow;
use clap::{self, Clap};
use log::debug;
use std::collections::HashMap;
use std::error::Error;

const IPV4_FORWARD: &str = "net.ipv4.ip_forward";

#[derive(Clap, Debug)]
pub struct Setup {
    /// Network namespace path
    #[clap(forbid_empty_values = true, required = true)]
    network_namespace_path: String,
}

impl Setup {
    /// The setup command configures the given network namespace with the given configuration, creating any interfaces and firewall rules necessary.
    pub fn new(network_namespace_path: String) -> Self {
        Self {
            network_namespace_path,
        }
    }

    pub fn exec(&self, input_file: String) -> Result<(), Box<dyn Error>> {
        match network::validation::ns_checks(&self.network_namespace_path) {
            Ok(_) => (),
            Err(e) => {
                bail!("invalid namespace path: {}", e);
            }
        }
        debug!("{:?}", "Setting up...");

        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => {
                return Err(Box::new(NetavarkError {
                    error: format!("failed to load network options: {}", e),
                    errno: 1,
                }));
            }
        };

        let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => panic!("{}", e.to_string()),
        };

        // Sysctl setup
        // set ip forwarding to 1
        core_utils::CoreUtils::apply_sysctl_value(IPV4_FORWARD, "1")?;

        let mut response: HashMap<String, types::StatusBlock> = HashMap::new();

        // Perform per-network setup
        for (net_name, network) in network_options.network_info.iter() {
            debug!(
                "Setting up network {} with driver {}",
                net_name, network.driver
            );

            match network.driver.as_str() {
                "bridge" => {
                    let per_network_opts =
                        network_options.networks.get(net_name).ok_or_else(|| {
                            anyhow!(NetavarkErrorCode::ErrNoNetworkOptions {
                                network_name: net_name.to_string()
                            })
                        })?;
                    //Configure Bridge and veth_pairs
                    let status_block = network::core::Core::bridge_per_podman_network(
                        per_network_opts,
                        network,
                        &self.network_namespace_path,
                    )?;
                    response.insert(net_name.to_owned(), status_block);

                    let id_network_hash = CoreUtils::create_network_hash(net_name, MAX_HASH_SIZE);
                    let sn = SetupNetwork {
                        net: (*network).clone(),
                        network_hash_name: id_network_hash.clone(),
                    };
                    firewall_driver.setup_network(sn)?;

                    let port_bindings = network_options.port_mappings.clone();
                    match port_bindings {
                        None => {}
                        Some(i) => {
                            let spf = SetupPortForward {
                                net: (*network).clone(),
                                container_id: network_options.container_id.clone(),
                                port_mappings: i,
                                network_name: (*net_name).clone(),
                                network_hash_name: id_network_hash,
                                options: (*per_network_opts).clone(),
                            };
                            firewall_driver.setup_port_forward(spf)?;
                        }
                    }
                }
                "macvlan" => {
                    let per_network_opts =
                        network_options.networks.get(net_name).ok_or_else(|| {
                            anyhow!(NetavarkErrorCode::ErrNoNetworkOptions {
                                network_name: net_name.to_string()
                            })
                        })?;
                    //Configure Bridge and veth_pairs
                    let status_block = network::core::Core::macvlan_per_podman_network(
                        per_network_opts,
                        network,
                        &self.network_namespace_path,
                    )?;
                    response.insert(net_name.to_owned(), status_block);
                }
                // unknown driver
                _ => {
                    return Err(NetavarkErrorCode::ErrUnknownNetworkDriver {
                        expected: network.driver.to_string(),
                    }
                    .into());
                }
            }
        }

        debug!("{:#?}", response);
        let response_json = serde_json::to_string(&response)?;
        println!("{}", response_json);
        debug!("{:?}", "Setup complete");
        Ok(())
    }
}
