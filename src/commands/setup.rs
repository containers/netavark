//! Configures the given network namespace with provided specs
use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkResult};
use crate::firewall;
use crate::network;
use crate::network::driver::{get_network_driver, DriverInfo};
use crate::network::types;
use clap::Parser;
use log::{debug, error, info};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::os::unix::prelude::AsRawFd;
use std::path::Path;

#[derive(Parser, Debug)]
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

    pub fn exec(
        &self,
        input_file: String,
        config_dir: String,
        aardvark_bin: String,
        rootless: bool,
    ) -> NetavarkResult<()> {
        match network::validation::ns_checks(&self.network_namespace_path) {
            Ok(_) => (),
            Err(e) => {
                return Err(NetavarkError::wrap_str("invalid namespace path", e));
            }
        }
        debug!("{:?}", "Setting up...");

        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => {
                // TODO: Convert this to a proper typed error
                return Err(NetavarkError::Message(format!(
                    "failed to load network options: {}",
                    e
                )));
            }
        };

        let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => return Err(e),
        };

        let mut response: HashMap<String, types::StatusBlock> = HashMap::new();

        let dns_port = match env::var("NETAVARK_DNS_PORT") {
            Ok(port_string) => match port_string.parse() {
                Ok(port) => port,
                Err(e) => {
                    return Err(NetavarkError::Message(format!(
                        "Invalid NETAVARK_DNS_PORT {}: {}",
                        port_string, e
                    )))
                }
            },
            Err(_) => 53,
        };

        let f = File::open(&self.network_namespace_path)?;
        let ns_fd = f.as_raw_fd();

        let mut drivers = Vec::with_capacity(network_options.network_info.len());

        // Perform per-network setup
        for (net_name, network) in network_options.network_info.iter() {
            let per_network_opts = network_options.networks.get(net_name).ok_or_else(|| {
                NetavarkError::Message(format!(
                    "network options for network {} not found",
                    net_name
                ))
            })?;

            let mut driver = get_network_driver(DriverInfo {
                firewall: firewall_driver.as_ref(),
                container_id: &network_options.container_id,
                netns_container: ns_fd,
                network,
                per_network_opts,
                port_mappings: &network_options.port_mappings,
                dns_port,
            })?;

            // validate before we do anything
            driver.validate()?;

            drivers.push(driver);
        }

        // Only now after we validated all drivers we setup each.
        // If there is an error we have to tear down all previous drivers.
        for (i, driver) in drivers.iter().enumerate() {
            let (status, _) = match driver.setup() {
                Ok((s, a)) => (s, a),
                Err(e) => {
                    // now teardown the already setup drivers
                    for dri in drivers.iter().take(i) {
                        match dri.teardown() {
                            Ok(_) => {}
                            Err(e) => {
                                error!(
                                    "failed to cleanup previous networks after setup failed: {}",
                                    e
                                )
                            }
                        };
                    }
                    return Err(e);
                }
            };

            let _ = response.insert(driver.network_name(), status);
        }

        if Path::new(&aardvark_bin).exists() {
            let path = Path::new(&config_dir).join("aardvark-dns");

            match fs::create_dir(path.as_path()) {
                Ok(_) => {}
                // ignore error when path already exists
                Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to create aardvark-dns directory: {}", e),
                    )
                    .into());
                }
            }

            let path_string = match path.into_os_string().into_string() {
                Ok(path) => path,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to convert path to String",
                    )
                    .into());
                }
            };

            let mut aardvark_interface =
                Aardvark::new(path_string, rootless, aardvark_bin, dns_port);

            if let Err(er) = aardvark_interface.commit_netavark_entries(
                network_options.container_name,
                network_options.container_id.clone(),
                network_options.networks.clone(),
                response.clone(),
            ) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error while applying dns entries: {}", er),
                )
                .into());
            }
        } else {
            info!("dns disabled because aardvark-dns path does not exists");
        }
        debug!("{:#?}", response);
        let response_json = serde_json::to_string(&response)?;
        println!("{}", response_json);
        debug!("{:?}", "Setup complete");
        Ok(())
    }
}
