//! Configures the given network namespace with provided specs
use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkResult};
use crate::firewall;
use crate::network::driver::{get_network_driver, DriverInfo};
use crate::network::netlink::LinkID;
use crate::network::{self};
use crate::network::{core_utils, types};

use clap::Parser;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs::{self};
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
        input_file: Option<String>,
        config_dir: &str,
        aardvark_bin: String,
        rootless: bool,
    ) -> NetavarkResult<()> {
        match network::validation::ns_checks(&self.network_namespace_path) {
            Ok(_) => (),
            Err(e) => {
                return Err(NetavarkError::wrap("invalid namespace path", e));
            }
        }
        debug!("{:?}", "Setting up...");
        let network_options = network::types::NetworkOptions::load(input_file)?;

        let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => return Err(e),
        };

        let mut response: HashMap<String, types::StatusBlock> = HashMap::new();

        let dns_port = core_utils::get_netavark_dns_port()?;

        let (mut hostns, mut netns) =
            core_utils::open_netlink_sockets(&self.network_namespace_path)?;

        // setup loopback, it should be safe to assume that 1 is the loopback index
        netns.netlink.set_up(LinkID::ID(1))?;

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
                container_name: &network_options.container_name,
                container_dns_servers: &network_options.dns_servers,
                netns_host: hostns.fd,
                netns_container: netns.fd,
                netns_path: &self.network_namespace_path,
                network,
                per_network_opts,
                port_mappings: &network_options.port_mappings,
                dns_port,
            })?;

            // validate before we do anything
            driver.validate()?;

            drivers.push(driver);
        }

        let mut aardvark_entries = Vec::new();

        // Only now after we validated all drivers we setup each.
        // If there is an error we have to tear down all previous drivers.
        for (i, driver) in drivers.iter().enumerate() {
            let (status, aardvark_entry) =
                match driver.setup((&mut hostns.netlink, &mut netns.netlink)) {
                    Ok((s, a)) => (s, a),
                    Err(e) => {
                        // now teardown the already setup drivers
                        for dri in drivers.iter().take(i) {
                            match dri.teardown((&mut hostns.netlink, &mut netns.netlink)) {
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
            if let Some(a) = aardvark_entry {
                aardvark_entries.push(a);
            }
        }

        if Path::new(&aardvark_bin).exists() && !aardvark_entries.is_empty() {
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

            let aardvark_interface = Aardvark::new(path_string, rootless, aardvark_bin, dns_port);

            if let Err(er) = aardvark_interface.commit_netavark_entries(aardvark_entries) {
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
