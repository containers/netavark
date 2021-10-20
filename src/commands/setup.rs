//! Configures the given network namespace with provided specs
use crate::firewall;
use crate::network;
use clap::{self, Clap};
use log::debug;

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

    pub fn exec(&self, input_file: String) {
        debug!("{:?}", "Setting up...");

        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => panic!("{}", e.to_string()),
        };

        // TODO: SETUP SYSCTLS

        // Perform per-network setup
        for (net_name, network) in network_options.network_info {
            debug!("Setting up network {}", net_name);
            // Setup up network interface
            //make_network_interface(net_name, network);

            // Setup basic firewall rules for each network.
            match firewall_driver.setup_network(network) {
                Ok(_) => {}
                Err(e) => panic!("{}", e.to_string()),
            };
        }

        // TODO: Set up port forwarding. How? What network do we point to?

        debug!("{:?}", "Setup complete");
        //()
    }
}
