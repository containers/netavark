//! Configures the given network namespace with provided specs
//use crate::firewall;
use crate::network;
use clap::{self, Clap};
use log::debug;
use std::error::Error;
use sysctl::Sysctl;
use sysctl::SysctlError;

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
        network::validation::ns_checks(&self.network_namespace_path);

        debug!("{:?}", "Setting up...");

        let network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        // TODO: Remove comments for firewall setup when its in working state. NO_OP as of now.
        /*let firewall_driver = match firewall::get_supported_firewall_driver() {
            Ok(driver) => driver,
            Err(e) => panic!("{}", e.to_string()),
        };

        // Perform per-network setup
        for (net_name, network) in network_options.network_info {
            debug!("Setting up network {}", net_name);
            // Setup up network interface
            //make_network_interface(net_name, network);

            // Setup basic firewall rules for each network.
            firewall_driver.setup_network(network)?;
        }*/

        // Sysctl setup
        // set ip forwarding to 1 if not already
        let sysctl_ipv4 = get_sysctl_value(IPV4_FORWARD)?;
        if sysctl_ipv4 != *"1" {
            set_sysctl_value(IPV4_FORWARD, "1")?;
        }

        //Configure Bridge and veth_pairs
        network::core::Core::bridge_per_podman_network(
            &network_options,
            &self.network_namespace_path,
        )?;

        // TODO: Set up port forwarding. How? What network do we point to?

        debug!("{:?}", "Setup complete");
        Ok(())
    }
}
// get a sysctl value by the value's namespace
fn get_sysctl_value(ns_value: &str) -> Result<String, SysctlError> {
    debug!("Getting sysctl value for {}", ns_value);
    let ctl = sysctl::Ctl::new(ns_value)?;
    ctl.value_string()
}

// set a sysctl value by value's namespace
fn set_sysctl_value(ns_value: &str, val: &str) -> Result<String, SysctlError> {
    debug!("Setting sysctl value for {} to {}", ns_value, val);
    let ctl = sysctl::Ctl::new(ns_value)?;
    ctl.set_value_string(val)
}
