//! Configures the given network namespace with provided specs
use crate::network;
use clap::{self, Clap};
use log::debug;
use std::path::PathBuf;

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

    pub fn exec(&self, input_file: PathBuf) {
        debug!("{:?}", "Setting up...");

        let _network_options = match network::types::NetworkOptions::load(
            &input_file
                .into_os_string()
                .into_string()
                .expect("Failed to convert PathBuf to string during network setup"),
        ) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        debug!("{:?}", "Setup complete");
        //()
    }
}
