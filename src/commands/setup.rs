//! Configures the given network namespace with provided specs
use std::path::PathBuf;
use clap::{self, Clap};
use crate::network;
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

    pub fn exec(&self, input_file: PathBuf) {

        debug!("{:?}", "Setting up...");

        //TODO: Can we be more safe while converting PathBuf to string
        let _network_options = match network::NetworkOptions::load(&input_file.into_os_string().into_string().unwrap()) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        debug!("{:?}", "Setup complete");
        ()
    }
}
