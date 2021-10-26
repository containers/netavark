use crate::network;
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
        let _network_options = match network::types::NetworkOptions::load(&input_file) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        debug!("{:?}", "Teardown complete");
        Ok(())
    }
}
