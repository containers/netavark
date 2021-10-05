use std::path::PathBuf;
use clap::{self, Clap};
use crate::network;
use log::debug;

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

    pub fn exec(&self, input_file: PathBuf) {

        debug!("{:?}", "Tearing down..");
        //TODO: Can we be more safe while converting PathBuf to string
        let _network_options = match network::NetworkOptions::load(&input_file.into_os_string().into_string().unwrap()) {
            Ok(opts) => opts,
            Err(e) => panic!("{}", e),
        };

        debug!("{:?}", "Teardown complete");
        ()
    }
}
