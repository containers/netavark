use crate::error::NetavarkResult;
use crate::network;
use clap::Parser;
use std::ffi::OsString;

#[derive(Parser, Debug)]
pub struct Create {}

impl Create {
    pub fn exec(
        &self,
        input_file: Option<OsString>,
        plugin_directories: Option<Vec<OsString>>,
    ) -> NetavarkResult<()> {
        let network_options = network::types::NetworkCreateConfig::load(input_file)?;

        let network = network::create_config::new_network(network_options, &plugin_directories)?;
        let response_json = serde_json::to_string(&network)?;
        println!("{response_json}");

        Ok(())
    }
}
