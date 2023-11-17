use crate::commands::get_config_dir;
use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkResult};
use crate::network::core_utils;

use clap::builder::NonEmptyStringValueParser;
use clap::Parser;
use log::debug;
use std::ffi::OsString;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct Update {
    /// Network name to update
    #[clap(required = true, value_parser = NonEmptyStringValueParser::new())]
    network_name: String,
    /// DNS Servers to update for the network
    #[clap(long, required = true)]
    network_dns_servers: Vec<String>,
}

impl Update {
    /// Updates network dns servers for an already configured network
    pub fn new(network_name: String, network_dns_servers: Vec<String>) -> Self {
        Self {
            network_name,
            network_dns_servers,
        }
    }

    pub fn exec(
        &mut self,
        config_dir: Option<OsString>,
        aardvark_bin: OsString,
        rootless: bool,
    ) -> NetavarkResult<()> {
        let dns_port = core_utils::get_netavark_dns_port()?;
        let config_dir = get_config_dir(config_dir, "update")?;
        if Path::new(&aardvark_bin).exists() {
            let path = Path::new(&config_dir).join("aardvark-dns");

            let aardvark_interface = Aardvark::new(path, rootless, aardvark_bin, dns_port);
            // if empty network_dns_servers are passed, pass empty array instead of `[""]`
            if self.network_dns_servers.len() == 1 && self.network_dns_servers[0].is_empty() {
                self.network_dns_servers = Vec::new();
            }
            if let Err(err) = aardvark_interface
                .modify_network_dns_servers(&self.network_name, &self.network_dns_servers)
            {
                return Err(NetavarkError::wrap(
                    "unable to modify network dns servers",
                    err,
                ));
            }
        }

        debug!("Network update complete");
        Ok(())
    }
}
