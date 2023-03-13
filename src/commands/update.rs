use crate::dns::aardvark::Aardvark;
use crate::error::{NetavarkError, NetavarkResult};
use crate::network::core_utils;

use clap::Parser;
use log::debug;
use std::path::Path;

#[derive(Parser, Debug)]
pub struct Update {
    /// Network name to update
    #[clap(forbid_empty_values = true, required = true)]
    network_name: String,
    /// DNS Servers to update for the network
    #[clap(long, required = true, forbid_empty_values = false)]
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
        &self,
        config_dir: &str,
        aardvark_bin: String,
        rootless: bool,
    ) -> NetavarkResult<()> {
        let dns_port = core_utils::get_netavark_dns_port()?;

        if Path::new(&aardvark_bin).exists() {
            let path = Path::new(&config_dir).join("aardvark-dns");
            if let Ok(path_string) = path.into_os_string().into_string() {
                let aardvark_interface =
                    Aardvark::new(path_string, rootless, aardvark_bin, dns_port);
                if let Err(err) = aardvark_interface
                    .modify_network_dns_servers(&self.network_name, &self.network_dns_servers)
                {
                    return Err(NetavarkError::wrap(
                        "unable to modify network dns servers",
                        NetavarkError::Io(err),
                    ));
                }
            } else {
                return Err(NetavarkError::msg(
                    "Unable to parse aardvark config directory",
                ));
            }
        }

        debug!("Network update complete");
        Ok(())
    }
}
