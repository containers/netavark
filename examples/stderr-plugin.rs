//! This is just an example plugin, do not use it in production!

use netavark::{
    network::types,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};
fn main() {
    let info = Info::new("0.1.0-dev".to_owned(), API_VERSION.to_owned(), None);

    PluginExec::new(Exec {}, info).exec();
}

struct Exec {}

impl Plugin for Exec {
    fn create(
        &self,
        network: types::Network,
    ) -> Result<types::Network, Box<dyn std::error::Error>> {
        eprintln!("stderr create");
        Ok(network)
    }

    fn setup(
        &self,
        _netns: String,
        _opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        eprintln!("stderr setup");

        //  StatusBlock response
        let response = types::StatusBlock {
            dns_server_ips: None,
            dns_search_domains: None,
            interfaces: None,
        };

        Ok(response)
    }

    fn teardown(
        &self,
        _netns: String,
        _opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("stderr teardown");

        Ok(())
    }
}
