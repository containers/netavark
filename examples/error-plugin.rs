//! This is just an example plugin, do not use it in production!

use netavark::{
    network::types,
    new_error,
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
        _network: types::Network,
    ) -> Result<types::Network, Box<dyn std::error::Error>> {
        Err(new_error!("create error"))
    }

    fn setup(
        &self,
        _netns: String,
        _opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        Err(new_error!("setup error"))
    }

    fn teardown(
        &self,
        _netns: String,
        _opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Err(new_error!("teardown error"))
    }
}
