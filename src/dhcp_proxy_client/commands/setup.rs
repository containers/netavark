use clap::Parser;
use log::debug;
use netavark::{
    dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig},
    error::NetavarkError,
};

#[derive(Parser, Debug)]
pub struct Setup {}

impl Setup {
    pub async fn exec(&self, p: &str, config: NetworkConfig) -> Result<Lease, NetavarkError> {
        debug!("{:?}", "Setting up...");
        debug!("input: {:#?}", serde_json::to_string_pretty(&config));

        config.clone().get_lease(p).await
    }
}
