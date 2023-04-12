use clap::Parser;
use log::debug;
use netavark::{
    dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig},
    error::NetavarkError,
};

#[derive(Parser, Debug)]
pub struct Teardown {}

impl Teardown {
    pub async fn exec(&self, p: &str, config: NetworkConfig) -> Result<Lease, NetavarkError> {
        debug!("Entering teardown");
        config.clone().drop_lease(p).await
    }
}
