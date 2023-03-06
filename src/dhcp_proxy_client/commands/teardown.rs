use clap::Parser;
use log::debug;
use netavark::dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig};
use tonic::Status;

#[derive(Parser, Debug)]
pub struct Teardown {
    /// Network namespace path
    #[clap(forbid_empty_values = true, required = true)]
    config: NetworkConfig,
}

impl Teardown {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    pub async fn exec(&self, p: &str) -> Result<Lease, Status> {
        debug!("Entering teardown");
        self.config.clone().drop_lease(p).await
    }
}
