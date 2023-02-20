use clap::Parser;
use log::debug;
use netavark::dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig};
use tonic::Status;

#[derive(Parser, Debug)]
pub struct Setup {
    /// Network namespace path
    #[clap(forbid_empty_values = false, required = false)]
    config: NetworkConfig,
}

impl Setup {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    pub async fn exec(&self, p: &str) -> Result<Lease, Status> {
        debug!("{:?}", "Setting up...");
        debug!(
            "input: {:#?}",
            serde_json::to_string_pretty(&self.config.clone())
        );

        self.config.clone().get_lease(p).await
    }
}
