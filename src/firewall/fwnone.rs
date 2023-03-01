use crate::firewall;
use crate::firewall::NetavarkResult;
use crate::network::internal_types::{
    PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};

// Iptables driver - uses direct iptables commands via the iptables crate.
pub struct Fwnone {}

pub fn new() -> NetavarkResult<Box<dyn firewall::FirewallDriver>> {
    Ok(Box::new(Fwnone {}))
}

impl firewall::FirewallDriver for Fwnone {
    fn setup_network(&self, _network_setup: SetupNetwork) -> NetavarkResult<()> {
        Ok(())
    }

    // teardown_network should only be called in the case of
    // a complete teardown.
    fn teardown_network(&self, _tear: TearDownNetwork) -> NetavarkResult<()> {
        Ok(())
    }

    fn setup_port_forward(&self, _setup_portfw: PortForwardConfig) -> NetavarkResult<()> {
        Ok(())
    }

    fn teardown_port_forward(&self, _tear: TeardownPortForward) -> NetavarkResult<()> {
        Ok(())
    }
}
