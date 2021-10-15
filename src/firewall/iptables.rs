use crate::firewall;
use crate::network::types;
use std::error::Error;

// Iptables driver - uses direct iptables commands via the iptables crate.
pub struct IptablesDriver {
    // TODO - populate with necessary fields
}

pub fn new() -> Result<Box<dyn firewall::FirewallDriver>, Box<dyn Error>> {
    todo!();
}

impl firewall::FirewallDriver for IptablesDriver {
    fn setup_network(&self, _net: types::Network) -> Result<(), Box<dyn Error>> {
        todo!();
    }

    fn teardown_network(&self, _net: types::Network) -> Result<(), Box<dyn Error>> {
        todo!();
    }

    fn setup_port_forward(
        &self,
        _container_id: &str,
        _port_mappings: Vec<types::PortMapping>,
        _container_ip: &str,
    ) -> Result<(), Box<dyn Error>> {
        todo!();
    }

    fn teardown_port_forward(
        &self,
        _container_id: &str,
        _port_mappings: Vec<types::PortMapping>,
        _container_ip: &str,
    ) -> Result<(), Box<dyn Error>> {
        todo!();
    }
}
