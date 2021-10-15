use crate::firewall;
use crate::network::types;
use std::error::Error;
use zbus::Connection;

// Firewalld driver - uses a dbus connection to communicate with firewalld.
pub struct FirewallD {
    #[allow(dead_code)]
    conn: Connection,
}

pub fn new() -> Result<Box<dyn firewall::FirewallDriver>, Box<dyn Error>> {
    todo!();
}

impl firewall::FirewallDriver for FirewallD {
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
