use crate::network::types;
use std::error::Error;

pub mod firewalld;
pub mod iptables;

// Firewall drivers have the ability to set up per-network firewall forwarding
// and port mappings.
pub trait FirewallDriver {
    // Set up firewall rules for the given network,
    fn setup_network(&self, net: types::Network) -> Result<(), Box<dyn Error>>;
    // Tear down firewall rules for the given network.
    fn teardown_network(&self, net: types::Network) -> Result<(), Box<dyn Error>>;

    // Set up port-forwarding firewall rules for a given container.
    fn setup_port_forward(
        &self,
        container_id: &str,
        port_mappings: Vec<types::PortMapping>,
        container_ip: &str,
    ) -> Result<(), Box<dyn Error>>;
    // Tear down port-forwarding firewall rules for a single container.
    fn teardown_port_forward(
        &self,
        container_id: &str,
        port_mappings: Vec<types::PortMapping>,
        container_ip: &str,
    ) -> Result<(), Box<dyn Error>>;
}

// Types of firewall backend
enum FirewallImpl {
    Iptables,
    #[allow(dead_code)]
    Firewalld,
    #[allow(dead_code)]
    Nftables,
}

// What firewall implementations does this system support?
fn get_firewall_impl() -> FirewallImpl {
    // TODO: this should not just return iptables.
    FirewallImpl::Iptables
}

// Get the preferred firewall implementation for the current system
// configuration.
pub fn get_supported_firewall_driver() -> Result<Box<dyn FirewallDriver>, Box<dyn Error>> {
    match get_firewall_impl() {
        FirewallImpl::Iptables => iptables::new(),
        FirewallImpl::Firewalld => firewalld::new(),
        FirewallImpl::Nftables => {
            bail!("nftables support not presently available");
        }
    }
}
