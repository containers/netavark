use crate::firewall;
use crate::network::types;
use iptables;
use iptables::IPTables;
use log::debug;
use std::error::Error;

//  NAT constant for iptables
const NAT: &str = "nat";
const POSTROUTING: &str = "POSTROUTING";
const PRIV_CHAIN_NAME: &str = "NETAVARK_FORWARD";
const FILTER: &str = "filter";

// Iptables driver - uses direct iptables commands via the iptables crate.
pub struct IptablesDriver {
    conn: IPTables,
}

pub fn new() -> Result<Box<dyn firewall::FirewallDriver>, Box<dyn Error>> {
    // create an iptables connection
    let ipt = iptables::new(false)?;
    let driver = IptablesDriver { conn: ipt };
    Ok(Box::new(driver))
}

impl firewall::FirewallDriver for IptablesDriver {
    fn setup_network(&self, net: types::Network) -> Result<(), Box<dyn Error>> {
        let network_name = net.network_interface.unwrap();
        if let Some(subnet) = net.subnets {
            for network in subnet {
                // Check if the chain exists, if not - create it
                // Note: while there is an API provided to check if a chain exists in a table
                // by iptables, it, for some reason, is slow.  Instead we just get a list of
                // chains in a table and iterate.  Same is being done in golang implementations
                let nat_chains = self.conn.list_chains(NAT)?;
                if !nat_chains.iter().any(|i| i == &network_name) {
                    self.conn
                        .new_chain(NAT, &network_name)
                        .map(|_| debug_chain_create(NAT, &network_name))?;
                } else {
                    debug_chain_exists(NAT, &network_name);
                }

                // declare the rule
                let nat_rule = format!("-d {} -j ACCEPT", network.subnet.to_string()).to_string();
                let nat_check = self.conn.exists(NAT, &network_name, &nat_rule);
                match nat_check {
                    Ok(true) => debug_rule_exists(NAT, &network_name, nat_rule),
                    Ok(false) => {
                        // nat rule does not exists
                        self.conn
                            .append(NAT, &network_name, &nat_rule)
                            .map(|_| debug_rule_create(NAT, &network_name, nat_rule))?;
                    }
                    Err(e) => return Err(e),
                }

                //  Add first rule for the network
                let masq_rule = "! -d 224.0.0.0/4 -j MASQUERADE".to_string();
                debug!("{}", masq_rule);
                let masq_check = self.conn.exists(NAT, &network_name, &masq_rule);
                match masq_check {
                    Ok(true) => debug_rule_exists(NAT, &network_name, masq_rule),
                    Ok(false) => {
                        // Need to create the masq rule
                        self.conn
                            .append(NAT, &network_name, &masq_rule)
                            .map(|_| debug_rule_create(NAT, &network_name, masq_rule))?;
                    }
                    Err(e) => return Err(e),
                }

                //  Add POSTROUTING rule
                let jump_podman_rule = format!(
                    "--source {} --jump {}",
                    network.subnet.to_string(),
                    network_name
                )
                .to_string();
                let jump_check = self
                    .conn
                    .exists(&network_name, POSTROUTING, &jump_podman_rule);
                match jump_check {
                    Ok(true) => debug_rule_exists(NAT, POSTROUTING, jump_podman_rule),
                    Ok(false) => {
                        self.conn
                            .append(NAT, POSTROUTING, &jump_podman_rule)
                            .map(|_| debug_rule_create(NAT, POSTROUTING, jump_podman_rule))?;
                    }
                    Err(e) => return Err(e),
                }

                // Check if our private chain exists, if not create
                // Note: while there is an API provided to check if a chain exists in a table
                // by iptables, it, for some reason, is slow.  Instead we just get a list of
                // chains in a table and iterate.  Same is being done in golang implementations
                let filter_chains = self.conn.list_chains(FILTER)?;
                if !filter_chains.iter().any(|i| i == PRIV_CHAIN_NAME) {
                    self.conn
                        .new_chain(FILTER, PRIV_CHAIN_NAME)
                        .map(|_| debug_chain_create(FILTER, PRIV_CHAIN_NAME))?;
                } else {
                    debug_chain_exists(FILTER, PRIV_CHAIN_NAME);
                }

                //  Create netavark firewall rule
                let netavark_fw = format!(
                    "-m comment --comment 'netavark firewall plugin rules' -j {}",
                    PRIV_CHAIN_NAME
                );
                if !self.conn.exists(FILTER, "FORWARD", &netavark_fw)? {
                    self.conn
                        .insert(FILTER, "FORWARD", &netavark_fw, 1)
                        .map(|_| debug_rule_create(FILTER, "FORWARD", netavark_fw))?;
                }
                // Create incoming traffic rule
                // CNI did this by IP address, this is implemented per subnet
                let allow_incoming_rule = format!(
                    "-d {} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                    network.subnet.to_string()
                );
                if !self
                    .conn
                    .exists(FILTER, PRIV_CHAIN_NAME, &allow_incoming_rule)?
                {
                    let _ = self
                        .conn
                        .append(FILTER, PRIV_CHAIN_NAME, &allow_incoming_rule)
                        .map(|_| debug_rule_create(FILTER, PRIV_CHAIN_NAME, allow_incoming_rule))?;
                } else {
                    debug_rule_exists(FILTER, PRIV_CHAIN_NAME, allow_incoming_rule);
                }

                // Create outgoing traffic rule
                // CNI did this by IP address, this is implemented per subnet
                let allow_outgoing_rule = format!("-s {} -j ACCEPT", network.subnet.to_string());
                if !self
                    .conn
                    .exists(FILTER, PRIV_CHAIN_NAME, &allow_outgoing_rule)?
                {
                    self.conn
                        .append(FILTER, PRIV_CHAIN_NAME, &allow_outgoing_rule)
                        .map(|_| debug_rule_create(FILTER, PRIV_CHAIN_NAME, allow_outgoing_rule))?;
                } else {
                    debug_rule_exists(FILTER, PRIV_CHAIN_NAME, allow_outgoing_rule);
                }
            }
        }
        Ok(())
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
fn debug_chain_create(table: &str, chain: &str) {
    debug!("chain {} created on table {}", chain, table);
}

fn debug_chain_exists(table: &str, chain: &str) {
    debug!("chain {} exists on table {}", chain, table);
}

fn debug_rule_create(table: &str, chain: &str, rule: String) {
    debug!(
        "rule {} created on table {} and chain {}",
        rule, table, chain
    );
}

fn debug_rule_exists(table: &str, chain: &str, rule: String) {
    debug!(
        "rule {} exists on table {} and chain {}",
        rule, table, chain
    );
}
