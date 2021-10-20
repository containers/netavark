use crate::firewall;
use crate::network::types;
use iptables;
use iptables::IPTables;
use log::debug;
use std::error::Error;

//  NAT constant for iptables
const NAT: &str = "nat";

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
        debug!("iptables");
        let network_name = net.network_interface.unwrap();
        // let ipt = self.conn;
        if let Some(subnet) = net.subnets {
            for network in subnet {
                // Basic object setup
                //  Check if the chain exists, if not - create it
                let chain_check = self.conn.chain_exists(NAT, &network_name);
                match chain_check {
                    Ok(true) => debug!("{} chain exists", &network_name),
                    Ok(false) => {
                        // The chain did not exist
                        debug!("need to create chain {}", network_name);
                        self.conn
                            .new_chain(NAT, &network_name)
                            .map(|_| debug!("chain {} created", network_name))?;
                    }
                    Err(e) => return Err(e),
                }

                // declare the rule
                let nat_rule = format!("-d {} -j ACCEPT", network.subnet.to_string()).to_string();
                let nat_check = self.conn.exists(NAT, &network_name, &nat_rule);
                match nat_check {
                    Ok(true) => debug!("nat rule {} exists for {}", nat_rule, network_name),
                    Ok(false) => {
                        // nat rule does not exists
                        self.conn.append(NAT, &network_name, &nat_rule).map(|_| {
                            debug!(
                                "created iptables nat rule for {}:{}",
                                &network_name, nat_rule
                            )
                        })?;
                    }
                    Err(e) => return Err(e),
                }

                //  Add first rule for the network
                let masq_rule = "-d 224.0.0.0/4 -j MASQUERADE".to_string();
                debug!("{}", masq_rule);
                let masq_check = self.conn.exists(NAT, &network_name, &masq_rule);
                match masq_check {
                    Ok(true) => debug!("nat rule {} exists for {}", network_name, masq_rule),
                    Ok(false) => {
                        // Need to create the masq rule
                        self.conn.append(NAT, &network_name, &masq_rule).map(|_| {
                            debug!(
                                "create iptables nat rule for {}:{}",
                                &network_name, masq_rule
                            )
                        })?;
                    }
                    Err(e) => return Err(e),
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
