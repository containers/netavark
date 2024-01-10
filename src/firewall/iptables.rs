use crate::error::{NetavarkError, NetavarkResult};
use crate::firewall;
use crate::firewall::firewalld;
use crate::firewall::varktables::types::TeardownPolicy::OnComplete;
use crate::firewall::varktables::types::{
    create_network_chains, get_network_chains, get_port_forwarding_chains, TeardownPolicy,
};
use crate::network::internal_types::{
    PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};
use iptables;
use iptables::IPTables;

pub(crate) const MAX_HASH_SIZE: usize = 13;

// Iptables driver - uses direct iptables commands via the iptables crate.
pub struct IptablesDriver {
    conn: IPTables,
    conn6: IPTables,
}

pub fn new() -> NetavarkResult<Box<dyn firewall::FirewallDriver>> {
    // create an iptables connection
    let ipt = match iptables::new(false) {
        Ok(i) => i,
        Err(e) => return Err(NetavarkError::Message(format!("iptables: {e}"))),
    };
    let ipt6 = match iptables::new(true) {
        Ok(i) => i,
        Err(e) => return Err(NetavarkError::Message(format!("ip6tables: {e}"))),
    };
    let driver = IptablesDriver {
        conn: ipt,
        conn6: ipt6,
    };
    Ok(Box::new(driver))
}

impl firewall::FirewallDriver for IptablesDriver {
    fn driver_name(&self) -> &str {
        firewall::IPTABLES
    }

    fn setup_network(&self, network_setup: SetupNetwork) -> NetavarkResult<()> {
        if let Some(subnet) = network_setup.subnets {
            for network in subnet {
                let is_ipv6 = network.network().is_ipv6();
                let mut conn = &self.conn;
                if is_ipv6 {
                    conn = &self.conn6;
                }

                let chains = get_network_chains(
                    conn,
                    network,
                    &network_setup.network_hash_name,
                    is_ipv6,
                    network_setup.bridge_name.clone(),
                    network_setup.isolation,
                    network_setup.dns_port,
                );

                create_network_chains(chains)?;

                firewalld::add_firewalld_if_possible(&network);
            }
        }
        Ok(())
    }

    // teardown_network should only be called in the case of
    // a complete teardown.
    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        // Remove network specific general NAT rules
        if let Some(subnet) = tear.config.subnets {
            for network in subnet {
                let is_ipv6 = network.network().is_ipv6();
                let mut conn = &self.conn;
                if is_ipv6 {
                    conn = &self.conn6;
                }
                let chains = get_network_chains(
                    conn,
                    network,
                    &tear.config.network_hash_name,
                    is_ipv6,
                    tear.config.bridge_name.clone(),
                    tear.config.isolation,
                    tear.config.dns_port,
                );

                for c in &chains {
                    c.remove_rules(tear.complete_teardown)?;
                }
                for c in chains {
                    match &c.td_policy {
                        None => {}
                        Some(policy) => {
                            if tear.complete_teardown && *policy == OnComplete {
                                c.remove()?;
                            }
                        }
                    }
                }

                if tear.complete_teardown {
                    firewalld::rm_firewalld_if_possible(&network)
                }
            }
        }
        Result::Ok(())
    }

    fn setup_port_forward(&self, setup_portfw: PortForwardConfig) -> NetavarkResult<()> {
        if let Some(v4) = setup_portfw.container_ip_v4 {
            let subnet_v4 = match setup_portfw.subnet_v4 {
                Some(s) => s,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ipv4 address but provided but no v4 subnet provided",
                    )
                    .into())
                }
            };
            let chains =
                get_port_forwarding_chains(&self.conn, &setup_portfw, &v4, &subnet_v4, false)?;
            create_network_chains(chains)?;
        }
        if let Some(v6) = setup_portfw.container_ip_v6 {
            let subnet_v6 = match setup_portfw.subnet_v6 {
                Some(s) => s,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ipv6 address but provided but no v6 subnet provided",
                    )
                    .into())
                }
            };
            let chains =
                get_port_forwarding_chains(&self.conn6, &setup_portfw, &v6, &subnet_v6, true)?;
            create_network_chains(chains)?;
        };
        Result::Ok(())
    }

    fn teardown_port_forward(&self, tear: TeardownPortForward) -> NetavarkResult<()> {
        if let Some(v4) = tear.config.container_ip_v4 {
            let subnet_v4 = match tear.config.subnet_v4 {
                Some(s) => s,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ipv4 address but provided but no v4 subnet provided",
                    )
                    .into())
                }
            };

            let chains =
                get_port_forwarding_chains(&self.conn, &tear.config, &v4, &subnet_v4, false)?;

            for chain in &chains {
                chain.remove_rules(tear.complete_teardown)?;
            }
            for chain in &chains {
                if !tear.complete_teardown || !chain.create {
                    continue;
                }
                match &chain.td_policy {
                    None => {}
                    Some(policy) => {
                        if *policy == TeardownPolicy::OnComplete {
                            chain.remove()?;
                        }
                    }
                }
            }
        }

        if let Some(v6) = tear.config.container_ip_v6 {
            let subnet_v6 = match tear.config.subnet_v6 {
                Some(s) => s,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "ipv6 address but provided but no v6 subnet provided",
                    )
                    .into())
                }
            };

            let chains =
                get_port_forwarding_chains(&self.conn6, &tear.config, &v6, &subnet_v6, true)?;

            for chain in &chains {
                chain.remove_rules(tear.complete_teardown)?;
            }
            for chain in &chains {
                if !tear.complete_teardown || !chain.create {
                    continue;
                }
                match &chain.td_policy {
                    None => {}
                    Some(policy) => {
                        if *policy == TeardownPolicy::OnComplete {
                            chain.remove()?;
                        }
                    }
                }
            }
        }
        Result::Ok(())
    }
}
