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
use crate::network::types;
use iptables;
use iptables::IPTables;
use log::{debug, warn};
use zbus::blocking::Connection;

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
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    let ipt6 = match iptables::new(true) {
        Ok(i) => i,
        Err(e) => return Err(NetavarkError::Message(e.to_string())),
    };
    let driver = IptablesDriver {
        conn: ipt,
        conn6: ipt6,
    };
    Ok(Box::new(driver))
}

impl firewall::FirewallDriver for IptablesDriver {
    fn setup_network(&self, network_setup: SetupNetwork) -> NetavarkResult<()> {
        let interface = match network_setup.net.network_interface {
            Some(iface) => iface,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to get interface".to_string(),
                )
                .into())
            }
        };

        if let Some(subnet) = network_setup.net.subnets {
            for network in subnet {
                let is_ipv6 = network.subnet.network().is_ipv6();
                let mut conn = &self.conn;
                if is_ipv6 {
                    conn = &self.conn6;
                }

                let chains = get_network_chains(
                    conn,
                    network.subnet,
                    &network_setup.network_hash_name,
                    is_ipv6,
                    interface.to_string(),
                    network_setup.isolation,
                );

                create_network_chains(chains)?;

                add_firewalld_if_possible(&network);
            }
        }
        Ok(())
    }

    // teardown_network should only be called in the case of
    // a complete teardown.
    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        let interface = match tear.config.net.network_interface {
            Some(iface) => iface,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to get interface".to_string(),
                )
                .into())
            }
        };

        // Remove network specific general NAT rules
        if let Some(subnet) = tear.config.net.subnets {
            for network in subnet {
                let is_ipv6 = network.subnet.network().is_ipv6();
                let mut conn = &self.conn;
                if is_ipv6 {
                    conn = &self.conn6;
                }
                let chains = get_network_chains(
                    conn,
                    network.subnet,
                    &tear.config.network_hash_name,
                    is_ipv6,
                    interface.to_string(),
                    tear.config.isolation,
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
                    rm_firewalld_if_possible(&network)
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
                get_port_forwarding_chains(&self.conn, &setup_portfw, &v4, &subnet_v4, false);
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
                get_port_forwarding_chains(&self.conn6, &setup_portfw, &v6, &subnet_v6, true);
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
                get_port_forwarding_chains(&self.conn, &tear.config, &v4, &subnet_v4, false);

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
                get_port_forwarding_chains(&self.conn6, &tear.config, &v6, &subnet_v6, true);

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

/// Check if firewalld is running
fn is_firewalld_running(conn: &Connection) -> bool {
    conn.call_method(
        Some("org.freedesktop.DBus"),
        "/org/freedesktop/DBus",
        Some("org.freedesktop.DBus"),
        "GetNameOwner",
        &"org.fedoraproject.FirewallD1",
    )
    .is_ok()
}

/// If possible, add a firewalld rule to allow traffic.
/// Ignore all errors, beyond possibly logging them.
fn add_firewalld_if_possible(net: &types::Subnet) {
    let conn = match Connection::system() {
        Ok(conn) => conn,
        Err(_) => return,
    };
    if !is_firewalld_running(&conn) {
        return;
    }
    debug!(
        "Adding firewalld rules for network {}",
        net.subnet.to_string()
    );

    match firewalld::add_source_subnets_to_zone(&conn, "trusted", vec![net.clone()]) {
        Ok(_) => {}
        Err(e) => warn!(
            "Error adding subnet {} from firewalld trusted zone: {}",
            net.subnet.to_string(),
            e
        ),
    }
}

// If possible, remove a firewalld rule to allow traffic.
// Ignore all errors, beyond possibly logging them.
fn rm_firewalld_if_possible(net: &types::Subnet) {
    let conn = match Connection::system() {
        Ok(conn) => conn,
        Err(_) => return,
    };
    if !is_firewalld_running(&conn) {
        return;
    }
    debug!(
        "Removing firewalld rules for IPs {}",
        net.subnet.to_string()
    );
    match conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.zone"),
        "removeSource",
        &("trusted", net.subnet.to_string()),
    ) {
        Ok(_) => {}
        Err(e) => warn!(
            "Error removing subnet {} from firewalld trusted zone: {}",
            net.subnet.to_string(),
            e
        ),
    };
}
