use crate::firewall;
use crate::network::internal_types::{PortForwardConfig, TearDownNetwork, TeardownPortForward};
use crate::network::{internal_types, types};
use log::debug;
use std::collections::HashMap;
use std::error::Error;
use std::vec::Vec;
use zbus::Connection;
use zvariant::{Array, Value};

const ZONENAME: &str = "netavark_zone";
const POLICYNAME: &str = "netavark_policy";

// Firewalld driver - uses a dbus connection to communicate with firewalld.
pub struct FirewallD {
    conn: Connection,
}

pub fn new(conn: Connection) -> Result<Box<dyn firewall::FirewallDriver>, Box<dyn Error>> {
    Ok(Box::new(FirewallD { conn }))
}

impl firewall::FirewallDriver for FirewallD {
    fn setup_network(
        &self,
        network_setup: internal_types::SetupNetwork,
    ) -> Result<(), Box<dyn Error>> {
        let mut need_reload = false;

        need_reload |= match create_zone_if_not_exist(&self.conn, ZONENAME) {
            Ok(b) => b,
            Err(e) => bail!("Error creating zone {}: {}", ZONENAME, e),
        };
        need_reload |= match add_policy_if_not_exist(&self.conn, POLICYNAME, ZONENAME) {
            Ok(b) => b,
            Err(e) => bail!("Error creating policy {}: {}", POLICYNAME, e),
        };

        if need_reload {
            debug!("Reloading firewalld config to bring up zone and policy");
            let _ = self.conn.call_method(
                Some("org.fedoraproject.FirewallD1"),
                "/org/fedoraproject/FirewallD1",
                Some("org.fedoraproject.FirewallD1"),
                "reload",
                &(),
            )?;
        }

        // MUST come after the reload; otherwise the zone we made might not be
        // in the running config.
        if let Some(nets) = network_setup.net.subnets {
            match add_source_subnets_to_zone(&self.conn, ZONENAME, nets) {
                Ok(_) => {}
                Err(e) => bail!("Error adding source subnets to zone {}: {}", ZONENAME, e),
            };
        }

        Ok(())
    }

    fn teardown_network(&self, _tear: TearDownNetwork) -> Result<(), Box<dyn Error>> {
        todo!();
    }

    fn setup_port_forward(&self, _setup_portfw: PortForwardConfig) -> Result<(), Box<dyn Error>> {
        todo!();
    }

    fn teardown_port_forward(
        &self,
        _teardown_pf: TeardownPortForward,
    ) -> Result<(), Box<dyn Error>> {
        todo!();
    }
}

// Create a firewalld zone to hold all our interfaces.
fn create_zone_if_not_exist(conn: &Connection, zone_name: &str) -> Result<bool, Box<dyn Error>> {
    debug!("Creating firewall zone {}", zone_name);

    // First, double-check if the zone exists in the running config.
    let zones_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.zone"),
        "getZones",
        &(),
    )?;
    let zones: Vec<&str> = match zones_msg.body() {
        Ok(b) => b,
        Err(e) => bail!("Error decoding DBus message for active zones: {}", e),
    };
    for (_, &zone) in zones.iter().enumerate() {
        if zone == zone_name {
            debug!("Zone exists and is running");
            return Ok(false);
        }
    }

    // Zone is not in running config - check permanent config.
    let perm_zones_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1/config",
        Some("org.fedoraproject.FirewallD1.config"),
        "getZoneNames",
        &(),
    )?;
    let zones_perm: Vec<&str> = match perm_zones_msg.body() {
        Ok(b) => b,
        Err(e) => bail!("Error decoding DBus message for permanent zones: {}", e),
    };
    for (_, &zone) in zones_perm.iter().enumerate() {
        if zone == zone_name {
            debug!("Zone exists and is not running");
            return Ok(true);
        }
    }

    // We can probably avoid the permanent zones check about if we create
    // unconditionally and parse error strings to look for "duplicate name"
    // errors - but I really don't want to deal with matching error strings and
    // the complexities that could entail.
    // TODO: We can add a description to the zone, should do that.
    let _ = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1/config",
        Some("org.fedoraproject.FirewallD1.config"),
        "addZone2",
        &(zone_name, HashMap::<&str, &Value>::new()),
    )?;

    Ok(true)
}

// Add source subnets to the zone.
fn add_source_subnets_to_zone(
    conn: &Connection,
    zone_name: &str,
    subnets: Vec<types::Subnet>,
) -> zbus::Result<()> {
    for net in subnets {
        debug!(
            "Adding subnet {} to zone {} as source",
            net.subnet, zone_name
        );

        let _ = conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.zone"),
            "changeZoneOfSource",
            &(zone_name, net.subnet.to_string()),
        )?;
    }

    Ok(())
}

// Add a policy object for the zone to handle masqeuradeing.
fn add_policy_if_not_exist(
    conn: &Connection,
    policy_name: &str,
    ingress_zone_name: &str,
) -> Result<bool, Box<dyn Error>> {
    debug!(
        "Adding firewalld policy {} (ingress zone {}, egress zone ANY)",
        policy_name, ingress_zone_name
    );

    // Does policy exist in running policies?
    let policies_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.policy"),
        "getPolicies",
        &(),
    )?;
    let policies: Vec<&str> = match policies_msg.body() {
        Ok(v) => v,
        Err(e) => bail!("Error decoding policy list response: {}", e),
    };
    for (_, &policy) in policies.iter().enumerate() {
        if policy == policy_name {
            debug!("Policy exists and is running");
            return Ok(false);
        }
    }

    // Does the policy exist in permanent policies?
    let perm_policies_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1/config",
        Some("org.fedoraproject.FirewallD1.config"),
        "getPolicyNames",
        &(),
    )?;
    let perm_policies: Vec<&str> = match perm_policies_msg.body() {
        Ok(v) => v,
        Err(e) => bail!("Error decoding permanent policy list response: {}", e),
    };
    for (_, &policy) in perm_policies.iter().enumerate() {
        if policy == policy_name {
            debug!("Policy exists and is not running");
            return Ok(true);
        }
    }

    // Options for the new policy
    let mut policy_opts = HashMap::<&str, &Value>::new();
    let egress_zones = Value::new(Array::from(vec!["ANY"]));
    let ingress_zones = Value::new(Array::from(vec![ingress_zone_name]));
    let masquerade = Value::new(true);
    let target = Value::new("ACCEPT");
    policy_opts.insert("egress_zones", &egress_zones);
    policy_opts.insert("ingress_zones", &ingress_zones);
    policy_opts.insert("masquerade", &masquerade);
    policy_opts.insert("target", &target);

    // Policy does not exist, create it.
    // Returns object path, which we don't need.
    let _ = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1/config",
        Some("org.fedoraproject.FirewallD1.config"),
        "addPolicy",
        &(policy_name, &policy_opts),
    )?;

    Ok(true)
}
