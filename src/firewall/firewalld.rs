use crate::error::{NetavarkError, NetavarkResult};
use crate::firewall;
use crate::network::internal_types::{PortForwardConfig, TearDownNetwork, TeardownPortForward};
use crate::network::types::PortMapping;
use crate::network::{internal_types, types};
use core::convert::TryFrom;
use log::{debug, info};
use std::collections::HashMap;
use std::vec::Vec;
use zbus::{
    blocking::Connection,
    zvariant::{Array, Signature, Value},
};

const ZONENAME: &str = "netavark_zone";
const POLICYNAME: &str = "netavark_policy";
const PORTPOLICYNAME: &str = "netavark_portfwd";

// Firewalld driver - uses a dbus connection to communicate with firewalld.
pub struct FirewallD {
    conn: Connection,
}

pub fn new(conn: Connection) -> Result<Box<dyn firewall::FirewallDriver>, NetavarkError> {
    Ok(Box::new(FirewallD { conn }))
}

impl firewall::FirewallDriver for FirewallD {
    fn setup_network(&self, network_setup: internal_types::SetupNetwork) -> NetavarkResult<()> {
        let mut need_reload = false;

        need_reload |= match create_zone_if_not_exist(&self.conn, ZONENAME) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating zone {}", ZONENAME),
                    e,
                ))
            }
        };
        need_reload |=
            match add_policy_if_not_exist(&self.conn, POLICYNAME, ZONENAME, "ACCEPT", true) {
                Ok(b) => b,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        format!("Error creating policy {}", POLICYNAME),
                        e,
                    ))
                }
            };
        need_reload |=
            match add_policy_if_not_exist(&self.conn, PORTPOLICYNAME, "ANY", "CONTINUE", false) {
                Ok(b) => b,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        format!("Error creating policy {}", POLICYNAME),
                        e,
                    ))
                }
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
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        format!("Error adding source subnets to zone {}", ZONENAME),
                        e,
                    ))
                }
            };
        }

        Ok(())
    }

    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        if !tear.complete_teardown {
            return Ok(());
        }

        if let Some(subnets) = tear.config.net.subnets {
            for subnet in subnets {
                debug!("Removing subnet {} from zone {}", subnet.subnet, ZONENAME);
                let _ = self.conn.call_method(
                    Some("org.fedoraproject.FirewallD1"),
                    "/org/fedoraproject/FirewallD1",
                    Some("org.fedoraproject.FirewallD1.zone"),
                    "removeSource",
                    &(ZONENAME, subnet.subnet.to_string()),
                )?;
            }
        }

        Ok(())
    }

    fn setup_port_forward(&self, setup_portfw: PortForwardConfig) -> Result<(), NetavarkError> {
        // NOTE: There is a serious TOCTOU risk in this function if netavark
        // is either run in parallel, or is not the only thing to edit this
        // policy.
        // Because of Podman's locking, this should be safe in the typical
        // case.
        // I don't think there's a safer way, unfortunately.

        // Get the current configuration for the policy
        let policy_config_msg = self.conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.policy"),
            "getPolicySettings",
            &(PORTPOLICYNAME),
        )?;
        let policy_config: HashMap<&str, Value> = match policy_config_msg.body() {
            Ok(m) => m,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!(
                        "Error decoding DBus message for policy {} configuration",
                        PORTPOLICYNAME
                    ),
                    e.into(),
                ))
            }
        };

        let mut port_forwarding_rules: Array;
        match policy_config.get("forward_ports") {
            Some(a) => match a {
                Value::Array(arr) => port_forwarding_rules = arr.clone(),
                _ => {
                    return Err(NetavarkError::msg(
                        "forward-port in firewalld policy object has a bad type",
                    ))
                }
            },
            None => {
                // No existing rules
                // Make us a new array.
                let sig = match Signature::try_from("(ssss)") {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(NetavarkError::wrap(
                            "Error creating signature for new DBus array",
                            e.into(),
                        ))
                    }
                };

                port_forwarding_rules = Array::new(sig);
            }
        }

        // Create any necessary port forwarding rule(s) and add them to the
        // policy config we grabbed above.
        // Note that this does *absolutely no* conflict detection or
        // prevention - if two ports end up mapped to different containers,
        // that is not detected, and firewalld will allow it to happen.
        // Only one of them will win and be active, though.
        match setup_portfw.port_mappings {
            Some(ports) => {
                for port in ports {
                    if !port.host_ip.is_empty() {
                        port_forwarding_rules
                            .append(Value::new(make_port_tuple(port, &port.host_ip)))?;
                    } else {
                        if let Some(v4) = setup_portfw.container_ip_v4 {
                            port_forwarding_rules
                                .append(Value::new(make_port_tuple(port, &v4.to_string())))?;
                        }
                        if let Some(v6) = setup_portfw.container_ip_v6 {
                            port_forwarding_rules
                                .append(Value::new(make_port_tuple(port, &v6.to_string())))?;
                        }
                    }
                }
            }
            None => {}
        };

        // dns port forwarding requires rich rules as we also want to match destination ip
        // only bother if configured dns port isn't 53
        let mut rich_rules_option: Option<Array> = None;
        if setup_portfw.dns_port != 53 && !setup_portfw.dns_server_ips.is_empty() {
            let mut rich_rules: Array;
            match policy_config.get("rich_rules") {
                Some(a) => match a {
                    Value::Array(arr) => rich_rules = arr.clone(),
                    _ => {
                        return Err(NetavarkError::msg(
                            "forward-port in firewalld policy object has a bad type",
                        ))
                    }
                },
                None => {
                    // No existing rules
                    // Make us a new array.
                    let sig = match Signature::try_from("s") {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(NetavarkError::wrap(
                                "Error creating signature for new DBus array",
                                e.into(),
                            ))
                        }
                    };
                    rich_rules = Array::new(sig);
                }
            }
            for dns_ip in setup_portfw.dns_server_ips {
                let ip_family = if dns_ip.is_ipv6() { "ipv6" } else { "ipv4" };
                let rule = format!("rule family=\"{}\" destination address=\"{}\" forward-port port=\"53\" protocol=\"udp\" to-port=\"{}\" to-addr=\"{}\"",
                                   ip_family, dns_ip, setup_portfw.dns_port, dns_ip);
                rich_rules.append(Value::new(rule))?;
            }
            rich_rules_option = Some(rich_rules)
        }

        // Firewalld won't alter keys we don't mention, so make a new config
        // map - with only the changes to ports.
        let new_pf_rules = Value::new(port_forwarding_rules);
        let mut new_policy_config = HashMap::<&str, &Value>::new();
        new_policy_config.insert("forward_ports", &new_pf_rules);
        let new_rich_rules = rich_rules_option.map(Value::new);
        if let Some(rich) = &new_rich_rules {
            new_policy_config.insert("rich_rules", rich);
        }

        // Send the updated configuration back to firewalld.
        match self.conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.policy"),
            "setPolicySettings",
            &(PORTPOLICYNAME, new_policy_config),
        ) {
            Ok(_) => info!(
                "Successfully added port-forwarding rules for container {}",
                setup_portfw.container_id
            ),
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!(
                        "Failed to update policy {} to add container {} port forwarding rules",
                        PORTPOLICYNAME, setup_portfw.container_id
                    ),
                    e.into(),
                ))
            }
        };

        Ok(())
    }

    fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()> {
        // Get the current configuration for the policy
        let policy_config_msg = self.conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.policy"),
            "getPolicySettings",
            &(PORTPOLICYNAME),
        )?;
        let policy_config: HashMap<&str, Value> = match policy_config_msg.body() {
            Ok(m) => m,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!(
                        "Error decoding DBus message for policy {} configuration",
                        PORTPOLICYNAME
                    ),
                    e.into(),
                ))
            }
        };

        let old_port_forwarding_rules_option: Option<Array> =
            match policy_config.get("forward_ports") {
                Some(a) => match a {
                    Value::Array(arr) => Some(arr.clone()),
                    _ => {
                        return Err(NetavarkError::msg(
                            "forward-port in firewalld policy object has a bad type",
                        ))
                    }
                },
                None => {
                    // No existing rules - skip
                    None
                }
            };

        let mut port_forwarding_rules_option: Option<Array> = None;
        if let Some(old_port_forwarding_rules) = old_port_forwarding_rules_option {
            let sig = match Signature::try_from("(ssss)") {
                Ok(s) => s,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        "Error creating signature for new dbus array",
                        e.into(),
                    ))
                }
            };
            let mut port_forwarding_rules = Array::new(sig);
            // use an invalid string if we don't have a valid v4 or v6 address.
            // This is ugly, but easiest code-wise.
            let ipv4 = match teardown_pf.config.container_ip_v4 {
                Some(i) => i.to_string(),
                None => "DOES NOT EXIST".to_string(),
            };
            let ipv6 = match teardown_pf.config.container_ip_v6 {
                Some(i) => i.to_string(),
                None => "DOES NOT EXIST".to_string(),
            };

            // Iterate through old rules, remove anything with the IPv4 or IPv6 of
            // this container as the destination IP.
            for port_tuple in old_port_forwarding_rules.iter() {
                match port_tuple {
                    Value::Structure(s) => {
                        let fields = s.clone().into_fields();
                        if fields.len() != 4 {
                            return Err(NetavarkError::msg(
                                "Port forwarding rule that was not a 4-tuple encountered",
                            ));
                        }
                        let port_ip = match fields[3].clone() {
                            Value::Str(s) => s.as_str().to_string(),
                            _ => return Err(NetavarkError::msg("Port forwarding tuples must contain only strings, encountered a non-string object")),
                        };
                        debug!("IP string from firewalld is {}", port_ip);
                        if port_ip != ipv4 && port_ip != ipv6 {
                            port_forwarding_rules.append(port_tuple.clone())?;
                        }
                    }
                    _ => {
                        return Err(NetavarkError::msg(
                            "Port forwarding rule that was not a structure encountered",
                        ))
                    }
                }
            }
            port_forwarding_rules_option = Some(port_forwarding_rules)
        }

        // iterate through rich rules to remove dns forwarding if this
        // is the last container of the network e.g. teardown complete
        // only bother if configured dns port isn't 53
        let mut rich_rules_option: Option<Array> = None;
        let mut old_rich_rules_option: Option<Array> = None;
        if teardown_pf.complete_teardown
            && teardown_pf.config.dns_port != 53
            && !teardown_pf.config.dns_server_ips.is_empty()
        {
            if let Some(a) = policy_config.get("rich_rules") {
                match a {
                    Value::Array(arr) => old_rich_rules_option = Some(arr.clone()),
                    _ => {
                        return Err(NetavarkError::msg(
                            "forward-port in firewalld policy object has a bad type",
                        ))
                    }
                }
            }
        }
        if let Some(old_rich_rules) = old_rich_rules_option {
            let mut rules_to_delete: Vec<String> = vec![];
            for dns_ip in teardown_pf.config.dns_server_ips {
                let ip_family = if dns_ip.is_ipv6() { "ipv6" } else { "ipv4" };
                let rule = format!("rule family=\"{}\" destination address=\"{}\" forward-port port=\"53\" protocol=\"udp\" to-port=\"{}\" to-addr=\"{}\"",
                                   ip_family, dns_ip, teardown_pf.config.dns_port, dns_ip);
                rules_to_delete.push(rule);
            }
            let sig = match Signature::try_from("s") {
                Ok(s) => s,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        "Error creating signature for new DBus array",
                        e.into(),
                    ))
                }
            };
            let mut rich_rules = Array::new(sig);
            for rule in old_rich_rules.iter() {
                match rule {
                    Value::Str(old_rule) => {
                        if !rules_to_delete.contains(&old_rule.to_string()) {
                            rich_rules.append(rule.clone())?;
                        }
                    }
                    _ => {
                        return Err(NetavarkError::msg(
                            "Rich rule that was not a string encountered",
                        ))
                    }
                }
            }
            rich_rules_option = Some(rich_rules);
        }

        // Firewalld won't alter keys we don't mention, so make a new config
        // map - with only the changes to ports.
        let mut new_policy_config = HashMap::<&str, &Value>::new();
        let new_pf_rules = port_forwarding_rules_option.map(Value::new);
        if let Some(pf) = &new_pf_rules {
            new_policy_config.insert("forward_ports", pf);
        }
        let new_rich_rules = rich_rules_option.map(Value::new);
        if let Some(rich) = &new_rich_rules {
            new_policy_config.insert("rich_rules", rich);
        }

        // Send the updated configuration back to firewalld.
        match self.conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.policy"),
            "setPolicySettings",
            &(PORTPOLICYNAME, new_policy_config),
        ) {
            Ok(_) => info!(
                "Successfully added port-forwarding rules for container {}",
                teardown_pf.config.container_id
            ),
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!(
                        "Failed to update policy {} to remove container {} port forwarding rules",
                        PORTPOLICYNAME, teardown_pf.config.container_id
                    ),
                    e.into(),
                ))
            }
        };

        Ok(())
    }
}

/// Create a firewalld zone to hold all our interfaces.
fn create_zone_if_not_exist(conn: &Connection, zone_name: &str) -> NetavarkResult<bool> {
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
        Err(e) => {
            return Err(NetavarkError::wrap(
                "Error decoding DBus message for active zones",
                e.into(),
            ))
        }
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
        Err(e) => {
            return Err(NetavarkError::wrap(
                "Error decoding DBus message for permanent zones",
                e.into(),
            ))
        }
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

/// Add source subnets to the zone.
pub fn add_source_subnets_to_zone(
    conn: &Connection,
    zone_name: &str,
    subnets: Vec<types::Subnet>,
) -> NetavarkResult<()> {
    for net in subnets {
        // Check if subnet already exists in zone
        let subnet_zone = conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.zone"),
            "getZoneOfSource",
            &(net.subnet.to_string()),
        )?;
        let zone_string: String = match subnet_zone.body() {
            Ok(s) => s,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    "Error decoding DBus message for zone of subnet",
                    e.into(),
                ))
            }
        };
        if zone_string == zone_name {
            debug!("Subnet {} already exists in zone {}", net.subnet, zone_name);
            return Ok(());
        }

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

/// Add a policy object for the zone to handle masquerading.
fn add_policy_if_not_exist(
    conn: &Connection,
    policy_name: &str,
    ingress_zone_name: &str,
    target: &str,
    masquerade: bool,
) -> NetavarkResult<bool> {
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
        Err(e) => {
            return Err(NetavarkError::wrap(
                "Error decoding policy list response",
                e.into(),
            ))
        }
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
        Err(e) => {
            return Err(NetavarkError::wrap(
                "Error decoding permanent policy list response",
                e.into(),
            ))
        }
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
    policy_opts.insert("egress_zones", &egress_zones);
    policy_opts.insert("ingress_zones", &ingress_zones);

    let masquerade_bool = Value::new(true);
    if masquerade {
        policy_opts.insert("masquerade", &masquerade_bool);
    }

    let target = Value::new(target);
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

/// Make a port-forward tuple for firewalld
/// Port forward rules are a 4-tuple of:
/// (port, protocol, to-port, to-addr)
/// Port, to-port can be ranges (separated via hyphen)
/// Also accepts IP address to forward to.
fn make_port_tuple(port: &PortMapping, addr: &str) -> (String, String, String, String) {
    if port.range > 1 {
        // Subtract 1 as these are 1-indexed strings - range of 2 is 1000-1001
        let end_host_range = port.host_port + port.range - 1;
        let end_ctr_range = port.container_port + port.range - 1;
        (
            format!("{}-{}", port.host_port, end_host_range),
            port.protocol.clone(),
            format!("{}-{}", port.container_port, end_ctr_range),
            addr.to_string(),
        )
    } else {
        let to_return = (
            format!("{}", port.host_port),
            port.protocol.clone(),
            format!("{}", port.container_port),
            addr.to_string(),
        );
        debug!("Port is {:?}", to_return);
        to_return
    }
}
