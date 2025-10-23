use crate::error::{NetavarkError, NetavarkResult};
use crate::network::internal_types;
use crate::network::internal_types::{PortForwardConfig, TearDownNetwork, TeardownPortForward};
use crate::network::types::PortMapping;
use crate::{firewall, wrap};
use core::convert::TryFrom;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::vec::Vec;
use zbus::{
    blocking::Connection,
    zvariant::{Array, OwnedValue, Signature, Value},
};

const ZONENAME: &str = "netavark_zone";
const POLICYNAME: &str = "netavark_policy";
const PORTPOLICYNAME: &str = "netavark_portfwd";
const HOSTFWDPOLICYNAME: &str = "netavark_host_fwd";
const HOSTTOZONEPOLICYNAME: &str = "netavark_zone_acc";

// Firewalld driver - uses a dbus connection to communicate with firewalld.
pub struct FirewallD {
    conn: Connection,
}

pub fn new(conn: Connection) -> Result<Box<dyn firewall::FirewallDriver>, NetavarkError> {
    Ok(Box::new(FirewallD { conn }))
}

impl firewall::FirewallDriver for FirewallD {
    fn driver_name(&self) -> &str {
        firewall::FIREWALLD
    }

    fn setup_network(
        &self,
        network_setup: internal_types::SetupNetwork,
        _dbus_con: &Option<Connection>,
    ) -> NetavarkResult<()> {
        let mut need_reload = false;

        need_reload |= match create_zone_if_not_exist(&self.conn, ZONENAME) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating zone {ZONENAME}"),
                    e,
                ))
            }
        };
        // Determine if masquerade should be enabled based on SNAT configuration
        // For firewalld, we check if either IPv4 or IPv6 SNAT is enabled
        // since firewalld policy applies to both address families at the same level.
        // Note: Unlike nftables/iptables, firewalld applies masquerade at the policy level,
        // not per-subnet, so we use OR logic - if any protocol needs SNAT, enable it.
        let enable_masquerade = network_setup.snat_ipv4 || network_setup.snat_ipv6;

        need_reload |= match add_policy_if_not_exist(
            &self.conn, POLICYNAME, ZONENAME, "ANY", "ACCEPT", enable_masquerade, None,
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating policy {POLICYNAME}"),
                    e,
                ))
            }
        };
        need_reload |= match add_policy_if_not_exist(
            &self.conn,
            PORTPOLICYNAME,
            "ANY",
            "HOST",
            "CONTINUE",
            false,
            None,
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating policy {PORTPOLICYNAME}"),
                    e,
                ))
            }
        };
        need_reload |= match add_policy_if_not_exist(
            &self.conn,
            HOSTFWDPOLICYNAME,
            "HOST",
            "ANY",
            "CONTINUE",
            false,
            None,
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating policy {HOSTFWDPOLICYNAME}"),
                    e,
                ))
            }
        };
        need_reload |= match add_policy_if_not_exist(
            &self.conn,
            HOSTTOZONEPOLICYNAME,
            "ANY",
            ZONENAME,
            "CONTINUE",
            true,
            None,
        ) {
            Ok(b) => b,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    format!("Error creating policy {HOSTTOZONEPOLICYNAME}"),
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
        if let Some(nets) = network_setup.subnets {
            match add_source_subnets_to_zone(&self.conn, ZONENAME, &nets) {
                Ok(_) => {}
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        format!("Error adding source subnets to zone {ZONENAME}"),
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

        if let Some(subnets) = tear.config.subnets {
            for subnet in subnets {
                debug!("Removing subnet {subnet} from zone {ZONENAME}");
                let _ = self.conn.call_method(
                    Some("org.fedoraproject.FirewallD1"),
                    "/org/fedoraproject/FirewallD1",
                    Some("org.fedoraproject.FirewallD1.zone"),
                    "removeSource",
                    &(ZONENAME, subnet.to_string()),
                )?;
            }
        }

        Ok(())
    }

    fn setup_port_forward(
        &self,
        setup_portfw: PortForwardConfig,
        _dbus_con: &Option<Connection>,
    ) -> Result<(), NetavarkError> {
        // NOTE: There is a serious TOCTOU risk in this function if netavark
        // is either run in parallel, or is not the only thing to edit this
        // policy.
        // Because of Podman's locking, this should be safe in the typical
        // case.
        // I don't think there's a safer way, unfortunately.

        let sig_ssss = match Signature::try_from("(ssss)") {
            Ok(s) => s,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    "Error creating signature for new DBus array",
                    e.into(),
                ))
            }
        };
        let sig_s = match Signature::try_from("s") {
            Ok(s) => s,
            Err(e) => {
                return Err(NetavarkError::wrap(
                    "Error creating signature for new DBus array",
                    e.into(),
                ))
            }
        };
        let mut port_forwarding_rules: Array = Array::new(&sig_ssss);
        let mut rich_rules: Array = Array::new(&sig_s.clone());
        let mut localhost_rich_rules: Array = Array::new(&sig_s);

        // Create any necessary port forwarding rule(s) and add them to the
        // policy config we grabbed above.
        // Note that this does *absolutely no* conflict detection or
        // prevention - if two ports end up mapped to different containers,
        // that is not detected, and firewalld will allow it to happen.
        // Only one of them will win and be active, though.
        if let Some(ports) = setup_portfw.port_mappings {
            for port in ports {
                if !port.host_ip.is_empty() && port.host_ip != "0.0.0.0" && port.host_ip != "::" {
                    // Have to special-case forwarding off localhost.
                    if port.host_ip == "127.0.0.1" {
                        if let Some(v4) = setup_portfw.container_ip_v4 {
                            let rule = get_localhost_pf_rich_rule(port, &v4);
                            debug!("Adding localhost pf rule: {rule}");
                            localhost_rich_rules.append(Value::new(rule))?;
                        }
                        continue;
                    } else if port.host_ip == "::1" {
                        continue;
                    }

                    // Need a rich rule for traffic with a non-wildcard host IP.
                    let host_ip: IpAddr = match port.host_ip.parse() {
                        Ok(i) => i,
                        Err(_) => {
                            return Err(NetavarkError::msg(format!(
                                "invalid host ip \"{}\" provided for port {}",
                                port.host_ip, port.host_port
                            )));
                        }
                    };

                    match host_ip {
                        IpAddr::V4(_) => {
                            if let Some(ctr_ip_v4) = setup_portfw.container_ip_v4 {
                                let rule = get_port_forwarding_hostip_rich_rule(port, &ctr_ip_v4);
                                rich_rules.append(Value::new(rule))?;
                            }
                        }
                        IpAddr::V6(_) => {
                            if let Some(ctr_ip_v6) = setup_portfw.container_ip_v6 {
                                let rule = get_port_forwarding_hostip_rich_rule(port, &ctr_ip_v6);
                                rich_rules.append(Value::new(rule))?;
                            }
                        }
                    }
                } else {
                    if let Some(v4) = setup_portfw.container_ip_v4 {
                        if port.host_ip != "::" {
                            port_forwarding_rules
                                .append(Value::new(make_port_tuple(port, &v4.to_string())))?;
                            let localhost_rule = get_localhost_pf_rich_rule(port, &v4);
                            debug!("Adding localhost pf rule: {localhost_rule}");
                            localhost_rich_rules.append(Value::new(localhost_rule))?;
                        }
                    }
                    if let Some(v6) = setup_portfw.container_ip_v6 {
                        if port.host_ip != "0.0.0.0" {
                            port_forwarding_rules
                                .append(Value::new(make_port_tuple(port, &v6.to_string())))?;
                            // No localhost rule. Kernel does not support localhost v6 DNAT.
                        }
                    }
                }
            }
        };

        // dns port forwarding requires rich rules as we also want to match destination ip
        // only bother if configured dns port isn't 53
        if setup_portfw.dns_port != 53 && !setup_portfw.dns_server_ips.is_empty() {
            for dns_ip in setup_portfw.dns_server_ips {
                let rule = get_dns_pf_rich_rule(dns_ip, setup_portfw.dns_port);
                rich_rules.append(Value::new(rule))?;
            }
        }

        // Only update if we actually generated rules
        if !port_forwarding_rules.is_empty() || !rich_rules.is_empty() {
            let policy_config = get_policy_config(&self.conn, PORTPOLICYNAME.to_string())?;

            // The updated config for the policy. Firewalld won't alter keys we
            // don't mention, so safest to make a new map with only the keys we
            // altered.
            let mut new_policy_config = HashMap::<&str, &Value>::new();

            let mut pf_opt: Option<Value> = None;
            if !port_forwarding_rules.is_empty() {
                let final_port_forwarding_rules: Array = match policy_config.get("forward_ports") {
                    Some(a) => match a.try_to_owned()?.into() {
                        Value::Array(arr) => {
                            let mut new_arr = arr.try_clone()?;
                            for rule in port_forwarding_rules.iter() {
                                new_arr.append(rule.try_clone()?)?;
                            }
                            new_arr
                        }
                        _ => {
                            return Err(NetavarkError::msg(
                                "forward_ports in firewalld policy object has a bad type",
                            ))
                        }
                    },
                    None => port_forwarding_rules,
                };

                pf_opt = Some(Value::new(final_port_forwarding_rules));
            }
            if let Some(v) = &pf_opt {
                new_policy_config.insert("forward_ports", v);
            }

            let mut rich_rules_opt: Option<Value> = None;
            if !rich_rules.is_empty() {
                let final_rich_rules: Array = match policy_config.get("rich_rules") {
                    Some(a) => match a.try_to_owned()?.into() {
                        Value::Array(arr) => {
                            let mut new_arr = arr.try_clone()?;
                            for rule in rich_rules.iter() {
                                new_arr.append(rule.try_clone()?)?;
                            }
                            new_arr
                        }
                        _ => {
                            return Err(NetavarkError::msg(
                                "rich_rules in firewalld policy object has a bad type",
                            ))
                        }
                    },
                    None => rich_rules,
                };

                rich_rules_opt = Some(Value::new(final_rich_rules));
            }
            if let Some(v) = &rich_rules_opt {
                new_policy_config.insert("rich_rules", v);
            }

            // Send the new config back
            update_policy_config(&self.conn, PORTPOLICYNAME, new_policy_config)?;
        }

        // Same thing, but for our localhost forwarding policy
        if !localhost_rich_rules.is_empty() {
            let policy_config = get_policy_config(&self.conn, HOSTFWDPOLICYNAME.to_string())?;

            // The updated config for the policy. Firewalld won't alter keys we
            // don't mention, so safest to make a new map with only the keys we
            // altered.
            let final_rich_rules: Array = match policy_config.get("rich_rules") {
                Some(a) => match a.try_to_owned()?.into() {
                    Value::Array(arr) => {
                        let mut new_arr = arr.try_clone()?;
                        for rule in localhost_rich_rules.iter() {
                            new_arr.append(rule.try_clone()?)?;
                        }
                        new_arr
                    }
                    _ => {
                        return Err(NetavarkError::msg(
                            "rich_rules in firewalld policy object has a bad type",
                        ))
                    }
                },
                None => localhost_rich_rules,
            };

            let mut new_policy_config = HashMap::<&str, &Value>::new();
            let value_rich_rules = Value::new(final_rich_rules);
            new_policy_config.insert("rich_rules", &value_rich_rules);

            update_policy_config(&self.conn, HOSTFWDPOLICYNAME, new_policy_config)?;
        }

        info!(
            "Successfully added port-forwarding rules for container {}",
            setup_portfw.container_id
        );

        Ok(())
    }

    fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()> {
        // Get the current configuration for the policy
        let policy_config = get_policy_config(&self.conn, PORTPOLICYNAME.to_string())?;
        let localhost_policy_config = get_policy_config(&self.conn, HOSTFWDPOLICYNAME.to_string())?;

        let old_port_forwarding_rules_option: Option<Array> =
            match policy_config.get("forward_ports") {
                Some(a) => match a.try_to_owned()?.into() {
                    Value::Array(arr) => Some(arr.try_clone()?),
                    _ => {
                        return Err(NetavarkError::msg(
                            "forward-port in firewalld policy object has a bad type",
                        ));
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
            let mut port_forwarding_rules = Array::new(&sig);

            let ipv4 = teardown_pf.config.container_ip_v4.map(|i| i.to_string());
            let ipv6 = teardown_pf.config.container_ip_v6.map(|i| i.to_string());

            // Iterate through old rules, remove anything with the IPv4 or IPv6 of
            // this container as the destination IP.
            for port_tuple in old_port_forwarding_rules.iter() {
                match port_tuple {
                    Value::Structure(s) => {
                        let fields = s.fields();
                        if fields.len() != 4 {
                            return Err(NetavarkError::msg(
                                "Port forwarding rule that was not a 4-tuple encountered",
                            ));
                        }
                        let port_ip = match &fields[3] {
                            Value::Str(s) => s.as_str().to_string(),
                            _ => return Err(NetavarkError::msg("Port forwarding tuples must contain only strings, encountered a non-string object")),
                        };
                        let mut is_match = false;
                        if let Some(v4) = &ipv4 {
                            debug!("Checking firewalld IP {port_ip} against our IP {v4}");
                            if *v4 == port_ip {
                                is_match = true;
                            }
                        }
                        if let Some(v6) = &ipv6 {
                            debug!("Checking firewalld IP {port_ip} against our IP {v6}");
                            if *v6 == port_ip {
                                is_match = true;
                            }
                        }
                        if !is_match {
                            port_forwarding_rules.append(port_tuple.try_clone()?)?;
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
        let old_rich_rules_option: Option<Array> = match policy_config.get("rich_rules") {
            Some(a) => match a.try_to_owned()?.into() {
                Value::Array(arr) => Some(arr.try_clone()?),
                _ => {
                    return Err(NetavarkError::msg(
                        "rich_rules in firewalld policy object has a bad type",
                    ))
                }
            },
            None => None,
        };

        if let Some(old_rich_rules) = old_rich_rules_option {
            let sig = match Signature::try_from("s") {
                Ok(s) => s,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        "Error creating signature for new dbus array",
                        e.into(),
                    ))
                }
            };
            let mut new_rich_rules = Array::new(&sig);

            let ipv4 = teardown_pf.config.container_ip_v4.map(|i| i.to_string());
            let ipv6 = teardown_pf.config.container_ip_v6.map(|i| i.to_string());

            // DNS rules: get a vector of all rules we'll want to remove.
            let mut dns_rules: Vec<String> = Vec::new();
            if teardown_pf.complete_teardown
                && teardown_pf.config.dns_port != 53
                && !teardown_pf.config.dns_server_ips.is_empty()
            {
                for dns_ip in teardown_pf.config.dns_server_ips {
                    dns_rules.push(get_dns_pf_rich_rule(dns_ip, teardown_pf.config.dns_port))
                }
            }

            for rule in old_rich_rules.iter() {
                match rule {
                    Value::Str(old_rule) => {
                        let mut is_match = false;

                        if dns_rules.contains(&old_rule.to_string()) {
                            is_match = true;
                        }

                        // Remove any rule using our IPv4 or IPv6 as daddr.
                        if let Some(v4) = &ipv4 {
                            let daddr = format!("to-addr=\"{v4}\"");
                            debug!("Checking if {old_rule} contains string {daddr}");
                            if old_rule.to_string().contains(&daddr) {
                                is_match = true;
                            }
                        }
                        if let Some(v6) = &ipv6 {
                            let daddr = format!("to-addr=\"{v6}\"");
                            if old_rule.to_string().contains(&daddr) {
                                is_match = true;
                            }
                        }

                        if !is_match {
                            new_rich_rules.append(rule.try_clone()?)?;
                        }
                    }
                    _ => {
                        return Err(NetavarkError::msg(
                            "Rich rule that was not a string encountered",
                        ))
                    }
                }
            }

            rich_rules_option = Some(new_rich_rules);
        }

        // Now handle the localhost forwarding policy.
        let mut localhost_rich_rules_option: Option<Array> = None;
        let old_localhost_rich_rules_option: Option<Array> =
            match localhost_policy_config.get("rich_rules") {
                Some(a) => match a.try_to_owned()?.into() {
                    Value::Array(arr) => Some(arr.try_clone()?),
                    _ => {
                        return Err(NetavarkError::msg(
                            "rich_rules in firewalld localhost policy object has a bad type",
                        ))
                    }
                },
                None => None,
            };
        if let Some(old_localhost_rich_rules) = old_localhost_rich_rules_option {
            let sig = match Signature::try_from("s") {
                Ok(s) => s,
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        "Error creating signature for new dbus array",
                        e.into(),
                    ))
                }
            };
            let mut new_rich_rules = Array::new(&sig);

            let ipv4 = teardown_pf.config.container_ip_v4.map(|i| i.to_string());

            for rule in old_localhost_rich_rules.iter() {
                match rule {
                    Value::Str(old_rule) => {
                        let mut is_match = false;

                        // Remove any rule using our IPv4 as daddr.
                        // We don't do IPv6 localhost forwarding.
                        if let Some(v4) = &ipv4 {
                            let daddr = format!("to-addr=\"{v4}\"");
                            debug!("Checking if {old_rule} contains string {daddr}");
                            if old_rule.to_string().contains(&daddr) {
                                is_match = true;
                            }
                        }

                        if !is_match {
                            new_rich_rules.append(rule.try_clone()?)?;
                        }
                    }
                    _ => {
                        return Err(NetavarkError::msg(
                            "Rich rule that was not a string encountered",
                        ))
                    }
                }
            }

            localhost_rich_rules_option = Some(new_rich_rules);
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
        update_policy_config(&self.conn, PORTPOLICYNAME, new_policy_config)?;

        // And again for the localhost policy
        let mut new_localhost_policy_config = HashMap::<&str, &Value>::new();
        let new_localhost_rich_rules = localhost_rich_rules_option.map(Value::new);
        if let Some(rich) = &new_localhost_rich_rules {
            new_localhost_policy_config.insert("rich_rules", rich);
        }
        update_policy_config(&self.conn, HOSTFWDPOLICYNAME, new_localhost_policy_config)?;

        Ok(())
    }
}

/// Create a firewalld zone to hold all our interfaces.
fn create_zone_if_not_exist(conn: &Connection, zone_name: &str) -> NetavarkResult<bool> {
    debug!("Creating firewall zone {zone_name}");

    // First, double-check if the zone exists in the running config.
    let zones_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.zone"),
        "getZones",
        &(),
    )?;
    let body = zones_msg.body();
    let zones: Vec<&str> = wrap!(
        body.deserialize(),
        format!("Error decoding DBus message for active zones")
    )?;
    for &zone in zones.iter() {
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
    let body = perm_zones_msg.body();
    let zones_perm: Vec<&str> = body.deserialize().map_err(|e| {
        NetavarkError::wrap("Error decoding DBus message for permanent zones", e.into())
    })?;
    for &zone in zones_perm.iter() {
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
    subnets: &[ipnet::IpNet],
) -> NetavarkResult<()> {
    for net in subnets {
        // Check if subnet already exists in zone
        let subnet_zone = conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.zone"),
            "getZoneOfSource",
            &(net.to_string()),
        )?;
        let body = subnet_zone.body();
        let zone_string: String = wrap!(
            body.deserialize(),
            "Error decoding DBus message for zone of subnet"
        )?;
        if zone_string == zone_name {
            debug!("Subnet {net} already exists in zone {zone_name}");
            return Ok(());
        }

        debug!("Adding subnet {net} to zone {zone_name} as source");

        let _ = conn.call_method(
            Some("org.fedoraproject.FirewallD1"),
            "/org/fedoraproject/FirewallD1",
            Some("org.fedoraproject.FirewallD1.zone"),
            "changeZoneOfSource",
            &(zone_name, net.to_string()),
        )?;
    }

    Ok(())
}

/// Add a policy object for the zone to handle masquerading.
fn add_policy_if_not_exist(
    conn: &Connection,
    policy_name: &str,
    ingress_zone_name: &str,
    egress_zone_name: &str,
    target: &str,
    masquerade: bool,
    priority: Option<i16>,
) -> NetavarkResult<bool> {
    debug!(
        "Adding firewalld policy {policy_name} (ingress zone {ingress_zone_name}, egress zone {egress_zone_name})"
    );

    // Does policy exist in running policies?
    let policies_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.policy"),
        "getPolicies",
        &(),
    )?;
    let policies_body = policies_msg.body();
    let policies: Vec<&str> = wrap!(
        policies_body.deserialize(),
        "Error decoding policy list response"
    )?;
    for &policy in policies.iter() {
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
    let perm_policies_body = perm_policies_msg.body();
    let perm_policies: Vec<&str> = wrap!(
        perm_policies_body.deserialize(),
        "Error decoding permanent policy list response"
    )?;
    for &policy in perm_policies.iter() {
        if policy == policy_name {
            debug!("Policy exists and is not running");
            return Ok(true);
        }
    }

    // Options for the new policy
    let mut policy_opts = HashMap::<&str, &Value>::new();
    let egress_zones = Value::new(Array::from(vec![egress_zone_name]));
    let ingress_zones = Value::new(Array::from(vec![ingress_zone_name]));
    let priority_val = priority.map(Value::new);
    if let Some(prio) = &priority_val {
        policy_opts.insert("priority", prio);
    }
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
            port.host_port.to_string(),
            port.protocol.clone(),
            port.container_port.to_string(),
            addr.to_string(),
        );
        debug!("Port is {to_return:?}");
        to_return
    }
}

/// Get the configuration of the given policy.
fn get_policy_config(
    conn: &Connection,
    policy_name: String,
) -> NetavarkResult<HashMap<String, OwnedValue>> {
    let policy_config_msg = conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.policy"),
        "getPolicySettings",
        &policy_name,
    )?;
    let mut policy_config: HashMap<String, OwnedValue> = HashMap::new();
    match policy_config_msg
        .body()
        .deserialize::<HashMap<&str, Value>>()
    {
        Ok(m) => {
            for (k, v) in m {
                policy_config.insert(k.to_string(), v.try_to_owned()?);
            }
        }
        Err(e) => {
            return Err(NetavarkError::wrap(
                format!("Error decoding DBus message for policy {policy_name} configuration"),
                e.into(),
            ))
        }
    };
    Ok(policy_config)
}

/// Update a policy config object
fn update_policy_config(
    conn: &Connection,
    policy_name: &str,
    new_config: HashMap<&str, &Value>,
) -> NetavarkResult<()> {
    match conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.policy"),
        "setPolicySettings",
        &(policy_name, new_config),
    ) {
        Ok(_) => {}
        Err(e) => {
            return Err(NetavarkError::wrap(
                format!("Failed to update firewalld policy {policy_name} port forwarding rules"),
                e.into(),
            ))
        }
    };

    Ok(())
}

/// Get a rich rule to handle DNS port forwarding.
fn get_dns_pf_rich_rule(dns_ip: &IpAddr, dns_port: u16) -> String {
    let ip_family = get_rich_rule_ip_family(dns_ip);
    get_pf_rich_rule(
        &ip_family,
        &dns_ip.to_string(),
        "53",
        "udp",
        &dns_port.to_string(),
        &dns_ip.to_string(),
    )
}

/// Get a rich rule to handle port forwarding to a specific IP.
fn get_port_forwarding_hostip_rich_rule(port: &PortMapping, ctr_ip: &IpAddr) -> String {
    let ip_family = get_rich_rule_ip_family(ctr_ip);
    let host_port = get_rich_rule_port(port.host_port, port.range);
    let ctr_port = get_rich_rule_port(port.container_port, port.range);

    get_pf_rich_rule(
        &ip_family,
        &port.host_ip,
        &host_port,
        &port.protocol,
        &ctr_port,
        &ctr_ip.to_string(),
    )
}

/// Get a localhost port forwarding rich rule. IPv4 only.
fn get_localhost_pf_rich_rule(port: &PortMapping, ctr_ip: &IpAddr) -> String {
    let host_port = get_rich_rule_port(port.host_port, port.range);
    let ctr_port = get_rich_rule_port(port.container_port, port.range);
    get_pf_rich_rule(
        "ipv4",
        "127.0.0.1",
        &host_port,
        &port.protocol,
        &ctr_port,
        &ctr_ip.to_string(),
    )
}

/// Get a port string for a rich rule
fn get_rich_rule_port(port: u16, range: u16) -> String {
    if range > 1 {
        format!("{}-{}", port, (port + range - 1))
    } else {
        port.to_string()
    }
}

/// Get appropriate address family for an IP address
fn get_rich_rule_ip_family(ip: &IpAddr) -> String {
    if ip.is_ipv6() {
        "ipv6".to_string()
    } else {
        "ipv4".to_string()
    }
}

/// Get a port forwarding rich rule.
fn get_pf_rich_rule(
    ip_family: &str,
    host_ip: &str,
    host_port: &str,
    protocol: &str,
    ctr_port: &str,
    ctr_ip: &str,
) -> String {
    format!("rule family=\"{ip_family}\" destination address=\"{host_ip}\" forward-port port=\"{host_port}\" protocol=\"{protocol}\" to-port=\"{ctr_port}\" to-addr=\"{ctr_ip}\"")
}

/// Check if firewalld is running.
/// Not used within the firewalld driver, but by other drivers that may need to
/// interact with firewalld.
pub fn is_firewalld_running(conn: &Connection) -> bool {
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
/// Not used within the firewalld driver, but by other drivers that may need to
/// interact with firewalld.
pub fn add_firewalld_if_possible(dbus_conn: &Option<Connection>, net: &ipnet::IpNet) {
    let conn = match dbus_conn {
        Some(conn) => conn,
        None => return,
    };
    if !is_firewalld_running(conn) {
        return;
    }
    debug!("Adding firewalld rules for network {net}");

    match add_source_subnets_to_zone(conn, "trusted", &[*net]) {
        Ok(_) => {}
        Err(e) => warn!("Error adding subnet {net} from firewalld trusted zone: {e}"),
    }
}

/// If possible, remove a firewalld rule to allow traffic.
/// Ignore all errors, beyond possibly logging them.
/// Not used within the firewalld driver, but by other drivers that may need to
/// interact with firewalld.
pub fn rm_firewalld_if_possible(net: &ipnet::IpNet) {
    let conn = match Connection::system() {
        Ok(conn) => conn,
        Err(_) => return,
    };
    if !is_firewalld_running(&conn) {
        return;
    }
    debug!("Removing firewalld rules for IPs {net}");
    match conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1",
        Some("org.fedoraproject.FirewallD1.zone"),
        "removeSource",
        &("trusted", net.to_string()),
    ) {
        Ok(_) => {}
        Err(e) => warn!("Error removing subnet {net} from firewalld trusted zone: {e}"),
    };
}

/// Check whether firewalld's StrictForwardPorts setting is enabled.
/// Returns false if firewalld is not installed, not running, or there is any
/// error with the process.
pub fn is_firewalld_strict_forward_enabled(dbus_con: &Option<Connection>) -> bool {
    let conn = match dbus_con {
        Some(conn) => conn,
        None => return false,
    };
    if !is_firewalld_running(conn) {
        return false;
    }

    // Fetch current running config
    match conn.call_method(
        Some("org.fedoraproject.FirewallD1"),
        "/org/fedoraproject/FirewallD1/config",
        Some("org.freedesktop.DBus.Properties"),
        "Get",
        &("org.fedoraproject.FirewallD1.config", "StrictForwardPorts"),
    ) {
        Ok(b) => {
            let variant_str: String = match b.body().deserialize::<Value>() {
                Ok(v) => match v.downcast::<String>() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("couldn't downcast StrictForwardPorts value to string: {e}");
                        return false;
                    }
                },
                Err(e) => {
                    warn!("couldn't retrieve StrictForwardPorts property: {e}");
                    return false;
                }
            };
            match variant_str.to_lowercase().as_str() {
                "yes" => true,
                "no" => false,
                other => {
                    warn!("unexpected value from StrictForwardPorts property: {other}");
                    false
                }
            }
        }
        Err(_) => {
            // Assume any error is related to the property not existing
            // (As it will not on older firewalld versions)
            // Return false given that.
            false
        }
    }
}

/// Check if firewalld's StrictForwardPorts setting is enabled and, if so,
/// whether the container has requested any ports be forwarded. If both are true
/// return a helpful error that port forwarding cannot be performed.
pub fn check_can_forward_ports(
    dbus_conn: &Option<Connection>,
    setup_portfw: &PortForwardConfig,
) -> NetavarkResult<()> {
    if is_firewalld_strict_forward_enabled(dbus_conn) {
        let mut portfw_used = setup_portfw.dns_port != 53;
        if let Some(ports) = setup_portfw.port_mappings {
            portfw_used = portfw_used || !ports.is_empty();
        }
        if portfw_used {
            return Err(NetavarkError::msg(
                "Port forwarding not possible as firewalld StrictForwardPorts enabled",
            ));
        }
    }
    Ok(())
}
