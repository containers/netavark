use crate::error::{NetavarkError, NetavarkResult};
use crate::firewall;
use crate::firewall::firewalld;
use crate::network::internal_types;
use crate::network::internal_types::IsolateOption;
use crate::network::types::PortMapping;
use ipnet::IpNet;
use nftables::batch::Batch;
use nftables::expr;
use nftables::helper::{self};
use nftables::schema;
use nftables::stmt;
use nftables::types;
use std::collections::HashSet;
use std::net::IpAddr;

const TABLENAME: &str = "netavark";

const INPUTCHAIN: &str = "INPUT";
const FORWARDCHAIN: &str = "FORWARD";
const POSTROUTINGCHAIN: &str = "POSTROUTING";
const PREROUTINGCHAIN: &str = "PREROUTING";
const OUTPUTCHAIN: &str = "OUTPUT";
const DNATCHAIN: &str = "NETAVARK-HOSTPORT-DNAT";
const MASKCHAIN: &str = "NETAVARK-HOSTPORT-SETMARK";
const ISOLATION1CHAIN: &str = "NETAVARK-ISOLATION-1";
const ISOLATION2CHAIN: &str = "NETAVARK-ISOLATION-2";
const ISOLATION3CHAIN: &str = "NETAVARK-ISOLATION-3";

const MASK: u32 = 0x2000;

/// The dnat priority for chains
/// This (and the below) are based on https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Priority_within_hook
const DNATPRIO: i32 = -100;
/// The srcnat priority for chains
const SRCNATPRIO: i32 = 100;
/// The filter priority for chains
const FILTERPRIO: i32 = 0;

pub struct Nftables {}

pub fn new() -> Result<Box<dyn firewall::FirewallDriver>, NetavarkError> {
    Ok(Box::new(Nftables {}))
}

impl firewall::FirewallDriver for Nftables {
    fn driver_name(&self) -> &str {
        firewall::NFTABLES
    }

    fn setup_network(&self, network_setup: internal_types::SetupNetwork) -> NetavarkResult<()> {
        let mut batch = Batch::new();

        // Overall table
        batch.add(schema::NfListObject::Table(schema::Table::new(
            types::NfFamily::INet,
            TABLENAME.to_string(),
        )));

        // Five default chains, one for each hook we have to monitor
        batch.add(make_complex_chain(
            INPUTCHAIN,
            types::NfChainType::Filter,
            types::NfHook::Input,
            FILTERPRIO,
        ));
        batch.add(make_complex_chain(
            FORWARDCHAIN,
            types::NfChainType::Filter,
            types::NfHook::Forward,
            FILTERPRIO,
        ));
        batch.add(make_complex_chain(
            POSTROUTINGCHAIN,
            types::NfChainType::NAT,
            types::NfHook::Postrouting,
            SRCNATPRIO,
        ));
        batch.add(make_complex_chain(
            PREROUTINGCHAIN,
            types::NfChainType::NAT,
            types::NfHook::Prerouting,
            DNATPRIO,
        ));
        batch.add(make_complex_chain(
            OUTPUTCHAIN,
            types::NfChainType::NAT,
            types::NfHook::Output,
            DNATPRIO,
        ));

        // dnat rules. Not used here, but need to be created first, because they have rules that must be first in their chains.
        // A lot of these are thus conditional on if the rule already exists or not.
        let existing_rules = get_netavark_rules()?;

        // Two extra chains, not hooked to anything, for our NAT pf rules
        batch.add(make_basic_chain(DNATCHAIN));
        batch.add(make_basic_chain(MASKCHAIN));

        // Three extra chains, not hooked to anything, for isolation.
        batch.add(make_basic_chain(ISOLATION1CHAIN));
        batch.add(make_basic_chain(ISOLATION2CHAIN));
        batch.add(make_basic_chain(ISOLATION3CHAIN));

        // Postrouting chain needs a single rule to masquerade if mask is set.
        // But only one copy of that rule. So check if such a rule exists.
        let match_meta_masq = |r: &schema::Rule| -> bool {
            // Match on any rule that matches against 0x2000
            for statement in &r.expr {
                match statement {
                    stmt::Statement::Match(m) => match &m.right {
                        expr::Expression::Number(n) => {
                            if *n == MASK {
                                return true;
                            }
                        }
                        _ => continue,
                    },
                    _ => continue,
                }
            }
            false
        };
        if get_matching_rules_in_chain(&existing_rules, POSTROUTINGCHAIN, match_meta_masq)
            .is_empty()
        {
            // Postrouting: meta mark & 0x2000 == 0x2000 masquerade
            batch.add(make_rule(
                POSTROUTINGCHAIN,
                vec![
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::BinaryOperation(expr::BinaryOperation::AND(
                            Box::new(expr::Expression::Named(expr::NamedExpression::Meta(
                                expr::Meta {
                                    key: expr::MetaKey::Mark,
                                },
                            ))),
                            Box::new(expr::Expression::Number(MASK)),
                        )),
                        right: expr::Expression::Number(MASK),
                        op: stmt::Operator::EQ,
                    }),
                    stmt::Statement::Masquerade(None),
                ],
            ));
        }

        // Mask chain needs a single rule to apply the mask.
        // But only one copy of that rule. So check if such a rule exists.
        let match_meta_mark = |r: &schema::Rule| -> bool {
            // Match on any mangle rule.
            for statement in &r.expr {
                match statement {
                    stmt::Statement::Mangle(_) => return true,
                    _ => continue,
                }
            }
            false
        };
        if get_matching_rules_in_chain(&existing_rules, MASKCHAIN, match_meta_mark).is_empty() {
            // Mask chain: mark or 0x2000
            batch.add(make_rule(
                MASKCHAIN,
                vec![stmt::Statement::Mangle(stmt::Mangle {
                    key: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
                        key: expr::MetaKey::Mark,
                    })),
                    value: expr::Expression::BinaryOperation(expr::BinaryOperation::OR(
                        Box::new(expr::Expression::Named(expr::NamedExpression::Meta(
                            expr::Meta {
                                key: expr::MetaKey::Mark,
                            },
                        ))),
                        Box::new(expr::Expression::Number(MASK)),
                    )),
                })],
            ));
        }

        // We need rules in Prerouting and Output pointing to our dnat chain.
        // But only if they do not exist.
        let match_jump_dnat = get_rule_matcher_jump_to(DNATCHAIN.to_string());
        // Prerouting: fib daddr type local jump <dnat_chain>
        // Output: fib daddr type local jump <dnat_chain>
        let mut rules_hash: HashSet<expr::FibFlag> = HashSet::new();
        rules_hash.insert(expr::FibFlag::Daddr);
        let base_conditions: Vec<stmt::Statement> = vec![
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Fib(expr::Fib {
                    result: expr::FibResult::Type,
                    flags: rules_hash,
                })),
                right: expr::Expression::String("local".to_string()),
                op: stmt::Operator::EQ,
            }),
            get_jump_action(DNATCHAIN),
        ];
        if get_matching_rules_in_chain(&existing_rules, PREROUTINGCHAIN, &match_jump_dnat)
            .is_empty()
        {
            batch.add(make_rule(PREROUTINGCHAIN, base_conditions.clone()));
        }
        if get_matching_rules_in_chain(&existing_rules, OUTPUTCHAIN, &match_jump_dnat).is_empty() {
            batch.add(make_rule(OUTPUTCHAIN, base_conditions.clone()));
        }

        // Forward chain: ct state invalid drop
        let match_deny = |r: &schema::Rule| -> bool {
            for statement in &r.expr {
                match statement {
                    stmt::Statement::Drop(_) => return true,
                    _ => continue,
                }
            }
            false
        };
        if get_matching_rules_in_chain(&existing_rules, FORWARDCHAIN, match_deny).is_empty() {
            batch.add(make_rule(
                FORWARDCHAIN,
                vec![
                    stmt::Statement::Match(stmt::Match {
                        left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
                            key: "state".to_string(),
                            family: None,
                            dir: None,
                        })),
                        right: expr::Expression::String("invalid".to_string()),
                        op: stmt::Operator::IN,
                    }),
                    stmt::Statement::Drop(None),
                ],
            ));
        }

        // Forward chain: jump NETAVARK-ISOLATION-1
        if get_matching_rules_in_chain(
            &existing_rules,
            FORWARDCHAIN,
            get_rule_matcher_jump_to(ISOLATION1CHAIN.to_string()),
        )
        .is_empty()
        {
            batch.add(make_rule(
                FORWARDCHAIN,
                vec![get_jump_action(ISOLATION1CHAIN)],
            ));
        }

        let match_our_bridge = get_rule_matcher_bridge(&network_setup.bridge_name);

        // If and only if isolation is enabled: add isolation chains.
        // Some isolation rules are shared. Other rules are specific to one type
        // of isolation.
        if let IsolateOption::Normal | IsolateOption::Strict = network_setup.isolation {
            // NETAVARK-ISOLATION-1: iifname <bridgename> oifname != <bridgename> jump NETAVARK-ISOLATION-{2,3}
            // (Exact target varies based on Strict vs Normal Isolation - strict goes to 3, otherwise 2)
            let isolation_1_jump_target = if let IsolateOption::Strict = network_setup.isolation {
                ISOLATION3CHAIN
            } else {
                ISOLATION2CHAIN
            };
            if get_matching_rules_in_chain(&existing_rules, ISOLATION1CHAIN, &match_our_bridge)
                .is_empty()
            {
                batch.add(make_rule(
                    ISOLATION1CHAIN,
                    vec![
                        stmt::Statement::Match(stmt::Match {
                            left: expr::Expression::Named(expr::NamedExpression::Meta(
                                expr::Meta {
                                    key: expr::MetaKey::Iifname,
                                },
                            )),
                            right: expr::Expression::String(network_setup.bridge_name.clone()),
                            op: stmt::Operator::EQ,
                        }),
                        stmt::Statement::Match(stmt::Match {
                            left: expr::Expression::Named(expr::NamedExpression::Meta(
                                expr::Meta {
                                    key: expr::MetaKey::Oifname,
                                },
                            )),
                            right: expr::Expression::String(network_setup.bridge_name.clone()),
                            op: stmt::Operator::NEQ,
                        }),
                        get_jump_action(isolation_1_jump_target),
                    ],
                ));
            }

            // NETAVARK-ISOLATION-2: oifname == <bridgename> drop
            if get_matching_rules_in_chain(&existing_rules, ISOLATION2CHAIN, match_our_bridge)
                .is_empty()
            {
                batch.add(make_rule(
                    ISOLATION2CHAIN,
                    vec![
                        get_dest_bridge_match(&network_setup.bridge_name),
                        stmt::Statement::Drop(None),
                    ],
                ));
            }
        } else {
            // No isolation: insert a rule at position 1 in ISOLATION3 to drop traffic.
            // Do this to make sure the jump from ISOLATION3 to ISOLATION2 below is always the last thing in the chain.
            // NETAVARK-ISOLATION-3: oifname == <bridgename> drop
            if get_matching_rules_in_chain(&existing_rules, ISOLATION3CHAIN, match_our_bridge)
                .is_empty()
            {
                batch.add_cmd(schema::NfCmd::Insert(make_rule(
                    ISOLATION3CHAIN,
                    vec![
                        get_dest_bridge_match(&network_setup.bridge_name),
                        stmt::Statement::Drop(None),
                    ],
                )));
            }
        }

        // Always exists, even when isolation disabled. Must be the last item in the ISOLATION3 chain.
        // NETAVARK-ISOLATION-3: jump NETAVARK-ISOLATION-2
        if get_matching_rules_in_chain(
            &existing_rules,
            ISOLATION3CHAIN,
            get_rule_matcher_jump_to(ISOLATION2CHAIN.to_string()),
        )
        .is_empty()
        {
            batch.add(make_rule(
                ISOLATION3CHAIN,
                vec![get_jump_action(ISOLATION2CHAIN)],
            ));
        }

        // Basic forwarding for all subnets
        if let Some(nets) = network_setup.subnets {
            for subnet in nets {
                let chain = get_subnet_chain_name(subnet, &network_setup.network_id, false);

                // Add us to firewalld if necessary.
                // Do this first, as firewalld doesn't wipe our rules - so after a reload, we skip everything below.
                firewalld::add_firewalld_if_possible(&subnet);

                // Do we already have a chain for the subnet?
                if get_chain(&existing_rules, &chain).is_some() {
                    continue;
                }

                // We don't. Make one.
                batch.add(make_basic_chain(&chain));

                log::info!("Creating container chain {chain}");

                // Subnet chain: ip daddr <subnet> accept
                batch.add(make_rule(
                    &chain,
                    vec![
                        get_subnet_match(&subnet, "daddr", stmt::Operator::EQ),
                        stmt::Statement::Accept(None),
                    ],
                ));

                // Subnet chain: ip daddr != 224.0.0.0/4 masquerade
                let multicast_address: IpNet = match subnet {
                    IpNet::V4(_) => "224.0.0.0/4".parse()?,
                    IpNet::V6(_) => "ff::00/8".parse()?,
                };
                batch.add(make_rule(
                    &chain,
                    vec![
                        get_subnet_match(&multicast_address, "daddr", stmt::Operator::NEQ),
                        stmt::Statement::Masquerade(None),
                    ],
                ));

                // Next, populate basic chains with forwarding rules
                // Input chain: ip saddr <subnet> udp dport 53 accept
                batch.add(make_rule(
                    INPUTCHAIN,
                    vec![
                        get_subnet_match(&subnet, "saddr", stmt::Operator::EQ),
                        stmt::Statement::Match(stmt::Match {
                            left: expr::Expression::Named(expr::NamedExpression::Payload(
                                expr::Payload::PayloadField(expr::PayloadField {
                                    protocol: "udp".to_string(),
                                    field: "dport".to_string(),
                                }),
                            )),
                            right: expr::Expression::Number(53),
                            op: stmt::Operator::EQ,
                        }),
                        stmt::Statement::Accept(None),
                    ],
                ));
                // Forward chain: ip daddr <subnet> ct state related,established accept
                batch.add(make_rule(
                    FORWARDCHAIN,
                    vec![
                        get_subnet_match(&subnet, "daddr", stmt::Operator::EQ),
                        stmt::Statement::Match(stmt::Match {
                            left: expr::Expression::Named(expr::NamedExpression::CT(expr::CT {
                                key: "state".to_string(),
                                family: None,
                                dir: None,
                            })),
                            right: expr::Expression::List(vec![
                                expr::Expression::String("established".to_string()),
                                expr::Expression::String("related".to_string()),
                            ]),
                            op: stmt::Operator::IN,
                        }),
                        stmt::Statement::Accept(None),
                    ],
                ));
                // Forward chain: ip saddr <subnet> accept
                batch.add(make_rule(
                    FORWARDCHAIN,
                    vec![
                        get_subnet_match(&subnet, "saddr", stmt::Operator::EQ),
                        stmt::Statement::Accept(None),
                    ],
                ));
                // Postrouting chain: ip saddr <subnet> jump <chain>
                batch.add(make_rule(
                    POSTROUTINGCHAIN,
                    vec![
                        get_subnet_match(&subnet, "saddr", stmt::Operator::EQ),
                        get_jump_action(&chain),
                    ],
                ));
            }
        }

        let rules = batch.to_nftables();

        helper::apply_ruleset(&rules, None, None)?;

        Ok(())
    }

    fn teardown_network(&self, tear: internal_types::TearDownNetwork) -> NetavarkResult<()> {
        let mut batch = Batch::new();

        let existing_rules = get_netavark_rules()?;

        if let Some(nets) = tear.config.subnets {
            for subnet in nets {
                // Match subnet, either saddr or daddr.
                let match_subnet = |r: &schema::Rule| -> bool {
                    // Statement matching: We only care about match statements.
                    // Don't bother with left side. Just check if what they compare to is our subnet.
                    for statement in &r.expr {
                        match statement {
                            stmt::Statement::Match(m) => match &m.right {
                                expr::Expression::Named(expr::NamedExpression::Prefix(p)) => {
                                    match p.addr.as_ref() {
                                        expr::Expression::String(s) => {
                                            if *s == subnet.addr().to_string()
                                                && subnet.prefix_len() as u32 == p.len
                                            {
                                                return true;
                                            }
                                        }
                                        _ => continue,
                                    }
                                }
                                _ => continue,
                            },
                            _ => continue,
                        }
                    }
                    false
                };

                let mut to_remove: Vec<schema::Rule> = Vec::new();
                to_remove.append(&mut get_matching_rules_in_chain(
                    &existing_rules,
                    INPUTCHAIN,
                    match_subnet,
                ));
                to_remove.append(&mut get_matching_rules_in_chain(
                    &existing_rules,
                    FORWARDCHAIN,
                    match_subnet,
                ));
                to_remove.append(&mut get_matching_rules_in_chain(
                    &existing_rules,
                    POSTROUTINGCHAIN,
                    match_subnet,
                ));

                log::debug!("Removing {} rules", to_remove.len());

                for rule in to_remove {
                    batch.delete(schema::NfListObject::Rule(rule));
                }

                // Delete the chain last
                let chain = get_subnet_chain_name(subnet, &tear.config.network_id, false);
                if let Some(c) = get_chain(&existing_rules, &chain) {
                    batch.delete(schema::NfListObject::Chain(c));
                }

                // After all nftables work is done, remove us from firewalld.
                firewalld::rm_firewalld_if_possible(&subnet);
            }
        }

        let match_our_bridge = get_rule_matcher_bridge(&tear.config.bridge_name);

        let mut isolation_rules: Vec<schema::Rule> = Vec::new();
        isolation_rules.append(&mut get_matching_rules_in_chain(
            &existing_rules,
            ISOLATION1CHAIN,
            &match_our_bridge,
        ));
        isolation_rules.append(&mut get_matching_rules_in_chain(
            &existing_rules,
            ISOLATION2CHAIN,
            &match_our_bridge,
        ));
        isolation_rules.append(&mut get_matching_rules_in_chain(
            &existing_rules,
            ISOLATION3CHAIN,
            &match_our_bridge,
        ));

        log::debug!(
            "Removing {} isolation rules for network",
            isolation_rules.len()
        );
        for rule in isolation_rules {
            batch.delete(schema::NfListObject::Rule(rule));
        }

        let rules = batch.to_nftables();

        helper::apply_ruleset(&rules, None, None)?;
        Ok(())
    }

    fn setup_port_forward(
        &self,
        setup_portfw: internal_types::PortForwardConfig,
    ) -> NetavarkResult<()> {
        let mut batch = Batch::new();

        let existing_rules = get_netavark_rules()?;

        // Need DNAT rules for DNS if Aardvark is not on port 53.
        // Only need one per DNS server IP, so check if they already exist first.
        if setup_portfw.dns_port != 53 {
            for ip in setup_portfw.dns_server_ips {
                let match_dns_ip_dnat = |r: &schema::Rule| {
                    for statement in &r.expr {
                        match statement {
                            stmt::Statement::Match(m) => match &m.right {
                                expr::Expression::String(s) => {
                                    if *s == ip.to_string() {
                                        return true;
                                    }
                                }
                                _ => continue,
                            },
                            _ => continue,
                        }
                    }
                    false
                };
                if !get_matching_rules_in_chain(&existing_rules, DNATCHAIN, match_dns_ip_dnat)
                    .is_empty()
                {
                    continue;
                }

                // We have multiple DNS server IPs. Potentially v4 and v6 both.
                // Only add those when the container has an IP address matching the family.
                match ip {
                    IpAddr::V4(_) => {
                        if setup_portfw.container_ip_v4.is_some() {
                            batch.add(make_dns_dnat_rule(ip, setup_portfw.dns_port));
                        }
                    }
                    IpAddr::V6(_) => {
                        if setup_portfw.container_ip_v6.is_some() {
                            batch.add(make_dns_dnat_rule(ip, setup_portfw.dns_port));
                        }
                    }
                }
            }
        }

        if let Some(ip_v4) = setup_portfw.container_ip_v4 {
            if let Some(subnet_v4) = setup_portfw.subnet_v4 {
                for rule in get_dnat_rules_for_addr_family(
                    ip_v4,
                    subnet_v4,
                    &setup_portfw.network_id,
                    &existing_rules,
                    &setup_portfw,
                )? {
                    batch.add(rule);
                }
            }
        }
        if let Some(ip_v6) = setup_portfw.container_ip_v6 {
            if let Some(subnet_v6) = setup_portfw.subnet_v6 {
                for rule in get_dnat_rules_for_addr_family(
                    ip_v6,
                    subnet_v6,
                    &setup_portfw.network_id,
                    &existing_rules,
                    &setup_portfw,
                )? {
                    batch.add(rule);
                }
            }
        }

        let rules = batch.to_nftables();

        helper::apply_ruleset(&rules, None, None)?;

        Ok(())
    }

    fn teardown_port_forward(
        &self,
        teardown_pf: internal_types::TeardownPortForward,
    ) -> NetavarkResult<()> {
        let mut batch = Batch::new();

        let existing_rules = get_netavark_rules()?;

        let dnat_chain_v4 = teardown_pf
            .config
            .subnet_v4
            .map(|s| get_subnet_chain_name(s, &teardown_pf.config.network_id, true));
        let dnat_chain_v6 = teardown_pf
            .config
            .subnet_v6
            .map(|s| get_subnet_chain_name(s, &teardown_pf.config.network_id, true));

        // We need two matchers for each port.
        // One matching both the port and jumping to either the V4 or V6 chain (to clean NETAVARK_DNAT)
        // One matching just the port, to clean the v4 and v6 chains for the network.
        // As a bonus, the last one needs to match any individual port inside the range.
        if let Some(ports) = teardown_pf.config.port_mappings {
            for port in ports {
                let matcher_port_jump = |r: &schema::Rule| -> bool {
                    let mut match_jump = false;
                    let mut match_port = false;
                    for stmt in &r.expr {
                        // Basically, check for match and jump statements.
                        // For match, check that the right side is appropriate
                        // for our port mapping. Has to handle range vs
                        // singleton.
                        // For jump, make sure that it matches either the v4 or
                        // v6 DNAT chains.
                        // If we find both, the rule matches.
                        match stmt {
                            stmt::Statement::Match(m) => match &m.right {
                                expr::Expression::Number(n) => {
                                    if port.range <= 1 && port.host_port as u32 == *n {
                                        if match_jump {
                                            return true;
                                        }
                                        match_port = true;
                                    }
                                }
                                expr::Expression::Range(r) => {
                                    if port.range > 1 {
                                        if r.range.len() != 2 {
                                            // Malformed range, just return false
                                            return false;
                                        }
                                        match r.range[0] {
                                            expr::Expression::Number(n) => {
                                                if port.host_port as u32 != n {
                                                    continue;
                                                }
                                            }
                                            _ => continue,
                                        }
                                        match r.range[1] {
                                            expr::Expression::Number(n) => {
                                                if (port.host_port + port.range - 1) as u32 == n {
                                                    if match_jump {
                                                        return true;
                                                    }
                                                    match_port = true;
                                                }
                                            }
                                            _ => continue,
                                        }
                                    }
                                }
                                _ => continue,
                            },
                            stmt::Statement::Jump(j) => {
                                if let Some(v4) = &dnat_chain_v4 {
                                    if &j.target == v4 {
                                        if match_port {
                                            return true;
                                        }
                                        match_jump = true;
                                    }
                                }
                                if let Some(v6) = &dnat_chain_v6 {
                                    if &j.target == v6 {
                                        if match_port {
                                            return true;
                                        }
                                        match_jump = true
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                    match_jump && match_port
                };

                let match_all_ports_in_range = |r: &schema::Rule| -> bool {
                    for stmt in &r.expr {
                        match stmt {
                            stmt::Statement::Match(m) => match &m.right {
                                expr::Expression::Number(n) => {
                                    if port.range <= 1 && *n == port.host_port as u32 {
                                        return true;
                                    }
                                    if port.range > 1
                                        && *n >= port.host_port as u32
                                        && *n <= (port.host_port + port.range - 1) as u32
                                    {
                                        return true;
                                    }
                                }
                                expr::Expression::Range(r) => {
                                    if port.range > 1 {
                                        if r.range.len() != 2 {
                                            // Malformed range, just return false
                                            return false;
                                        }
                                        match r.range[0] {
                                            expr::Expression::Number(n) => {
                                                if port.host_port as u32 != n {
                                                    continue;
                                                }
                                            }
                                            _ => continue,
                                        }
                                        match r.range[1] {
                                            expr::Expression::Number(n) => {
                                                if (port.host_port + port.range - 1) as u32 == n {
                                                    return true;
                                                }
                                            }
                                            _ => continue,
                                        }
                                    }
                                }
                                _ => continue,
                            },
                            _ => continue,
                        }
                    }
                    false
                };

                for rule in
                    get_matching_rules_in_chain(&existing_rules, DNATCHAIN, matcher_port_jump)
                {
                    batch.delete(schema::NfListObject::Rule(rule));
                }

                if let Some(v4) = &dnat_chain_v4 {
                    for rule in
                        get_matching_rules_in_chain(&existing_rules, v4, match_all_ports_in_range)
                    {
                        batch.delete(schema::NfListObject::Rule(rule));
                    }
                }
                if let Some(v6) = &dnat_chain_v6 {
                    for rule in
                        get_matching_rules_in_chain(&existing_rules, v6, match_all_ports_in_range)
                    {
                        batch.delete(schema::NfListObject::Rule(rule));
                    }
                }
            }
        }

        if teardown_pf.complete_teardown {
            let match_dns_dnat = |r: &schema::Rule| -> bool {
                for statement in &r.expr {
                    match statement {
                        // Match any DNS server IP
                        stmt::Statement::Match(m) => match &m.right {
                            expr::Expression::String(s) => {
                                for ip in teardown_pf.config.dns_server_ips {
                                    if *s == ip.to_string() {
                                        return true;
                                    }
                                }
                            }
                            _ => continue,
                        },
                        _ => continue,
                    }
                }
                false
            };
            for rule in get_matching_rules_in_chain(&existing_rules, DNATCHAIN, match_dns_dnat) {
                batch.delete(schema::NfListObject::Rule(rule));
            }

            if let Some(v4) = dnat_chain_v4 {
                if let Some(c) = get_chain(&existing_rules, &v4) {
                    batch.delete(schema::NfListObject::Chain(c));
                }
            }
            if let Some(v6) = dnat_chain_v6 {
                if let Some(c) = get_chain(&existing_rules, &v6) {
                    batch.delete(schema::NfListObject::Chain(c));
                }
            }
        }

        let rules = batch.to_nftables();

        helper::apply_ruleset(&rules, None, None)?;

        Ok(())
    }
}

/// Convert a subnet into a chain name.
fn get_subnet_chain_name(subnet: IpNet, net_id: &str, dnat: bool) -> String {
    // nftables is very lenient around chain name lengths.
    // So let's use the full IP to be unambiguous.
    // Replace . and : with _, and / with _nm (netmask), to remove special characters.
    let subnet_clean = subnet
        .to_string()
        .replace('.', "_")
        .replace(':', "-")
        .replace('/', "_nm");
    let net_id_clean = if net_id.len() > 8 {
        net_id.split_at(8).0
    } else {
        net_id
    };

    if dnat {
        format!("nv_{}_{}_dnat", net_id_clean, subnet_clean)
    } else {
        format!("nv_{}_{}", net_id_clean, subnet_clean)
    }
}

/// Get a statement to match the given destination bridge.
/// Always matches using ==.
fn get_dest_bridge_match(bridge: &str) -> stmt::Statement {
    stmt::Statement::Match(stmt::Match {
        left: expr::Expression::Named(expr::NamedExpression::Meta(expr::Meta {
            key: expr::MetaKey::Oifname,
        })),
        right: expr::Expression::String(bridge.to_string()),
        op: stmt::Operator::EQ,
    })
}

/// Get a statement to match the given IP address.
/// Field should be either "saddr" or "daddr" for matching source or destination.
fn get_ip_match(ip: &IpAddr, field: &str, op: stmt::Operator) -> stmt::Statement {
    stmt::Statement::Match(stmt::Match {
        left: ip_to_payload(ip, field),
        right: expr::Expression::String(ip.to_string()),
        op,
    })
}

/// Convert a single IP into a Payload field.
/// Basically, pasts in "ip" or "ip6" in protocol field based on whether this is a v4 or v6 address.
fn ip_to_payload(addr: &IpAddr, field: &str) -> expr::Expression {
    let proto = match addr {
        IpAddr::V4(_) => "ip".to_string(),
        IpAddr::V6(_) => "ip6".to_string(),
    };

    expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
        expr::PayloadField {
            protocol: proto,
            field: field.to_string(),
        },
    )))
}

/// Get a statement to match the given subnet.
/// Field should be either "saddr" or "daddr" for matching source or destination.
fn get_subnet_match(net: &IpNet, field: &str, op: stmt::Operator) -> stmt::Statement {
    stmt::Statement::Match(stmt::Match {
        left: subnet_to_payload(net, field),
        right: expr::Expression::Named(expr::NamedExpression::Prefix(expr::Prefix {
            addr: Box::new(expr::Expression::String(net.addr().to_string())),
            len: net.prefix_len() as u32,
        })),
        op,
    })
}

/// Convert a subnet into a Payload field.
/// Basically, pastes in "ip" or "ip6" in protocol field based on whether this
/// is a v4 or v6 subnet.
fn subnet_to_payload(net: &IpNet, field: &str) -> expr::Expression {
    let proto = match net {
        IpNet::V4(_) => "ip".to_string(),
        IpNet::V6(_) => "ip6".to_string(),
    };

    expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
        expr::PayloadField {
            protocol: proto,
            field: field.to_string(),
        },
    )))
}

/// Get a condition to match destination port/ports based on a given PortMapping.
/// Properly handles port ranges, protocol, etc.
fn get_dport_cond(port: &PortMapping) -> stmt::Statement {
    stmt::Statement::Match(stmt::Match {
        left: expr::Expression::Named(expr::NamedExpression::Payload(expr::Payload::PayloadField(
            expr::PayloadField {
                protocol: port.protocol.clone(),
                field: "dport".to_string(),
            },
        ))),
        right: if port.range > 1 {
            // Ranges are a vector with a length of 2.
            // First value start, second value end.
            let range_vec = vec![
                expr::Expression::Number(port.host_port as u32),
                expr::Expression::Number((port.host_port + port.range - 1) as u32),
            ];
            expr::Expression::Range(expr::Range { range: range_vec })
        } else {
            expr::Expression::Number(port.host_port as u32)
        },
        op: stmt::Operator::EQ,
    })
}

/// Make the first container DNAT chain rule, which is used for both IP and IPv6 DNAT.
fn get_subnet_dport_match(
    dnat_chain: &str,
    subnet: &Option<IpNet>,
    host_ip_match: &Option<stmt::Statement>,
    dport_match: &stmt::Statement,
) -> schema::NfListObject {
    // <dnat_chain> ip saddr <subnet> ip daddr <host IP> <protocol> dport <port(s)> jump MARKCHAIN
    let mut statements: Vec<stmt::Statement> = Vec::new();
    if let Some(net) = &subnet {
        statements.push(get_subnet_match(net, "saddr", stmt::Operator::EQ));
    }

    if let Some(stmt) = host_ip_match {
        statements.push(stmt.clone());
    }

    statements.push(dport_match.clone());
    statements.push(get_jump_action(MASKCHAIN));
    make_rule(dnat_chain, statements)
}

/// Create DNAT rules for each port to be forwarded.
/// Used for both IP and IPv6 DNAT.
fn get_dnat_port_rules(
    dnat_chain: &str,
    port: &PortMapping,
    ip: &IpAddr,
    host_ip_cond: &Option<stmt::Statement>,
) -> Vec<schema::NfListObject> {
    let mut rules: Vec<schema::NfListObject> = Vec::new();

    // Container dnat chain: ip daddr <host IP> <proto> dport <port> dnat to <container ip: container port>
    // Unfortunately: We don't have range support in the schema. So we need 1 rule per port.
    let range = if port.range == 0 { 1 } else { port.range };
    for i in 0..range {
        let host_port: u32 = (port.host_port + i) as u32;
        let ctr_port: u32 = (port.container_port + i) as u32;

        let mut statements: Vec<stmt::Statement> = Vec::new();
        if let Some(stmt) = host_ip_cond {
            statements.push(stmt.clone());
        }
        statements.push(stmt::Statement::Match(stmt::Match {
            left: expr::Expression::Named(expr::NamedExpression::Payload(
                expr::Payload::PayloadField(expr::PayloadField {
                    protocol: port.protocol.clone(),
                    field: "dport".to_string(),
                }),
            )),
            right: expr::Expression::Number(host_port),
            op: stmt::Operator::EQ,
        }));
        statements.push(stmt::Statement::DNAT(Some(stmt::NAT {
            addr: Some(expr::Expression::String(ip.to_string())),
            family: Some(if ip.is_ipv6() {
                stmt::NATFamily::IP6
            } else {
                stmt::NATFamily::IP
            }),
            port: Some(ctr_port),
            flags: None,
        })));
        rules.push(make_rule(dnat_chain, statements));
    }

    rules
}

fn get_dnat_rules_for_addr_family(
    ip: IpAddr,
    subnet: IpNet,
    net_id: &str,
    existing_rules: &schema::Nftables,
    setup_portfw: &internal_types::PortForwardConfig,
) -> NetavarkResult<Vec<schema::NfListObject>> {
    let mut rules: Vec<schema::NfListObject> = Vec::new();

    if let Some(ports) = setup_portfw.port_mappings {
        let subnet_dnat_chain = get_subnet_chain_name(subnet, net_id, true);

        // Make the chain if it does not exist
        if get_chain(existing_rules, &subnet_dnat_chain).is_none() {
            rules.push(make_basic_chain(&subnet_dnat_chain));
        }

        for port in ports {
            // Condition to match destination ports (ports on the host)
            let dport_cond = get_dport_cond(port);
            // Destination address is only if user set an IP on the host to bind to.
            // Used by multiple rules in this section.
            // We need to ignore wildcards, but only if our IP family matches the wildcard.
            // If it doesn't, don't add any rules.
            let daddr: Option<IpAddr> = if !port.host_ip.is_empty() {
                if port.host_ip == "0.0.0.0" {
                    if ip.is_ipv6() {
                        continue;
                    }
                    None
                } else if port.host_ip == "::" {
                    if ip.is_ipv4() {
                        continue;
                    }
                    None
                } else {
                    match port.host_ip.parse() {
                        Ok(i) => Some(i),
                        Err(_) => {
                            return Err(NetavarkError::msg(format!(
                                "invalid host ip \"{}\" provided for port {}",
                                port.host_ip, port.host_port
                            )));
                        }
                    }
                }
            } else {
                None
            };

            // Do not add rules where the address family of host address does not match container address.
            if let Some(host_ip) = daddr {
                if ip.is_ipv4() != host_ip.is_ipv4() {
                    continue;
                }
            }
            let daddr_cond: Option<stmt::Statement> =
                daddr.map(|i| get_ip_match(&i, "daddr", stmt::Operator::EQ));

            // dnat chain: <protocol> dport <port> jump <container_dnat_chain>
            rules.push(make_rule(
                DNATCHAIN,
                vec![dport_cond.clone(), get_jump_action(&subnet_dnat_chain)],
            ));

            // Container dnat chain: ip saddr <subnet> ip daddr <host IP> <proto> dport <port(s)> jump SETMARKCHAIN
            rules.push(get_subnet_dport_match(
                &subnet_dnat_chain,
                &Some(subnet),
                &daddr_cond,
                &dport_cond,
            ));

            // This rule is only used for v4.
            if ip.is_ipv4() {
                // Container dnat chain: ip saddr 127.0.0.1 ip daddr <host IP> <proto> dport <port(s)> jump SETMARKCHAIN
                let mut localhost_jump_statements: Vec<stmt::Statement> = Vec::new();
                localhost_jump_statements.push(get_ip_match(
                    &("127.0.0.1".parse()?),
                    "saddr",
                    stmt::Operator::EQ,
                ));
                if let Some(stmt) = &daddr_cond {
                    localhost_jump_statements.push(stmt.clone());
                }
                localhost_jump_statements.push(dport_cond);
                localhost_jump_statements.push(get_jump_action(MASKCHAIN));
                rules.push(make_rule(&subnet_dnat_chain, localhost_jump_statements));
            }

            for rule in get_dnat_port_rules(&subnet_dnat_chain, port, &ip, &daddr_cond) {
                rules.push(rule);
            }
        }
    }

    Ok(rules)
}

/// Make a DNAT rule to allow DNS traffic to a DNS server on a non-standard port (53 -> actual port).
fn make_dns_dnat_rule(dns_ip: &IpAddr, dns_port: u16) -> schema::NfListObject {
    make_rule(
        DNATCHAIN,
        vec![
            get_ip_match(dns_ip, "daddr", stmt::Operator::EQ),
            stmt::Statement::Match(stmt::Match {
                left: expr::Expression::Named(expr::NamedExpression::Payload(
                    expr::Payload::PayloadField(expr::PayloadField {
                        protocol: "udp".to_string(),
                        field: "dport".to_string(),
                    }),
                )),
                right: expr::Expression::Number(53),
                op: stmt::Operator::EQ,
            }),
            stmt::Statement::DNAT(Some(stmt::NAT {
                addr: Some(expr::Expression::String(dns_ip.to_string())),
                family: Some(if dns_ip.is_ipv6() {
                    stmt::NATFamily::IP6
                } else {
                    stmt::NATFamily::IP
                }),
                port: Some(dns_port as u32),
                flags: None,
            })),
        ],
    )
}

/// Create a statement to jump to the given target
fn get_jump_action(target: &str) -> stmt::Statement {
    stmt::Statement::Jump(stmt::JumpTarget {
        target: target.to_string(),
    })
}

/// Create an instruction to make a basic chain (no hooks, no priority).
/// Chain is always inet, always in our overall netavark table.
fn make_basic_chain(name: &str) -> schema::NfListObject {
    schema::NfListObject::Chain(schema::Chain::new(
        types::NfFamily::INet,
        TABLENAME.to_string(),
        name.to_string(),
        None,
        None,
        None,
        None,
        None,
    ))
}

/// Create a more complicated chain with hooks and priority.
/// Policy is always accept, because we don't need anything else.
fn make_complex_chain(
    name: &str,
    chain_type: types::NfChainType,
    hook: types::NfHook,
    priority: i32,
) -> schema::NfListObject {
    schema::NfListObject::Chain(schema::Chain::new(
        types::NfFamily::INet,
        TABLENAME.to_string(),
        name.to_string(),
        Some(chain_type),
        Some(hook),
        Some(priority),
        None,
        Some(types::NfChainPolicy::Accept),
    ))
}

/// Make a rule in the given chain with the given conditions
fn make_rule(chain: &str, conditions: Vec<stmt::Statement>) -> schema::NfListObject {
    schema::NfListObject::Rule(schema::Rule::new(
        types::NfFamily::INet,
        TABLENAME.to_string(),
        chain.to_string(),
        conditions,
    ))
}

/// Make a closure that matches any rule that jumps to the given chain.
fn get_rule_matcher_jump_to(jump_target: String) -> Box<dyn Fn(&schema::Rule) -> bool> {
    Box::new(move |r: &schema::Rule| -> bool {
        for statement in &r.expr {
            match statement {
                stmt::Statement::Jump(j) => {
                    return j.target == jump_target;
                }
                _ => continue,
            }
        }
        false
    })
}

/// Make a closure that matches any rule that tests for a match to a given bridge interface.
fn get_rule_matcher_bridge(bridge: &String) -> impl '_ + Fn(&schema::Rule) -> bool {
    move |r: &schema::Rule| -> bool {
        for statement in &r.expr {
            match statement {
                stmt::Statement::Match(m) => match &m.right {
                    expr::Expression::String(s) => {
                        if *s == *bridge {
                            return true;
                        }
                    }
                    _ => continue,
                },
                _ => continue,
            }
        }
        false
    }
}

/// Find all rules in the given chain which match the given closure (true == include).
/// Returns all those rules, in a vector. Vector will be empty if there are none.
fn get_matching_rules_in_chain<F: Fn(&schema::Rule) -> bool>(
    base_rules: &schema::Nftables,
    chain: &str,
    rule_match: F,
) -> Vec<schema::Rule> {
    let mut rules: Vec<schema::Rule> = Vec::new();

    // Basically, we get back a big, flat array of everything in the table.
    // That makes this an absolute destructuring nightmare, but there's no avoiding it.
    // Ignore everything we get back that is not a rule.
    // Then ignore everything that is not in our table (not passed, but we only use one table).
    // Then ignore everything that is not in the given chain.
    // Then check conditions and add to the vector if it matches.
    for object in &base_rules.objects {
        match object {
            schema::NfObject::CmdObject(_) => continue,
            schema::NfObject::ListObject(obj) => match obj {
                schema::NfListObject::Rule(r) => {
                    if r.chain != *chain {
                        continue;
                    }

                    if rule_match(r) {
                        log::debug!("Matched {:?}", r);
                        rules.push(r.clone());
                    }
                }
                _ => continue,
            },
        }
    }

    rules
}

/// Get a chain with the given name in the Netavark table.
fn get_chain(base_rules: &schema::Nftables, chain: &str) -> Option<schema::Chain> {
    for object in &base_rules.objects {
        match object {
            schema::NfObject::CmdObject(_) => continue,
            schema::NfObject::ListObject(obj) => match obj {
                schema::NfListObject::Chain(c) => {
                    if c.name == *chain {
                        log::debug!("Found chain {}", chain);
                        return Some(c.clone());
                    }
                }
                _ => continue,
            },
        }
    }

    None
}

fn get_netavark_rules() -> Result<schema::Nftables, helper::NftablesError> {
    match helper::get_current_ruleset(None, Some(vec!["list", "table", "inet", TABLENAME])) {
        Ok(rules) => Ok(rules),
        Err(err) => match err {
            helper::NftablesError::NftFailed {
                program: _,
                hint: _,
                stdout: _,
                ref stderr,
            } => {
                // OK this is hacky but seems to work, when we run the first time after the boot the
                // netavark table does not exists to the list table call will fail (nft exit code 1).
                // Just return an empty ruleset in this case.
                if stderr.contains("No such file or directory") {
                    Ok(schema::Nftables { objects: vec![] })
                } else {
                    Err(err)
                }
            }

            err => Err(err),
        },
    }
}
