use crate::error::{NetavarkError, NetavarkResult};
use crate::network::bridge::parse_bridge_opts;
use crate::network::constants;
use crate::network::core_utils::CoreUtils;
use crate::network::create_config::subnet::{
    get_free_ipv4_network_subnet, get_free_ipv6_network_subnet,
};
use crate::network::netlink::Socket;
use crate::network::netlink_route::NetlinkRoute;
use crate::network::plugin::{
    exec_plugin_common, handle_plugin_error, handle_plugin_killed, PluginResult,
};
use crate::network::types::{CreateOpts, Network, Used};
use crate::network::vlan::parse_vlan_opts;
use netlink_packet_route::link::LinkAttribute;
use regex::Regex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn setup_bridge_options(network: &mut Network) -> NetavarkResult<(bool, bool)> {
    let Some(network_opts) = &mut network.options else {
        return Ok((true, true));
    };

    // validate the given options
    if let Some(value) = network_opts.remove("com.docker.network.driver.mtu") {
        network_opts.insert(constants::OPTION_MTU.to_string(), value);
    }
    if let Some(value) = network_opts.remove("com.docker.network.bridge.name") {
        network.network_interface = Some(value);
    }

    let mut check_used = true;
    let mut check_bridge_conflict = true;

    let bridge_opts = parse_bridge_opts(&network.options, true)?;
    if bridge_opts.vlan.is_some()
        || (bridge_opts.mode.is_some() && bridge_opts.mode.unwrap() != "managed")
    {
        check_used = false;
        check_bridge_conflict = false;
    }
    Ok((check_used, check_bridge_conflict))
}

pub fn create_bridge(
    network: &mut Network,
    used: &Used,
    check_used: bool,
    check_bridge_conflict: bool,
    opts: CreateOpts,
) -> NetavarkResult<()> {
    match &network.network_interface {
        Some(interface) => {
            if check_bridge_conflict && used.interfaces.contains(interface) {
                return Err(NetavarkError::msg(format!(
                    "bridge name {} already in use",
                    interface
                )));
            }
            let interface_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$").unwrap();
            if !interface_regex.is_match(interface) {
                return Err(NetavarkError::msg(format!(
                    "bridge name {} is invalid",
                    interface
                )));
            }
        }
        None => {
            network.network_interface = Some(get_free_device_name(
                &opts.default_interface_name,
                &used.interfaces,
                &used.names,
            )?);
        }
    }

    // Check if IPAM driver is unset, empty, or set to host-local
    // Support both "driver" and "types.Driver" keys for compatibility
    let should_use_hostlocal = network
        .ipam_options
        .as_ref()
        .and_then(|ipam_opts| ipam_opts.get("driver"))
        .map(|driver| driver.is_empty() || driver == constants::IPAM_HOSTLOCAL)
        .unwrap_or(true); // Default to true if no IPAM options (means no driver set = use host-local)

    if should_use_hostlocal {
        let has_subnets = network
            .subnets
            .as_ref()
            .is_some_and(|subnets| !subnets.is_empty());
        if !has_subnets {
            let free_subnet =
                get_free_ipv4_network_subnet(&used.subnets, &opts.subnet_pools, check_used)?;
            network.subnets = Some(vec![free_subnet]);
        }
        if network.ipv6_enabled {
            if let Some(subnets) = &network.subnets {
                let mut ipv4 = false;
                let mut ipv6 = false;
                for subnet in subnets {
                    if let ipnet::IpNet::V6(_) = &subnet.subnet {
                        ipv6 = true
                    }
                    if let ipnet::IpNet::V4(_) = &subnet.subnet {
                        ipv4 = true
                    }
                }
                let mut updated_subnets = subnets.clone();
                if !ipv4 {
                    let free_subnet = get_free_ipv4_network_subnet(
                        &used.subnets,
                        &opts.subnet_pools,
                        check_used,
                    )?;
                    updated_subnets.push(free_subnet);
                }
                if !ipv6 {
                    let free_subnet = get_free_ipv6_network_subnet(&used.subnets)?;
                    updated_subnets.push(free_subnet);
                }
                if !ipv4 || !ipv6 {
                    network.subnets = Some(updated_subnets);
                }
            }
        }
        network
            .ipam_options
            .get_or_insert_with(HashMap::new)
            .insert("driver".to_string(), constants::IPAM_HOSTLOCAL.to_string());
    }

    Ok(())
}

pub fn create_ipvlan_macvlan(network: &mut Network) -> NetavarkResult<()> {
    if let Some(interface) = &network.network_interface {
        if let Some(interface_names) = get_link_names() {
            if !interface_names.contains(interface) {
                return Err(NetavarkError::msg(format!(
                    "parent interface {} does not exist",
                    interface
                )));
            }
        }
    }

    let driver = &network.driver;
    let is_macvlan = driver != constants::DRIVER_IPVLAN;

    // always turn dns off with macvlan, it is not implemented in netavark
    // and makes little sense to support with macvlan
    // see https://github.com/containers/netavark/pull/467
    network.dns_enabled = false;

    // we already validated the drivers before so we just have to set the default here
    let ipam_opts = network.ipam_options.get_or_insert_with(HashMap::new);
    let ipam_driver = ipam_opts.get("driver").map(|s| s.as_str()).unwrap_or("");

    match ipam_driver {
        "" => {
            let subnets_len = network.subnets.as_ref().map_or(0, |s| s.len());
            if subnets_len == 0 {
                // if no subnets and no driver choose dhcp
                ipam_opts.insert("driver".to_string(), constants::IPAM_DHCP.to_string());
                if !is_macvlan {
                    return Err(NetavarkError::msg(
                        "ipam driver dhcp is not supported with ipvlan",
                    ));
                }
            } else {
                ipam_opts.insert("driver".to_string(), constants::IPAM_HOSTLOCAL.to_string());
            }
        }
        d if d == constants::IPAM_HOSTLOCAL => {
            let subnets_len = network.subnets.as_ref().map_or(0, |s| s.len());
            if subnets_len == 0 {
                return Err(NetavarkError::msg(format!(
                    "{} driver needs at least one subnet specified when the host-local ipam driver is set",
                    driver
                )));
            }
        }
        d if d == constants::IPAM_DHCP => {
            if !is_macvlan {
                return Err(NetavarkError::msg(
                    "ipam driver dhcp is not supported with ipvlan",
                ));
            }
            let subnets_len = network.subnets.as_ref().map_or(0, |s| s.len());
            if subnets_len > 0 {
                return Err(NetavarkError::msg(
                    "ipam driver dhcp set but subnets are set",
                ));
            }
        }
        _ => {}
    }

    // validate the given options, we do not need them but just check to make sure they are valid
    let vlan_opts = parse_vlan_opts(&network.options, true)?;
    if vlan_opts.mode.is_some() {
        if is_macvlan {
            CoreUtils::get_macvlan_mode_from_string(vlan_opts.mode.as_deref())?;
        } else {
            CoreUtils::get_ipvlan_mode_from_string(vlan_opts.mode.as_deref())?;
        }
        if vlan_opts.bclim.is_some() && !is_macvlan {
            return Err(NetavarkError::msg(
                "bclim is not supported with ipvlan".to_string(),
            ));
        }
    }

    Ok(())
}

fn get_free_device_name(
    default_interface_name: &Option<String>,
    used_interfaces: &[String],
    used_networks: &HashMap<String, String>,
) -> NetavarkResult<String> {
    let prefix = default_interface_name
        .as_deref()
        .ok_or_else(|| NetavarkError::msg("default interface name is not set"))?;
    let mut names = get_link_names().unwrap_or_default();
    names.extend(used_interfaces.iter().cloned());
    names.extend(used_networks.keys().cloned());
    for i in 1..1_000_000 {
        let device_name = format!("{}{}", prefix, i);
        if !names.contains(&device_name) {
            return Ok(device_name);
        }
    }

    Err(NetavarkError::msg(
        "Could not find a free device name after 1,000,000 attempts",
    ))
}

pub fn exec_plugin_driver(
    network: &mut Network,
    plugin_directories: &Option<Vec<OsString>>,
) -> NetavarkResult<()> {
    // Find the plugin binary
    let driver_name = &network.driver;
    let plugin_path = if let Some(dirs) = plugin_directories {
        let found_path = dirs.iter().find_map(|dir| {
            let path = Path::new(dir).join(driver_name);
            if let Ok(meta) = path.metadata() {
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                    return Some(path);
                }
            }
            None
        });
        found_path.ok_or_else(|| {
            NetavarkError::msg(format!(
                "plugin for driver \"{}\" not found in plugin directories",
                driver_name
            ))
        })?
    } else {
        return Err(NetavarkError::msg(
            "plugin directory not provided".to_string(),
        ));
    };

    // Clone the network since we need to send it via JSON
    let input = network.clone();

    let result = exec_plugin_common(&plugin_path, &["create"], &input)?;
    let plugin_name = plugin_path.file_name();

    match result {
        PluginResult::Success(buffer) => {
            // read the modified network config
            let updated_network: Network = serde_json::from_slice(&buffer)?;
            // Update the network with the plugin's response
            *network = updated_network;
            Ok(())
        }
        PluginResult::Error { code, buffer } => {
            // exit code not 0 => error
            Err(handle_plugin_error(code, &buffer, plugin_name))
        }
        PluginResult::Killed => {
            // If we could not get the exit code then the process was killed by a signal.
            // I don't think it is necessary to read and return the signal so we just return a generic error.
            Err(handle_plugin_killed(plugin_name))
        }
    }
}

fn get_link_names() -> Option<Vec<String>> {
    let mut sock = Socket::<NetlinkRoute>::new().ok()?;
    let links = sock.dump_links(&mut vec![]).ok()?;

    let mut names = Vec::with_capacity(links.len());

    for link in links {
        for attribute in link.attributes.into_iter() {
            if let LinkAttribute::IfName(name) = attribute {
                names.push(name);
                break;
            }
        }
    }

    Some(names)
}
