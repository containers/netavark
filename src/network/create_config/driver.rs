use crate::network::constants;
use crate::network::create_config::subnet::{
    get_free_ipv4_network_subnet, get_free_ipv6_network_subnet,
};
use crate::network::types::{CreateOpts, Network, Used};
use crate::{
    error::{JsonError, NetavarkError, NetavarkResult},
    wrap,
};
use pnet::datalink;
use regex::Regex;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

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

    // Collect keys to avoid borrowing issues when modifying the map
    let keys: Vec<String> = network_opts.keys().cloned().collect();

    for key in keys {
        let value = network_opts.get(&key).expect("key should exist");
        match key.as_str() {
            constants::OPTION_MTU => {
                parse_mtu(value)?;
            }
            constants::OPTION_VLAN => {
                parse_vlan(value)?;
                check_used = false;
                check_bridge_conflict = false;
            }
            constants::OPTION_ISOLATE => {
                let iso = parse_isolate(value)?;
                network_opts.insert(key, iso);
            }
            constants::OPTION_METRIC => {
                parse_metric(value)?;
            }
            constants::OPTION_NO_DEFAULT_ROUTE => {
                let ndr = parse_no_default_route(value)?;
                network_opts.insert(key, ndr);
            }
            constants::OPTION_VRF => {
                if value.is_empty() {
                    return Err(NetavarkError::msg(format!("invalid vrf name: {}", value)));
                }
            }
            constants::OPTION_MODE => {
                check_used = false;
                check_bridge_conflict = false;
            }
            _ => {
                return Err(NetavarkError::msg(format!(
                    "unsupported bridge network option {}",
                    key
                )))
            }
        }
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
        let interface_names: Vec<String> = datalink::interfaces()
            .into_iter()
            .map(|iface| iface.name)
            .collect();
        if !interface_names.contains(interface) {
            return Err(NetavarkError::msg(format!(
                "parent interface {} does not exist",
                interface
            )));
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
    if let Some(options) = &network.options {
        let options_clone = options.clone();
        for (key, value) in options_clone {
            match key.as_str() {
                constants::OPTION_MODE => {
                    if is_macvlan {
                        if !constants::VALID_MACVLAN_MODES.contains(&value.as_str()) {
                            return Err(NetavarkError::msg(format!(
                                "unknown macvlan mode {:?}",
                                value
                            )));
                        }
                    } else if !constants::VALID_IPVLAN_MODES.contains(&value.as_str()) {
                        return Err(NetavarkError::msg(format!(
                            "unknown ipvlan mode {:?}",
                            value
                        )));
                    }
                }
                constants::OPTION_METRIC => {
                    value.parse::<u32>().map_err(|e| {
                        NetavarkError::msg(format!("Failed to parse metric: {}", e))
                    })?;
                }
                constants::OPTION_MTU => {
                    parse_mtu(&value)?;
                }
                constants::OPTION_NO_DEFAULT_ROUTE => {
                    let val = parse_no_default_route(&value)?;
                    // rust only support "true" or "false" while go can parse 1 and 0 as well so we need to change it
                    if let Some(opts) = &mut network.options {
                        opts.insert(key.clone(), val.to_string());
                    }
                }
                constants::OPTION_BCLIM => {
                    if is_macvlan {
                        value.parse::<i32>().map_err(|e| {
                            NetavarkError::msg(format!("failed to parse {:?} option: {}", key, e))
                        })?;
                        // do not fallthrough for macvlan
                    } else {
                        // bclim is only valid for macvlan not ipvlan so fallthrough to error case
                        return Err(NetavarkError::msg(format!(
                            "unsupported {} network option {}",
                            driver, key
                        )));
                    }
                }
                _ => {
                    return Err(NetavarkError::msg(format!(
                        "unsupported {} network option {}",
                        driver, key
                    )));
                }
            }
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
    let mut names: Vec<String> = datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect();
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

fn parse_mtu(mtu: &str) -> NetavarkResult<u32> {
    if mtu.is_empty() {
        return Ok(0);
    }
    mtu.parse::<u32>()
        .map_err(|e| NetavarkError::msg(format!("Failed to parse mtu: {}", e)))
}

fn parse_vlan(vlan: &str) -> NetavarkResult<u32> {
    if vlan.is_empty() {
        return Ok(0);
    }
    let n = vlan
        .parse::<u32>()
        .map_err(|e| NetavarkError::msg(format!("Failed to parse: {}", e)))?;
    if n > 4094 {
        return Err(NetavarkError::msg(format!(
            "vlan id {} must be between 0 and 4094",
            n
        )));
    }
    Ok(n)
}

fn parse_isolate(isolate: &str) -> NetavarkResult<String> {
    match isolate {
        "" => Ok(String::from("false")),
        "1" => Ok(String::from("true")),
        "0" => Ok(String::from("false")),
        "strict" | "true" | "false" => Ok(isolate.to_string()),
        _ => Err(NetavarkError::msg(format!(
            "failed to parse isolate option {}",
            isolate
        ))),
    }
}

fn parse_no_default_route(ndr: &str) -> NetavarkResult<String> {
    match ndr {
        "" => Ok(String::from("false")),
        "1" => Ok(String::from("true")),
        "0" => Ok(String::from("false")),
        "strict" | "true" | "false" => Ok(ndr.to_string()),
        _ => Err(NetavarkError::msg(format!(
            "invalid no_default_route value {}",
            ndr
        ))),
    }
}

fn parse_metric(metric: &str) -> NetavarkResult<u32> {
    metric
        .parse::<u32>()
        .map_err(|e| NetavarkError::msg(format!("Failed to parse metric: {}", e)))
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

    let mut child = Command::new(&plugin_path)
        .arg("create")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdin = child.stdin.take().unwrap();
    serde_json::to_writer(&stdin, &input)?;
    // Close stdin here to avoid that the plugin waits forever for an EOF.
    // And then we would wait for the child to exit which would cause a hang.
    drop(stdin);

    // Note: We need to buffer the output and then deserialize into the correct type after
    // the plugin exits, since the plugin can return two different json types depending on
    // the exit code.
    let mut buffer: Vec<u8> = Vec::new();

    let mut stdout = child.stdout.take().unwrap();
    // Do not handle error here, we have to wait for the child first.
    let result = stdout.read_to_end(&mut buffer);

    let exit_status = wrap!(child.wait(), "wait for plugin to exit")?;
    if let Some(rc) = exit_status.code() {
        // make sure the buffer is correct
        wrap!(result, "read into buffer")?;
        if rc == 0 {
            // read the modified network config
            let updated_network: Network = serde_json::from_slice(&buffer)?;
            // Update the network with the plugin's response
            *network = updated_network;
            Ok(())
        } else {
            // exit code not 0 => error
            let err: JsonError = serde_json::from_slice(&buffer)?;
            Err(NetavarkError::msg(format!(
                "plugin {:?} failed with exit code {}, message: {}",
                plugin_path.file_name().unwrap_or_default(),
                rc,
                err.error
            )))
        }
    } else {
        // If we could not get the exit code then the process was killed by a signal.
        // I don't think it is necessary to read and return the signal so we just return a generic error.
        Err(NetavarkError::msg(format!(
            "plugin {:?} killed by signal",
            plugin_path.file_name().unwrap_or_default()
        )))
    }
}
