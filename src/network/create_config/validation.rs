use crate::error::{NetavarkError, NetavarkResult};
use crate::network::constants;
use crate::network::create_config::subnet::network_intersects_with_networks;
use crate::network::types::{Network, Route, Subnet};
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

pub fn validate_name_id(
    name: &str,
    id: &str,
    existing_networks: &HashMap<String, String>,
) -> NetavarkResult<()> {
    if name.is_empty() {
        return Err(NetavarkError::msg("Network name must be supplied"));
    }
    let name_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$").unwrap();
    if !name_regex.is_match(name) {
        return Err(NetavarkError::msg(
            "Invalid characters in network name: must match [a-zA-Z0-9][a-zA-Z0-9_.-]",
        ));
    }
    if existing_networks.contains_key(name) {
        return Err(NetavarkError::msg(format!(
            "network already exists {}",
            name
        )));
    }

    if id.is_empty() {
        return Err(NetavarkError::msg("Network id must be supplied"));
    }
    if id.len() != 64 {
        return Err(NetavarkError::msg(format!(
            "Network id must be exactly 64 characters long, got {}",
            id.len()
        )));
    }
    let hex_regex = Regex::new(r"^[0-9a-fA-F]{64}$").unwrap();
    if !hex_regex.is_match(id) {
        return Err(NetavarkError::msg(
            "Network id must be a hexadecimal string",
        ));
    }
    Ok(())
}

// validate_interface_name validates the interface name based on the following rules:
// 1. The name must be less than MaxInterfaceNameLength characters
// 2. The name must not be "." or ".."
// 3. The name must not contain / or : or any whitespace characters
// ref to https://github.com/torvalds/linux/blob/81e4f8d68c66da301bb881862735bd74c6241a19/include/uapi/linux/if.h#L33C18-L33C20
pub fn validate_interface_name(if_name: &str) -> NetavarkResult<()> {
    if if_name.chars().count() > constants::MAX_INTERFACE_NAME_LEN {
        return Err(NetavarkError::msg(format!(
            "Interface name is too long: interface names must be {} characters or less: {}",
            constants::MAX_INTERFACE_NAME_LEN,
            if_name
        )));
    }
    if if_name.is_empty() || if_name == ".." {
        return Err(NetavarkError::msg("Interface name cannot be . or .."));
    }

    if let Some(bad) = if_name
        .chars()
        .find(|&c| c == '/' || c == ':' || c.is_whitespace())
    {
        return Err(NetavarkError::msg(format!(
            "Interface name cannot contain\"{}\"",
            bad
        )));
    }

    Ok(())
}

pub fn validate_ipam_driver(
    ipam_opts: &Option<HashMap<String, String>>,
    subnets: &Option<Vec<Subnet>>,
) -> NetavarkResult<()> {
    let Some(ipam_opts) = ipam_opts.as_ref() else {
        return Ok(());
    };

    let ipam_driver = ipam_opts.get("driver");
    match ipam_driver {
        None => Ok(()),
        Some(driver) if driver == constants::IPAM_HOSTLOCAL || driver == constants::IPAM_DHCP => {
            Ok(())
        }
        Some(driver) if driver == constants::IPAM_NONE => {
            let subnetlen = subnets.as_ref().map_or(0, |v| v.len());
            if subnetlen > 0 {
                return Err(NetavarkError::msg(
                    "None ipam driver is set but subnets are given",
                ));
            }
            Ok(())
        }
        Some(driver) => Err(NetavarkError::msg(format!(
            "Unsupported ipam driver: {}",
            driver
        ))),
    }
}

pub fn validate_subnets(
    network: &mut Network,
    add_gateway: bool,
    check_used: bool,
    used_networks: &[IpNet],
) -> NetavarkResult<()> {
    let Some(subnets) = &mut network.subnets else {
        return Ok(());
    };

    for subnet in subnets {
        validate_subnet(subnet, add_gateway, check_used, used_networks)?;
    }

    Ok(())
}

/// Get the first IP address in a subnet (network address + 1).
fn first_ip_in_subnet(network: &IpNet) -> NetavarkResult<IpAddr> {
    match network {
        IpNet::V4(net_v4) => {
            let network_addr: u32 = net_v4.network().into();
            let first_ip = network_addr
                .checked_add(1)
                .ok_or_else(|| NetavarkError::msg("Subnet address overflow"))?;
            Ok(IpAddr::V4(first_ip.into()))
        }
        IpNet::V6(net_v6) => {
            use std::net::Ipv6Addr;
            let network_addr = net_v6.network();
            // Convert to u128, add 1, convert back to octets
            let addr_u128: u128 = u128::from_be_bytes(network_addr.octets());
            let first_ip_u128 = addr_u128
                .checked_add(1)
                .ok_or_else(|| NetavarkError::msg("Subnet address overflow"))?;
            Ok(IpAddr::V6(Ipv6Addr::from(first_ip_u128.to_be_bytes())))
        }
    }
}

/// Validate lease range IP addresses against a subnet.
/// Ensures both IPs are valid, in the subnet, same version, and start_ip <= end_ip.
fn validate_lease_range(
    lease_range: &crate::network::types::LeaseRange,
    subnet: &IpNet,
) -> NetavarkResult<()> {
    // Parse start_ip if present
    let start_ip = if let Some(ref start_str) = lease_range.start_ip {
        let ip = IpAddr::from_str(start_str)
            .map_err(|e| NetavarkError::msg(format!("invalid start_ip: {}", e)))?;
        if !subnet.contains(&ip) {
            return Err(NetavarkError::msg(format!(
                "lease range start_ip {} not in subnet {}",
                ip, subnet
            )));
        }
        Some(ip)
    } else {
        None
    };

    // Parse end_ip if present
    let end_ip = if let Some(ref end_str) = lease_range.end_ip {
        let ip = IpAddr::from_str(end_str)
            .map_err(|e| NetavarkError::msg(format!("invalid end_ip: {}", e)))?;
        if !subnet.contains(&ip) {
            return Err(NetavarkError::msg(format!(
                "lease range end_ip {} not in subnet {}",
                ip, subnet
            )));
        }
        Some(ip)
    } else {
        None
    };

    // If both are present, validate the range
    if let (Some(start), Some(end)) = (start_ip, end_ip) {
        // Ensure both are the same IP version
        match (start, end) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                return Err(NetavarkError::msg(
                    "lease range start_ip and end_ip must be the same IP version",
                ));
            }
            _ => {}
        }

        // Ensure start_ip <= end_ip
        if start > end {
            return Err(NetavarkError::msg(format!(
                "lease range start_ip {} must be less than or equal to end_ip {}",
                start, end
            )));
        }
    }

    Ok(())
}

/// Validate a single subnet.
/// This function validates the subnet, checks for conflicts with used networks,
/// validates/creates the gateway, and validates the lease range.
pub fn validate_subnet(
    s: &mut Subnet,
    add_gateway: bool,
    check_used: bool,
    used_networks: &[IpNet],
) -> NetavarkResult<()> {
    // Check that the new subnet does not conflict with existing ones
    if check_used && network_intersects_with_networks(&s.subnet, used_networks) {
        return Err(NetavarkError::msg(format!(
            "subnet {} is already used on the host or by another config",
            s.subnet
        )));
    }

    // Validate or create gateway
    if let Some(ref gateway) = s.gateway {
        if !s.subnet.contains(gateway) {
            return Err(NetavarkError::msg(format!(
                "gateway {} not in subnet {}",
                gateway, &s.subnet
            )));
        }
    } else if add_gateway {
        s.gateway = Some(first_ip_in_subnet(&s.subnet)?);
    }

    // Validate lease range if present
    if let Some(ref lease_range) = s.lease_range {
        validate_lease_range(lease_range, &s.subnet)?;
    }

    Ok(())
}

/// Validate routes for a network.
/// Ensures that each route has a valid destination (must be a network address, not a host address)
/// and a valid gateway.
pub fn validate_routes(network: &mut Network) -> NetavarkResult<()> {
    let Some(routes) = &network.routes else {
        return Ok(());
    };

    for route in routes {
        validate_route(route)?;
    }

    Ok(())
}

/// Validate a single route.
/// Ensures that the destination is a valid network address (not a host address).
fn validate_route(route: &Route) -> NetavarkResult<()> {
    // Check that destination is a network and not an address
    // The address part of the destination must equal the network address
    match &route.destination {
        ipnet::IpNet::V4(net_v4) => {
            if net_v4.addr() != net_v4.network() {
                return Err(NetavarkError::msg("route destination invalid"));
            }
        }
        ipnet::IpNet::V6(net_v6) => {
            if net_v6.addr() != net_v6.network() {
                return Err(NetavarkError::msg("route destination invalid"));
            }
        }
    }

    Ok(())
}
