use crate::network::types;
use chrono::Utc;
use std::ffi::OsString;

use crate::error::{NetavarkError, NetavarkResult};

use super::driver::*;
use super::validation::*;

pub fn new_network(
    create: types::NetworkCreateConfig,
    plugin_directories: &Option<Vec<OsString>>,
) -> NetavarkResult<types::Network> {
    use crate::network::constants;
    let mut network = create.network;
    validate_name_id(&network.name, &network.id, &create.used.names)?;
    if let Some(ref if_name) = network.network_interface {
        validate_interface_name(if_name)?;
    }
    validate_ipam_driver(&network.ipam_options, &network.subnets)?;

    let mut check_used = false;

    match network.driver.as_str() {
        constants::DRIVER_BRIDGE => {
            let (check_used_val, check_bridge_conflict) = setup_bridge_options(&mut network)?;
            check_used = check_used_val && create.create_opts.check_used_subnets;
            create_bridge(
                &mut network,
                &create.used,
                check_used,
                check_bridge_conflict,
                create.create_opts,
            )?;
        }
        constants::DRIVER_IPVLAN | constants::DRIVER_MACVLAN => {
            create_ipvlan_macvlan(&mut network)?;
        }
        _ => exec_plugin_driver(&mut network, plugin_directories)?,
    }

    if network
        .ipam_options
        .as_ref()
        .and_then(|ipam_opts| ipam_opts.get("driver"))
        .map(|driver| driver == constants::IPAM_NONE)
        .unwrap_or(false)
    {
        log::debug!(
            "dns disabled for network {:?} because ipam driver is set to none",
            network.name
        );
        network.dns_enabled = false;
    }
    if network.network_dns_servers.is_some() && !network.dns_enabled {
        return Err(NetavarkError::msg(
            "cannot set NetworkDNSServers if DNS is not enabled for the network",
        ));
    }

    let add_gateway = !network.internal || network.dns_enabled;
    validate_subnets(&mut network, add_gateway, check_used, &create.used.subnets)?;

    if network.routes.is_some() {
        validate_routes(&mut network)?;
    }

    network.created = Some(Utc::now());

    Ok(network)
}
