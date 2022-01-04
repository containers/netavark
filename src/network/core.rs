use crate::network::types::NetAddress;
use crate::network::{constants, core_utils, types};
use ipnet;
use log::debug;
use log::warn;
use nix::sched;
use rand::Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::Error;
use std::net::IpAddr;
use std::os::unix::prelude::*;
use std::thread;

pub struct Core {
    pub networkns: String,
}

impl Core {
    pub fn bridge_per_podman_network(
        per_network_opts: &types::PerNetworkOptions,
        network: &types::Network,
        netns: &str,
    ) -> Result<types::StatusBlock, std::io::Error> {
        //  StatusBlock response
        let mut response = types::StatusBlock {
            interfaces: Some(HashMap::new()),
        };
        // get bridge name
        let bridge_name = match network.network_interface.clone() {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no bridge provided".to_string(),
                ))
            }
            Some(i) => i,
        };
        // static ip vector
        let mut address_vector = Vec::new();
        // gateway ip vector
        let mut gw_ipaddr_vector = Vec::new();
        // network addresses for response
        let mut response_net_addresses: Vec<NetAddress> = Vec::new();
        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();
        // any vlan id specified with bridge for tagging.
        let mut vlan_id: u16 = 0;
        let mut vlan_filtering: bool = false;
        // mtu to configure, 0 means it was not set do nothing.
        let mut mtu_config: u32 = 0;
        if let Some(options_map) = network.options.as_ref() {
            if let Some(mtu) = options_map.get("mtu") {
                match mtu.parse() {
                    Ok(mtu) => {
                        mtu_config = mtu;
                    }
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("unable to parse mtu: {}", err),
                        ))
                    }
                }
            }
        }

        if let Some(options_map) = network.options.as_ref() {
            if let Some(vlan) = options_map.get("vlan") {
                match vlan.parse() {
                    Ok(vlan) => {
                        vlan_id = vlan;
                        if vlan_id != 0 {
                            vlan_filtering = true;
                        }
                    }
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("unable to parse vlan_id: {}", err),
                        ))
                    }
                }
            }
        }

        let container_veth_name: String = per_network_opts.interface_name.to_owned();
        let static_ips = match per_network_opts.static_ips.as_ref() {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no static ips provided".to_string(),
                ))
            }
            Some(i) => i,
        };
        let static_mac: String = match &per_network_opts.static_mac {
            Some(mac) => mac.to_owned(),
            None => "".to_string(),
        };

        // is ipv6 enabled, we need to propogate this to lower stack
        let mut ipv6_enabled = network.ipv6_enabled;
        // for dual-stack network.ipv6_enabled could be false do explicit check
        for ip in static_ips.iter() {
            if ip.is_ipv6() {
                ipv6_enabled = true;
                break;
            }
        }

        //we have the bridge name but we must iterate for all the available gateways
        for (idx, subnet) in network.subnets.iter().flatten().enumerate() {
            let subnet_mask_cidr = subnet.subnet.prefix_len();
            if let Some(gw) = subnet.gateway {
                let gw_net = match gw {
                    IpAddr::V4(gw4) => match ipnet::Ipv4Net::new(gw4, subnet_mask_cidr) {
                        Ok(dest) => ipnet::IpNet::from(dest),
                        Err(err) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "failed to parse address {}/{}: {}",
                                    gw4, subnet_mask_cidr, err
                                ),
                            ))
                        }
                    },
                    IpAddr::V6(gw6) => match ipnet::Ipv6Net::new(gw6, subnet_mask_cidr) {
                        Ok(dest) => ipnet::IpNet::from(dest),
                        Err(err) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "failed to parse address {}/{}: {}",
                                    gw6, subnet_mask_cidr, err
                                ),
                            ))
                        }
                    },
                };

                gw_ipaddr_vector.push(gw_net)
            }

            // Build up response information
            let container_address: ipnet::IpNet =
                match format!("{}/{}", static_ips[idx].to_string(), subnet_mask_cidr).parse() {
                    Ok(i) => i,
                    Err(e) => {
                        return Err(Error::new(std::io::ErrorKind::Other, e));
                    }
                };
            // Add the IP to the address_vector
            address_vector.push(container_address);
            response_net_addresses.push(types::NetAddress {
                gateway: subnet.gateway,
                ipnet: container_address,
            });
        }
        debug!("Container veth name: {:?}", container_veth_name);
        debug!("Brige name: {:?}", bridge_name);
        debug!("IP address for veth vector: {:?}", address_vector);
        debug!("Gateway ip address vector: {:?}", gw_ipaddr_vector);

        // get random name for host veth
        let host_veth_name = format!("veth{:x}", rand::thread_rng().gen::<u32>());

        let container_veth_mac = match Core::add_bridge_and_veth(
            &bridge_name,
            address_vector,
            gw_ipaddr_vector,
            &static_mac,
            &container_veth_name,
            &host_veth_name,
            netns,
            mtu_config,
            ipv6_enabled,
            vlan_filtering,
        ) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to configure bridge and veth interface: {}", err),
                ))
            }
        };

        if vlan_filtering {
            //Wait for: https://github.com/little-dude/netlink/pull/222
            //For a l2:
            //Configure the vlan tag on the veth host side.
            // flags must not be 100u16 instead use constants from upstream
            if let Err(er) =
                core_utils::CoreUtils::set_bridge_vlan(&host_veth_name, vlan_id, 100u16)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed assigning bridge vlan tag {}", er),
                ));
            }
        }

        debug!("Container veth mac: {:?}", container_veth_mac);
        let interface = types::NetInterface {
            mac_address: container_veth_mac,
            subnets: Option::from(response_net_addresses),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(container_veth_name, interface);
        let _ = response.interfaces.insert(interfaces);
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_bridge_and_veth(
        br_name: &str,
        netns_ipaddr: Vec<ipnet::IpNet>,
        gw_ipaddr: Vec<ipnet::IpNet>,
        static_mac: &str,
        container_veth_name: &str,
        host_veth_name: &str,
        netns: &str,
        mtu_config: u32,
        ipv6_enabled: bool,
        vlan_filtering: bool,
    ) -> Result<String, std::io::Error> {
        //copy subnet masks and gateway ips since we are going to use it later
        let mut gw_ipaddr_clone = Vec::new();
        for gw_ip in &gw_ipaddr {
            gw_ipaddr_clone.push(*gw_ip)
        }
        //call configure bridge
        let _ = match core_utils::CoreUtils::configure_bridge_async(
            br_name,
            gw_ipaddr,
            mtu_config,
            ipv6_enabled,
            vlan_filtering,
        ) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed while configuring network interface {}:", err),
                ))
            }
        };

        let _ = match core_utils::CoreUtils::configure_veth_async(
            host_veth_name,
            container_veth_name,
            br_name,
            netns,
            mtu_config,
            ipv6_enabled,
        ) {
            Ok(_) => (),
            Err(err) => {
                // it seems something went wrong
                // we must not leave dangling interfaces
                // otherwise cleanup would become mess
                // try removing leaking interfaces from host
                if let Err(er) = core_utils::CoreUtils::remove_interface(host_veth_name) {
                    warn!("failed while cleaning up interfaces: {}", er);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed while configuring network interface {}:", err),
                ));
            }
        };

        //bridge and veth configured successfully
        //do we want mac ?
        //TODO: we can verify MAC here

        match File::open(&netns) {
            Ok(netns_file) => {
                let netns_fd = netns_file.as_raw_fd();
                //clone values before spwaning thread in new namespace
                let container_veth_name_clone: String = container_veth_name.to_owned();
                let static_mac_clone: String = static_mac.to_owned();
                // So complicated cloning for threads ?
                // TODO: simplify this later
                let mut netns_ipaddr_clone = Vec::new();
                for ip in &netns_ipaddr {
                    netns_ipaddr_clone.push(*ip)
                }
                let handle = thread::spawn(move || -> Result<String, Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        panic!("failed to setns to fd={}: {}", netns_fd, err);
                    }

                    if let Err(err) = core_utils::CoreUtils::configure_netns_interface_async(
                        &container_veth_name_clone,
                        netns_ipaddr_clone,
                        gw_ipaddr_clone,
                        &static_mac_clone,
                    ) {
                        return Err(err);
                    }
                    debug!(
                        "Configured static up address for {}",
                        container_veth_name_clone
                    );

                    if let Err(er) = core_utils::CoreUtils::turn_up_interface("lo") {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed while turning up `lo` in container namespace {}", er),
                        ));
                    }

                    //return MAC address to status block could use this
                    match core_utils::CoreUtils::get_interface_address(&container_veth_name_clone) {
                        Ok(addr) => Ok(addr),
                        Err(err) => Err(err),
                    }
                });
                match handle.join() {
                    Ok(interface_address) => interface_address,
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to join: {:?}", err),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to open the netns file: {}", err),
                ))
            }
        }
    }

    pub fn macvlan_per_podman_network(
        per_network_opts: &types::PerNetworkOptions,
        network: &types::Network,
        netns: &str,
    ) -> Result<types::StatusBlock, std::io::Error> {
        //  StatusBlock response
        //  StatusBlock response
        let mut response = types::StatusBlock {
            interfaces: Some(HashMap::new()),
        };
        // Default MACVLAN_MODE to bridge or get from driver options
        let mut macvlan_mode: u32 = constants::MACVLAN_MODE_BRIDGE;
        if let Some(options_map) = network.options.as_ref() {
            if let Some(mode) = options_map.get("mode") {
                match core_utils::CoreUtils::get_macvlan_mode_from_string(mode) {
                    Ok(mode) => {
                        macvlan_mode = mode;
                    }
                    Err(err) => {
                        return Err(err);
                    }
                }
            }
        }

        // get master interface name
        let mut master_ifname: String = match network.network_interface.as_ref() {
            None => {
                if let Ok(ifname) = core_utils::CoreUtils::get_default_route_interface() {
                    ifname
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to find any valid master interface for macvlan".to_string(),
                    ));
                }
            }
            Some(interface) => interface.to_owned(),
        };

        // user could provide empty value as well so handle that
        if master_ifname.is_empty() {
            if let Ok(ifname) = core_utils::CoreUtils::get_default_route_interface() {
                if ifname.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to find any valid master interface for macvlan".to_string(),
                    ));
                }
                master_ifname = ifname;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unable to find any valid master interface for macvlan".to_string(),
                ));
            }
        }

        // static ip vector
        let mut address_vector = Vec::new();
        // network addresses for response
        let mut response_net_addresses: Vec<NetAddress> = Vec::new();
        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();

        let container_macvlan_name: String = per_network_opts.interface_name.to_owned();
        let static_ips = match per_network_opts.static_ips.as_ref() {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no static ips provided".to_string(),
                ))
            }
            Some(i) => i.clone(),
        };

        // prepare a vector of static aps with appropriate cidr
        // we only need static ips so do not process gateway,
        for (idx, subnet) in network.subnets.iter().flatten().enumerate() {
            let subnet_mask_cidr = subnet.subnet.prefix_len();

            // Build up response information
            let container_address: ipnet::IpNet =
                match format!("{}/{}", static_ips[idx].to_string(), subnet_mask_cidr).parse() {
                    Ok(i) => i,
                    Err(e) => {
                        return Err(Error::new(std::io::ErrorKind::Other, e));
                    }
                };
            // Add the IP to the address_vector
            address_vector.push(container_address);
            response_net_addresses.push(types::NetAddress {
                gateway: subnet.gateway,
                ipnet: container_address,
            });
        }
        debug!("Container macvlan name: {:?}", container_macvlan_name);
        debug!("Master interface name: {:?}", master_ifname);
        debug!("IP address for macvlan: {:?}", address_vector);

        // create macvlan
        let container_macvlan_mac = match Core::add_macvlan(
            &master_ifname,
            &container_macvlan_name,
            macvlan_mode,
            address_vector,
            netns,
        ) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed configure macvlan: {}", err),
                ))
            }
        };
        debug!("Container macvlan mac: {:?}", container_macvlan_mac);
        let interface = types::NetInterface {
            mac_address: container_macvlan_mac,
            subnets: Option::from(response_net_addresses),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(container_macvlan_name, interface);
        let _ = response.interfaces.insert(interfaces);
        Ok(response)
    }

    pub fn add_macvlan(
        master_ifname: &str,
        container_macvlan: &str,
        macvlan_mode: u32,
        netns_ipaddr: Vec<ipnet::IpNet>,
        netns: &str,
    ) -> Result<String, std::io::Error> {
        let _ = match core_utils::CoreUtils::configure_macvlan_async(
            master_ifname,
            container_macvlan,
            macvlan_mode,
            netns,
        ) {
            Ok(_) => (),
            Err(err) => {
                // it seems something went wrong
                // we must not leave dangling interfaces
                // otherwise cleanup would become mess
                // try removing leaking interfaces from host
                if let Err(er) = core_utils::CoreUtils::remove_interface(container_macvlan) {
                    warn!("failed while cleaning up interfaces: {}", er);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed while configuring macvlan {}:", err),
                ));
            }
        };

        match File::open(&netns) {
            Ok(netns_file) => {
                let netns_fd = netns_file.as_raw_fd();
                //clone values before spwaning thread in new namespace
                let container_macvlan_clone: String = container_macvlan.to_owned();
                // So complicated cloning for threads ?
                // TODO: simplify this later
                let _gw_ipaddr_empty = Vec::new(); // we are not using this for macvlan but arg is needed.
                let mut netns_ipaddr_clone = Vec::new();
                for ip in &netns_ipaddr {
                    netns_ipaddr_clone.push(*ip)
                }
                let handle = thread::spawn(move || -> Result<String, Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        panic!("failed to setns to fd={}: {}", netns_fd, err);
                    }

                    if let Err(err) = core_utils::CoreUtils::configure_netns_interface_async(
                        &container_macvlan_clone,
                        netns_ipaddr_clone,
                        _gw_ipaddr_empty,
                        &"".to_string(), // do we want static mac support for macvlan ? probably later.
                    ) {
                        return Err(err);
                    }
                    debug!(
                        "Configured static up address for {}",
                        container_macvlan_clone
                    );

                    if let Err(er) = core_utils::CoreUtils::turn_up_interface("lo") {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed while turning up `lo` in container namespace {}", er),
                        ));
                    }

                    //return MAC address to status block could use this
                    match core_utils::CoreUtils::get_interface_address(&container_macvlan_clone) {
                        Ok(addr) => Ok(addr),
                        Err(err) => Err(err),
                    }
                });
                match handle.join() {
                    Ok(interface_address) => interface_address,
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to join: {:?}", err),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to open the netns file: {}", err),
                ))
            }
        }
    }

    pub fn remove_interface_per_podman_network(
        per_network_opts: &types::PerNetworkOptions,
        _network: &types::Network,
        netns: &str,
    ) -> Result<(), std::io::Error> {
        let container_veth_name: String = per_network_opts.interface_name.to_owned();
        debug!(
            "Container veth name being removed: {:?}",
            container_veth_name
        );

        if let Err(err) = Core::remove_container_veth(&container_veth_name, netns) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to remove container veth: {}", err),
            ));
        }

        debug!("Container veth removed: {:?}", container_veth_name);

        Ok(())
    }

    fn remove_container_veth(ifname: &str, netns: &str) -> Result<(), std::io::Error> {
        match File::open(netns) {
            Ok(file) => {
                let netns_fd = file.as_raw_fd();
                let container_veth: String = ifname.to_owned();
                let handle = thread::spawn(move || -> Result<(), Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        panic!(
                            "{}",
                            format!(
                                "failed to setns on container network namespace fd={}: {}",
                                netns_fd, err
                            )
                        )
                    }

                    if let Err(err) = core_utils::CoreUtils::remove_interface(&container_veth) {
                        return Err(err);
                    }

                    Ok(())
                });
                if let Err(err) = handle.join() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unable to join thread: {:?}", err),
                    ));
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to open network namespace: {}", err),
                ))
            }
        };

        Ok(())
    }
}
