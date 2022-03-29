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
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
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
        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();

        // mtu to configure
        let mtu_config = match network.options.as_ref().and_then(|map| map.get("mtu")) {
            Some(mtu) => match mtu.parse() {
                Ok(mtu) => mtu,
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unable to parse mtu: {}", err),
                    ))
                }
            },
            // default mtu is 0 (the kernel will pick one)
            None => 0,
        };

        let container_veth_name: String = per_network_opts.interface_name.to_owned();
        let static_mac = match &per_network_opts.static_mac {
            Some(mac) => mac,
            None => "",
        };

        let ipam = core_utils::get_ipam_addresses(per_network_opts, network)?;

        debug!("Container veth name: {:?}", container_veth_name);
        debug!("Brige name: {:?}", bridge_name);
        debug!("IP address for veth vector: {:?}", ipam.container_addresses);
        debug!("Gateway ip address vector: {:?}", ipam.gateway_addresses);

        // get random name for host veth
        let host_veth_name = format!("veth{:x}", rand::thread_rng().gen::<u32>());

        let container_veth_mac = match Core::add_bridge_and_veth(
            &bridge_name,
            ipam.container_addresses,
            ipam.gateway_addresses,
            static_mac,
            &container_veth_name,
            &host_veth_name,
            netns,
            mtu_config,
            ipam.ipv6_enabled,
        ) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to configure bridge and veth interface: {}", err),
                ))
            }
        };
        debug!("Container veth mac: {:?}", container_veth_mac);
        let interface = types::NetInterface {
            mac_address: container_veth_mac,
            subnets: Option::from(ipam.net_addresses),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(container_veth_name, interface);
        let _ = response.interfaces.insert(interfaces);
        if network.dns_enabled {
            let _ = response.dns_server_ips.insert(ipam.nameservers);
            // Note: this is being added so podman setup is backward compatible with the design
            // which we had with dnsname/dnsmasq. I belive this can be fixed in later releases.
            let _ = response
                .dns_search_domains
                .insert(vec![constants::PODMAN_DEFAULT_SEARCH_DOMAIN.to_string()]);
        }
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
        ) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed while configuring network interface: {}", err),
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
                    format!("failed while configuring network interface: {}", err),
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
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to setns to fd={}: {}", netns_fd, err),
                        ));
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
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };

        // parse mode option
        let macvlan_mode = match network.options.as_ref().and_then(|map| map.get("mode")) {
            Some(mode) => match core_utils::CoreUtils::get_macvlan_mode_from_string(mode) {
                Ok(mode) => mode,
                Err(err) => {
                    return Err(err);
                }
            },
            // default MACVLAN_MODE is bridge
            None => constants::MACVLAN_MODE_BRIDGE,
        };

        // mtu to configure
        let mtu_config = match network.options.as_ref().and_then(|map| map.get("mtu")) {
            Some(mtu) => match mtu.parse() {
                Ok(mtu) => mtu,
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unable to parse mtu: {}", err),
                    ))
                }
            },
            // default mtu is 0 (the kernel will pick one)
            None => 0,
        };

        // get master interface name
        let master_ifname = match network.network_interface.as_deref() {
            None | Some("") => {
                if let Ok(ifname) = core_utils::CoreUtils::get_default_route_interface() {
                    ifname
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to find any valid master interface for macvlan",
                    ));
                }
            }
            Some(interface) => interface.to_string(),
        };

        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();
        let container_macvlan_name: String = per_network_opts.interface_name.to_owned();
        let mut ipam = core_utils::get_ipam_addresses(per_network_opts, network)?;
        // Remove gateways when marked as internal network
        if network.internal {
            ipam.gateway_addresses = Vec::new();
        }

        debug!("Container macvlan name: {:?}", container_macvlan_name);
        debug!("Master interface name: {:?}", master_ifname);
        debug!("IP address for macvlan: {:?}", ipam.container_addresses);

        // create macvlan
        let container_macvlan_mac = match Core::add_macvlan(
            &master_ifname,
            &container_macvlan_name,
            ipam.gateway_addresses,
            macvlan_mode,
            mtu_config,
            ipam.container_addresses,
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
            subnets: Option::from(ipam.net_addresses),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(container_macvlan_name, interface);
        let _ = response.interfaces.insert(interfaces);
        Ok(response)
    }

    pub fn add_macvlan(
        master_ifname: &str,
        container_macvlan: &str,
        gw_ipaddr: Vec<ipnet::IpNet>,
        macvlan_mode: u32,
        mtu: u32,
        netns_ipaddr: Vec<ipnet::IpNet>,
        netns: &str,
    ) -> Result<String, std::io::Error> {
        let _ = match core_utils::CoreUtils::configure_macvlan_async(
            master_ifname,
            container_macvlan,
            macvlan_mode,
            mtu,
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
                let mut netns_ipaddr_clone = Vec::new();
                for ip in &netns_ipaddr {
                    netns_ipaddr_clone.push(*ip)
                }
                let handle = thread::spawn(move || -> Result<String, Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to setns to fd={}: {}", netns_fd, err),
                        ));
                    }

                    if let Err(err) = core_utils::CoreUtils::configure_netns_interface_async(
                        &container_macvlan_clone,
                        netns_ipaddr_clone,
                        gw_ipaddr,
                        "", // do we want static mac support for macvlan ? probably later.
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
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to setns on container network namespace fd={}: {}",
                                netns_fd, err
                            ),
                        ));
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
