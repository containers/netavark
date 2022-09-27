use crate::network::core_utils;
use ipnet;
use log::debug;
use log::warn;
use nix::sched;
use std::io::Error;

use std::os::unix::prelude::*;
use std::thread;

pub struct Core {}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn add_bridge_and_veth(
        br_name: &str,
        netns_ipaddr: &Vec<ipnet::IpNet>,
        gw_ipaddr: &Vec<ipnet::IpNet>,
        static_mac: Option<Vec<u8>>,
        container_veth_name: &str,
        host_veth_name: &str,
        netns_fd: RawFd,
        mtu_config: u32,
        ipv6_enabled: bool,
    ) -> Result<String, std::io::Error> {
        //copy subnet masks and gateway ips since we are going to use it later
        let mut gw_ipaddr_clone = Vec::new();
        for gw_ip in gw_ipaddr {
            gw_ipaddr_clone.push(*gw_ip)
        }
        //call configure bridge
        match core_utils::CoreUtils::configure_bridge_async(
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

        match core_utils::CoreUtils::configure_veth_async(
            host_veth_name,
            container_veth_name,
            br_name,
            netns_fd,
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
        //clone values before spwaning thread in new namespace
        let container_veth_name_clone: String = container_veth_name.to_owned();
        let static_mac_clone = static_mac;
        // So complicated cloning for threads ?
        // TODO: simplify this later
        let mut netns_ipaddr_clone = Vec::new();
        for ip in netns_ipaddr {
            netns_ipaddr_clone.push(*ip)
        }
        let handle = thread::spawn(move || -> Result<String, Error> {
            if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to setns to fd={}: {}", netns_fd, err),
                ));
            }

            core_utils::CoreUtils::configure_netns_interface_async(
                &container_veth_name_clone,
                netns_ipaddr_clone,
                &gw_ipaddr_clone,
                static_mac_clone,
            )?;

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
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to join: {:?}", err),
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_macvlan(
        master_ifname: &str,
        container_macvlan: &str,
        gw_ipaddr: &[ipnet::IpNet],
        macvlan_mode: u32,
        mtu: u32,
        netns_ipaddr: &[ipnet::IpNet],
        static_mac: Option<Vec<u8>>,
        netns: RawFd,
    ) -> Result<String, std::io::Error> {
        match core_utils::CoreUtils::configure_macvlan_async(
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

        //clone values before spwaning thread in new namespace
        let container_macvlan_clone: String = container_macvlan.to_owned();
        // So complicated cloning for threads ?
        // TODO: simplify this later
        let netns_ipaddr_clone = netns_ipaddr.to_vec();
        let gw_addrs_clone = gw_ipaddr.to_vec();
        let handle = thread::spawn(move || -> Result<String, Error> {
            if let Err(err) = sched::setns(netns, sched::CloneFlags::CLONE_NEWNET) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to setns to fd={}: {}", netns, err),
                ));
            }

            core_utils::CoreUtils::configure_netns_interface_async(
                &container_macvlan_clone,
                netns_ipaddr_clone,
                &gw_addrs_clone,
                static_mac,
            )?;

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
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to join: {:?}", err),
            )),
        }
    }

    pub fn remove_container_interface(ifname: &str, netns: RawFd) -> Result<(), std::io::Error> {
        let container_veth: String = ifname.to_owned();
        let handle = thread::spawn(move || -> Result<(), Error> {
            if let Err(err) = sched::setns(netns, sched::CloneFlags::CLONE_NEWNET) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "failed to setns on container network namespace fd={}: {}",
                        netns, err
                    ),
                ));
            }

            core_utils::CoreUtils::remove_interface(&container_veth)?;

            Ok(())
        });
        if let Err(err) = handle.join() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to join thread: {:?}", err),
            ));
        }

        Ok(())
    }
}
