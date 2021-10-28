use crate::network::{core_utils, types};
use log::debug;
use nix::sched;
use rand::Rng;
use std::fs::File;
use std::io::Error;
use std::os::unix::prelude::*;
use std::thread;

pub struct Core {
    pub networkns: String,
}

impl Core {
    pub fn bridge_per_podman_network(
        network_opts: &types::NetworkOptions,
        netns: &str,
    ) -> Result<(), std::io::Error> {
        for (net_name, network) in &network_opts.network_info {
            let network_name: String = net_name.to_owned();
            // get PerNetworkOptions for this network
            let network_per_opts = network_opts.networks.get(&network_name);
            // get bridge name
            let bridge_name: String = network.network_interface.as_ref().unwrap().to_owned();
            //let _br_subnets = &network.subnets;

            // create a vector for all subnet masks
            let mut subnet_mask_vector = Vec::new();
            // static ip vector
            let mut address_vector = Vec::new();
            // gateway ip vector
            let mut gw_ipaddr_vector = Vec::new();

            let container_veth_name: String = network_per_opts.unwrap().interface_name.to_owned();
            let static_ips: &Vec<String> = network_per_opts.unwrap().static_ips.as_ref().unwrap();
            for ip in static_ips {
                let _ip_addr: String = ip.to_owned();
                address_vector.push(_ip_addr);
            }

            //we have the bridge name but we must iterate for all the available gateways
            for subnet in network.subnets.as_ref().unwrap() {
                gw_ipaddr_vector.push(subnet.gateway.as_ref().unwrap().to_owned());
                let _subnet = subnet.subnet.netmask().to_string();
                subnet_mask_vector.push(_subnet);
            }

            debug!("Container veth name: {:?}", container_veth_name);
            debug!("Brige name: {:?}", bridge_name);
            debug!("Subnet masks vector: {:?}", subnet_mask_vector);
            debug!("IP address for veth vector: {:?}", address_vector);
            debug!("Gateway ip address vector: {:?}", gw_ipaddr_vector);

            if let Err(err) = Core::add_bridge_and_veth(
                &bridge_name,
                address_vector,
                subnet_mask_vector,
                gw_ipaddr_vector,
                &container_veth_name,
                netns,
            ) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed configure bridge and veth interface: {:?}", err),
                ));
            }
        }

        Ok(())
    }

    pub fn add_bridge_and_veth(
        br_name: &str,
        netns_ipaddr: Vec<String>,
        netns_ipaddr_mask: Vec<String>,
        gw_ipaddr: Vec<String>,
        container_veth_name: &str,
        netns: &str,
    ) -> Result<(), std::io::Error> {
        //copy subnet masks and gateway ips since we are going to use it later
        let mut netns_ipaddr_mask_clone = Vec::new();
        let mut gw_ipaddr_clone = Vec::new();
        for mask in &netns_ipaddr_mask {
            let mask_add: String = mask.to_owned().to_string();
            netns_ipaddr_mask_clone.push(mask_add)
        }
        for gw_ip in &gw_ipaddr {
            let gw_ip_add: String = gw_ip.to_owned().to_string();
            gw_ipaddr_clone.push(gw_ip_add)
        }
        //call configure bridge
        let _ = match core_utils::CoreUtils::configure_bridge_async(
            br_name,
            gw_ipaddr,
            netns_ipaddr_mask,
        ) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error while configuring network interface {}:", err),
                ))
            }
        };

        let host_veth_name = format!("veth{:x}", rand::thread_rng().gen::<u32>());

        let _ = match core_utils::CoreUtils::configure_veth_async(
            &host_veth_name,
            container_veth_name,
            br_name,
            netns,
        ) {
            Ok(_) => (),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error while configuring network interface {}:", err),
                ))
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
                // So complicated cloning for threads ?
                // TODO: simplify this later
                let mut netns_ipaddr_clone = Vec::new();
                for ip in &netns_ipaddr {
                    let ip_add: String = ip.to_owned().to_string();
                    netns_ipaddr_clone.push(ip_add)
                }
                let handle = thread::spawn(move || -> Result<String, Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        panic!("failed to setns to fd={}: {}", netns_fd, err);
                    }

                    if let Err(err) = core_utils::CoreUtils::configure_netns_interface_async(
                        &container_veth_name_clone,
                        netns_ipaddr_clone,
                        netns_ipaddr_mask_clone,
                        gw_ipaddr_clone,
                    ) {
                        return Err(err);
                    }
                    debug!(
                        "Configured static up address for {}",
                        container_veth_name_clone
                    );
                    //TODO: we can verify mac here
                    Ok("applied interface".to_string())
                });
                match handle.join() {
                    Ok(_status) => (),
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

        Ok(())
    }
}
