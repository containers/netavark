use std::{collections::HashMap, net::IpAddr};

use log::debug;

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{NetavarkError, NetavarkResult},
    network::core::Core,
};

use super::{
    constants::{NO_CONTAINER_INTERFACE_ERROR, OPTION_MODE, OPTION_MTU},
    core_utils::{get_ipam_addresses, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::IPAMAddresses,
    types::{NetInterface, StatusBlock},
};

struct InternalData {
    /// interface name of on the host
    host_interface_name: String,
    /// static mac address
    mac_address: Option<Vec<u8>>,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// macvlan mode
    macvlan_mode: u32,
    // TODO: add vlan
}

pub struct MacVlan<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> MacVlan<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        MacVlan { info, data: None }
    }
}

impl driver::NetworkDriver for MacVlan<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg_str(NO_CONTAINER_INTERFACE_ERROR));
        }

        let master_ifname = match self.info.network.network_interface.as_deref() {
            None | Some("") => match CoreUtils::get_default_route_interface() {
                Ok(ifname) => ifname,
                Err(e) => {
                    return Err(NetavarkError::wrap_str(
                        "unable to find any valid master interface for macvlan",
                        e.into(),
                    ));
                }
            },
            Some(interface) => interface.to_string(),
        };

        let mode = parse_option(&self.info.network.options, OPTION_MODE, String::default())?;
        let macvlan_mode = CoreUtils::get_macvlan_mode_from_string(&mode)?;

        let mut ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        let mtu = parse_option(&self.info.network.options, OPTION_MTU, 0)?;

        let static_mac = match &self.info.per_network_opts.static_mac {
            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
            None => None,
        };

        // Remove gateways when marked as internal network
        if self.info.network.internal {
            ipam.gateway_addresses = Vec::new();
        }

        self.data = Some(InternalData {
            host_interface_name: master_ifname,
            mac_address: static_mac,
            ipam,
            macvlan_mode,
            mtu,
        });
        Ok(())
    }

    fn setup(&self) -> Result<(StatusBlock, Option<AardvarkEntry>), NetavarkError> {
        let data = match &self.data {
            Some(d) => d,
            None => {
                return Err(NetavarkError::msg_str(
                    "must call validate() before setup()",
                ))
            }
        };

        debug!("Setup network {}", self.info.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            self.info.per_network_opts.interface_name, data.ipam.container_addresses
        );

        // create macvlan
        let container_macvlan_mac = match Core::add_macvlan(
            &data.host_interface_name,
            &self.info.per_network_opts.interface_name,
            &data.ipam.gateway_addresses,
            data.macvlan_mode,
            data.mtu,
            &data.ipam.container_addresses,
            data.mac_address.clone(),
            self.info.netns_container,
        ) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(NetavarkError::wrap_str(
                    "failed configure macvlan",
                    err.into(),
                ))
            }
        };

        //  StatusBlock response
        let mut response = StatusBlock {
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };

        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, NetInterface> = HashMap::new();
        let interface = NetInterface {
            mac_address: container_macvlan_mac,
            subnets: Option::from(data.ipam.net_addresses.clone()),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(self.info.per_network_opts.interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);
        Ok((response, None))
    }

    fn teardown(&self) -> NetavarkResult<()> {
        Core::remove_container_interface(
            &self.info.per_network_opts.interface_name,
            self.info.netns_container,
        )?; // handle error and continue
        Ok(())
    }
}
