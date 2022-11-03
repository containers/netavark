use log::{debug, error};
use std::{collections::HashMap, net::IpAddr, os::unix::prelude::RawFd};

use netlink_packet_route::nlas::link::{InfoData, InfoKind, InfoMacVlan, Nla};
use rand::distributions::{Alphanumeric, DistString};

use crate::network::macvlan_dhcp::{get_dhcp_lease, release_dhcp_lease};
use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    exec_netns,
    network::core_utils::{disable_ipv6_autoconf, join_netns},
};

use super::{
    constants::{NO_CONTAINER_INTERFACE_ERROR, OPTION_METRIC, OPTION_MODE, OPTION_MTU},
    core_utils::{self, get_ipam_addresses, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::IPAMAddresses,
    netlink::{self, CreateLinkOptions},
    types::{NetInterface, StatusBlock},
};

struct InternalData {
    /// interface name inside the container
    container_interface_name: String,
    /// interface name on the host
    host_interface_name: String,
    /// static mac address
    mac_address: Option<Vec<u8>>,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// macvlan mode
    macvlan_mode: u32,
    /// Route metric for default routes added to the network
    metric: Option<u32>,
    // TODO: add vlan
}

pub struct MacVlan<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> MacVlan<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        MacVlan {
            info,
            data: None::<InternalData>,
        }
    }
}

impl driver::NetworkDriver for MacVlan<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg(NO_CONTAINER_INTERFACE_ERROR));
        }

        let mode = parse_option(&self.info.network.options, OPTION_MODE, String::default())?;
        let macvlan_mode = CoreUtils::get_macvlan_mode_from_string(&mode)?;

        let mut ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        let mtu = parse_option(&self.info.network.options, OPTION_MTU, 0)?;
        let metric = parse_option(&self.info.network.options, OPTION_METRIC, 100)?;

        let static_mac = match &self.info.per_network_opts.static_mac {
            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
            None => None,
        };

        // Remove gateways when marked as internal network
        if self.info.network.internal {
            ipam.gateway_addresses = Vec::new();
        }

        self.data = Some(InternalData {
            container_interface_name: self.info.per_network_opts.interface_name.clone(),
            host_interface_name: self
                .info
                .network
                .network_interface
                .clone()
                .unwrap_or_default(),
            mac_address: static_mac,
            ipam,
            macvlan_mode,
            mtu,
            metric: Some(metric),
        });
        Ok(())
    }

    fn setup(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> Result<(StatusBlock, Option<AardvarkEntry>), NetavarkError> {
        let data = match &self.data {
            Some(d) => d,
            None => return Err(NetavarkError::msg("must call validate() before setup()")),
        };

        debug!("Setup network {}", self.info.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            self.info.per_network_opts.interface_name, data.ipam.container_addresses
        );

        let (host_sock, netns_sock) = netlink_sockets;

        let container_macvlan_mac = setup(
            host_sock,
            netns_sock,
            &self.info.per_network_opts.interface_name,
            data,
            self.info.netns_host,
            self.info.netns_container,
        )?;

        //  StatusBlock response is what we return at the end
        // of all of this
        let mut response = StatusBlock {
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };

        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, NetInterface> = HashMap::new();

        // if dhcp is enabled, we need to call the dhcp proxy to perform
        // a dhcp lease.  it will also perform the IP address assignment
        // to the macvlan interface.
        let subnets = if data.ipam.dhcp_enabled {
            get_dhcp_lease(
                &data.host_interface_name,
                &data.container_interface_name,
                self.info.netns_path,
                &container_macvlan_mac,
            )?
        } else {
            data.ipam.net_addresses.clone()
        };

        let interface = NetInterface {
            mac_address: container_macvlan_mac,
            subnets: Option::from(subnets),
        };

        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(self.info.per_network_opts.interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);
        Ok((response, None))
    }

    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<()> {
        let ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;
        let if_name = self.info.per_network_opts.interface_name.clone();

        // If we are using DHCP macvlan, we need to at least call to the proxy so that
        // the proxy's cache can get updated and the current lease can be released.
        if ipam.dhcp_enabled {
            let dev = netlink_sockets
                .1
                .get_link(netlink::LinkID::Name(if_name))
                .wrap(format!(
                    "get macvlan interface {}",
                    &self.info.per_network_opts.interface_name
                ))?;

            let container_mac_address = get_mac_address(dev.nlas)?;
            release_dhcp_lease(
                &self
                    .info
                    .network
                    .network_interface
                    .clone()
                    .unwrap_or_default(),
                &self.info.per_network_opts.interface_name,
                self.info.netns_path,
                &container_mac_address,
            )?
        }

        netlink_sockets.1.del_link(netlink::LinkID::Name(
            self.info.per_network_opts.interface_name.to_string(),
        ))?;
        Ok(())
    }
}

fn setup(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    if_name: &str,
    data: &InternalData,
    hostns_fd: RawFd,
    netns_fd: RawFd,
) -> NetavarkResult<String> {
    let master_ifname = match data.host_interface_name.as_ref() {
        "" => get_default_route_interface(host)?,
        host_name => host_name.to_string(),
    };

    let link = host.get_link(netlink::LinkID::Name(master_ifname))?;

    let mut opts = CreateLinkOptions::new(if_name.to_string(), InfoKind::MacVlan);
    opts.mac = data.mac_address.clone().unwrap_or_default();
    opts.mtu = data.mtu;
    opts.netns = netns_fd;
    opts.link = link.header.index;
    opts.info_data = Some(InfoData::MacVlan(vec![InfoMacVlan::Mode(
        data.macvlan_mode,
    )]));
    let mut result = host.create_link(opts.clone());
    // Sigh, the kernel creates the interface first in the hostns before moving it into the netns.
    // Therefore it can fail with EEXIST if the name is already used on the host. Create the link
    // with tmp name, then rename it in the netns.
    // If you change the iterations here make sure to match the number in early return case below as well.
    for i in 0..3 {
        match result {
            // no error we can break
            Ok(_) => break,

            Err(err) => match err {
                NetavarkError::Netlink(ref e) if -e.code == libc::EEXIST => {
                    let random = Alphanumeric.sample_string(&mut rand::thread_rng(), 10);
                    let tmp_name = "mv-".to_string() + &random;
                    let mut opts = opts.clone();
                    opts.name = tmp_name.clone();
                    result = host.create_link(opts);
                    if let Err(ref e) = result {
                        // if last element return directly
                        if i == 2 {
                            return Err(NetavarkError::msg(format!(
                                "create macvlan interface: {}",
                                e
                            )));
                        }
                        // retry, error could EEXIST again because we pick a random name
                        continue;
                    }

                    let link = netns
                        .get_link(netlink::LinkID::Name(tmp_name.clone()))
                        .wrap("get tmp macvlan interface")?;
                    netns
                        .set_link_name(link.header.index, if_name.to_string())
                        .wrap("rename tmp macvlan interface")
                        .map_err(|err| {
                            // If there is an error here most likely the name in the netns is already used,
                            // make sure to delete the tmp interface.
                            if let Err(err) = netns.del_link(netlink::LinkID::ID(link.header.index))
                            {
                                error!("failed to delete tmp macvlan link {}: {}", tmp_name, err);
                            };
                            err
                        })?;

                    // successful run, break out of loop
                    break;
                }
                err => return Err(err).wrap("create macvlan interface")?,
            },
        }
    }

    exec_netns!(hostns_fd, netns_fd, res, { disable_ipv6_autoconf(if_name) });
    res?; // return autoconf sysctl error

    let dev = netns
        .get_link(netlink::LinkID::Name(if_name.to_string()))
        .wrap("get macvlan interface")?;

    for addr in &data.ipam.container_addresses {
        netns
            .add_addr(dev.header.index, addr)
            .wrap("add ip addr to macvlan")?;
    }

    netns
        .set_up(netlink::LinkID::ID(dev.header.index))
        .wrap("set macvlan up")?;

    core_utils::add_default_routes(netns, &data.ipam.gateway_addresses, data.metric)?;

    get_mac_address(dev.nlas)
}

fn get_mac_address(v: Vec<Nla>) -> NetavarkResult<String> {
    for nla in v.into_iter() {
        if let Nla::Address(ref addr) = nla {
            return Ok(CoreUtils::encode_address_to_hex(addr));
        }
    }
    Err(NetavarkError::msg(
        "failed to get the the container mac address",
    ))
}

fn get_default_route_interface(host: &mut netlink::Socket) -> NetavarkResult<String> {
    let routes = host.dump_routes().wrap("dump routes")?;

    for route in routes {
        let mut dest = false;
        let mut out_if = 0;
        for nla in route.nlas {
            if let netlink_packet_route::route::Nla::Destination(_) = nla {
                dest = true;
            }
            if let netlink_packet_route::route::Nla::Oif(oif) = nla {
                out_if = oif;
            }
        }

        // if there is no dest we have a default route
        // return the output interface for this route
        if !dest && out_if > 0 {
            let link = host.get_link(netlink::LinkID::ID(out_if))?;
            let name = link.nlas.iter().find_map(|nla| {
                if let Nla::IfName(name) = nla {
                    Some(name)
                } else {
                    None
                }
            });
            if let Some(name) = name {
                return Ok(name.to_owned());
            }
        }
    }
    Err(NetavarkError::msg("failed to get default route interface"))
}
