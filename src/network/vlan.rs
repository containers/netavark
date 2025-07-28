use log::{debug, error};
use std::os::fd::BorrowedFd;
use std::{collections::HashMap, net::IpAddr};

use netlink_packet_route::link::{
    InfoData, InfoIpVlan, InfoKind, InfoMacVlan, IpVlanMode, MacVlanMode,
};
use rand::distr::{Alphanumeric, SampleString};

use crate::network::core_utils::get_default_route_interface;
use crate::network::dhcp::{dhcp_teardown, get_dhcp_lease};
use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    exec_netns,
    network::core_utils::join_netns,
    network::sysctl::disable_ipv6_autoconf,
};

use super::{
    constants::{
        NO_CONTAINER_INTERFACE_ERROR, OPTION_BCLIM, OPTION_METRIC, OPTION_MODE, OPTION_MTU,
        OPTION_NO_DEFAULT_ROUTE,
    },
    core_utils::{self, get_ipam_addresses, get_mac_address, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::IPAMAddresses,
    netlink::{self, CreateLinkOptions},
    types::{NetInterface, StatusBlock},
};

enum KindData {
    MacVlan {
        /// static mac address
        mac_address: Option<Vec<u8>>,
        /// macvlan mode
        mode: MacVlanMode,

        // IFLA_MACVLAN_BC_CUTOFF option if set
        bclim: Option<i32>,
    },
    IpVlan {
        /// ipvlan mode
        mode: IpVlanMode,
    },
}

impl core::fmt::Display for KindData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str(match self {
            Self::MacVlan { .. } => "macvlan",
            Self::IpVlan { .. } => "ipvlan",
        })
    }
}

struct InternalData {
    /// interface name inside the container
    container_interface_name: String,
    /// interface name on the host
    host_interface_name: String,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// Route metric for default routes added to the network
    metric: Option<u32>,
    /// kind-specific data
    kind: KindData,
    /// if set, no default gateway will be added
    no_default_route: bool,
    // TODO: add vlan
}

pub struct Vlan<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> Vlan<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        Self {
            info,
            data: None::<InternalData>,
        }
    }
}

impl driver::NetworkDriver for Vlan<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg(NO_CONTAINER_INTERFACE_ERROR));
        }

        let mode: Option<String> = parse_option(&self.info.network.options, OPTION_MODE)?;

        let mut ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        let mtu = parse_option(&self.info.network.options, OPTION_MTU)?.unwrap_or(0);
        let metric = parse_option(&self.info.network.options, OPTION_METRIC)?.unwrap_or(100);
        let no_default_route: bool =
            parse_option(&self.info.network.options, OPTION_NO_DEFAULT_ROUTE)?.unwrap_or(false);

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
            ipam,
            mtu,
            metric: Some(metric),
            kind: match self.info.network.driver.as_str() {
                super::constants::DRIVER_IPVLAN => KindData::IpVlan {
                    mode: CoreUtils::get_ipvlan_mode_from_string(mode.as_deref())?,
                },
                super::constants::DRIVER_MACVLAN => {
                    let bclim = parse_option(&self.info.network.options, OPTION_BCLIM)?;
                    KindData::MacVlan {
                        mode: CoreUtils::get_macvlan_mode_from_string(mode.as_deref())?,
                        mac_address: match &self.info.per_network_opts.static_mac {
                            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
                            None => None,
                        },
                        bclim,
                    }
                }
                other => return Err(NetavarkError::msg(format!("unsupported VLAN type {other}"))),
            },
            no_default_route,
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

        let container_vlan_mac = setup(
            host_sock,
            netns_sock,
            &self.info.per_network_opts.interface_name,
            data,
            self.info.netns_host,
            self.info.netns_container,
            &data.kind,
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
            let (subnets, dns_servers, domain_name) = get_dhcp_lease(
                &data.host_interface_name,
                &data.container_interface_name,
                self.info.netns_path,
                &container_vlan_mac,
                self.info.container_hostname.as_deref().unwrap_or(""),
                self.info.container_id,
                data.metric, // Pass the configured metric
            )?;
            // do not overwrite dns servers set by dns podman flag
            if !self.info.container_dns_servers.is_some() {
                response.dns_server_ips = dns_servers;
            }
            if domain_name.is_some() {
                response.dns_search_domains = domain_name;
            }
            subnets
        } else {
            data.ipam.net_addresses.clone()
        };

        let interface = NetInterface {
            mac_address: container_vlan_mac,
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
        dhcp_teardown(&self.info, netlink_sockets.1)?;

        let routes = core_utils::create_route_list(&self.info.network.routes)?;
        for route in routes.iter() {
            netlink_sockets.1.del_route(route)?;
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
    hostns_fd: BorrowedFd<'_>,
    netns_fd: BorrowedFd<'_>,
    kind_data: &KindData,
) -> NetavarkResult<String> {
    let link = match data.host_interface_name.as_ref() {
        "" => get_default_route_interface(host)?,
        host_name => host.get_link(netlink::LinkID::Name(host_name.to_string()))?,
    };

    let opts = match kind_data {
        KindData::IpVlan { mode } => {
            let mut opts = CreateLinkOptions::new(if_name.to_string(), InfoKind::IpVlan);
            opts.mtu = data.mtu;
            opts.netns = Some(netns_fd);
            opts.link = link.header.index;
            opts.info_data = Some(InfoData::IpVlan(vec![InfoIpVlan::Mode(*mode)]));
            opts
        }
        KindData::MacVlan {
            mode,
            mac_address,
            bclim,
        } => {
            let mut opts = CreateLinkOptions::new(if_name.to_string(), InfoKind::MacVlan);
            opts.mac = mac_address.clone().unwrap_or_default();
            opts.mtu = data.mtu;
            opts.netns = Some(netns_fd);
            opts.link = link.header.index;

            let mut mv_opts = vec![InfoMacVlan::Mode(*mode)];
            if let Some(bclim) = bclim {
                debug!("setting macvlan bclim to {bclim}");
                mv_opts.push(InfoMacVlan::BcCutoff(*bclim))
            }

            opts.info_data = Some(InfoData::MacVlan(mv_opts));
            opts
        }
    };
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
                NetavarkError::Netlink(ref e) if -e.raw_code() == libc::EEXIST => {
                    let random = Alphanumeric.sample_string(&mut rand::rng(), 10);
                    let tmp_name = "mv-".to_string() + &random;
                    let mut opts = opts.clone();
                    opts.name.clone_from(&tmp_name);
                    result = host.create_link(opts);
                    if let Err(ref e) = result {
                        // if last element return directly
                        if i == 2 {
                            return Err(NetavarkError::msg(format!(
                                "create {kind_data} interface: {e}"
                            )));
                        }
                        // retry, error could EEXIST again because we pick a random name
                        continue;
                    }

                    let link = netns
                        .get_link(netlink::LinkID::Name(tmp_name.clone()))
                        .wrap(format!("get tmp {kind_data} interface"))?;
                    netns
                        .set_link_name(link.header.index, if_name.to_string())
                        .wrap(format!("rename tmp {kind_data} interface"))
                        .inspect_err(|_| {
                            // If there is an error here most likely the name in the netns is already used,
                            // make sure to delete the tmp interface.
                            if let Err(err) = netns.del_link(netlink::LinkID::ID(link.header.index))
                            {
                                error!("failed to delete tmp {kind_data} link {tmp_name}: {err}");
                            };
                        })?;

                    // successful run, break out of loop
                    break;
                }
                err => return Err(err).wrap(format!("create {kind_data} interface"))?,
            },
        }
    }

    exec_netns!(hostns_fd, netns_fd, { disable_ipv6_autoconf(if_name) })?;

    let dev = netns
        .get_link(netlink::LinkID::Name(if_name.to_string()))
        .wrap(format!("get {kind_data} interface"))?;

    for addr in &data.ipam.container_addresses {
        netns
            .add_addr(dev.header.index, addr)
            .wrap(format!("add ip addr to {kind_data}"))?;
    }

    netns
        .set_up(netlink::LinkID::ID(dev.header.index))
        .wrap(format!("set {kind_data} up"))?;

    if !data.no_default_route {
        core_utils::add_default_routes(netns, &data.ipam.gateway_addresses, data.metric)?;
    }

    // add static routes
    for route in data.ipam.routes.iter() {
        netns.add_route(route)?
    }

    get_mac_address(dev.attributes)
}
