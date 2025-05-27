use std::{collections::HashMap, net::IpAddr, os::fd::BorrowedFd, sync::Once};

use ipnet::IpNet;
use log::{debug, error};
use netlink_packet_route::link::{
    BridgeVlanInfoFlags, InfoBridge, InfoData, InfoKind, InfoVeth, LinkAttribute, LinkInfo,
    LinkMessage,
};

use crate::dns::aardvark::SafeString;
use crate::network::dhcp::{dhcp_teardown, get_dhcp_lease};
use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkErrorList, NetavarkResult},
    exec_netns,
    firewall::{
        iptables::MAX_HASH_SIZE,
        state::{remove_fw_config, write_fw_config},
    },
    network::{constants, core_utils::disable_ipv6_autoconf, types},
};

use super::{
    constants::{
        ISOLATE_OPTION_FALSE, ISOLATE_OPTION_STRICT, ISOLATE_OPTION_TRUE,
        NO_CONTAINER_INTERFACE_ERROR, OPTION_HOST_INTERFACE_NAME, OPTION_ISOLATE, OPTION_METRIC,
        OPTION_MODE, OPTION_MTU, OPTION_NO_DEFAULT_ROUTE, OPTION_VLAN, OPTION_VRF,
    },
    core_utils::{self, get_ipam_addresses, join_netns, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::{
        IPAMAddresses, IsolateOption, PortForwardConfig, SetupNetwork, TearDownNetwork,
        TeardownPortForward,
    },
    netlink,
    types::StatusBlock,
};

const NO_BRIDGE_NAME_ERROR: &str = "no bridge interface name given";

#[derive(Clone, Copy, PartialEq)]
enum BridgeMode {
    /// The bridge is managed by netavark.
    Managed,
    /// The bridge was created externally and we only add/remove veths.
    Unmanaged,
}

struct InternalData {
    /// interface name of the veth pair inside the container netns
    container_interface_name: String,
    /// interace name of the veth pair in the host netns
    host_interface_name: String,
    /// interface name of the bridge for on the host
    bridge_interface_name: String,
    /// static mac address
    mac_address: Option<Vec<u8>>,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// if this network should be isolated from others
    isolate: IsolateOption,
    /// Route metric for any default routes added for the network
    metric: Option<u32>,
    /// Management mode of the bridge.
    mode: BridgeMode,
    /// if set, no default gateway will be added
    no_default_route: bool,
    /// sef vrf for bridge
    vrf: Option<String>,
    /// vlan id of the interface attached to the bridge
    vlan: Option<u16>,
}

pub struct Bridge<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> Bridge<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        Bridge { info, data: None }
    }
}

impl driver::NetworkDriver for Bridge<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        let bridge_name = get_interface_name(self.info.network.network_interface.clone())?;
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg(NO_CONTAINER_INTERFACE_ERROR));
        }
        let ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        let mode: Option<String> = parse_option(&self.info.network.options, OPTION_MODE)?;
        let mtu: u32 = parse_option(&self.info.network.options, OPTION_MTU)?.unwrap_or(0);
        let isolate: IsolateOption = get_isolate_option(&self.info.network.options)?;
        let metric: u32 = parse_option(&self.info.network.options, OPTION_METRIC)?.unwrap_or(100);
        let no_default_route: bool =
            parse_option(&self.info.network.options, OPTION_NO_DEFAULT_ROUTE)?.unwrap_or(false);
        let vrf: Option<String> = parse_option(&self.info.network.options, OPTION_VRF)?;
        let vlan: Option<u16> = parse_option(&self.info.network.options, OPTION_VLAN)?;
        let host_interface_name = parse_option(
            &self.info.per_network_opts.options,
            OPTION_HOST_INTERFACE_NAME,
        )?
        .unwrap_or_else(|| "".to_string());

        let static_mac = match &self.info.per_network_opts.static_mac {
            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
            None => None,
        };

        let mode = get_bridge_mode_from_string(mode.as_deref())?;

        // Cannot chain both conditions with "&&"
        // until https://github.com/rust-lang/rust/issues/53667 is stable
        if ipam.dhcp_enabled {
            if let BridgeMode::Managed = mode {
                return Err(NetavarkError::msg(
                    "cannot use dhcp ipam driver without using the option mode=unmanaged",
                ));
            }
        }

        self.data = Some(InternalData {
            bridge_interface_name: bridge_name,
            container_interface_name: self.info.per_network_opts.interface_name.clone(),
            host_interface_name,
            mac_address: static_mac,
            ipam,
            mtu,
            isolate,
            metric: Some(metric),
            mode,
            no_default_route,
            vrf,
            vlan,
        });
        Ok(())
    }

    fn setup(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<(StatusBlock, Option<AardvarkEntry>)> {
        let data = match &self.data {
            Some(d) => d,
            None => return Err(NetavarkError::msg("must call validate() before setup()")),
        };

        debug!("Setup network {}", self.info.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            data.container_interface_name, data.ipam.container_addresses
        );
        debug!(
            "Bridge name: {} with IP addresses {:?}",
            data.bridge_interface_name, data.ipam.gateway_addresses
        );

        if let BridgeMode::Managed = data.mode {
            if !self.info.network.internal {
                setup_ipv4_fw_sysctl()?;
                if data.ipam.ipv6_enabled {
                    setup_ipv6_fw_sysctl()?;
                }
            }
        }

        let (host_sock, netns_sock) = netlink_sockets;

        let container_veth_mac = create_interfaces(
            host_sock,
            netns_sock,
            data,
            self.info.network.internal,
            self.info.netns_host,
            self.info.netns_container,
        )?;

        //  StatusBlock response
        let mut response = types::StatusBlock {
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };
        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();

        // if dhcp is enabled, we need to call the dhcp proxy to perform
        // a dhcp lease.  it will also perform the IP address assignment
        // to the container interface.
        let subnets = if data.ipam.dhcp_enabled {
            let (subnets, dns_servers, domain_name) = get_dhcp_lease(
                &data.bridge_interface_name,
                &data.container_interface_name,
                self.info.netns_path,
                &container_veth_mac,
                self.info.container_hostname.as_deref().unwrap_or(""),
                self.info.container_id,
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

        let interface = types::NetInterface {
            mac_address: container_veth_mac,
            subnets: Option::from(subnets),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(data.container_interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);
        let aardvark_entry = if self.info.network.dns_enabled {
            let _ = response
                .dns_server_ips
                .insert(data.ipam.nameservers.clone());
            // Note: this is being added so podman setup is backward compatible with the design
            // which we had with dnsname/dnsmasq.
            let _ = response
                .dns_search_domains
                .insert(vec![constants::PODMAN_DEFAULT_SEARCH_DOMAIN.to_string()]);

            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for ipnet in &data.ipam.container_addresses {
                match ipnet.addr() {
                    IpAddr::V4(v4) => {
                        ipv4.push(v4);
                    }
                    IpAddr::V6(v6) => {
                        ipv6.push(v6);
                    }
                }
            }

            // get size so we can preallocate the vector which is more efficient
            let len = match &self.info.per_network_opts.aliases {
                Some(n) => n.len() + 1,
                None => 1,
            };
            let mut names = Vec::with_capacity(len);
            maybe_add_alias(&mut names, self.info.container_name);
            if let Some(aliases) = &self.info.per_network_opts.aliases {
                for name in aliases {
                    maybe_add_alias(&mut names, name);
                }
            }

            let gw = data
                .ipam
                .gateway_addresses
                .iter()
                .map(|ipnet| ipnet.addr())
                .collect();

            match self.info.container_id.as_str().try_into() {
                Ok(id) => Some(AardvarkEntry {
                    network_name: &self.info.network.name,
                    container_id: id,
                    network_gateways: gw,
                    network_dns_servers: &self.info.network.network_dns_servers,
                    container_ips_v4: ipv4,
                    container_ips_v6: ipv6,
                    container_names: names,
                    container_dns_servers: self.info.container_dns_servers,
                    is_internal: self.info.network.internal,
                }),
                Err(err) => {
                    log::warn!("invalid container id {}: {err}", &self.info.container_id);
                    None
                }
            }
        } else {
            // If --dns-enable=false and --dns was set then return following DNS servers
            // in status_block so podman can use these and populate resolv.conf
            if let Some(container_dns_servers) = self.info.container_dns_servers {
                let _ = response
                    .dns_server_ips
                    .insert(container_dns_servers.clone());
            }
            None
        };

        if let BridgeMode::Managed = data.mode {
            // if the network is internal block routing and do not setup firewall rules
            if self.info.network.internal {
                CoreUtils::apply_sysctl_value(
                    format!(
                        "/proc/sys/net/ipv4/conf/{}/forwarding",
                        data.bridge_interface_name
                    ),
                    "0",
                )?;
                if data.ipam.ipv6_enabled {
                    CoreUtils::apply_sysctl_value(
                        format!(
                            "/proc/sys/net/ipv6/conf/{}/forwarding",
                            data.bridge_interface_name
                        ),
                        "0",
                    )?;
                }
            } else {
                self.setup_firewall(data)?
            }
        }

        Ok((response, aardvark_entry))
    }

    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<()> {
        let mode: Option<String> = parse_option(&self.info.network.options, OPTION_MODE)?;
        let mode = get_bridge_mode_from_string(mode.as_deref())?;
        let (host_sock, netns_sock) = netlink_sockets;

        let mut error_list = NetavarkErrorList::new();

        dhcp_teardown(&self.info, netns_sock)?;

        let routes = core_utils::create_route_list(&self.info.network.routes)?;
        for route in routes.iter() {
            netns_sock
                .del_route(route)
                .unwrap_or_else(|err| error_list.push(err))
        }

        let bridge_name = get_interface_name(self.info.network.network_interface.clone())?;

        let complete_teardown = match remove_link(
            host_sock,
            netns_sock,
            mode,
            &bridge_name,
            &self.info.per_network_opts.interface_name,
        ) {
            Ok(teardown) => teardown,
            Err(err) => {
                error_list.push(err);
                false
            }
        };

        if !self.info.network.internal && mode == BridgeMode::Managed {
            match self.teardown_firewall(complete_teardown, bridge_name) {
                Ok(_) => {}
                Err(err) => {
                    error_list.push(err);
                }
            }
        }

        if !error_list.is_empty() {
            return Err(NetavarkError::List(error_list));
        }

        Ok(())
    }
}

fn get_interface_name(name: Option<String>) -> NetavarkResult<String> {
    let name = match name {
        None => return Err(NetavarkError::msg(NO_BRIDGE_NAME_ERROR)),
        Some(n) => {
            if n.is_empty() {
                return Err(NetavarkError::msg(NO_BRIDGE_NAME_ERROR));
            }
            n
        }
    };
    Ok(name)
}

impl<'a> Bridge<'a> {
    fn get_firewall_conf(
        &'a self,
        container_addresses: &Vec<IpNet>,
        nameservers: &'a Vec<IpAddr>,
        isolate: IsolateOption,
        bridge_name: String,
    ) -> NetavarkResult<(SetupNetwork, PortForwardConfig<'a>)> {
        let id_network_hash =
            CoreUtils::create_network_hash(&self.info.network.name, MAX_HASH_SIZE);
        let sn = SetupNetwork {
            subnets: self
                .info
                .network
                .subnets
                .as_ref()
                .map(|nets| nets.iter().map(|n| n.subnet).collect()),
            bridge_name,
            network_id: self.info.network.id.clone(),
            network_hash_name: id_network_hash.clone(),
            isolation: isolate,
            dns_port: self.info.dns_port,
        };

        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        let mut addr_v4: Option<IpAddr> = None;
        let mut addr_v6: Option<IpAddr> = None;
        let mut net_v4: Option<IpNet> = None;
        let mut net_v6: Option<IpNet> = None;
        for net in container_addresses {
            match net {
                IpNet::V4(v4) => {
                    if has_ipv4 {
                        continue;
                    }
                    addr_v4 = Some(IpAddr::V4(v4.addr()));
                    net_v4 = Some(IpNet::new(v4.network().into(), v4.prefix_len())?);
                    has_ipv4 = true;
                }
                IpNet::V6(v6) => {
                    if has_ipv6 {
                        continue;
                    }

                    addr_v6 = Some(IpAddr::V6(v6.addr()));
                    net_v6 = Some(IpNet::new(v6.network().into(), v6.prefix_len())?);
                    has_ipv6 = true;
                }
            }
        }
        let spf = PortForwardConfig {
            container_id: self.info.container_id.clone(),
            network_id: self.info.network.id.clone(),
            port_mappings: self.info.port_mappings,
            network_name: self.info.network.name.clone(),
            network_hash_name: id_network_hash,
            container_ip_v4: addr_v4,
            subnet_v4: net_v4,
            container_ip_v6: addr_v6,
            subnet_v6: net_v6,
            dns_port: self.info.dns_port,
            dns_server_ips: nameservers,
        };
        Ok((sn, spf))
    }

    fn setup_firewall(&self, data: &InternalData) -> NetavarkResult<()> {
        let (sn, spf) = self.get_firewall_conf(
            &data.ipam.container_addresses,
            &data.ipam.nameservers,
            data.isolate,
            data.bridge_interface_name.clone(),
        )?;

        if !self.info.rootless {
            write_fw_config(
                self.info.config_dir,
                &self.info.network.id,
                self.info.container_id,
                self.info.firewall.driver_name(),
                &sn,
                &spf,
            )?;
        }

        let system_dbus = zbus::blocking::Connection::system().ok();

        self.info.firewall.setup_network(sn, &system_dbus)?;

        if spf.port_mappings.is_some() {
            // Need to enable sysctl localnet so that traffic can pass
            // through localhost to containers

            CoreUtils::apply_sysctl_value(
                format!(
                    "net.ipv4.conf.{}.route_localnet",
                    data.bridge_interface_name
                ),
                "1",
            )?;
        }

        self.info.firewall.setup_port_forward(spf, &system_dbus)?;
        Ok(())
    }

    fn teardown_firewall(
        &self,
        complete_teardown: bool,
        bridge_name: String,
    ) -> NetavarkResult<()> {
        // we have to allocate the vecoros here in the top level to avoid
        // "borrow later used" problems
        let (container_addresses, nameservers);

        let (container_addresses_ref, nameservers_ref, isolate) = match &self.data {
            Some(d) => (&d.ipam.container_addresses, &d.ipam.nameservers, d.isolate),
            None => {
                let isolate = get_isolate_option(&self.info.network.options).unwrap_or_else(|e| {
                    // just log we still try to do as much as possible for cleanup
                    error!("failed to parse {} option: {}", OPTION_ISOLATE, e);
                    IsolateOption::Never
                });

                (container_addresses, nameservers) =
                    match get_ipam_addresses(self.info.per_network_opts, self.info.network) {
                        Ok(i) => (i.container_addresses, i.nameservers),
                        Err(e) => {
                            // just log we still try to do as much as possible for cleanup
                            error!("failed to parse ipam options: {}", e);
                            (Vec::new(), Vec::new())
                        }
                    };
                (&container_addresses, &nameservers, isolate)
            }
        };

        let (sn, spf) = self.get_firewall_conf(
            container_addresses_ref,
            nameservers_ref,
            isolate,
            bridge_name,
        )?;

        let tn = TearDownNetwork {
            config: sn,
            complete_teardown,
        };

        if !self.info.rootless {
            // IMPORTANT: This must happen before we actually teardown rules.
            remove_fw_config(
                self.info.config_dir,
                &self.info.network.id,
                self.info.container_id,
                complete_teardown,
            )?;
        }

        if complete_teardown {
            // FIXME store error and continue
            self.info.firewall.teardown_network(tn)?;
        }

        let tpf = TeardownPortForward {
            config: spf,
            complete_teardown,
        };

        self.info.firewall.teardown_port_forward(tpf)?;
        Ok(())
    }
}

// sysctl forward

static IPV4_FORWARD_ONCE: Once = Once::new();
static IPV6_FORWARD_ONCE: Once = Once::new();

const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";

fn setup_ipv4_fw_sysctl() -> NetavarkResult<()> {
    let mut result = Ok("".to_string());

    IPV4_FORWARD_ONCE.call_once(|| {
        result = CoreUtils::apply_sysctl_value(IPV4_FORWARD, "1");
    });

    match result {
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    };
    Ok(())
}

fn setup_ipv6_fw_sysctl() -> NetavarkResult<()> {
    let mut result = Ok("".to_string());

    IPV6_FORWARD_ONCE.call_once(|| {
        result = CoreUtils::apply_sysctl_value(IPV6_FORWARD, "1");
    });

    match result {
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    };
    Ok(())
}

/// returns the container veth mac address
fn create_interfaces(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    data: &InternalData,
    internal: bool,
    hostns_fd: BorrowedFd<'_>,
    netns_fd: BorrowedFd<'_>,
) -> NetavarkResult<String> {
    let (bridge_index, mac) = match host.get_link(netlink::LinkID::Name(
        data.bridge_interface_name.to_string(),
    )) {
        Ok(bridge) => (
            validate_bridge_link(
                bridge,
                data.vlan.is_some(),
                host,
                &data.bridge_interface_name,
            )?,
            None,
        ),
        Err(err) => match err.unwrap() {
            NetavarkError::Netlink(e) => {
                if -e.raw_code() != libc::ENODEV {
                    // if bridge does not exists we will create it below,
                    // for all other errors we want to return the error
                    return Err(err).wrap("get bridge interface");
                }

                if let BridgeMode::Unmanaged = data.mode {
                    return Err(err)
                        .wrap("in unmanaged mode, the bridge must already exist on the host");
                }

                let mut create_link_opts = netlink::CreateLinkOptions::new(
                    data.bridge_interface_name.to_string(),
                    InfoKind::Bridge,
                );
                create_link_opts.mtu = data.mtu;

                if data.vlan.is_some() {
                    create_link_opts.info_data =
                        Some(InfoData::Bridge(vec![InfoBridge::VlanFiltering(true)]));
                }

                if let Some(vrf_name) = &data.vrf {
                    let vrf = match host.get_link(netlink::LinkID::Name(vrf_name.to_string())) {
                        Ok(vrf) => check_link_is_vrf(vrf, vrf_name)?,
                        Err(err) => return Err(err).wrap("get vrf to set up bridge interface"),
                    };
                    create_link_opts.primary_index = vrf.header.index;
                }

                host.create_link(create_link_opts).wrap("create bridge")?;

                if data.ipam.ipv6_enabled {
                    // Disable duplicate address detection if ipv6 enabled
                    // Do not accept Router Advertisements if ipv6 is enabled
                    let br_accept_dad = format!(
                        "/proc/sys/net/ipv6/conf/{}/accept_dad",
                        &data.bridge_interface_name
                    );
                    let br_accept_ra =
                        format!("net/ipv6/conf/{}/accept_ra", &data.bridge_interface_name);
                    CoreUtils::apply_sysctl_value(br_accept_dad, "0")?;
                    CoreUtils::apply_sysctl_value(br_accept_ra, "0")?;
                }

                // Disable strict reverse path search validation. On RHEL it is set to strict mode
                // which breaks port forwarding when multiple networks are attached as the package
                // may be routed over a different interface on the reverse path.
                // As documented for the sysctl for complicated or asymmetric routing loose mode (2)
                // is recommended.
                let br_rp_filter = format!(
                    "/proc/sys/net/ipv4/conf/{}/rp_filter",
                    &data.bridge_interface_name
                );
                CoreUtils::apply_sysctl_value(br_rp_filter, "2")?;

                let link = host
                    .get_link(netlink::LinkID::Name(
                        data.bridge_interface_name.to_string(),
                    ))
                    .wrap("get bridge interface")?;

                let mut mac = None;
                for nla in link.attributes.into_iter() {
                    if let LinkAttribute::Address(addr) = nla {
                        mac = Some(addr);
                    }
                }
                if mac.is_none() {
                    return Err(NetavarkError::msg(
                        "failed to get the mac address from the bridge interface",
                    ));
                }

                for addr in &data.ipam.gateway_addresses {
                    host.add_addr(link.header.index, addr)
                        .wrap("add ip addr to bridge")?;
                }

                host.set_up(netlink::LinkID::ID(link.header.index))
                    .wrap("set bridge up")?;

                (link.header.index, mac)
            }
            _ => return Err(err),
        },
    };

    create_veth_pair(
        host,
        netns,
        data,
        bridge_index,
        mac,
        internal,
        hostns_fd,
        netns_fd,
    )
}

/// return the container veth mac address
#[allow(clippy::too_many_arguments)]
fn create_veth_pair<'fd>(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    data: &InternalData,
    primary_index: u32,
    bridge_mac: Option<Vec<u8>>,
    internal: bool,
    hostns_fd: BorrowedFd<'fd>,
    netns_fd: BorrowedFd<'fd>,
) -> NetavarkResult<String> {
    let mut peer_opts =
        netlink::CreateLinkOptions::new(data.container_interface_name.to_string(), InfoKind::Veth);
    peer_opts.mac = data.mac_address.clone().unwrap_or_default();
    peer_opts.mtu = data.mtu;
    peer_opts.netns = Some(netns_fd);

    let mut peer = LinkMessage::default();
    netlink::parse_create_link_options(&mut peer, peer_opts);

    let mut host_veth =
        netlink::CreateLinkOptions::new(data.host_interface_name.clone(), InfoKind::Veth);
    host_veth.mtu = data.mtu;
    host_veth.primary_index = primary_index;
    host_veth.info_data = Some(InfoData::Veth(InfoVeth::Peer(peer)));

    host.create_link(host_veth).map_err(|err| match err {
        NetavarkError::Netlink(ref e) if -e.raw_code() == libc::EEXIST => NetavarkError::wrap(
            if data.host_interface_name.is_empty() {
                format!(
                    "create veth pair: interface {} already exists on container namespace",
                    data.container_interface_name
                )
            } else {
                format!(
                    "create veth pair: interface {} already exists on container namespace or {} exists on host namespace",
                    data.container_interface_name, data.host_interface_name,
                )
            },
            err,
        ),
        _ => NetavarkError::wrap("create veth pair", err),
    })?;

    let veth = netns
        .get_link(netlink::LinkID::Name(
            data.container_interface_name.to_string(),
        ))
        .wrap("get container veth")?;

    let mut mac = String::from("");
    let mut host_link = 0;

    for nla in veth.attributes.into_iter() {
        if let LinkAttribute::Address(ref addr) = nla {
            mac = CoreUtils::encode_address_to_hex(addr);
        }
        if let LinkAttribute::Link(link) = nla {
            host_link = link;
        }
    }

    if mac.is_empty() {
        return Err(NetavarkError::Message(
            "failed to get the mac address from the container veth interface".to_string(),
        ));
    }

    if let Some(vid) = data.vlan {
        host.set_vlan_id(
            host_link,
            vid,
            BridgeVlanInfoFlags::Pvid | BridgeVlanInfoFlags::Untagged,
        )?;
    }

    if let BridgeMode::Managed = data.mode {
        exec_netns!(hostns_fd, netns_fd, res, {
            disable_ipv6_autoconf(&data.container_interface_name)?;
            if data.ipam.ipv6_enabled {
                //  Disable dad inside the container too
                let disable_dad_in_container = format!(
                    "/proc/sys/net/ipv6/conf/{}/accept_dad",
                    &data.container_interface_name
                );
                core_utils::CoreUtils::apply_sysctl_value(disable_dad_in_container, "0")?;
            }
            let enable_arp_notify = format!(
                "/proc/sys/net/ipv4/conf/{}/arp_notify",
                &data.container_interface_name
            );
            core_utils::CoreUtils::apply_sysctl_value(enable_arp_notify, "1")?;

            // disable strict reverse path search validation
            let rp_filter = format!(
                "/proc/sys/net/ipv4/conf/{}/rp_filter",
                &data.container_interface_name
            );
            CoreUtils::apply_sysctl_value(rp_filter, "2")?;
            Ok::<(), NetavarkError>(())
        });
        // check the result and return error
        res?;

        if data.ipam.ipv6_enabled {
            let host_veth = host.get_link(netlink::LinkID::ID(host_link))?;

            for nla in host_veth.attributes.into_iter() {
                if let LinkAttribute::IfName(name) = nla {
                    //  Disable dad inside on the host too
                    let disable_dad_in_container =
                        format!("/proc/sys/net/ipv6/conf/{name}/accept_dad");
                    core_utils::CoreUtils::apply_sysctl_value(disable_dad_in_container, "0")?;
                }
            }
        }
    }

    host.set_up(netlink::LinkID::ID(host_link))
        .wrap("failed to set host veth up")?;

    // Ok this is extremely strange, by default the kernel will always choose the mac address with the
    // lowest value from all connected interfaces for the bridge. This means as our veth interfaces are
    // added and removed the bridge mac can change randomly which causes problems with ARP. This causes
    // package loss until the old incorrect ARP entry is updated with the new bridge mac which for some
    // reason can take a very long time, we noticed delays up to 100s.
    // This here forces a static mac because we explicitly requested one even though we still just only
    // set the same autogenerated one. Not that this must happen after the first veth interface is
    // connected otherwise no connectivity is possible at all and I have no idea why but CNI does it
    // also in the same way.
    if let Some(m) = bridge_mac {
        host.set_mac_address(netlink::LinkID::ID(primary_index), m)
            .wrap("set static mac on bridge")?;
    }

    for addr in &data.ipam.container_addresses {
        netns
            .add_addr(veth.header.index, addr)
            .wrap("add ip addr to container veth")?;
    }

    netns
        .set_up(netlink::LinkID::ID(veth.header.index))
        .wrap("set container veth up")?;

    if !internal && !data.no_default_route {
        core_utils::add_default_routes(netns, &data.ipam.gateway_addresses, data.metric)?;
    }

    // add static routes
    for route in data.ipam.routes.iter() {
        netns.add_route(route)?
    }

    Ok(mac)
}

/// Make sure the LinkMessage is of type bridge and if vlan is set also checks
/// that the bridge has vlan_filtering enabled and if not enables it. Returns
/// the link id or errors when the link is not a bridge.
fn validate_bridge_link(
    msg: LinkMessage,
    vlan: bool,
    netlink: &mut netlink::Socket,
    br_name: &str,
) -> NetavarkResult<u32> {
    for nla in msg.attributes.iter() {
        if let LinkAttribute::LinkInfo(info) = nla {
            // when vlan is requested also check the VlanFiltering attribute
            if vlan {
                for inf in info.iter() {
                    if let LinkInfo::Data(data) = inf {
                        match data {
                            InfoData::Bridge(vec) => {
                                // set the return value here based on the VlanFiltering state
                                let vlan_enabled = vec
                                    .iter()
                                    .find_map(|a| {
                                        if let InfoBridge::VlanFiltering(on) = a {
                                            Some(*on)
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(false);
                                if !vlan_enabled {
                                    // vlan filtering not enabled, enable it now
                                    netlink.set_vlan_filtering(msg.header.index, true)?;
                                }
                            }
                            _ => {
                                return Err(NetavarkError::Message(format!(
                                    "bridge interface {br_name} doesn't contain any bridge data",
                                )))
                            }
                        }
                        break;
                    }
                }
            }

            for inf in info.iter() {
                if let LinkInfo::Kind(kind) = inf {
                    if *kind == InfoKind::Bridge {
                        return Ok(msg.header.index);
                    } else {
                        return Err(NetavarkError::Message(format!(
                            "bridge interface {br_name} already exists but is a {kind:?} interface"
                        )));
                    }
                }
            }
        }
    }
    Err(NetavarkError::Message(format!(
        "could not determine namespace link kind for bridge {br_name}"
    )))
}

/// make sure the LinkMessage is the kind VRF
fn check_link_is_vrf(msg: LinkMessage, vrf_name: &str) -> NetavarkResult<LinkMessage> {
    for nla in msg.attributes.iter() {
        if let LinkAttribute::LinkInfo(info) = nla {
            for inf in info.iter() {
                if let LinkInfo::Kind(kind) = inf {
                    if *kind == InfoKind::Vrf {
                        return Ok(msg);
                    } else {
                        return Err(NetavarkError::Message(format!(
                            "vrf {} already exists but is a {:?} interface",
                            vrf_name, kind
                        )));
                    }
                }
            }
        }
    }
    Err(NetavarkError::Message(format!(
        "could not determine namespace link kind for vrf {}",
        vrf_name
    )))
}

fn remove_link(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    mode: BridgeMode,
    br_name: &str,
    container_veth_name: &str,
) -> NetavarkResult<bool> {
    netns
        .del_link(netlink::LinkID::Name(container_veth_name.to_string()))
        .wrap(format!(
            "failed to delete container veth {container_veth_name}"
        ))?;

    let br = host
        .get_link(netlink::LinkID::Name(br_name.to_string()))
        .wrap("failed to get bridge interface")?;

    let links = host
        .dump_links(&mut vec![LinkAttribute::Controller(br.header.index)])
        .wrap("failed to get connected bridge interfaces")?;
    // no connected interfaces on that bridge we can remove it
    if links.is_empty() {
        if let BridgeMode::Managed = mode {
            log::info!("removing bridge {}", br_name);
            host.del_link(netlink::LinkID::ID(br.header.index))
                .wrap(format!("failed to delete bridge {container_veth_name}"))?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn get_isolate_option(opts: &Option<HashMap<String, String>>) -> NetavarkResult<IsolateOption> {
    let isolate = parse_option(opts, OPTION_ISOLATE)?.unwrap_or(ISOLATE_OPTION_FALSE.to_string());
    // return isolate option value "false" if unknown value or no value passed
    Ok(match isolate.as_str() {
        ISOLATE_OPTION_STRICT => IsolateOption::Strict,
        ISOLATE_OPTION_TRUE => IsolateOption::Normal,
        ISOLATE_OPTION_FALSE => IsolateOption::Never,
        _ => IsolateOption::Never,
    })
}

fn get_bridge_mode_from_string(mode: Option<&str>) -> NetavarkResult<BridgeMode> {
    match mode {
        // default to l3 when unset
        None | Some("") | Some("managed") => Ok(BridgeMode::Managed),
        Some("unmanaged") => Ok(BridgeMode::Unmanaged),
        Some(name) => Err(NetavarkError::msg(format!(
            "invalid bridge mode \"{name}\""
        ))),
    }
}

fn maybe_add_alias<'a>(names: &mut Vec<SafeString<'a>>, name: &'a str) {
    match name.try_into() {
        Ok(name) => names.push(name),
        Err(err) => log::warn!(
            "invalid network alias {:?}: {err}, ignoring this name",
            name
        ),
    }
}
