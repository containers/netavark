use std::{collections::HashMap, net::IpAddr, os::unix::prelude::RawFd, sync::Once};

use ipnet::IpNet;
use log::{debug, error};
use netlink_packet_route::{
    nlas::link::{Info, InfoData, InfoKind, Nla, VethInfo},
    LinkMessage,
};

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkErrorList, NetavarkResult},
    exec_netns,
    firewall::iptables::MAX_HASH_SIZE,
    network::{constants, core_utils::disable_ipv6_autoconf, types},
};

use super::{
    constants::{NO_CONTAINER_INTERFACE_ERROR, OPTION_ISOLATE, OPTION_METRIC, OPTION_MTU},
    core_utils::{self, get_ipam_addresses, join_netns, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::{
        IPAMAddresses, PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
    },
    netlink,
    types::StatusBlock,
};

const NO_BRIDGE_NAME_ERROR: &str = "no bridge interface name given";

struct InternalData {
    /// interface name of the veth pair inside the container netns
    container_interface_name: String,
    /// interface name of the bridge for on the host
    bridge_interface_name: String,
    /// static mac address
    mac_address: Option<Vec<u8>>,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// if this network should be isolated from others
    isolate: bool,
    /// Route metric for any default routes added for the network
    metric: Option<u32>,
    // TODO: add vlan
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

        let mtu: u32 = parse_option(&self.info.network.options, OPTION_MTU, 0)?;
        let isolate: bool = parse_option(&self.info.network.options, OPTION_ISOLATE, false)?;
        let metric: u32 = parse_option(&self.info.network.options, OPTION_METRIC, 100)?;

        let static_mac = match &self.info.per_network_opts.static_mac {
            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
            None => None,
        };

        self.data = Some(InternalData {
            bridge_interface_name: bridge_name,
            container_interface_name: self.info.per_network_opts.interface_name.clone(),
            mac_address: static_mac,
            ipam,
            mtu,
            isolate,
            metric: Some(metric),
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

        setup_ipv4_fw_sysctl()?;
        if data.ipam.ipv6_enabled {
            setup_ipv6_fw_sysctl()?;
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

        let interface = types::NetInterface {
            mac_address: container_veth_mac,
            subnets: Option::from(data.ipam.net_addresses.clone()),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(data.container_interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);
        let aardvark_entry = if self.info.network.dns_enabled {
            let _ = response
                .dns_server_ips
                .insert(data.ipam.nameservers.clone());
            // Note: this is being added so podman setup is backward compatible with the design
            // which we had with dnsname/dnsmasq. I believe this can be fixed in later releases.
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
            let mut names = vec![self.info.container_name.to_string()];
            match &self.info.per_network_opts.aliases {
                Some(n) => {
                    names.extend(n.clone());
                }
                None => {}
            }

            let gw = data
                .ipam
                .gateway_addresses
                .iter()
                .map(|ipnet| ipnet.addr())
                .collect();

            Some(AardvarkEntry {
                network_name: &self.info.network.name,
                container_id: self.info.container_id,
                network_gateways: gw,
                network_dns_servers: &self.info.network.network_dns_servers,
                container_ips_v4: ipv4,
                container_ips_v6: ipv6,
                container_names: names,
                container_dns_servers: self.info.container_dns_servers,
            })
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
            // return here to skip setting up firewall rules
            return Ok((response, aardvark_entry));
        }

        self.setup_firewall(data)?;

        Ok((response, aardvark_entry))
    }

    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<()> {
        let (host_sock, netns_sock) = netlink_sockets;

        let mut error_list = NetavarkErrorList::new();

        let complete_teardown = match remove_link(
            host_sock,
            netns_sock,
            &get_interface_name(self.info.network.network_interface.clone())?,
            &self.info.per_network_opts.interface_name,
        ) {
            Ok(teardown) => teardown,
            Err(err) => {
                error_list.push(err);
                false
            }
        };

        if self.info.network.internal {
            if !error_list.is_empty() {
                return Err(NetavarkError::List(error_list));
            }
            return Ok(());
        }

        match self.teardown_firewall(complete_teardown) {
            Ok(_) => {}
            Err(err) => {
                error_list.push(err);
            }
        };

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
        isolate: bool,
    ) -> NetavarkResult<(SetupNetwork, PortForwardConfig)> {
        let id_network_hash =
            CoreUtils::create_network_hash(&self.info.network.name, MAX_HASH_SIZE);
        let sn = SetupNetwork {
            net: self.info.network.clone(),
            network_hash_name: id_network_hash.clone(),
            isolation: isolate,
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
        )?;

        self.info.firewall.setup_network(sn)?;

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

        self.info.firewall.setup_port_forward(spf)?;
        Ok(())
    }

    fn teardown_firewall(&self, complete_teardown: bool) -> NetavarkResult<()> {
        // we have to allocate the vecoros here in the top level to avoid
        // "borrow later used" problems
        let (container_addresses, nameservers);

        let (container_addresses_ref, nameservers_ref, isolate) = match &self.data {
            Some(d) => (&d.ipam.container_addresses, &d.ipam.nameservers, d.isolate),
            None => {
                // options are not yet parsed
                let isolate = match parse_option(&self.info.network.options, OPTION_ISOLATE, false)
                {
                    Ok(i) => i,
                    Err(e) => {
                        // just log we still try to do as much as possible for cleanup
                        error!("failed to parse {} option: {}", OPTION_ISOLATE, e);
                        false
                    }
                };

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

        let (sn, spf) =
            self.get_firewall_conf(container_addresses_ref, nameservers_ref, isolate)?;

        let tn = TearDownNetwork {
            config: sn,
            complete_teardown,
        };

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
    hostns_fd: RawFd,
    netns_fd: RawFd,
) -> NetavarkResult<String> {
    let bridge = match host.get_link(netlink::LinkID::Name(
        data.bridge_interface_name.to_string(),
    )) {
        Ok(bridge) => check_link_is_bridge(bridge, &data.bridge_interface_name)?,
        Err(err) => match err.unwrap() {
            NetavarkError::Netlink(e) => {
                if -e.code != libc::ENODEV {
                    // if bridge does not exists we will create it below,
                    // for all other errors we want to return the error
                    return Err(err).wrap("get bridge interface");
                }
                let mut create_link_opts = netlink::CreateLinkOptions::new(
                    data.bridge_interface_name.to_string(),
                    InfoKind::Bridge,
                );
                create_link_opts.mtu = data.mtu;
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

                let link = host
                    .get_link(netlink::LinkID::Name(
                        data.bridge_interface_name.to_string(),
                    ))
                    .wrap("get bridge interface")?;

                for addr in &data.ipam.gateway_addresses {
                    host.add_addr(link.header.index, addr)
                        .wrap("add ip addr to bridge")?;
                }

                host.set_up(netlink::LinkID::ID(link.header.index))
                    .wrap("set bridge up")?;
                link
            }
            _ => return Err(err),
        },
    };

    create_veth_pair(
        host,
        netns,
        data,
        bridge.header.index,
        internal,
        hostns_fd,
        netns_fd,
    )
}

/// return the container veth mac address
fn create_veth_pair(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    data: &InternalData,
    primary_index: u32,
    internal: bool,
    hostns_fd: RawFd,
    netns_fd: RawFd,
) -> NetavarkResult<String> {
    let mut peer_opts =
        netlink::CreateLinkOptions::new(data.container_interface_name.to_string(), InfoKind::Veth);
    peer_opts.mac = data.mac_address.clone().unwrap_or_default();
    peer_opts.mtu = data.mtu;
    peer_opts.netns = netns_fd;

    let mut peer = LinkMessage::default();
    netlink::parse_create_link_options(&mut peer, peer_opts);

    let mut host_veth = netlink::CreateLinkOptions::new(String::from(""), InfoKind::Veth);
    host_veth.mtu = data.mtu;
    host_veth.primary_index = primary_index;
    host_veth.info_data = Some(InfoData::Veth(VethInfo::Peer(peer)));

    host.create_link(host_veth).map_err(|err| match err {
        NetavarkError::Netlink(ref e) if -e.code == libc::EEXIST => NetavarkError::wrap(
            format!(
                "create veth pair: interface {} already exists on container namespace",
                data.container_interface_name
            ),
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

    for nla in veth.nlas.into_iter() {
        if let Nla::Address(ref addr) = nla {
            mac = CoreUtils::encode_address_to_hex(addr);
        }
        if let Nla::Link(link) = nla {
            host_link = link;
        }
    }

    if mac.is_empty() {
        return Err(NetavarkError::Message(
            "failed to get the mac address from the container veth interface".to_string(),
        ));
    }

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
        Ok::<(), NetavarkError>(())
    });
    // check the result and return error
    res?;

    if data.ipam.ipv6_enabled {
        let host_veth = host.get_link(netlink::LinkID::ID(host_link))?;

        for nla in host_veth.nlas.into_iter() {
            if let Nla::IfName(name) = nla {
                //  Disable dad inside on the host too
                let disable_dad_in_container =
                    format!("/proc/sys/net/ipv6/conf/{}/accept_dad", name);
                core_utils::CoreUtils::apply_sysctl_value(disable_dad_in_container, "0")?;
            }
        }
    }

    host.set_up(netlink::LinkID::ID(host_link))
        .wrap("failed to set host veth up")?;

    for addr in &data.ipam.container_addresses {
        netns
            .add_addr(veth.header.index, addr)
            .wrap("add ip addr to container veth")?;
    }

    netns
        .set_up(netlink::LinkID::ID(veth.header.index))
        .wrap("set container veth up")?;

    if !internal {
        core_utils::add_default_routes(netns, &data.ipam.gateway_addresses, data.metric)?;
    }

    Ok(mac)
}

/// make sure the LinkMessage has the kind bridge
fn check_link_is_bridge(msg: LinkMessage, br_name: &str) -> NetavarkResult<LinkMessage> {
    for nla in msg.nlas.iter() {
        if let Nla::Info(info) = nla {
            for inf in info.iter() {
                if let Info::Kind(kind) = inf {
                    if *kind == InfoKind::Bridge {
                        return Ok(msg);
                    } else {
                        return Err(NetavarkError::Message(format!(
                            "bridge interface {} already exists but is a {:?} interface",
                            br_name, kind
                        )));
                    }
                }
            }
        }
    }
    Err(NetavarkError::Message(format!(
        "could not determine namespace link kind for bridge {}",
        br_name
    )))
}

fn remove_link(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    br_name: &str,
    container_veth_name: &str,
) -> NetavarkResult<bool> {
    netns
        .del_link(netlink::LinkID::Name(container_veth_name.to_string()))
        .wrap(format!(
            "failed to delete container veth {}",
            container_veth_name
        ))?;

    let br = host
        .get_link(netlink::LinkID::Name(br_name.to_string()))
        .wrap("failed to get bridge interface")?;

    let links = host
        .dump_links(&mut vec![Nla::Master(br.header.index)])
        .wrap("failed to get connected bridge interfaces")?;
    // no connected interfaces on that bridge we can remove it
    if links.is_empty() {
        log::info!("removing bridge {}", br_name);
        host.del_link(netlink::LinkID::ID(br.header.index))
            .wrap(format!("failed to delete bridge {}", container_veth_name))?;
        return Ok(true);
    }
    Ok(false)
}
