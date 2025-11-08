use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use crate::{
    error::{NetavarkError, NetavarkResult},
    network::{
        constants,
        netlink::{expect_netlink_result, function, NetlinkFamily, Socket},
    },
};
use log::info;
use netlink_packet_core::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL};
use netlink_packet_route::{
    address::AddressMessage,
    link::{
        AfSpecBridge, BridgeVlanInfo, BridgeVlanInfoFlags, InfoBridge, InfoData, InfoKind,
        LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
    },
    route::{RouteAddress, RouteMessage, RouteProtocol, RouteScope, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::protocols::NETLINK_ROUTE;

#[derive(Clone)]
pub struct CreateLinkOptions<'fd> {
    pub name: String,
    kind: InfoKind,
    pub info_data: Option<InfoData>,
    pub mtu: u32,
    pub primary_index: u32,
    pub link: u32,
    pub mac: Vec<u8>,
    pub netns: Option<BorrowedFd<'fd>>,
}

pub enum LinkID {
    ID(u32),
    Name(String),
}

pub enum Route {
    Ipv4 {
        dest: ipnet::Ipv4Net,
        gw: Ipv4Addr,
        metric: Option<u32>,
    },
    Ipv6 {
        dest: ipnet::Ipv6Net,
        gw: Ipv6Addr,
        metric: Option<u32>,
    },
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (dest, gw, metric) = match self {
            Route::Ipv4 { dest, gw, metric } => (
                dest.to_string(),
                gw.to_string(),
                metric.unwrap_or(constants::DEFAULT_METRIC),
            ),
            Route::Ipv6 { dest, gw, metric } => (
                dest.to_string(),
                gw.to_string(),
                metric.unwrap_or(constants::DEFAULT_METRIC),
            ),
        };
        write!(f, "(dest: {dest} ,gw: {gw}, metric {metric})")
    }
}

pub struct NetlinkRoute;

impl NetlinkFamily for NetlinkRoute {
    const PROTOCOL: isize = NETLINK_ROUTE;
    type Message = RouteNetlinkMessage;
}

impl Socket<NetlinkRoute> {
    pub fn get_link(&mut self, id: LinkID) -> NetavarkResult<LinkMessage> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.attributes.push(LinkAttribute::IfName(name)),
        }

        let mut result = self.make_netlink_request(RouteNetlinkMessage::GetLink(msg), 0)?;
        expect_netlink_result!(result, 1);
        match result.remove(0) {
            RouteNetlinkMessage::NewLink(m) => Ok(m),
            m => Err(NetavarkError::Message(format!(
                "unexpected netlink message type: {}",
                m.message_type()
            ))),
        }
    }

    pub fn create_link(&mut self, options: CreateLinkOptions) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        parse_create_link_options(&mut msg, options);
        let result = self.make_netlink_request(
            RouteNetlinkMessage::NewLink(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        )?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn set_link_name(&mut self, id: u32, name: String) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = id;
        msg.attributes.push(LinkAttribute::IfName(name));
        let result = self.make_netlink_request(RouteNetlinkMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_link(&mut self, id: LinkID) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.attributes.push(LinkAttribute::IfName(name)),
        }

        let result = self.make_netlink_request(RouteNetlinkMessage::DelLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    pub fn set_link_ns<Fd: AsFd>(&mut self, link_id: u32, netns: Fd) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = link_id;
        msg.attributes
            .push(LinkAttribute::NetNsFd(netns.as_fd().as_raw_fd()));

        let result = self.make_netlink_request(RouteNetlinkMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    /// set the vlan_filtering attribute on a bridge
    pub fn set_vlan_filtering(&mut self, link_id: u32, vlan_filtering: bool) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = link_id;
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Bridge),
            LinkInfo::Data(InfoData::Bridge(vec![InfoBridge::VlanFiltering(
                vlan_filtering,
            )])),
        ]));

        // Now idea why this must use NewLink not SetLink, I strace'd ip route
        // and they use newlink and which setlink here it does not error but also does not set the setting.
        let result = self.make_netlink_request(RouteNetlinkMessage::NewLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    /// set the vlan id for an interface which is attached to the bridge with vlan_filtering
    /// Performs the equivalent of "bridge vlan add dev test vid <num> [flags]"
    pub fn set_vlan_id(
        &mut self,
        link_id: u32,
        // vlan id
        vid: u16,
        // flags for the vlan config
        flags: BridgeVlanInfoFlags,
    ) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.interface_family = AddressFamily::Bridge;
        // msg.header.link_layer_type = LinkLayerType::Netrom;
        msg.header.index = link_id;
        msg.attributes
            .push(LinkAttribute::AfSpecBridge(vec![AfSpecBridge::VlanInfo(
                BridgeVlanInfo { flags, vid },
            )]));

        let result = self.make_netlink_request(RouteNetlinkMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    fn create_addr_msg(link_id: u32, addr: &ipnet::IpNet) -> AddressMessage {
        let mut msg = AddressMessage::default();
        msg.header.index = link_id;

        match addr {
            ipnet::IpNet::V4(v4) => {
                msg.header.family = AddressFamily::Inet;
                msg.attributes
                    .push(netlink_packet_route::address::AddressAttribute::Broadcast(
                        v4.broadcast(),
                    ));
            }
            ipnet::IpNet::V6(_) => {
                msg.header.family = AddressFamily::Inet6;
            }
        };

        msg.header.prefix_len = addr.prefix_len();
        msg.attributes
            .push(netlink_packet_route::address::AddressAttribute::Local(
                addr.addr(),
            ));
        msg
    }

    pub fn add_addr(&mut self, link_id: u32, addr: &ipnet::IpNet) -> NetavarkResult<()> {
        let msg = Self::create_addr_msg(link_id, addr);
        let result = match self.make_netlink_request(
            RouteNetlinkMessage::NewAddress(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        ) {
            Ok(result) => result,
            Err(err) => match err {
                // kernel returns EACCES when we try to add an ipv6 but ipv6 is disabled in the kernel
                NetavarkError::Netlink(ref e) if -e.raw_code() == libc::EACCES => match addr {
                    ipnet::IpNet::V6(_) => {
                        return Err(NetavarkError::wrap(
                            "failed to add ipv6 address, is ipv6 enabled in the kernel?",
                            err,
                        ));
                    }
                    _ => return Err(err),
                },
                err => return Err(err),
            },
        };
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_addr(&mut self, link_id: u32, addr: &ipnet::IpNet) -> NetavarkResult<()> {
        let msg = Self::create_addr_msg(link_id, addr);
        let result = self.make_netlink_request(RouteNetlinkMessage::DelAddress(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    fn create_route_msg(route: &Route) -> RouteMessage {
        let mut msg = RouteMessage::default();

        msg.header.table = libc::RT_TABLE_MAIN;
        msg.header.protocol = RouteProtocol::Static;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let (dest, dest_prefix, gateway, final_metric) = match route {
            Route::Ipv4 { dest, gw, metric } => {
                msg.header.address_family = AddressFamily::Inet;
                (
                    RouteAddress::Inet(dest.addr()),
                    dest.prefix_len(),
                    RouteAddress::Inet(*gw),
                    metric.unwrap_or(constants::DEFAULT_METRIC),
                )
            }
            Route::Ipv6 { dest, gw, metric } => {
                msg.header.address_family = AddressFamily::Inet6;
                (
                    RouteAddress::Inet6(dest.addr()),
                    dest.prefix_len(),
                    RouteAddress::Inet6(*gw),
                    metric.unwrap_or(constants::DEFAULT_METRIC),
                )
            }
        };

        msg.header.destination_prefix_length = dest_prefix;
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Destination(
                dest,
            ));
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Gateway(
                gateway,
            ));
        msg.attributes
            .push(netlink_packet_route::route::RouteAttribute::Priority(
                final_metric,
            ));
        msg
    }

    pub fn add_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);
        info!("Adding route {route}");

        let result = self
            .make_netlink_request(RouteNetlinkMessage::NewRoute(msg), NLM_F_ACK | NLM_F_CREATE)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);
        info!("Deleting route {route}");

        let result = self.make_netlink_request(RouteNetlinkMessage::DelRoute(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn dump_routes(&mut self) -> NetavarkResult<Vec<RouteMessage>> {
        let mut msg = RouteMessage::default();

        msg.header.table = libc::RT_TABLE_MAIN;
        msg.header.protocol = RouteProtocol::Unspec;
        msg.header.scope = RouteScope::Universe;
        msg.header.kind = RouteType::Unicast;

        let results =
            self.make_netlink_request(RouteNetlinkMessage::GetRoute(msg), NLM_F_DUMP | NLM_F_ACK)?;

        let mut routes = Vec::with_capacity(results.len());

        for res in results {
            match res {
                RouteNetlinkMessage::NewRoute(m) => routes.push(m),
                m => {
                    return Err(NetavarkError::Message(format!(
                        "unexpected netlink message type: {}",
                        m.message_type()
                    )))
                }
            };
        }
        Ok(routes)
    }

    pub fn dump_links(
        &mut self,
        nlas: &mut Vec<LinkAttribute>,
    ) -> NetavarkResult<Vec<LinkMessage>> {
        let mut msg = LinkMessage::default();
        msg.attributes.append(nlas);

        let results =
            self.make_netlink_request(RouteNetlinkMessage::GetLink(msg), NLM_F_DUMP | NLM_F_ACK)?;

        let mut links = Vec::with_capacity(results.len());

        for res in results {
            match res {
                RouteNetlinkMessage::NewLink(m) => links.push(m),
                m => {
                    return Err(NetavarkError::Message(format!(
                        "unexpected netlink message type: {}",
                        m.message_type()
                    )))
                }
            };
        }
        Ok(links)
    }

    // If filtering options are supplied, then only the ip addresses satisfying the filter are returned. Otherwise all ip addresses of all interfaces are returned
    pub fn dump_addresses(
        &mut self,
        interface_id_filter: Option<u32>,
    ) -> NetavarkResult<Vec<AddressMessage>> {
        let mut msg = AddressMessage::default();

        if let Some(id) = interface_id_filter {
            msg.header.index = id;
        }

        let results =
            self.make_netlink_request(RouteNetlinkMessage::GetAddress(msg), NLM_F_DUMP)?;

        let mut addresses = Vec::with_capacity(results.len());

        for res in results {
            match res {
                RouteNetlinkMessage::NewAddress(m) => addresses.push(m),
                m => {
                    return Err(NetavarkError::Message(format!(
                        "unexpected netlink message type: {}",
                        m.message_type()
                    )))
                }
            };
        }
        Ok(addresses)
    }

    pub fn set_up(&mut self, id: LinkID) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.attributes.push(LinkAttribute::IfName(name)),
        }

        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;

        let result = self.make_netlink_request(
            RouteNetlinkMessage::SetLink(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        )?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn set_mac_address(&mut self, id: LinkID, mac: Vec<u8>) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.attributes.push(LinkAttribute::IfName(name)),
        }

        msg.attributes.push(LinkAttribute::Address(mac));

        let result = self.make_netlink_request(RouteNetlinkMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }
}

impl CreateLinkOptions<'_> {
    pub fn new(name: String, kind: InfoKind) -> Self {
        CreateLinkOptions {
            name,
            kind,
            info_data: None,
            mtu: 0,
            primary_index: 0,
            link: 0,
            mac: vec![],
            netns: None,
        }
    }
}

pub fn parse_create_link_options(msg: &mut LinkMessage, options: CreateLinkOptions) {
    // add link specific data
    let mut link_info_nlas = vec![LinkInfo::Kind(options.kind)];
    if let Some(data) = options.info_data {
        link_info_nlas.push(LinkInfo::Data(data));
    }
    msg.attributes.push(LinkAttribute::LinkInfo(link_info_nlas));

    // add name
    if !options.name.is_empty() {
        msg.attributes.push(LinkAttribute::IfName(options.name));
    }

    // add mtu
    if options.mtu != 0 {
        msg.attributes.push(LinkAttribute::Mtu(options.mtu));
    }

    // add mac address
    if !options.mac.is_empty() {
        msg.attributes.push(LinkAttribute::Address(options.mac));
    }

    // add primary device
    if options.primary_index != 0 {
        msg.attributes
            .push(LinkAttribute::Controller(options.primary_index));
    }

    // add link device
    if options.link != 0 {
        msg.attributes.push(LinkAttribute::Link(options.link));
    }

    // add netnsfd
    if let Some(netns) = options.netns {
        msg.attributes
            .push(LinkAttribute::NetNsFd(netns.as_raw_fd()));
    }
}
