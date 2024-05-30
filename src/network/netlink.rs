use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use crate::{
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::constants,
    wrap,
};
use log::{info, trace};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::AddressMessage,
    link::{InfoData, InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    route::{RouteAddress, RouteMessage, RouteProtocol, RouteScope, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, SocketAddr};

pub struct Socket {
    socket: netlink_sys::Socket,
    sequence_number: u32,
    ///  buffer size for reading netlink messages, see NLMSG_GOODSIZE in the kernel
    buffer: [u8; 8192],
}

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

macro_rules! expect_netlink_result {
    ($result:expr, $count:expr) => {
        if $result.len() != $count {
            return Err(NetavarkError::msg(format!(
                "{}: unexpected netlink result (got {} result(s), want {})",
                function!(),
                $result.len(),
                $count
            )));
        }
    };
}

/// get the function name of the currently executed function
/// taken from https://stackoverflow.com/a/63904992
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);

        // Find and cut the rest of the path
        match &name[..name.len() - 3].rfind(':') {
            Some(pos) => &name[pos + 1..name.len() - 3],
            None => &name[..name.len() - 3],
        }
    }};
}

impl Socket {
    pub fn new() -> NetavarkResult<Socket> {
        let mut socket = wrap!(netlink_sys::Socket::new(NETLINK_ROUTE), "open")?;
        let addr = &SocketAddr::new(0, 0);
        wrap!(socket.bind(addr), "bind")?;
        wrap!(socket.connect(addr), "connect")?;

        Ok(Socket {
            socket,
            sequence_number: 0,
            buffer: [0; 8192],
        })
    }

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
        info!("Adding route {}", route);

        let result = self
            .make_netlink_request(RouteNetlinkMessage::NewRoute(msg), NLM_F_ACK | NLM_F_CREATE)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);
        info!("Deleting route {}", route);

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

    pub fn dump_addresses(&mut self) -> NetavarkResult<Vec<AddressMessage>> {
        let msg = AddressMessage::default();

        let results = self
            .make_netlink_request(RouteNetlinkMessage::GetAddress(msg), NLM_F_DUMP | NLM_F_ACK)?;

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

    fn make_netlink_request(
        &mut self,
        msg: RouteNetlinkMessage,
        flags: u16,
    ) -> NetavarkResult<Vec<RouteNetlinkMessage>> {
        self.send(msg, flags).wrap("send to netlink")?;
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }

    fn send(&mut self, msg: RouteNetlinkMessage, flags: u16) -> NetavarkResult<()> {
        let mut packet = NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::from(msg));
        packet.header.flags = NLM_F_REQUEST | flags;
        packet.header.sequence_number = {
            self.sequence_number += 1;
            self.sequence_number
        };
        packet.finalize();

        packet.serialize(&mut self.buffer[..]);
        trace!("send netlink packet: {:?}", packet);

        self.socket.send(&self.buffer[..packet.buffer_len()], 0)?;
        Ok(())
    }

    fn recv(&mut self, multi: bool) -> NetavarkResult<Vec<RouteNetlinkMessage>> {
        let mut offset = 0;
        let mut result = Vec::new();

        // if multi is set we expect a multi part message
        loop {
            let size = wrap!(
                self.socket.recv(&mut &mut self.buffer[..], 0),
                "recv from netlink"
            )?;

            loop {
                let bytes = &self.buffer[offset..];
                let rx_packet: NetlinkMessage<RouteNetlinkMessage> =
                    NetlinkMessage::deserialize(bytes).map_err(|e| {
                        NetavarkError::Message(format!(
                            "failed to deserialize netlink message: {e}",
                        ))
                    })?;
                trace!("read netlink packet: {:?}", rx_packet);

                if rx_packet.header.sequence_number != self.sequence_number {
                    return Err(NetavarkError::msg(format!(
                        "netlink: sequence_number out of sync (got {}, want {})",
                        rx_packet.header.sequence_number, self.sequence_number,
                    )));
                }

                match rx_packet.payload {
                    NetlinkPayload::Done(_) => return Ok(result),
                    NetlinkPayload::Error(e) => {
                        if e.code.is_some() {
                            return Err(e.into());
                        }
                        return Ok(result);
                    }
                    NetlinkPayload::Noop => {
                        return Err(NetavarkError::msg(
                            "unimplemented netlink message type NOOP",
                        ))
                    }
                    NetlinkPayload::Overrun(_) => {
                        return Err(NetavarkError::msg(
                            "unimplemented netlink message type OVERRUN",
                        ))
                    }
                    NetlinkPayload::InnerMessage(msg) => {
                        result.push(msg);
                        if !multi {
                            return Ok(result);
                        }
                    }
                    _ => {}
                };

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
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
