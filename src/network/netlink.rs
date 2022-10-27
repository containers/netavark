use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::prelude::RawFd,
};

use crate::{
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::constants,
    wrap,
};
use log::{info, trace};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_route::{
    nlas::link::{Info, InfoData, InfoKind, Nla},
    AddressMessage, LinkMessage, RouteMessage, RtnlMessage, AF_INET, AF_INET6, IFF_UP, RTN_UNICAST,
    RTPROT_STATIC, RTPROT_UNSPEC, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};
use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};
use netlink_sys::{
    protocols::{NETLINK_GENERIC, NETLINK_ROUTE},
    SocketAddr,
};

// helper macros
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

// Generic Trait over all sockets
pub enum NetlinkType {
    NetlinkRoute = NETLINK_ROUTE,
    NetlinkGeneric = NETLINK_GENERIC,
}

pub trait NetlinkSocket {
    fn send<T>(&mut self, msg: T, flags: u16, family: Option<u16>) -> NetavarkResult<()>
    where
        T: NetlinkSerializable + std::fmt::Debug + Into<NetlinkPayload<T>>,
    {
        let mut nlmsg = NetlinkMessage::from(msg);
        nlmsg.header.flags = NLM_F_REQUEST | flags;
        nlmsg.header.sequence_number = self.increase_sequence_number();
        nlmsg.finalize();

        if let Some(family) = family {
            nlmsg.header.message_type = family;
        }

        //  buffer size for netlink messages, see NLMSG_GOODSIZE in the kernel
        let mut buffer = [0; 8192];
        let socket = self.get_socket();

        nlmsg.serialize(&mut buffer[..]);

        trace!("sending GenlCtrl netlink msg: {:?}", nlmsg);
        socket.send(&buffer[..nlmsg.buffer_len()], 0)?;
        Ok(())
    }

    fn get_socket(&self) -> &netlink_sys::Socket;
    fn get_sequence_number(&self) -> u32;
    fn increase_sequence_number(&mut self) -> u32;

    fn recv<T>(&mut self, multi: bool) -> NetavarkResult<Vec<T>>
    where
        T: std::fmt::Debug + NetlinkDeserializable,
    {
        let mut offset = 0;
        let mut result = Vec::new();

        // if multi is set we expect a multi part message
        let socket = self.get_socket();
        let sequence_number = self.get_sequence_number();
        //  buffer size for netlink messages, see NLMSG_GOODSIZE in the kernel
        let mut buffer = [0; 8192];
        loop {
            let size = wrap!(socket.recv(&mut &mut buffer[..], 0), "recv from netlink")?;

            loop {
                let bytes = &buffer[offset..];
                let rx_packet: NetlinkMessage<T> =
                    NetlinkMessage::deserialize(bytes).map_err(|e| {
                        NetavarkError::Message(format!(
                            "failed to deserialize netlink message: {}",
                            e,
                        ))
                    })?;
                trace!("read netlink packet: {:?}", rx_packet);

                if rx_packet.header.sequence_number != sequence_number {
                    return Err(NetavarkError::msg(format!(
                        "netlink: sequence_number out of sync (got {}, want {})",
                        rx_packet.header.sequence_number, sequence_number,
                    )));
                }

                match rx_packet.payload {
                    NetlinkPayload::Done => return Ok(result),
                    NetlinkPayload::Error(e) | NetlinkPayload::Ack(e) => {
                        if e.code != 0 {
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
                    _ => {
                        // The NetlinkPayload could have new members that are not yet covered by
                        // netavark. This is because of https://github.com/rust-netlink/netlink-packet-core/commit/53a4c4ecfec60e1f26ad8b6aaa62abc7b112df50
                        return Err(NetavarkError::msg("unimplemented netlink message type"));
                    }
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

// Netlink API for Links
#[derive(Clone)]
pub struct CreateLinkOptions {
    pub name: String,
    kind: InfoKind,
    pub info_data: Option<InfoData>,
    pub mtu: u32,
    pub primary_index: u32,
    pub link: u32,
    pub mac: Vec<u8>,
    pub netns: RawFd,
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
        write!(f, "(dest: {} ,gw: {}, metric {})", dest, gw, metric)
    }
}

pub struct LinkSocket {
    socket: netlink_sys::Socket,
    sequence_number: u32,
}

impl NetlinkSocket for LinkSocket {
    fn get_socket(&self) -> &netlink_sys::Socket {
        &self.socket
    }

    fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    fn increase_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}

impl LinkSocket {
    pub fn new() -> NetavarkResult<LinkSocket> {
        let mut socket = wrap!(netlink_sys::Socket::new(NETLINK_ROUTE), "open")?;
        let addr = &SocketAddr::new(0, 0);
        wrap!(socket.bind(addr), "bind")?;
        wrap!(socket.connect(addr), "connect")?;

        Ok(LinkSocket {
            socket,
            sequence_number: 0,
        })
    }

    pub fn get_link(&mut self, id: LinkID) -> NetavarkResult<LinkMessage> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.nlas.push(Nla::IfName(name)),
        }

        let mut result = self.make_netlink_request(RtnlMessage::GetLink(msg), 0)?;
        expect_netlink_result!(result, 1);
        match result.remove(0) {
            RtnlMessage::NewLink(m) => Ok(m),
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
            RtnlMessage::NewLink(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        )?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn set_link_name(&mut self, id: u32, name: String) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = id;
        msg.nlas.push(Nla::IfName(name));
        let result = self.make_netlink_request(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_link(&mut self, id: LinkID) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.nlas.push(Nla::IfName(name)),
        }

        let result = self.make_netlink_request(RtnlMessage::DelLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    pub fn set_link_ns(&mut self, link_id: u32, netns_fd: i32) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = link_id;
        msg.nlas.push(Nla::NetNsFd(netns_fd));

        let result = self.make_netlink_request(RtnlMessage::SetLink(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    fn create_addr_msg(link_id: u32, addr: &ipnet::IpNet) -> AddressMessage {
        let mut msg = AddressMessage::default();
        msg.header.index = link_id;

        let addr_vec = match addr {
            ipnet::IpNet::V4(v4) => {
                msg.header.family = AF_INET as u8;
                msg.nlas.push(netlink_packet_route::address::Nla::Broadcast(
                    v4.broadcast().octets().to_vec(),
                ));
                v4.addr().octets().to_vec()
            }
            ipnet::IpNet::V6(v6) => {
                msg.header.family = AF_INET6 as u8;
                v6.addr().octets().to_vec()
            }
        };

        msg.header.prefix_len = addr.prefix_len();
        msg.nlas
            .push(netlink_packet_route::address::Nla::Local(addr_vec));
        msg
    }

    pub fn add_addr(&mut self, link_id: u32, addr: &ipnet::IpNet) -> NetavarkResult<()> {
        let msg = Self::create_addr_msg(link_id, addr);
        let result = match self.make_netlink_request(
            RtnlMessage::NewAddress(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        ) {
            Ok(result) => result,
            Err(err) => match err {
                // kernel returns EACCES when we try to add an ipv6 but ipv6 is disabled in the kernel
                NetavarkError::Netlink(ref e) if -e.code == libc::EACCES => match addr {
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
        let result = self.make_netlink_request(RtnlMessage::DelAddress(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    fn create_route_msg(route: &Route) -> RouteMessage {
        let mut msg = RouteMessage::default();

        msg.header.table = RT_TABLE_MAIN;
        msg.header.protocol = RTPROT_STATIC;
        msg.header.scope = RT_SCOPE_UNIVERSE;
        msg.header.kind = RTN_UNICAST;

        info!("Adding route {}", route);

        let (dest_vec, dest_prefix, gateway_vec, final_metric) = match route {
            Route::Ipv4 { dest, gw, metric } => {
                msg.header.address_family = AF_INET as u8;
                (
                    dest.addr().octets().to_vec(),
                    dest.prefix_len(),
                    gw.octets().to_vec(),
                    metric.unwrap_or(constants::DEFAULT_METRIC),
                )
            }
            Route::Ipv6 { dest, gw, metric } => {
                msg.header.address_family = AF_INET6 as u8;
                (
                    dest.addr().octets().to_vec(),
                    dest.prefix_len(),
                    gw.octets().to_vec(),
                    metric.unwrap_or(constants::DEFAULT_METRIC),
                )
            }
        };

        msg.header.destination_prefix_length = dest_prefix;
        msg.nlas
            .push(netlink_packet_route::route::Nla::Destination(dest_vec));
        msg.nlas
            .push(netlink_packet_route::route::Nla::Gateway(gateway_vec));
        msg.nlas
            .push(netlink_packet_route::route::Nla::Priority(final_metric));
        msg
    }

    pub fn add_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);

        let result =
            self.make_netlink_request(RtnlMessage::NewRoute(msg), NLM_F_ACK | NLM_F_CREATE)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn del_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);

        let result = self.make_netlink_request(RtnlMessage::DelRoute(msg), NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    pub fn dump_routes(&mut self) -> NetavarkResult<Vec<RouteMessage>> {
        let mut msg = RouteMessage::default();

        msg.header.table = RT_TABLE_MAIN;
        msg.header.protocol = RTPROT_UNSPEC;
        msg.header.scope = RT_SCOPE_UNIVERSE;
        msg.header.kind = RTN_UNICAST;

        let results =
            self.make_netlink_request(RtnlMessage::GetRoute(msg), NLM_F_DUMP | NLM_F_ACK)?;

        let mut routes = Vec::with_capacity(results.len());

        for res in results {
            match res {
                RtnlMessage::NewRoute(m) => routes.push(m),
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

    pub fn dump_links(&mut self, nlas: &mut Vec<Nla>) -> NetavarkResult<Vec<LinkMessage>> {
        let mut msg = LinkMessage::default();
        msg.nlas.append(nlas);

        let results =
            self.make_netlink_request(RtnlMessage::GetLink(msg), NLM_F_DUMP | NLM_F_ACK)?;

        let mut links = Vec::with_capacity(results.len());

        for res in results {
            match res {
                RtnlMessage::NewLink(m) => links.push(m),
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

    pub fn set_up(&mut self, id: LinkID) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.nlas.push(Nla::IfName(name)),
        }

        msg.header.flags |= IFF_UP;
        msg.header.change_mask |= IFF_UP;

        let result = self.make_netlink_request(
            RtnlMessage::SetLink(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        )?;
        expect_netlink_result!(result, 0);

        Ok(())
    }

    fn make_netlink_request(
        &mut self,
        msg: RtnlMessage,
        flags: u16,
    ) -> NetavarkResult<Vec<RtnlMessage>> {
        self.send(msg, flags, None).wrap("send to netlink")?;
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }
}

impl CreateLinkOptions {
    pub fn new(name: String, kind: InfoKind) -> Self {
        CreateLinkOptions {
            name,
            kind,
            info_data: None,
            mtu: 0,
            primary_index: 0,
            link: 0,
            mac: vec![],
            // 0 is a valid fd, so use -1 by default
            netns: -1,
        }
    }
}

pub fn parse_create_link_options(msg: &mut LinkMessage, options: CreateLinkOptions) {
    // add link specific data
    let mut link_info_nlas = vec![Info::Kind(options.kind)];
    if let Some(data) = options.info_data {
        link_info_nlas.push(Info::Data(data));
    }
    msg.nlas.push(Nla::Info(link_info_nlas));

    // add name
    if !options.name.is_empty() {
        msg.nlas.push(Nla::IfName(options.name));
    }

    // add mtu
    if options.mtu != 0 {
        msg.nlas.push(Nla::Mtu(options.mtu));
    }

    // add mac address
    if !options.mac.is_empty() {
        msg.nlas.push(Nla::Address(options.mac));
    }

    // add primary device
    if options.primary_index != 0 {
        msg.nlas.push(Nla::Master(options.primary_index));
    }

    // add link device
    if options.link != 0 {
        msg.nlas.push(Nla::Link(options.link));
    }

    // add netnsfd
    if options.netns > -1 {
        msg.nlas.push(Nla::NetNsFd(options.netns));
    }
}

// Netlink API for Generic Sockets

pub struct GenericSocket {
    socket: netlink_sys::Socket,
    sequence_number: u32,
    wireguard_family: Option<u16>,
}

impl NetlinkSocket for GenericSocket {
    fn get_socket(&self) -> &netlink_sys::Socket {
        &self.socket
    }

    fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    fn increase_sequence_number(&mut self) -> u32 {
        self.sequence_number += 1;
        self.sequence_number
    }
}

impl GenericSocket {
    pub fn new() -> NetavarkResult<GenericSocket> {
        let mut socket = wrap!(netlink_sys::Socket::new(NETLINK_GENERIC), "open")?;
        let kernel_addr = &SocketAddr::new(0, 0);
        wrap!(socket.bind_auto(), "bind")?;
        wrap!(socket.connect(kernel_addr), "connect")?;

        Ok(GenericSocket {
            socket,
            sequence_number: 0,
            wireguard_family: None,
        })
    }

    pub fn set_wireguard_device(&mut self, nlas: Vec<WgDeviceAttrs>) -> NetavarkResult<()> {
        let msg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas,
        });
        let result = self.make_wireguard_request(msg, NLM_F_ACK)?;
        expect_netlink_result!(result, 0);
        Ok(())
    }

    fn query_family_id(&mut self, family_name: &'static str) -> NetavarkResult<u16> {
        let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(family_name.to_owned())],
        });
        let mut result = self.make_ctrl_request(genlmsg, true, NLM_F_ACK)?;
        expect_netlink_result!(result, 1);
        let result: GenlMessage<GenlCtrl> = result.remove(0);
        let mut family: Option<u16> = None;
        for nla in result.payload.nlas {
            if let GenlCtrlAttrs::FamilyId(m) = nla {
                family = Some(m)
            }
        }
        match family {
            Some(fam) => Ok(fam),
            None => Err(NetavarkError::msg(
                "Unable to resolve netlink family id for WireGuard API packets",
            )),
        }
    }

    fn make_ctrl_request(
        &mut self,
        msg: GenlMessage<GenlCtrl>,
        multi: bool,
        flags: u16,
    ) -> NetavarkResult<Vec<GenlMessage<GenlCtrl>>> {
        self.send(msg, flags, None).wrap("send to netlink")?;
        self.recv(multi)
    }

    fn make_wireguard_request(
        &mut self,
        msg: GenlMessage<Wireguard>,
        flags: u16,
    ) -> NetavarkResult<Vec<GenlMessage<Wireguard>>> {
        if self.wireguard_family.is_none() {
            let family = self
                .query_family_id("wireguard")
                .expect("Could not resolve family_id for WireGuard netlink API");
            trace!("WireGuard family ID is: {:?}", family);
            self.wireguard_family = Some(family);
        }
        self.send(msg, flags, self.wireguard_family)
            .wrap("send to netlink")?;
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }
}
