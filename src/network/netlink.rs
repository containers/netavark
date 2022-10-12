use std::{
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::prelude::RawFd,
};

use crate::{
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    wrap,
};
use log::trace;
use netlink_packet_route::{
    nlas::link::{Info, InfoData, InfoKind, Nla},
    AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, RouteMessage,
    RtnlMessage, AF_INET, AF_INET6, IFF_UP, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST, RTN_UNICAST, RTPROT_STATIC, RTPROT_UNSPEC, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN,
};
use netlink_sys::{protocols::NETLINK_ROUTE, SocketAddr};

pub struct Socket {
    socket: netlink_sys::Socket,
    sequence_number: u32,
    ///  buffer size for reading netlink messages, see NLMSG_GOODSIZE in the kernel
    buffer: [u8; 8192],
}

pub struct CreateLinkOptions {
    name: String,
    kind: InfoKind,
    pub info_data: Option<InfoData>,
    pub mtu: u32,
    pub master_index: u32,
    pub link: u32,
    pub mac: Vec<u8>,
    pub netns: RawFd,
}

pub enum LinkID {
    ID(u32),
    Name(String),
}

pub enum Route {
    Ipv4 { dest: ipnet::Ipv4Net, gw: Ipv4Addr },
    Ipv6 { dest: ipnet::Ipv6Net, gw: Ipv6Addr },
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (dest, gw) = match self {
            Route::Ipv4 { dest, gw } => (dest.to_string(), gw.to_string()),
            Route::Ipv6 { dest, gw } => (dest.to_string(), gw.to_string()),
        };
        write!(f, "(dest: {} ,gw: {})", dest, gw)
    }
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
            LinkID::Name(name) => msg.nlas.push(Nla::IfName(name)),
        }

        let mut result = self.make_netlink_request(RtnlMessage::GetLink(msg), 0)?;
        if result.len() != 1 {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }
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
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

        Ok(())
    }

    pub fn del_link(&mut self, id: LinkID) -> NetavarkResult<()> {
        let mut msg = LinkMessage::default();

        match id {
            LinkID::ID(id) => msg.header.index = id,
            LinkID::Name(name) => msg.nlas.push(Nla::IfName(name)),
        }

        let result = self.make_netlink_request(RtnlMessage::DelLink(msg), NLM_F_ACK)?;
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result 1243"));
        }
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
        let result = self.make_netlink_request(
            RtnlMessage::NewAddress(msg),
            NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        )?;
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

        Ok(())
    }

    pub fn del_addr(&mut self, link_id: u32, addr: &ipnet::IpNet) -> NetavarkResult<()> {
        let msg = Self::create_addr_msg(link_id, addr);
        let result = self.make_netlink_request(RtnlMessage::DelAddress(msg), NLM_F_ACK)?;
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

        Ok(())
    }

    fn create_route_msg(route: &Route) -> RouteMessage {
        let mut msg = RouteMessage::default();

        msg.header.table = RT_TABLE_MAIN;
        msg.header.protocol = RTPROT_STATIC;
        msg.header.scope = RT_SCOPE_UNIVERSE;
        msg.header.kind = RTN_UNICAST;

        let (dest_vec, dest_prefix, gateway_vec) = match route {
            Route::Ipv4 { dest, gw } => {
                msg.header.address_family = AF_INET as u8;
                (
                    dest.addr().octets().to_vec(),
                    dest.prefix_len(),
                    gw.octets().to_vec(),
                )
            }
            Route::Ipv6 { dest, gw } => {
                msg.header.address_family = AF_INET6 as u8;
                (
                    dest.addr().octets().to_vec(),
                    dest.prefix_len(),
                    gw.octets().to_vec(),
                )
            }
        };

        msg.header.destination_prefix_length = dest_prefix;
        msg.nlas
            .push(netlink_packet_route::route::Nla::Destination(dest_vec));
        msg.nlas
            .push(netlink_packet_route::route::Nla::Gateway(gateway_vec));
        msg
    }

    pub fn add_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);

        let result =
            self.make_netlink_request(RtnlMessage::NewRoute(msg), NLM_F_ACK | NLM_F_CREATE)?;
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

        Ok(())
    }

    pub fn del_route(&mut self, route: &Route) -> NetavarkResult<()> {
        let msg = Self::create_route_msg(route);

        let result = self.make_netlink_request(RtnlMessage::DelRoute(msg), NLM_F_ACK)?;
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

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
        if !result.is_empty() {
            return Err(NetavarkError::msg_str("unexpected netlink result"));
        }

        Ok(())
    }

    fn make_netlink_request(
        &mut self,
        msg: RtnlMessage,
        flags: u16,
    ) -> NetavarkResult<Vec<RtnlMessage>> {
        self.send(msg, flags).wrap("send to netlink")?;
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }

    fn send(&mut self, msg: RtnlMessage, flags: u16) -> NetavarkResult<()> {
        let mut packet = NetlinkMessage {
            header: NetlinkHeader::default(),
            payload: NetlinkPayload::from(msg),
        };
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

    fn recv(&mut self, multi: bool) -> NetavarkResult<Vec<RtnlMessage>> {
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
                let rx_packet: NetlinkMessage<RtnlMessage> = NetlinkMessage::deserialize(bytes)
                    .map_err(|e| {
                        NetavarkError::Message(format!(
                            "failed to deserialize netlink message: {}",
                            e,
                        ))
                    })?;
                trace!("read netlink packet: {:?}", rx_packet);

                match rx_packet.payload {
                    NetlinkPayload::Done => return Ok(result),
                    NetlinkPayload::Error(e) | NetlinkPayload::Ack(e) => {
                        if e.code != 0 {
                            return Err(e.into());
                        }
                        return Ok(result);
                    }
                    NetlinkPayload::Noop => {
                        return Err(NetavarkError::msg_str(
                            "unimplemented netlink message type NOOP",
                        ))
                    }
                    NetlinkPayload::Overrun(_) => {
                        return Err(NetavarkError::msg_str(
                            "unimplemented netlink message type OVERRUN",
                        ))
                    }
                    NetlinkPayload::InnerMessage(msg) => {
                        result.push(msg);
                        if !multi {
                            return Ok(result);
                        }
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

impl CreateLinkOptions {
    pub fn new(name: String, kind: InfoKind) -> Self {
        CreateLinkOptions {
            name,
            kind,
            info_data: None,
            mtu: 0,
            master_index: 0,
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

    // add master device
    if options.master_index != 0 {
        msg.nlas.push(Nla::Master(options.master_index));
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
