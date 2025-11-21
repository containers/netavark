use netlink_packet_netfilter::{
    conntrack::{ConntrackNla, IPTuple, ProtoTuple, Protocol, Tuple},
    NetfilterMessageInner,
};
use std::{collections::HashSet, net::IpAddr, num::NonZeroI32};

use crate::{
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::{
        netlink::{expect_netlink_result, function, NetlinkFamily, Socket},
        types::PortMapping,
    },
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP};
use netlink_packet_netfilter::{
    conntrack::ConntrackMessage, NetfilterHeader, NetfilterMessage, ProtoFamily,
};
use netlink_sys::protocols::NETLINK_NETFILTER;

pub struct NetlinkNetfilter;

impl NetlinkFamily for NetlinkNetfilter {
    const PROTOCOL: isize = NETLINK_NETFILTER;
    type Message = NetfilterMessage;
}

// Represents the 5-tuple for a single direction of a connection flow.
#[derive(Clone)]
pub struct FlowTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}
impl FlowTuple {
    pub fn is_ipv6(&self) -> bool {
        self.src_ip.is_ipv6() && self.dst_ip.is_ipv6()
    }
}

// Represents a conntrack entry, detailing the original and reply flows.
#[derive(Clone)]
pub struct ConntrackFlow {
    pub origin: Option<FlowTuple>,
    pub reply: Option<FlowTuple>,
}

// Converts a `ConntrackFlow` into a vector of `ConntrackNla`
// attributes suitable for a netlink message payload.
impl ConntrackFlow {
    fn to_attributes(self: ConntrackFlow) -> Vec<ConntrackNla> {
        fn to_tuple_attributes(flow_tuple: &FlowTuple) -> Vec<Tuple> {
            let ip_attributes = vec![
                IPTuple::SourceAddress(flow_tuple.src_ip),
                IPTuple::DestinationAddress(flow_tuple.dst_ip),
            ];

            let proto_attributes = vec![
                ProtoTuple::Protocol(flow_tuple.protocol),
                ProtoTuple::SourcePort(flow_tuple.src_port),
                ProtoTuple::DestinationPort(flow_tuple.dst_port),
            ];
            vec![Tuple::Ip(ip_attributes), Tuple::Proto(proto_attributes)]
        }

        let mut attributes = Vec::new();

        if let Some(ref origin_flow) = self.origin {
            let origin_attributes = to_tuple_attributes(origin_flow);
            if !origin_attributes.is_empty() {
                attributes.push(ConntrackNla::CtaTupleOrig(origin_attributes));
            }
        }

        if let Some(ref reply_flow) = self.reply {
            let reply_attributes = to_tuple_attributes(reply_flow);
            if !reply_attributes.is_empty() {
                attributes.push(ConntrackNla::CtaTupleReply(reply_attributes));
            }
        }

        attributes
    }
    fn is_ipv6(&self) -> NetavarkResult<bool> {
        match (&self.origin, &self.reply) {
            (Some(origin), Some(reply)) => {
                let origin_is_v6 = origin.is_ipv6();

                if origin_is_v6 != reply.is_ipv6() {
                    Err(NetavarkError::Message(
                        "The families are different".to_string(),
                    ))
                } else {
                    Ok(origin_is_v6)
                }
            }

            (Some(origin), None) => Ok(origin.is_ipv6()),

            (None, Some(reply)) => Ok(reply.is_ipv6()),

            (None, None) => Err(NetavarkError::Message(
                "There needs to be atleast one FlowTuple in a conntrack flow".to_string(),
            )),
        }
    }
}

impl Socket<NetlinkNetfilter> {
    pub fn dump_conntrack(&mut self) -> NetavarkResult<Vec<NetfilterMessage>> {
        let msg: NetfilterMessage = NetfilterMessage::new(
            NetfilterHeader::new(ProtoFamily::ProtoUnspec, 0, 0),
            ConntrackMessage::Get(vec![]),
        );

        let result = self.make_netlink_request(msg, NLM_F_DUMP)?;

        Ok(result)
    }

    pub fn del_conntrack(&mut self, flow: ConntrackFlow) -> NetavarkResult<()> {
        let is_v6 = flow.is_ipv6()?;
        let proto_family = if is_v6 {
            ProtoFamily::ProtoIPv6
        } else {
            ProtoFamily::ProtoIPv4
        };
        let msg: NetfilterMessage = NetfilterMessage::new(
            NetfilterHeader::new(proto_family, 0, 0),
            ConntrackMessage::Delete(flow.to_attributes()),
        );

        let result = self.make_netlink_request(msg, NLM_F_ACK)?;
        expect_netlink_result!(result, 0);

        Ok(())
    }
}

/// This function addresses an issue where UDP traffic is dropped due to stale conntrack entries.
///
/// To solve this, we proactively flush any conntrack entries associated with the mapped UDP
/// host ports before the network is fully set up. This ensures the kernel creates a fresh,
/// correct entry for the new service instance.
///
/// Fixes: https://github.com/containers/netavark/issues/1045
pub fn flush_udp_conntrack(
    port_mappings: &[PortMapping],
    container_ipv4: Option<IpAddr>,
    container_ipv6: Option<IpAddr>,
) -> NetavarkResult<()> {
    let mut host_ports_to_flush = HashSet::<u16>::new();
    for pm in port_mappings.iter().filter(|pm| pm.protocol == "udp") {
        for port in pm.host_port..(pm.host_port + pm.range) {
            host_ports_to_flush.insert(port);
        }
    }

    if host_ports_to_flush.is_empty() && container_ipv4.is_none() && container_ipv6.is_none() {
        return Ok(());
    }

    let mut ct_socket = Socket::<NetlinkNetfilter>::new().wrap("conntrack netlink socket")?;
    let conntrack_dump = ct_socket.dump_conntrack()?;

    for msg in &conntrack_dump {
        if let Some(flow) = parse_ct_new_msg(msg) {
            if matches_flow(&flow, &host_ports_to_flush, container_ipv4, container_ipv6) {
                match ct_socket.del_conntrack(flow) {
                    Ok(_) => {}
                    // We iterate over a dump of entries. Between the time we dump the table
                    // and the time we attempt the delete, the entry might have naturally
                    // expired. Treating ENOENT as success ensures we don't fail the setup
                    // just because the cleanup happened automatically.
                    Err(NetavarkError::Netlink(e)) if e.code == NonZeroI32::new(-libc::ENOENT) => {
                        log::debug!("Conntrack entry already deleted, skipping");
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

fn matches_flow(
    flow: &ConntrackFlow,
    ports: &HashSet<u16>,
    ipv4: Option<IpAddr>,
    ipv6: Option<IpAddr>,
) -> bool {
    if let Some(origin) = &flow.origin {
        if origin.protocol == Protocol::Udp && ports.contains(&origin.dst_port) {
            return true;
        }
    }
    if let Some(reply) = &flow.reply {
        let is_match = |ip| ipv4 == Some(ip) || ipv6 == Some(ip);
        if is_match(reply.src_ip) || is_match(reply.dst_ip) {
            return true;
        }
    }
    false
}

/// parses a conntrack new netfilter message into a ConntrackFlow struct
pub fn parse_ct_new_msg(msg: &NetfilterMessage) -> Option<ConntrackFlow> {
    let attributes = match &msg.inner {
        NetfilterMessageInner::Conntrack(ConntrackMessage::New(attr)) => attr,
        _ => return None,
    };

    let mut origin_tuples = None;
    let mut reply_tuples = None;

    for nla in attributes {
        match nla {
            ConntrackNla::CtaTupleOrig(tuples) => origin_tuples = Some(tuples.as_slice()),
            ConntrackNla::CtaTupleReply(tuples) => reply_tuples = Some(tuples.as_slice()),
            _ => {}
        }

        if origin_tuples.is_some() && reply_tuples.is_some() {
            break;
        }
    }

    let origin_flow = parse_tuples_to_flow(origin_tuples?)?;
    let reply_flow = parse_tuples_to_flow(reply_tuples?)?;

    Some(ConntrackFlow {
        origin: Some(origin_flow),
        reply: Some(reply_flow),
    })
}

fn parse_tuples_to_flow(tuples: &[Tuple]) -> Option<FlowTuple> {
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut src_port = None;
    let mut dst_port = None;
    let mut protocol_from_tuple = None;

    for tuple in tuples {
        match tuple {
            Tuple::Ip(ip_tuples) => {
                for ip_tuple in ip_tuples {
                    match ip_tuple {
                        IPTuple::SourceAddress(ip) => src_ip = Some(*ip),
                        IPTuple::DestinationAddress(ip) => dst_ip = Some(*ip),
                        _ => (),
                    }
                }
            }
            Tuple::Proto(proto_tuples) => {
                for proto_tuple in proto_tuples {
                    match proto_tuple {
                        ProtoTuple::Protocol(p) => protocol_from_tuple = Some(*p),
                        ProtoTuple::SourcePort(p) => src_port = Some(*p),
                        ProtoTuple::DestinationPort(p) => dst_port = Some(*p),
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }

    Some(FlowTuple {
        src_ip: src_ip?,
        dst_ip: dst_ip?,
        src_port: src_port?,
        dst_port: dst_port?,
        protocol: protocol_from_tuple?,
    })
}
