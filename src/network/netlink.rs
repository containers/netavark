use std::marker::PhantomData;

use crate::{
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    wrap,
};
use log::trace;
use netlink_packet_core::{
    NetlinkBuffer, NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    NetlinkSerializable, NLMSG_DONE, NLMSG_ERROR, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_sys::SocketAddr;

pub trait NetlinkFamily {
    const PROTOCOL: isize;
    type Message;
}

const NLMSG_GOODSIZE: usize = 8192;

pub struct Socket<P: NetlinkFamily> {
    socket: netlink_sys::Socket,
    sequence_number: u32,
    ///  buffer size for reading netlink messages, see NLMSG_GOODSIZE in the kernel
    buffer: [u8; NLMSG_GOODSIZE],
    _protocol: PhantomData<P>,
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
pub(crate) use function;

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
pub(crate) use expect_netlink_result;

impl<P> Socket<P>
where
    P: NetlinkFamily,
{
    pub fn new() -> NetavarkResult<Socket<P>> {
        let mut socket = wrap!(netlink_sys::Socket::new(P::PROTOCOL), "open")?;
        let addr = &SocketAddr::new(0, 0);
        // Needs to be enabled for dump filtering to work
        socket.set_netlink_get_strict_chk(true)?;
        wrap!(socket.bind(addr), "bind")?;
        wrap!(socket.connect(addr), "connect")?;

        Ok(Socket {
            socket,
            sequence_number: 0,
            buffer: [0; 8192],
            _protocol: PhantomData,
        })
    }

    fn send(&mut self, msg: P::Message, flags: u16) -> NetavarkResult<()>
    where
        P::Message: NetlinkSerializable + std::fmt::Debug,
        NetlinkPayload<P::Message>: From<P::Message>,
    {
        let mut packet = NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::from(msg));
        packet.header.flags = NLM_F_REQUEST | flags;
        packet.header.sequence_number = {
            self.sequence_number += 1;
            self.sequence_number
        };
        packet.finalize();

        let len = packet.buffer_len();
        let buffer = self.buffer.get_mut(..len).ok_or_else(|| {
            NetavarkError::msg(format!(
                "netlink request size {len} to large for buffer with len {}",
                NLMSG_GOODSIZE
            ))
        })?;

        packet.serialize(buffer);
        trace!("send netlink packet: {packet:?}");

        self.socket.send(buffer, 0)?;
        Ok(())
    }

    fn recv(&mut self, multi: bool) -> NetavarkResult<Vec<P::Message>>
    where
        P::Message: NetlinkDeserializable + std::fmt::Debug,
    {
        match self.recv_inner(multi) {
            Ok(result) => Ok(result),
            Err(e) => {
                if multi {
                    self.drain_dump()?;
                }
                Err(e)
            }
        }
    }

    fn recv_inner(&mut self, multi: bool) -> NetavarkResult<Vec<P::Message>>
    where
        P::Message: NetlinkDeserializable + std::fmt::Debug,
    {
        let mut result = Vec::new();

        // if multi is set we expect a multi part message
        loop {
            let size = wrap!(
                self.socket.recv(&mut &mut self.buffer[..], 0),
                "recv from netlink"
            )?;

            // only use the amount of bytes we actually read
            let mut buffer = &self.buffer[..size];

            loop {
                let rx_packet: NetlinkMessage<P::Message> = NetlinkMessage::deserialize(buffer)
                    .map_err(|e| {
                        NetavarkError::Message(format!(
                            "failed to deserialize netlink message: {e}",
                        ))
                    })?;
                trace!("read netlink packet: {rx_packet:?}");

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

                let len = rx_packet.header.length as usize;
                if buffer.len() == len || len == 0 {
                    break;
                }
                // move the buffer to the next message
                buffer = &buffer[len..];
            }
        }
    }

    /// Drain the rest of a multi-part reply after an error, so the next request
    /// doesn't read this one's left over messages.
    fn drain_dump(&mut self) -> NetavarkResult<()> {
        loop {
            let size = wrap!(
                self.socket.recv(&mut &mut self.buffer[..], 0),
                "recv from netlink (drain)"
            )?;
            match scan_for_dump_end(&self.buffer[..size]) {
                Ok(true) => return Ok(()),
                Ok(false) => continue,
                Err(_) => return self.drain_best_effort(),
            }
        }
    }

    fn drain_best_effort(&mut self) -> NetavarkResult<()> {
        loop {
            match self
                .socket
                .recv(&mut &mut self.buffer[..], libc::MSG_DONTWAIT)
            {
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => {
                    return Err(NetavarkError::wrap(
                        "recv from netlink (best effort drain)",
                        e.into(),
                    ))
                }
            }
        }
    }

    pub fn make_netlink_request(
        &mut self,
        msg: P::Message,
        flags: u16,
    ) -> NetavarkResult<Vec<P::Message>>
    where
        P::Message: NetlinkSerializable + NetlinkDeserializable + std::fmt::Debug,
        NetlinkPayload<P::Message>: From<P::Message>,
    {
        self.send(msg, flags).wrap("send to netlink")?;
        self.recv(flags & NLM_F_DUMP == NLM_F_DUMP)
    }
}

/// Scan a buffer of netlink message headers for the end of a dump
/// (NLMSG_DONE or NLMSG_ERROR). Returns true if found, false if the
/// buffer ran out first and the caller needs to read more.
fn scan_for_dump_end(mut buffer: &[u8]) -> NetavarkResult<bool> {
    while !buffer.is_empty() {
        let hdr = NetlinkBuffer::new_checked(buffer).map_err(|e| {
            NetavarkError::Message(format!(
                "failed to parse netlink header while draining socket: {e}"
            ))
        })?;

        if hdr.message_type() == NLMSG_DONE || hdr.message_type() == NLMSG_ERROR {
            return Ok(true);
        }

        let len = hdr.length() as usize;
        if buffer.len() == len {
            return Ok(false);
        }
        buffer = &buffer[len..];
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // builds a minimal netlink message header-only buffer (no payload)
    fn header(len: u32, msg_type: u16) -> Vec<u8> {
        let mut buf = vec![0u8; len as usize];
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf
    }

    const RTM_NEWROUTE: u16 = 24;

    #[test]
    fn finds_done_after_unparseable_message() {
        let mut buffer = Vec::new();
        buffer.extend(header(16, RTM_NEWROUTE)); // normal route
        buffer.extend(header(16, RTM_NEWROUTE)); // stand-in for the broken multicast entry
        buffer.extend(header(16, NLMSG_DONE));

        assert!(scan_for_dump_end(&buffer).unwrap());
    }

    #[test]
    fn needs_more_data_when_buffer_ends_without_done() {
        let mut buffer = Vec::new();
        buffer.extend(header(16, RTM_NEWROUTE));
        buffer.extend(header(16, RTM_NEWROUTE));

        assert!(!scan_for_dump_end(&buffer).unwrap());
    }

    #[test]
    fn treats_error_as_dump_end() {
        let mut buffer = Vec::new();
        buffer.extend(header(16, RTM_NEWROUTE));
        buffer.extend(header(36, NLMSG_ERROR));

        assert!(scan_for_dump_end(&buffer).unwrap());
    }

    #[test]
    fn rejects_corrupt_length() {
        // buffer is only 16 bytes, but its length field lies and claims 100
        let mut buffer = header(16, RTM_NEWROUTE);
        buffer[0..4].copy_from_slice(&100u32.to_ne_bytes());
        assert!(scan_for_dump_end(&buffer).is_err());
    }
}
