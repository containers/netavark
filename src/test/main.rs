//! Test program only, unsupported outside of our test suite.
use std::{
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
};

use netavark::exec_netns;
use netavark::network::core_utils::join_netns;
use nix::sys::socket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    _ = args.next(); // skip argv0

    let mut i = 0;
    let mut netns = String::new();
    let mut connect = String::new();
    let mut listen = String::new();

    let mut sock_type = socket::SockType::Stream;
    let mut protocol = socket::SockProtocol::Tcp;

    for arg in args {
        match arg.as_str() {
            "--tcp" => {
                protocol = socket::SockProtocol::Tcp;
                sock_type = socket::SockType::Stream;
            }
            "--udp" => {
                protocol = socket::SockProtocol::Udp;
                sock_type = socket::SockType::Datagram;
            }
            "--sctp" => {
                protocol = socket::SockProtocol::Sctp;
                sock_type = socket::SockType::Stream;
            }
            _ => {
                match i {
                    0 => netns = arg,
                    1 => connect = arg,
                    2 => listen = arg,
                    _ => {
                        eprintln!("To many arguments\nUsage: NETNS CONNECT_ADDRESS LISTEN_PORT");
                        std::process::exit(1)
                    }
                };
                i += 1;
            }
        }
    }

    let hostns = std::fs::File::open("/proc/self/ns/net").expect("open host netns");
    let containerns = std::fs::File::open(netns).expect("open netns");

    let connect_addr: std::net::SocketAddr =
        connect.parse().expect("failed to parse connect address");

    let listen_port: u16 = listen.parse().expect("parse listne port");

    let (address_family, listen_addr) = match connect_addr {
        std::net::SocketAddr::V4(_) => (
            socket::AddressFamily::Inet,
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::UNSPECIFIED,
                listen_port,
            )),
        ),
        std::net::SocketAddr::V6(_) => (
            socket::AddressFamily::Inet6,
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::UNSPECIFIED,
                listen_port,
                0,
                0,
            )),
        ),
    };

    // create socket in namespace
    let listen_sock = exec_netns!(&hostns, &containerns, {
        let listen_sock = socket::socket(
            address_family,
            sock_type,
            socket::SockFlag::empty(),
            Some(protocol),
        )
        .expect("listen socket");

        socket::bind(
            listen_sock.as_raw_fd(),
            &socket::SockaddrStorage::from(listen_addr),
        )
        .expect("bind listen socket");

        listen_sock
    });

    let connect_sock = socket::socket(
        address_family,
        sock_type,
        socket::SockFlag::empty(),
        Some(protocol),
    )
    .expect("connect socket");

    let mut send_buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut send_buf)
        .expect("read stdin");

    match sock_type {
        socket::SockType::Stream => stream_test(listen_sock, connect_sock, connect_addr, &send_buf),
        socket::SockType::Datagram => {
            datagram_test(listen_sock, connect_sock, connect_addr, &send_buf)
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn stream_test(
    listen_sock: OwnedFd,
    connect_sock: OwnedFd,
    connect_addr: std::net::SocketAddr,
    buf: &[u8],
) {
    socket::listen(&listen_sock, socket::Backlog::new(5).unwrap()).expect("listen on socket");

    socket::connect(
        connect_sock.as_raw_fd(),
        &socket::SockaddrStorage::from(connect_addr),
    )
    .expect("connect to remote socket");

    let conn = socket::accept4(listen_sock.as_raw_fd(), socket::SockFlag::empty())
        .expect("accept connection");

    let peer_addr = socket::getpeername::<socket::SockaddrStorage>(conn).expect("getpeername");
    println!("Peer address: {peer_addr}");

    socket::send(connect_sock.as_raw_fd(), buf, socket::MsgFlags::empty()).expect("send msg");

    let mut read_buf = vec![0; buf.len()];

    let len = socket::recv(conn, &mut read_buf, socket::MsgFlags::empty()).expect("recv msg");

    println!(
        "Message: {}",
        std::str::from_utf8(&read_buf[..len]).expect("parse msg")
    );
}

fn datagram_test(
    listen_sock: OwnedFd,
    connect_sock: OwnedFd,
    connect_addr: std::net::SocketAddr,
    buf: &[u8],
) {
    socket::sendto(
        connect_sock.as_raw_fd(),
        buf,
        &socket::SockaddrStorage::from(connect_addr),
        socket::MsgFlags::empty(),
    )
    .expect("sendto msg");

    let mut read_buf = vec![0; buf.len()];

    let (len, peer_addr) =
        socket::recvfrom::<socket::SockaddrStorage>(listen_sock.as_raw_fd(), &mut read_buf)
            .expect("recvfrom msg");

    let peer_addr = peer_addr.expect("no peer address");
    println!("Peer address: {peer_addr}");

    println!(
        "Message: {}",
        std::str::from_utf8(&read_buf[..len]).expect("parse msg")
    );
}
