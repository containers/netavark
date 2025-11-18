#[cfg(test)]
mod tests {
    use netavark::network::netlink::Socket;
    use netavark::network::netlink_netfilter::{
        parse_ct_new_msg, ConntrackFlow, FlowTuple, NetlinkNetfilter,
    };
    use netavark::network::netlink_route::{CreateLinkOptions, LinkID, NetlinkRoute, Route};
    use netlink_packet_netfilter::conntrack::Protocol;

    use netlink_packet_route::{address, link::InfoKind};
    use std::net::{IpAddr, Ipv4Addr};

    macro_rules! test_setup {
        () => {
            if !nix::unistd::getuid().is_root() {
                // there is no actual way to mark a test as skipped
                // https://internals.rust-lang.org/t/pre-rfc-skippable-tests/14611
                eprintln!("test skipped, requires root");
                return;
            }
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                .expect("unshare(CLONE_NEWNET)");
        };
    }

    macro_rules! run_command {
        ($command:expr  $(, $args:expr)*) => {
            std::process::Command::new($command).args([$($args),*]).output()
                .expect("failed to run command")
        };
    }

    #[test]
    fn test_socket_new() {
        test_setup!();
        assert!(
            Socket::<NetlinkRoute>::new().is_ok(),
            "Netlink Socket::new() should work"
        );
    }

    #[test]
    fn test_add_link() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let name = String::from("test1");
        sock.create_link(CreateLinkOptions::new(name.clone(), InfoKind::Dummy))
            .expect("create link failed");

        let out = String::from_utf8(run_command!("ip", "link", "show", &name).stdout)
            .expect("convert to string failed");

        assert!(out.contains(&name), "link test1 does not exists");
    }

    #[test]
    fn test_add_addr() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let out = run_command!("ip", "link", "add", "test1", "type", "dummy");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add link via ip");

        let link = sock
            .get_link(LinkID::Name("test1".into()))
            .expect("get_link failed");

        let net = "10.0.0.2/24";
        sock.add_addr(link.header.index, &net.parse().unwrap())
            .expect("add_addr failed");

        let out = String::from_utf8(run_command!("ip", "addr", "show", "test1").stdout)
            .expect("convert to string failed");

        assert!(out.contains(net), "addr does not exists");
    }

    #[test]
    fn test_del_addr() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let out = run_command!("ip", "link", "add", "test1", "type", "dummy");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add link via ip");

        let net = "10.0.0.2/24";

        let out = run_command!("ip", "addr", "add", net, "dev", "test1");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add addr via ip");

        let link = sock
            .get_link(LinkID::Name("test1".into()))
            .expect("get_link failed");

        sock.del_addr(link.header.index, &net.parse().unwrap())
            .expect("del_addr failed");

        let out = run_command!("ip", "addr", "show", "test1");
        let stdout = String::from_utf8(out.stdout).unwrap();
        eprintln!("{stdout}");
        assert!(out.status.success(), "failed to show addr via ip");

        assert!(!stdout.contains(net), "addr does exist");
    }

    /// This test fails because we do not have actual functioning routes in the test netns
    /// For some reason the kernel expects us to set different options to make it work but
    /// I do not want to expose them just for a test.
    /// With these option you could get it to work but it will not work in the actual use case
    ///         msg.header.protocol = RTPROT_UNSPEC;
    ///         msg.header.scope = RT_SCOPE_NOWHERE;
    ///         msg.header.kind = RTN_UNSPEC;
    #[test]
    #[ignore]
    fn test_del_route() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let out = run_command!("ip", "link", "add", "test1", "type", "dummy");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add link via ip");

        let net = "10.0.0.2/24";

        let out = run_command!("ip", "addr", "add", net, "dev", "test1");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add addr via ip");

        // route requires that the link is up!
        let out = run_command!("ip", "link", "set", "dev", "test1", "up");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to set test1 up via ip");

        let net = "10.0.1.0/24";
        let gw = "10.0.0.2";

        let out = run_command!("ip", "route", "add", net, "via", gw);
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add route via ip");

        let out = run_command!("ip", "route", "show");
        let stdout = String::from_utf8(out.stdout).unwrap();
        eprintln!("{stdout}");
        assert!(out.status.success(), "failed to show addr via ip");

        assert!(stdout.contains(net), "route should exist");

        sock.del_route(&Route::Ipv4 {
            dest: net.parse().unwrap(),
            gw: gw.parse().unwrap(),
            metric: None,
        })
        .expect("del_route failed");

        let out = run_command!("ip", "route", "show");
        let stdout = String::from_utf8(out.stdout).unwrap();
        eprintln!("{stdout}");
        assert!(out.status.success(), "failed to show addr via ip");

        assert!(!stdout.contains(net), "route should not exist");
    }

    #[test]
    fn test_dump_addr() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let out = run_command!("ip", "link", "add", "test1", "type", "dummy");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add link via ip");

        let net = "10.0.0.2/24";

        let out = run_command!("ip", "addr", "add", net, "dev", "test1");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add addr via ip");

        let out = run_command!("ip", "link", "set", "up", "lo");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to set up lo via ip");

        let addresses = sock.dump_addresses(None).expect("dump_addresses failed");
        for nla in addresses[0].attributes.iter() {
            if let address::AddressAttribute::Address(ip) = nla {
                assert_eq!(ip, &IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            }
        }
        for nla in addresses[1].attributes.iter() {
            if let address::AddressAttribute::Address(ip) = nla {
                assert_eq!(ip, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            }
        }
    }
    #[test]
    fn test_dump_addr_filter() {
        test_setup!();
        let mut sock = Socket::<NetlinkRoute>::new().expect("Socket::new()");

        let out = run_command!("ip", "link", "add", "test1", "type", "dummy");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add link via ip");

        let net = "10.0.0.2/24";

        let out = run_command!("ip", "addr", "add", net, "dev", "test1");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to add addr via ip");

        let out = run_command!("ip", "link", "set", "up", "lo");
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        assert!(out.status.success(), "failed to set up lo via ip");

        let bridge_id: u32 = sock
            .get_link(LinkID::Name("test1".to_string()))
            .expect("get_link failed")
            .header
            .index;

        let addresses = sock
            .dump_addresses(Some(bridge_id))
            .expect("dump_address_filter failed");
        for nla in addresses[0].attributes.iter() {
            if let address::AddressAttribute::Address(ip) = nla {
                assert_eq!(ip, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            }
        }
    }

    #[test]
    fn test_dump_conntrack() {
        test_setup!();
        let mut sock = Socket::<NetlinkNetfilter>::new().expect("Socket::new()");

        let tcp_src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let tcp_dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let tcp_src_port: u16 = 12345;
        let tcp_dst_port: u16 = 80;

        let udp_src_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 30, 5));
        let udp_dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        let udp_src_port: u16 = 49152;
        let udp_dst_port: u16 = 53;

        let out = run_command!(
            "conntrack",
            "-I",
            "-p",
            "tcp",
            "--src",
            &tcp_src_ip.to_string(),
            "--dst",
            &tcp_dst_ip.to_string(),
            "--sport",
            &tcp_src_port.to_string(),
            "--dport",
            &tcp_dst_port.to_string(),
            "--state",
            "SYN_SENT",
            "--timeout",
            "60"
        );
        assert!(out.status.success(), "failed to add TCP conntrack entry");

        let out = run_command!(
            "conntrack",
            "-I",
            "-p",
            "udp",
            "--src",
            &udp_src_ip.to_string(),
            "--dst",
            &udp_dst_ip.to_string(),
            "--sport",
            &udp_src_port.to_string(),
            "--dport",
            &udp_dst_port.to_string(),
            "--timeout",
            "30"
        );
        assert!(out.status.success(), "failed to add UDP conntrack entry");

        let msgs = sock.dump_conntrack().expect("dump_conntrack failed");
        assert!(msgs.len() == 2, "Expected two conntrack entries");

        let mut found_tcp_flow = false;
        let mut found_udp_flow = false;

        for msg in &msgs {
            if let Some(flow) = parse_ct_new_msg(msg) {
                let origin = flow.origin.as_ref().unwrap();

                match origin.protocol {
                    Protocol::Tcp if origin.dst_port == tcp_dst_port => {
                        assert_eq!(origin.src_ip, tcp_src_ip, "TCP origin source IP mismatch");
                        assert_eq!(
                            origin.src_port, tcp_src_port,
                            "TCP origin source port mismatch"
                        );
                        found_tcp_flow = true;
                    }
                    Protocol::Udp if origin.dst_port == udp_dst_port => {
                        assert_eq!(origin.src_ip, udp_src_ip, "UDP origin source IP mismatch");
                        assert_eq!(
                            origin.src_port, udp_src_port,
                            "UDP origin source port mismatch"
                        );
                        found_udp_flow = true;
                    }
                    _ => (),
                }
            }
        }

        assert!(
            found_tcp_flow,
            "Did not find the expected TCP conntrack flow in the dump"
        );
        assert!(
            found_udp_flow,
            "Did not find the expected UDP conntrack flow in the dump"
        );
    }

    #[test]
    fn test_del_conntrack() {
        test_setup!();
        let mut sock = Socket::<NetlinkNetfilter>::new().expect("Socket::new()");

        let src_ip = "192.168.1.100";
        let src_port = "12345";
        let dst_ip = "10.0.0.1";
        let dst_port = "80";

        let out = run_command!(
            "conntrack",
            "-I",
            "-p",
            "tcp",
            "--src",
            src_ip,
            "--dst",
            dst_ip,
            "--sport",
            src_port,
            "--dport",
            dst_port,
            "--state",
            "SYN_SENT",
            "--timeout",
            "60"
        );
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        assert!(
            out.status.success(),
            "failed to add conntrack entry via conntrack-tools"
        );

        let conntrack_flow = ConntrackFlow {
            origin: Some(FlowTuple {
                src_ip: IpAddr::V4(src_ip.parse().unwrap()),
                dst_ip: IpAddr::V4(dst_ip.parse().unwrap()),
                src_port: src_port.parse().unwrap(),
                dst_port: dst_port.parse().unwrap(),
                protocol: Protocol::Tcp,
            }),
            reply: None,
        };

        sock.del_conntrack(conntrack_flow)
            .expect("del_conntrack failed");

        let out = run_command!(
            "conntrack",
            "-G",
            "-p",
            "tcp",
            "--src",
            src_ip,
            "--dst",
            dst_ip,
            "--sport",
            src_port,
            "--dport",
            dst_port
        );
        assert!(
            !out.status.success(),
            "got deleted conntrack entry via conntrack-tools, i.e., deleting unsuccessful"
        );
    }
}
