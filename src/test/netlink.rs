#[cfg(test)]
mod tests {
    use netavark::network::netlink::*;
    use netlink_packet_route::{address, nlas::link::InfoKind};

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
        assert!(Socket::new().is_ok(), "Netlink Socket::new() should work");
    }

    #[test]
    fn test_add_link() {
        test_setup!();
        let mut sock = Socket::new().expect("Socket::new()");

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
        let mut sock = Socket::new().expect("Socket::new()");

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
        let mut sock = Socket::new().expect("Socket::new()");

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
        eprintln!("{}", stdout);
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
        let mut sock = Socket::new().expect("Socket::new()");

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
        eprintln!("{}", stdout);
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
        eprintln!("{}", stdout);
        assert!(out.status.success(), "failed to show addr via ip");

        assert!(!stdout.contains(net), "route should not exist");
    }

    #[test]
    fn test_dump_addr() {
        test_setup!();
        let mut sock = Socket::new().expect("Socket::new()");

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

        let addresses = sock.dump_addresses().expect("dump_addresses failed");
        for nla in addresses[0].nlas.iter() {
            if let address::Nla::Address(a) = nla {
                assert_eq!(a, &vec![127, 0, 0, 1])
            }
        }
        for nla in addresses[1].nlas.iter() {
            if let address::Nla::Address(a) = nla {
                assert_eq!(a, &vec![10, 0, 0, 2])
            }
        }
    }
}
