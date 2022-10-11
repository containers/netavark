#[cfg(test)]
mod tests {
    use netavark::network::netlink::*;
    use netlink_packet_route::nlas::link::InfoKind;

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
}
