use futures::stream::TryStreamExt;
use futures::StreamExt;
use libc;
use nix::sched;
use rtnetlink;
use rtnetlink::packet::constants::*;
use rtnetlink::packet::rtnl::link::nlas::Nla;
use rtnetlink::packet::NetlinkPayload;
use rtnetlink::packet::RouteMessage;
use std::fmt::Write;
use std::fs::File;
use std::io::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::prelude::*;
use std::process;
use std::thread;

pub struct CoreUtils {
    pub networkns: String,
}

impl CoreUtils {
    fn encode_address_to_hex(bytes: &[u8]) -> String {
        let mut final_slice = Vec::new();
        for &b in bytes {
            let mut a = String::with_capacity(bytes.len() * 2);
            write!(&mut a, "{:02x}", b).unwrap();
            final_slice.push(a);
        }
        final_slice.join(":")
    }

    #[tokio::main]
    pub async fn get_interface_address(link_name: &str) -> Result<String, std::io::Error> {
        let (_connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(_connection);

        let mut links = handle
            .link()
            .get()
            .set_name_filter(link_name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                for nla in link.nlas.into_iter() {
                    if let Nla::Address(ref addr) = nla {
                        return Ok(CoreUtils::encode_address_to_hex(addr));
                    }
                }

                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Unable to resolve physical address for interface {}",
                        link_name
                    ),
                ));
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Unable to resolve physical address for interface {}: {}",
                        link_name, err
                    ),
                ));
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Unable to resolve physical address for interface {}",
                        link_name
                    ),
                ))
            }
        }
    }
    async fn add_ip_address(
        handle: &rtnetlink::Handle,
        ifname: &str,
        ip: &ipnet::IpNet,
    ) -> Result<(), std::io::Error> {
        let mut links = handle
            .link()
            .get()
            .set_name_filter(ifname.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle
                    .address()
                    .add(link.header.index, ip.addr(), ip.prefix_len())
                    .execute()
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(rtnetlink::Error::NetlinkError(err)) => {
                        // the returned errno codes are negative
                        // ignore EEXIST error beccause the ip is already assigned
                        if -err.code == libc::EEXIST {
                            return Ok(());
                        };
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to set ip address to {}: {}", ifname, err),
                        ))
                    }
                    Err(err) => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to set ip address to {}: {}", ifname, err),
                    )),
                }
            }
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("interface {} not found", ifname),
            )),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to get interface {} up: {}", ifname, err),
            )),
        }
    }

    async fn add_route_v4(
        handle: &rtnetlink::Handle,
        dest: &ipnet::Ipv4Net,
        gateway: &Ipv4Addr,
    ) -> Result<(), std::io::Error> {
        let route = handle.route();
        let msg = route
            .add()
            .v4()
            .destination_prefix(dest.addr(), dest.prefix_len())
            .gateway(*gateway)
            .message_mut()
            .to_owned();

        CoreUtils::execute_route_msg(handle, msg).await
    }

    async fn add_route_v6(
        handle: &rtnetlink::Handle,
        dest: &ipnet::Ipv6Net,
        gateway: &Ipv6Addr,
    ) -> Result<(), std::io::Error> {
        let route = handle.route();
        let msg = route
            .add()
            .v6()
            .destination_prefix(dest.addr(), dest.prefix_len())
            .gateway(*gateway)
            .message_mut()
            .to_owned();

        CoreUtils::execute_route_msg(handle, msg).await
    }

    async fn execute_route_msg(
        handle: &rtnetlink::Handle,
        msg: RouteMessage,
    ) -> Result<(), std::io::Error> {
        // Note: we do not use .execute because we have to overwrite the request flags
        // by default NLM_F_EXCL is set and this throws an error if we try to create multiple default routes
        // We need to create a default route for each network because we need to keep the internet connectivity
        // after a podman disconnect via the other network.
        let mut req =
            rtnetlink::packet::NetlinkMessage::from(rtnetlink::packet::RtnlMessage::NewRoute(msg));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;

        let mut response = match handle.clone().request(req) {
            Ok(res) => res,
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to add route: {}", err),
                ));
            }
        };
        while let Some(message) = response.next().await {
            if let NetlinkPayload::Error(err) = message.payload {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to add route: {}", err),
                ));
            }
        }
        Ok(())
    }

    #[tokio::main]
    pub async fn remove_interface(ifname: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(connection);

        if let Err(err) = CoreUtils::remove_link(&handle, ifname).await {
            return Err(err);
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn turn_up_interface(ifname: &str) -> Result<(), Error> {
        let (connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(connection);

        if let Err(err) = CoreUtils::set_link_up(&handle, ifname).await {
            return Err(err);
        }

        Ok(())
    }

    async fn remove_link(handle: &rtnetlink::Handle, ifname: &str) -> Result<(), std::io::Error> {
        let mut links = handle
            .link()
            .get()
            .set_name_filter(ifname.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => match handle.link().del(link.header.index).execute().await {
                Ok(_) => Ok(()),
                Err(err) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to delete if {}: {}", ifname, err),
                )),
            },
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("link {} not found", ifname),
            )),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to get if {}: {}", ifname, err),
            )),
        }
    }

    async fn set_link_up(handle: &rtnetlink::Handle, ifname: &str) -> Result<(), std::io::Error> {
        let mut links = handle
            .link()
            .get()
            .set_name_filter(ifname.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => match handle.link().set(link.header.index).up().execute().await {
                Ok(_) => Ok(()),
                Err(err) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to set {} up: {}", ifname, err),
                )),
            },
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("interface {} not found", ifname),
            )),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to get veth interface {} up: {}", ifname, err),
            )),
        }
    }

    #[tokio::main]
    pub async fn configure_bridge_async(
        ifname: &str,
        ip_add: Vec<String>,
        ip_mask: Vec<String>,
    ) -> Result<(), Error> {
        let (_connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(_connection);

        // create if not exist
        let mut links = handle
            .link()
            .get()
            .set_name_filter(ifname.to_string())
            .execute();
        match links.try_next().await {
            // FIXME: Make sure this interface is a bridge, if not error.
            // I am unable to decipher how I can get get the link mode.
            Ok(Some(_)) => (),
            Ok(None) => {
                if let Err(err) = handle
                    .link()
                    .add()
                    .bridge(ifname.to_string())
                    .execute()
                    .await
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to create a bridge interface {}: {}", &ifname, err),
                    ));
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get bridge interface {}: {}", ifname, err),
                ))
            }
        }

        for (index_iter, mask) in ip_mask.into_iter().enumerate() {
            // add an ip address to the bridge interface
            match format!("{}/{}", ip_add[index_iter], mask).parse() {
                Ok(ip) => {
                    if let Err(err) = CoreUtils::add_ip_address(&handle, ifname, &ip).await {
                        return Err(err);
                    }
                }
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "failed to parse address {}: {}",
                            format!("{}/{}", ip_add[index_iter], mask),
                            err
                        ),
                    ))
                }
            }
        }

        // make the bridge interface up
        if let Err(err) = CoreUtils::set_link_up(&handle, ifname).await {
            return Err(err);
        }

        Ok(())
    }

    /* generates veth pair in configured namespace and moves other to namespace of the host_pid */
    /* for netavark this will be called inside container namespace. */
    #[tokio::main]
    async fn generate_veth_pair_internal(
        host_pid: u32,
        host_veth: &str,
        container_veth: &str,
    ) -> Result<(), std::io::Error> {
        /* Note: most likely this is called in a seperate thread so create a new connection, rather than
         * sharing from parent stack */
        /* Reason: rtnetlink handle does not implements copy so we cant share it across stack and
         * copying manually is more expesive than creating a new handle */
        let (_connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(_connection);

        // ip link add <eth> type veth peer name <ifname>
        if let Err(err) = handle
            .link()
            .add()
            .veth(host_veth.to_string(), container_veth.to_string())
            .execute()
            .await
        {
            if let rtnetlink::Error::NetlinkError(ref er) = err {
                if -er.code == libc::EEXIST {
                    // Note: Most likely network interface already exists on container namespace
                    // Add a hist
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "interface {} already exists on container namespace",
                            container_veth
                        ),
                    ));
                }
            }

            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "failed to create a pair of veth interfaces on container namespace: {}",
                    err
                ),
            ));
        }

        // ip link set <ifname> netns <namespace> up
        let mut links = handle
            .link()
            .get()
            .set_name_filter(host_veth.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle
                    .link()
                    .set(link.header.index)
                    .setns_by_pid(host_pid)
                    .execute()
                    .await
                {
                    Ok(_) => (),
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to set veth {} to host namespace: {}",
                                &container_veth, err
                            ),
                        ))
                    }
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("host veth interface {} not found", &container_veth),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get veth interface {}: {}", &container_veth, err),
                ))
            }
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn configure_veth_async(
        host_veth: &str,
        container_veth: &str,
        br_if: &str,
        netns_path: &str,
    ) -> Result<(), Error> {
        let (_connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };

        tokio::spawn(_connection);

        // get bridge interface index
        let mut links = handle
            .link()
            .get()
            .set_name_filter(br_if.to_string())
            .execute();
        let bridge_interface_index = match links.try_next().await {
            Ok(Some(link)) => link.header.index,
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("bridge interface {} not found", &br_if),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get bridge interface {}: {}", &br_if, err),
                ))
            }
        };

        //generate veth pair in container namespace and move host end back to hostnamespace
        match File::open(netns_path) {
            Ok(file) => {
                let netns_fd = file.as_raw_fd();
                let ctr_veth: String = container_veth.to_owned();
                let hst_veth: String = host_veth.to_owned();
                //we are going to use this pid to move back one end to host
                let netavark_pid: u32 = process::id();
                let thread_handle = thread::spawn(move || -> Result<(), Error> {
                    if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                        panic!(
                            "{}",
                            format!(
                                "failed to setns on container network namespace fd={}: {}",
                                netns_fd, err
                            )
                        )
                    }

                    if let Err(err) =
                        CoreUtils::generate_veth_pair_internal(netavark_pid, &hst_veth, &ctr_veth)
                    {
                        return Err(err);
                    }

                    Ok(())
                });
                if let Err(err) = thread_handle.join().unwrap() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("from container namespace: {:?}", err),
                    ));
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to open network namespace: {}", err),
                ))
            }
        }

        // ip link set <veth_name> master <bridge>
        let mut links = handle
            .link()
            .get()
            .set_name_filter(host_veth.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle
                    .link()
                    .set(link.header.index)
                    .master(bridge_interface_index)
                    .execute()
                    .await
                {
                    Ok(_) => (),
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to set veth interface {} to network bridge {}: {}",
                                host_veth, br_if, err
                            ),
                        ))
                    }
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("veth interface {} not found", host_veth),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get veth interface {}: {}", host_veth, err),
                ))
            }
        }

        // ip link set <eth> up
        if let Err(err) = CoreUtils::set_link_up(&handle, host_veth).await {
            return Err(err);
        }

        Ok(())
    }

    // block for async
    #[tokio::main]
    pub async fn configure_netns_interface_async(
        ifname: &str,
        ip_add: Vec<String>,
        ip_mask: Vec<String>,
        gw_ip_addrs: Vec<String>,
    ) -> Result<(), Error> {
        let (_connection, handle, _) = match rtnetlink::new_connection() {
            Ok((conn, handle, messages)) => (conn, handle, messages),
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to connect: {}", err),
                ))
            }
        };
        tokio::spawn(_connection);
        // ip netns exec ip link set <ifname> up
        if let Err(err) = CoreUtils::set_link_up(&handle, ifname).await {
            return Err(err);
        }

        // ip netns exec <namespace> ip addr add <addr>/<mask> dev <ifname>
        for (index_iter, addr) in ip_add.into_iter().enumerate() {
            match format!("{}/{}", addr, ip_mask[index_iter]).parse() {
                Ok(ip) => {
                    if let Err(err) = CoreUtils::add_ip_address(&handle, ifname, &ip).await {
                        return Err(err);
                    }
                }
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "failed to parse address {}: {}",
                            format!("{}/{}", addr, ip_mask[index_iter]),
                            err
                        ),
                    ))
                }
            }
        }

        // ip netns exec <namespace> ip route add default via <gateway> dev <ifname>
        for gw_ip_add in gw_ip_addrs {
            match gw_ip_add.to_string().parse() {
                Ok(gateway) => match gateway {
                    IpAddr::V4(gateway) => {
                        match ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0) {
                            Ok(dest) => {
                                if let Err(err) =
                                    CoreUtils::add_route_v4(&handle, &dest, &gateway).await
                                {
                                    return Err(err);
                                }
                            }
                            Err(err) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("failed to parse address 0.0.0.0/0: {}", err),
                                ))
                            }
                        }
                    }
                    IpAddr::V6(gateway) => {
                        match ipnet::Ipv6Net::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0) {
                            Ok(dest) => {
                                if let Err(err) =
                                    CoreUtils::add_route_v6(&handle, &dest, &gateway).await
                                {
                                    return Err(err);
                                }
                            }
                            Err(err) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!("failed to parse address ::/0: {}", err),
                                ))
                            }
                        }
                    }
                },
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("failed to parse address {}: {}", gw_ip_add, err),
                    ))
                }
            }
        }

        Ok(())
    }
}
