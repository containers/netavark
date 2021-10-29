use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use ipnetwork::Ipv4Network;
use ipnetwork::Ipv6Network;
use libc;
use rtnetlink;
use std::fs::File;
use std::io::Error;
use std::os::unix::prelude::*;

pub struct CoreUtils {
    pub networkns: String,
}

impl CoreUtils {
    async fn add_ip_address(
        handle: &rtnetlink::Handle,
        ifname: &str,
        ip: &IpNetwork,
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
                    .add(link.header.index, ip.ip(), ip.prefix())
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
        dest: &Ipv4Network,
        gateway: &Ipv4Network,
    ) -> Result<(), std::io::Error> {
        let route = handle.route();
        match route
            .add()
            .v4()
            .destination_prefix(dest.ip(), dest.prefix())
            .gateway(gateway.ip())
            .execute()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to add route: {}", err),
            )),
        }
    }

    async fn add_route_v6(
        handle: &rtnetlink::Handle,
        dest: &Ipv6Network,
        gateway: &Ipv6Network,
    ) -> Result<(), std::io::Error> {
        let route = handle.route();
        match route
            .add()
            .v6()
            .destination_prefix(dest.ip(), dest.prefix())
            .gateway(gateway.ip())
            .execute()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to add route: {}", err),
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

        // ip link add <eth> type veth peer name <ifname>
        if let Err(err) = handle
            .link()
            .add()
            .veth(host_veth.to_string(), container_veth.to_string())
            .execute()
            .await
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("failed to create a pair of veth interfaces: {}", err),
            ));
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

        // ip link set <ifname> netns <namespace> up
        match File::open(netns_path) {
            Ok(netns_file) => {
                let netns_fd = netns_file.as_raw_fd();
                let mut links = handle
                    .link()
                    .get()
                    .set_name_filter(container_veth.to_string())
                    .execute();
                match links.try_next().await {
                    Ok(Some(link)) => {
                        match handle
                            .link()
                            .set(link.header.index)
                            .setns_by_fd(netns_fd)
                            .execute()
                            .await
                        {
                            Ok(_) => (),
                            Err(err) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    format!(
                                        "failed to set veth {} to namespace: {}",
                                        &container_veth, err
                                    ),
                                ))
                            }
                        }
                    }
                    Ok(None) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("veth interface {} not found", &container_veth),
                        ))
                    }
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to get veth interface {}: {}", &container_veth, err),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to open namespace: {}", err),
                ))
            }
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
                    IpNetwork::V4(gateway) => match "0.0.0.0/0".to_string().parse() {
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
                    },
                    IpNetwork::V6(gateway) => match "::/0".to_string().parse() {
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
                    },
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
