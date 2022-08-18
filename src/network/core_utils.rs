use crate::error::{NetavarkError, NetavarkResult};
use crate::network::{constants, internal_types, types};
use futures::stream::TryStreamExt;
use futures::StreamExt;
use libc;
use log::debug;
use nix::sched;
use rand::Rng;
use rtnetlink;
use rtnetlink::packet::constants::*;
use rtnetlink::packet::rtnl::link::nlas::Nla;
use rtnetlink::packet::NetlinkPayload;
use rtnetlink::packet::RouteMessage;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::fmt::Display;
use std::io::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::prelude::*;
use std::process;
use std::str::FromStr;
use std::thread;
use sysctl::{Sysctl, SysctlError};

pub struct CoreUtils {
    pub networkns: String,
}

pub fn parse_option<T>(
    opts: &Option<HashMap<String, String>>,
    name: &str,
    default: T,
) -> NetavarkResult<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
    T: Default,
{
    let val = match opts.as_ref().and_then(|map| map.get(name)) {
        Some(val) => match val.parse::<T>() {
            Ok(mtu) => mtu,
            Err(err) => {
                return Err(NetavarkError::Message(format!(
                    "unable to parse \"{}\": {}",
                    name, err
                )));
            }
        },
        // if no option is set return the default value
        None => default,
    };
    Ok(val)
}

pub fn get_ipam_addresses<'a>(
    per_network_opts: &'a types::PerNetworkOptions,
    network: &'a types::Network,
) -> Result<internal_types::IPAMAddresses, std::io::Error> {
    let addresses = match network
        .ipam_options
        .as_ref()
        .and_then(|map| map.get("driver").cloned())
        .as_deref()
    {
        // when option is none default to host local
        Some(constants::IPAM_HOSTLOCAL) | None => {
            // static ip vector
            let mut container_addresses = Vec::new();
            // gateway ip vector
            let mut gateway_addresses = Vec::new();
            // network addresses for response
            let mut net_addresses: Vec<types::NetAddress> = Vec::new();
            // bool for ipv6
            let mut ipv6_enabled = false;

            // nameservers which can be configured for this container
            let mut nameservers: Vec<IpAddr> = Vec::new();

            let static_ips = match per_network_opts.static_ips.as_ref() {
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "no static ips provided",
                    ))
                }
                Some(i) => i,
            };

            // prepare a vector of static aps with appropriate cidr
            for (idx, subnet) in network.subnets.iter().flatten().enumerate() {
                let subnet_mask_cidr = subnet.subnet.prefix_len();
                if let Some(gw) = subnet.gateway {
                    let gw_net = match ipnet::IpNet::new(gw, subnet_mask_cidr) {
                        Ok(dest) => dest,
                        Err(err) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "failed to parse address {}/{}: {}",
                                    gw, subnet_mask_cidr, err
                                ),
                            ))
                        }
                    };
                    gateway_addresses.push(gw_net);
                    nameservers.push(gw);
                }

                // for dual-stack network.ipv6_enabled could be false do explicit check
                if subnet.subnet.addr().is_ipv6() {
                    ipv6_enabled = true;
                }

                // Build up response information
                let container_address: ipnet::IpNet =
                    match format!("{}/{}", static_ips[idx], subnet_mask_cidr).parse() {
                        Ok(i) => i,
                        Err(e) => {
                            return Err(Error::new(std::io::ErrorKind::Other, e));
                        }
                    };
                // Add the IP to the address_vector
                container_addresses.push(container_address);
                net_addresses.push(types::NetAddress {
                    gateway: subnet.gateway,
                    ipnet: container_address,
                });
            }
            internal_types::IPAMAddresses {
                container_addresses,
                gateway_addresses,
                net_addresses,
                nameservers,
                ipv6_enabled,
            }
        }
        Some(constants::IPAM_NONE) => {
            // no ipam just return empty vectors
            internal_types::IPAMAddresses {
                container_addresses: vec![],
                gateway_addresses: vec![],
                net_addresses: vec![],
                nameservers: vec![],
                ipv6_enabled: false,
            }
        }
        Some(constants::IPAM_DHCP) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "dhcp ipam driver is not yet supported",
            ));
        }
        Some(driver) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unsupported ipam driver {}", driver),
            ));
        }
    };

    Ok(addresses)
}

impl CoreUtils {
    fn encode_address_to_hex(bytes: &[u8]) -> String {
        let address: String = bytes
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(":");

        address
    }

    pub fn decode_address_from_hex(input: &str) -> Result<Vec<u8>, std::io::Error> {
        let bytes: Result<Vec<u8>, _> = input
            .split(|c| c == ':' || c == '-')
            .into_iter()
            .map(|b| u8::from_str_radix(b, 16))
            .collect();

        let result = match bytes {
            Ok(bytes) => {
                if bytes.len() != 6 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid mac length for address: {}", input),
                    ));
                }
                bytes
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to parse mac address {}: {}", input, e),
                ));
            }
        };

        Ok(result)
    }

    pub fn get_macvlan_mode_from_string(mode: &str) -> Result<u32, std::io::Error> {
        // Replace to constant from library once this gets merged.
        // TODO: use actual constants after https://github.com/little-dude/netlink/pull/200
        match mode {
            "" | "bridge" => Ok(constants::MACVLAN_MODE_BRIDGE),
            "private" => Ok(constants::MACVLAN_MODE_PRIVATE),
            "vepa" => Ok(constants::MACVLAN_MODE_VEPA),
            "passthru" => Ok(constants::MACVLAN_MODE_PASSTHRU),
            "source" => Ok(constants::MACVLAN_MODE_SOURCE),
            // default to bridge
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid macvlan mode",
            )),
        }
    }

    #[tokio::main]
    pub async fn get_default_route_interface() -> Result<String, std::io::Error> {
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

        let mut routes = handle.route().get(rtnetlink::IpVersion::V4).execute();
        loop {
            match routes.try_next().await {
                Ok(Some(route)) => {
                    for nla in route.nlas.into_iter() {
                        if let netlink_packet_route::route::Nla::Oif(interface_id) = nla {
                            let mut links = handle.link().get().match_index(interface_id).execute();
                            match links.try_next().await {
                                Ok(Some(msg)) => {
                                    for nla in msg.nlas.into_iter() {
                                        if let Nla::IfName(name) = nla {
                                            return Ok(name);
                                        }
                                    }
                                }
                                Err(_) => continue,
                                Ok(None) => continue,
                            };
                        }
                    }
                }
                Err(_) => continue,
                Ok(None) => break,
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no interfaces found for default route".to_string(),
        ))
    }

    //count interfaces on bridge
    #[tokio::main]
    #[allow(irrefutable_let_patterns)]
    pub async fn bridge_count_connected_interfaces(
        ifname: &str,
    ) -> Result<Vec<u32>, std::io::Error> {
        let mut connected_veth: Vec<u32> = Vec::new();
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

        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        let master_index: u32 = match links.try_next().await {
            Ok(Some(msg)) => msg.header.index,
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Unable to resolve bridge interface {}: interface not found",
                        ifname
                    ),
                ));
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unable to resolve bridge interface {}: {}", ifname, err),
                ));
            }
        };

        let mut links = handle
            .link()
            .get()
            .set_filter_mask(AF_BRIDGE as u8, RTEXT_FILTER_BRVLAN)
            .execute();
        while let msg = links.try_next().await {
            match msg {
                Ok(Some(msg)) => {
                    // do not count the bridge itself
                    if msg.header.index == master_index {
                        continue;
                    }
                    for nla in msg.nlas.into_iter() {
                        if let Nla::Master(data) = nla {
                            if data == master_index {
                                connected_veth.push(msg.header.index);
                            }
                            continue;
                        }
                    }
                }
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "failed while querying interfaces connected to bridge: {}",
                            err
                        ),
                    ));
                }
                _ => {
                    break;
                }
            }
        }
        debug!("bridge has {} connected interfaces", connected_veth.len());

        Ok(connected_veth)
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
            .match_name(link_name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                for nla in link.nlas.into_iter() {
                    if let Nla::Address(ref addr) = nla {
                        return Ok(CoreUtils::encode_address_to_hex(addr));
                    }
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Unable to resolve physical address for interface {}",
                        link_name
                    ),
                ))
            }
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Unable to resolve physical address for interface {}: {}",
                    link_name, err
                ),
            )),
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Unable to resolve physical address for interface {}",
                    link_name
                ),
            )),
        }
    }
    async fn add_ip_address(
        handle: &rtnetlink::Handle,
        ifname: &str,
        ip: &ipnet::IpNet,
    ) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
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
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
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
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
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

    async fn set_link_mtu(
        handle: &rtnetlink::Handle,
        ifname: &str,
        mtu: u32,
    ) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => match handle
                .link()
                .set(link.header.index)
                .mtu(mtu)
                .execute()
                .await
            {
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

    async fn set_link_mac(
        handle: &rtnetlink::Handle,
        ifname: &str,
        mac: Vec<u8>,
    ) -> Result<(), std::io::Error> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        match links.try_next().await {
            Ok(Some(link)) => match handle
                .link()
                .set(link.header.index)
                .address(mac)
                .execute()
                .await
            {
                Ok(_) => Ok(()),
                Err(err) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to set mac address for {} : {}", ifname, err),
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

    /* renames macvlan interface inside configured namespace and turns up the interface*/
    /* for netavark this will be called inside container namespace. */
    #[tokio::main]
    async fn rename_macvlan_internal(
        macvlan_tmp_ifname: &str,
        macvlan_ifname: &str,
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
        let mut links = handle
            .link()
            .get()
            .match_name(macvlan_tmp_ifname.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle
                    .link()
                    .set(link.header.index)
                    .name(macvlan_ifname.to_string())
                    .execute()
                    .await
                {
                    Ok(_) => (),
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to rename macvlan {} to {}: {}",
                                &macvlan_tmp_ifname, &macvlan_ifname, err
                            ),
                        ))
                    }
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("macvlan interface {} not found", &macvlan_tmp_ifname),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get interface {}: {}", &macvlan_tmp_ifname, err),
                ))
            }
        }

        // NOTE: I dont think we need to turn up the interface cause its already up.
        // But turn up macvlan interface up again if its needed. Although i doubt.

        Ok(())
    }

    /* generates macvlan and links with master interface link on the most */
    /* moves macvlan to given network namespaces */
    /* master interface must be up*/
    /* by default macvlan mode is bridge*/
    #[tokio::main]
    pub async fn configure_macvlan_async(
        master_ifname: &str,
        macvlan_ifname: &str,
        macvlan_mode: u32,
        mtu: u32,
        netns: RawFd,
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

        //generate a random name on host to prevent collision.
        //check https://github.com/containernetworking/plugins/blob/master/plugins/main/macvlan/macvlan.go#L176
        let macvlan_tmp_name = format!("macvlan{:x}", rand::thread_rng().gen::<u32>());

        let mut links = handle
            .link()
            .get()
            .match_name(master_ifname.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                if let Err(err) = handle
                    .link()
                    .add()
                    .macvlan(macvlan_tmp_name.to_owned(), link.header.index, macvlan_mode)
                    .execute()
                    .await
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "failed to create a macvlan interface {}: {}",
                            &macvlan_tmp_name, err
                        ),
                    ));
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("master interface {} not found", &master_ifname),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get interface {}: {}", &master_ifname, err),
                ))
            }
        }

        // configure mtu of macvlan interface
        // before moving it to network namespace
        // See: https://github.com/containernetworking/plugins/blob/master/plugins/main/macvlan/macvlan.go#L181
        if mtu != 0 {
            if let Err(err) =
                CoreUtils::set_link_mtu(&handle, &macvlan_tmp_name.to_owned(), mtu).await
            {
                return Err(err);
            }
        }

        // change network namespace of macvlan interface
        let mut links = handle
            .link()
            .get()
            .match_name(macvlan_tmp_name.to_string())
            .execute();
        match links.try_next().await {
            Ok(Some(link)) => {
                match handle
                    .link()
                    .set(link.header.index)
                    .setns_by_fd(netns)
                    .execute()
                    .await
                {
                    Ok(_) => (),
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "failed to set macvlan {} to netns: {}",
                                &macvlan_tmp_name, err
                            ),
                        ))
                    }
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("macvlan interface {} not found", &macvlan_tmp_name),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get interface {}: {}", &macvlan_tmp_name, err),
                ))
            }
        }

        let macvlan_tmp_ifname: String = macvlan_tmp_name.to_owned();
        let macvlan_ifname_clone: String = macvlan_ifname.to_owned();
        // we have to also swtich to network namespace. rename macvlan interface and turn
        // up interface
        let thread_handle = thread::spawn(move || -> Result<(), Error> {
            if let Err(err) = sched::setns(netns, sched::CloneFlags::CLONE_NEWNET) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "failed to setns on container network namespace fd={}: {}",
                        netns, err
                    ),
                ));
            }

            if let Err(err) =
                CoreUtils::rename_macvlan_internal(&macvlan_tmp_ifname, &macvlan_ifname_clone)
            {
                return Err(err);
            }

            Ok(())
        });
        match thread_handle.join() {
            Ok(_) => {}
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("from container namespace: {:?}", err),
                ));
            }
        }

        Ok(())
    }

    #[tokio::main]
    pub async fn configure_bridge_async(
        ifname: &str,
        ips: &[ipnet::IpNet],
        mtu: u32,
        ipv6_enabled: bool,
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
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        match links.try_next().await {
            // FIXME: Make sure this interface is a bridge, if not error.
            // I am unable to decipher how I can get get the link mode.
            Ok(Some(_)) => (),
            Err(rtnetlink::Error::NetlinkError(er)) if -er.code == libc::ENODEV => {
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

                if ipv6_enabled {
                    // Disable duplicate address detection if ipv6 enabled
                    // Do not accept Router Advertisements if ipv6 is enabled
                    let br_accept_dad = format!("/proc/sys/net/ipv6/conf/{}/accept_dad", ifname);
                    let br_accept_ra = format!("net/ipv6/conf/{}/accept_ra", ifname);
                    if let Err(e) = CoreUtils::apply_sysctl_value(&br_accept_dad, "0") {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("{}", e),
                        ));
                    }
                    if let Err(e) = CoreUtils::apply_sysctl_value(&br_accept_ra, "0") {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("{}", e),
                        ));
                    }
                }
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "failed to get bridge interface {}: empty netlink response",
                        ifname
                    ),
                ))
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to get bridge interface {}: {}", ifname, err),
                ))
            }
        }
        if ipv6_enabled {
            // Do not accept Router Advertisements if ipv6 is enabled
            match CoreUtils::apply_sysctl_value(format!("net/ipv6/conf/{}/accept_ra", ifname), "0")
            {
                Ok(_) => {}
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", err),
                    ))
                }
            }
        }
        for ip_net in ips.iter() {
            if let Err(err) = CoreUtils::add_ip_address(&handle, ifname, ip_net).await {
                return Err(err);
            }
        }

        if mtu != 0 {
            if let Err(err) = CoreUtils::set_link_mtu(&handle, ifname, mtu).await {
                return Err(err);
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
        mtu: u32,
        ipv6_enabled: bool,
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
            .veth(container_veth.to_string(), host_veth.to_string())
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

        // set mtu for container and host veth
        if mtu != 0 {
            if let Err(err) = CoreUtils::set_link_mtu(&handle, host_veth, mtu).await {
                return Err(err);
            }
            if let Err(err) = CoreUtils::set_link_mtu(&handle, container_veth, mtu).await {
                return Err(err);
            }
        }

        if ipv6_enabled {
            //  Disable dad inside the container too
            let disable_dad_in_container =
                format!("/proc/sys/net/ipv6/conf/{}/accept_dad", container_veth);
            if let Err(e) = CoreUtils::apply_sysctl_value(&disable_dad_in_container, "0") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{}", e),
                ));
            }
        }

        // ip link set <ifname> netns <namespace> up
        let mut links = handle
            .link()
            .get()
            .match_name(host_veth.to_string())
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
        netns_fd: RawFd,
        mtu: u32,
        ipv6_enabled: bool,
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
        let mut links = handle.link().get().match_name(br_if.to_string()).execute();
        let bridge_interface_index = match links.try_next().await {
            Ok(Some(link)) => link.header.index,
            Err(rtnetlink::Error::NetlinkError(er)) if -er.code == libc::ENODEV => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("bridge interface {} not found", &br_if),
                ))
            }
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
        let ctr_veth: String = container_veth.to_owned();
        let hst_veth: String = host_veth.to_owned();
        //we are going to use this pid to move back one end to host
        let netavark_pid: u32 = process::id();
        let thread_handle = thread::spawn(move || -> Result<(), Error> {
            if let Err(err) = sched::setns(netns_fd, sched::CloneFlags::CLONE_NEWNET) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "failed to setns on container network namespace fd={}: {}",
                        netns_fd, err
                    ),
                ));
            }

            if let Err(err) = CoreUtils::generate_veth_pair_internal(
                netavark_pid,
                &hst_veth,
                &ctr_veth,
                mtu,
                ipv6_enabled,
            ) {
                return Err(err);
            }

            Ok(())
        });
        match thread_handle.join() {
            Ok(ok) => {
                // read the result from the thread
                match ok {
                    Ok(_) => {}
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("from network namespace: {}", err),
                        ));
                    }
                }
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("error waiting for thread: {:?}", err),
                ));
            }
        }

        if ipv6_enabled {
            // Disable duplicate address detection on host veth if ipv6 enabled
            let k = format!("/proc/sys/net/ipv6/conf/{}/accept_dad", &host_veth);
            match CoreUtils::apply_sysctl_value(&k, "0") {
                Ok(_) => {}
                Err(err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{}", err),
                    ))
                }
            }
        }
        // ip link set <veth_name> master <bridge>
        let mut links = handle
            .link()
            .get()
            .match_name(host_veth.to_string())
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
        ips: Vec<ipnet::IpNet>,
        gw_ip_addrs: &Vec<ipnet::IpNet>,
        static_mac: Option<Vec<u8>>,
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
        for ip_net in ips.into_iter() {
            if let Err(err) = CoreUtils::add_ip_address(&handle, ifname, &ip_net).await {
                return Err(err);
            }
        }

        // set static mac here
        match static_mac {
            Some(mac) => {
                if let Err(err) = CoreUtils::set_link_mac(&handle, ifname, mac).await {
                    return Err(err);
                }
            }
            None => {}
        };

        // ip netns exec <namespace> ip route add default via <gateway> dev <ifname>
        for gw_ip_add in gw_ip_addrs {
            match gw_ip_add.addr() {
                IpAddr::V4(gateway) => match ipnet::Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0) {
                    Ok(dest) => {
                        if let Err(err) = CoreUtils::add_route_v4(&handle, &dest, &gateway).await {
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
            }
        }

        Ok(())
    }

    pub fn create_network_hash(network_name: &str, length: usize) -> String {
        let mut hasher = Sha512::new();
        hasher.update(network_name.as_bytes());
        let result = hasher.finalize();
        let hash_string = format!("{:X}", result);
        let response = &hash_string[0..length];
        response.to_string()
    }

    /// Set a sysctl value by value's namespace.
    pub fn apply_sysctl_value(
        ns_value: impl AsRef<str>,
        val: impl AsRef<str>,
    ) -> Result<String, SysctlError> {
        let ns_value = ns_value.as_ref();
        let val = val.as_ref();
        debug!("Setting sysctl value for {} to {}", ns_value, val);
        let ctl = sysctl::Ctl::new(ns_value)?;
        match ctl.value_string() {
            Ok(result) => {
                if result == val {
                    return Ok(result);
                }
            }
            Err(e) => return Err(e),
        }
        ctl.set_value_string(val)
    }
}
