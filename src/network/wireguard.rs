use std::net::ToSocketAddrs;
use std::{collections::HashMap, convert::TryInto, net::IpAddr, os::unix::prelude::RawFd};
use std::{net, vec};

use base64::decode;
use ipnet::IpNet;
use log::debug;
use netlink_packet_route::nlas::link::InfoKind;
use netlink_packet_wireguard::constants::{AF_INET, AF_INET6};
use netlink_packet_wireguard::nlas::{
    WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs,
};

use crate::network::netlink::Route;
use crate::network::types::NetInterface;
use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkResult},
};

use super::{
    constants::NO_CONTAINER_INTERFACE_ERROR,
    core_utils,
    driver::{self, DriverInfo},
    netlink::{self, CreateLinkOptions},
    types::StatusBlock,
};

// TODO_WG: Document the option
const CONFIG_OPTION: &str = "config";

#[derive(Debug)]
struct Peer {
    /// IPs that will be forwarded to the Peer
    /// and from which traffic is accepted
    allowed_ips: Vec<IpNet>,
    /// Seconds between Handshakes sent to peer
    /// in order to keep the connection alive
    /// Optional
    persistent_keepalive: Option<u16>,
    /// Peers public key to verify traffic during crypto routing
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<net::SocketAddr>,
}

#[derive(Debug)]
struct InternalData {
    /// WireGuard interface name
    interface_name: String,
    /// addresses of the WireGuard interface
    addresses: Vec<IpNet>,
    ///
    private_key: [u8; 32],
    /// mtu for the network interface (0 if default)
    mtu: u16,
    /// WireGuard peers
    peers: Vec<Peer>,
    /// Listening Port
    /// Optional
    port: Option<u16>,
}

pub struct WireGuard<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> WireGuard<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        WireGuard { info, data: None }
    }
}

impl driver::NetworkDriver for WireGuard<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg(NO_CONTAINER_INTERFACE_ERROR));
        }

        let options = match &self.info.per_network_opts.options {
            Some(options) => options,
            None => {
                return Err(NetavarkError::msg(
                    "no options specified for WireGuard driver",
                ))
            }
        };

        let config_path = match options.get(CONFIG_OPTION) {
            Some(path) => path,
            None => {
                return Err(NetavarkError::msg(
                    "no path to WireGuard config file specified",
                ))
            }
        };

        let data = match parse_config(
            config_path,
            self.info.per_network_opts.interface_name.clone(),
        ) {
            Ok(data) => data,
            Err(e) => {
                return Err(NetavarkError::msg(format!(
                    "when parsing WireGuard config: {:?}",
                    e
                )))
            }
        };

        // Peer Validation
        for (index, peer) in data.peers.iter().enumerate() {
            if peer.public_key == [0; 32] {
                return Err(NetavarkError::msg(format!(
                    "invalid WireGuard configuration: Peer #{:?} is missing a PublicKey",
                    index
                )));
            }
            if peer.allowed_ips.is_empty() {
                return Err(NetavarkError::msg(format!(
                    "invalid WireGuard configuration: Peer #{:?} is missing AllowedIPs",
                    index
                )));
            }
        }

        // Interface Validation
        // will succeed if the interface has an Address and a PrivateKey
        if data.private_key == [0; 32] {
            return Err(NetavarkError::msg(
                "invalid WireGuard configuration: Interface is missing a PrivateKey".to_string(),
            ));
        }
        if data.addresses.is_empty() {
            return Err(NetavarkError::msg(
                "invalid WireGuard configuration: Interface is missing an Address".to_string(),
            ));
        }
        self.data = Some(data);

        Ok(())
    }

    fn setup(
        &self,
        netlink_sockets: (&mut netlink::LinkSocket, &mut netlink::LinkSocket),
    ) -> Result<(StatusBlock, Option<AardvarkEntry>), NetavarkError> {
        let (mut generic_host_sock, mut generic_netns_sock) =
            match core_utils::open_generic_netlink_sockets_from_fd(
                self.info.netns_host,
                self.info.netns_container,
            ) {
                Ok(tuple) => tuple,
                Err(e) => return Err(e),
            };

        let data = match &self.data {
            Some(d) => d,
            None => return Err(NetavarkError::msg("must call validate() before setup()")),
        };

        debug!("Setup network {}", self.info.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            self.info.per_network_opts.interface_name, data.addresses
        );

        let (host_sock, netns_sock) = netlink_sockets;

        let interface = create_wireguard_interface(
            (host_sock, &mut generic_host_sock),
            (netns_sock, &mut generic_netns_sock),
            data,
            self.info.netns_host,
            self.info.netns_container,
        )?;
        let mut interfaces: HashMap<String, NetInterface> = HashMap::new();
        interfaces.insert(
            interface,
            NetInterface {
                mac_address: "".to_string(),
                subnets: None,
            },
        );

        let response = StatusBlock {
            dns_server_ips: None,
            dns_search_domains: None,
            interfaces: Some(interfaces),
        };
        Ok((response, None))
    }

    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::LinkSocket, &mut netlink::LinkSocket),
    ) -> NetavarkResult<()> {
        netlink_sockets.1.del_link(netlink::LinkID::Name(
            self.info.per_network_opts.interface_name.to_string(),
        ))?;
        Ok(())
    }
}

fn create_wireguard_interface(
    host: (&mut netlink::LinkSocket, &mut netlink::GenericSocket),
    netns: (&mut netlink::LinkSocket, &mut netlink::GenericSocket),
    data: &InternalData,
    hostns_fd: RawFd,
    netns_fd: RawFd,
) -> NetavarkResult<String> {
    let (host_link_socket, _host_generic_socket) = host;
    let (netns_link_socket, netns_generic_socket) = netns;

    let mut create_link_opts =
        CreateLinkOptions::new(data.interface_name.to_string(), InfoKind::Wireguard);
    create_link_opts.mtu = data.mtu as u32;

    debug!(
        "Creating WireGuard interface {}",
        data.interface_name.to_string()
    );

    host_link_socket
        .create_link(create_link_opts)
        .wrap("create WireGuard interface: {}")?;

    let link = host_link_socket
        .get_link(netlink::LinkID::Name(data.interface_name.to_string()))
        .wrap("get WireGuard interface")?;

    debug!(
        "Moving WireGuard interface {} from namespace {} to container namespace {}",
        data.interface_name.to_string(),
        hostns_fd,
        netns_fd
    );
    host_link_socket
        .set_link_ns(link.header.index, netns_fd)
        .wrap("moving WireGuard interface to container network namespace")?;

    debug!(
        "Adding Addresses to WireGuard interface {}",
        data.interface_name.to_string()
    );

    for addr in &data.addresses {
        netns_link_socket
            .add_addr(link.header.index, addr)
            .wrap("add ip addr to WireGuard interface")?;
    }

    let nlas = generate_wireguard_device_nlas(data);

    debug!(
        "Setting up WireGuard interface {}",
        data.interface_name.to_string()
    );
    netns_generic_socket
        .set_wireguard_device(nlas)
        .wrap("add WireGuard interface settings")?;

    if !data.peers.is_empty() {
        debug!(
            "Adding Peers to WireGuard interface {}",
            data.interface_name.to_string()
        );

        for peer in data.peers[..].iter() {
            let nlas = generate_peer_nlas_for_wireguard_device(peer, data.interface_name.clone());
            netns_generic_socket
                .set_wireguard_device(nlas)
                .wrap("add Peer {:?} to WireGuard interface")?;
        }
    }

    debug!(
        "Activating WireGuard interface {}",
        data.interface_name.to_string(),
    );

    netns_link_socket
        .set_up(netlink::LinkID::Name(data.interface_name.to_string()))
        .wrap("set WireGuard interface up")?;

    for peer in data.peers[..].iter() {
        let routes = generate_routes_for_peer(&data.addresses, &peer.allowed_ips);
        for route in routes {
            netns_link_socket.add_route(&route)?;
        }
    }

    Ok(data.interface_name.clone())
}

fn parse_config(path: &String, interface_name: String) -> Result<InternalData, String> {
    // Get configuration data from file
    let config_data = match std::fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) => return Err(format!("problem reading WireGuard config: {:?}", e)),
    };

    // Setup line based parsing
    // with empty data structures to store into
    //
    // Only Peer and Interface sections exists
    // [Interface] can only be specified once and subsequent definitions
    // will overwrite previously stored data
    //
    // If a [Peer] section is encountered a new Peer is added
    let lines = config_data.lines();
    let mut peers: Vec<Peer> = vec![];
    let mut interface = InternalData {
        interface_name: "".to_string(),
        addresses: vec![],
        private_key: [0x00; 32],
        mtu: 1420,
        peers: vec![],
        port: None,
    };
    let mut interface_section = false;
    let mut peer_section = false;

    for (index, line) in lines.into_iter().enumerate() {
        if line.trim_start() == "" || line.trim_start().chars().next().unwrap().to_string() == "#" {
            continue;
        }
        if line == "[Interface]" {
            interface_section = true;
            peer_section = false;
            continue;
        }
        if line == "[Peer]" {
            interface_section = false;
            peer_section = true;
            // Add a new peer to the peers array
            // which will be used to store information
            // from lines that will be parsed next
            peers.push(Peer {
                allowed_ips: vec![],
                persistent_keepalive: None,
                public_key: [0; 32],
                preshared_key: None,
                endpoint: None,
            });
            continue;
        }
        // splitting once gives key and value.
        // Using any other split can conflict with the base64 encoded keys
        let (key, value) = match line.split_once('=') {
            Some(tuple) => {
                let key: String = tuple.0.split_whitespace().collect();
                let value: String = tuple.1.split_whitespace().collect();
                (key, value)
            }
            None => {
                return Err(format!(
                    "when parsing WireGuard configuration {} on line: {}.",
                    line, index
                ))
            }
        };
        if !key.is_empty() && value.is_empty() && value.is_empty() {
            return Err(format!(
                "when parsing WireGuard configuration {} on line {}.  No value provided.",
                key, index
            ));
        }
        if interface_section {
            match key.as_str() {
                "Address" => {
                    let ip_with_cidr = add_cidr_to_ip_addr_if_missing(value.clone());
                    let ip: IpNet = match ip_with_cidr.parse() {
                        Ok(ip) => ip,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard interface address: {:?}",
                                e, value
                            ))
                        }
                    };
                    interface.addresses.push(ip)
                }
                "ListenPort" => {
                    let port = match value.parse::<u16>() {
                        Ok(port) => port,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard interface port: {:?}",
                                e, value
                            ));
                        }
                    };
                    interface.port = Some(port);
                }
                "PrivateKey" => {
                    interface.private_key = match decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => key,
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PrivateKey: {:?}. Is it 32 bytes?",
                                    e, value
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PrivateKey: {:?}",
                                e, value
                            ))
                        }
                    }
                }
                _ => {
                    debug!(
                        "Ignoring key `{}` in WireGuard interface configuration",
                        key
                    );
                }
            }
        }
        if peer_section {
            let current_peer_index = peers.len() - 1;
            let current_peer = &mut peers[current_peer_index];
            match key.as_str() {
                "AllowedIPs" => {
                    let ips = value.split(',');
                    for ip in ips {
                        let ip_with_cidr = add_cidr_to_ip_addr_if_missing(ip.to_string());
                        let ip: IpNet = match ip_with_cidr.parse() {
                            Ok(ip) => ip,
                            Err(e) => {
                                    return Err(format!(
                                        "{:?} when parsing WireGuard peers AllowedIPs: {:?}. Occurs in {:?}",
                                        e, value, ip
                                    ))
                            }
                        };
                        current_peer.allowed_ips.push(ip);
                    }
                }
                "Endpoint" => {
                    current_peer.endpoint = match parse_endpoint(value.clone()) {
                        Ok(endpoint) => endpoint,
                        Err(e) => {
                            return Err(format!(
                                "when trying to parse Endpoint {} for peer {}: {:?}",
                                value, current_peer_index, e
                            ))
                        }
                    }
                }
                "PublicKey" => {
                    current_peer.public_key = match decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => key,
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PublicKey: {:?} for peer {:?}. Is it 32 bytes?",
                                    e, value, current_peer_index
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PublicKey: {:?} for peer {:?}",
                            e, value, current_peer_index
                            ))
                        }
                    }
                }
                "PresharedKey" => {
                    current_peer.preshared_key = match decode(value.clone()) {
                        Ok(key) => match key.try_into() {
                            Ok(key) => Some(key),
                            Err(e) => {
                                return Err(format!(
                                    "{:?} when decoding base64 PresharedKey: {:?} for peer {:?}. Is it 32 bytes?",
                                    e, value, current_peer_index
                                ))
                            }
                        },
                        Err(e) => {
                            return Err(format!(
                                "{:?} when decoding base64 PresharedKey: {:?} for peer {:?}",
                            e, value, current_peer_index
                            ))
                        }
                    }
                }
                "PersistentKeepalive" => {
                    let keepalive = match value.parse::<u16>() {
                        Ok(keepalive) => keepalive,
                        Err(e) => {
                            return Err(format!(
                                "{:?} when parsing WireGuard peers PersistentKeepalive value: {:?}",
                                e, value
                            ));
                        }
                    };
                    current_peer.persistent_keepalive = Some(keepalive);
                }
                _ => {
                    debug!("Ignoring key `{}` in WireGuard peer configuration", key);
                }
            }
        }
    }

    interface.interface_name = interface_name;
    interface.peers = peers;

    Ok(interface)
}

fn add_cidr_to_ip_addr_if_missing(addr: String) -> String {
    let mut ip4_cidr = "/32".to_string();
    let mut ip6_cidr = "/128".to_string();
    match addr.split_once('/') {
        Some(_) => addr, // CIDR was defined, nothing to do
        None => {
            // default to a host CIDR
            if addr.contains(':') {
                ip6_cidr.insert_str(0, &addr);

                ip6_cidr
            } else {
                ip4_cidr.insert_str(0, &addr);

                ip4_cidr
            }
        }
    }
}

fn parse_endpoint(addr: String) -> Result<Option<net::SocketAddr>, String> {
    let (endpoint_addr, endpoint_port) = match addr.split_once(':') {
        Some(tuple) => tuple,
        None => return Err("incomplete Endpoint address".to_string()),
    };
    let port: u16 = match endpoint_port.parse() {
        Ok(ip) => ip,
        Err(e) => return Err(format!("incorrect port: {}", e)),
    };

    let ip: IpAddr = match endpoint_addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            // we might have gotten a hostname in the config
            // try this next
            match addr.to_socket_addrs() {
                Ok(mut addr) => match addr.next() {
                    Some(addr) => addr.ip(),
                    None => {
                        return Err(format!("could not parse {:?}", addr));
                    }
                },
                Err(_) => {
                    return Err(format!("could not parse {:?}", addr));
                }
            }
        }
    };

    Ok(Some(net::SocketAddr::new(ip, port)))
}

fn generate_wireguard_device_nlas(data: &InternalData) -> Vec<WgDeviceAttrs> {
    let mut nlas = vec![
        WgDeviceAttrs::IfName(data.interface_name.to_string()),
        WgDeviceAttrs::PrivateKey(data.private_key),
    ];

    if let Some(port) = data.port {
        nlas.push(WgDeviceAttrs::ListenPort(port))
    }
    nlas
}

// This has to be allowed since Clippy's suggestion seems
// off
// 609 ~     let mut wg_peer = WgPeer(<[_]>::into_vec(
// 610 +             #[rustc_box]
// 611 +             $crate::boxed::Box::new([$($x),+])
// 612 ~         ));

#[allow(clippy::init_numbered_fields)]
fn generate_peer_nlas_for_wireguard_device(
    peer: &Peer,
    interface_name: String,
) -> Vec<WgDeviceAttrs> {
    let mut allowed_ip_nla = vec![];
    for ip in peer.allowed_ips[..].iter() {
        let mut family: u16 = AF_INET;

        match ip {
            IpNet::V4(_) => (),
            IpNet::V6(_) => family = AF_INET6,
        }
        allowed_ip_nla.push(WgAllowedIp {
            0: vec![
                WgAllowedIpAttrs::IpAddr(ip.network()),
                WgAllowedIpAttrs::Cidr(ip.prefix_len()),
                WgAllowedIpAttrs::Family(family),
            ],
        });
    }
    let mut wg_peer = WgPeer {
        0: vec![
            WgPeerAttrs::PublicKey(peer.public_key),
            WgPeerAttrs::AllowedIps(allowed_ip_nla),
        ],
    };
    if let Some(key) = peer.preshared_key {
        wg_peer.0.push(WgPeerAttrs::PresharedKey(key))
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        wg_peer.0.push(WgPeerAttrs::PersistentKeepalive(keepalive))
    }
    if let Some(endpoint) = peer.endpoint {
        wg_peer.0.push(WgPeerAttrs::Endpoint(endpoint))
    }
    let nlas = vec![
        WgDeviceAttrs::IfName(interface_name),
        WgDeviceAttrs::Peers(vec![wg_peer]),
    ];
    nlas
}

fn generate_routes_for_peer(interface_addresses: &[IpNet], allowed_ips: &[IpNet]) -> Vec<Route> {
    let mut routes = vec![];
    for gateway in interface_addresses {
        match gateway {
            IpNet::V4(gateway) => {
                for dest in allowed_ips {
                    match dest {
                        IpNet::V4(dest) => {
                            if dest.contains(gateway) || gateway.supernet() == dest.supernet() {
                                let route: Route = Route::Ipv4 {
                                    dest: *dest,
                                    gw: gateway.addr(),
                                    metric: None,
                                };
                                routes.push(route);
                            }
                        }
                        IpNet::V6(_) => {
                            continue;
                        }
                    }
                }
            }
            IpNet::V6(gateway) => {
                for dest in allowed_ips {
                    match dest {
                        IpNet::V4(_) => {
                            continue;
                        }
                        IpNet::V6(dest) => {
                            if dest.contains(gateway) || gateway.supernet() == dest.supernet() {
                                let route: Route = Route::Ipv6 {
                                    dest: *dest,
                                    gw: gateway.addr(),
                                    metric: None,
                                };
                                routes.push(route);
                            }
                        }
                    }
                }
            }
        }
    }
    routes
}
