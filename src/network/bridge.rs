use std::{collections::HashMap, net::IpAddr, sync::Once};

use ipnet::IpNet;
use log::{debug, error};
use rand::Rng;

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{NetavarkError, NetavarkResult},
    firewall::iptables::MAX_HASH_SIZE,
    network::{constants, types},
};

use super::{
    constants::{NO_CONTAINER_INTERFACE_ERROR, OPTION_ISOLATE, OPTION_MTU},
    core::Core,
    core_utils::{get_ipam_addresses, parse_option, CoreUtils},
    driver::{self, DriverInfo},
    internal_types::{
        IPAMAddresses, PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
    },
    types::StatusBlock,
};

const NO_BRIDGE_NAME_ERROR: &str = "no bridge interface name given";

struct InternalData {
    /// interface name of the veth pair inside the container netns
    container_interface_name: String,
    /// interface name of the bridge for on the host
    bridge_interface_name: String,
    /// static mac address
    mac_address: Option<Vec<u8>>,
    /// ip addresses
    ipam: IPAMAddresses,
    /// mtu for the network interfaces (0 if default)
    mtu: u32,
    /// if this network should be isolated from others
    isolate: bool,
    // TODO: add vlan
}

pub struct Bridge<'a> {
    info: DriverInfo<'a>,
    data: Option<InternalData>,
}

impl<'a> Bridge<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        Bridge { info, data: None }
    }
}

impl driver::NetworkDriver for Bridge<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        let bridge_name = get_interface_name(self.info.network.network_interface.clone())?;
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg_str(NO_CONTAINER_INTERFACE_ERROR));
        }
        let ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        let mtu: u32 = parse_option(&self.info.network.options, OPTION_MTU, 0)?;
        let isolate: bool = parse_option(&self.info.network.options, OPTION_ISOLATE, false)?;

        let static_mac = match &self.info.per_network_opts.static_mac {
            Some(mac) => Some(CoreUtils::decode_address_from_hex(mac)?),
            None => None,
        };

        self.data = Some(InternalData {
            bridge_interface_name: bridge_name,
            container_interface_name: self.info.per_network_opts.interface_name.clone(),
            mac_address: static_mac,
            ipam,
            mtu,
            isolate,
        });
        Ok(())
    }

    fn setup(&self) -> NetavarkResult<(StatusBlock, Option<AardvarkEntry>)> {
        let data = match &self.data {
            Some(d) => d,
            None => {
                return Err(NetavarkError::msg_str(
                    "must call validate() before setup()",
                ))
            }
        };

        debug!("Setup network {}", self.info.network.name);
        debug!(
            "Container interface name: {} with IP addresses {:?}",
            data.container_interface_name, data.ipam.container_addresses
        );
        debug!(
            "Bridge name: {} with IP addresses {:?}",
            data.bridge_interface_name, data.ipam.gateway_addresses
        );

        setup_ipv4_fw_sysctl()?;
        if data.ipam.ipv6_enabled {
            setup_ipv6_fw_sysctl()?;
        }

        // get random name for host veth, TODO let kernel assign name
        let host_veth_name = format!("veth{:x}", rand::thread_rng().gen::<u32>());
        let container_veth_mac = match Core::add_bridge_and_veth(
            &data.bridge_interface_name,
            &data.ipam.container_addresses,
            &data.ipam.gateway_addresses,
            data.mac_address.clone(),
            &data.container_interface_name,
            &host_veth_name,
            self.info.netns_container,
            data.mtu,
            data.ipam.ipv6_enabled,
        ) {
            Ok(addr) => addr,
            Err(err) => {
                return Err(NetavarkError::Message(format!(
                    "failed to configure bridge and veth interface: {}",
                    err
                )))
            }
        };

        //  StatusBlock response
        let mut response = types::StatusBlock {
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };
        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();

        let interface = types::NetInterface {
            mac_address: container_veth_mac,
            subnets: Option::from(data.ipam.net_addresses.clone()),
        };
        // Add interface to interfaces (part of StatusBlock)
        interfaces.insert(data.container_interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);
        if self.info.network.dns_enabled {
            let _ = response
                .dns_server_ips
                .insert(data.ipam.nameservers.clone());
            // Note: this is being added so podman setup is backward compatible with the design
            // which we had with dnsname/dnsmasq. I belive this can be fixed in later releases.
            let _ = response
                .dns_search_domains
                .insert(vec![constants::PODMAN_DEFAULT_SEARCH_DOMAIN.to_string()]);
        }

        // if the network is internal block routing and do not setup firewall rules
        if self.info.network.internal {
            CoreUtils::apply_sysctl_value(
                format!(
                    "/proc/sys/net/ipv4/conf/{}/forwarding",
                    data.bridge_interface_name
                ),
                "0",
            )?;
            if data.ipam.ipv6_enabled {
                CoreUtils::apply_sysctl_value(
                    format!(
                        "/proc/sys/net/ipv6/conf/{}/forwarding",
                        data.bridge_interface_name
                    ),
                    "0",
                )?;
            }
            // return here to skip setting up firewall rules
            return Ok((response, None));
        }

        self.setup_firewall(data)?;

        Ok((response, None))
    }

    fn teardown(&self) -> NetavarkResult<()> {
        Core::remove_container_interface(
            &self.info.per_network_opts.interface_name,
            self.info.netns_container,
        )?; // handle error and continue

        let complete_teardown =
            match get_interface_name(self.info.network.network_interface.clone()) {
                Ok(bridge_name) => {
                    let complete_teardown =
                        match CoreUtils::bridge_count_connected_interfaces(&bridge_name) {
                            Ok(ints) => ints.is_empty(),
                            Err(e) => {
                                error!(
                                    "failed to count veth interface on bridge {}: {}",
                                    bridge_name, e
                                );
                                false
                            }
                        };

                    if complete_teardown {
                        CoreUtils::remove_interface(&bridge_name)?; // handle error and continue
                    }
                    complete_teardown
                }
                Err(e) => {
                    error!(
                        "failed to get bridge name on network {}: {}",
                        self.info.network.name, e
                    );
                    false
                }
            };

        if self.info.network.internal {
            return Ok(());
        }

        self.teardown_firewall(complete_teardown)?;

        Ok(())
    }
}

fn get_interface_name(name: Option<String>) -> NetavarkResult<String> {
    let name = match name {
        None => return Err(NetavarkError::msg_str(NO_BRIDGE_NAME_ERROR)),
        Some(n) => {
            if n.is_empty() {
                return Err(NetavarkError::msg_str(NO_BRIDGE_NAME_ERROR));
            }
            n
        }
    };
    Ok(name)
}

impl<'a> Bridge<'a> {
    fn get_firewall_conf(
        &'a self,
        container_addresses: &Vec<IpNet>,
        nameservers: &'a Vec<IpAddr>,
        isolate: bool,
    ) -> NetavarkResult<(SetupNetwork, PortForwardConfig)> {
        let id_network_hash =
            CoreUtils::create_network_hash(&self.info.network.name, MAX_HASH_SIZE);
        let sn = SetupNetwork {
            net: self.info.network.clone(),
            network_hash_name: id_network_hash.clone(),
            isolation: isolate,
        };

        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        let mut addr_v4: Option<IpAddr> = None;
        let mut addr_v6: Option<IpAddr> = None;
        let mut net_v4: Option<IpNet> = None;
        let mut net_v6: Option<IpNet> = None;
        for net in container_addresses {
            match net {
                IpNet::V4(v4) => {
                    if has_ipv4 {
                        continue;
                    }
                    addr_v4 = Some(IpAddr::V4(v4.addr()));
                    net_v4 = Some(IpNet::new(v4.network().into(), v4.prefix_len())?);
                    has_ipv4 = true;
                }
                IpNet::V6(v6) => {
                    if has_ipv6 {
                        continue;
                    }

                    addr_v6 = Some(IpAddr::V6(v6.addr()));
                    net_v6 = Some(IpNet::new(v6.network().into(), v6.prefix_len())?);
                    has_ipv6 = true;
                }
            }
        }
        let spf = PortForwardConfig {
            container_id: self.info.container_id.clone(),
            port_mappings: self.info.port_mappings.clone().unwrap_or_default(),
            network_name: self.info.network.name.clone(),
            network_hash_name: id_network_hash,
            container_ip_v4: addr_v4,
            subnet_v4: net_v4,
            container_ip_v6: addr_v6,
            subnet_v6: net_v6,
            dns_port: self.info.dns_port,
            dns_server_ips: nameservers,
        };
        Ok((sn, spf))
    }

    fn setup_firewall(&self, data: &InternalData) -> NetavarkResult<()> {
        let (sn, spf) = self.get_firewall_conf(
            &data.ipam.container_addresses,
            &data.ipam.nameservers,
            data.isolate,
        )?;

        self.info.firewall.setup_network(sn)?;

        if !spf.port_mappings.is_empty() {
            // Need to enable sysctl localnet so that traffic can pass
            // through localhost to containers

            CoreUtils::apply_sysctl_value(
                format!(
                    "net.ipv4.conf.{}.route_localnet",
                    data.bridge_interface_name
                ),
                "1",
            )?;
        }

        self.info.firewall.setup_port_forward(spf)?;
        Ok(())
    }

    fn teardown_firewall(&self, complete_teardown: bool) -> NetavarkResult<()> {
        // we have to allocate the vecoros here in the top level to avoid
        // "borrow later used" problems
        let (container_addresses, nameservers);

        let (container_addresses_ref, nameservers_ref, isolate) = match &self.data {
            Some(d) => (&d.ipam.container_addresses, &d.ipam.nameservers, d.isolate),
            None => {
                // options are not yet parsed
                let isolate = match parse_option(&self.info.network.options, OPTION_ISOLATE, false)
                {
                    Ok(i) => i,
                    Err(e) => {
                        // just log we still try to do as much as possible for cleanup
                        error!("failed to parse {} option: {}", OPTION_ISOLATE, e);
                        false
                    }
                };

                (container_addresses, nameservers) =
                    match get_ipam_addresses(self.info.per_network_opts, self.info.network) {
                        Ok(i) => (i.container_addresses, i.nameservers),
                        Err(e) => {
                            // just log we still try to do as much as possible for cleanup
                            error!("failed to parse ipam options: {}", e);
                            (Vec::new(), Vec::new())
                        }
                    };
                (&container_addresses, &nameservers, isolate)
            }
        };

        let (sn, spf) =
            self.get_firewall_conf(container_addresses_ref, nameservers_ref, isolate)?;

        let tn = TearDownNetwork {
            config: sn,
            complete_teardown,
        };

        // FIXME store error and continue
        self.info.firewall.teardown_network(tn)?;

        let tpf = TeardownPortForward {
            config: spf,
            complete_teardown,
        };

        self.info.firewall.teardown_port_forward(tpf)?;
        Ok(())
    }
}

// sysctl forward

static IPV4_FORWARD_ONCE: Once = Once::new();
static IPV6_FORWARD_ONCE: Once = Once::new();

const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";

fn setup_ipv4_fw_sysctl() -> NetavarkResult<()> {
    let mut result = Ok("".to_string());

    IPV4_FORWARD_ONCE.call_once(|| {
        result = CoreUtils::apply_sysctl_value(IPV4_FORWARD, "1");
    });

    match result {
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    };
    Ok(())
}

fn setup_ipv6_fw_sysctl() -> NetavarkResult<()> {
    let mut result = Ok("".to_string());

    IPV6_FORWARD_ONCE.call_once(|| {
        result = CoreUtils::apply_sysctl_value(IPV6_FORWARD, "1");
    });

    match result {
        Ok(_) => {}
        Err(e) => return Err(e.into()),
    };
    Ok(())
}
