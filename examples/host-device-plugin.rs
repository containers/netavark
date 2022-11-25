//! This is just an example plugin, do not use it in production!

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use netavark::{
    network::{
        core_utils::{open_netlink_sockets, CoreUtils},
        netlink, types,
    },
    new_error,
    plugin::{Info, Plugin, PluginExec, API_VERSION},
};
use netlink_packet_route::{address::Nla, nlas::link};

fn main() {
    let info = Info::new("0.1.0-dev".to_owned(), API_VERSION.to_owned(), None);

    PluginExec::new(Exec {}, info).exec();
}

struct Exec {}

impl Plugin for Exec {
    fn create(
        &self,
        network: types::Network,
    ) -> Result<types::Network, Box<dyn std::error::Error>> {
        if network.network_interface.as_deref().unwrap_or_default() == "" {
            return Err(new_error!("no network interface is specified"));
        }

        Ok(network)
    }

    fn setup(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn std::error::Error>> {
        let (mut host, netns) = open_netlink_sockets(&netns)?;

        let name = opts.network.network_interface.unwrap_or_default();

        let link = host.netlink.get_link(netlink::LinkID::Name(name.clone()))?;

        let mut mac_address = String::from("");
        for nla in link.nlas {
            if let link::Nla::Address(ref addr) = nla {
                mac_address = CoreUtils::encode_address_to_hex(addr);
            }
        }

        let addresses = host.netlink.dump_addresses()?;
        let mut subnets = Vec::new();
        for address in addresses {
            if address.header.index == link.header.index {
                for nla in address.nlas {
                    if let Nla::Address(a) = &nla {
                        let ip = match a.len() {
                            4 => Ipv4Addr::new(a[0], a[1], a[2], a[3]).into(),
                            16 => Ipv6Addr::from([
                                a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10],
                                a[11], a[12], a[13], a[14], a[15],
                            ])
                            .into(),
                            len => {
                                return Err(new_error!("invalid netlink address, length: {}", len))
                            }
                        };
                        let net = ipnet::IpNet::new(ip, address.header.prefix_len)?;
                        subnets.push(types::NetAddress {
                            gateway: None,
                            ipnet: net,
                        })
                    }
                }
            }
        }

        host.netlink.set_link_ns(link.header.index, netns.fd)?;

        // interfaces map, but we only ever expect one, for response
        let mut interfaces: HashMap<String, types::NetInterface> = HashMap::new();

        let interface = types::NetInterface {
            mac_address: mac_address,
            subnets: Option::from(subnets),
        };
        interfaces.insert(name, interface);

        //  StatusBlock response
        let response = types::StatusBlock {
            dns_server_ips: None,
            dns_search_domains: None,
            interfaces: Some(interfaces),
        };

        Ok(response)
    }

    fn teardown(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // on teardown revert what was done in setup
        let (host, mut netns) = open_netlink_sockets(&netns)?;

        let name = opts.network.network_interface.unwrap_or_default();

        let link = netns.netlink.get_link(netlink::LinkID::Name(name))?;

        netns.netlink.set_link_ns(link.header.index, host.fd)?;

        Ok(())
    }
}
