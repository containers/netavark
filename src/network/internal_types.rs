use super::netlink;
use crate::network::types;
use std::net::IpAddr;

/// Teardown contains options for tearing down behind a container
#[derive(Debug)]
pub struct TeardownPortForward<'a> {
    pub config: PortForwardConfig<'a>,
    /// remove network related information
    pub complete_teardown: bool,
}

/// SetupNetwork contains options for setting up a container
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SetupNetwork {
    /// subnets used for this network
    pub subnets: Option<Vec<ipnet::IpNet>>,
    /// bridge interface name
    pub bridge_name: String,
    /// id for the network
    #[serde(default)]
    pub network_id: String,
    /// hash id for the network
    pub network_hash_name: String,
    /// isolation determines whether the network can communicate with others outside of its interface
    pub isolation: IsolateOption,
    /// port used for the dns server
    pub dns_port: u16,
}

#[derive(Debug)]
pub struct TearDownNetwork {
    pub config: SetupNetwork,
    pub complete_teardown: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PortForwardConfigGeneric<Ports, IpAddresses> {
    /// id of container
    pub container_id: String,
    /// id of the network
    #[serde(default)]
    pub network_id: String,
    /// port mappings
    pub port_mappings: Ports,
    /// name of network
    pub network_name: String,
    /// hash id for the network
    pub network_hash_name: String,
    /// ipv4 address of the container to bind to.
    /// If multiple v4 addresses are present, use the first one for this.
    /// At least one of container_ip_v6 and container_ip_v6 must be set. Both can
    /// be set at the same time as well.
    pub container_ip_v4: Option<IpAddr>,
    /// subnet associated with the IPv4 address.
    /// Must be set if v4 address is set.
    pub subnet_v4: Option<ipnet::IpNet>,
    /// ipv6 address of the container.
    /// If multiple v6 addresses are present, use the first one for this.
    /// At least one of container_ip_v6 and container_ip_v6 must be set. Both can
    /// be set at the same time as well.
    pub container_ip_v6: Option<IpAddr>,
    /// subnet associated with the ipv6 address.
    /// Must be set if the v6 address is set.
    pub subnet_v6: Option<ipnet::IpNet>,
    /// port used by DNS that should create forwarding rules
    /// forwarding is not setup if this is 53.
    pub dns_port: u16,
    /// dns servers IPs where forwarding rule to port 53 from dns_port are necessary
    pub dns_server_ips: IpAddresses,
}

// Some trickery to define two struct one with references and one with owned data,
// basically the reference version should be used everywhere and the owned version
// is only needed to deserialize the json data.
pub type PortForwardConfigOwned =
    PortForwardConfigGeneric<Option<Vec<types::PortMapping>>, Vec<IpAddr>>;
pub type PortForwardConfig<'a> =
    PortForwardConfigGeneric<&'a Option<Vec<types::PortMapping>>, &'a Vec<IpAddr>>;

impl<'a> From<&'a PortForwardConfigOwned> for PortForwardConfig<'a> {
    fn from(p: &'a PortForwardConfigOwned) -> PortForwardConfig<'a> {
        Self {
            container_id: p.container_id.clone(),
            network_id: p.network_id.clone(),
            port_mappings: &p.port_mappings,
            network_name: p.network_name.clone(),
            network_hash_name: p.network_hash_name.clone(),
            container_ip_v4: p.container_ip_v4,
            subnet_v4: p.subnet_v4,
            container_ip_v6: p.container_ip_v6,
            subnet_v6: p.subnet_v6,
            dns_port: p.dns_port,
            dns_server_ips: &p.dns_server_ips,
        }
    }
}

/// IPAMAddresses is used to pass ipam information around
pub struct IPAMAddresses {
    // ip addresses for netlink
    pub container_addresses: Vec<ipnet::IpNet>,
    // if using macvlan and dhcp, then true
    pub dhcp_enabled: bool,
    pub gateway_addresses: Vec<ipnet::IpNet>,
    pub routes: Vec<netlink::Route>,
    pub ipv6_enabled: bool,
    // result for podman
    pub net_addresses: Vec<types::NetAddress>,
    pub nameservers: Vec<IpAddr>,
}

// IsolateOption is used to select isolate option value
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IsolateOption {
    Strict,
    Normal,
    Never,
}
