// Crate contains the types which are accepted by netavark.

use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

// Network describes the Network attributes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    /// Set up dns for this network
    #[serde(rename = "dns_enabled")]
    pub dns_enabled: bool,

    /// Driver for this Network, e.g. bridge, macvlan...
    #[serde(rename = "driver")]
    pub driver: String,

    /// ID of the Network.
    #[serde(rename = "id")]
    pub id: String,

    /// Internal is whether the Network should not have external routes
    /// to public or other Networks.
    #[serde(rename = "internal")]
    pub internal: bool,

    /// This network contains at least one ipv6 subnet.
    #[serde(rename = "ipv6_enabled")]
    pub ipv6_enabled: bool,

    /// Name of the Network.
    #[serde(rename = "name")]
    pub name: String,

    /// NetworkInterface is the network interface name on the host.
    #[serde(rename = "network_interface")]
    pub network_interface: Option<String>,

    /// Options is a set of key-value options that have been applied to
    /// the Network.
    #[serde(rename = "options")]
    pub options: Option<HashMap<String, String>>,

    /// IPAM options is a set of key-value options that have been applied to
    /// the Network.
    #[serde(rename = "ipam_options")]
    pub ipam_options: Option<HashMap<String, String>>,

    /// Subnets to use for this network.
    #[serde(rename = "subnets")]
    pub subnets: Option<Vec<Subnet>>,

    /// Network DNS servers for aardvark-dns.
    #[serde(rename = "network_dns_servers")]
    pub network_dns_servers: Option<Vec<IpAddr>>,
}

/// NetworkOptions for a given container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkOptions {
    /// The container id, used for iptables comments and ipam allocation.
    #[serde(rename = "container_id")]
    pub container_id: String,

    /// The container name, used as dns name.
    #[serde(rename = "container_name")]
    pub container_name: String,

    /// The options used to create the interfaces with.
    /// The networks listed in "network_info" have to match this,
    /// both use the network name as key for the map.
    #[serde(rename = "networks")]
    pub networks: HashMap<String, PerNetworkOptions>,

    /// The networks which are needed to run this.
    /// It has to match the networks listed in "networks",
    /// both use the network name as key for the map.
    #[serde(rename = "network_info")]
    pub network_info: HashMap<String, Network>,

    /// The port mappings for this container.
    #[serde(rename = "port_mappings")]
    pub port_mappings: Option<Vec<PortMapping>>,

    /// Custom DNS servers for aardvark-dns.
    #[serde(rename = "dns_servers")]
    pub dns_servers: Option<Vec<IpAddr>>,
}

/// PerNetworkOptions are options which should be set on a per network basis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerNetworkOptions {
    /// Aliases contains a list of names which the dns server should resolve
    /// to this container. Should only be set when DNSEnabled is true on the Network.
    /// If aliases are set but there is no dns support for this network the
    /// network interface implementation should ignore this and NOT error.
    #[serde(rename = "aliases")]
    pub aliases: Option<Vec<String>>,

    /// InterfaceName for this container. Required.
    #[serde(rename = "interface_name")]
    pub interface_name: String,

    /// StaticIPs for this container.
    #[serde(rename = "static_ips")]
    pub static_ips: Option<Vec<IpAddr>>,

    /// MAC address for the container interface.
    #[serde(rename = "static_mac")]
    pub static_mac: Option<String>,
}

/// PortMapping is one or more ports that will be mapped into the container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortMapping {
    /// ContainerPort is the port number that will be exposed from the
    /// container.
    #[serde(rename = "container_port")]
    pub container_port: u16,

    /// HostIP is the IP that we will bind to on the host.
    /// If unset, assumed to be 0.0.0.0 (all interfaces).
    #[serde(rename = "host_ip")]
    pub host_ip: String,

    /// HostPort is the port number that will be forwarded from the host into
    /// the container.
    #[serde(rename = "host_port")]
    pub host_port: u16,

    /// Protocol is the protocol forward.
    /// Must be either "tcp", "udp", and "sctp", or some combination of these
    /// separated by commas.
    /// If unset, assumed to be TCP.
    #[serde(rename = "protocol")]
    pub protocol: String,

    /// Range is the number of ports that will be forwarded, starting at
    /// HostPort and ContainerPort and counting up.
    /// This is 1-indexed, so 1 is assumed to be a single port (only the
    /// Hostport:Containerport mapping will be added), 2 is two ports (both
    /// Hostport:Containerport and Hostport+1:Containerport+1), etc.
    /// If unset, assumed to be 1 (a single port).
    /// Both hostport + range and containerport + range must be less than
    /// 65536.
    #[serde(rename = "range")]
    pub range: u16,
}

/// StatusBlock contains the network information about a container
/// connected to one Network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusBlock {
    /// Aardvark supports resolving queries with
    /// having fewer than ndots dots. So we dont
    /// need this as of now.
    /// DNS search domains for /etc/resolv.conf
    #[serde(rename = "dns_search_domains")]
    pub dns_search_domains: Option<Vec<String>>,

    /// DNS nameservers /etc/resolv.conf will be populated by these
    #[serde(rename = "dns_server_ips")]
    pub dns_server_ips: Option<Vec<IpAddr>>,

    /// Interfaces contains the created network interface in the container.
    /// The map key is the interface name.
    #[serde(rename = "interfaces")]
    pub interfaces: Option<HashMap<String, NetInterface>>,
}

/// NetInterface contains the settings for a given network interface.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetInterface {
    /// MacAddress for this Interface.
    #[serde(rename = "mac_address")]
    pub mac_address: String,

    /// Subnets list of assigned subnets with their gateway.
    #[serde(rename = "subnets")]
    pub subnets: Option<Vec<NetAddress>>,
}

/// NetAddress contains the ip address, subnet and gateway.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetAddress {
    /// Gateway for the network. This can be empty if there is no gateway, e.g. internal network.
    #[serde(rename = "gateway")]
    pub gateway: Option<IpAddr>,

    /// IPNet of this NetAddress. Note that this is a subnet but it has to contain the
    /// actual ip of the network interface and not the network address.
    #[serde(rename = "ipnet")]
    pub ipnet: IpNet,
}

/// Subnet for a network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subnet {
    /// Subnet for this Network in CIDR form.
    #[serde(rename = "gateway")]
    pub gateway: Option<IpAddr>,

    /// LeaseRange contains the range where IP are leased. Optional.
    #[serde(rename = "lease_range")]
    pub lease_range: Option<LeaseRange>,

    /// Gateway IP for this Network.
    #[serde(rename = "subnet")]
    pub subnet: IpNet,
}

/// LeaseRange contains the range where IP are leased.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseRange {
    /// EndIP last IP in the subnet which should be used to assign ips.
    #[serde(rename = "end_ip")]
    pub end_ip: Option<String>,

    /// StartIP first IP in the subnet which should be used to assign ips.
    #[serde(rename = "start_ip")]
    pub start_ip: Option<String>,
}
