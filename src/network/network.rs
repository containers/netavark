// Crate contains the types which are accepted by netvark.

extern crate serde_derive;
use std::collections::HashMap;

// Network describes the Network attributes.
#[derive(Serialize, Deserialize)]
pub struct Network {
    #[serde(rename = "created")]
    pub created: Option<String>,

    #[serde(rename = "dns_enabled")]
    pub dns_enabled: bool,

    #[serde(rename = "driver")]
    pub driver: String,

    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "internal")]
    pub internal: bool,

    #[serde(rename = "ipam_options")]
    pub ipam_options: Option<HashMap<String, String>>,

    #[serde(rename = "ipv6_enabled")]
    pub ipv6_enabled: bool,

    #[serde(rename = "labels")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "network_interface")]
    pub network_interface: Option<String>,

    #[serde(rename = "options")]
    pub options: Option<HashMap<String, String>>,

    #[serde(rename = "subnets")]
    pub subnets: Option<Vec<Subnet>>,
}

// NetworkOptions for a given container.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkOptions {
    #[serde(rename = "container_id")]
    pub container_id: String,

    #[serde(rename = "container_name")]
    pub container_name: String,

    #[serde(rename = "networks")]
    pub networks: HashMap<String, PerNetworkOptions>,

    #[serde(rename = "port_mappings")]
    pub port_mappings: Option<Vec<PortMapping>>,
}

// PerNetworkOptions are options which should be set on a per network basis
#[derive(Debug, Serialize, Deserialize)]
pub struct PerNetworkOptions {
    #[serde(rename = "aliases")]
    pub aliases: Option<Vec<String>>,

    #[serde(rename = "interface_name")]
    pub interface_name: String,

    #[serde(rename = "static_ips")]
    pub static_ips: Option<Vec<String>>,

    #[serde(rename = "static_mac")]
    pub static_mac: Option<String>,
}

// PortMapping is one or more ports that will be mapped into the container.
#[derive(Debug, Serialize, Deserialize)]
pub struct PortMapping {
    #[serde(rename = "container_port")]
    pub container_port: u16,

    #[serde(rename = "host_ip")]
    pub host_ip: String,

    #[serde(rename = "host_port")]
    pub host_port: u16,

    #[serde(rename = "protocol")]
    pub protocol: String,

    #[serde(rename = "range")]
    pub range: u16,
}

// StatusBlock contains the network information about a container
// connected to one Network.
#[derive(Serialize, Deserialize)]
pub struct StatusBlock {
    #[serde(rename = "dns_search_domains")]
    pub dns_search_domains: Option<Vec<String>>,

    #[serde(rename = "dns_server_ips")]
    pub dns_server_ips: Option<Vec<String>>,

    #[serde(rename = "interfaces")]
    pub interfaces: Option<HashMap<String, NetInterface>>,
}

// NetInterface contains the settings for a given network interface.
#[derive(Serialize, Deserialize)]
pub struct NetInterface {
    #[serde(rename = "mac_address")]
    pub mac_address: String,

    #[serde(rename = "networks")]
    pub networks: Option<Vec<NetAddress>>,
}

// NetAddress contains the subnet and gatway.
#[derive(Serialize, Deserialize)]
pub struct NetAddress {
    #[serde(rename = "gateway")]
    pub gateway: Option<String>,

    #[serde(rename = "subnet")]
    pub subnet: IpNet,
}

// IPNet is used as custom net.IPNet type to add Marshal/Unmarshal methods.
// TODO: [Not important] Transformed from golang net.IPNet. Swtich to native rust if needed.
#[derive(Serialize, Deserialize)]
pub struct IpNet {
    #[serde(rename = "IP")]
    pub ip: String,

    #[serde(rename = "Mask")]
    pub mask: String,
}

#[derive(Serialize, Deserialize)]
pub struct Subnet {
    #[serde(rename = "gateway")]
    pub gateway: Option<String>,

    #[serde(rename = "lease_range")]
    pub lease_range: Option<LeaseRange>,

    #[serde(rename = "subnet")]
    pub subnet: IpNet,
}

// LeaseRange contains the range where IP are leased.
#[derive(Serialize, Deserialize)]
pub struct LeaseRange {
    #[serde(rename = "end_ip")]
    pub end_ip: Option<String>,

    #[serde(rename = "start_ip")]
    pub start_ip: Option<String>,
}
