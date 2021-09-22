// Crate contains the types which are accepted by netvark.

extern crate serde_derive;
use std::collections::HashMap;

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
