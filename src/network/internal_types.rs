use crate::network::types;
use crate::network::types::{Network, Subnet};
use std::net::IpAddr;

//  Teardown contains options for tearing down behind a container
#[derive(Clone, Debug)]
pub struct TeardownPortForward {
    // network object
    pub network: Network,
    // container id
    pub container_id: String,
    // portmappings
    pub port_mappings: Vec<types::PortMapping>,
    // name of network
    pub network_name: String,
    // network id
    pub id_network_hash: String,
    // ip address of container
    pub container_ip: IpAddr,
    // remove network related information
    pub complete_teardown: bool,
    // container ip
    pub network_address: Subnet,
}

//  SetupNetwork contains options for setting up a container
#[derive(Clone, Debug)]
pub struct SetupNetwork {
    // network object
    pub net: types::Network,
    // hash id for the network
    pub network_hash_name: String,
}

#[derive(Clone, Debug)]
pub struct TearDownNetwork {
    //  network object
    pub net: types::Network,
    // complete teardown of network
    pub complete_teardown: bool,
}

#[derive(Clone, Debug)]
pub struct SetupPortForward {
    //  network object
    pub net: types::Network,
    // id of container
    pub container_id: String,
    // port mappings
    pub port_mappings: Vec<types::PortMapping>,
    // name of network
    pub network_name: String,
    // hash id for the network
    pub network_hash_name: String,
    // ip addresses of the container
    pub container_ip: IpAddr,
    // network address (subnet)
    pub network_address: Subnet,
}
