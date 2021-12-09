use crate::network::types;
use crate::network::types::Subnet;
use std::net::IpAddr;

//  Teardown contains options for tearing down behind a container
#[derive(Clone, Debug)]
pub struct TeardownPortForward {
    pub config: PortForwardConfig,
    // remove network related information
    pub complete_teardown: bool,
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
    pub config: SetupNetwork,
    pub complete_teardown: bool,
}

#[derive(Clone, Debug)]
pub struct PortForwardConfig {
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
