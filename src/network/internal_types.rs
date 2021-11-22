use crate::network::types;
use crate::network::types::{Network, PerNetworkOptions};

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
    // pernetwork options
    pub options: PerNetworkOptions,
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
    // per network options
    pub options: PerNetworkOptions,
}
