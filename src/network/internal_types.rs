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
#[derive(Debug)]
pub struct SetupNetwork {
    /// network object
    pub net: types::Network,
    /// hash id for the network
    pub network_hash_name: String,
    /// isolation determines whether the network can communicate with others outside of its interface
    pub isolation: bool,
}

#[derive(Debug)]
pub struct TearDownNetwork {
    pub config: SetupNetwork,
    pub complete_teardown: bool,
}

#[derive(Debug)]
pub struct PortForwardConfig<'a> {
    /// id of container
    pub container_id: String,
    /// port mappings
    pub port_mappings: &'a Option<Vec<types::PortMapping>>,
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
    pub dns_server_ips: &'a Vec<IpAddr>,
}

/// IPAMAddresses is used to pass ipam information around
pub struct IPAMAddresses {
    // ip addresses for netlink
    pub container_addresses: Vec<ipnet::IpNet>,
    // if using macvlan and dhcp, then true
    pub dhcp_enabled: bool,
    pub gateway_addresses: Vec<ipnet::IpNet>,
    pub ipv6_enabled: bool,
    // result for podman
    pub net_addresses: Vec<types::NetAddress>,
    pub nameservers: Vec<IpAddr>,
}
