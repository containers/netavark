use crate::error::{NetavarkError, NetavarkResult};
use crate::network::types::{Subnet, SubnetPool};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::random;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Check if a network intersects with any of the used networks.
pub fn network_intersects_with_networks(network: &IpNet, used_networks: &[IpNet]) -> bool {
    used_networks
        .iter()
        .any(|used_net| match (network, used_net) {
            (IpNet::V4(net_v4), IpNet::V4(used_v4)) => {
                net_v4.contains(&used_v4.network()) || used_v4.contains(&net_v4.network())
            }
            (IpNet::V6(net_v6), IpNet::V6(used_v6)) => {
                net_v6.contains(&used_v6.network()) || used_v6.contains(&net_v6.network())
            }
            _ => false,
        })
}

/// Get the next subnet by incrementing the network address by the subnet size.
fn next_subnet(network: &Ipv4Net) -> NetavarkResult<Ipv4Net> {
    let prefix_len = network.prefix_len();
    let subnet_size = 1u32 << (32 - prefix_len);

    let network_addr: u32 = network.network().into();

    let next_addr = network_addr
        .checked_add(subnet_size)
        .ok_or_else(|| NetavarkError::msg("Subnet address overflow"))?;

    let next_ip = Ipv4Addr::from(next_addr);

    // Create new network with same prefix length
    Ipv4Net::new(next_ip, prefix_len)
        .map_err(|e| NetavarkError::msg(format!("Failed to create next subnet: {}", e)))
}

/// Get a free IPv4 network subnet from subnet pools.
pub fn get_free_ipv4_network_subnet(
    used_networks: &[IpNet],
    subnet_pools: &[SubnetPool],
    check_used: bool,
) -> NetavarkResult<Subnet> {
    let mut last_error: Option<NetavarkError> = None;

    for pool in subnet_pools {
        let pool_v4 = match pool.base {
            IpNet::V4(v4) => v4,
            IpNet::V6(_) => continue,
        };

        // Create initial network starting from pool base with pool.size as prefix length
        // Make sure to use the network address of the pool base to prevent overwriting
        let pool_base_network_addr: Ipv4Addr = pool_v4.network();
        let mut network = match Ipv4Net::new(pool_base_network_addr, pool.size as u8) {
            Ok(net) => net,
            Err(e) => {
                last_error = Some(NetavarkError::msg(format!(
                    "Failed to create network from pool: {}",
                    e
                )));
                continue;
            }
        };

        loop {
            let network_addr: Ipv4Addr = network.network();
            if !pool_v4.contains(&network_addr) {
                break;
            }

            // If check_used is true, only return if the network doesn't intersect with used networks
            let found = !(check_used
                && network_intersects_with_networks(&IpNet::V4(network), used_networks));
            if found {
                return Ok(Subnet {
                    gateway: None,
                    lease_range: None,
                    subnet: IpNet::V4(network),
                });
            }

            match next_subnet(&network) {
                Ok(next) => network = next,
                Err(e) => {
                    last_error = Some(e);
                    break;
                }
            }
        }
    }

    if let Some(err) = last_error {
        Err(err)
    } else {
        Err(NetavarkError::msg(
            "could not find free subnet from subnet pools",
        ))
    }
}

// returns a random internal ipv6 subnet as described in RFC3879.
fn get_random_ipv6_subnet() -> NetavarkResult<Ipv6Net> {
    // RFC4193: fd00::/8 prefix
    // Generate random bytes for Global ID (40 bits) and Subnet ID (16 bits)
    // For a /64 subnet, we randomize bytes 1-7 (56 bits total)
    let mut octets = [0u8; 16];
    octets[0] = 0xfd; // fd00::/8 prefix

    for octet in octets.iter_mut().take(8).skip(1) {
        *octet = random::<u8>(); // Use * to assign the value directly to the reference
    }

    let addr = Ipv6Addr::from(octets);
    Ipv6Net::new(addr, 64)
        .map_err(|e| NetavarkError::msg(format!("Failed to create random IPv6 subnet: {}", e)))
}

// generates random IPv6 subnets and finds the first available subnet
pub fn get_free_ipv6_network_subnet(used_networks: &[IpNet]) -> NetavarkResult<Subnet> {
    const MAX_ATTEMPTS: usize = 10000;

    for _ in 0..MAX_ATTEMPTS {
        // RFC4193: Choose the ipv6 subnet random and NOT sequentially.
        let network = get_random_ipv6_subnet()?;

        if !network_intersects_with_networks(&IpNet::V6(network), used_networks) {
            return Ok(Subnet {
                gateway: None,
                lease_range: None,
                subnet: IpNet::V6(network),
            });
        }
    }

    Err(NetavarkError::msg("failed to get random ipv6 subnet"))
}
