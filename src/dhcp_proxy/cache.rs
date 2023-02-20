use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, Lease};
use log::{debug, error};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::{Cursor, Write};

#[derive(Debug)]
#[allow(dead_code)]
pub struct ClearError {
    msg: String,
}
/// The Writer on the cache must be clearable so that any new changes can be overwritten
pub trait Clear {
    fn clear(&mut self) -> Result<(), ClearError>;
}
impl Clear for Cursor<Vec<u8>> {
    fn clear(&mut self) -> Result<(), ClearError> {
        self.set_position(0);
        self.get_mut().clear();
        Ok(())
    }
}

impl Clear for File {
    fn clear(&mut self) -> Result<(), ClearError> {
        match self.set_len(0) {
            Ok(_) => Ok(()),
            Err(e) => Err(ClearError { msg: e.to_string() }),
        }
    }
}
/// The leasing cache holds a in memory record of the leases, and a on file version
#[derive(Debug)]
pub struct LeaseCache<W: Write + Clear> {
    mem: HashMap<String, Vec<NetavarkLease>>,
    writer: W,
}

impl<W: Write + Clear> LeaseCache<W> {
    ///
    ///
    /// # Arguments
    ///
    /// * `writer`: any type that can has the Write and Clear trait implemented. In production this
    /// is a file. In development/testing this is a Cursor of bytes
    ///
    /// returns: Result<LeaseCache<W>, Error>
    ///
    pub fn new(writer: W) -> Result<LeaseCache<W>, io::Error> {
        Ok(LeaseCache {
            mem: HashMap::new(),
            writer,
        })
    }

    /// Add a new lease to a memory and file system cache
    ///
    /// # Arguments
    ///
    /// * `mac_addr`: Mac address of the container
    /// * `lease`: New lease that should be saved in the cache
    ///
    /// returns: Result<(), Error>
    ///
    pub fn add_lease(&mut self, mac_addr: &str, lease: &NetavarkLease) -> Result<(), io::Error> {
        debug!("add lease: {:?}", mac_addr);
        // Update cache memory with new lease
        let cache = &mut self.mem;
        cache.insert(mac_addr.to_string(), vec![lease.clone()]);
        // write updated memory cache to the file system
        self.save_memory_to_fs()
    }

    /// When a lease changes, update the lease in memory and on the writer.
    ///
    /// # Arguments
    ///
    /// * `mac_addr`: Mac address of the container
    /// * `lease`: Newest lease information
    ///
    /// returns: Result<(), Error>
    ///
    pub fn update_lease(&mut self, mac_addr: &str, lease: NetavarkLease) -> Result<(), io::Error> {
        let cache = &mut self.mem;
        // write to the memory cache
        cache.insert(mac_addr.to_string(), vec![lease]);
        // write updated memory cache to the file system
        self.save_memory_to_fs()
    }

    /// When a singular container is taken down. Remove that lease from the cache memory and fs
    ///
    /// # Arguments
    ///
    /// * `mac_addr`: Mac address of the container
    pub fn remove_lease(&mut self, mac_addr: &str) -> Result<Lease, io::Error> {
        debug!("remove lease: {:?}", mac_addr);
        let mem = &mut self.mem;
        // Check and see if the lease exists, if not create an empty one
        let lease = match mem.get(mac_addr) {
            None => Lease {
                t1: 0,
                t2: 0,
                lease_time: 0,
                mtu: 0,
                domain_name: "".to_string(),
                mac_address: "".to_string(),
                is_v6: false,
                siaddr: "".to_string(),
                yiaddr: "".to_string(),
                srv_id: "".to_string(),
                subnet_mask: "".to_string(),
                broadcast_addr: "".to_string(),
                dns_servers: vec![],
                gateways: vec![],
                ntp_servers: vec![],
                host_name: "".to_string(),
            },
            Some(l) => l[0].clone(),
        };
        // Try and remove the lease. If it doesnt exist, exit with the blank lease
        if mem.remove(mac_addr).is_none() {
            return Ok(lease);
        }

        // write updated memory cache to the file system
        match self.save_memory_to_fs() {
            Ok(_) => Ok(lease),
            Err(e) => Err(e),
        }
    }

    /// Clean up the memory and file system on tear down of the proxy server
    pub fn teardown(&mut self) -> Result<(), io::Error> {
        self.mem.clear();
        self.save_memory_to_fs()
    }

    /// Save the memory contents to the file system. This will remove the contents in the file,
    /// then write the memory map to the file. This method will be called any the lease memory cache
    /// changes (new lease, remove lease, update lease)
    fn save_memory_to_fs(&mut self) -> io::Result<()> {
        let mem = &self.mem;
        let writer = &mut self.writer;
        // Clear the writer so we can add the old leases
        match writer.clear() {
            Ok(_) => {
                serde_json::to_writer(writer.by_ref(), &mem)?;
                writer.flush()
            }
            Err(e) => {
                error!(
                    "Could not clear the writer. Not updating lease information: {:?}",
                    e
                );
                Ok(())
            }
        }
    }
    // rust validators require both len and is_empty if you define one
    // of them
    pub fn len(&self) -> usize {
        self.mem.len()
    }
    pub fn is_empty(&self) -> bool {
        if self.len() < 1 {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod cache_tests {
    use super::super::cache::LeaseCache;
    use super::super::lib::g_rpc::{Lease as NetavarkLease, Lease};
    use macaddr::MacAddr6;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;
    use std::io::Cursor;

    // Create a single random ipv4 addr
    fn random_ipv4() -> String {
        let mut rng = thread_rng();
        format!(
            "{:?}.{:?}.{:?}.{:?}.",
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255),
            rng.gen_range(0..255)
        )
    }
    // Create a single random mac address
    fn random_macaddr() -> MacAddr6 {
        let mut rng = thread_rng();
        MacAddr6::new(
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
            rng.gen::<u8>(),
        )
    }
    // Create a single random lease
    fn random_lease(mac_address: &String) -> Lease {
        Lease {
            t1: 0,
            t2: 3600,
            lease_time: 0,
            mtu: 0,
            domain_name: "example.domain".to_string(),
            mac_address: String::from(mac_address),
            siaddr: random_ipv4(),
            yiaddr: random_ipv4(),
            srv_id: random_ipv4(),
            subnet_mask: "".to_string(),
            broadcast_addr: "".to_string(),
            dns_servers: vec![],
            gateways: vec![],
            ntp_servers: vec![],
            host_name: "example.host_name".to_string(),
            is_v6: false,
        }
    }
    // Shared information for all tests
    struct CacheTestSetup {
        cache: LeaseCache<Cursor<Vec<u8>>>,
        macaddrs: Vec<String>,
        range: u8,
    }

    impl CacheTestSetup {
        fn new() -> Self {
            // Use byte Cursor instead of file for testing
            let buff = Cursor::new(Vec::new());
            let cache = match LeaseCache::new(buff) {
                Ok(cache) => cache,
                Err(e) => panic!("Could not create leases cache: {:?}", e),
            };

            // Create a random amount of randomized leases
            let macaddrs = Vec::new();
            let mut rng = thread_rng();
            // Make a random amount of leases
            let range: u8 = rng.gen_range(0..10);

            CacheTestSetup {
                cache,
                macaddrs,
                range,
            }
        }
    }
    #[test]
    fn add_leases() {
        let setup = CacheTestSetup::new();
        let mut cache = setup.cache;
        let mut macaddrs = setup.macaddrs;
        let range = setup.range;

        for i in 0..range {
            // Create a random mac address to create a random lease of that mac address
            let mac_address = random_macaddr().to_string();
            macaddrs.push(mac_address.clone());
            let lease = random_lease(&mac_address);

            // Add the lease to the cache
            cache
                .add_lease(&mac_address, &lease)
                .expect("could not add lease to cache");

            // Deserialize the written bytes to compare
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };

            // Get the mac address of the lease
            let macaddr = macaddrs
                .get(i as usize)
                .expect("Could not get the mac address of the lease added");

            // Find the lease in the set of deserialized leases
            let deserialized_lease = s
                .get(macaddr)
                .expect("Could not get the mac address from the map")
                .get(0)
                .expect("Could not get lease from set of mac addresses")
                .clone();
            // Assure that the amount of leases added is correct amount
            assert_eq!(s.len(), (i + 1) as usize);
            // Assure that the lease added was correct
            assert_eq!(lease, deserialized_lease);
        }
    }

    #[test]
    fn remove_leases() {
        let setup = CacheTestSetup::new();
        let mut cache = setup.cache;
        let mut macaddrs = setup.macaddrs;
        let range = setup.range;
        for i in 0..range {
            // Create a random mac address to create a random lease of that mac address
            let mac_address = random_macaddr().to_string();
            macaddrs.push(mac_address.clone());
            let lease = random_lease(&mac_address);

            // Add the lease to the cache
            cache
                .add_lease(&mac_address, &lease)
                .expect("could not add lease to cache");

            // Deserialize the written bytes to compare
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };

            // Get the mac address of the lease
            let macaddr = macaddrs
                .get(i as usize)
                .expect("Could not get the mac address of the lease added");

            // Find the lease in the set of deserialized leases
            let deserialized_lease = s
                .get(macaddr)
                .expect("Could not get the mac address from the map")
                .get(0)
                .expect("Could not get lease from set of mac addresses")
                .clone();
            // Assure that the amount of leases added is correct amount
            assert_eq!(s.len(), (i + 1) as usize);
            // Assure that the lease added was correct
            assert_eq!(lease, deserialized_lease);
        }
        for i in 0..range {
            // Deserialize the written bytes to compare
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };

            let macaddr = macaddrs
                .get(i as usize)
                .expect("Could not get the mac address of the lease added");

            let deserialized_lease = s
                .get(macaddr)
                .expect("Could not get the mac address from the map")
                .get(0)
                .expect("Could not get lease from set of mac addresses")
                .clone();

            let removed_lease = cache
                .remove_lease(macaddr)
                .unwrap_or_else(|_| panic!("Could not remove {:?} from leases", macaddr));
            // Assure the lease is no longer in memory
            assert_eq!(deserialized_lease, removed_lease);
            assert_eq!(s.len(), (range - i) as usize);

            // Deserialize the cache again to assure the lease is not in the writer
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };
            // There should be no lease under that mac address if the lease was removed
            let no_lease = s.get(macaddr);
            assert_eq!(no_lease, None);

            // Remove a lease that does not exist
            let removed_lease = cache
                .remove_lease(macaddr)
                .expect("Could not remove the lease successfully");
            // The returned lease should be a blank one
            assert_eq!(removed_lease.mac_address, "".to_string());
        }
    }

    #[test]
    fn update_leases() {
        let setup = CacheTestSetup::new();
        let mut cache = setup.cache;
        let mut macaddrs = setup.macaddrs;
        let range = setup.range;

        for i in 0..range {
            // Create a random mac address to create a random lease of that mac address
            let mac_address = random_macaddr().to_string();
            macaddrs.push(mac_address.clone());
            let lease = random_lease(&mac_address);

            // Add the lease to the cache
            cache
                .add_lease(&mac_address, &lease)
                .expect("could not add lease to cache");

            // Deserialize the written bytes to compare
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };

            // Get the mac address of the lease
            let macaddr = macaddrs
                .get(i as usize)
                .expect("Could not get the mac address of the lease added");

            // Find the lease in the set of deserialized leases
            let deserialized_lease = s
                .get(macaddr)
                .expect("Could not get the mac address from the map")
                .get(0)
                .expect("Could not get lease from set of mac addresses")
                .clone();
            // Assure that the amount of leases added is correct amount
            assert_eq!(s.len(), (i + 1) as usize);
            // Assure that the lease added was correct
            assert_eq!(lease, deserialized_lease);
        }
        // Update all of the leases
        for i in 0..range {
            // Deserialize the written bytes to compare
            let macaddr = macaddrs
                .get(i as usize)
                .expect("Could not get the mac address of the lease added");

            // Create a new random lease with the same mac address
            let new_lease = random_lease(macaddr);

            cache
                .update_lease(macaddr, new_lease.clone())
                .expect("Could not update the lease");

            // Deserialize the cache again to assure the lease is not in the writer
            let lease_bytes = cache.writer.get_ref().as_slice();
            let s: HashMap<String, Vec<NetavarkLease>> = match serde_json::from_slice(lease_bytes) {
                Ok(s) => s,
                Err(e) => panic!("Error: {:?}", e),
            };
            // There should be no lease under that mac address if the lease was removed
            let deserialized_updated_lease = s
                .get(macaddr)
                .expect("Could not get lease from deserialized map")
                .get(0)
                .expect("Could not find lease in set of multi-homing leases");

            assert_eq!(deserialized_updated_lease, &new_lease);
        }
    }
}
