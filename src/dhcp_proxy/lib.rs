extern crate core;

use crate::dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig};
use crate::error::NetavarkError;
use std::convert::TryFrom;
use std::error::Error;

use g_rpc::netavark_proxy_client::NetavarkProxyClient;
use hyper_util::rt::TokioIo;
use log::debug;
use std::fs::File;
use std::net::AddrParseError;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tower::service_fn;

#[allow(clippy::unwrap_used)]
pub mod g_rpc {
    include!(concat!(env!("OUT_DIR"), "/netavark_proxy.rs"));
    use crate::dhcp_proxy::lib::VectorConv;
    use crate::dhcp_proxy::types::{CustomErr, ProxyError};
    use mozim::DhcpV4Lease;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    impl Lease {
        /// Add mac address to a lease
        pub fn add_mac_address(&mut self, mac_addr: &String) {
            self.mac_address = mac_addr.to_string()
        }
        /// Update the domain name of the lease
        pub fn add_domain_name(&mut self, domain_name: &String) {
            self.domain_name = domain_name.to_string();
        }
    }

    impl From<DhcpV4Lease> for Lease {
        fn from(l: DhcpV4Lease) -> Lease {
            // Since these fields are optional as per mozim. Match them first and then set them
            let domain_name = l.domain_name.unwrap_or_default();
            let mtu = l.mtu.unwrap_or(0) as u32;

            Lease {
                t1: l.t1_sec,
                t2: l.t2_sec,
                lease_time: l.lease_time_sec,
                mtu,
                domain_name,
                mac_address: "".to_string(),
                siaddr: l.siaddr.to_string(),
                yiaddr: l.yiaddr.to_string(),
                srv_id: l.srv_id.to_string(),
                subnet_mask: l.subnet_mask.to_string(),
                // TODO something is jacked with8 broadcast, moving on
                broadcast_addr: "".to_string(),
                dns_servers: handle_ip_vectors(l.dns_srvs),
                gateways: handle_ip_vectors(l.gateways),
                ntp_servers: handle_ip_vectors(l.ntp_srvs),
                host_name: l.host_name.unwrap_or_else(|| String::from("")),
                is_v6: false,
            }
        }
    }

    impl TryFrom<Lease> for DhcpV4Lease {
        type Error = ProxyError;
        fn try_from(l: Lease) -> Result<Self, ProxyError> {
            let host_name = if !l.host_name.is_empty() {
                Some(l.host_name)
            } else {
                None
            };
            let domain_name = if !l.domain_name.is_empty() {
                Some(l.domain_name)
            } else {
                None
            };
            let broadcast_addr = if !l.broadcast_addr.is_empty() {
                Some(Ipv4Addr::from_str(&l.broadcast_addr)?)
            } else {
                None
            };

            let mtu = match u16::try_from(l.mtu) {
                Ok(m) => Some(m),
                Err(e) => return Err(ProxyError::new(e.to_string())),
            };
            // Have to do it the hard way because the struct in mozim has a private
            // called srv_id which is a vector of 6 u8s representing the DHCP server's
            // mac address
            let mut lease = DhcpV4Lease::default();
            lease.siaddr = Ipv4Addr::from_str(&l.siaddr)?;
            lease.yiaddr = Ipv4Addr::from_str(&l.yiaddr)?;
            lease.t1_sec = l.t1;
            lease.t2_sec = l.t2;
            lease.lease_time_sec = l.lease_time;
            lease.srv_id = Ipv4Addr::from_str(&l.srv_id)?;
            lease.subnet_mask = Ipv4Addr::from_str(&l.subnet_mask)?;
            lease.broadcast_addr = broadcast_addr;
            lease.dns_srvs = l.dns_servers.to_v4_addrs()?;
            lease.gateways = l.gateways.to_v4_addrs()?;
            lease.ntp_srvs = l.ntp_servers.to_v4_addrs()?;
            lease.mtu = mtu;
            lease.host_name = host_name;
            lease.domain_name = domain_name;
            Ok(lease)
        }
    }

    fn handle_ip_vectors(ip: Option<Vec<std::net::Ipv4Addr>>) -> Vec<String> {
        let mut ips: Vec<String> = Vec::new();
        if let Some(j) = ip {
            for ip in j {
                ips.push(ip.to_string());
            }
        }
        ips
    }

    impl From<std::net::Ipv4Addr> for NvIpv4Addr {
        fn from(ip: std::net::Ipv4Addr) -> NvIpv4Addr {
            NvIpv4Addr {
                octets: Vec::from(ip.octets()),
            }
        }
    }

    impl From<Option<std::net::Ipv4Addr>> for NvIpv4Addr {
        fn from(ip: Option<std::net::Ipv4Addr>) -> Self {
            if let Some(addr) = ip {
                return NvIpv4Addr {
                    octets: Vec::from(addr.octets()),
                };
            }
            NvIpv4Addr {
                octets: Vec::from([0, 0, 0, 0]),
            }
        }
    }

    #[test]
    fn test_handle_gw() {
        use std::str::FromStr;
        let mut ips: Vec<std::net::Ipv4Addr> = Vec::new();
        for i in 0..5 {
            let ip = format!("10.1.{i}.1");
            let ipv4 = std::net::Ipv4Addr::from_str(&ip).expect("failed hard");
            ips.push(ipv4);
        }
        let response = handle_ip_vectors(Some(ips));
        // Len of response should be same as ips
        assert_eq!(response.len(), 5);
        assert_eq!(response[0].to_string(), "10.1.0.1");
    }
}

// A collection of functions for client side connections to the proxy server
impl NetworkConfig {
    pub fn load(path: &str) -> Result<NetworkConfig, Box<dyn Error>> {
        let file = std::io::BufReader::new(File::open(path)?);
        Ok(serde_json::from_reader(file)?)
    }

    /// get_client is an internal function to obtain the uds endpoint
    ///
    /// # Arguments
    ///
    /// * `p`: path to uds
    ///
    /// returns: Result<NetavarkProxyClient<Channel>, NetavarkError>
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    async fn get_client(p: String) -> Result<NetavarkProxyClient<Channel>, NetavarkError> {
        // We do not know why the uds connections need to be done like this.  The
        // maintainer suggested it is part of the their API.
        // We know this is safe and if it ever fails test will catch it
        let endpoint = Endpoint::try_from("http://[::1]").unwrap();

        debug!("using uds path: {}", &p);
        let path = p.clone();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_| {
                let path = p.clone();
                async{Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))}
            }))
            .await
            .map_err(|e| {
                let msg = match e.source() {
                    Some(err) => {
                        // this is a bit ugly but we check if the socket was not found to provide a proper error message
                        // and hint at the systemd socket unit
                        match err
                            .source()
                            .and_then(|e| e.downcast_ref::<std::io::Error>())
                            .and_then(|e| {
                                if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::ConnectionRefused {
                                    Some(format!("socket \"{}\": {e}, is the netavark-dhcp-proxy.socket unit enabled?", &path))
                                } else {
                                    None
                                }
                            }) {
                            Some(msg) => msg,
                            None => err.to_string(),
                        }
                    }
                    None => e.to_string(),
                };
                NetavarkError::msg(msg)
            })?;

        Ok(NetavarkProxyClient::new(channel))
    }

    /// get_lease is a wrapper function for obtaining a lease
    /// over grpc from the nvproxy-server
    ///
    /// # Arguments
    ///
    /// * `p`: path to uds
    ///
    /// returns: Result<Lease, NetavarkError>
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    pub async fn get_lease(self, p: &str) -> Result<Lease, NetavarkError> {
        let mut client = NetworkConfig::get_client(p.to_string()).await?;
        let lease = match client.setup(Request::new(self)).await {
            Ok(l) => l.into_inner(),
            Err(e) => {
                return Err(NetavarkError::msg(format!(
                    "get DHCP lease: {}",
                    e.message()
                )))
            }
        };
        Ok(lease)
    }

    /// drop_lease is a wrapper function to release the current
    /// DHCP lease via the nvproxy
    ///
    ///
    /// # Arguments
    ///
    /// * `p`:  path to uds
    ///
    /// returns: Result<Lease, NetavarkError>
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    pub async fn drop_lease(self, p: &str) -> Result<Lease, NetavarkError> {
        let mut client = NetworkConfig::get_client(p.to_string()).await?;
        let lease = match client.teardown(Request::new(self)).await {
            Ok(l) => l.into_inner(),
            Err(e) => {
                return Err(NetavarkError::msg(format!(
                    "drop DHCP lease: {}",
                    e.message()
                )))
            }
        };
        Ok(lease)
    }
}

trait VectorConv {
    fn to_v4_addrs(&self) -> Result<Option<Vec<Ipv4Addr>>, AddrParseError>;
}

impl VectorConv for Vec<String> {
    fn to_v4_addrs(&self) -> Result<Option<Vec<Ipv4Addr>>, AddrParseError> {
        if self.is_empty() {
            return Ok(None);
        }
        let mut out_addrs = Vec::new();
        for ip in self {
            match Ipv4Addr::from_str(ip) {
                Ok(i) => out_addrs.push(i),
                Err(e) => return Err(e),
            };
        }
        Ok(Some(out_addrs))
    }
}
