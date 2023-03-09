use crate::dhcp_proxy::dhcp_service::DhcpServiceErrorKind::{
    Bug, InvalidArgument, NoLease, Timeout,
};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, Lease, NetworkConfig};
use log::warn;
use mozim::{
    DhcpError, DhcpV4Client, DhcpV4Config, DhcpV4Lease as MozimV4Lease, DhcpV4Lease, ErrorKind,
};

use tonic::{Code, Status};

/// The kind of DhcpServiceError that can be caused when finding a dhcp lease
pub enum DhcpServiceErrorKind {
    Timeout,
    InvalidArgument,
    InvalidDhcpServerReply,
    NoLease,
    Bug,
    LeaseExpired,
    Unimplemented,
}
/// A DhcpServiceError is an error caused in the process of finding a dhcp lease
pub struct DhcpServiceError {
    kind: DhcpServiceErrorKind,
    msg: String,
}

impl DhcpServiceError {
    pub fn new(kind: DhcpServiceErrorKind, msg: String) -> Self {
        DhcpServiceError { kind, msg }
    }
}

/// The dhcp client can either be a Ipv4 or Ipv6.
///
/// These clients are managed differently. so it is important to keep these separate.
pub enum DhcpClient {
    V4Client(Box<DhcpV4Client>),
    V6Client(/*TODO implement v6 client*/),
}
/// DHCP service is responsible for creating, handling, and managing the dhcp lease process.
pub struct DhcpService {
    client: Option<DhcpClient>,
    network_config: NetworkConfig,
    timeout: u32,
}

trait IP4Conv {
    fn from(self) -> Ipv4Addr;
}

impl IP4Conv for IpAddr {
    fn from(self) -> Ipv4Addr {
        if let IpAddr::V4(ipv4) = self {
            return ipv4;
        }
        Ipv4Addr::from(0)
    }
}

trait IP6Conv {
    fn from(self) -> Ipv6Addr;
}

impl IP6Conv for IpAddr {
    fn from(self) -> Ipv6Addr {
        if let IpAddr::V6(ipv6) = self {
            return ipv6;
        }
        Ipv6Addr::from(0)
    }
}

impl DhcpService {
    pub fn new(nc: &NetworkConfig, timeout: u32) -> Result<DhcpService, DhcpServiceError> {
        let client = Self::create_client(nc)?;
        Ok(DhcpService {
            client: Some(client),
            network_config: nc.clone(),
            timeout,
        })
    }
    /// Based on the IP version, use the dhcp client to process a dhcp lease using DORA.
    /// Note: By using process you pass ownership of the dhcp service.
    pub fn get_lease(mut self) -> Result<NetavarkLease, DhcpServiceError> {
        // match the ip version to create the correct dhcp client
        if let Some(client) = self.client.take() {
            return match client {
                DhcpClient::V4Client(v4_client) => self.get_v4_lease(*v4_client),
                DhcpClient::V6Client() => self.get_v6_lease(),
            };
        }
        Err(DhcpServiceError::new(
            Bug,
            "Could not initiate dhcp client".to_string(),
        ))
    }

    pub fn release_lease(mut self, lease: &Lease) -> Result<(), DhcpError> {
        // match the ip version to create the correct dhcp client
        if let Some(client) = self.client.take() {
            return match client {
                DhcpClient::V4Client(mut v4_client) => {
                    let v4_lease = DhcpV4Lease::try_from(lease.clone())?;
                    v4_client.release(&v4_lease)
                }
                DhcpClient::V6Client() => self.release_v6_lease(),
            };
        }
        // Releasing a lease is not a fatal error
        warn!(
            "Unable to release lease for {}",
            self.network_config.container_mac_addr
        );
        Ok(())
    }

    /// Performs a DHCP DORA on a ipv4 network configuration.
    /// # Arguments
    ///
    /// * `client`: a IPv4 mozim dhcp client. When this method is called, it takes ownership of client.
    ///
    /// returns: Result<Lease, DhcpSearchError>. Either finds a lease successfully, finds no lease, or fails
    fn get_v4_lease(&self, mut client: DhcpV4Client) -> Result<NetavarkLease, DhcpServiceError> {
        let timeout = self.timeout;
        loop {
            match client.poll(timeout) {
                Ok(events) => {
                    for event in events {
                        match client.process(event) {
                            Ok(Some(new_lease)) => {
                                log::debug!("successfully found a lease");
                                let mut netavark_lease =
                                    <NetavarkLease as From<MozimV4Lease>>::from(new_lease);
                                netavark_lease.add_domain_name(&self.network_config.domain_name);
                                netavark_lease
                                    .add_mac_address(&self.network_config.container_mac_addr);
                                return Ok(netavark_lease);
                            }
                            Err(err) => {
                                return Err(DhcpServiceError::new(NoLease, err.to_string()))
                            }
                            Ok(None) => { /*No lease found, keep looking for one*/ }
                        };
                    }
                }
                Err(dhcp_error) => {
                    log::error!("DHCP socket timed out: {}", dhcp_error.to_string());
                    return Err(DhcpServiceError::new(Timeout, dhcp_error.to_string()));
                }
            };
            log::info!("Socket timed out, retrying for a lease");
        }
    }
    /// TODO
    /// Performs a DHCP DORA on a IPv6 network configuration.
    /// # Arguments
    ///
    /// * `client`: a Ipv6 mozim dhcp client. When this method is called, it takes ownership of client.
    ///
    /// returns: Result<NetavarkLease, DhcpSearchError>. Either finds a lease successfully, finds no lease, or fails
    fn get_v6_lease(&self) -> Result<NetavarkLease, DhcpServiceError> {
        log::error!("ipv6 dhcp requests are unimplemented.");
        Err(DhcpServiceError::new(
            Bug,
            "ipv6 dhcp requests are unimplemented.".to_string(),
        ))
    }

    /// Create a DHCP client
    /// # Arguments
    ///
    /// * `iface`: network interface name
    /// * `version`: Version - can be Ipv4 or Ipv6
    ///
    /// returns: Result<DhcpV4Client, DhcpError>. If there are no invalid arguments, mozim creates a client.
    fn create_client(nc: &NetworkConfig) -> Result<DhcpClient, DhcpServiceError> {
        let version = &nc.version;
        let iface = &nc.host_iface;
        match version {
            //V4
            0 => {
                let config = DhcpV4Config::new_proxy(iface, &nc.container_mac_addr);
                match DhcpV4Client::init(config, None) {
                    Ok(client) => Ok(DhcpClient::V4Client(Box::new(client))),
                    Err(err) => Err(DhcpServiceError::new(InvalidArgument, err.to_string())),
                }
            }
            //V6 TODO implement DHCPv6
            1 => {
                unimplemented!();
            }
            // No valid version found in the network configuration sent by the client
            _ => Err(DhcpServiceError::new(
                InvalidArgument,
                String::from("Must select a valid IP protocol 0=v4, 1=v6"),
            )),
        }
    }

    fn release_v6_lease(&self) -> Result<(), DhcpError> {
        Err(DhcpError::new(
            ErrorKind::Bug,
            "not implemented".to_string(),
        ))
    }
}

impl std::fmt::Display for DhcpServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<DhcpServiceError> for Status {
    fn from(err: DhcpServiceError) -> Self {
        match err.kind {
            Timeout => Status::new(Code::Aborted, err.msg),
            InvalidArgument => Status::new(Code::InvalidArgument, err.msg),
            NoLease => Status::new(Code::NotFound, err.msg),
            Bug => Status::new(Code::Internal, err.msg),
            _ => Status::new(Code::Internal, err.msg),
        }
    }
}
