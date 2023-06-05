use crate::dhcp_proxy::dhcp_service::DhcpServiceErrorKind::{
    Bug, InvalidArgument, NoLease, Timeout,
};

use crate::dhcp_proxy::lib::g_rpc::{Lease as NetavarkLease, NetworkConfig};
use log::debug;
use mozim::{DhcpV4ClientAsync, DhcpV4Config, DhcpV4Lease as MozimV4Lease};
use tokio_stream::StreamExt;

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
    V4Client(Box<DhcpV4ClientAsync>),
    V6Client(/*TODO implement v6 client*/),
}

/// DHCP service is responsible for creating, handling, and managing the dhcp lease process.
pub struct DhcpV4Service {
    client: DhcpV4ClientAsync,
    network_config: NetworkConfig,
}

impl DhcpV4Service {
    pub fn new(nc: NetworkConfig, timeout: u32) -> Result<Self, DhcpServiceError> {
        let mut config = DhcpV4Config::new_proxy(&nc.host_iface, &nc.container_mac_addr);
        config.set_timeout(timeout);
        let client = match DhcpV4ClientAsync::init(config, None) {
            Ok(client) => Ok(client),
            Err(err) => Err(DhcpServiceError::new(InvalidArgument, err.to_string())),
        }?;
        Ok(Self {
            client: client,
            network_config: nc,
        })
    }

    /// Performs a DHCP DORA on a ipv4 network configuration.
    /// # Arguments
    ///
    /// * `client`: a IPv4 mozim dhcp client. When this method is called, it takes ownership of client.
    ///
    /// returns: Result<Lease, DhcpSearchError>. Either finds a lease successfully, finds no lease, or fails
    ///
    pub async fn get_lease(&mut self) -> Result<NetavarkLease, DhcpServiceError> {
        if let Some(Ok(lease)) = self.client.next().await {
            debug!(
                "successfully found a lease for {:?}",
                &self.network_config.container_mac_addr
            );

            let mut netavark_lease = <NetavarkLease as From<MozimV4Lease>>::from(lease);
            netavark_lease.add_domain_name(&self.network_config.domain_name);
            netavark_lease.add_mac_address(&self.network_config.container_mac_addr);

            debug!(
                "found a lease for {:?}, {:?}",
                &self.network_config.container_mac_addr, &netavark_lease
            );

            return Ok(netavark_lease);
        }
        Err(DhcpServiceError::new(
            Timeout,
            "Could not find a lease within the timeout limit".to_string(),
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
