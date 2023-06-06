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

/// DHCP service is responsible for creating, handling, and managing the dhcp lease process.
pub struct DhcpV4Service {
    client: DhcpV4ClientAsync,
    network_config: NetworkConfig,
    previous_lease: Option<NetavarkLease>,
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
            client,
            network_config: nc,
            previous_lease: None,
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
            let mut netavark_lease = <NetavarkLease as From<MozimV4Lease>>::from(lease);
            netavark_lease.add_domain_name(&self.network_config.domain_name);
            netavark_lease.add_mac_address(&self.network_config.container_mac_addr);

            debug!(
                "found a lease for {:?}, {:?}",
                &self.network_config.container_mac_addr, &netavark_lease
            );
            self.previous_lease = Some(netavark_lease.clone());

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

pub async fn process_client_stream(mut client: DhcpV4Service) {
    while let Some(lease) = client.client.next().await {
        match lease {
            Ok(lease) => {
                log::debug!(
                    "got new lease for mac {}: {:?}",
                    &client.network_config.container_mac_addr,
                    &lease
                );
                let lease = NetavarkLease::from(lease);
                // get previous lease and check if ip addr changed, if not we do not have to do anything
                if let Some(old_lease) = &client.previous_lease {
                    if old_lease.yiaddr != lease.yiaddr
                        || old_lease.gateways != lease.gateways
                        || old_lease.subnet_mask != lease.subnet_mask
                    {
                        // ips do not match, remove old ones and assign new ones.
                        log::error!("ips do not match, reassign not implemented")
                    }
                }
                client.previous_lease = Some(lease)
            }
            Err(err) => log::error!(
                "Failed to renew lease for {}: {err}",
                &client.network_config.container_mac_addr
            ),
        }
    }
}
