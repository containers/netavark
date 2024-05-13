use crate::error::{NetavarkError, NetavarkResult};
use crate::network::internal_types::{
    PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};
use log::{debug, info};
use zbus::blocking::Connection;

pub mod firewalld;
pub mod fwnone;
pub mod iptables;
pub mod nft;
pub mod state;
mod varktables;

const IPTABLES: &str = "iptables";
const FIREWALLD: &str = "firewalld";
const NFTABLES: &str = "nftables";
const NONE: &str = "none";

/// Firewall drivers have the ability to set up per-network firewall forwarding
/// and port mappings.
pub trait FirewallDriver {
    /// Set up firewall rules for the given network,
    fn setup_network(&self, network_setup: SetupNetwork) -> NetavarkResult<()>;
    /// Tear down firewall rules for the given network.
    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()>;

    /// Set up port-forwarding firewall rules for a given container.
    fn setup_port_forward(&self, setup_pw: PortForwardConfig) -> NetavarkResult<()>;
    /// Tear down port-forwarding firewall rules for a single container.
    fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()>;

    /// Return the name of the driver.
    fn driver_name(&self) -> &str;
}

/// Types of firewall backend
enum FirewallImpl {
    Iptables,
    Firewalld(Connection),
    Nftables,
    Fwnone,
}

/// What firewall implementations does this system support?
fn get_firewall_impl(driver_name: Option<String>) -> NetavarkResult<FirewallImpl> {
    // It respects "firewalld", "iptables", "nftables", "none".
    if let Some(driver) = driver_name {
        debug!("Forcibly using firewall driver {driver}");
        match driver.to_lowercase().as_str() {
            FIREWALLD => {
                let conn = match Connection::system() {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(NetavarkError::wrap(
                            "Error retrieving dbus connection for requested firewall backend",
                            e.into(),
                        ))
                    }
                };
                return Ok(FirewallImpl::Firewalld(conn));
            }
            IPTABLES => return Ok(FirewallImpl::Iptables),
            NFTABLES => return Ok(FirewallImpl::Nftables),
            NONE => return Ok(FirewallImpl::Fwnone),
            any => {
                return Err(NetavarkError::Message(format!(
                    "Must provide a valid firewall backend, got {any}"
                )))
            }
        }
    }

    get_default_fw_impl()

    // Is firewalld running?
    // let conn = match Connection::system() {
    //     Ok(conn) => conn,
    //     Err(_) => return FirewallImpl::Iptables,
    // };
    // match conn.call_method(
    //     Some("org.freedesktop.DBus"),
    //     "/org/freedesktop/DBus",
    //     Some("org.freedesktop.DBus"),
    //     "GetNameOwner",
    //     &"org.fedoraproject.FirewallD1",
    // ) {
    //     Ok(_) => FirewallImpl::Firewalld(conn),
    //     Err(_) => FirewallImpl::Iptables,
    // }
}

#[cfg(default_fw = "nftables")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Nftables)
}

#[cfg(default_fw = "iptables")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Iptables)
}

#[cfg(default_fw = "none")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Fwnone)
}

/// Get the preferred firewall implementation for the current system
/// configuration.
pub fn get_supported_firewall_driver(
    driver_name: Option<String>,
) -> NetavarkResult<Box<dyn FirewallDriver>> {
    match get_firewall_impl(driver_name) {
        Ok(fw) => match fw {
            FirewallImpl::Iptables => {
                info!("Using iptables firewall driver");
                iptables::new()
            }
            FirewallImpl::Firewalld(conn) => {
                info!("Using firewalld firewall driver");
                firewalld::new(conn)
            }
            FirewallImpl::Nftables => {
                info!("Using nftables firewall driver");
                nft::new()
            }
            FirewallImpl::Fwnone => {
                info!("Not using firewall");
                fwnone::new()
            }
        },
        Err(e) => Err(e),
    }
}
