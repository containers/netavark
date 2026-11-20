use crate::error::{NetavarkError, NetavarkResult};
use crate::network::internal_types::{
    PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};
use log::{debug, info};
use zbus::Connection;

pub mod firewalld;
pub mod fwnone;
pub mod nft;
pub mod state;

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

/// Same as FirewallDriver, just with async setup and teardown methods.
trait AsyncFirewallDriver {
    /// Set up firewall rules for the given network,
    async fn setup_network(&self, network_setup: SetupNetwork) -> NetavarkResult<()>;
    /// Tear down firewall rules for the given network.
    async fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()>;

    /// Set up port-forwarding firewall rules for a given container.
    async fn setup_port_forward(&self, setup_pw: PortForwardConfig) -> NetavarkResult<()>;
    /// Tear down port-forwarding firewall rules for a single container.
    async fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()>;

    /// Return the name of the driver.
    fn driver_name(&self) -> &str;

    fn runtime(&self) -> &tokio::runtime::Runtime;
}

/// Provides sync wrapper for async firewall driver.
impl<T: AsyncFirewallDriver> FirewallDriver for T {
    fn setup_network(&self, network_setup: SetupNetwork) -> NetavarkResult<()> {
        self.runtime()
            .block_on(AsyncFirewallDriver::setup_network(self, network_setup))
    }

    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        self.runtime()
            .block_on(AsyncFirewallDriver::teardown_network(self, tear))
    }

    fn setup_port_forward(&self, setup_pw: PortForwardConfig) -> NetavarkResult<()> {
        self.runtime()
            .block_on(AsyncFirewallDriver::setup_port_forward(self, setup_pw))
    }

    fn teardown_port_forward(&self, teardown_pf: TeardownPortForward) -> NetavarkResult<()> {
        self.runtime()
            .block_on(AsyncFirewallDriver::teardown_port_forward(
                self,
                teardown_pf,
            ))
    }

    fn driver_name(&self) -> &str {
        AsyncFirewallDriver::driver_name(self)
    }
}

/// Types of firewall backend
enum FirewallImpl {
    Firewalld,
    Nftables,
    Fwnone,
}

/// What firewall implementations does this system support?
fn get_firewall_impl(driver_name: Option<String>) -> NetavarkResult<FirewallImpl> {
    // It respects "firewalld", "nftables", "none".
    if let Some(driver) = driver_name {
        debug!("Forcibly using firewall driver {driver}");
        match driver.to_lowercase().as_str() {
            FIREWALLD => return Ok(FirewallImpl::Firewalld),
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
    //     Err(_) => return FirewallImpl::Nftables,
    // };
    // match conn.call_method(
    //     Some("org.freedesktop.DBus"),
    //     "/org/freedesktop/DBus",
    //     Some("org.freedesktop.DBus"),
    //     "GetNameOwner",
    //     &"org.fedoraproject.FirewallD1",
    // ) {
    //     Ok(_) => FirewallImpl::Firewalld(conn),
    //     Err(_) => FirewallImpl::Nftables,
    // }
}

#[cfg(default_fw = "nftables")]
fn get_default_fw_impl() -> NetavarkResult<FirewallImpl> {
    Ok(FirewallImpl::Nftables)
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
            FirewallImpl::Firewalld => {
                info!("Using firewalld firewall driver");
                firewalld::new(DbusContext::system()?)
            }
            FirewallImpl::Nftables => {
                info!("Using nftables firewall driver");
                nft::new(DbusContext::system().ok())
            }
            FirewallImpl::Fwnone => {
                info!("Not using firewall");
                fwnone::new()
            }
        },
        Err(e) => Err(e),
    }
}

pub struct DbusContext {
    pub runtime: tokio::runtime::Runtime,
    pub conn: Connection,
}

impl DbusContext {
    pub fn system() -> NetavarkResult<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| NetavarkError::wrap("failed to build async runtime", e.into()))?;
        let conn = runtime
            .block_on(Connection::system())
            .map_err(|e| NetavarkError::wrap("failed to create DBus connection", e.into()))?;
        Ok(Self { conn, runtime })
    }
}
