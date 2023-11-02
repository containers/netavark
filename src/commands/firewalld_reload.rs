use zbus::{blocking::Connection, dbus_proxy, CacheProperties};

use crate::error::NetavarkResult;

#[dbus_proxy(
    interface = "org.fedoraproject.FirewallD1",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1"
)]
trait FirewallDDbus {}

const SIGNAL_NAME: &str = "Reloaded";

pub fn listen(_config_dir: Option<String>) -> NetavarkResult<()> {
    // Setup fw rules on start because we are started after firewalld
    // this means at the time firewalld stated the fw rules were flushed
    // and we need to add them back.

    // TODO add rules here

    let conn = Connection::system()?;
    let proxy = FirewallDDbusProxyBlocking::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build()?;

    for _ in proxy.receive_signal(SIGNAL_NAME)? {
        log::debug!("got firewalld reload signal");
        // TODO add rules here
    }

    Ok(())
}
