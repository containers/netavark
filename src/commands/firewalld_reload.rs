use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

use zbus::{blocking::Connection, dbus_proxy, CacheProperties};

use crate::{
    error::{ErrorWrap, NetavarkResult},
    firewall::{get_supported_firewall_driver, state::read_fw_config},
    network::constants,
};

#[dbus_proxy(
    interface = "org.fedoraproject.FirewallD1",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1"
)]
trait FirewallDDbus {}

const SIGNAL_NAME: &str = "Reloaded";

pub fn listen(config_dir: Option<OsString>) -> NetavarkResult<()> {
    let config_dir = Path::new(
        config_dir
            .as_deref()
            .unwrap_or(OsStr::new(constants::DEFAULT_CONFIG_DIR)),
    );
    log::debug!("looking for firewall configs in {:?}", config_dir);

    let conn = Connection::system()?;
    let proxy = FirewallDDbusProxyBlocking::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build()?;

    // Setup fw rules on start because we are started after firewalld
    // this means at the time firewalld stated the fw rules were flushed
    // and we need to add them back.
    // It is important to keep things like "systemctl restart firewalld" working.
    reload_rules(config_dir);

    // This loops forever until the process is killed or there is some dbus error.
    for _ in proxy.receive_signal(SIGNAL_NAME)? {
        log::debug!("got firewalld {} signal", SIGNAL_NAME);
        reload_rules(config_dir);
    }

    Ok(())
}

fn reload_rules(config_dir: &Path) {
    if let Err(e) = reload_rules_inner(config_dir) {
        log::error!("failed to reload firewall rules: {e}");
    }
}

fn reload_rules_inner(config_dir: &Path) -> NetavarkResult<()> {
    let conf = read_fw_config(config_dir).wrap("read firewall config")?;
    // If we got no conf there are no containers so nothing to do.
    if let Some(conf) = conf {
        let fw_driver = get_supported_firewall_driver(Some(conf.driver))?;

        for net in conf.net_confs {
            fw_driver.setup_network(net)?;
        }
        for port in &conf.port_confs {
            fw_driver.setup_port_forward(port.into())?;
        }
        log::info!("Successfully reloaded firewall rules");
    }

    Ok(())
}
