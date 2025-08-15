use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

use crate::{
    error::{ErrorWrap, NetavarkResult},
    firewall::{get_supported_firewall_driver, state::read_fw_config},
    network::constants,
};

// This is our new main entry point. It's a "oneshot" function.
// It will be called once by systemd, do its job, and then exit.
pub fn firewall_reload(config_dir: Option<OsString>) -> NetavarkResult<()> {
    // Set the path to the directory where Podman stores the container network state.
    let config_dir = Path::new(
        config_dir
            .as_deref()
            .unwrap_or(OsStr::new(constants::DEFAULT_CONFIG_DIR)), // path to the config dir mainatined by podman
    );
    log::debug!("looking for firewall configs in {config_dir:?}");

    // Call the reload logic. We pass `None` for the D-Bus connection
    // because we are on an nftables system and don't need it.
    reload_rules(config_dir)?;

    Ok(())
}

// This function is copied directly from firewalld_reload.rs.
// It's a simple wrapper to handle and log any errors.
fn reload_rules(config_dir: &Path) -> NetavarkResult<()> {
    reload_rules_inner(config_dir)?;
    Ok(())
}

// This is the core logic, also copied directly.
// the `conn` parameter will be `None` and won't be used by the nftables driver.
fn reload_rules_inner(config_dir: &Path) -> NetavarkResult<()> {
    // read_fw_config reads all the JSON files from `/run/containers/netavark/`
    let conf = read_fw_config(config_dir).wrap("read firewall config")?;

    // If there are no config files, there are no running containers, so we do nothing.
    if let Some(conf) = conf {
        // Get the appropriate firewall driver (it will auto-detect nftables).
        let fw_driver = get_supported_firewall_driver(Some(conf.driver))?;

        // Loop through each network configuration and restore its rules.
        for net in conf.net_confs {
            fw_driver.setup_network(net, &None)?;
        }
        // Loop through each container's port mappings and restore them.
        for port in &conf.port_confs {
            fw_driver.setup_port_forward(port.into(), &None)?;
        }
        log::info!("Successfully reloaded firewall rules");
    }

    Ok(())
}
// src/commands/firewall_reload.rs

// We only need basic imports for paths and error handling.
// All the `zbus` (D-Bus) related imports are removed.
