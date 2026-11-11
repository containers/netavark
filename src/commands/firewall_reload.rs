use crate::{
    error::{ErrorWrap, NetavarkResult},
    firewall::{get_supported_firewall_driver, state::read_fw_config},
    network::constants,
};
use std::{
    ffi::{OsStr, OsString},
    path::Path,
};

pub fn firewall_reload(config_dir: Option<OsString>) -> NetavarkResult<()> {
    // Set the path to the directory where Podman stores the container network state.
    let config_dir = Path::new(
        config_dir
            .as_deref()
            .unwrap_or(OsStr::new(constants::DEFAULT_CONFIG_DIR)), // path to the config dir mainatined by podman
    );
    log::debug!("looking for firewall configs in {config_dir:?}");

    reload_rules(config_dir)?;

    Ok(())
}

// This function is copied directly from firewalld_reload.rs.
fn reload_rules(config_dir: &Path) -> NetavarkResult<()> {
    reload_rules_inner(config_dir)?;
    Ok(())
}

// This is the core logic, also copied directly.
fn reload_rules_inner(config_dir: &Path) -> NetavarkResult<()> {
    // read_fw_config reads all the JSON files from `/run/containers/netavark/`
    let conf = read_fw_config(config_dir).wrap("read firewall config")?;

    // If there are no config files, there are no running containers, so we do nothing.
    if let Some(conf) = conf {
        // Get the appropriate firewall driver
        let fw_driver = get_supported_firewall_driver(Some(conf.driver))?;

        // Loop through each network configuration and restore its rules.
        for net in conf.net_confs {
            fw_driver.setup_network(net)?;
        }
        // Loop through each container's port mappings and restore them.
        for port in &conf.port_confs {
            fw_driver.setup_port_forward(port.into())?;
        }
        log::info!("Successfully reloaded firewall rules");
    }

    Ok(())
}
