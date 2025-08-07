use std::{
    ffi::{OsStr, OsString},
    path::Path,
};
use crate::{
    error::NetavarkResult,
    firewall::{get_supported_firewall_driver, state::read_fw_config},
    network::constants,
};

pub fn reload_nftables(config_dir: Option<OsString>) -> NetavarkResult<()> {
    let config_dir = Path::new(
        config_dir
            .as_deref()
            .unwrap_or(OsStr::new(constants::DEFAULT_CONFIG_DIR)),
    );
    log::debug!("Reloading nftables rules from {:?}", config_dir);
    
    let conf = read_fw_config(config_dir)?;
    if let Some(conf) = conf {
        let fw_driver = get_supported_firewall_driver(Some(conf.driver))?;
        
        // Setup network rules
        for net in conf.net_confs {
            fw_driver.setup_network(net, &None)?;
        }
        
        // Setup port forwarding rules  
        for port in &conf.port_confs {
            fw_driver.setup_port_forward(port.into(), &None)?;
        }
        
        log::info!("nftables rules reloaded successfully");
    } else {
        log::debug!("No configs found, nothing to reload");
    }
    Ok(())
}