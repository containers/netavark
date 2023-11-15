use crate::error::{NetavarkError, NetavarkResult};

pub mod dhcp_proxy;
pub mod firewalld_reload;
pub mod setup;
pub mod teardown;
pub mod update;
pub mod version;

fn get_config_dir(dir: Option<String>, cmd: &str) -> NetavarkResult<String> {
    dir.ok_or_else(|| {
        NetavarkError::msg(format!(
            "--config not specified but required for netavark {}",
            cmd
        ))
    })
}
