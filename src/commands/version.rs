use crate::error::NetavarkResult;
use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug)]
pub struct Version {}

#[derive(Debug, Serialize)]
struct Info {
    version: &'static str,
    commit: &'static str,
    build_time: &'static str,
    target: &'static str,
    default_fw_driver: &'static str,
}

impl Version {
    pub fn exec(&self) -> NetavarkResult<()> {
        let info = Info {
            version: env!("CARGO_PKG_VERSION"),
            commit: env!("GIT_COMMIT"),
            build_time: env!("BUILD_TIMESTAMP"),
            target: env!("BUILD_TARGET"),
            default_fw_driver: env!("DEFAULT_FW"),
        };

        let out = serde_json::to_string_pretty(&info)?;
        println!("{out}");

        Ok(())
    }
}
