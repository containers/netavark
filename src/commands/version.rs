use std::error::Error;

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
}

impl Version {
    pub fn exec(&self) -> Result<(), Box<dyn Error>> {
        let info = Info {
            version: env!("VERGEN_BUILD_SEMVER"),
            commit: env!("VERGEN_GIT_SHA"),
            build_time: env!("VERGEN_BUILD_TIMESTAMP"),
            target: env!("VERGEN_RUSTC_HOST_TRIPLE"),
        };

        let out = serde_json::to_string_pretty(&info)?;
        println!("{}", out);

        Ok(())
    }
}
