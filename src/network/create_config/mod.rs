use crate::network::types;
use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader},
};

use crate::{
    error::{NetavarkError, NetavarkResult},
    wrap,
};

mod config;
mod driver;
mod subnet;
mod validation;

pub use config::new_network;

impl types::NetworkCreateConfig {
    pub fn load(path: Option<OsString>) -> NetavarkResult<types::NetworkCreateConfig> {
        wrap!(Self::load_inner(path), "failed to load network create")
    }

    fn load_inner(path: Option<OsString>) -> Result<types::NetworkCreateConfig, io::Error> {
        let network_create = match path {
            Some(path) => serde_json::from_reader(BufReader::new(File::open(path)?)),
            None => serde_json::from_reader(io::stdin()),
        }?;
        Ok(network_create)
    }
}
