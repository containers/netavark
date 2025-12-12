pub mod types;
pub mod validation;
use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufReader},
};

use crate::{
    error::{NetavarkError, NetavarkResult},
    wrap,
};
pub mod bridge;
pub mod constants;
pub mod core_utils;
mod dhcp;
pub mod driver;
pub mod internal_types;

pub mod netlink;
pub mod netlink_netfilter;
pub mod netlink_route;

pub mod plugin;
pub mod sysctl;
pub mod vlan;

impl types::NetworkOptions {
    pub fn load(path: Option<OsString>) -> NetavarkResult<types::NetworkOptions> {
        wrap!(Self::load_inner(path), "failed to load network options")
    }

    fn load_inner(path: Option<OsString>) -> Result<types::NetworkOptions, io::Error> {
        let opts = match path {
            Some(path) => serde_json::from_reader(BufReader::new(File::open(path)?)),
            None => serde_json::from_reader(io::stdin()),
        }?;
        Ok(opts)
    }
}
