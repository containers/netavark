pub mod types;
pub mod validation;
use std::{
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
pub mod driver;
pub mod internal_types;
mod macvlan_dhcp;
pub mod netlink;
pub mod vlan;

impl types::NetworkOptions {
    pub fn load(path: Option<String>) -> NetavarkResult<types::NetworkOptions> {
        wrap!(Self::load_inner(path), "failed to load network options")
    }

    fn load_inner(path: Option<String>) -> Result<types::NetworkOptions, io::Error> {
        let opts = match path {
            Some(path) => serde_json::from_reader(BufReader::new(File::open(path)?)),
            None => serde_json::from_reader(io::stdin()),
        }?;
        Ok(opts)
    }
}
