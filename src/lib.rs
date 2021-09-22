#[macro_use]
extern crate serde;
extern crate serde_derive;
extern crate serde_json;

pub mod serialize;
pub mod network;
pub mod commands;

impl network::NetworkOptions {
    pub fn load(path: &str) -> Result<network::NetworkOptions, serialize::SerializeError> {
        serialize::deserialize(path)
    }
    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)
    }
}
