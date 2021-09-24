pub mod network;
use crate::serialize;
pub use network::NetworkOptions;

impl network::NetworkOptions {
    pub fn load(path: &str) -> Result<network::NetworkOptions, serialize::SerializeError> {
        serialize::deserialize(path)
    }
    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)
    }
}
