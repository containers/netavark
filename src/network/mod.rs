pub mod types;
pub mod adapter;
use crate::serialize;

impl types::NetworkOptions {
    pub fn load(path: &str) -> Result<types::NetworkOptions, serialize::SerializeError> {
        serialize::deserialize(path)
    }
    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)
    }
}
