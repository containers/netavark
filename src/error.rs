use std::error::Error;
use std::{fmt, io};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetavarkError {
    pub error: String,
    // Do not serialize this field we already get the exit code when the program exits so there is no need to include it.
    #[serde(skip_serializing)]
    pub errno: i32,
}

impl NetavarkError {
    pub fn print_json(&self) {
        println!(
            "{}",
            serde_json::to_string(&self)
                .unwrap_or(format!("Failed to serialize error message: {}", self.error))
        )
    }
}

impl fmt::Display for NetavarkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for NetavarkError {}

#[derive(thiserror::Error, Debug)]
pub enum NetavarkErrorCode {
    #[error("network options for network {network_name:?} not found")]
    ErrNoNetworkOptions { network_name: String },

    #[error("failed to load network options: {e}")]
    ErrFailNetworkOptions { e: anyhow::Error },

    #[error("no container ip provided:")]
    ErrNoContainerIP,

    #[error("no network address provided:")]
    ErrNoNetworkAddress,

    #[error("unknown network driver: {expected:?}")]
    ErrUnknownNetworkDriver { expected: String },

    #[error("invalid namespace path: {e}")]
    ErrInvalidNamespacePath { e: io::Error },
}
