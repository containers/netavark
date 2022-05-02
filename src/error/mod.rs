use std::error::Error;
use std::fmt;

pub type NetavarkResult<T> = Result<T, NetavarkError>;

// The main Netavark error type
#[derive(Debug)]
pub enum NetavarkError {
    // A string message
    Message(String),
    // A string message that sets a specific exit code for Netavark
    ExitCode(String, i32),
    // A chain of multiple errors
    Chain(String, Box<NetavarkError>),

    Io(std::io::Error),

    Dbus(zbus::Error),
    DbusVariant(zvariant::Error),

    Sysctl(sysctl::SysctlError),

    Serde(serde_json::Error),
}

// Internal struct for JSON output
#[derive(Debug, Serialize, Deserialize)]
struct JsonError {
    pub error: String,
}

impl NetavarkError {
    // TODO: There has to be a better way of doing this
    pub fn from_str(string: &str) -> NetavarkError {
        NetavarkError::Message(string.to_string())
    }

    // TODO: There has to be a better way of doing this
    pub fn make_chain(string: String, chained: NetavarkError) -> NetavarkError {
        NetavarkError::Chain(string, Box::new(chained))
    }

    // TODO: There has to be a better way of doing this
    pub fn make_chain_str(string: &str, chained: NetavarkError) -> NetavarkError {
        NetavarkError::Chain(string.to_string(), Box::new(chained))
    }

    // Print the error in a standardized JSON format recognized by callers of
    // Netavark.
    pub fn print_json(&self) {
        let to_json = JsonError {
            error: self.to_string(),
        };
        println!(
            "{}",
            serde_json::to_string(&to_json).unwrap_or(format!(
                "Failed to serialize error message: {}",
                to_json.error
            ))
        );
    }

    // Get the exit code that Netavark should exit with
    pub fn get_exit_code(&self) -> i32 {
        match *self {
            NetavarkError::ExitCode(_, i) => i,
            _ => 1,
        }
    }
}

impl fmt::Display for NetavarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            NetavarkError::Message(s) => write!(f, "{}", s),
            NetavarkError::ExitCode(s, _) => write!(f, "{}", s),
            NetavarkError::Chain(s, e) => write!(f, "{}: {}", s, e),
            NetavarkError::Io(e) => write!(f, "IO error: {}", e),
            NetavarkError::Dbus(e) => write!(f, "DBus error: {}", e),
            NetavarkError::DbusVariant(e) => write!(f, "DBus Variant Error: {}", e),
            NetavarkError::Sysctl(e) => write!(f, "Sysctl error: {}", e),
            NetavarkError::Serde(e) => write!(f, "JSON Decoding error: {}", e),
        }
    }
}

impl Error for NetavarkError {}

impl From<std::io::Error> for NetavarkError {
    fn from(err: std::io::Error) -> NetavarkError {
        NetavarkError::Io(err)
    }
}

impl From<zbus::Error> for NetavarkError {
    fn from(err: zbus::Error) -> NetavarkError {
        NetavarkError::Dbus(err)
    }
}

impl From<zvariant::Error> for NetavarkError {
    fn from(err: zvariant::Error) -> NetavarkError {
        NetavarkError::DbusVariant(err)
    }
}

impl From<sysctl::SysctlError> for NetavarkError {
    fn from(err: sysctl::SysctlError) -> NetavarkError {
        NetavarkError::Sysctl(err)
    }
}

impl From<serde_json::Error> for NetavarkError {
    fn from(err: serde_json::Error) -> NetavarkError {
        NetavarkError::Serde(err)
    }
}
