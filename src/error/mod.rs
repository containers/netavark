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
    pub fn msg_str(string: &str) -> NetavarkError {
        NetavarkError::Message(string.to_string())
    }

    // TODO: There has to be a better way of doing this
    pub fn wrap(string: String, chained: NetavarkError) -> NetavarkError {
        NetavarkError::Chain(string, Box::new(chained))
    }

    // TODO: There has to be a better way of doing this
    pub fn wrap_str(string: &str, chained: NetavarkError) -> NetavarkError {
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
        match self {
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

impl PartialEq for NetavarkError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            NetavarkError::Message(s) => {
                if let NetavarkError::Message(o) = other {
                    return s == o;
                }
            }
            NetavarkError::ExitCode(s, i) => {
                if let NetavarkError::ExitCode(s2, i2) = other {
                    return s == s2 && i == i2;
                }
            }
            NetavarkError::Chain(s, e) => {
                if let NetavarkError::Chain(s2, e2) = other {
                    return s == s2 && e == e2;
                }
            }
            NetavarkError::Io(e) => {
                if let NetavarkError::Io(e2) = other {
                    return e.to_string() == e2.to_string();
                }
            }
            NetavarkError::Dbus(e) => {
                if let NetavarkError::Dbus(e2) = other {
                    return e.to_string() == e2.to_string();
                }
            }
            NetavarkError::DbusVariant(e) => {
                if let NetavarkError::DbusVariant(e2) = other {
                    return e.to_string() == e2.to_string();
                }
            }
            NetavarkError::Sysctl(e) => {
                if let NetavarkError::Sysctl(e2) = other {
                    return e.to_string() == e2.to_string();
                }
            }
            NetavarkError::Serde(e) => {
                if let NetavarkError::Serde(e2) = other {
                    return e.to_string() == e2.to_string();
                }
            }
        }
        false
    }
}

impl Eq for NetavarkError {}

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

impl From<ipnet::PrefixLenError> for NetavarkError {
    fn from(e: ipnet::PrefixLenError) -> Self {
        NetavarkError::Message(format!("{}", e))
    }
}
