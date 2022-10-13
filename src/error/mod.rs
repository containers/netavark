use std::error::Error;
use std::fmt;

pub type NetavarkResult<T> = Result<T, NetavarkError>;

/// wrap any result into a NetavarkError and add the given msg
#[macro_export]
macro_rules! wrap {
    ($result:expr, $msg:expr) => {
        $result.map_err(|err| NetavarkError::wrap($msg, err.into()))
    };
}

pub trait ErrorWrap<T> {
    /// wrap NetavarkResult error into a NetavarkError and add the given msg
    fn wrap<S>(self, msg: S) -> NetavarkResult<T>
    where
        S: Into<String>;
}

impl<T> ErrorWrap<T> for NetavarkResult<T> {
    fn wrap<S>(self, msg: S) -> NetavarkResult<T>
    where
        S: Into<String>,
    {
        self.map_err(|err| NetavarkError::wrap(msg, err))
    }
}

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

    Netlink(netlink_packet_core::error::ErrorMessage),
}

// Internal struct for JSON output
#[derive(Debug, Serialize, Deserialize)]
struct JsonError {
    pub error: String,
}

impl NetavarkError {
    pub fn msg<S>(msg: S) -> NetavarkError
    where
        S: Into<String>,
    {
        NetavarkError::Message(msg.into())
    }

    pub fn wrap<S>(msg: S, chained: NetavarkError) -> NetavarkError
    where
        S: Into<String>,
    {
        NetavarkError::Chain(msg.into(), Box::new(chained))
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

    /// unwrap the chain error recursively until we a non chain type error
    pub fn unwrap(&self) -> &NetavarkError {
        match self {
            NetavarkError::Chain(_, inner) => inner.unwrap(),
            _ => self,
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
            NetavarkError::Netlink(e) => write!(f, "Netlink error: {}", e),
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
            NetavarkError::Netlink(e) => {
                if let NetavarkError::Netlink(e2) = other {
                    return e == e2;
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

impl From<netlink_packet_core::error::ErrorMessage> for NetavarkError {
    fn from(err: netlink_packet_core::error::ErrorMessage) -> Self {
        NetavarkError::Netlink(err)
    }
}
