use crate::{Error, Result};
use async_io::Async;
use nix::unistd::Uid;
use std::{
    collections::HashMap, convert::TryFrom, env, ffi::OsString, os::unix::net::UnixStream,
    str::FromStr,
};

/// A bus address
#[derive(Debug, PartialEq)]
pub enum Address {
    /// A path on the filesystem
    Unix(OsString),
}

#[derive(Debug)]
pub(crate) enum Stream {
    Unix(Async<UnixStream>),
}

impl Address {
    pub(crate) async fn connect(&self) -> Result<Stream> {
        match self {
            Address::Unix(p) => Async::<UnixStream>::connect(p)
                .await
                .map(Stream::Unix)
                .map_err(Error::Io),
        }
    }

    /// Get the address for session socket respecting the DBUS_SESSION_BUS_ADDRESS environment
    /// variable. If we don't recognize the value (or it's not set) we fall back to
    /// $XDG_RUNTIME_DIR/bus
    pub fn session() -> Result<Self> {
        match env::var("DBUS_SESSION_BUS_ADDRESS") {
            Ok(val) => Self::from_str(&val),
            _ => {
                let runtime_dir = env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", Uid::current()));
                let path = format!("unix:path={}/bus", runtime_dir);

                Self::from_str(&path)
            }
        }
    }

    /// Get the address for system bus respecting the DBUS_SYSTEM_BUS_ADDRESS environment
    /// variable. If we don't recognize the value (or it's not set) we fall back to
    /// /var/run/dbus/system_bus_socket
    pub fn system() -> Result<Self> {
        match env::var("DBUS_SYSTEM_BUS_ADDRESS") {
            Ok(val) => Self::from_str(&val),
            _ => Self::from_str("unix:path=/var/run/dbus/system_bus_socket"),
        }
    }

    // Helper for FromStr
    fn from_unix(opts: HashMap<&str, &str>) -> Result<Self> {
        let path = if let Some(abs) = opts.get("abstract") {
            if opts.get("path").is_some() {
                return Err(Error::Address(
                    "`path` and `abstract` cannot be specified together".into(),
                ));
            }
            let mut s = OsString::from("\0");
            s.push(abs);
            s
        } else if let Some(path) = opts.get("path") {
            OsString::from(path)
        } else {
            return Err(Error::Address(
                "unix address is missing path or abstract".to_owned(),
            ));
        };

        Ok(Address::Unix(path))
    }
}

impl FromStr for Address {
    type Err = Error;

    /// Parse a D-BUS address and return its path if we recognize it
    fn from_str(address: &str) -> Result<Self> {
        let col = address
            .find(':')
            .ok_or_else(|| Error::Address("address has no colon".into()))?;
        let transport = &address[..col];
        let mut options = HashMap::new();
        for kv in address[col + 1..].split(',') {
            let (k, v) = match kv.find('=') {
                Some(eq) => (&kv[..eq], &kv[eq + 1..]),
                None => return Err(Error::Address("missing = when parsing key/value".into())),
            };
            if options.insert(k, v).is_some() {
                return Err(Error::Address(format!(
                    "Key `{}` specified multiple times",
                    k
                )));
            }
        }

        match transport {
            "unix" => Self::from_unix(options),
            _ => Err(Error::Address(format!(
                "unsupported transport '{}'",
                transport
            ))),
        }
    }
}

impl TryFrom<&str> for Address {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::from_str(value)
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use crate::Error;
    use std::str::FromStr;
    use test_log::test;

    #[test]
    fn parse_dbus_addresses() {
        match Address::from_str("").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "address has no colon"),
            _ => panic!(),
        }
        match Address::from_str("foo").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "address has no colon"),
            _ => panic!(),
        }
        match Address::from_str("foo:opt").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "missing = when parsing key/value"),
            _ => panic!(),
        }
        match Address::from_str("foo:opt=1,opt=2").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "Key `opt` specified multiple times"),
            _ => panic!(),
        }
        match Address::from_str("tcp:host=localhost").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "unsupported transport 'tcp'"),
            _ => panic!(),
        }
        match Address::from_str("unix:foo=blah").unwrap_err() {
            Error::Address(e) => assert_eq!(e, "unix address is missing path or abstract"),
            _ => panic!(),
        }
        match Address::from_str("unix:path=/tmp,abstract=foo").unwrap_err() {
            Error::Address(e) => {
                assert_eq!(e, "`path` and `abstract` cannot be specified together")
            }
            _ => panic!(),
        }
        assert_eq!(
            Address::Unix("/tmp/dbus-foo".into()),
            Address::from_str("unix:path=/tmp/dbus-foo").unwrap()
        );
        assert_eq!(
            Address::Unix("/tmp/dbus-foo".into()),
            Address::from_str("unix:path=/tmp/dbus-foo,guid=123").unwrap()
        );
    }
}
