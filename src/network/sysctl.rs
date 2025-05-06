use std::{
    fs::{File, OpenOptions},
    io::{Error, ErrorKind, Read as _, Write as _},
};

use crate::error::{NetavarkError, NetavarkResult};

pub fn apply_sysctl_value(ns_value: impl AsRef<str>, val: impl AsRef<str>) -> NetavarkResult<()> {
    _apply_sysctl_value(&ns_value, val)
        .map_err(|e| NetavarkError::wrap(format!("set sysctl {}", ns_value.as_ref()), e.into()))
}

/// Set a sysctl value by value's namespace.
/// ns_value is the path of the sysctl (using slashes not dots!) and without the "/proc/sys/" prefix.
fn _apply_sysctl_value(ns_value: impl AsRef<str>, val: impl AsRef<str>) -> Result<(), Error> {
    const PREFIX: &str = "/proc/sys/";
    let ns_value = ns_value.as_ref();
    let mut path = String::with_capacity(PREFIX.len() + ns_value.len());
    path.push_str(PREFIX);
    path.push_str(ns_value);
    let val = val.as_ref();

    log::debug!("Setting sysctl value for {} to {}", ns_value, val);

    let mut f = File::open(&path)?;
    let mut buf = String::with_capacity(1);
    f.read_to_string(&mut buf)?;

    if buf.trim() == val {
        return Ok(());
    }

    let mut f = OpenOptions::new().write(true).open(&path)?;
    f.write_all(val.as_bytes())
}

pub fn disable_ipv6_autoconf(if_name: &str) -> NetavarkResult<()> {
    // make sure autoconf is off, we want manual config only
    if let Err(err) = _apply_sysctl_value(format!("net/ipv6/conf/{if_name}/autoconf"), "0") {
        match err.kind() {
            ErrorKind::NotFound => {
                // if the sysctl is not found we likely run on a system without ipv6
                // just ignore that case
            }

            // if we have a read only /proc we ignore it as well
            ErrorKind::ReadOnlyFilesystem => {}

            _ => {
                return Err(NetavarkError::wrap(
                    "failed to set autoconf sysctl",
                    err.into(),
                ));
            }
        }
    };
    Ok(())
}
