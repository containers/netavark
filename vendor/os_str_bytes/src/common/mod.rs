use std::borrow::Cow;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::result;

#[cfg(all(target_vendor = "fortanix", target_env = "sgx"))]
use std::os::fortanix_sgx as os;
#[cfg(any(target_os = "hermit", target_os = "redox", unix))]
use std::os::unix as os;
#[cfg(any(target_env = "wasi", target_os = "wasi"))]
use std::os::wasi as os;

use os::ffi::OsStrExt;
use os::ffi::OsStringExt;

if_raw! {
    pub(super) mod raw;
}

pub(super) type EncodingError = Infallible;

type Result<T> = result::Result<T, EncodingError>;

#[allow(renamed_and_removed_lints)]
#[allow(clippy::unknown_clippy_lints)]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn os_str_from_bytes(string: &[u8]) -> Result<Cow<'_, OsStr>> {
    Ok(Cow::Borrowed(OsStrExt::from_bytes(string)))
}

pub(crate) fn os_str_to_bytes(os_string: &OsStr) -> Cow<'_, [u8]> {
    Cow::Borrowed(OsStrExt::as_bytes(os_string))
}

#[allow(renamed_and_removed_lints)]
#[allow(clippy::unknown_clippy_lints)]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn os_string_from_vec(string: Vec<u8>) -> Result<OsString> {
    Ok(OsStringExt::from_vec(string))
}

pub(crate) fn os_string_into_vec(os_string: OsString) -> Vec<u8> {
    OsStringExt::into_vec(os_string)
}
