// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `vergen` feature implementations

#[cfg(any(
    feature = "build",
    feature = "cargo",
    feature = "git",
    feature = "rustc",
    feature = "si",
))]
use {crate::config::VergenKey, std::collections::BTreeMap};

mod build;
mod cargo;
mod git;
mod rustc;
mod si;

pub(crate) use build::configure_build;
#[cfg(feature = "build")]
pub use build::Build;
pub(crate) use cargo::configure_cargo;
#[cfg(feature = "cargo")]
pub use cargo::Cargo;
pub(crate) use git::configure_git;
#[cfg(feature = "git")]
pub use git::{Git, SemverKind, ShaKind};
pub(crate) use rustc::configure_rustc;
#[cfg(feature = "rustc")]
pub use rustc::Rustc;
pub(crate) use si::configure_sysinfo;
#[cfg(feature = "si")]
pub use si::Sysinfo;

#[cfg(any(
    feature = "build",
    feature = "cargo",
    feature = "git",
    feature = "rustc",
    feature = "si",
))]
pub(crate) fn add_entry(
    map: &mut BTreeMap<VergenKey, Option<String>>,
    key: VergenKey,
    value: Option<String>,
) {
    *map.entry(key).or_insert_with(Option::default) = value;
}

/// The timezone kind to use with date information
#[cfg(any(feature = "git", feature = "build"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeZone {
    /// UTC
    Utc,
    /// Local
    Local,
}

/// The timestamp kind to output
#[cfg(any(feature = "git", feature = "build"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampKind {
    /// Output the date only
    DateOnly,
    /// Output the time only
    TimeOnly,
    /// Output the date and time only
    DateAndTime,
    /// Output the timestamp only
    Timestamp,
    /// Output all formats
    All,
}

#[cfg(all(
    test,
    any(
        feature = "build",
        feature = "cargo",
        feature = "git",
        feature = "rustc",
        feature = "si",
    )
))]
mod test {
    use super::add_entry;
    use crate::config::VergenKey;
    use std::collections::BTreeMap;

    #[test]
    fn check_add_entry() {
        let mut hm = BTreeMap::new();
        add_entry(&mut hm, VergenKey::BuildTimestamp, Some("".to_string()));
        assert!(hm.get(&VergenKey::BuildTimestamp).is_some());
    }
}
