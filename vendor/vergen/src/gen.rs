// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `vergen` cargo instruction generation

use crate::config::{Config, Instructions, VergenKey};
use anyhow::Result;
use std::{
    io::{self, Write},
    path::Path,
};

/// Generate the `cargo:` instructions
///
/// # Errors
///
/// * Errors may be generated from the `git2` library.
/// * [I/O](std::io::Error) errors may be generated.
/// * Errors may be generated from the `rustc_version` library.
/// * [env](std::env::VarError) errors may be generated.
///
/// # Usage
///
/// ```
/// # use anyhow::Result;
/// # use vergen::{Config, vergen};
/// #
/// # fn main() -> Result<()> {
/// // Generate the default 'cargo:' instruction output
/// vergen(Config::default())
/// # }
/// ```
#[cfg(not(feature = "git"))]
pub fn vergen(config: crate::Config) -> Result<()> {
    // This is here to help with type inference
    let no_repo: Option<&'static str> = None;
    config_from_instructions(config, no_repo, &mut io::stdout())
}

/// Generate the `cargo:` instructions
///
/// # Errors
///
/// * Errors may be generated from the `git2` library.
/// * [I/O](std::io::Error) errors may be generated.
/// * Errors may be generated from the `rustc_version` library.
/// * [env](std::env::VarError) errors may be generated.
///
/// # Usage
///
/// ```
/// # use anyhow::Result;
/// # use vergen::{Config, vergen};
/// #
/// # fn main() -> Result<()> {
/// // Generate the default 'cargo:' instruction output
/// vergen(Config::default())
/// # }
/// ```
#[cfg(feature = "git")]
pub fn vergen(config: crate::Config) -> Result<()> {
    if *config.git().enabled() {
        let base_git_dir = config.git().base_dir().clone();
        config_from_instructions(config, base_git_dir, &mut io::stdout())
    } else {
        // This is here to help with type inference
        let no_repo: Option<&'static str> = None;
        config_from_instructions(config, no_repo, &mut io::stdout())
    }
}

fn config_from_instructions<T, U>(
    instructions: Instructions,
    repo: Option<U>,
    stdout: &mut T,
) -> Result<()>
where
    T: Write,
    U: AsRef<Path>,
{
    output_cargo_instructions(&instructions.config(repo)?, stdout)
}

fn output_cargo_instructions<T>(config: &Config, stdout: &mut T) -> Result<()>
where
    T: Write,
{
    // Generate the 'cargo:' instruction output
    for (k, v) in config.cfg_map().iter().filter_map(some_vals) {
        writeln!(stdout, "cargo:rustc-env={}={}", k.name(), v)?;
    }

    // Add the HEAD path to cargo:rerun-if-changed
    if let Some(head_path) = config.head_path() {
        writeln!(stdout, "cargo:rerun-if-changed={}", head_path.display())?;
    }

    // Add the resolved ref path to cargo:rerun-if-changed
    if let Some(ref_path) = config.ref_path() {
        writeln!(stdout, "cargo:rerun-if-changed={}", ref_path.display())?;
    }

    Ok(())
}

fn some_vals<'a>(tuple: (&'a VergenKey, &'a Option<String>)) -> Option<(&VergenKey, &String)> {
    if tuple.1.is_some() {
        Some((tuple.0, tuple.1.as_ref().unwrap()))
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::{config_from_instructions, vergen};
    use crate::{
        config::Instructions,
        testutils::{setup, teardown},
    };
    use anyhow::Result;
    use lazy_static::lazy_static;
    use regex::Regex;
    use std::{io, path::PathBuf};

    lazy_static! {
        static ref VBD_REGEX: Regex = Regex::new(r".*VERGEN_BUILD_TIMESTAMP.*").unwrap();
    }

    #[cfg(feature = "build")]
    lazy_static! {
        static ref DATE_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_BUILD_DATE=\d{4}-\d{2}-\d{2}"#;
        static ref TIMESTAMP_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_BUILD_TIMESTAMP=([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))"#;
        static ref CARGO_SEMVER_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_GIT_SEMVER=\d{1}\.\d{1}\.\d{1}"#;
        static ref BUILD_SEMVER_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_BUILD_SEMVER=\d{1}\.\d{1}\.\d{1}"#;
        static ref BUILD_REGEX_INST: Regex = {
            let re_str = vec![*TIMESTAMP_RE_STR, *BUILD_SEMVER_RE_STR].join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(all(feature = "build", not(feature = "git")))]
    lazy_static! {
        static ref BUILD_CARGO_REGEX: Regex = {
            let re_str = vec![*DATE_RE_STR, *TIMESTAMP_RE_STR, *CARGO_SEMVER_RE_STR].join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(feature = "cargo")]
    lazy_static! {
        static ref CARGO_TT_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_CARGO_TARGET_TRIPLE=[a-zA-Z0-9-_]+"#;
        static ref CARGO_PROF_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_CARGO_PROFILE=[a-zA-Z0-9-_]+"#;
        static ref CARGO_FEA_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_CARGO_FEATURES=[a-zA-Z0-9-_]+,[a-zA-Z0-9-_]+"#;
        static ref CARGO_REGEX: Regex = {
            let re_str = vec![*CARGO_TT_RE_STR, *CARGO_PROF_RE_STR, *CARGO_FEA_RE_STR].join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(feature = "git")]
    lazy_static! {
        static ref GIT_BRANCH_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_GIT_BRANCH=.*"#;
        static ref GIT_CD_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_GIT_COMMIT_DATE=([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))"#;
        static ref GIT_CT_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_GIT_COMMIT_TIMESTAMP=([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))"#;
        static ref GIT_SEMVER_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_GIT_SEMVER=(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"#;
        static ref GIT_SL_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_GIT_SEMVER_LIGHTWEIGHT=.*"#;
        static ref GIT_SHA_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_GIT_SHA=[0-9a-f]{40}"#;
        static ref GIT_SHA_SHORT_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_GIT_SHA_SHORT=[0-9a-f]{7}"#;
        static ref GIT_RIC_RE_STR: &'static str = r#"cargo:rerun-if-changed=.*\.git/HEAD"#;
        static ref GIT_RIC1_RE_STR: &'static str = r#"cargo:rerun-if-changed=.*"#;
        static ref GIT_RIC_REGEX: Regex = {
            let re_str = vec![*GIT_RIC_RE_STR, *GIT_RIC1_RE_STR].join("\n");
            Regex::new(&re_str).unwrap()
        };
        static ref GIT_REGEX_INST: Regex = {
            let re_str = vec![
                *GIT_BRANCH_RE_STR,
                *GIT_CT_RE_STR,
                *GIT_SEMVER_RE_STR,
                *GIT_SHA_RE_STR,
            ]
            .join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(feature = "rustc")]
    lazy_static! {
        static ref RUSTC_CHANNEL_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_RUSTC_CHANNEL=.*"#;
        static ref RUSTC_CD_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_RUSTC_COMMIT_DATE=\d{4}-\d{2}-\d{2}"#;
        static ref RUSTC_CH_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_RUSTC_COMMIT_HASH=[0-9a-f]{40}"#;
        static ref RUSTC_HT_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_RUSTC_HOST_TRIPLE=.*"#;
        static ref RUSTC_LLVM_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_RUSTC_LLVM_VERSION=\d{2}\.\d{1}"#;
        static ref RUSTC_SEMVER_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_RUSTC_SEMVER=(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"#;
        static ref RUSTC_REGEX: Regex = {
            let re_str = vec![
                *RUSTC_CHANNEL_RE_STR,
                *RUSTC_CD_RE_STR,
                *RUSTC_CH_RE_STR,
                *RUSTC_HT_RE_STR,
                *RUSTC_LLVM_RE_STR,
                *RUSTC_SEMVER_RE_STR,
            ]
            .join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(all(feature = "si", not(target_os = "windows"), not(target_os = "macos")))]
    lazy_static! {
        static ref NAME_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_SYSINFO_NAME=.*"#;
        static ref OS_VERSION_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_OS_VERSION=.*"#;
        static ref USER_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_SYSINFO_USER=.*"#;
        static ref TOTAL_MEMORY_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_TOTAL_MEMORY=.*"#;
        static ref CPU_VENDOR_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_VENDOR=.*"#;
        static ref CPU_CORE_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_CORE_COUNT=.*"#;
        static ref SYSINFO_REGEX_INST: Regex = {
            let re_str = vec![
                *NAME_RE_STR,
                *OS_VERSION_RE_STR,
                *USER_RE_STR,
                *TOTAL_MEMORY_RE_STR,
                *CPU_VENDOR_RE_STR,
                *CPU_CORE_RE_STR,
            ]
            .join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(all(feature = "si", target_os = "macos"))]
    lazy_static! {
        static ref NAME_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_SYSINFO_NAME=.*"#;
        static ref OS_VERSION_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_OS_VERSION=.*"#;
        static ref TOTAL_MEMORY_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_TOTAL_MEMORY=.*"#;
        static ref CPU_VENDOR_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_VENDOR=.*"#;
        static ref CPU_CORE_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_CORE_COUNT=.*"#;
        static ref SYSINFO_REGEX_INST: Regex = {
            let re_str = vec![
                *NAME_RE_STR,
                *OS_VERSION_RE_STR,
                *TOTAL_MEMORY_RE_STR,
                *CPU_VENDOR_RE_STR,
                *CPU_CORE_RE_STR,
            ]
            .join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[cfg(all(feature = "si", target_os = "windows"))]
    lazy_static! {
        static ref NAME_RE_STR: &'static str = r#"cargo:rustc-env=VERGEN_SYSINFO_NAME=.*"#;
        static ref OS_VERSION_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_OS_VERSION=.*"#;
        static ref TOTAL_MEMORY_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_TOTAL_MEMORY=.*"#;
        static ref CPU_VENDOR_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_VENDOR=.*"#;
        static ref CPU_CORE_RE_STR: &'static str =
            r#"cargo:rustc-env=VERGEN_SYSINFO_CPU_CORE_COUNT=.*"#;
        static ref SYSINFO_REGEX_INST: Regex = {
            let re_str = vec![
                *NAME_RE_STR,
                *OS_VERSION_RE_STR,
                *TOTAL_MEMORY_RE_STR,
                *CPU_VENDOR_RE_STR,
                *CPU_CORE_RE_STR,
            ]
            .join("\n");
            Regex::new(&re_str).unwrap()
        };
    }

    #[test]
    #[serial_test::serial]
    #[allow(deprecated)]
    fn gen_works() -> Result<()> {
        setup();
        assert!(vergen(Instructions::default()).is_ok());
        teardown();
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    fn vergen_works() -> Result<()> {
        setup();
        assert!(vergen(Instructions::default()).is_ok());
        teardown();
        Ok(())
    }

    #[test]
    #[serial_test::serial]
    #[cfg(feature = "git")]
    fn vergen_base_dir() -> Result<()> {
        setup();
        let mut inst = Instructions::default();
        *inst.git_mut().enabled_mut() = false;
        assert!(vergen(inst).is_ok());
        teardown();
        Ok(())
    }

    #[test]
    fn describe_falls_back() -> Result<()> {
        let no_tags_path = PathBuf::from("testdata").join("notagsrepo");
        assert!(config_from_instructions(
            Instructions::default(),
            Some(no_tags_path),
            &mut io::sink(),
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn describe() -> Result<()> {
        let no_tags_path = PathBuf::from("testdata").join("tagsrepo");
        assert!(config_from_instructions(
            Instructions::default(),
            Some(no_tags_path),
            &mut io::sink(),
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn detached_head() -> Result<()> {
        let dh_path = PathBuf::from("testdata").join("detachedhead");
        assert!(
            config_from_instructions(Instructions::default(), Some(dh_path), &mut io::sink(),)
                .is_ok()
        );
        Ok(())
    }

    // TODO: Make this a macro to check all toggles
    #[test]
    #[cfg(feature = "build")]
    fn toggle_works() -> Result<()> {
        use crate::TimestampKind;
        let repo_path = PathBuf::from(".");
        let mut config = Instructions::default();
        *config.build_mut().kind_mut() = TimestampKind::DateOnly;

        let mut stdout_buf = vec![];
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf).is_ok());
        let stdout = String::from_utf8_lossy(&stdout_buf);
        assert!(!VBD_REGEX.is_match(&stdout));
        Ok(())
    }

    #[cfg(all(
        not(feature = "build"),
        not(feature = "cargo"),
        not(feature = "git"),
        not(feature = "rustc"),
        not(feature = "si"),
    ))]
    #[test]
    fn no_features_no_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        assert!(stdout_buf.is_empty());
    }

    #[cfg(feature = "build")]
    #[test]
    fn contains_build_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        assert!(BUILD_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "build")]
    #[test]
    fn contains_no_build_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut instructions = Instructions::default();
        *instructions.build_mut().enabled_mut() = false;
        assert!(config_from_instructions(instructions, Some(repo_path), &mut stdout_buf,).is_ok());
        assert!(!BUILD_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "cargo")]
    #[test]
    #[serial_test::serial]
    fn contains_cargo_output() {
        setup();
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        assert!(CARGO_REGEX.is_match(&String::from_utf8_lossy(&stdout_buf)));
        teardown();
    }

    #[cfg(feature = "cargo")]
    #[test]
    #[serial_test::serial]
    fn contains_no_cargo_output() {
        setup();
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut instructions = Instructions::default();
        *instructions.cargo_mut().enabled_mut() = false;
        assert!(config_from_instructions(instructions, Some(repo_path), &mut stdout_buf,).is_ok());
        assert!(!CARGO_REGEX.is_match(&String::from_utf8_lossy(&stdout_buf)));
        teardown();
    }

    #[cfg(feature = "git")]
    #[test]
    fn contains_git_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        assert!(GIT_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
        assert!(GIT_RIC_REGEX.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "git")]
    #[test]
    fn contains_no_git_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut instructions = Instructions::default();
        *instructions.git_mut().enabled_mut() = false;
        assert!(config_from_instructions(instructions, Some(repo_path), &mut stdout_buf,).is_ok());
        assert!(!GIT_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
        assert!(!GIT_RIC_REGEX.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "rustc")]
    #[test]
    fn contains_rustc_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        check_rustc_output(&stdout_buf);
    }

    #[cfg(feature = "rustc")]
    #[test]
    fn contains_no_rustc_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut instructions = Instructions::default();
        *instructions.rustc_mut().enabled_mut() = false;
        assert!(config_from_instructions(instructions, Some(repo_path), &mut stdout_buf,).is_ok());
        check_no_rustc_output(&stdout_buf);
    }

    #[cfg(feature = "si")]
    #[test]
    fn contains_sysinfo_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        assert!(config_from_instructions(
            Instructions::default(),
            Some(repo_path),
            &mut stdout_buf,
        )
        .is_ok());
        assert!(SYSINFO_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "si")]
    #[test]
    fn contains_no_sysinfo_output() {
        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut instructions = Instructions::default();
        *instructions.sysinfo_mut().enabled_mut() = false;
        assert!(config_from_instructions(instructions, Some(repo_path), &mut stdout_buf,).is_ok());
        assert!(!SYSINFO_REGEX_INST.is_match(&String::from_utf8_lossy(&stdout_buf)));
    }

    #[cfg(feature = "rustc")]
    fn check_rustc_output(stdout: &[u8]) {
        assert!(RUSTC_REGEX.is_match(&String::from_utf8_lossy(&stdout)));
    }

    #[cfg(feature = "rustc")]
    fn check_no_rustc_output(stdout: &[u8]) {
        assert!(!RUSTC_REGEX.is_match(&String::from_utf8_lossy(&stdout)));
    }

    #[cfg(feature = "build")]
    #[test]
    fn build_local_timezone() {
        use super::config_from_instructions;
        use crate::TimeZone;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.build_mut().timezone_mut() = TimeZone::Local;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_local_timezone() {
        use super::config_from_instructions;
        use crate::TimeZone;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().commit_timestamp_timezone_mut() = TimeZone::Local;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "build")]
    #[test]
    fn build_time_only() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.build_mut().kind_mut() = TimestampKind::TimeOnly;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_time_only() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().commit_timestamp_kind_mut() = TimestampKind::TimeOnly;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "build")]
    #[test]
    fn build_date_only() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.build_mut().kind_mut() = TimestampKind::DateOnly;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_date_only() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().commit_timestamp_kind_mut() = TimestampKind::DateOnly;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "build")]
    #[test]
    fn build_date_and_time() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.build_mut().kind_mut() = TimestampKind::DateAndTime;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_date_and_time() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().commit_timestamp_kind_mut() = TimestampKind::DateAndTime;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "build")]
    #[test]
    fn build_all_kind() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.build_mut().kind_mut() = TimestampKind::All;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_all_kind() {
        use super::config_from_instructions;
        use crate::TimestampKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().commit_timestamp_kind_mut() = TimestampKind::All;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn sha_kind() {
        use super::config_from_instructions;
        use crate::ShaKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().sha_kind_mut() = ShaKind::Short;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn semver_kind() {
        use super::config_from_instructions;
        use crate::SemverKind;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().semver_kind_mut() = SemverKind::Lightweight;
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }

    #[cfg(feature = "git")]
    #[test]
    fn git_dirty() {
        use super::config_from_instructions;

        let repo_path = PathBuf::from(".");
        let mut stdout_buf = vec![];
        let mut config = Instructions::default();
        *config.git_mut().semver_dirty_mut() = Some("-dirty");
        assert!(config_from_instructions(config, Some(repo_path), &mut stdout_buf,).is_ok());
    }
}
