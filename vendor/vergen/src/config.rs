// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `vergen` configuration

#[cfg(feature = "build")]
use crate::feature::Build;
#[cfg(feature = "cargo")]
use crate::feature::Cargo;
#[cfg(feature = "git")]
use crate::feature::Git;
#[cfg(feature = "rustc")]
use crate::feature::Rustc;
#[cfg(feature = "si")]
use crate::feature::Sysinfo;
use crate::{
    constants::{
        BUILD_DATE_NAME, BUILD_SEMVER_NAME, BUILD_TIMESTAMP_NAME, BUILD_TIME_NAME, CARGO_FEATURES,
        CARGO_PROFILE, CARGO_TARGET_TRIPLE, GIT_BRANCH_NAME, GIT_COMMIT_DATE_NAME,
        GIT_COMMIT_TIMESTAMP_NAME, GIT_COMMIT_TIME_NAME, GIT_SEMVER_NAME, GIT_SEMVER_TAGS_NAME,
        GIT_SHA_NAME, GIT_SHA_SHORT_NAME, RUSTC_CHANNEL_NAME, RUSTC_COMMIT_DATE, RUSTC_COMMIT_HASH,
        RUSTC_HOST_TRIPLE_NAME, RUSTC_LLVM_VERSION, RUSTC_SEMVER_NAME, SYSINFO_CPU_BRAND,
        SYSINFO_CPU_CORE_COUNT, SYSINFO_CPU_FREQUENCY, SYSINFO_CPU_NAME, SYSINFO_CPU_VENDOR,
        SYSINFO_MEMORY, SYSINFO_NAME, SYSINFO_OS_VERSION, SYSINFO_USER,
    },
    feature::{
        configure_build, configure_cargo, configure_git, configure_rustc, configure_sysinfo,
    },
};
use anyhow::Result;
use enum_iterator::IntoEnumIterator;
use getset::{Getters, MutGetters};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// Configure `vergen` to produce the `cargo:` instructions you need
///
/// * See [`Build`](crate::Build) for details on `VERGEN_BUILD_*` instruction configuration
/// * See [`Cargo`](crate::Cargo) for details on `VERGEN_CARGO_*` instruction configuration
/// * See [`Git`](crate::Git) for details on `VERGEN_GIT_*` instruction configuration
/// * See [`Rustc`](crate::Rustc) for details on `VERGEN_RUSTC_*` instruction configuration
/// * See [`Sysinfo`](crate::Sysinfo) for details on `VERGEN_SYSINFO_*` instruction configuration
///
/// # Example
///
/// ```
/// use vergen::Config;
#[cfg_attr(feature = "git", doc = r##"use vergen::TimeZone;"##)]
///
/// let mut config = Config::default();
#[cfg_attr(
    feature = "build",
    doc = r##"
// Turn off the build semver instruction
*config.build_mut().semver_mut() = false;
"##
)]
#[cfg_attr(
    feature = "git",
    doc = r##"
// Change the commit timestamp timezone to local
*config.git_mut().commit_timestamp_timezone_mut() = TimeZone::Local;
"##
)]
#[cfg_attr(
    feature = "rustc",
    doc = r##"
// Turn off the LLVM version instruction
*config.rustc_mut().llvm_version_mut() = false;
"##
)]
#[cfg_attr(
    feature = "cargo",
    doc = r##"
// Turn off the cargo profile instruction
*config.cargo_mut().profile_mut() = false;
"##
)]
#[cfg_attr(
    feature = "si",
    doc = r##"
// Turn off the sysinfo name instruction
*config.sysinfo_mut().name_mut() = false;
"##
)]
/// ```
#[derive(Clone, Debug, Getters, MutGetters)]
#[cfg_attr(not(feature = "git"), derive(Copy))]
#[getset(get = "pub(crate)", get_mut = "pub")]
pub struct Instructions {
    /// Use this to modify the [`Build`] feature configuration.
    #[cfg(feature = "build")]
    build: Build,
    /// Use this to modify the [`Cargo`] feature configuration.
    #[cfg(feature = "cargo")]
    cargo: Cargo,
    /// Use this to modify the [`Git`] feature configuration.
    #[cfg(feature = "git")]
    git: Git,
    /// Use this to modify the [`Rustc`] feature configuration.
    #[cfg(feature = "rustc")]
    rustc: Rustc,
    /// Use this to modify the [`Sysinfo`] feature configuration.
    #[cfg(feature = "si")]
    sysinfo: Sysinfo,
}

#[cfg_attr(msrv, allow(clippy::derivable_impls))]
impl Default for Instructions {
    fn default() -> Self {
        Self {
            #[cfg(feature = "build")]
            build: Build::default(),
            #[cfg(feature = "cargo")]
            cargo: Cargo::default(),
            #[cfg(feature = "git")]
            git: Git::default(),
            #[cfg(feature = "rustc")]
            rustc: Rustc::default(),
            #[cfg(feature = "si")]
            sysinfo: Sysinfo::default(),
        }
    }
}

impl Instructions {
    pub(crate) fn config<T>(self, repo_path: Option<T>) -> Result<Config>
    where
        T: AsRef<Path>,
    {
        let mut config = Config::default();

        configure_build(&self, &mut config);
        configure_git(&self, repo_path, &mut config)?;
        configure_rustc(&self, &mut config)?;
        configure_cargo(&self, &mut config);
        configure_sysinfo(&self, &mut config)?;

        Ok(config)
    }
}

/// Build information keys.
#[derive(Clone, Copy, Debug, IntoEnumIterator, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum VergenKey {
    /// The build date. (VERGEN_BUILD_DATE)
    BuildDate,
    /// The build time. (VERGEN_BUILD_TIME)
    BuildTime,
    /// The build timestamp. (VERGEN_BUILD_TIMESTAMP)
    BuildTimestamp,
    /// The build semver. (VERGEN_BUILD_SEMVER)
    BuildSemver,
    /// The current working branch name (VERGEN_GIT_BRANCH)
    Branch,
    /// The commit date. (VERGEN_GIT_COMMIT_DATE)
    CommitDate,
    /// The commit time. (VERGEN_GIT_COMMIT_TIME)
    CommitTime,
    /// The commit timestamp. (VERGEN_GIT_COMMIT_TIMESTAMP)
    CommitTimestamp,
    /// The semver version from the last git tag. (VERGEN_GIT_SEMVER)
    Semver,
    /// The semver version from the last git tag, including lightweight.
    /// (VERGEN_GIT_SEMVER_LIGHTWEIGHT)
    SemverLightweight,
    /// The latest commit SHA. (VERGEN_GIT_SHA)
    Sha,
    /// The latest commit short SHA. (VERGEN_GIT_SHA_SHORT)
    ShortSha,
    /// The release channel of the rust compiler. (VERGEN_RUSTC_CHANNEL)
    RustcChannel,
    /// The rustc commit date. (VERGEN_RUSTC_COMMIT_DATE)
    RustcCommitDate,
    /// The rustc commit hash. (VERGEN_RUSTC_COMMIT_HASH)
    RustcCommitHash,
    /// The host triple. (VERGEN_HOST_TRIPLE)
    RustcHostTriple,
    /// The rustc LLVM version. (VERGEN_RUSTC_LLVM_VERSION)
    RustcLlvmVersion,
    /// The version information of the rust compiler. (VERGEN_RUSTC_SEMVER)
    RustcSemver,
    /// The cargo target triple (VERGEN_CARGO_TARGET_TRIPLE)
    CargoTargetTriple,
    /// The cargo profile (VERGEN_CARGO_PROFILE)
    CargoProfile,
    /// The cargo features (VERGEN_CARGO_FEATURES)
    CargoFeatures,
    /// The sysinfo system name (VERGEN_SYSINFO_NAME)
    SysinfoName,
    /// The sysinfo os version (VERGEN_SYSINFO_OS_VERSION)
    SysinfoOsVersion,
    /// The sysinfo user name (VERGEN_SYSINFO_USER)
    SysinfoUser,
    /// The sysinfo total memory (VERGEN_SYSINFO_TOTAL_MEMORY)
    SysinfoMemory,
    /// The sysinfo cpu vendor (VERGEN_SYSINFO_CPU_VENDOR)
    SysinfoCpuVendor,
    /// The sysinfo cpu core count (VERGEN_SYSINFO_CPU_CORE_COUNT)
    SysinfoCpuCoreCount,
    /// The sysinfo cpu core count (VERGEN_SYSINFO_CPU_NAME)
    SysinfoCpuName,
    /// The sysinfo cpu core count (VERGEN_SYSINFO_CPU_BRAND)
    SysinfoCpuBrand,
    /// The sysinfo cpu core count (VERGEN_SYSINFO_CPU_FREQUENCY)
    SysinfoCpuFrequency,
}

impl VergenKey {
    /// Get the name for the given key.
    pub(crate) fn name(self) -> &'static str {
        match self {
            VergenKey::BuildDate => BUILD_DATE_NAME,
            VergenKey::BuildTime => BUILD_TIME_NAME,
            VergenKey::BuildTimestamp => BUILD_TIMESTAMP_NAME,
            VergenKey::BuildSemver => BUILD_SEMVER_NAME,
            VergenKey::Branch => GIT_BRANCH_NAME,
            VergenKey::CommitDate => GIT_COMMIT_DATE_NAME,
            VergenKey::CommitTime => GIT_COMMIT_TIME_NAME,
            VergenKey::CommitTimestamp => GIT_COMMIT_TIMESTAMP_NAME,
            VergenKey::Semver => GIT_SEMVER_NAME,
            VergenKey::SemverLightweight => GIT_SEMVER_TAGS_NAME,
            VergenKey::Sha => GIT_SHA_NAME,
            VergenKey::ShortSha => GIT_SHA_SHORT_NAME,
            VergenKey::RustcChannel => RUSTC_CHANNEL_NAME,
            VergenKey::RustcCommitDate => RUSTC_COMMIT_DATE,
            VergenKey::RustcCommitHash => RUSTC_COMMIT_HASH,
            VergenKey::RustcHostTriple => RUSTC_HOST_TRIPLE_NAME,
            VergenKey::RustcLlvmVersion => RUSTC_LLVM_VERSION,
            VergenKey::RustcSemver => RUSTC_SEMVER_NAME,
            VergenKey::CargoTargetTriple => CARGO_TARGET_TRIPLE,
            VergenKey::CargoProfile => CARGO_PROFILE,
            VergenKey::CargoFeatures => CARGO_FEATURES,
            VergenKey::SysinfoName => SYSINFO_NAME,
            VergenKey::SysinfoOsVersion => SYSINFO_OS_VERSION,
            VergenKey::SysinfoUser => SYSINFO_USER,
            VergenKey::SysinfoMemory => SYSINFO_MEMORY,
            VergenKey::SysinfoCpuVendor => SYSINFO_CPU_VENDOR,
            VergenKey::SysinfoCpuCoreCount => SYSINFO_CPU_CORE_COUNT,
            VergenKey::SysinfoCpuName => SYSINFO_CPU_NAME,
            VergenKey::SysinfoCpuBrand => SYSINFO_CPU_BRAND,
            VergenKey::SysinfoCpuFrequency => SYSINFO_CPU_FREQUENCY,
        }
    }
}

#[derive(Clone, Debug, Getters, MutGetters)]
#[getset(get = "pub(crate)")]
#[getset(get_mut = "pub(crate)")]
pub(crate) struct Config {
    cfg_map: BTreeMap<VergenKey, Option<String>>,
    head_path: Option<PathBuf>,
    ref_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Self {
            cfg_map: VergenKey::into_enum_iter().map(|x| (x, None)).collect(),
            head_path: Option::default(),
            ref_path: Option::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Config, Instructions};

    #[test]
    fn default_config_works() {
        assert!(!Config::default().cfg_map().is_empty());
    }

    #[cfg(feature = "build")]
    fn check_build_config(instructions: &Instructions) {
        use crate::{TimeZone, TimestampKind};

        let config = instructions.build();
        assert!(config.has_enabled());
        assert!(config.timestamp());
        assert_eq!(*config.timezone(), TimeZone::Utc);
        assert_eq!(*config.kind(), TimestampKind::Timestamp);
        assert!(config.semver());
    }

    #[cfg(not(feature = "build"))]
    fn check_build_config(_instructions: &Instructions) {}

    #[cfg(feature = "cargo")]
    fn check_cargo_config(instructions: &Instructions) {
        let config = instructions.cargo();
        assert!(config.has_enabled());
        assert!(config.features());
        assert!(config.profile());
        assert!(config.target_triple());
    }

    #[cfg(not(feature = "cargo"))]
    fn check_cargo_config(_instructions: &Instructions) {}

    #[cfg(feature = "git")]
    fn check_git_config(instructions: &Instructions) {
        use crate::{SemverKind, ShaKind, TimeZone, TimestampKind};

        let config = instructions.git();
        assert!(config.has_enabled());
        assert!(config.branch());
        assert!(config.commit_timestamp());
        assert_eq!(*config.commit_timestamp_timezone(), TimeZone::Utc);
        assert_eq!(*config.commit_timestamp_kind(), TimestampKind::Timestamp);
        assert!(config.rerun_on_head_change());
        assert!(config.semver());
        assert_eq!(*config.semver_kind(), SemverKind::Normal);
        assert!(config.sha());
        assert_eq!(*config.sha_kind(), ShaKind::Normal);
    }

    #[cfg(not(feature = "git"))]
    fn check_git_config(_instructions: &Instructions) {}

    #[cfg(feature = "rustc")]
    fn check_rustc_config(instructions: &Instructions) {
        let config = instructions.rustc();
        assert!(config.has_enabled());
        assert!(config.channel());
        assert!(config.commit_date());
        assert!(config.host_triple());
        assert!(config.llvm_version());
        assert!(config.sha());
    }

    #[cfg(not(feature = "rustc"))]
    fn check_rustc_config(_instructions: &Instructions) {}

    #[cfg(feature = "si")]
    fn check_sysinfo_config(instructions: &Instructions) {
        let config = instructions.sysinfo();
        assert!(config.has_enabled());
        assert!(config.name());
        assert!(config.os_version());
        assert!(config.user());
        assert!(config.memory());
        assert!(config.cpu_vendor());
        assert!(config.cpu_core_count());
    }

    #[cfg(not(feature = "si"))]
    fn check_sysinfo_config(_instructions: &Instructions) {}

    #[test]
    fn default_instructions() {
        let default = Instructions::default();
        check_build_config(&default);
        check_cargo_config(&default);
        check_git_config(&default);
        check_rustc_config(&default);
        check_sysinfo_config(&default);
    }
}
