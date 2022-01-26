// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! `vergen` rustc feature implementation

use crate::config::{Config, Instructions};
use anyhow::Result;
#[cfg(feature = "rustc")]
use {
    crate::{config::VergenKey, feature::add_entry},
    getset::{Getters, MutGetters},
    rustc_version::{version_meta, Channel},
};

/// Configuration for the `VERGEN_RUSTC_*` instructions
///
/// # Instructions
/// The following instructions can be generated:
///
/// | Instruction | Default |
/// | ----------- | :-----: |
/// | `cargo:rustc-env=VERGEN_RUSTC_CHANNEL=nightly` | * |
/// | `cargo:rustc-env=VERGEN_RUSTC_COMMIT_DATE=2021-02-10` | * |
/// | `cargo:rustc-env=VERGEN_RUSTC_COMMIT_HASH=07194ffcd25b0871ce560b9f702e52db27ac9f77` | * |
/// | `cargo:rustc-env=VERGEN_RUSTC_HOST_TRIPLE=x86_64-apple-darwin` | * |
/// | `cargo:rustc-env=VERGEN_RUSTC_LLVM_VERSION=11.0` | * |
/// | `cargo:rustc-env=VERGEN_RUSTC_SEMVER=1.52.0-nightly` | * |
///
/// * If the `channel` field is false, the `VERGEN_RUSTC_CHANNEL` instruction will not be generated.
/// * If the `commit_date` field is false, the `VERGEN_RUSTC_COMMIT_DATE` instruction will not be generated.
/// * If the `host_triple` field is false, the `VERGEN_RUSTC_HOST_TRIPLE` instruction will not be generated.
/// * If the `llvm_version` field is false, the `VERGEN_RUSTC_LLVM_VERSION` instruction will not be generated.
/// * If the `semver` field is false, the `VERGEN_RUSTC_SEMVER` instruction will not be generated.
/// * If the `sha` field is false, the `VERGEN_RUSTC_COMMIT_HASH` instruction will not be generated.
/// * **NOTE** - The `commit_date` filed is only a date, as we are restricted to the output from `rustc_version`
/// * **NOTE** - The `VERGEN_RUSTC_LLVM_VERSION` instruction will only be generated on the `nightly` channel, regardless of the `llvm_version` field.
///
/// # Example
///
/// ```
/// # use anyhow::Result;
/// use vergen::{vergen, Config};
///
/// # pub fn main() -> Result<()> {
/// let mut config = Config::default();
#[cfg_attr(
    feature = "rustc",
    doc = r##"
// Turn off the LLVM instruction
*config.rustc_mut().llvm_version_mut() = false;

// Generate the instructions
vergen(config)?;
"##
)]
/// # Ok(())
/// # }
#[cfg(feature = "rustc")]
#[derive(Clone, Copy, Debug, Getters, MutGetters)]
#[getset(get = "pub(crate)", get_mut = "pub")]
#[allow(clippy::struct_excessive_bools)]
pub struct Rustc {
    /// Enable/Disable the rustc output
    enabled: bool,
    /// Enable/Disable the `VERGEN_RUSTC_CHANNEL` instruction
    channel: bool,
    /// Enable/Disable the `VERGEN_RUSTC_COMMIT_DATE` instruction
    commit_date: bool,
    /// Enable/Disable the `VERGEN_RUSTC_HOST_TRIPLE` instruction
    host_triple: bool,
    /// Enable/Disable the `VERGEN_RUSTC_LLVM_VERSION` instruction
    llvm_version: bool,
    /// Enable/Disable the `VERGEN_RUSTC_SEMVER` instruction
    semver: bool,
    /// Enable/Disable the `VERGEN_RUSTC_COMMIT_HASH` instruction
    sha: bool,
}

#[cfg(feature = "rustc")]
impl Default for Rustc {
    fn default() -> Self {
        Self {
            enabled: true,
            channel: true,
            commit_date: true,
            host_triple: true,
            llvm_version: true,
            semver: true,
            sha: true,
        }
    }
}

#[cfg(feature = "rustc")]
impl Rustc {
    pub(crate) fn has_enabled(self) -> bool {
        self.enabled
            && (self.channel
                || self.commit_date
                || self.host_triple
                || self.llvm_version
                || self.sha)
    }
}

#[cfg(feature = "rustc")]
pub(crate) fn configure_rustc(instructions: &Instructions, config: &mut Config) -> Result<()> {
    let rustc_config = instructions.rustc();
    if rustc_config.has_enabled() {
        let rustc = version_meta()?;

        if *rustc_config.channel() {
            add_entry(
                config.cfg_map_mut(),
                VergenKey::RustcChannel,
                Some(
                    match rustc.channel {
                        Channel::Dev => "dev",
                        Channel::Nightly => "nightly",
                        Channel::Beta => "beta",
                        Channel::Stable => "stable",
                    }
                    .to_string(),
                ),
            );
        }

        if *rustc_config.host_triple() {
            add_entry(
                config.cfg_map_mut(),
                VergenKey::RustcHostTriple,
                Some(rustc.host),
            );
        }

        if *rustc_config.semver() {
            add_entry(
                config.cfg_map_mut(),
                VergenKey::RustcSemver,
                Some(format!("{}", rustc.semver)),
            );
        }

        if *rustc_config.sha() {
            add_entry(
                config.cfg_map_mut(),
                VergenKey::RustcCommitHash,
                Some(rustc.commit_hash.unwrap_or_else(|| "unknown".to_string())),
            );
        }

        if *rustc_config.commit_date() {
            add_entry(
                config.cfg_map_mut(),
                VergenKey::RustcCommitDate,
                Some(rustc.commit_date.unwrap_or_else(|| "unknown".to_string())),
            );
        }

        if *rustc_config.llvm_version() {
            if let Some(llvmver) = rustc.llvm_version {
                add_entry(
                    config.cfg_map_mut(),
                    VergenKey::RustcLlvmVersion,
                    Some(format!("{}", llvmver)),
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "rustc"))]
pub(crate) fn configure_rustc(_instructions: &Instructions, _config: &mut Config) -> Result<()> {
    Ok(())
}

#[cfg(all(test, feature = "rustc"))]
mod test {
    use crate::config::Instructions;

    #[test]
    fn rustc_config() {
        let mut config = Instructions::default();
        assert!(config.rustc().channel);
        assert!(config.rustc().commit_date);
        assert!(config.rustc().host_triple);
        assert!(config.rustc().llvm_version);
        assert!(config.rustc().sha);
        config.rustc_mut().host_triple = false;
        assert!(!config.rustc().host_triple);
    }

    #[test]
    fn not_enabled() {
        let mut config = Instructions::default();
        *config.rustc_mut().enabled_mut() = false;
        assert!(!config.rustc().has_enabled());
    }

    #[test]
    fn no_channel() {
        let mut config = Instructions::default();
        *config.rustc_mut().channel_mut() = false;
        assert!(config.rustc().has_enabled());
    }

    #[test]
    fn no_commit_date() {
        let mut config = Instructions::default();
        *config.rustc_mut().channel_mut() = false;
        *config.rustc_mut().commit_date_mut() = false;
        assert!(config.rustc().has_enabled());
    }

    #[test]
    fn no_host_triple() {
        let mut config = Instructions::default();
        *config.rustc_mut().channel_mut() = false;
        *config.rustc_mut().commit_date_mut() = false;
        *config.rustc_mut().host_triple_mut() = false;
        assert!(config.rustc().has_enabled());
    }

    #[test]
    fn no_llvm_version() {
        let mut config = Instructions::default();
        *config.rustc_mut().channel_mut() = false;
        *config.rustc_mut().commit_date_mut() = false;
        *config.rustc_mut().host_triple_mut() = false;
        *config.rustc_mut().llvm_version_mut() = false;
        assert!(config.rustc().has_enabled());
    }

    #[test]
    fn nothing() {
        let mut config = Instructions::default();
        *config.rustc_mut().channel_mut() = false;
        *config.rustc_mut().commit_date_mut() = false;
        *config.rustc_mut().host_triple_mut() = false;
        *config.rustc_mut().llvm_version_mut() = false;
        *config.rustc_mut().sha_mut() = false;
        assert!(!config.rustc().has_enabled());
    }
}

#[cfg(all(test, not(feature = "rustc")))]
mod test {}
