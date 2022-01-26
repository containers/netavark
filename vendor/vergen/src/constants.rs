// Copyright (c) 2016, 2018, 2021 vergen developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! Internal Constants

// Build Constants
pub(crate) const BUILD_TIMESTAMP_NAME: &str = "VERGEN_BUILD_TIMESTAMP";
pub(crate) const BUILD_DATE_NAME: &str = "VERGEN_BUILD_DATE";
pub(crate) const BUILD_TIME_NAME: &str = "VERGEN_BUILD_TIME";
pub(crate) const BUILD_SEMVER_NAME: &str = "VERGEN_BUILD_SEMVER";

// git Constants
pub(crate) const GIT_BRANCH_NAME: &str = "VERGEN_GIT_BRANCH";
pub(crate) const GIT_COMMIT_DATE_NAME: &str = "VERGEN_GIT_COMMIT_DATE";
pub(crate) const GIT_COMMIT_TIME_NAME: &str = "VERGEN_GIT_COMMIT_TIME";
pub(crate) const GIT_COMMIT_TIMESTAMP_NAME: &str = "VERGEN_GIT_COMMIT_TIMESTAMP";
pub(crate) const GIT_SEMVER_NAME: &str = "VERGEN_GIT_SEMVER";
pub(crate) const GIT_SEMVER_TAGS_NAME: &str = "VERGEN_GIT_SEMVER_LIGHTWEIGHT";
pub(crate) const GIT_SHA_NAME: &str = "VERGEN_GIT_SHA";
pub(crate) const GIT_SHA_SHORT_NAME: &str = "VERGEN_GIT_SHA_SHORT";

// rustc Constants
pub(crate) const RUSTC_CHANNEL_NAME: &str = "VERGEN_RUSTC_CHANNEL";
pub(crate) const RUSTC_HOST_TRIPLE_NAME: &str = "VERGEN_RUSTC_HOST_TRIPLE";
pub(crate) const RUSTC_SEMVER_NAME: &str = "VERGEN_RUSTC_SEMVER";
pub(crate) const RUSTC_COMMIT_HASH: &str = "VERGEN_RUSTC_COMMIT_HASH";
pub(crate) const RUSTC_COMMIT_DATE: &str = "VERGEN_RUSTC_COMMIT_DATE";
pub(crate) const RUSTC_LLVM_VERSION: &str = "VERGEN_RUSTC_LLVM_VERSION";

// cargo Constants
pub(crate) const CARGO_TARGET_TRIPLE: &str = "VERGEN_CARGO_TARGET_TRIPLE";
pub(crate) const CARGO_PROFILE: &str = "VERGEN_CARGO_PROFILE";
pub(crate) const CARGO_FEATURES: &str = "VERGEN_CARGO_FEATURES";

// sysinfo Constants
pub(crate) const SYSINFO_NAME: &str = "VERGEN_SYSINFO_NAME";
pub(crate) const SYSINFO_OS_VERSION: &str = "VERGEN_SYSINFO_OS_VERSION";
pub(crate) const SYSINFO_USER: &str = "VERGEN_SYSINFO_USER";
pub(crate) const SYSINFO_MEMORY: &str = "VERGEN_SYSINFO_TOTAL_MEMORY";
pub(crate) const SYSINFO_CPU_VENDOR: &str = "VERGEN_SYSINFO_CPU_VENDOR";
pub(crate) const SYSINFO_CPU_CORE_COUNT: &str = "VERGEN_SYSINFO_CPU_CORE_COUNT";
pub(crate) const SYSINFO_CPU_NAME: &str = "VERGEN_SYSINFO_CPU_NAME";
pub(crate) const SYSINFO_CPU_BRAND: &str = "VERGEN_SYSINFO_CPU_BRAND";
pub(crate) const SYSINFO_CPU_FREQUENCY: &str = "VERGEN_SYSINFO_CPU_FREQUENCY";

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constants_dont_change() {
        // Build Constants
        assert_eq!(BUILD_TIMESTAMP_NAME, "VERGEN_BUILD_TIMESTAMP");
        assert_eq!(BUILD_DATE_NAME, "VERGEN_BUILD_DATE");

        // git Constants
        assert_eq!(GIT_BRANCH_NAME, "VERGEN_GIT_BRANCH");
        assert_eq!(GIT_SHA_NAME, "VERGEN_GIT_SHA");
        assert_eq!(GIT_SHA_SHORT_NAME, "VERGEN_GIT_SHA_SHORT");
        assert_eq!(GIT_COMMIT_DATE_NAME, "VERGEN_GIT_COMMIT_DATE");
        assert_eq!(GIT_SEMVER_NAME, "VERGEN_GIT_SEMVER");
        assert_eq!(GIT_SEMVER_TAGS_NAME, "VERGEN_GIT_SEMVER_LIGHTWEIGHT");

        // rustc Constants
        assert_eq!(RUSTC_SEMVER_NAME, "VERGEN_RUSTC_SEMVER");
        assert_eq!(RUSTC_CHANNEL_NAME, "VERGEN_RUSTC_CHANNEL");
        assert_eq!(RUSTC_HOST_TRIPLE_NAME, "VERGEN_RUSTC_HOST_TRIPLE");
        assert_eq!(RUSTC_COMMIT_HASH, "VERGEN_RUSTC_COMMIT_HASH");
        assert_eq!(RUSTC_COMMIT_DATE, "VERGEN_RUSTC_COMMIT_DATE");
        assert_eq!(RUSTC_LLVM_VERSION, "VERGEN_RUSTC_LLVM_VERSION");

        // cargo Constants
        assert_eq!(CARGO_TARGET_TRIPLE, "VERGEN_CARGO_TARGET_TRIPLE");
        assert_eq!(CARGO_PROFILE, "VERGEN_CARGO_PROFILE");
        assert_eq!(CARGO_FEATURES, "VERGEN_CARGO_FEATURES");

        // sysinfo Constants
        assert_eq!(SYSINFO_NAME, "VERGEN_SYSINFO_NAME");
        assert_eq!(SYSINFO_OS_VERSION, "VERGEN_SYSINFO_OS_VERSION");
        assert_eq!(SYSINFO_USER, "VERGEN_SYSINFO_USER");
        assert_eq!(SYSINFO_MEMORY, "VERGEN_SYSINFO_TOTAL_MEMORY");
        assert_eq!(SYSINFO_CPU_VENDOR, "VERGEN_SYSINFO_CPU_VENDOR");
        assert_eq!(SYSINFO_CPU_CORE_COUNT, "VERGEN_SYSINFO_CPU_CORE_COUNT");
        assert_eq!(SYSINFO_CPU_NAME, "VERGEN_SYSINFO_CPU_NAME");
        assert_eq!(SYSINFO_CPU_BRAND, "VERGEN_SYSINFO_CPU_BRAND");
        assert_eq!(SYSINFO_CPU_FREQUENCY, "VERGEN_SYSINFO_CPU_FREQUENCY");
    }
}
