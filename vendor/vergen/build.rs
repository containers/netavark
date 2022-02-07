use chrono::Utc;

pub fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // These are here so some doc tests work
    let now = Utc::now();
    println!(
        "cargo:rustc-env=VERGEN_BUILD_TIMESTAMP={}",
        now.to_rfc3339()
    );
    println!("cargo:rustc-env=VERGEN_GIT_SEMVER=v3.2.0-86-g95fc0f5");
    nightly_lints();
    beta_lints();
    stable_lints();
    msrv_lints();
}

#[rustversion::nightly]
fn nightly_lints() {
    println!("cargo:rustc-cfg=nightly_lints");
}

#[rustversion::not(nightly)]
fn nightly_lints() {}

#[rustversion::beta]
fn beta_lints() {
    println!("cargo:rustc-cfg=beta_lints");
}

#[rustversion::not(beta)]
fn beta_lints() {}

#[rustversion::stable]
fn stable_lints() {
    println!("cargo:rustc-cfg=stable_lints");
}

#[rustversion::not(stable)]
fn stable_lints() {}

#[rustversion::before(1.58)]
fn msrv_lints() {}

#[rustversion::since(1.58)]
fn msrv_lints() {
    println!("cargo:rustc-cfg=msrv");
}
