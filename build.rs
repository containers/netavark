use chrono::{DateTime, NaiveDateTime, Utc};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let builder = tonic_build::configure()
        .type_attribute("netavark_proxy.Lease", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.DhcpV4Lease", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.DhcpV6Lease", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.IPResponse", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.MacAddress", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.NvIpv4Addr", "#[derive(serde::Serialize)]")
        .type_attribute("netavark_proxy.Lease", "#[derive(serde::Deserialize)]")
        .type_attribute(
            "netavark_proxy.DhcpV4Lease",
            "#[derive(serde::Deserialize)]",
        )
        .type_attribute(
            "netavark_proxy.DhcpV6Lease",
            "#[derive(serde::Deserialize)]",
        )
        .type_attribute("netavark_proxy.IPResponse", "#[derive(serde::Deserialize)]")
        .type_attribute("netavark_proxy.MacAddress", "#[derive(serde::Deserialize)]")
        .type_attribute("netavark_proxy.NvIpv4Addr", "#[derive(serde::Deserialize)]")
        .type_attribute("netavark_proxy.MacAddress", "#[derive(Eq)]")
        .type_attribute("netavark_proxy.MacAddress", "#[derive(Hash)]")
        .type_attribute(
            "netavark_proxy.NetworkConfig",
            "#[derive(serde::Deserialize)]",
        )
        .type_attribute(
            "netavark_proxy.NetworkConfig",
            "#[derive(serde::Serialize)]",
        )
        .out_dir(PathBuf::from("src/proto-build"));

    builder
        .compile(&[Path::new("src/proto/proxy.proto")], &[Path::new("proto")])
        .unwrap_or_else(|e| panic!("Failed at builder: {:?}", e.to_string()));

    // Generate the default 'cargo:' instruction output
    println!("cargo:rerun-if-changed=build.rs");

    // get timestamp
    let now = match env::var("SOURCE_DATE_EPOCH") {
        Ok(val) => {
            let naive = match NaiveDateTime::from_timestamp_opt(val.parse::<i64>().unwrap(), 0) {
                Some(n) => n,
                None => Utc::now().naive_utc(),
            };
            let datetime: DateTime<Utc> = DateTime::from_utc(naive, Utc);
            datetime
        }
        Err(_) => Utc::now(),
    };
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", now.to_rfc3339());

    // get rust target triple from TARGET env
    println!(
        "cargo:rustc-env=BUILD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );

    // get git commit
    let command = Command::new("git").args(["rev-parse", "HEAD"]).output();
    let commit = match command {
        Ok(output) => String::from_utf8(output.stdout).unwrap(),
        // if error, e.g. build from source without git repo, just show empty string
        Err(_) => "".to_string(),
    };
    println!("cargo:rustc-env=GIT_COMMIT={commit}");
}
