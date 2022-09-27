use chrono::{DateTime, NaiveDateTime, Utc};
use std::env;
use std::process::Command;

fn main() {
    // Generate the default 'cargo:' instruction output
    println!("cargo:rerun-if-changed=build.rs");

    // get timestamp
    let now = match env::var("SOURCE_DATE_EPOCH") {
        Ok(val) => {
            let naive = NaiveDateTime::from_timestamp(val.parse::<i64>().unwrap(), 0);
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
    let command = Command::new("git").args(&["rev-parse", "HEAD"]).output();
    let commit = match command {
        Ok(output) => String::from_utf8(output.stdout).unwrap(),
        // if error, e.g. build from source with git repo, just show empty string
        Err(_) => "".to_string(),
    };
    println!("cargo:rustc-env=GIT_COMMIT={}", commit);
}
