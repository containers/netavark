use faccess::{AccessMode, PathExt};
use log::debug;
use std::path::Path;

pub fn ns_checks(file: &str) -> bool {
    debug!("{:?}", "Checking network namespace permissions...");
    let path_validate = Path::new(&file)
        .access(AccessMode::EXISTS & AccessMode::WRITE)
        .is_ok();
    path_validate
}
