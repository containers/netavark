use faccess::{AccessMode, PathExt};
use log::debug;
use std::path::Path;

pub fn ns_checks(file: &str) -> std::io::Result<()> {
    debug!("{:?}", "Checking network namespace permissions...");
    // TODO check for FS_MAGIC
    Path::new(&file).access(AccessMode::EXISTS & AccessMode::WRITE)
}
