use crate::error::NetavarkResult;
use log::debug;
use std::fs::File;

pub fn ns_checks(file: &str) -> NetavarkResult<()> {
    debug!("{:?}", "Validating network namespace...");
    // TODO check for FS_MAGIC
    let _ = File::open(file)?.metadata()?;
    Ok(())
}
