use log::debug;
use std::fs::File;

pub fn ns_checks(file: &str) -> std::io::Result<()> {
    debug!("{:?}", "Validating network namespace...");
    // TODO check for FS_MAGIC
    let _ = File::open(&file)?.metadata()?;
    Ok(())
}
