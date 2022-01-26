use anyhow::Result;
use vergen::{vergen, Config};

fn main() -> Result<()> {
    // Generate the default 'cargo:' instruction output
    vergen(Config::default())
}
