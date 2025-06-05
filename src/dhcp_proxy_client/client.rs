use clap::{Parser, Subcommand};
use commands::{setup, teardown};
use std::process;

use netavark::dhcp_proxy::lib::g_rpc::NetworkConfig;
use netavark::dhcp_proxy::proxy_conf::{DEFAULT_NETWORK_CONFIG, DEFAULT_UDS_PATH};

pub mod commands;

#[derive(Parser, Debug)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    /// Use specific uds path
    #[clap(short, long)]
    uds: Option<String>,
    /// Instead of reading from STDIN, read the configuration to be applied from the given file.
    #[clap(short, long)]
    file: Option<String>,
    /// Netavark trig command
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Configures the given network namespace with the given configuration.
    Setup(setup::Setup),
    /// Undo any configuration applied via setup command.
    Teardown(teardown::Teardown),
    // Display info about netavark.
    // Version(version::Version),
}

#[cfg(unix)]
#[tokio::main]
// This client assumes you use the default lease directory
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // This should be moved to somewhere central.  We also need to add override logic.
    env_logger::builder().format_timestamp(None).init();
    let opts = Opts::parse();
    let file = opts
        .file
        .unwrap_or_else(|| DEFAULT_NETWORK_CONFIG.to_string());
    let uds_path = opts.uds.unwrap_or_else(|| DEFAULT_UDS_PATH.to_string());
    let input_config = NetworkConfig::load(&file)?;
    let result = match opts.subcmd {
        SubCommand::Setup(s) => s.exec(&uds_path, input_config).await,
        SubCommand::Teardown(t) => t.exec(&uds_path, input_config).await,
    };
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let pp = ::serde_json::to_string_pretty(&r);
    // TODO this should probably return an empty lease so consumers
    // don't soil themselves
    println!("{}", pp.unwrap_or_else(|_| "".to_string()));
    Ok(())
}
