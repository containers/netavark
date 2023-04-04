use clap::{Parser, Subcommand};
use commands::{setup, teardown};
use std::process;
use tonic::{Code, Status};

use netavark::dhcp_proxy::lib::g_rpc::{Lease, NetworkConfig};
use netavark::dhcp_proxy::proxy_conf::{DEFAULT_NETWORK_CONFIG, DEFAULT_UDS_PATH};
use netavark::error::NetavarkError;

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
        SubCommand::Setup(_) => {
            let s = setup::Setup::new(input_config);
            s.exec(&uds_path).await
        }
        SubCommand::Teardown(_) => {
            let t = teardown::Teardown::new(input_config);
            t.exec(&uds_path).await
        }
    };
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            match e {
                NetavarkError::DHCPProxy(status) => process_failure(status),
                _ => process::exit(1),
            }
        }
    };

    let pp = ::serde_json::to_string_pretty(&r);
    // TODO this should probably return an empty lease so consumers
    // don't soil themselves
    println!("{}", pp.unwrap_or_else(|_| "".to_string()));
    Ok(())
}

//
// process_failure makes the client exit with a specific
// error code
//
fn process_failure(status: Status) -> Lease {
    let mut rc: i32 = 1;

    match status.code() {
        Code::Unknown => {
            rc = 155;
        }
        Code::InvalidArgument => {
            rc = 156;
        }
        Code::DeadlineExceeded => {}
        Code::NotFound => {
            rc = 6;
        }
        _ => {}
    }
    process::exit(rc)
}
