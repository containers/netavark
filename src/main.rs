use clap::{crate_version, Clap};

use netavark::commands::setup;
use netavark::commands::teardown;
use netavark::commands::version;

#[derive(Clap, Debug)]
#[clap(version = crate_version!())]
struct Opts {
    /// Instead of reading from STDIN, read the configuration to be applied from the given file.
    #[clap(short, long)]
    file: Option<String>,
    /// config directory for aardvark, usually path to a tmpfs.
    #[clap(short, long)]
    config: Option<String>,
    /// Tells if current netavark invocation is for rootless container.
    #[clap(short, long)]
    rootless: Option<bool>,
    #[clap(short, long)]
    /// Path to the aardvark-dns binary.
    aardvark_binary: Option<String>,
    /// Netavark trig command
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap(version = crate_version!())]
    /// Configures the given network namespace with the given configuration.
    Setup(setup::Setup),
    #[clap(version = crate_version!())]
    /// Undo any configuration applied via setup command.
    Teardown(teardown::Teardown),

    /// Display info about netavark.
    Version(version::Version),
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let opts = Opts::parse();

    let file = opts.file.unwrap_or_else(|| String::from("/dev/stdin"));
    // aardvark config directory must be supplied by parent or it defaults to /tmp/aardvark
    let config = opts.config.unwrap_or_else(|| String::from("/tmp"));
    let rootless = opts.rootless.unwrap_or(false);
    let aardvark_bin = opts
        .aardvark_binary
        .unwrap_or_else(|| String::from("/usr/libexec/podman/aardvark-dns"));
    let result = match opts.subcmd {
        SubCommand::Setup(setup) => setup.exec(file, config, aardvark_bin, rootless),
        SubCommand::Teardown(teardown) => teardown.exec(file, config, rootless),
        SubCommand::Version(version) => version.exec(),
    };

    match result {
        Ok(_) => {}
        Err(err) => {
            let er = netavark::error::NetavarkError {
                error: format!("{}", err),
                errno: 1,
            };
            er.print_json();
            std::process::exit(er.errno);
        }
    }
}

#[cfg(test)]
mod test;
