use clap::{Parser, Subcommand};

use netavark::commands::dhcp_proxy;
use netavark::commands::setup;
use netavark::commands::teardown;
use netavark::commands::update;
use netavark::commands::version;

#[derive(Parser, Debug)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
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
    /// Path to netavark plugin directories, can be set multiple times to specify more than one directory.
    #[clap(long, long = "plugin-directory")]
    plugin_directories: Option<Vec<String>>,
    /// Netavark trig command
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Configures the given network namespace with the given configuration.
    Setup(setup::Setup),
    /// Updates network dns servers for an already configured network.
    Update(update::Update),
    /// Undo any configuration applied via setup command.
    Teardown(teardown::Teardown),
    /// Display info about netavark.
    Version(version::Version),
    /// Start dhcp-proxy
    DHCPProxy(dhcp_proxy::Opts),
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let opts = Opts::parse();

    // aardvark config directory must be supplied by parent or it defaults to /tmp/aardvark
    let config = opts.config.as_deref().unwrap_or("/tmp");
    let rootless = opts.rootless.unwrap_or(false);
    let aardvark_bin = opts
        .aardvark_binary
        .unwrap_or_else(|| String::from("/usr/libexec/podman/aardvark-dns"));
    let result = match opts.subcmd {
        SubCommand::Setup(setup) => setup.exec(
            opts.file,
            config,
            aardvark_bin,
            opts.plugin_directories,
            rootless,
        ),
        SubCommand::Teardown(teardown) => teardown.exec(
            opts.file,
            config,
            aardvark_bin,
            opts.plugin_directories,
            rootless,
        ),
        SubCommand::Update(mut update) => update.exec(config, aardvark_bin, rootless),
        SubCommand::Version(version) => version.exec(),
        SubCommand::DHCPProxy(proxy) => dhcp_proxy::serve(proxy),
    };

    match result {
        Ok(_) => {}
        Err(err) => {
            err.print_json();
            std::process::exit(err.get_exit_code());
        }
    }
}

#[cfg(test)]
mod test;
