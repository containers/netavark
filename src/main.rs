use clap::{crate_version, Clap};

use netavark::commands::setup;
use netavark::commands::teardown;

#[derive(Clap, Debug)]
#[clap(version = crate_version!())]
struct Opts {
    /// Instead of reading from STDIN, read the configuration to be applied from the given file.
    #[clap(short, long)]
    file: Option<String>,
    /// config directory for aardvark, usually path to a tmpfs.
    #[clap(short, long)]
    config: Option<String>,
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
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let opts = Opts::parse();

    let file = opts.file.unwrap_or_else(|| String::from("/dev/stdin"));
    // aardvark config directory must be supplied by parent or it defaults to /tmp/aardvark
    let config = opts.config.unwrap_or_else(|| String::from("/tmp/aardvark"));
    let result = match opts.subcmd {
        SubCommand::Setup(setup) => setup.exec(file, config),
        SubCommand::Teardown(teardown) => teardown.exec(file, config),
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
