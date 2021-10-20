use clap::{crate_version, Clap};

use netavark::commands::setup;
use netavark::commands::teardown;

#[derive(Clap, Debug)]
#[clap(version = crate_version!())]
struct Opts {
    /// Instead of reading from STDIN, read the configuration to be applied from the given file.
    #[clap(short, long)]
    file: Option<String>,
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
    env_logger::init();
    let opts = Opts::parse();

    let file = opts.file.unwrap_or_else(|| String::from("/dev/stdin"));

    match opts.subcmd {
        SubCommand::Setup(setup) => setup.exec(file),
        SubCommand::Teardown(teardown) => teardown.exec(file),
    }
}

#[cfg(test)]
mod test;
