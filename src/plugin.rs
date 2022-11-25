use std::{collections::HashMap, env, error::Error, io};

use serde::Serialize;

use crate::{error, network::types};

pub const API_VERSION: &str = "1.0.0";

// create new boxed error with string error message, also accepts format!() style arguments
#[macro_export]
macro_rules! new_error {
    ($msg:ident) => {
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, $msg))
    };
    ($($arg:tt)*) => {{
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!($($arg)*)))
    }};
}

/// Contains info about this plugin
#[derive(Serialize)]
pub struct Info {
    /// The version of this plugin.
    version: String,
    // The api version for the netavark plugin API.
    api_version: String,
    /// Optional fields you want to be displayed for the info command
    #[serde(flatten)]
    extra_info: Option<HashMap<String, String>>,
}

impl Info {
    pub fn new(
        version: String,
        api_version: String,
        extra_info: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            version,
            api_version,
            extra_info,
        }
    }
}

/// Define the plugin functions
pub trait Plugin {
    // create a network config
    fn create(&self, network: types::Network) -> Result<types::Network, Box<dyn Error>>;
    /// set up the network configuration
    fn setup(
        &self,
        netns: String,
        opts: types::NetworkPluginExec,
    ) -> Result<types::StatusBlock, Box<dyn Error>>;
    /// tear down the network configuration
    fn teardown(&self, netns: String, opts: types::NetworkPluginExec)
        -> Result<(), Box<dyn Error>>;
}

pub struct PluginExec<P: Plugin> {
    plugin: P,
    info: Info,
}

impl<P: Plugin> PluginExec<P> {
    pub fn new(plugin: P, info: Info) -> Self {
        PluginExec { plugin, info }
    }

    pub fn exec(&self) {
        match self.inner_exec() {
            Ok(_) => {}
            Err(err) => {
                let e = error::JsonError {
                    error: err.to_string(),
                };
                serde_json::to_writer(io::stdout(), &e)
                    .unwrap_or_else(|e| println!("failed to write json error: {}: {}", e, err));
                std::process::exit(1);
            }
        };
    }

    fn inner_exec(&self) -> Result<(), Box<dyn Error>> {
        let mut args = env::args();
        args.next()
            .ok_or_else(|| new_error!("zero arguments given"))?;

        // match subcommand
        match args.next().as_deref() {
            Some("create") => {
                let mut network = serde_json::from_reader(io::stdin())?;

                network = self.plugin.create(network)?;

                serde_json::to_writer(io::stdout(), &network)?;
            }
            Some("setup") => {
                let netns = args
                    .next()
                    .ok_or_else(|| new_error!("netns path argument is missing"))?;

                let opts = serde_json::from_reader(io::stdin())?;

                let status_block = self.plugin.setup(netns, opts)?;
                serde_json::to_writer(io::stdout(), &status_block)?;
            }
            Some("teardown") => {
                let netns = args
                    .next()
                    .ok_or_else(|| new_error!("netns path argument is missing"))?;

                let opts = serde_json::from_reader(io::stdin())?;
                self.plugin.teardown(netns, opts)?;
            }
            Some("info") => self.print_info()?,
            Some(unknown) => {
                return Err(new_error!("unknown subcommand: {}", unknown));
            }
            None => self.print_info()?,
        };
        Ok(())
    }

    fn print_info(&self) -> Result<(), Box<dyn Error>> {
        serde_json::to_writer(io::stdout(), &self.info)?;
        Ok(())
    }
}
