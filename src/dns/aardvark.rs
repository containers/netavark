use crate::network::constants::DRIVER_BRIDGE;
use crate::network::types;

use fs2::FileExt;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Result;
use std::io::{prelude::*, ErrorKind};
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};

const SYSTEMD_CHECK_PATH: &str = "/run/systemd/system";
const SYSTEMD_RUN: &str = "systemd-run";
const AARDVARK_COMMIT_LOCK: &str = "aardvark.lock";

#[derive(Clone, Debug)]
pub struct AardvarkEntry<'a> {
    pub network_name: &'a str,
    pub network_gateways: Vec<IpAddr>,
    pub network_dns_servers: &'a Option<Vec<IpAddr>>,
    pub container_id: &'a str,
    pub container_ips_v4: Vec<Ipv4Addr>,
    pub container_ips_v6: Vec<Ipv6Addr>,
    pub container_names: Vec<String>,
    pub container_dns_servers: &'a Option<Vec<IpAddr>>,
}

#[derive(Debug, Clone)]
pub struct Aardvark {
    /// aardvark's config directory
    pub config: String,
    /// tells if container is rootfull or rootless
    pub rootless: bool,
    /// path to the aardvark-dns binary
    pub aardvark_bin: String,
    /// port to bind to
    pub port: String,
}

impl Aardvark {
    pub fn new(config: String, rootless: bool, aardvark_bin: String, port: u16) -> Self {
        Aardvark {
            config,
            rootless,
            aardvark_bin,
            port: port.to_string(),
        }
    }

    /// On success retuns aardvark server's pid or returns -1;
    fn get_aardvark_pid(&self) -> i32 {
        let path = Path::new(&self.config).join("aardvark.pid");
        let pid: i32 = match fs::read_to_string(path) {
            Ok(content) => match content.parse::<i32>() {
                Ok(val) => val,
                Err(_) => {
                    return -1;
                }
            },
            Err(_) => {
                return -1;
            }
        };

        pid
    }

    fn is_executable_in_path(program: &str) -> bool {
        if let Ok(path) = std::env::var("PATH") {
            for p in path.split(':') {
                let p_str = format!("{}/{}", p, program);
                if fs::metadata(p_str).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    pub fn start_aardvark_server(&self) -> Result<()> {
        log::debug!("Spawning aardvark server");

        let mut aardvark_args = vec![];
        // only use systemd when it is booted, see sd_booted(3)
        if Path::new(SYSTEMD_CHECK_PATH).exists() && Aardvark::is_executable_in_path(SYSTEMD_RUN) {
            // TODO: This could be replaced by systemd-api.
            aardvark_args = vec![SYSTEMD_RUN, "-q", "--scope"];

            if self.rootless {
                aardvark_args.push("--user");
            }
        }

        aardvark_args.extend(vec![
            self.aardvark_bin.as_str(),
            "--config",
            &self.config,
            "-p",
            &self.port,
            "run",
        ]);

        log::debug!("start aardvark-dns: {:?}", aardvark_args);

        // After https://github.com/containers/aardvark-dns/pull/148 this command
        // will block till aardvark-dns's parent process returns back and let
        // aardvark inherit all the fds.
        Command::new(aardvark_args[0])
            .args(&aardvark_args[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            // set RUST_LOG for aardvark
            .env("RUST_LOG", log::max_level().as_str())
            .output()?;

        Ok(())
    }

    pub fn notify(&self, start: bool) -> Result<()> {
        let aardvark_pid = self.get_aardvark_pid();
        if aardvark_pid != -1 {
            match signal::kill(Pid::from_raw(aardvark_pid), Signal::SIGHUP) {
                Ok(_) => return Ok(()),
                Err(err) => {
                    // ESRCH == process does not exists
                    if err != nix::errno::Errno::ESRCH {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("failed to send SIGHUP to aardvark: {}", err),
                        ));
                    }
                }
            }
        }
        if !start {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "aardvark pid not found",
            ));
        }
        self.start_aardvark_server()?;

        Ok(())
    }
    pub fn commit_entries(&self, entries: Vec<AardvarkEntry>) -> Result<()> {
        // Acquire fs lock to ensure other instance of aardvark cannot commit
        // or start aardvark instance till already running instance has not
        // completed its `commit` phase.
        let lockfile_path = Path::new(&self.config)
            .join("..")
            .join(AARDVARK_COMMIT_LOCK);
        let lockfile = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&lockfile_path)
        {
            Ok(file) => file,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to open/create lockfile {:?}: {}", &lockfile_path, e),
                ));
            }
        };
        if let Err(er) = lockfile.lock_exclusive() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to acquire exclusive lock on {:?}: {}",
                    lockfile_path, er
                ),
            ));
        }

        for entry in &entries {
            let path = Path::new(&self.config).join(entry.network_name);

            let file = match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    // collect gateway
                    let gws = entry
                        .network_gateways
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<Vec<String>>()
                        .join(",");

                    // collect network dns servers if specified
                    let network_dns_servers =
                        if let Some(network_dns_servers) = &entry.network_dns_servers {
                            if !network_dns_servers.is_empty() {
                                let dns_server_collected = network_dns_servers
                                    .iter()
                                    .map(|g| g.to_string())
                                    .collect::<Vec<String>>()
                                    .join(",");
                                format!(" {}", dns_server_collected)
                            } else {
                                "".to_string()
                            }
                        } else {
                            "".to_string()
                        };

                    let data = format!("{}{}\n", gws, network_dns_servers);
                    f.write_all(data.as_bytes())?; // return error if write fails
                    f
                }
                Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
                    OpenOptions::new().append(true).open(&path)?
                }
                Err(e) => {
                    return Err(e);
                }
            };
            match Aardvark::commit_entry(entry, file) {
                Err(er) => {
                    // drop lockfile when commit is completed
                    if let Err(er) = lockfile.unlock() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "Failed to unlock exclusive lock on {:?}: {}",
                                lockfile_path, er
                            ),
                        ));
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to commit entry {:?}: {}", entry, er),
                    ));
                }
                Ok(_) => continue,
            }
        }

        // drop lockfile when commit is completed
        if let Err(er) = lockfile.unlock() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to unlock exclusive lock on {:?}: {}",
                    lockfile_path, er
                ),
            ));
        }
        Ok(())
    }

    fn commit_entry(entry: &AardvarkEntry, mut file: File) -> Result<()> {
        let container_names = entry.container_names.join(",");

        let ipv4s = entry
            .container_ips_v4
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<String>>()
            .join(",");

        let ipv6s = entry
            .container_ips_v6
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<String>>()
            .join(",");

        let dns_server = if let Some(dns_servers) = &entry.container_dns_servers {
            if !dns_servers.is_empty() {
                let dns_server_collected = dns_servers
                    .iter()
                    .map(|g| g.to_string())
                    .collect::<Vec<String>>()
                    .join(",");
                format!(" {}", dns_server_collected)
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        let data = format!(
            "{} {} {} {}{}\n",
            entry.container_id, ipv4s, ipv6s, container_names, dns_server
        );

        file.write_all(data.as_bytes())?; // return error if write fails

        Ok(())
    }

    pub fn commit_netavark_entries(&self, entries: Vec<AardvarkEntry>) -> Result<()> {
        if !entries.is_empty() {
            self.commit_entries(entries)?;
            self.notify(true)?;
        }
        Ok(())
    }

    pub fn delete_entry(&self, container_id: &str, network_name: &str) -> Result<()> {
        let path = Path::new(&self.config).join(network_name);
        let file_content = fs::read_to_string(&path)?;
        let lines: Vec<&str> = file_content.split_terminator('\n').collect();

        let mut idx = 0;
        let mut file = File::create(&path)?;

        for line in lines {
            if line.contains(container_id) {
                continue;
            }
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
            idx += 1;
        }
        // nothing left in file (only header), remove it
        if idx <= 1 {
            fs::remove_file(&path)?
        }
        Ok(())
    }

    // Modifies network dns_servers for a specific network and notifies aardvark-dns server
    // with the change.
    pub fn modify_network_dns_servers(
        &self,
        network_name: &str,
        network_dns_servers: &Vec<String>,
    ) -> Result<()> {
        let mut dns_servers_modified = false;
        let path = Path::new(&self.config).join(network_name);
        let file_content = fs::read_to_string(&path)?;

        let mut file = File::create(&path)?;

        //for line in lines {
        for (idx, line) in file_content.split_terminator('\n').enumerate() {
            if idx == 0 {
                // If this is first line, we have to modify this
                // first line has a format of `<BINDIP>... <NETWORK_DNSSERVERS>..`
                // We will read the first line and get the first coloumn and
                // override the second coloumn with new network dns servers.
                let network_parts = line.split(' ').collect::<Vec<&str>>();
                if network_parts.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid network configuration file: {}", path.display()),
                    ));
                }
                let network_dns_servers_collected = if !network_dns_servers.is_empty() {
                    dns_servers_modified = true;
                    let dns_server_collected = network_dns_servers
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
                    format!(" {}", dns_server_collected)
                } else {
                    "".to_string()
                };
                // Modify line to support new format
                let content = format!("{}{}", network_parts[0], network_dns_servers_collected);
                file.write_all(content.as_bytes())?;
            } else {
                file.write_all(line.as_bytes())?;
            }
            file.write_all(b"\n")?;
        }

        // If dns servers were updated notify the aardvark-dns server
        // if refresh is needed.
        if dns_servers_modified {
            self.notify(false)?;
        }

        Ok(())
    }

    pub fn delete_from_netavark_entries(
        &self,
        network_options: &types::NetworkOptions,
    ) -> Result<()> {
        let mut modified = false;
        for (key, network) in &network_options.network_info {
            if network.dns_enabled && network.driver == DRIVER_BRIDGE {
                modified = true;
                self.delete_entry(&network_options.container_id, key)?;
            }
        }
        if modified {
            self.notify(false)?;
        }
        Ok(())
    }
}
