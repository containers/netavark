use crate::network::types;
use log::log_enabled;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{thread, time};

const SYSTEMD_CHECK_PATH: &str = "/run/systemd/system";
const SYSTEMD_RUN: &str = "systemd-run";

#[derive(Debug, Clone)]
pub struct AardvarkEntry {
    pub network_name: String,
    pub network_gateway_v4: String,
    pub network_gateway_v6: String,
    pub container_id: String,
    pub container_ip_v4: String,
    pub container_ip_v6: String,
    pub container_name: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Aardvark {
    // aardvark's config directory
    pub config: String,
    // tells if container is rootfull or rootless
    pub rootless: bool,
    // path to the aardvark-dns binary
    pub aardvark_bin: String,
}

impl Aardvark {
    pub fn new(config: String, rootless: bool, aardvark_bin: String) -> Self {
        Aardvark {
            config,
            rootless,
            aardvark_bin,
        }
    }

    // On success retuns aardvark server's pid or returns -1;
    fn get_aardvark_pid(&mut self) -> i32 {
        let path = Path::new(&self.config).join("aardvark.pid");
        let pid: i32 = match fs::read_to_string(&path) {
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

    pub fn start_aardvark_server(&mut self) -> Result<()> {
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
            "53",
            "run",
        ]);

        log::debug!("start aardvark-dns: {:?}", aardvark_args);

        let output = match log_enabled!(log::Level::Debug) {
            true => Stdio::inherit(),
            false => Stdio::null(),
        };

        Command::new(&aardvark_args[0])
            .args(&aardvark_args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(output)
            // set RUST_LOG for aardvark
            .env("RUST_LOG", log::max_level().as_str())
            .spawn()?;

        // Starting aardvark server is the last task for netavark so in some env
        // setup netavark will end up exiting way sooner then aardvark process
        // is actually ready to serve so after starting aardvark we have to wait
        // till aardvark process is ready. If it does not shows up atleast retry
        // 10 times with a delay of 500ms and then return.
        let mut retry_count = 10;
        while retry_count > 0 {
            let aardvark_pid = self.get_aardvark_pid();
            if aardvark_pid != -1
                && signal::kill(Pid::from_raw(aardvark_pid), Signal::SIGHUP).is_ok()
            {
                break;
            }
            let duration_millis = time::Duration::from_millis(500);
            thread::sleep(duration_millis);
            retry_count -= 1;
        }

        Ok(())
    }

    pub fn notify(&mut self, start: bool) -> Result<()> {
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
    pub fn commit_entries(&mut self, entries: Vec<AardvarkEntry>) -> Result<()> {
        for entry in entries {
            match self.commit_entry(entry.clone()) {
                Err(er) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to commit entry {:?}: {}", entry, er),
                    ));
                }
                Ok(_) => continue,
            }
        }

        Ok(())
    }

    pub fn commit_entry(&mut self, entry: AardvarkEntry) -> Result<()> {
        let mut data: String;
        let path = Path::new(&self.config).join(entry.network_name);
        let file_exists = path.exists();
        let mut file = OpenOptions::new().append(true).create(true).open(&path)?;
        // check if this is the first container in this network
        if !file_exists {
            // write first line as gateway ip
            if !entry.network_gateway_v4.is_empty() && !entry.network_gateway_v6.is_empty() {
                data = format!(
                    "{},{}\n",
                    entry.network_gateway_v4, entry.network_gateway_v6
                );
            } else if !entry.network_gateway_v4.is_empty() {
                data = format!("{}\n", entry.network_gateway_v4);
            } else {
                data = format!("{}\n", entry.network_gateway_v6);
            }
            file.write_all(data.as_bytes())?;
        }

        let container_names = entry
            .container_name
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        data = format!(
            "{} {} {} {}\n",
            entry.container_id, entry.container_ip_v4, entry.container_ip_v6, container_names
        );

        file.write_all(data.as_bytes())?; // return error if write fails

        Ok(())
    }

    pub fn commit_netavark_entries(
        &mut self,
        container_name: String,
        container_id: String,
        per_network_opts: HashMap<String, types::PerNetworkOptions>,
        netavark_res: HashMap<String, types::StatusBlock>,
    ) -> Result<()> {
        let entries = Aardvark::netavark_response_to_aardvark_entries(
            container_name,
            container_id,
            per_network_opts,
            netavark_res,
        );
        if !entries.is_empty() {
            self.commit_entries(entries)?;
            self.notify(true)?;
        }
        Ok(())
    }

    pub fn netavark_response_to_aardvark_entries(
        container_name: String,
        container_id: String,
        per_network_opts: HashMap<String, types::PerNetworkOptions>,
        netavark_res: HashMap<String, types::StatusBlock>,
    ) -> Vec<AardvarkEntry> {
        let mut result: Vec<AardvarkEntry> = Vec::<AardvarkEntry>::new();
        for (key, network) in netavark_res {
            let network_name = key.clone();
            if let Some(dns_server_ips) = network.dns_server_ips {
                if !dns_server_ips.is_empty() {
                    match network.interfaces {
                        None => continue,
                        Some(interfaces) => {
                            for (_interface_name, interface) in interfaces {
                                match interface.subnets {
                                    Some(subnets) => {
                                        for subnet in subnets {
                                            let mut network_gateway_v4: String = "".to_string();
                                            let mut network_gateway_v6: String = "".to_string();
                                            let mut container_ip_v4: String = "".to_string();
                                            let mut container_ip_v6: String = "".to_string();
                                            let container_ip = subnet.ipnet.addr();
                                            let gateway = match subnet.gateway {
                                                Some(gateway) => gateway,
                                                None => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                            };

                                            if !gateway.is_unspecified() {
                                                if gateway.is_ipv4() {
                                                    network_gateway_v4 = gateway.to_string();
                                                } else {
                                                    network_gateway_v6 = gateway.to_string();
                                                }
                                            }

                                            if container_ip.is_ipv4() {
                                                container_ip_v4 = container_ip.to_string();
                                            } else {
                                                container_ip_v6 = container_ip.to_string();
                                            }

                                            let mut name_vector =
                                                Vec::from([container_name.clone()]);
                                            if let Some(network_opt) =
                                                &per_network_opts.get(&network_name)
                                            {
                                                if let Some(alias) = &network_opt.aliases {
                                                    let aliases = alias.clone();
                                                    name_vector.extend(aliases);
                                                }
                                            }

                                            result.push(AardvarkEntry {
                                                network_name: network_name.clone(),
                                                network_gateway_v4,
                                                network_gateway_v6,
                                                container_id: container_id.clone(),
                                                container_ip_v6,
                                                container_ip_v4,
                                                container_name: name_vector,
                                            });
                                        }
                                    }
                                    None => continue,
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    pub fn delete_entry(&mut self, container_id: String, network_name: String) -> Result<()> {
        let path = Path::new(&self.config).join(network_name);
        let file_content = fs::read_to_string(&path)?;
        let lines: Vec<&str> = file_content.split('\n').collect();

        let mut idx = 1;
        let mut file = File::create(&path)?;

        for line in &lines {
            if line.contains(&container_id) {
                if lines.len() <= 3 {
                    // delete the file and return
                    // since there is nothing in the network
                    fs::remove_file(&path)?;
                    return Ok(());
                }
                idx += 1;
                continue;
            }
            file.write_all(line.as_bytes())?;
            if idx < lines.len() {
                file.write_all(b"\n")?;
            }
            idx += 1;
        }
        Ok(())
    }

    pub fn delete_from_netavark_entries(
        &mut self,
        network_options: types::NetworkOptions,
    ) -> Result<()> {
        let mut modified = false;
        let container_id = network_options.container_id;
        for (key, network) in network_options.network_info {
            if network.dns_enabled {
                modified = true;
                self.delete_entry(container_id.clone(), key)?;
            }
        }
        if modified {
            self.notify(false)?;
        }
        Ok(())
    }
}
