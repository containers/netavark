use crate::network::types;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nix::{
    sys::wait::waitpid,
    unistd::{fork, ForkResult},
};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

const AARDVARK_BINARY: [&str; 1] = ["/usr/libexec/podman/aardvark-dns"];

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
}

impl Aardvark {
    pub fn new(config: String, rootless: bool) -> Self {
        Aardvark { config, rootless }
    }

    pub fn check_aardvark_support() -> bool {
        for key in AARDVARK_BINARY {
            if Path::new(key).exists() {
                return true;
            }
        }
        log::debug!("No aardvark support found");
        false
    }

    // On success retuns aardvark server's pid or returns -1;
    fn get_aardvark_pid(&mut self) -> i32 {
        let pid: i32;
        let path = Path::new(&self.config).join("aardvark.pid".to_string());
        match fs::read_to_string(&path) {
            Ok(content) => {
                pid = match content.parse::<i32>() {
                    Ok(val) => val,
                    Err(_) => {
                        return -1;
                    }
                }
            }
            Err(_) => {
                return -1;
            }
        }

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

    pub fn start_aardvark_server_if_not_running(&mut self) -> Result<()> {
        let aardvark_pid = self.get_aardvark_pid();
        if aardvark_pid != -1 {
            // check if pid is running
            match signal::kill(Pid::from_raw(aardvark_pid), Signal::SIGWINCH) {
                Ok(_) => {
                    log::debug!("Found aardvark server running");
                    // process is running do nothing
                    return Ok(());
                }
                _ => {
                    log::debug!("No aardvark server found of pid {}", aardvark_pid);
                }
            }
        }

        if !Path::new(&self.config).exists() {
            // silently try to create empty config dir if its not there
            let _ = fs::create_dir(&self.config);
        }

        log::debug!("Spawning aardvark server");

        // Why double fork ?
        // Its important that nature of aardvark server is more like a daemon
        // so following block ensures that aardvark server keeps on running even
        // if parent is killed
        //
        // setsid() ensures that there is no controlling terminal on the child process

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                log::debug!("starting aardvark on a child with pid {}", child);
                if let Err(err) = waitpid(Some(child), None) {
                    log::debug!("error while waiting for child pid {}", err);
                }
            }
            Ok(ForkResult::Child) => {
                if Aardvark::is_executable_in_path("systemd-run") {
                    // remove any controlling terminals
                    // but don't hardstop if this fails
                    let _ = unsafe { libc::setsid() }; // check https://docs.rs/libc

                    // TODO: This could be replaced by systemd-api.
                    let systemd_run_args = vec![
                        "--scope",
                        AARDVARK_BINARY[0],
                        "--config",
                        &self.config,
                        "-p",
                        "53",
                        "run",
                    ];

                    if self.rootless {
                        let mut rootless_systemd_args = vec!["-q", "--user"];
                        rootless_systemd_args.extend(&systemd_run_args);

                        Command::new("systemd-run")
                            .args(rootless_systemd_args)
                            .spawn()?;
                    } else {
                        let mut rootfull_systemd_args = vec!["-q"];
                        rootfull_systemd_args.extend(&systemd_run_args);
                        Command::new("systemd-run")
                            .args(rootfull_systemd_args)
                            .spawn()?;
                    }
                } else {
                    Command::new(AARDVARK_BINARY[0])
                        .args(["--config", &self.config, "-p", "53", "run"])
                        .spawn()?;
                }

                // exit child
                std::process::exit(0);
            }
            Err(err) => {
                log::debug!("fork failed with error {}", err);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("fork failed with error: {}", err),
                ));
            }
        }

        Ok(())
    }

    pub fn notify(&mut self) -> Result<()> {
        let aardvark_pid = self.get_aardvark_pid();
        if aardvark_pid != -1 {
            signal::kill(Pid::from_raw(aardvark_pid), Signal::SIGHUP)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid pid to notify",
            ));
        }

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
        let mut file: Option<File> = None;
        let data: String;
        let path = Path::new(&self.config).join(entry.network_name);
        // check if this is the first container in this network
        if !path.exists() {
            // create file
            // and write first line as gateway ip
            let create = File::create(&path)?; // return error if fails
            let data: String;
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

            file = Some(create);
            file.as_ref().unwrap().write_all(data.as_bytes())?;
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

        if let Some(mut f) = file {
            f.write_all(data.as_bytes())?; //return error if write fails
        } else {
            let mut f = OpenOptions::new().append(true).open(&path)?; //return error if open fails
            f.write_all(data.as_bytes())?; // return error if write fails
        }

        Ok(())
    }

    pub fn commit_netavark_entries(
        &mut self,
        container_name: String,
        container_id: String,
        netavark_res: HashMap<String, types::StatusBlock>,
    ) -> Result<()> {
        let entries = Aardvark::netavark_response_to_aardvark_entries(
            container_name,
            container_id,
            netavark_res,
        );
        self.commit_entries(entries)?;
        self.notify()?;
        Ok(())
    }

    pub fn netavark_response_to_aardvark_entries(
        container_name: String,
        container_id: String,
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

                                            result.push(AardvarkEntry {
                                                network_name: network_name.clone(),
                                                network_gateway_v4,
                                                network_gateway_v6,
                                                container_id: container_id.clone(),
                                                container_ip_v6,
                                                container_ip_v4,
                                                container_name: Vec::from([container_name.clone()]),
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
            self.notify()?;
        }
        Ok(())
    }
}
