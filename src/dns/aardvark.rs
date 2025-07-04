use crate::error::{NetavarkError, NetavarkResult};
use crate::network::core_utils::is_using_systemd;

use fs2::FileExt;
use libc::pid_t;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SYSTEMD_RUN: &str = "systemd-run";
const AARDVARK_COMMIT_LOCK: &str = "aardvark.lock";

/// For better safety we wrap &str in our own custom type here
/// where we can enforce that the caller can only construct it
/// via the TryFrom trait. With that we can guarantee via the
/// type system that we never get invalid chars here when we
/// write the config file.
#[derive(Debug)]
pub struct SafeString<'a>(&'a str);

impl<'a> TryFrom<&'a str> for SafeString<'a> {
    type Error = &'static str;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("name is empty");
        }
        if value.contains([',', '\n', ' ']) {
            Err("name contains invalid chars")
        } else {
            Ok(SafeString(value))
        }
    }
}

#[derive(Debug)]
pub struct AardvarkEntry<'a> {
    pub network_name: &'a str,
    pub network_gateways: Vec<IpAddr>,
    pub network_dns_servers: &'a Option<Vec<IpAddr>>,
    pub container_id: SafeString<'a>,
    pub container_ips_v4: Vec<Ipv4Addr>,
    pub container_ips_v6: Vec<Ipv6Addr>,
    pub container_names: Vec<SafeString<'a>>,
    pub container_dns_servers: &'a Option<Vec<IpAddr>>,
    pub is_internal: bool,
}

#[derive(Debug, Clone)]
pub struct Aardvark {
    /// aardvark's config directory
    pub config: PathBuf,
    /// tells if container is rootfull or rootless
    pub rootless: bool,
    /// path to the aardvark-dns binary
    pub aardvark_bin: OsString,
    /// port to bind to
    pub port: OsString,
}

impl Aardvark {
    pub fn new(config: PathBuf, rootless: bool, aardvark_bin: OsString, port: u16) -> Self {
        Aardvark {
            config,
            rootless,
            aardvark_bin,
            port: port.to_string().into(),
        }
    }

    /// On success returns aardvark server's pid or returns -1;
    fn get_aardvark_pid(&self) -> NetavarkResult<pid_t> {
        let path = Path::new(&self.config).join("aardvark.pid");
        let pid: i32 = match fs::read_to_string(path) {
            Ok(content) => match content.parse::<pid_t>() {
                Ok(val) => val,
                Err(e) => {
                    return Err(NetavarkError::msg(format!("parse aardvark pid: {e}")));
                }
            },
            Err(e) => {
                return Err(NetavarkError::Io(e));
            }
        };

        Ok(pid)
    }

    fn is_executable_in_path(program: &str) -> bool {
        if let Ok(path) = std::env::var("PATH") {
            for p in path.split(':') {
                let p_str = format!("{p}/{program}");
                if fs::metadata(p_str).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    pub fn start_aardvark_server(&self) -> NetavarkResult<()> {
        log::debug!("Spawning aardvark server");

        let mut aardvark_args = vec![];
        // only use systemd when it is booted
        if is_using_systemd() && Aardvark::is_executable_in_path(SYSTEMD_RUN) {
            // TODO: This could be replaced by systemd-api.
            aardvark_args = vec![
                OsStr::new(SYSTEMD_RUN),
                OsStr::new("-q"),
                OsStr::new("--scope"),
            ];

            if self.rootless {
                aardvark_args.push(OsStr::new("--user"));
            }
        }

        aardvark_args.extend(vec![
            self.aardvark_bin.as_os_str(),
            OsStr::new("--config"),
            self.config.as_os_str(),
            OsStr::new("-p"),
            self.port.as_os_str(),
            OsStr::new("run"),
        ]);

        log::debug!("start aardvark-dns: {aardvark_args:?}");

        // After https://github.com/containers/aardvark-dns/pull/148 this command
        // will block till aardvark-dns's parent process returns back and let
        // aardvark inherit all the fds.
        let out = Command::new(aardvark_args[0])
            .args(&aardvark_args[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // set RUST_LOG for aardvark
            .env("RUST_LOG", log::max_level().as_str())
            .output()?;

        if out.status.success() {
            return Ok(());
        }
        if out.stderr.is_empty() {
            return Err(NetavarkError::msg(
                "aardvark-dns exited unexpectedly without error message",
            ));
        }
        // aardvark-dns failed capture stderr
        let msg = String::from_utf8(out.stderr).map_err(|e| {
            NetavarkError::msg(format!("failed to parse aardvark-dns stderr message: {e}"))
        })?;

        Err(NetavarkError::msg(format!(
            "aardvark-dns failed to start: {}",
            msg.trim()
        )))
    }

    fn check_netns(&self, pid: pid_t) {
        // This should never fail but ignore errors anyway
        let cur_ns = match fs::read_link("/proc/self/ns/net") {
            Ok(p) => p,
            Err(_) => return,
        };
        // This might fail
        let aardvark_ns = match fs::read_link(format!("/proc/{pid}/ns/net")) {
            Ok(p) => p,
            // In case of errors ignore them and do not warn. When the process is exiting then
            // several different errors can happen. I have observed ENOENT, ESRCH and EACCES so
            // to be safe just ignore all errors as this warning here is just best effort anyway.
            // https://github.com/containers/podman/issues/22103
            Err(_) => return,
        };

        if aardvark_ns != cur_ns {
            // netns does not match, this means dns will not work.
            // see https://github.com/containers/podman/issues/20396 for how that might happen
            // We do not not really what the problem in the aardvark-dns config files so we
            // cannot really self heal here and must ask the user to fix it.
            // I am not sure if this should be a hard error??
            log::error!(
                "aardvark-dns runs in a different netns, dns will not work for this container. To resolve please stop all containers, kill the aardvark-dns process, remove the {} directory and then start the containers again",
                self.config.display()
            );
        }
    }

    pub fn notify(&self, start: bool, is_update: bool) -> NetavarkResult<()> {
        match self.get_aardvark_pid() {
            Ok(pid) => {
                match signal::kill(Pid::from_raw(pid), Signal::SIGHUP) {
                    Ok(_) => {
                        // We do not want to check the netns when doing an update
                        // this is not working because podman does not enter the
                        // rootless netns for the update as we only change the file
                        // and send SIGHUP.
                        if !is_update {
                            self.check_netns(pid)
                        }
                        return Ok(());
                    }
                    Err(err) => {
                        // ESRCH == process does not exists
                        // start new sever below in that case and not error
                        if err != nix::errno::Errno::ESRCH {
                            return Err(NetavarkError::msg(format!(
                                "failed to send SIGHUP to aardvark: {err}"
                            )));
                        }
                    }
                }
            }
            Err(err) => {
                if !start {
                    return Err(NetavarkError::wrap("failed to get aardvark pid", err));
                }
            }
        };
        self.start_aardvark_server()?;
        Ok(())
    }

    pub fn commit_entries(&self, entries: &[AardvarkEntry]) -> NetavarkResult<()> {
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
            .truncate(true)
            .open(&lockfile_path)
        {
            Ok(file) => file,
            Err(e) => {
                return Err(NetavarkError::msg(format!(
                    "Failed to open/create lockfile {:?}: {}",
                    &lockfile_path, e
                )));
            }
        };
        if let Err(er) = lockfile.lock_exclusive() {
            return Err(NetavarkError::msg(format!(
                "Failed to acquire exclusive lock on {lockfile_path:?}: {er}"
            )));
        }

        for entry in entries {
            let mut path = Path::new(&self.config).join(entry.network_name);
            if entry.is_internal {
                let new_path = Path::new(&self.config).join(entry.network_name.to_owned() + "%int");
                let _ = std::fs::rename(&path, &new_path);
                path = new_path;
            }

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
                                format!(" {dns_server_collected}")
                            } else {
                                "".to_string()
                            }
                        } else {
                            "".to_string()
                        };

                    let data = format!("{gws}{network_dns_servers}\n");
                    f.write_all(data.as_bytes())?; // return error if write fails
                    f
                }
                Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
                    OpenOptions::new().append(true).open(&path)?
                }
                Err(e) => {
                    return Err(NetavarkError::Io(e));
                }
            };
            match Aardvark::commit_entry(entry, file) {
                Err(er) => {
                    return Err(NetavarkError::msg(format!(
                        "Failed to commit entry {entry:?}: {er}"
                    )));
                }
                Ok(_) => continue,
            }
        }

        Ok(())
    }

    fn commit_entry(entry: &AardvarkEntry, mut file: File) -> Result<()> {
        let mut buf = String::with_capacity(4096);

        // The line is space separated keys and then for the ips/names they are comma separated
        // Format: ID ipv4s ipv6s names[ dns-servers]
        buf.push_str(entry.container_id.0);

        buf.push(' ');
        write_comma_separated_list(
            &mut buf,
            entry.container_ips_v4.iter().map(|g| g.to_string()),
        );

        buf.push(' ');
        write_comma_separated_list(
            &mut buf,
            entry.container_ips_v6.iter().map(|g| g.to_string()),
        );

        buf.push(' ');
        write_comma_separated_list(&mut buf, entry.container_names.iter().map(|n| n.0));

        if let Some(dns_servers) = &entry.container_dns_servers {
            if !dns_servers.is_empty() {
                buf.push(' ');
                write_comma_separated_list(&mut buf, dns_servers.iter().map(|g| g.to_string()));
            }
        }
        buf.push('\n');

        file.write_all(buf.as_bytes())?; // return error if write fails

        Ok(())
    }

    pub fn commit_netavark_entries(&self, entries: Vec<AardvarkEntry>) -> NetavarkResult<()> {
        if !entries.is_empty() {
            self.commit_entries(&entries)?;
            match self.notify(true, false) {
                Ok(_) => (),
                Err(e) => {
                    if let Err(err) = self.delete_from_netavark_entries(&entries) {
                        log::warn!(
                            "Failed to delete aardvark-dns entries after failed start: {err}"
                        );
                    };
                    return Err(e);
                }
            };
        }
        Ok(())
    }

    pub fn delete_entry(&self, container_id: &str, network_name: &str) -> Result<()> {
        let mut path = Path::new(&self.config).join(network_name);
        if !path.exists() {
            path = Path::new(&self.config).join(network_name.to_owned() + "%int");
        }

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
    // Note: If no aardvark dns config exists for a network function will return success without
    // doing anything, because `podman network update` is applicable for networks even when no
    // container is attached to it.
    pub fn modify_network_dns_servers(
        &self,
        network_name: &str,
        network_dns_servers: &[String],
    ) -> NetavarkResult<()> {
        let mut dns_servers_modified = false;
        let path = Path::new(&self.config).join(network_name);
        let file_content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    // Most likely `podman network update` was called
                    // but no container on the network is running hence
                    // no aardvark file is there in such case return success
                    // since podman database still got updated and it will be
                    // populated correctly for the next container.
                    return Ok(());
                } else {
                    return Err(NetavarkError::Io(error));
                }
            }
        };

        let mut file = File::create(&path)?;

        //for line in lines {
        for (idx, line) in file_content.split_terminator('\n').enumerate() {
            if idx == 0 {
                // If this is first line, we have to modify this
                // first line has a format of `<BINDIP>... <NETWORK_DNSSERVERS>..`
                // We will read the first line and get the first column and
                // override the second column with new network dns servers.
                let network_parts = line.split(' ').collect::<Vec<&str>>();
                if network_parts.is_empty() {
                    return Err(NetavarkError::msg(format!(
                        "invalid network configuration file: {}",
                        path.display()
                    )));
                }
                let network_dns_servers_collected = if !network_dns_servers.is_empty() {
                    dns_servers_modified = true;
                    let dns_server_collected = network_dns_servers
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<Vec<String>>()
                        .join(",");
                    format!(" {dns_server_collected}")
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
            self.notify(false, true)?;
        }

        Ok(())
    }

    pub fn delete_from_netavark_entries(&self, entries: &[AardvarkEntry]) -> NetavarkResult<()> {
        for entry in entries {
            self.delete_entry(entry.container_id.0, entry.network_name)?;
        }
        self.notify(false, false)
    }
}

fn write_comma_separated_list<I, T>(buf: &mut String, mut iter: I)
where
    T: AsRef<str>,
    I: Iterator<Item = T>,
{
    // first one write without comma
    match iter.next() {
        Some(el) => buf.push_str(el.as_ref()),
        None => return,
    };

    for el in iter {
        buf.push(',');
        buf.push_str(el.as_ref());
    }
}
