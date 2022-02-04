// In the name of Allah

//! Provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux.
//! This crate uses iptables binary to manipulate chains and tables.
//! This source code is licensed under MIT license that can be found in the LICENSE file.
//!
//! # Example
//! ```
//! let ipt = iptables::new(false).unwrap();
//! assert!(ipt.new_chain("nat", "NEWCHAINNAME").is_ok());
//! assert!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
//! assert!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap());
//! assert!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
//! assert!(ipt.delete_chain("nat", "NEWCHAINNAME").is_ok());
//! ```

pub mod error;

use error::IptablesError;
use lazy_static::lazy_static;
use nix::fcntl::{flock, FlockArg};
use regex::{Match, Regex};
use std::convert::From;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Output};
use std::vec::Vec;

// List of built-in chains taken from: man 8 iptables
const BUILTIN_CHAINS_FILTER: &[&str] = &["INPUT", "FORWARD", "OUTPUT"];
const BUILTIN_CHAINS_MANGLE: &[&str] = &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"];
const BUILTIN_CHAINS_NAT: &[&str] = &["PREROUTING", "POSTROUTING", "OUTPUT"];
const BUILTIN_CHAINS_RAW: &[&str] = &["PREROUTING", "OUTPUT"];
const BUILTIN_CHAINS_SECURITY: &[&str] = &["INPUT", "OUTPUT", "FORWARD"];

lazy_static! {
    static ref RE_SPLIT: Regex = Regex::new(r#"["'].+?["']|[^ ]+"#).unwrap();
}

trait SplitQuoted {
    fn split_quoted(&self) -> Vec<&str>;
}

impl SplitQuoted for str {
    fn split_quoted(&self) -> Vec<&str> {
        RE_SPLIT
            // Iterate over matched segments
            .find_iter(self)
            // Get match as str
            .map(|m| Match::as_str(&m))
            // Remove any surrounding quotes (they will be reinserted by `Command`)
            .map(|s| s.trim_matches(|c| c == '"' || c == '\''))
            // Collect
            .collect::<Vec<_>>()
    }
}

fn error_from_str(msg: &str) -> Box<dyn Error> {
    msg.into()
}

fn output_to_result(output: Output) -> Result<(), Box<dyn Error>> {
    if !output.status.success() {
        return Err(Box::new(IptablesError::from(output)));
    }
    Ok(())
}

fn get_builtin_chains(table: &str) -> Result<&[&str], Box<dyn Error>> {
    match table {
        "filter" => Ok(BUILTIN_CHAINS_FILTER),
        "mangle" => Ok(BUILTIN_CHAINS_MANGLE),
        "nat" => Ok(BUILTIN_CHAINS_NAT),
        "raw" => Ok(BUILTIN_CHAINS_RAW),
        "security" => Ok(BUILTIN_CHAINS_SECURITY),
        _ => Err(error_from_str("given table is not supported by iptables")),
    }
}

/// Contains the iptables command and shows if it supports -w and -C options.
/// Use `new` method to create a new instance of this struct.
pub struct IPTables {
    /// The utility command which must be 'iptables' or 'ip6tables'.
    pub cmd: &'static str,

    /// Indicates if iptables has -C (--check) option
    pub has_check: bool,

    /// Indicates if iptables has -w (--wait) option
    pub has_wait: bool,

    /// Indicates if iptables will be run with -n (--numeric) option
    pub is_numeric: bool,
}

/// Returns `None` because iptables only works on linux
#[cfg(not(target_os = "linux"))]
pub fn new(is_ipv6: bool) -> Result<IPTables, Box<dyn Error>> {
    Err(error_from_str("iptables only works on Linux"))
}

/// Creates a new `IPTables` Result with the command of 'iptables' if `is_ipv6` is `false`, otherwise the command is 'ip6tables'.
#[cfg(target_os = "linux")]
pub fn new(is_ipv6: bool) -> Result<IPTables, Box<dyn Error>> {
    let cmd = if is_ipv6 { "ip6tables" } else { "iptables" };

    let version_output = Command::new(cmd).arg("--version").output()?;
    let re = Regex::new(r"v(\d+)\.(\d+)\.(\d+)")?;
    let version_string = String::from_utf8_lossy(version_output.stdout.as_slice());
    let versions = re
        .captures(&version_string)
        .ok_or("invalid version number")?;
    let v_major = versions
        .get(1)
        .ok_or("unable to get major version number")?
        .as_str()
        .parse::<i32>()?;
    let v_minor = versions
        .get(2)
        .ok_or("unable to get minor version number")?
        .as_str()
        .parse::<i32>()?;
    let v_patch = versions
        .get(3)
        .ok_or("unable to get patch version number")?
        .as_str()
        .parse::<i32>()?;

    Ok(IPTables {
        cmd,
        has_check: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 10),
        has_wait: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 19),
        is_numeric: false,
    })
}

impl IPTables {
    /// Get the default policy for a table/chain.
    pub fn get_policy(&self, table: &str, chain: &str) -> Result<String, Box<dyn Error>> {
        let builtin_chains = get_builtin_chains(table)?;
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(error_from_str(
                "given chain is not a default chain in the given table, can't get policy",
            ));
        }

        let stdout = match self.is_numeric {
            false => self.run(&["-t", table, "-L", chain])?.stdout,
            true => self.run(&["-t", table, "-L", chain, "-n"])?.stdout,
        };
        let output = String::from_utf8_lossy(stdout.as_slice());
        for item in output.trim().split('\n') {
            let fields = item.split(' ').collect::<Vec<&str>>();
            if fields.len() > 1 && fields[0] == "Chain" && fields[1] == chain {
                return Ok(fields[3].replace(")", ""));
            }
        }
        Err(error_from_str(
            "could not find the default policy for table and chain",
        ))
    }

    /// Set the default policy for a table/chain.
    pub fn set_policy(&self, table: &str, chain: &str, policy: &str) -> Result<(), Box<dyn Error>> {
        let builtin_chains = get_builtin_chains(table)?;
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(error_from_str(
                "given chain is not a default chain in the given table, can't set policy",
            ));
        }

        self.run(&["-t", table, "-P", chain, policy])
            .and_then(output_to_result)
    }

    /// Executes a given `command` on the chain.
    /// Returns the command output if successful.
    pub fn execute(&self, table: &str, command: &str) -> Result<Output, Box<dyn Error>> {
        self.run(&[&["-t", table], command.split_quoted().as_slice()].concat())
    }

    /// Checks for the existence of the `rule` in the table/chain.
    /// Returns true if the rule exists.
    #[cfg(target_os = "linux")]
    pub fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool, Box<dyn Error>> {
        if !self.has_check {
            return self.exists_old_version(table, chain, rule);
        }

        self.run(&[&["-t", table, "-C", chain], rule.split_quoted().as_slice()].concat())
            .map(|output| output.status.success())
    }

    /// Checks for the existence of the `chain` in the table.
    /// Returns true if the chain exists.
    #[cfg(target_os = "linux")]
    pub fn chain_exists(&self, table: &str, chain: &str) -> Result<bool, Box<dyn Error>> {
        match self.is_numeric {
            false => self
                .run(&["-t", table, "-L", chain])
                .map(|output| output.status.success()),
            true => self
                .run(&["-t", table, "-L", chain, "-n"])
                .map(|output| output.status.success()),
        }
    }

    fn exists_old_version(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<bool, Box<dyn Error>> {
        match self.is_numeric {
            false => self.run(&["-t", table, "-S"]).map(|output| {
                String::from_utf8_lossy(&output.stdout).contains(&format!("-A {} {}", chain, rule))
            }),
            true => self.run(&["-t", table, "-S", "-n"]).map(|output| {
                String::from_utf8_lossy(&output.stdout).contains(&format!("-A {} {}", chain, rule))
            }),
        }
    }

    /// Inserts `rule` in the `position` to the table/chain.
    pub fn insert(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
        position: i32,
    ) -> Result<(), Box<dyn Error>> {
        self.run(
            &[
                &["-t", table, "-I", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        )
        .and_then(output_to_result)
    }

    /// Inserts `rule` in the `position` to the table/chain if it does not exist.
    pub fn insert_unique(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
        position: i32,
    ) -> Result<(), Box<dyn Error>> {
        if self.exists(table, chain, rule)? {
            return Err(error_from_str("the rule exists in the table/chain"));
        }

        self.insert(table, chain, rule, position)
    }

    /// Replaces `rule` in the `position` to the table/chain.
    pub fn replace(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
        position: i32,
    ) -> Result<(), Box<dyn Error>> {
        self.run(
            &[
                &["-t", table, "-R", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        )
        .and_then(output_to_result)
    }

    /// Appends `rule` to the table/chain.
    pub fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), Box<dyn Error>> {
        self.run(&[&["-t", table, "-A", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    /// Appends `rule` to the table/chain if it does not exist.
    pub fn append_unique(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<(), Box<dyn Error>> {
        if self.exists(table, chain, rule)? {
            return Err(error_from_str("the rule exists in the table/chain"));
        }

        self.append(table, chain, rule)
    }

    /// Appends or replaces `rule` to the table/chain if it does not exist.
    pub fn append_replace(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<(), Box<dyn Error>> {
        if self.exists(table, chain, rule)? {
            self.delete(table, chain, rule)?;
        }

        self.append(table, chain, rule)
    }

    /// Deletes `rule` from the table/chain.
    pub fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), Box<dyn Error>> {
        self.run(&[&["-t", table, "-D", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    /// Deletes all repetition of the `rule` from the table/chain.
    pub fn delete_all(&self, table: &str, chain: &str, rule: &str) -> Result<(), Box<dyn Error>> {
        while self.exists(table, chain, rule)? {
            self.delete(table, chain, rule)?;
        }

        Ok(())
    }

    /// Lists rules in the table/chain.
    pub fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, Box<dyn Error>> {
        match self.is_numeric {
            false => self.get_list(&["-t", table, "-S", chain]),
            true => self.get_list(&["-t", table, "-S", chain, "-n"]),
        }
    }

    /// Lists rules in the table.
    pub fn list_table(&self, table: &str) -> Result<Vec<String>, Box<dyn Error>> {
        match self.is_numeric {
            false => self.get_list(&["-t", table, "-S"]),
            true => self.get_list(&["-t", table, "-S", "-n"]),
        }
    }

    /// Lists the name of each chain in the table.
    pub fn list_chains(&self, table: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let mut list = Vec::new();
        let stdout = self.run(&["-t", table, "-S"])?.stdout;
        let output = String::from_utf8_lossy(stdout.as_slice());
        for item in output.trim().split('\n') {
            let fields = item.split(' ').collect::<Vec<&str>>();
            if fields.len() > 1 && (fields[0] == "-P" || fields[0] == "-N") {
                list.push(fields[1].to_string());
            }
        }
        Ok(list)
    }

    /// Creates a new user-defined chain.
    pub fn new_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-N", chain])
            .and_then(output_to_result)
    }

    /// Flushes (deletes all rules) a chain.
    pub fn flush_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-F", chain])
            .and_then(output_to_result)
    }

    /// Renames a chain in the table.
    pub fn rename_chain(
        &self,
        table: &str,
        old_chain: &str,
        new_chain: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-E", old_chain, new_chain])
            .and_then(output_to_result)
    }

    /// Deletes a user-defined chain in the table.
    pub fn delete_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-X", chain])
            .and_then(output_to_result)
    }

    /// Flushes all chains in a table.
    pub fn flush_table(&self, table: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-F"]).and_then(output_to_result)
    }

    fn get_list<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Vec<String>, Box<dyn Error>> {
        let stdout = self.run(args)?.stdout;
        Ok(String::from_utf8_lossy(stdout.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .collect())
    }

    /// Set whether iptables is called with the -n (--numeric) option,
    /// to avoid host name and port name lookups
    pub fn set_numeric(&mut self, numeric: bool) {
        self.is_numeric = numeric;
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output, Box<dyn Error>> {
        let mut file_lock = None;

        let mut output_cmd = Command::new(self.cmd);
        let output;

        if self.has_wait {
            output = output_cmd.args(args).arg("--wait").output()?;
        } else {
            file_lock = Some(File::create("/var/run/xtables_old.lock")?);

            let mut need_retry = true;
            while need_retry {
                match flock(
                    file_lock.as_ref().unwrap().as_raw_fd(),
                    FlockArg::LockExclusiveNonblock,
                ) {
                    Ok(_) => need_retry = false,
                    Err(e) if e == nix::errno::Errno::EAGAIN => {
                        // FIXME: may cause infinite loop
                        need_retry = true;
                    }
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            output = output_cmd.args(args).output()?;
        }

        if let Some(f) = file_lock {
            drop(f)
        }
        Ok(output)
    }
}
