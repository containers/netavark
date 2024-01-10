use std::{
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::de::DeserializeOwned;

use crate::{
    error::{NetavarkError, NetavarkResult},
    network::internal_types::{PortForwardConfig, PortForwardConfigOwned, SetupNetwork},
    wrap,
};

/// File layout looks like this
/// $config/firewall/
///                 - firewall-driver -> name of the firewall driver
///                 - networks/$netID -> network config setup
///                 - ports/$netID_$conID -> port config

const FIREWALL_DIR: &str = "firewall";
const FIREWALL_DRIVER_FILE: &str = "firewall-driver";
const FIREWALL_LOCK_FILE: &str = "firewall-reload.lock";
const NETWORK_CONF_DIR: &str = "networks";
const PORT_CONF_DIR: &str = "ports";

struct FilePaths {
    fw_driver_file: PathBuf,
    net_conf_file: PathBuf,
    port_conf_file: PathBuf,
    /// The file is returned locked, it does not need
    /// to be unlocked as rust does it automatically on drop.
    /// This file is required to ensure that remove_fw_config is not racing against
    /// the firewall reload service, i.e. without it would be possible that we read
    /// the config files and then during re-adding the rules the file got removed.
    /// This leaves a chance that the service will add rules that should not be added
    /// anymore.
    lock_file: File,
}

/// macro to quickly wrap the IO error with useful context
/// First argument is the function, second the path, third the extra error message.
/// The full error is "$msg $path: $org_error"
macro_rules! fs_err {
    ($func:expr, $path:expr, $msg:expr) => {
        $func($path).map_err(|err| {
            NetavarkError::wrap(format!("{} {:?}", $msg, $path.display()), err.into())
        })
    };
}

macro_rules! ignore_enoent {
    ($call:expr, $action:expr) => {
        match $call {
            Ok(ok) => Ok(ok),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => $action,
            Err(e) => Err(e),
        }
    };
}

fn remove_file_ignore_enoent<P: AsRef<Path>>(path: P) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(ok) => Ok(ok),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn firewall_config_dir(config_dir: &Path) -> PathBuf {
    Path::new(config_dir).join(FIREWALL_DIR)
}

/// Assemble file paths for the config files, when create_dirs is set to true
/// it will create the parent dirs as well so the caller does not have to.
///
/// As a special case when network_id and container_id is empty it will return
/// the paths for the directories instead which are used to walk the dir for all configs.
fn get_file_paths(
    config_dir: &Path,
    network_id: &str,
    container_id: &str,
    create_dirs: bool,
) -> NetavarkResult<FilePaths> {
    let path = firewall_config_dir(config_dir);
    let fw_driver_file = path.join(FIREWALL_DRIVER_FILE);
    let mut net_conf_file = path.join(NETWORK_CONF_DIR);
    let mut port_conf_file = path.join(PORT_CONF_DIR);

    // we need to always create this for the lockfile
    fs_err!(fs::create_dir_all, &path, "create firewall config dir")?;
    if create_dirs {
        fs_err!(
            fs::create_dir_all,
            &net_conf_file,
            "create network config dir"
        )?;
        fs_err!(
            fs::create_dir_all,
            &port_conf_file,
            "create port config dir"
        )?;
    }
    if !network_id.is_empty() && !container_id.is_empty() {
        net_conf_file.push(network_id);
        port_conf_file.push(network_id.to_string() + "_" + container_id);
    }

    let lock_file = fs_err!(
        File::create,
        &path.join(FIREWALL_LOCK_FILE),
        "create firewall lock file"
    )?;
    wrap!(lock_file.lock_exclusive(), "lock firewall lock file")?;

    Ok(FilePaths {
        fw_driver_file,
        net_conf_file,
        port_conf_file,
        lock_file,
    })
}

/// Store the firewall configs on disk.
/// This should be caller after firewall setup to allow the firewalld reload
/// service to read the configs later and readd the rules.
pub fn write_fw_config(
    config_dir: &Path,
    network_id: &str,
    container_id: &str,
    fw_driver: &str,
    net_conf: &SetupNetwork,
    port_conf: &PortForwardConfig,
) -> NetavarkResult<()> {
    let paths = get_file_paths(config_dir, network_id, container_id, true)?;
    fs_err!(
        File::create,
        &paths.fw_driver_file,
        "create firewall-driver file"
    )?
    .write_all(fw_driver.as_bytes())
    .map_err(|err| NetavarkError::wrap("failed to write firewall-driver file", err.into()))?;

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&paths.net_conf_file)
    {
        Ok(f) => serde_json::to_writer(f, &net_conf)?,
        // net config file already exists no need to write the same stuff again.
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => (),
        Err(e) => {
            return Err(NetavarkError::wrap(
                format!("create network config {:?}", &paths.net_conf_file.display()),
                e.into(),
            ));
        }
    };

    let ports_file = fs_err!(File::create, &paths.port_conf_file, "create port config")?;
    serde_json::to_writer(ports_file, &port_conf)?;

    Ok(())
}

/// Remove firewall config files.
/// On firewall teardown remove the specific config files again so the
/// firewalld reload service does not keep using them.
pub fn remove_fw_config(
    config_dir: &Path,
    network_id: &str,
    container_id: &str,
    complete_teardown: bool,
) -> NetavarkResult<()> {
    let paths = get_file_paths(config_dir, network_id, container_id, false)?;
    fs_err!(
        remove_file_ignore_enoent,
        &paths.port_conf_file,
        "remove port config"
    )?;
    if complete_teardown {
        fs_err!(
            remove_file_ignore_enoent,
            &paths.net_conf_file,
            "remove network config"
        )?;
    }
    Ok(())
}

pub struct FirewallConfig {
    /// Name of the firewall driver
    pub driver: String,
    /// All the network firewall configs
    pub net_confs: Vec<SetupNetwork>,
    /// All port forwarding configs
    pub port_confs: Vec<PortForwardConfigOwned>,

    /// Lock file for the firewall code to prevent us from adding rules while the state files
    /// have been removed in the meantime.
    /// We never do anything with it but we need to keep it open as closing it closes the lock
    /// So once this struct is dropped the lock is closed automatically.
    #[allow(dead_code)]
    lock_file: File,
}

/// Read all firewall configs files from the dir.
pub fn read_fw_config(config_dir: &Path) -> NetavarkResult<Option<FirewallConfig>> {
    let paths = get_file_paths(config_dir, "", "", false)?;

    // now it is possible the firewall-reload is started before any containers were started so we just
    // return None in this case.
    let driver = wrap!(
        ignore_enoent!(fs::read_to_string(&paths.fw_driver_file), return Ok(None)),
        format!("read firewall-driver {:?}", &paths.fw_driver_file.display())
    )?;

    let net_confs = read_dir_conf(paths.net_conf_file)?;
    let port_confs = read_dir_conf(paths.port_conf_file)?;

    Ok(Some(FirewallConfig {
        driver,
        net_confs,
        port_confs,
        lock_file: paths.lock_file,
    }))
}

fn read_dir_conf<T: DeserializeOwned>(dir: PathBuf) -> NetavarkResult<Vec<T>> {
    let mut confs = Vec::new();
    for entry in fs_err!(fs::read_dir, &dir, "read dir")? {
        let path = ignore_enoent!(entry, continue)?.path();

        let content = wrap!(
            ignore_enoent!(fs::read_to_string(&path), continue),
            format!("read config {:?}", path.display())
        )?;
        // Note one might think we should use from_reader() instead of reading
        // into one string. However the files we act on are small enough that it
        // should't matter to have the content into memory at once and based on
        // https://github.com/serde-rs/json/issues/160 this here is much faster.
        let conf: T = serde_json::from_str(&content)?;
        confs.push(conf);
    }
    Ok(confs)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::network::internal_types::IsolateOption;

    use super::*;
    use tempfile::Builder;

    #[test]
    fn test_fw_config() {
        let network_id = "abc";
        let container_id = "123";
        let driver = "iptables";

        let tmpdir = Builder::new().prefix("netavark-tests").tempdir().unwrap();
        let config_dir = tmpdir.path();

        let net_conf = SetupNetwork {
            subnets: Some(vec!["10.0.0.0/24".parse().unwrap()]),
            network_id: "c2c8a073252874648259997d53b0a1bffa491e21f04bc1bf8609266359931395"
                .to_string(),
            bridge_name: "bridge".to_string(),
            network_hash_name: "hash".to_string(),
            isolation: IsolateOption::Never,
            dns_port: 53,
        };
        let net_conf_json = r#"{"subnets":["10.0.0.0/24"],"bridge_name":"bridge","network_id":"c2c8a073252874648259997d53b0a1bffa491e21f04bc1bf8609266359931395","network_hash_name":"hash","isolation":"Never","dns_port":53}"#;

        let port_conf = PortForwardConfig {
            container_id: container_id.to_string(),
            network_id: "c2c8a073252874648259997d53b0a1bffa491e21f04bc1bf8609266359931395"
                .to_string(),
            port_mappings: &None,
            network_name: "name".to_string(),
            network_hash_name: "hash".to_string(),
            container_ip_v4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            subnet_v4: Some("10.0.0.0/24".parse().unwrap()),
            container_ip_v6: None,
            subnet_v6: None,
            dns_port: 53,
            dns_server_ips: &vec![],
        };
        let port_conf_json = r#"{"container_id":"123","network_id":"c2c8a073252874648259997d53b0a1bffa491e21f04bc1bf8609266359931395","port_mappings":null,"network_name":"name","network_hash_name":"hash","container_ip_v4":"10.0.0.2","subnet_v4":"10.0.0.0/24","container_ip_v6":null,"subnet_v6":null,"dns_port":53,"dns_server_ips":[]}"#;

        let res = write_fw_config(
            config_dir,
            network_id,
            container_id,
            driver,
            &net_conf,
            &port_conf,
        );

        assert!(res.is_ok(), "write_fw_config failed");

        let paths = get_file_paths(config_dir, network_id, container_id, false).unwrap();
        drop(paths.lock_file); // unlock to prevent deadlock with other calls

        let res = fs::read_to_string(paths.fw_driver_file).unwrap();
        assert_eq!(res, "iptables", "read fw driver");

        let res = fs::read_to_string(&paths.net_conf_file).unwrap();
        assert_eq!(res, net_conf_json, "read net conf");

        let res = fs::read_to_string(&paths.port_conf_file).unwrap();
        assert_eq!(res, port_conf_json, "read port conf");

        let res = read_fw_config(config_dir)
            .unwrap()
            .expect("no fw config files");
        assert_eq!(res.driver, driver, "correct fw driver");
        assert_eq!(res.net_confs, vec![net_conf], "same net configs");
        let port_confs_ref: Vec<PortForwardConfig> =
            res.port_confs.iter().map(|f| f.into()).collect();
        assert_eq!(port_confs_ref, vec![port_conf], "same port configs");
        // unlock lock file
        drop(res);

        let res = remove_fw_config(config_dir, network_id, container_id, true);
        assert!(res.is_ok(), "remove_fw_config failed");

        assert_eq!(
            paths.net_conf_file.exists(),
            false,
            "net conf should not exists"
        );
        assert_eq!(
            paths.port_conf_file.exists(),
            false,
            "port conf should not exists"
        );

        // now again since we ignore ENOENT it should still return no error
        let res = remove_fw_config(config_dir, network_id, container_id, true);
        assert!(res.is_ok(), "remove_fw_config failed second time");
    }

    #[test]
    fn test_read_fw_config_empty() {
        let tmpdir = Builder::new().prefix("netavark-tests").tempdir().unwrap();
        let config_dir = tmpdir.path();

        let res = read_fw_config(config_dir).expect("no read_fw_config error");
        assert!(res.is_none(), "no firewall config should be given");
    }
}
