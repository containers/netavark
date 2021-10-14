extern crate fs2;
use fs2::FileExt;
use std::fs::File;
use nmstate::NetworkState;
use nmstate::NmstateError;
extern crate serde_derive;
use serde_yaml::{self, Value};

const IFACE_TOP_PRIORTIES: [&str; 2] = ["name", "type"];
const ADAPTER_LOCK_FILE: &str = "/var/tmp/netvark.adapter.lock";

/* Adapter: Is a genric adapter to any NetworkManager
 * Currently supports: nmstate-rs
 */
pub struct Adapter {
    _input: NmStateAdapterInterface,
}

pub struct AdapterError {
    pub(crate) msg: String,
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<std::io::Error> for AdapterError {
    fn from(e: std::io::Error) -> Self {
        Self { msg: format!("std::io::Error: {}", e) }
    }
}

impl From<NmstateError> for AdapterError {
    fn from(e: NmstateError) -> Self {
        Self { msg: format!("NmstateError: {}", e) }
    }
}

impl From<serde_yaml::Error> for AdapterError {
    fn from(e: serde_yaml::Error) -> Self {
        Self { msg: format!("serde_yaml::Error: {}", e) }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NmStateAdapterInterface {
    #[serde(rename = "interfaces")]
    pub interfaces: Vec<Interface>,
}

#[derive(Serialize, Deserialize)]
pub struct Interface {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "type")]
    pub interface_type: String,

    #[serde(rename = "state")]
    pub state: String,

    #[serde(rename = "bridge")]
    pub bridge: Option<Bridge>,

    #[serde(rename = "ipv4")]
    pub ipv4: Option<NmIp>,

    #[serde(rename = "ipv6")]
    pub ipv6: Option<NmIp>,
}

#[derive(Serialize, Deserialize)]
pub struct Bridge {
    #[serde(rename = "port")]
    pub port: Vec<Port>,

    #[serde(rename = "options")]
    pub options: Options,
}

#[derive(Serialize, Deserialize)]
pub struct Options {
    #[serde(rename = "stp")]
    pub stp: Stp,
}

#[derive(Serialize, Deserialize)]
pub struct Stp {
    #[serde(rename = "enabled")]
    pub enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Port {
    #[serde(rename = "name")]
    pub name: String,
}

#[derive(Serialize, Deserialize)]
pub struct NmIp {
    #[serde(rename = "address")]
    pub address: Vec<Address>,

    #[serde(rename = "dhcp")]
    pub dhcp: bool,

    #[serde(rename = "enabled")]
    pub enabled: bool,

    #[serde(rename = "autoconf")]
    pub autoconf: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Address {
    #[serde(rename = "ip")]
    pub ip: String,

    #[serde(rename = "prefix-length")]
    pub prefix_length: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SortedNetworkState {
    interfaces: Vec<Value>,
}

impl Adapter {
    fn sort_netstate(net_state: NetworkState) -> Result<SortedNetworkState, AdapterError> {
        let mut ifaces = net_state.interfaces.to_vec();
        ifaces.sort_by(|a, b| a.name().cmp(b.name()));

        if let Value::Sequence(ifaces) = serde_yaml::to_value(&ifaces)? {
            let mut new_ifaces = Vec::new();
            for iface_v in ifaces {
                if let Value::Mapping(iface) = iface_v {
                    let mut new_iface = serde_yaml::Mapping::new();
                    for top_property in &IFACE_TOP_PRIORTIES {
                        if let Some(v) = iface.get(&Value::String(top_property.to_string())) {
                            new_iface.insert(Value::String(top_property.to_string()), v.clone());
                        }
                    }
                    for (k, v) in iface.iter() {
                        if let Value::String(ref name) = k {
                            if IFACE_TOP_PRIORTIES.contains(&name.as_str()) {
                                continue;
                            }
                        }
                        new_iface.insert(k.clone(), v.clone());
                    }

                    new_ifaces.push(Value::Mapping(new_iface));
                }
            }
            return Ok(SortedNetworkState { interfaces: new_ifaces });
        }

        Ok(SortedNetworkState { interfaces: Vec::new() })
    }

    pub fn nmstate_adapter_apply_file(
        file_path: &str,
        kernel_only: bool,
        no_verify: bool,
    ) -> Result<String, AdapterError> {
        // create lockfile or truncate
        let _lockfile_create = File::open(&ADAPTER_LOCK_FILE)?;
        let lockfile = File::open(&ADAPTER_LOCK_FILE)?;
        lockfile.lock_exclusive()?;
        let fd = std::fs::File::open(file_path)?;
        let mut net_state: NetworkState = serde_yaml::from_reader(fd)?;
        net_state.set_kernel_only(kernel_only);
        net_state.set_verify_change(!no_verify);
        net_state.apply()?;
        lockfile.unlock()?;
        let sorted_net_state = Adapter::sort_netstate(net_state)?;
        Ok(serde_yaml::to_string(&sorted_net_state)?)
    }

    pub fn nmstate_adapter_apply(
        input: &NmStateAdapterInterface,
        kernel_only: bool,
        no_verify: bool,
    ) -> Result<String, AdapterError> {
        // create lockfile or truncate
        let _lockfile_create = File::open(&ADAPTER_LOCK_FILE)?;
        let lockfile = File::open(&ADAPTER_LOCK_FILE)?;
        lockfile.lock_exclusive()?;
        let value = serde_yaml::to_value(&input).unwrap();
        let mut net_state: NetworkState = serde_yaml::from_value(value).unwrap();
        net_state.set_kernel_only(kernel_only);
        net_state.set_verify_change(!no_verify);
        net_state.apply()?;
        lockfile.unlock()?;
        let sorted_net_state = Adapter::sort_netstate(net_state)?;
        Ok(serde_yaml::to_string(&sorted_net_state)?)
    }

    pub fn nmstate_adapter_apply_directly(
        input: NetworkState,
        kernel_only: bool,
        no_verify: bool,
    ) -> Result<String, AdapterError> {
        // create lockfile or truncate
        let _lockfile_create = File::open(&ADAPTER_LOCK_FILE)?;
        let lockfile = File::open(&ADAPTER_LOCK_FILE)?;
        lockfile.lock_exclusive()?;
        let mut net_state: NetworkState = input;
        net_state.set_kernel_only(kernel_only);
        net_state.set_verify_change(!no_verify);
        net_state.apply()?;
        lockfile.unlock()?;
        let sorted_net_state = Adapter::sort_netstate(net_state)?;
        Ok(serde_yaml::to_string(&sorted_net_state)?)
    }
}
