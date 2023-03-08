// TODO these constant destinations are not final.

use std::env;
use std::path::{Path, PathBuf};

// Where the cache and socket are stored by default
pub const NETAVARK_PROXY_RUN_DIR: &str = "/run/podman";

pub const NETAVARK_PROXY_RUN_DIR_ENV: &str = "NETAVARK_PROXY_RUN_DIR_ENV";

// Default UDS path for gRPC to communicate on.
pub const DEFAULT_UDS_PATH: &str = "/run/podman/nv-proxy.sock";
// Default configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "";
// Default Network configuration path
pub const DEFAULT_NETWORK_CONFIG: &str = "/dev/stdin";
// Default epoll wait time before dhcp socket times out
pub const DEFAULT_TIMEOUT: u32 = 8;
// Proxy server gRPC socket file name
pub const PROXY_SOCK_NAME: &str = "nv-proxy.sock";
// Where leases are stored on the filesystem
pub const CACHE_FILE_NAME: &str = "nv-proxy.lease";
// Seconds until the service should exit
pub const DEFAULT_INACTIVITY_TIMEOUT: u64 = 300;

/// Get the RUN_DIR where the proxy cache and socket
/// are stored
///
///
/// # Arguments
///
/// * `run_cli`:
///
/// returns: String
///
/// # Examples
///
/// ```
///
/// ```
pub fn get_run_dir(run_cli: Option<&str>) -> String {
    // if environment, return it
    // if opt, return it
    // return default

    match env::var(NETAVARK_PROXY_RUN_DIR_ENV) {
        // env::var returns an error if the key doesnt exist
        Ok(v) => return v,
        Err(_) => {
            if let Some(val) = run_cli {
                return val.to_string();
            }
        }
    }
    NETAVARK_PROXY_RUN_DIR.to_string()
}

/// Returns the fully qualified path of the proxy socket file including
/// the socket file name
///
/// # Arguments
///
/// * `run_dir_opt`:
///
/// returns: PathBuf
///
/// # Examples
///
/// ```
///
/// ```
pub fn get_proxy_sock_fqname(run_dir_opt: Option<&str>) -> PathBuf {
    let run_dir = get_run_dir(run_dir_opt);
    Path::new(&run_dir).join(PROXY_SOCK_NAME)
}

/// Returns the fully qualified path of the cache file including the cache
/// file name
///
///
/// # Arguments
///
/// * `run_dir`:
///
/// returns: PathBuf
///
/// # Examples
///
/// ```
///
/// ```
pub fn get_cache_fqname(run_dir: Option<&str>) -> PathBuf {
    let run_dir = get_run_dir(run_dir);
    Path::new(&run_dir).join(CACHE_FILE_NAME)
}

#[cfg(test)]
mod conf_tests {
    use crate::dhcp_proxy::proxy_conf::{
        get_cache_fqname, get_proxy_sock_fqname, get_run_dir, CACHE_FILE_NAME,
        NETAVARK_PROXY_RUN_DIR, NETAVARK_PROXY_RUN_DIR_ENV, PROXY_SOCK_NAME,
    };
    use std::path::Path;

    use std::collections::HashMap;
    use std::env;
    use std::ffi::OsStr;
    use std::hash::Hash;
    use std::panic::{self, RefUnwindSafe, UnwindSafe};
    use std::sync::Mutex;

    use once_cell::sync::Lazy;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    /// Make sure that the environment isn't modified concurrently.
    static SERIAL_TEST: Lazy<Mutex<()>> = Lazy::new(Default::default);

    ///
    /// The following stanzas of code should be attributed to https://github.com/vmx/temp-env
    ///

    /// The previous value is restored when the closure completes or panics, before unwinding the
    /// panic.
    ///
    /// If `value` is set to `None`, then the environment variable is unset.
    pub fn with_var<K, V, F, R>(key: K, value: Option<V>, closure: F) -> R
    where
        K: AsRef<OsStr> + Clone + Eq + Hash,
        V: AsRef<OsStr> + Clone,
        F: Fn() -> R + UnwindSafe + RefUnwindSafe,
    {
        with_vars(vec![(key, value)], closure)
    }

    /// Unsets a single environment variable for the duration of the closure.
    ///
    /// The previous value is restored when the closure completes or panics, before unwinding the
    /// panic.
    ///
    /// This is a shorthand and identical to the following:
    /// ```rust
    /// temp_env::with_var("MY_ENV_VAR", None::<&str>, || {
    ///     // Run some code where `MY_ENV_VAR` is unset.
    /// });
    /// ```
    pub fn with_var_unset<K, F, R>(key: K, closure: F) -> R
    where
        K: AsRef<OsStr> + Clone + Eq + Hash,
        F: Fn() -> R + UnwindSafe + RefUnwindSafe,
    {
        with_var(key, None::<&str>, closure)
    }

    /// Sets environment variables for the duration of the closure.
    ///
    /// The previous values are restored when the closure completes or panics, before unwinding the
    /// panic.
    ///
    /// If a `value` is set to `None`, then the environment variable is unset.
    ///
    /// If the variable with the same name is set multiple times, the last one wins.
    pub fn with_vars<K, V, F, R>(kvs: Vec<(K, Option<V>)>, closure: F) -> R
    where
        K: AsRef<OsStr> + Clone + Eq + Hash,
        V: AsRef<OsStr> + Clone,
        F: Fn() -> R + UnwindSafe + RefUnwindSafe,
    {
        let guard = SERIAL_TEST.lock().unwrap();
        let mut old_kvs: HashMap<K, Option<String>> = HashMap::new();
        for (key, value) in kvs {
            // If the same key is given several times, the original/old value is only correct before
            // the environment was updated.
            if !old_kvs.contains_key(&key) {
                let old_value = env::var(&key).ok();
                old_kvs.insert(key.clone(), old_value);
            }
            update_env(&key, value);
        }

        match panic::catch_unwind(closure) {
            Ok(result) => {
                for (key, value) in old_kvs {
                    update_env(key, value);
                }
                result
            }
            Err(err) => {
                for (key, value) in old_kvs {
                    update_env(key, value);
                }
                drop(guard);
                panic::resume_unwind(err);
            }
        }
    }

    fn update_env<K, V>(key: K, value: Option<V>)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        match value {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
    }

    fn random_string(len: usize) -> String {
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect();
        format!("/{rand_string}")
    }

    // The following tests seem to be susceptible to the environment variables poisoning
    // each other when run in parallel (default rust behavior).  If we set --test-threads=1,
    // this will not happen.  For now, I wrap the tests in `with_var_unset`.

    #[test]
    fn test_run_dir_env() {
        let r = random_string(25);
        with_var(NETAVARK_PROXY_RUN_DIR_ENV, Some(&r), || {
            assert_eq!(get_run_dir(None), r)
        });
    }

    #[test]
    fn test_run_dir_with_opt() {
        let r = random_string(25);
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(get_run_dir(Some(&r)), r)
        });
    }

    #[test]
    fn test_run_dir_as_none() {
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(get_run_dir(None), NETAVARK_PROXY_RUN_DIR)
        });
    }

    #[test]
    fn test_get_cache_env() {
        let r = random_string(25);
        with_var(NETAVARK_PROXY_RUN_DIR_ENV, Some(&r), || {
            assert_eq!(get_cache_fqname(None), Path::new(&r).join(CACHE_FILE_NAME));
        });
    }

    #[test]
    fn test_get_cache_with_opt() {
        let r = random_string(25);
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(
                get_cache_fqname(Some(&r)),
                Path::new(&r).join(CACHE_FILE_NAME)
            )
        })
    }

    #[test]
    fn test_get_cache_as_none() {
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(
                get_cache_fqname(None),
                Path::new(NETAVARK_PROXY_RUN_DIR).join(CACHE_FILE_NAME)
            )
        });
    }

    #[test]
    fn test_get_proxy_sock_env() {
        let r = random_string(25);
        with_var(NETAVARK_PROXY_RUN_DIR_ENV, Some(&r), || {
            assert_eq!(
                get_proxy_sock_fqname(None),
                Path::new(&r).join(PROXY_SOCK_NAME)
            );
        });
    }

    #[test]
    fn test_get_proxy_sock_with_opt() {
        let r = random_string(25);
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(
                get_proxy_sock_fqname(Some(&r)),
                Path::new(&r).join(PROXY_SOCK_NAME)
            )
        })
    }

    #[test]
    fn test_get_proxy_sock_as_none() {
        with_var_unset(NETAVARK_PROXY_RUN_DIR_ENV, || {
            assert_eq!(
                get_proxy_sock_fqname(None),
                Path::new(NETAVARK_PROXY_RUN_DIR).join(PROXY_SOCK_NAME)
            )
        });
    }
}
