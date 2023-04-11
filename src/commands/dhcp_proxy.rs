#![cfg_attr(not(unix), allow(unused_imports))]

use clap::Parser;
use log::{debug, error, warn};
use macaddr::MacAddr;

use crate::dhcp_proxy::cache::{Clear, LeaseCache};
use crate::dhcp_proxy::dhcp_service::DhcpService;
use crate::dhcp_proxy::ip;
use crate::dhcp_proxy::lib::g_rpc::netavark_proxy_server::{NetavarkProxy, NetavarkProxyServer};
use crate::dhcp_proxy::lib::g_rpc::{
    Empty, Lease as NetavarkLease, NetworkConfig, OperationResponse,
};
use crate::dhcp_proxy::proxy_conf::{
    get_cache_fqname, get_proxy_sock_fqname, DEFAULT_INACTIVITY_TIMEOUT, DEFAULT_TIMEOUT,
};
use crate::error::{NetavarkError, NetavarkResult};

use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener as stdUnixListener;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{env, fs};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Code, Code::Internal, Request, Response, Status};

#[derive(Debug)]
/// This is the tonic netavark proxy service that is required to impl the Netavark Proxy trait which
/// includes the gRPC methods defined in proto/proxy.proto. We can store a atomically referenced counted
/// mutex cache in the structure tuple.
///
/// The cache needs to be **safely mutable across multiple threads**. We need to share the lease cache
/// across multiple threads for 2 reasons
/// 1. Each tonic request is spawned in its own new thread.
/// 2. A new thread must be spawned in any request that uses mozim, such as get_lease. This is because
///    tonic creates its own runtime for each request and mozim trys to make its own runtime inside of
///    a runtime.
///
struct NetavarkProxyService<W: Write + Clear> {
    // cache is the lease hashmap
    cache: Arc<Mutex<LeaseCache<W>>>,
    // the timeout for the dora operation
    dora_timeout: u32,
    // channel send-side for resetting the inactivity timeout
    timeout_sender: Arc<Mutex<Sender<i32>>>,
}

impl<W: Write + Clear> NetavarkProxyService<W> {
    fn reset_inactivity_timeout(&self) {
        let sender = self.timeout_sender.clone();
        let locked_sender = match sender.lock() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{}", e.to_string());
                return;
            }
        };
        match locked_sender.try_send(1) {
            Ok(..) => {}
            Err(e) => log::error!("{}", e.to_string()),
        }
    }
}

// gRPC request and response methods
#[tonic::async_trait]
impl<W: Write + Clear + Send + 'static> NetavarkProxy for NetavarkProxyService<W> {
    /// gRPC connection to get a lease
    async fn setup(
        &self,
        request: Request<NetworkConfig>,
    ) -> Result<Response<NetavarkLease>, Status> {
        debug!("Request from client {:?}", request.remote_addr());
        // notify server of activity
        self.reset_inactivity_timeout();

        let cache = self.cache.clone();
        let timeout = self.dora_timeout;

        // setup client side streaming
        let network_config = request.into_inner();
        // _tx will be dropped when the request is dropped, this will trigger rx, which means the
        // client disconnected
        let (_tx, mut rx) = oneshot::channel::<()>();
        let lease = tokio::task::spawn(async move {
            // Check if the connection has been dropped before attempting to get a lease
            if rx.try_recv() == Err(TryRecvError::Closed) {
                log::debug!("Request dropped, aborting DORA");
                return Err(Status::new(Code::Aborted, "client disconnected"));
            }
            let get_lease = process_setup(network_config, &timeout, cache);
            // watch the client and the lease, which ever finishes first return
            let get_lease: NetavarkLease = tokio::select! {
                _ = &mut rx => {
                    // we never send to tx, so this completing means that the other end, tx, was dropped!
                    log::debug!("Request dropped, aborting DORA");
                    return Err(Status::new(Code::Aborted, "client disconnected"))
                }
                lease = get_lease => {
                    Ok::<NetavarkLease, Status>(lease?)
                }
            }?;
            // check after lease was found that the client is still there
            if rx.try_recv() == Err(TryRecvError::Closed) {
                log::debug!("Request dropped, aborting DORA");
                return Err(Status::new(Code::Aborted, "client disconnected"));
            }

            Ok(get_lease)
        })
        .await;
        return match lease {
            Ok(Ok(lease)) => Ok(Response::new(lease)),
            Ok(Err(status)) => Err(status),
            Err(e) => Err(Status::new(Code::Unknown, e.to_string())),
        };
    }

    /// When a container is shut down this method should be called. It will clear the lease information
    /// from the caching system.
    async fn teardown(
        &self,
        request: Request<NetworkConfig>,
    ) -> Result<Response<NetavarkLease>, Status> {
        // notify server of activity
        self.reset_inactivity_timeout();
        let nc = request.into_inner();

        let cache = self.cache.clone();
        let timeout = self.dora_timeout;

        std::thread::spawn(move || {
            // Remove the client from the cache dir
            let lease = cache
                .clone()
                .lock()
                .expect("Could not unlock cache. A thread was poisoned")
                .remove_lease(&nc.container_mac_addr)
                .map_err(|e| Status::internal(e.to_string()))?;

            // Send the DHCP release message
            DhcpService::new(&nc, &timeout)?
                .release_lease(&lease)
                .map_err(|e| Status::internal(e.to_string()))?;

            Ok(Response::new(lease))
        })
        .join()
        .expect("Error joining thread")
    }

    /// On teardown of the proxy the cache will be cleared gracefully.
    async fn clean(&self, request: Request<Empty>) -> Result<Response<OperationResponse>, Status> {
        debug!("Request from client: {:?}", request.remote_addr());
        self.cache
            .clone()
            .lock()
            .expect("Could not unlock cache. A thread was poisoned")
            .teardown()?;
        Ok(Response::new(OperationResponse { success: true }))
    }
}

#[derive(Parser, Debug)]
#[clap(version = env ! ("CARGO_PKG_VERSION"))]
pub struct Opts {
    /// location to store backup files
    #[clap(short, long)]
    dir: Option<String>,
    /// alternative uds location
    #[clap(short, long)]
    uds: Option<String>,
    /// optional time in seconds to time out after looking for a lease
    #[clap(short, long)]
    timeout: Option<u32>,
    /// activity timeout
    #[clap(short, long)]
    activity_timeout: Option<u64>,
}

/// Handle SIGINT signal.
///
/// Will wait until process receives a SIGINT/ ctrl+c signal and then clean up and shut down
async fn handle_signal(uds_path: PathBuf) {
    tokio::spawn(async move {
        // Handle signal hooks with expect, it is important these are setup so data is not corrupted
        let mut sigterm = signal(SignalKind::terminate()).expect("Could not set up SIGTERM hook");
        let mut sigint = signal(SignalKind::interrupt()).expect("Could not set up SIGINT hook");
        // Wait for either a SIGINT or a SIGTERM to clean up
        tokio::select! {
            _ = sigterm.recv() => {
                warn!("Received SIGTERM, cleaning up and exiting");
            }
            _ = sigint.recv() => {
                warn!("Received SIGINT, cleaning up and exiting");
            }
        }
        if let Err(e) = fs::remove_file(uds_path) {
            error!("Could not close uds socket: {}", e);
        }

        std::process::exit(0x0100);
    });
}

#[tokio::main]
pub async fn serve(opts: Opts) -> NetavarkResult<()> {
    let optional_run_dir = opts.dir.as_deref();
    let dora_timeout = opts.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let inactivity_timeout =
        Duration::from_secs(opts.activity_timeout.unwrap_or(DEFAULT_INACTIVITY_TIMEOUT));

    let uds_path = get_proxy_sock_fqname(optional_run_dir);
    debug!(
        "socket path: {}",
        &uds_path.clone().into_os_string().into_string().unwrap()
    );

    let mut is_systemd_activated = false;

    // check if the UDS is a systemd socket activated service.  if it is,
    // then systemd hands this over to us on FD 3.
    let uds: UnixListener = match env::var("LISTEN_FDS") {
        Ok(effds) => {
            if effds != "1" {
                return Err(NetavarkError::msg("Received more than one FD from systemd"));
            }
            is_systemd_activated = true;
            let systemd_socket = unsafe { stdUnixListener::from_raw_fd(3) };
            systemd_socket.set_nonblocking(true)?;
            UnixListener::from_std(systemd_socket)?
        }
        // Use the standard socket approach
        Err(..) => {
            // Create a new uds socket path
            match Path::new(&uds_path).parent() {
                None => {
                    return Err(NetavarkError::msg("Could not get parent from uds path"));
                }
                Some(f) => tokio::fs::create_dir_all(f).await?,
            }
            // Watch for signals after the uds path has been created, so that the socket can be closed.
            handle_signal(uds_path.clone()).await;
            UnixListener::bind(&uds_path)?
        }
    };

    let uds_stream = UnixListenerStream::new(uds);

    // Create the cache file
    let fq_cache_path = get_cache_fqname(optional_run_dir);
    let file = match File::create(&fq_cache_path) {
        Ok(file) => {
            debug!("Successfully created leases file: {:?}", fq_cache_path);
            file
        }
        Err(e) => {
            return Err(NetavarkError::msg(format!(
                "Exiting. Could not create lease cache file: {e}",
            )));
        }
    };

    let cache = match LeaseCache::new(file) {
        Ok(c) => Arc::new(Mutex::new(c)),
        Err(e) => {
            return Err(NetavarkError::msg(format!(
                "Could not setup the cache: {e}"
            )));
        }
    };

    // Create send and receive channels for activity timeout. If anything is
    // sent by the tx side, the inactivity timeout is reset
    let (activity_timeout_tx, activity_timeout_rx) = mpsc::channel(5);
    let netavark_proxy_service = NetavarkProxyService {
        cache: cache.clone(),
        dora_timeout,
        timeout_sender: Arc::new(Mutex::new(activity_timeout_tx.clone())),
    };

    let server = Server::builder()
        .add_service(NetavarkProxyServer::new(netavark_proxy_service))
        .serve_with_incoming(uds_stream);

    tokio::pin!(server);

    tokio::select! {
        //  a timeout duration of 0 means NEVER
        _ = handle_wakeup(activity_timeout_rx, inactivity_timeout, cache.clone()), if inactivity_timeout.as_secs() > 0  => {},
        _ = &mut server => {},
    };

    // Make sure to only remove the socket path when we do not run socket activated,
    // otherwise we delete the socket systemd is using which causes all new connections to fail.
    if !is_systemd_activated {
        fs::remove_file(uds_path)?;
    }
    Ok(())
}

/// manages the timeout lifecycle for the proxy server based on a defined timeout.
///
/// # Arguments
///
/// * `rx`: receive side of channel
/// * `timeout_duration`: time duration in seconds
///
/// returns: ()
///
/// # Examples
///
/// ```
///
/// ```
async fn handle_wakeup<W: Write + Clear>(
    mut rx: mpsc::Receiver<i32>,
    timeout_duration: Duration,
    current_cache: Arc<Mutex<LeaseCache<W>>>,
) {
    loop {
        match timeout(timeout_duration, rx.recv()).await {
            Ok(Some(_)) => {
                debug!("timeout timer reset")
            }
            Ok(None) => {
                println!("timeout channel closed");
                break;
            }
            Err(_) => {
                // only 'exit' if the timeout is met AND there are no leases
                // if we do not exit, the activity_timeout is reset
                if is_catch_empty(current_cache.clone()) {
                    println!(
                        "timeout met: exiting after {} secs of inactivity",
                        timeout_duration.as_secs()
                    );
                    break;
                }
            }
        }
    }
}

/// get_cache_len returns the number of leases in the hashmap in memory
///
/// # Arguments
///
/// * `current_cache`:
///
/// returns: usize
///
/// # Examples
///
/// ```
///
/// ```
fn is_catch_empty<W: Write + Clear>(current_cache: Arc<Mutex<LeaseCache<W>>>) -> bool {
    match current_cache.lock() {
        Ok(v) => {
            debug!("cache_len is {}", v.len().to_string());
            v.is_empty()
        }
        Err(e) => {
            log::error!("{}", e.to_string());
            false
        }
    }
}

/// Process network config into a lease and setup the ip
///
/// # Arguments
///
/// * `network_config`: Network config
/// * `timeout`: dora timeout
/// * `cache`: lease cache
///
/// returns: Result<Lease, Status>
async fn process_setup<W: Write + Clear>(
    network_config: NetworkConfig,
    timeout: &u32,
    cache: Arc<Mutex<LeaseCache<W>>>,
) -> Result<NetavarkLease, Status> {
    let container_network_interface = network_config.container_iface.clone();
    let ns_path = network_config.ns_path.clone();
    // Check mac address and add it to nc
    let mac_addr = network_config.container_mac_addr.clone();
    if mac_addr.is_empty() {
        return Err(Status::new(
            Code::InvalidArgument,
            "No mac address provided",
        ));
    }
    if MacAddr::from_str(&mac_addr).is_err() {
        return Err(Status::new(Code::InvalidArgument, "Invalid mac address"));
    };
    let nv_lease = DhcpService::new(&network_config, timeout)?
        .get_lease()
        .await?;
    debug!("found a lease for {:?}", mac_addr);

    if let Err(e) = cache
        .lock()
        .expect("Could not unlock cache. A thread was poisoned")
        .add_lease(&mac_addr, &nv_lease)
    {
        return Err(Status::new(
            Internal,
            format!("Error caching the lease: {e}"),
        ));
    }

    ip::setup(&nv_lease, &container_network_interface, &ns_path)?;
    Ok(nv_lease)
}
