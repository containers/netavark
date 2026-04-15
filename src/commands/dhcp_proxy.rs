#![cfg_attr(not(unix), allow(unused_imports))]

use std::{
    collections::HashMap,
    env, fs,
    fs::File,
    io::Write,
    os::{
        fd::AsFd,
        unix::{io::FromRawFd, net::UnixListener as stdUnixListener},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
};

use clap::Parser;
use log::{debug, error, warn};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::{
    sync::{mpsc, mpsc::Sender, oneshot, oneshot::error::TryRecvError, watch},
    time::{timeout, Duration},
};
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{
    transport::Server,
    Code,
    Code::{Internal, InvalidArgument},
    Request, Response, Status,
};

use crate::{
    dhcp_proxy::{
        cache::{Clear, LeaseCache},
        dhcp_service::{process_client_stream, DhcpV4Service},
        ip,
        lib::g_rpc::{
            netavark_proxy_server::{NetavarkProxy, NetavarkProxyServer},
            Empty, Lease as NetavarkLease, NetworkConfig, OperationResponse,
        },
        proxy_conf::{
            get_cache_fqname, get_proxy_sock_fqname, DEFAULT_INACTIVITY_TIMEOUT, DEFAULT_TIMEOUT,
        },
    },
    error::{NetavarkError, NetavarkResult},
    network::core_utils,
};

struct DhcpWorker {
    handle: DhcpWorkerHandle,
    initial_lease_rx: oneshot::Receiver<Result<NetavarkLease, Status>>,
}

#[derive(Debug)]
struct DhcpWorkerHandle {
    shutdown_tx: watch::Sender<bool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DhcpWorkerHandle {
    fn shutdown(mut self) -> NetavarkResult<()> {
        let _ = self.shutdown_tx.send(true);

        match self.thread.take() {
            Some(thread) => match thread.join() {
                Ok(()) => Ok(()),
                Err(_) => Err(NetavarkError::msg("DHCP worker thread panicked")),
            },
            None => Ok(()),
        }
    }
}

#[derive(Debug)]
/// This is the tonic netavark proxy service that is required to impl the
/// Netavark Proxy trait which includes the gRPC methods defined in
/// proto/proxy.proto. We can store a atomically referenced counted mutex cache
/// in the structure tuple.
///
/// The cache needs to be **safely mutable across multiple threads**. We need to
/// share the lease cache across multiple threads for 2 reasons
/// 1. Each tonic request is spawned in its own new thread.
/// 2. A new thread must be spawned in any request that uses mozim, such as
///    get_lease. This is because tonic creates its own runtime for each request
///    and mozim trys to make its own runtime inside of a runtime.
struct NetavarkProxyService<W: Write + Clear> {
    // cache is the lease hashmap
    cache: Arc<Mutex<LeaseCache<W>>>,
    // the timeout for the dora operation
    dora_timeout: u32,
    // channel send-side for resetting the inactivity timeout
    timeout_sender: Option<Arc<Mutex<Sender<i32>>>>,
    // Keep a handle for each namespace-bound DHCP worker so teardown can shut
    // it down cleanly. The key is the container mac.
    task_map: Arc<Mutex<HashMap<String, DhcpWorkerHandle>>>,
}

impl<W: Write + Clear> NetavarkProxyService<W> {
    fn reset_inactivity_timeout(&self) {
        if let Some(sender) = &self.timeout_sender {
            let sender_clone = sender.clone();
            let locked_sender = match sender_clone.lock() {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{e}");
                    return;
                }
            };
            match locked_sender.try_send(1) {
                Ok(..) => {}
                Err(e) => log::error!("{e}"),
            }
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
        let task_map = self.task_map.clone();

        // setup client side streaming
        let network_config = request.into_inner();
        // _tx will be dropped when the request is dropped, this will trigger
        // rx, which means the client disconnected
        let (_tx, mut rx) = oneshot::channel::<()>();
        let lease = tokio::task::spawn(async move {
            // Check if the connection has been dropped before attempting to get a lease
            if rx.try_recv() == Err(TryRecvError::Closed) {
                log::debug!("Request dropped, aborting DORA");
                return Err(Status::new(Code::Aborted, "client disconnected"));
            }
            process_setup(network_config, timeout, cache, task_map, &mut rx).await
        })
        .await;
        return match lease {
            Ok(Ok(lease)) => Ok(Response::new(lease)),
            Ok(Err(status)) => Err(status),
            Err(e) => Err(Status::new(Code::Unknown, e.to_string())),
        };
    }

    /// When a container is shut down this method should be called. It will
    /// release the DHCP lease and clear the lease information from the
    /// caching system.
    async fn teardown(
        &self,
        request: Request<NetworkConfig>,
    ) -> Result<Response<NetavarkLease>, Status> {
        // notify server of activity
        self.reset_inactivity_timeout();
        let nc = request.into_inner();

        let cache = self.cache.clone();
        let tasks = self.task_map.clone();

        let maybe_worker = {
            let mut tasks_guard = tasks.lock().expect("lock tasks");
            tasks_guard.remove(&nc.container_mac_addr)
        };
        if let Some(worker) = maybe_worker {
            stop_dhcp_worker(&nc.container_mac_addr, worker).await;
        }

        // Remove the client from the cache dir
        let lease = cache
            .lock()
            .expect("Could not unlock cache. A thread was poisoned")
            .remove_lease(&nc.container_mac_addr)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(lease))
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
/// Will wait until process receives a SIGINT/ ctrl+c signal and then clean up
/// and shut down
async fn handle_signal(uds_path: PathBuf) {
    tokio::spawn(async move {
        // Handle signal hooks with expect, it is important these are setup so
        // data is not corrupted
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
            error!("Could not close uds socket: {e}");
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
    debug!("socket path: {}", &uds_path.display());

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
            // Watch for signals after the uds path has been created, so that
            // the socket can be closed.
            handle_signal(uds_path.clone()).await;
            UnixListener::bind(&uds_path)?
        }
    };

    let uds_stream = UnixListenerStream::new(uds);

    // Create the cache file
    let fq_cache_path = get_cache_fqname(optional_run_dir);
    let file = match File::create(&fq_cache_path) {
        Ok(file) => {
            debug!("Successfully created leases file: {fq_cache_path:?}");
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
    let (activity_timeout_tx, activity_timeout_rx) = if inactivity_timeout.as_secs() > 0 {
        let (tx, rx) = mpsc::channel(5);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let netavark_proxy_service = NetavarkProxyService {
        cache: cache.clone(),
        dora_timeout,
        timeout_sender: activity_timeout_tx
            .clone()
            .map(|tx| Arc::new(Mutex::new(tx))),
        task_map: Arc::new(Mutex::new(HashMap::new())),
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

    // Make sure to only remove the socket path when we do not run socket
    // activated, otherwise we delete the socket systemd is using which
    // causes all new connections to fail.
    if !is_systemd_activated {
        fs::remove_file(uds_path)?;
    }
    Ok(())
}

/// manages the timeout lifecycle for the proxy server based on a defined
/// timeout.
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
/// ```
async fn handle_wakeup<W: Write + Clear>(
    rx: Option<mpsc::Receiver<i32>>,
    timeout_duration: Duration,
    current_cache: Arc<Mutex<LeaseCache<W>>>,
) {
    if let Some(mut rx) = rx {
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
/// ```
fn is_catch_empty<W: Write + Clear>(current_cache: Arc<Mutex<LeaseCache<W>>>) -> bool {
    match current_cache.lock() {
        Ok(v) => {
            debug!("cache_len is {}", v.len());
            v.is_empty()
        }
        Err(e) => {
            log::error!("{e}");
            false
        }
    }
}

fn spawn_dhcp_worker(network_config: NetworkConfig, timeout: u32) -> Result<DhcpWorker, Status> {
    let thread_name = format!("netavark-dhcp-{}", network_config.container_mac_addr);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (initial_lease_tx, initial_lease_rx) = oneshot::channel();

    let thread = thread::Builder::new()
        .name(thread_name)
        .spawn(move || dhcp_worker_thread(network_config, timeout, shutdown_rx, initial_lease_tx))
        .map_err(|e| Status::new(Code::Internal, format!("failed to spawn DHCP worker: {e}")))?;

    Ok(DhcpWorker {
        handle: DhcpWorkerHandle {
            shutdown_tx,
            thread: Some(thread),
        },
        initial_lease_rx,
    })
}

async fn stop_dhcp_worker(container_mac_addr: &str, worker: DhcpWorkerHandle) {
    match tokio::task::spawn_blocking(move || worker.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(
                "Failed to stop DHCP worker for {}: {}",
                container_mac_addr, err
            );
        }
        Err(err) => {
            warn!(
                "Failed to join DHCP worker for {}: {}",
                container_mac_addr, err
            );
        }
    }
}

fn dhcp_worker_thread(
    network_config: NetworkConfig,
    timeout: u32,
    shutdown_rx: watch::Receiver<bool>,
    initial_lease_tx: oneshot::Sender<Result<NetavarkLease, Status>>,
) {
    let host_ns = match File::open("/proc/self/ns/net") {
        Ok(file) => file,
        Err(err) => {
            let _ = initial_lease_tx.send(Err(Status::new(
                Code::Internal,
                format!("failed to open host network namespace: {err}"),
            )));
            return;
        }
    };

    let container_ns = match File::open(&network_config.ns_path) {
        Ok(file) => file,
        Err(err) => {
            let _ = initial_lease_tx.send(Err(Status::new(
                Code::Internal,
                format!(
                    "failed to open target network namespace {}: {err}",
                    network_config.ns_path
                ),
            )));
            return;
        }
    };

    if let Err(err) = core_utils::join_netns(container_ns.as_fd()) {
        let _ = initial_lease_tx.send(Err(Status::new(
            Code::Internal,
            format!(
                "failed to join target network namespace {}: {err}",
                network_config.ns_path
            ),
        )));
        return;
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = initial_lease_tx.send(Err(Status::new(
                Code::Internal,
                format!("failed to build DHCP worker runtime: {err}"),
            )));
            let _ = core_utils::join_netns(host_ns.as_fd());
            return;
        }
    };

    runtime.block_on(run_dhcp_worker(
        network_config,
        timeout,
        shutdown_rx,
        initial_lease_tx,
    ));

    if let Err(err) = core_utils::join_netns(host_ns.as_fd()) {
        warn!("Failed to restore host network namespace for DHCP worker: {err}");
    }
}

async fn run_dhcp_worker(
    network_config: NetworkConfig,
    timeout: u32,
    mut shutdown_rx: watch::Receiver<bool>,
    initial_lease_tx: oneshot::Sender<Result<NetavarkLease, Status>>,
) {
    let container_mac_addr = network_config.container_mac_addr.clone();

    let mut service = match DhcpV4Service::new(network_config, timeout).await {
        Ok(service) => service,
        Err(err) => {
            let _ = initial_lease_tx.send(Err(Status::from(err)));
            return;
        }
    };

    let initial_lease = tokio::select! {
        changed = shutdown_rx.changed() => {
            match changed {
                Ok(_) if *shutdown_rx.borrow_and_update() => return,
                Ok(_) => return,
                Err(_) => return,
            }
        }
        lease = service.get_lease() => {
            match lease {
                Ok(lease) => lease,
                Err(err) => {
                    let _ = initial_lease_tx.send(Err(Status::from(err)));
                    return;
                }
            }
        }
    };

    if initial_lease_tx.send(Ok(initial_lease)).is_err() {
        if let Err(err) = service.release_lease().await {
            warn!(
                "Failed to release DHCP lease for {} after setup cancellation: {}",
                container_mac_addr, err
            );
        }
        return;
    }

    process_client_stream(&mut service, &mut shutdown_rx).await;

    if let Err(err) = service.release_lease().await {
        warn!(
            "Failed to send DHCPRELEASE for {}: {}",
            container_mac_addr, err
        );
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
    timeout: u32,
    cache: Arc<Mutex<LeaseCache<W>>>,
    tasks: Arc<Mutex<HashMap<String, DhcpWorkerHandle>>>,
    client_disconnect: &mut oneshot::Receiver<()>,
) -> Result<NetavarkLease, Status> {
    let container_network_interface = network_config.container_iface.clone();
    let ns_path = network_config.ns_path.clone();

    // test if mac is valid
    core_utils::CoreUtils::decode_address_from_hex(&network_config.container_mac_addr)
        .map_err(|e| Status::new(InvalidArgument, format!("{e}")))?;
    let mac = network_config.container_mac_addr.clone();

    let nv_lease = match network_config.version {
        //V4
        0 => {
            let worker = spawn_dhcp_worker(network_config, timeout)?;
            let mut initial_lease_rx = worker.initial_lease_rx;
            let mut worker_handle = Some(worker.handle);

            let lease = tokio::select! {
                _ = client_disconnect => {
                    if let Some(handle) = worker_handle.take() {
                        stop_dhcp_worker(&mac, handle).await;
                    }
                    return Err(Status::new(Code::Aborted, "client disconnected"));
                }
                result = &mut initial_lease_rx => {
                    result
                        .map_err(|_| Status::new(Code::Internal, "DHCP worker exited before returning a lease"))??
                }
            };

            let cache_add_result = {
                cache
                    .lock()
                    .expect("Could not unlock cache. A thread was poisoned")
                    .add_lease(&mac, &lease)
            };
            if let Err(e) = cache_add_result {
                if let Some(handle) = worker_handle.take() {
                    stop_dhcp_worker(&mac, handle).await;
                }
                return Err(Status::new(
                    Internal,
                    format!("Error caching the lease: {e}"),
                ));
            }

            if let Err(err) = ip::setup(&lease, &container_network_interface, &ns_path) {
                let _ = {
                    cache
                        .lock()
                        .expect("Could not unlock cache. A thread was poisoned")
                        .remove_lease(&mac)
                };
                if let Some(handle) = worker_handle.take() {
                    stop_dhcp_worker(&mac, handle).await;
                }
                return Err(Status::from(err));
            }

            let replaced_worker = {
                let mut tasks_guard = tasks.lock().expect("lock tasks");
                tasks_guard.insert(
                    mac.clone(),
                    worker_handle.take().expect("worker handle must be present"),
                )
            };
            if let Some(worker) = replaced_worker {
                warn!("Replacing existing DHCP worker for {}", mac);
                stop_dhcp_worker(&mac, worker).await;
            }

            lease
        }
        //V6 TODO implement DHCPv6
        1 => {
            return Err(Status::new(InvalidArgument, "ipv6 not yet supported"));
        }
        _ => {
            return Err(Status::new(InvalidArgument, "invalid protocol version"));
        }
    };

    Ok(nv_lease)
}
