//Following module contains all the network constants

// default search domain
pub static PODMAN_DEFAULT_SEARCH_DOMAIN: &str = "dns.podman";

// IPAM drivers
pub const IPAM_HOSTLOCAL: &str = "host-local";
pub const IPAM_DHCP: &str = "dhcp";
pub const IPAM_NONE: &str = "none";

pub const DRIVER_BRIDGE: &str = "bridge";
pub const DRIVER_IPVLAN: &str = "ipvlan";
pub const DRIVER_MACVLAN: &str = "macvlan";

pub const OPTION_ISOLATE: &str = "isolate";
pub const OPTION_MTU: &str = "mtu";
pub const OPTION_MODE: &str = "mode";
pub const OPTION_METRIC: &str = "metric";

/// 100 is the default metric for most Linux networking tools.
pub const DEFAULT_METRIC: u32 = 100;

pub const NO_CONTAINER_INTERFACE_ERROR: &str = "no container interface name given";
