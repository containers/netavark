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
pub const ISOLATE_OPTION_TRUE: &str = "true";
pub const ISOLATE_OPTION_FALSE: &str = "false";
pub const ISOLATE_OPTION_STRICT: &str = "strict";
pub const OPTION_MTU: &str = "mtu";
pub const OPTION_MODE: &str = "mode";
pub const OPTION_METRIC: &str = "metric";
pub const OPTION_NO_DEFAULT_ROUTE: &str = "no_default_route";
pub const OPTION_BCLIM: &str = "bclim";
pub const OPTION_VRF: &str = "vrf";
pub const OPTION_VLAN: &str = "vlan";
pub const OPTION_HOST_INTERFACE_NAME: &str = "host_interface_name";
pub const OPTION_OUTBOUND_ADDR4: &str = "outbound_addr4";
pub const OPTION_OUTBOUND_ADDR6: &str = "outbound_addr6";

pub const MACVLAN_MODE_PRIVATE: &str = "private";
pub const MACVLAN_MODE_VEPA: &str = "vepa";
pub const MACVLAN_MODE_BRIDGE: &str = "bridge";
pub const MACVLAN_MODE_PASSTHRU: &str = "passthru";

/// 100 is the default metric for most Linux networking tools.
pub const DEFAULT_METRIC: u32 = 100;

pub const NO_CONTAINER_INTERFACE_ERROR: &str = "no container interface name given";

/// make sure this is the same rootful default as used in podman.
pub const DEFAULT_CONFIG_DIR: &str = "/run/containers/networks";

pub const MAX_INTERFACE_NAME_LEN: usize = 15;

// valid ipvlan driver modes.
pub const IPVLAN_MODE_L2: &str = "l2";
pub const IPVLAN_MODE_L3: &str = "l3";
pub const IPVLAN_MODE_L3S: &str = "l3s";

// ValidIPVLANModes is the list of valid mode options for the ipvlan driver.
pub const VALID_IPVLAN_MODES: &[&str] = &[IPVLAN_MODE_L2, IPVLAN_MODE_L3, IPVLAN_MODE_L3S];

// ValidMacVlanModes is the list of valid option constants for the macvlan driver.
pub const VALID_MACVLAN_MODES: &[&str] = &[
    MACVLAN_MODE_PRIVATE,
    MACVLAN_MODE_VEPA,
    MACVLAN_MODE_BRIDGE,
    MACVLAN_MODE_PASSTHRU,
];
