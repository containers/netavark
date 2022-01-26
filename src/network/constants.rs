//Following module contains all the network constants

// default search domain
pub static PODMAN_DEFAULT_SEARCH_DOMAIN: &str = "dns.podman";

// Available macvlan modes
// TODO: remove constants from here after https://github.com/little-dude/netlink/pull/200
pub const MACVLAN_MODE_PRIVATE: u32 = 1;
pub const MACVLAN_MODE_VEPA: u32 = 2;
pub const MACVLAN_MODE_BRIDGE: u32 = 4;
pub const MACVLAN_MODE_PASSTHRU: u32 = 8;
pub const MACVLAN_MODE_SOURCE: u32 = 16;
