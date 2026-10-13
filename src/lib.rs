#[macro_use]
extern crate serde;
extern crate serde_json;

pub mod commands;
pub mod dhcp_proxy;
pub mod dns;
pub mod error;
pub mod firewall;
pub mod network;
pub mod plugin;

pub mod netlink {
    //! `netavark`'s pinned `netlink-*` dependencies.
    //!
    //! **NOTE:** `netavark` *does not* offer or guarantee a stable API,
    //! it's pinned `netlink-*` dependencies are re-exported here exclusively
    //! in support of / as a convenience to plugin authors and other downstream
    //! consumers.
    pub use netlink_packet_core as packet_core;
    pub use netlink_packet_route as packet_route;
    pub use netlink_sys as sys;
}
