#![deny(rust_2018_idioms)]
#![doc(
    html_logo_url = "https://storage.googleapis.com/fdo-gitlab-uploads/project/avatar/3213/zbus-logomark.png"
)]

//! This crate provides collection of types for various [D-Bus bus names][dbn].
//!
//! This is used by [`zbus`] (and in future by [`zbus_macros`] as well) crate. Other D-Bus crates
//! are also encouraged to use this API in the spirit of cooperation. :)
//!
//! [dbn]: https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names
//! [`zbus`]: https://crates.io/crates/zbus
//! [`zbus_macros`]: https://crates.io/crates/zbus_macros

mod bus_name;
pub use bus_name::*;

mod unique_name;
pub use unique_name::*;

mod well_known_name;
pub use well_known_name::*;

mod interface_name;
pub use interface_name::*;

mod member_name;
pub use member_name::*;

mod error;
pub use error::*;
