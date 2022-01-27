# libz-sys

A common library for linking `libz` to rust programs (also known as zlib).

[Documentation](https://docs.rs/libz-sys)

# High-level API

This crate provides bindings to the raw low-level C API. For a higher-level
safe API to work with DEFLATE, zlib, or gzip streams, see
[`flate2`](https://docs.rs/flate2). `flate2` also supports alternative
implementations, including slower but pure Rust implementations.

# zlib-ng

This crate supports building either the high-performance zlib-ng (in
zlib-compat mode), or the widely available stock zlib.

By default, `libz-sys` uses stock zlib, primarily because doing so allows the
use of a shared system zlib library if available.

Any application or library designed for zlib should work with zlib-ng in
zlib-compat mode, as long as it doesn't make assumptions about the exact size
or output of the deflated data (e.g. "compressing this data produces exactly
this many bytes"), and as long as you don't also dynamically pull in a copy of
stock zlib (which will produce conflicting symbols). Nonetheless, for maximum
compatibility, every library crate in a build must opt into allowing zlib-ng;
if any library crate in your dependency graph wants stock zlib, `libz-sys` will
use stock zlib.

Library crates depending on `libz-sys` should use:
```
libz-sys = { version = "1.1.0", default-features = false, features = ["libc"] }
```
(Omit the `libc` feature if you don't require the corresponding functions.)

This allows higher-level crates depending on your library to opt into zlib-ng
if desired.

Building zlib-ng requires `cmake`.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `libz-sys` by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
