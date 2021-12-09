Rust iptables
=============

[![crates.io](https://img.shields.io/crates/v/iptables.svg)](https://crates.io/crates/iptables) [![Documentation](https://img.shields.io/badge/Docs-iptables-blue.svg)](https://docs.rs/iptables) [![Build Status](https://travis-ci.org/yaa110/rust-iptables.svg)](https://travis-ci.org/yaa110/rust-iptables) [![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/yaa110/rust-iptables/blob/master/LICENSE)

This crate provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux (inspired by [go-iptables](https://github.com/coreos/go-iptables)). This crate uses iptables binary to manipulate chains and tables. This source code is licensed under MIT license that can be found in the LICENSE file.

```toml
[dependencies]
iptables = "0.4"
```

## Getting started
1- Import the crate `iptables` and manipulate chains:

```rust
let ipt = iptables::new(false).unwrap();

assert!(ipt.new_chain("nat", "NEWCHAINNAME").is_ok());
assert!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
assert!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap());
assert!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
assert!(ipt.delete_chain("nat", "NEWCHAINNAME").is_ok());
```

For more information, please check the test file in `tests` folder.
