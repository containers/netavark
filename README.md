# netavark: A container network stack

Netavark is a rust based network stack for containers.  It is being designed
to work with [Podman](https://github.com/containers/podman) but is also applicable
for other OCI container management applications.

## Overview and scope

Netavark is a tool for configuring networking for Linux containers. Its features include:
* Configuration of container networks via JSON configuration file
* Creation and management of required network interfaces, including MACVLAN networks
* All required firewall configuration to perform NAT and port forwarding as required for containers
* Support for firewalld and nftables
* Support for rootless containers
* Support for IPv4 and IPv6
* Support for container DNS resolution via the [aardvark-dns](https://github.com/containers/aardvark-dns) project

## Requires

- [go-md2man](https://github.com/cpuguy83/go-md2man)
- [Rust](https://www.rust-lang.org/tools/install)
- [Podman](https://podman.io/docs) 4.0+
- [protoc](https://grpc.io/docs/protoc-installation/)

At runtime, Netavark needs at least Linux kernel 4.20. It relies on
`NETLINK_GET_STRICT_CHK` strict netlink checking, which was added in 4.20; on
older kernels netlink calls fail with `Protocol not available`
(EPROTONOSUPPORT). This is a lower bound rather than a tested floor: kernels
older than those in CI are not exercised, so it is possible that other parts of
Netavark already require something newer than 4.20.

## MSRV (Minimum Supported Rust Version)

v1.88

We test that Netavark can be build on this Rust version and on some newer versions.
All newer versions should also build, and if they do not, the issue should be
reported and will be fixed. Older versions are not guaranteed to build and issues
will not be fixed.

## Build

```console
$ make
```
## Test
```console
$ make test
```
Also see [./test](./test/README.md) for more information.

## Communications

For general questions and discussion, please use Podman's
[channels](https://podman.io/community/).

For discussions around issues/bugs and features, you can use the GitHub
[issues](https://github.com/containers/netavark/issues)
and [PRs](https://github.com/containers/netavark/pulls) tracking system.

## Plugins

Netavark also supports executing external plugins, see [./plugin-API.md](./plugin-API.md).

## [Contributing](./CONTRIBUTING.md)
