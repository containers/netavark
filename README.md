# netavark: A container network stack

Netavark is a rust based network stack for containers.  It is being designed
to work with [Podman](https://github.com/containers/podman) but is also applicable
for other OCI container management applications.

## Overview and scope

Netavark is a tool for configuring networking for Linux containers. Its features include:
* Configuration of container networks via JSON configuration file
* Creation and management of required network interfaces, including MACVLAN networks
* All required firewall configuration to perform NAT and port forwarding as required for containers
* Support for iptables and firewalld at present, with support for nftables planned in a future release
* Support for rootless containers
* Support for IPv4 and IPv6
* Support for container DNS resolution via the [aardvark-dns](https://github.com/containers/aardvark-dns) project

## Requires

- [Rust](https://www.rust-lang.org/tools/install)
- [Podman](https://podman.io/getting-started/) 4.0+

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
[channels](https://podman.io/community/#slack-irc-matrix-and-discord).

For discussions around issues/bugs and features, you can use the GitHub
[issues](https://github.com/containers/netavark/issues)
and [PRs](https://github.com/containers/netavark/pulls) tracking system.

## Plugins

Netavark also supports executing external plugins, see [./plugin-API.md](./plugin-API.md).
