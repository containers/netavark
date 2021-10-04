# netavark: A container network stack

Netavark is a rust based network stack for containers.  It is being designed
to work with [Podman](https://github.com/containers/podman) but is also applicable
for other OCI container management applications.

## Overview and scope

Netavark is capable of the following given the proper JSON input:
* Create, manage, and destroy network interfaces including bridge and macvlan
* Configure firewall (NAT) and port mapping rules
* Support IPv4 and IPv6

As this project is in very early development, we will add more capabilities in
the near future.

## Requires

- [Rust](https://www.rust-lang.org/tools/install)

## Build

```console
$ make
```
## Latest release
Not applicable yet (TBD)

## Latest release
Not applicable yet (TBD)

## Communications

For general questions and discussion, please use Podman's
[channels](https://podman.io/community/#slack-irc-matrix-and-discord).

For discussions around issues/bugs and features, you can use the GitHub
[issues](https://github.com/containers/netavark/issues)
and [PRs](https://github.com/containers/netavark/pulls) tracking system.
