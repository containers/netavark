# Release Notes

## v1.16.1

* Fixed an incompatibility with nftables 1.1.4 json output which broke the firewall rule generation. ([#1303](https://github.com/containers/netavark/issues/1303))

## v1.16.0

* The netavark bridge driver now defaults to using the MTU of the default route interface when no explicit MTU was configured for the network. This helps in environments where a non standard MTU is used. ([containers/podman#20009](https://github.com/containers/podman/issues/20009))
* Netavark now creates sysctl config files under /run/sysctl.d (only when running as root and with systemd as init system) for the sysctl values we configure for our bridge/veth interface. This ensures that running `sysctl --system` or systemd-sysctl won't revert them back to its original value.
* The MSRV has been bumped to v1.83.
* Dependency updates.

## v1.15.2

* Fixed a bug that caused a thread leak in the dhcp-proxy for each started container. ([#811](https://github.com/containers/netavark/issues/811))
* Fixed a bug which printed bogus errors when the dhcp-proxy was run with an activity timeout of 0. ([#1262](https://github.com/containers/netavark/issues/1262))

## v1.15.1

* Fixed a regression that caused container name lookups to get the wrong ip address when the host's search domain responded for the same name. ([containers/podman#26198](https://github.com/containers/podman/issues/26198))

## v1.15.0

* Fixed an issue where invalid dns names that included a space would cause aardvark-dns to crash. Instead such names are now ignored and generate a warning. ([#1019](https://github.com/containers/netavark/issues/1019))
* Netavark teardown now ignores SIGTERM and SIGINT signals to prevent interfaces/firewall rules from leaking during teardown. ([#1223](https://github.com/containers/netavark/issues/1223))
* Netavark no longer set the dns.podman search domain in the response. Aardvark-dns sill uses that name and resolves it but it will no longer be added to the containers resolv.conf because of that. ([#1133](https://github.com/containers/netavark/issues/1133))
* The MSRV has been bumped to v1.77.
* Dependency updates.

## v1.14.1

* Fixed an issue where the Makefile did not install the `netavark-firewalld(7)` man page. ([#1179](https://github.com/containers/netavark/issues/1179))
* Fixed the detection of Firewalld's StrictForwardPorts property.
* Upstream tests no longer check for the commit sha in the version output by default so downstream tests on packaged versions without the commit info can pass.

## v1.14.0

* bridge: Add support for a new option called `mode`. When set to `unmanaged` only the veth pair and ip addresses are setup. The bridge must exist and no firewall or sysctl setting will be configured in this mode. ([#1090](https://github.com/containers/netavark/issues/1090))
* bridge: Add support for DHCP when using unmanaged mode. ([#868](https://github.com/containers/netavark/issues/868))
* bridge: Add support for the `vlan` option. ([#1028](https://github.com/containers/netavark/issues/1028))
* When using DHCP netavark will now send the container hostname in the DHCP request and use the container id as client id. ([#676](https://github.com/containers/netavark/issues/676))
* The firewalld driver was improved and major outstanding bugs were addressed but is still considered experimental. A new man page `netavark-firewalld(7)` has been added to document some of the firewalld interactions.
* Dependency updates.

## v1.13.1

* Fixed a bug where port forwarding rules might not be removed correctly on nftables when different host ips are used for the same port. ([#1129](https://github.com/containers/netavark/issues/1129))
* On aardvark-dns setup errors properly cleanup interfaces and firewall rules again. ([#1121](https://github.com/containers/netavark/issues/1121))

## v1.13.0

* Fixed bug where port forwarding rules might not be removed correctly on nftables
* Add DNS DNAT rules first with nftables

## v1.12.2

* Ensure DNS rules cover TCP for iptables and nftables
* On ardvark-dns start, delete entries again on failure

## v1.12.1

* Fixed problem with categories in Cargo.toml that prevented us from publishing v1.12.0

## v1.12.0

* Dependency updates
* Netavark-DHCP proxy: use dns servers from dhcp lease
* Improved handling and visibility of errors from aardvark-dns
* Use nftables as default driver for Fedora 41

## v1.11.0

* Do not perform namespace detection for aardvark-dns updates as it is not needed
* Fixed condition where ignored errors were being returned as real
* With nftables, only dump netavark table rules
* Fix port forward with strict RPF and multi-networks
* updated dependencies

## v1.10.1

* updated nftables to 0.3

## v1.10.0

* added an nftables backend that allows its use on systems without iptables installed
* added command line option to change firewall driver
* show error if process is in wrong netns
* removed unessesary unlock lockfile calls
* updated dependencies

## v1.9.0

* add firewalld-reload subcommand
* bridge: force static mac on bridge interface
* dependency updates
* numerous fixes to test suite

## v1.8.0

* iptables: improve error when ip6?tables commands are missing
* docs: Convert markdown with go-md2man instead of mandown
* iptables: drop invalid packages
* bump rust edition to 2021
* Add ACCEPT rules in firewall for bridge network with internal dns
* Add vrf support for bridges

## v1.7.0

* Fix misleading dns disabled log
* Dependency updates
* --config is now required when dns is used
* netavark dhcp-proxy correctly renews the lease after dhcp time-out
* bridge: isolate=strict option has been added
* macvlan: bclim option has been added
* "no_default_route" option has been added
* static routes can now be configured

## v1.6.0

* Now supports a driver plugin module for user defined network drivers
* Initial MACVLAN DHCP support (additional unit file required for packagers)
* Dependency updates

## v1.5.0

* Removed crossbeam-utils
* Dependency updates
* Preliminary macvlan dhcp support (not fully supported yet)
* Addition of ipvlan support

## v1.4.0

* Added network update command
* Corrected issue #491 to only teardown network forwarding when on complete teardown only
* Fixed some rust documentation

## v1.3.0

* Housekeep and code cleanup
* macvlan: remove tmp interface when name already used in netns
* Add support for route metrics
* netlink: return better error if ipv6 is disabled
* macvlan: fix name collision on hostns
* Ignore dns-enabled for macvlan (BZ2137320)
* better errors on teardown
* allow customer dns servers for containers
* do not set route for internal-only networks
* do not use ipv6 autoconf

## v1.2.0

* Reworked how netavark calls aardvark
* Implemented locking when committing
* Remove bridge only when no containers are attached
* Updated versions of libraries where possible

## v1.1.0

* Netavark is now capable of starting Aardvark on a port other than 53 (controlled by `dns_bind_port`
  in `containers.conf`). Firewall rules are added to ensure DNS still functions properly despite the port change.
* Added the ability to isolate networks. Networks with the isolate option set cannot communicate with other networks
  with the isolate option set.
* Improved the way Aardvark is launched to avoid potential race conditions where DNS would not be ready when containers
  were started.
* Fixed a bug where Aardvark could not be run in environments with a read-only `/proc` (e.g. inside a container).

## v1.0.3

* Updated dependenciess
* Simplified option parsing for bridge/macvlan
* Added support for an ipam `none` driver

## v1.0.2

* Fix issue [#13533](https://github.com/containers/podman/issues/13533) - only use systemd when present
* Dropped vergen dependency
* Updated several dependency libraries
* Allow macvlans to not require a default gateway

## v1.0.1

* core,macvlan: add gateway as default route to macvlan interface
* Add host_ip and container_ip version matching to iptables portforwardinhg
* Remove vendor directory from upstream github repo

## v1.0.0

* First official release of netavark

## v1.0.0-RC2

* RC2 containers several bug fixes and code cleanup

## v1.0.0-RC1

* This is the first release candidate of Netavark. All functionality should be working.
