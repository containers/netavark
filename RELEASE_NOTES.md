# Release Notes

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
* Implemented locking when commiting
* Remove bridge only when no containers are attached
* Updated versions of libraries where possible

## v1.1.0
* Netavark is now capable of starting Aardvark on a port other than 53 (controlled by `dns_bind_port` in `containers.conf`). Firewall rules are added to ensure DNS still functions properly despite the port change.
* Added the ability to isolate networks. Networks with the isolate option set cannot communicate with other networks with the isolate option set.
* Improved the way Aardvark is launched to avoid potential race conditions where DNS would not be ready when containers were started.
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
