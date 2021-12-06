# Netavark integration test with bats

## Running tests

To run the tests locally in your sandbox, you can use one of these methods:
* bats ./test/001-basic.bats  # runs just the specified test
* bats ./test/                # runs all

The tests need root privileges to create network namespaces, so you either have to run the test as root or in a user namespace. Because the tests use iptables you also need write access to `/run/xtables.lock`. You can use `podman unshare --rootless-netns bats test/` to run the tests as rootless user.

## Requirements
- jq
- iproute2
- iptables
- firewalld
- dbus-daemon
- ncat
