#!/usr/bin/env bash

set -exo pipefail

uname -r
rpm -q aardvark-dns netavark netavark-tests

# Run integration tests
bats /usr/share/netavark/test

# Run DHCP tests
bats /usr/share/netavark/test-dhcp
