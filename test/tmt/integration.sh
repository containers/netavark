#!/usr/bin/env bash

set -exo pipefail

rpm -q aardvark-dns cargo netavark

# Run tests
bats /usr/share/netavark/test
