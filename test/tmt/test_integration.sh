#!/usr/bin/env bash

set -exo pipefail

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# Install dependencies for running tests
dnf -y update aardvark-dns

rpm -q aardvark-dns cargo netavark

# Run tests
make -C ../.. NETAVARK=/usr/libexec/podman/netavark TEST_PLUGINS=/usr/share/netavark/test/examples integration
