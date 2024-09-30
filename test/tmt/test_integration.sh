#!/usr/bin/env bash

set -exo pipefail

cat /etc/redhat-release

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# Install dependencies for running tests
dnf -y install \
    bats \
    bind-utils \
    bridge-utils \
    cargo \
    clippy \
    dbus-daemon \
    dnsmasq \
    firewalld \
    go-md2man \
    iptables \
    jq \
    make \
    net-tools \
    nftables \
    nmap-ncat \
    rustfmt

rpm -q aardvark-dns cargo netavark

systemctl status firewalld dnsmasq

# Run tests
make -C ../.. NETAVARK=/usr/libexec/podman/netavark TEST_PLUGINS=/usr/share/netavark/test/examples integration
