#!/bin/bash

# This script configures the CI runtime environment.  It's intended
# to be used by Cirrus-CI, not humans.

set -e

source $(dirname $0)/lib.sh

# Only do this once
if [[ -r "/etc/ci_environment" ]]; then
    msg "It appears ${BASH_SOURCE[0]} already ran, exiting."
    exit 0
fi
trap "complete_setup" EXIT


msg "************************************************************"
msg "Setting up runtime environment"
msg "************************************************************"


show_env_vars

if [[ "$CIRRUS_TASK_NAME" == "build_cross" ]]; then
	# Setup short-name for rustembedded/cross
	# TODO: We can move this to quay.io if we reach rate-limits, hopefully that's not gonna happen for netavark
	echo '  "rustembedded/cross" = "docker.io/rustembedded/cross"'  >> /etc/containers/registries.conf.d/000-shortnames.conf
fi

if [[ "$CIRRUS_TASK_NAME" == "podman_e2e" ]]; then
	# build netavark
	make
	cp -v bin/netavark /usr/libexec/podman/
	# clone podman upstream main
	git clone https://github.com/containers/podman /var/tmp/go/src/github.com/containers/podman
	rm /usr/bin/podman
	make -C /var/tmp/go/src/github.com/containers/podman/ install.tools
	# compile podman
	make -C /var/tmp/go/src/github.com/containers/podman podman
	# compile and install aardvark-dns head
	dnf -y copr enable rhcontainerbot/podman-next
	dnf -y install aardvark-dns
fi
