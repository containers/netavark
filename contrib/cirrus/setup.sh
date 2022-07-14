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

dnf -y install make automake gcc gcc-c++ kernel-devel

show_env_vars

if [[ "$CIRRUS_TASK_NAME" == "build_cross" ]]; then
	# Setup short-name for rustembedded/cross
	# TODO: We can move this to quay.io if we reach rate-limits, hopefully that's not gonna happen for netavark
	echo '  "rustembedded/cross" = "docker.io/rustembedded/cross"'  >> /etc/containers/registries.conf.d/000-shortnames.conf
fi

req_env_vars AARDVARK_DNS_URL

set -x  # show what's happening
curl --fail --location -o /tmp/aardvark-dns.zip "$AARDVARK_DNS_URL"
mkdir -p /usr/libexec/podman
cd /usr/libexec/podman
rm -f aardvark-dns*
unzip -o /tmp/aardvark-dns.zip
chmod a+x /usr/libexec/podman/aardvark-dns

