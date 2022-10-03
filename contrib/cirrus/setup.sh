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

req_env_vars AARDVARK_DNS_URL

showrun curl --fail --location -o /tmp/aardvark-dns.zip "$AARDVARK_DNS_URL"
mkdir -p /usr/libexec/podman
cd /usr/libexec/podman
rm -f aardvark-dns*
showrun unzip -o /tmp/aardvark-dns.zip
if [[ $(uname -m) != "x86_64" ]]; then
    showrun mv aardvark-dns.$(uname -m)-unknown-linux-gnu aardvark-dns
fi
showrun chmod a+x /usr/libexec/podman/aardvark-dns

# Warning, this isn't the end.  An exit-handler is installed to finalize
# setup of env. vars.  This is required for runner.sh to operate properly.
# See complete_setup() in lib.sh for details.
