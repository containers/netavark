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

req_env_vars AARDVARK_DNS_URL AARDVARK_DNS_BRANCH
cd /usr/libexec/podman
rm -vf aardvark-dns*
if showrun curl --fail --location -o /tmp/aardvark-dns.zip "$AARDVARK_DNS_URL" && \
   unzip -o /tmp/aardvark-dns.zip; then

    if [[ $(uname -m) != "x86_64" ]]; then
        showrun mv aardvark-dns.$(uname -m)-unknown-linux-gnu aardvark-dns
    fi
    showrun chmod a+x /usr/libexec/podman/aardvark-dns
else
    warn "Error downloading/extracting the latest pre-compiled aardvark binary from CI"
    showrun cargo install \
      --root /usr/libexec/podman \
      --git https://github.com/containers/aardvark-dns \
      --branch "$AARDVARK_DNS_BRANCH"
    mv -v /usr/libexec/podman/bin/aardvark-dns /usr/libexec/podman
fi
# show aardvark commit in CI logs
showrun /usr/libexec/podman/aardvark-dns version

# Warning, this isn't the end.  An exit-handler is installed to finalize
# setup of env. vars.  This is required for runner.sh to operate properly.
# See complete_setup() in lib.sh for details.
