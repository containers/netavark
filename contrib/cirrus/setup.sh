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

# To improve CI reliability and predictability, these operations
# should be moved into the VM Image building process managed from
# containers/automation_images repository.  For now, we do it here
# for simplicity and expediency sake.  Long-term, operations
# marked with calls to this function should be relocated.
warntodo() { warn "$1 - TODO: Move into static VM image"; }

warntodo "Updating OS"
# Support Cirrus-CI /var/cache/dnf caching
_dnf_opts="--exclude=kernel --setopt=keepcache=True --setopt=check_config_file_age=False --setopt=metadata_expire=14400"
retry dnf $_dnf_opts update -y

warntodo "Installing Rust toolchain"
retry dnf $_dnf_opts install -y rust clippy rustfmt cargo

# Oddly this is necessary to catch some corner-cases.
warntodo "Upgrading packages"
retry dnf $_dnf_opts update -y

# This is made performant by caching $CARGO_HOME
msg "Installing Rust packages (CARGO_HOME=$CARGO_HOME)"
retry cargo install mandown

# This database seems to change every time the above
# dnf commands are run.  Remove it to avoid unnecessary
# cache re-uploads, since it will be re-created next time
# it's needed.  All we really care to cache is metadata and RPMs
# anyway.  Everything else could be excluded from cache here,
# but all this should be going away when dedicated VM images
# are implemented.
warntodo "Clobbering cache-flapping packages.db"
rm -rf /var/cache/dnf/packages.db
