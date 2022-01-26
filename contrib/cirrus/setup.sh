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

if [[ "$1" == "cross" ]]; then
    msg "Installing gcc cross-compile packages"
    err_retry 8 1000 "" dnf install -y \
        qemu-user-static \
        'gcc-*-linux-gnu' \
        'gcc-c++-*-linux-gnu'

    # This is required by rustup-init (it will complain if any tools are in $PATH)
    rust_version=$(rpm -q --qf '%{v}' rust)
    msg "Replacing Fedora native rust toolchain with upstream '$rust_version'"
    dnf erase -y cargo rust rust-std-static

    msg "Initializing upstream rust environment."
    mkdir -p $CARGO_HOME/bin/
    cd $CARGO_HOME/bin/
    curl --fail --silent --location -O --url \
        "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    chmod +x rustup-init
    # complete_setup() will take care of updating $PATH properly
    showrun ./rustup-init -y \
        --default-toolchain "$rust_version" \
        --no-modify-path \
        --target $(tr ' ' ','<<<"$CROSS_TARGETS")
fi
