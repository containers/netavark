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
