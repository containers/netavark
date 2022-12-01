#!/bin/bash

set -eo pipefail

# This script runs in the Cirrus CI environment, invoked from .cirrus.yml .
# It can also be invoked manually in a `hack/get_ci_cm.sh` environment,
# documentation of said usage is TBI.
#
# The principal deciding factor is the first argument.  For any
# given value 'xyz' there must be a function '_run_xyz' to handle that
# argument.

source $(dirname ${BASH_SOURCE[0]})/lib.sh

_run_noarg() {
    die "runner.sh must be called with a single argument"
}

_run_build() {
    # Assume we're on a fast VM, compile everything needed by the
    # rest of CI since subsequent tasks may have limited resources.
    make all debug=1
    make build_unit  # reuses some debug binaries
    make all  # optimized/non-debug binaries
    # This will get scooped up and become part of the artifact archive.
    # Identify where the binary came from to benefit downstream consumers.
    cat | tee bin/netavark.info << EOF
repo: $CIRRUS_REPO_CLONE_URL
branch: $CIRRUS_BASE_BRANCH
title: $CIRRUS_CHANGE_TITLE
commit: $CIRRUS_CHANGE_IN_REPO
build: https://cirrus-ci.com/build/$CIRRUS_BUILD_ID
task: https://cirrus-ci.com/task/$CIRRUS_TASK_ID
EOF
}

_run_build_aarch64() {
    _run_build
}

_run_validate() {
    make validate
}

_run_validate_aarch64() {
    _run_validate
}

_run_unit() {
    make unit
}

_run_unit_aarch64() {
    _run_unit
}

_run_integration() {
    make integration
}

_run_integration_aarch64() {
    _run_integration
}

show_env_vars

msg "************************************************************"
msg "Toolchain details"
msg "************************************************************"

rustc --version
cargo --version

msg "************************************************************"
msg "Runner executing '$1' on $OS_REL_VER"
msg "************************************************************"

((${SETUP_ENVIRONMENT:-0})) || \
    die "Expecting setup.sh to have completed successfully"

cd "${CIRRUS_WORKING_DIR}/"

handler="_run_${1:-noarg}"

if [ "$(type -t $handler)" != "function" ]; then
    die "Unknown/Unsupported runner.sh argument '$1'"
fi

$handler
