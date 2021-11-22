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
    make all
}

_run_validate() {
    make validate
}

_run_unit() {
    make test
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
