

# Library of common, shared utility functions.  This file is intended
# to be sourced by other scripts, not called directly.

# BEGIN Global export of all variables
set -a

# Automation library installed at image-build time,
# defining $AUTOMATION_LIB_PATH in this file.
if [[ -r "/etc/automation_environment" ]]; then
    source /etc/automation_environment
fi

if [[ -n "$AUTOMATION_LIB_PATH" ]]; then
        source $AUTOMATION_LIB_PATH/common_lib.sh
else
    (
    echo "WARNING: It does not appear that containers/automation was installed."
    echo "         Functionality of most of this library will be negatively impacted"
    echo "         This ${BASH_SOURCE[0]} was loaded by ${BASH_SOURCE[1]}"
    ) > /dev/stderr
fi

# Unsafe env. vars for display
SECRET_ENV_RE='(ACCOUNT)|(GC[EP]..+)|(SSH)|(PASSWORD)|(TOKEN)'

# setup.sh calls make_cienv() to cache these values for the life of the VM
if [[ -r "/etc/ci_environment" ]]; then
    source /etc/ci_environment
else  # set default values - see make_cienv() below
    # VM Images are built with this setup
    CARGO_HOME="${CARGO_HOME:-/var/cache/cargo}"
    source $CARGO_HOME/env

    # Make caching more effective - disable incremental compilation,
    # so that the Rust compiler doesn't waste time creating the
    # additional artifacts required for incremental builds.
    # Ref: https://github.com/marketplace/actions/rust-cache#cache-details
    CARGO_INCREMENTAL=0
fi

# END Global export of all variables
set -a

# Shortcut to automation library timeout/retry function
retry() { err_retry 8 1000 "" "$@"; }  # just over 4 minutes max

# Helper to ensure a consistent environment across multiple CI scripts
# containers, and shell environments (e.g. hack/get_ci_vm.sh)
make_cienv(){
    local envname
    local envval
    local SETUP_ENVIRONMENT=1
    for envname in CARGO_HOME PATH CIRRUS_WORKING_DIR SETUP_ENVIRONMENT; do
        envval="${!envname}"
        # Properly escape values to prevent injection
        printf -- "$envname=%q\n" "$envval"
    done
}

complete_setup(){
    set +x
    msg "************************************************************"
    msg "Completing environment setup, writing vars:"
    msg "************************************************************"
    make_cienv | tee -a /etc/ci_environment
}
