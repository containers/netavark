#!/bin/bash
# Set podman-next COPR repository priority to 1

COPR_REPO_FILE="/etc/yum.repos.d/*podman-next*.repo"
if compgen -G $COPR_REPO_FILE > /dev/null; then
    sed -i -n '/^priority=/!p;$apriority=1' $COPR_REPO_FILE
fi
dnf -y upgrade --allowerasing
