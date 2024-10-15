#!/bin/bash

set -e

PODMAN=${PODMAN:-podman}
SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
DOCKERFILE="$(dirname "${BASH_SOURCE[0]}")/Dockerfile.Rust"

# get the tag from the Dockerfile so we do not duplicate it
TAG=$(awk -F':' '/FROM/{print $NF}' $DOCKERFILE)
if [[ -z "$TAG" ]]; then
    echo "Empty tag in $DOCKERFILE; the tag must specify the rust version to use" >&2
    exit 1
fi

FULL_IMAGE_NAME="quay.io/libpod/nv-rust:$TAG"

$PODMAN build -t $FULL_IMAGE_NAME -f $DOCKERFILE
$PODMAN push $FULL_IMAGE_NAME
