#!/usr/bin/env bash

# This script will update the cargo imports in the rpm spec for downstream fedora
# packaging, via the `propose-downstream` packit action.
# The cargo imports don't need to be present upstream.

set -eo pipefail

PACKAGE=netavark
# script is run from git root directory
SPEC_FILE=rpm/$PACKAGE.spec

# Remove existing imports in spec
sed -i '/^Provides: bundled(crate.*/d' $SPEC_FILE

# Update spec file with latest imports
IMPORTS=$(cargo tree --prefix none | awk '{print "Provides: bundled(crate("$1"))"}' | sort | uniq)
awk -v r="$IMPORTS" '/^# vendored libraries/ {print; print r; next} 1' $SPEC_FILE > temp && mv temp $SPEC_FILE
