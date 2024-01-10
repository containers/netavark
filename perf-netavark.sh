#!/bin/bash

# Netavark binary
NETAVARK=${NETAVARK:-./bin/netavark}

trap cleanup EXIT

function cleanup() {
    kill -9 $netnspid
    rm -rf $TMP_CONFIG
}

TMP_CONFIG=$(mktemp -d)
unshare -n sleep 100 &
netnspid=$!

# first arg is the fw driver
if [ -n "$1" ]; then
    export NETAVARK_FW="$1"
fi

unshare -n perf stat $NETAVARK -f ./test/testfiles/simplebridge.json --config $TMP_CONFIG setup /proc/$netnspid/ns/net
