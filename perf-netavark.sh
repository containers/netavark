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

unshare -n perf stat $NETAVARK -f ./test/testfiles/simplebridge.json --config $TMP_CONFIG setup /proc/$netnspid/ns/net
