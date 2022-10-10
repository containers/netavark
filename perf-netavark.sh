#!/bin/bash

# Netavark binary
NETAVARK=${NETAVARK:-./bin/netavark}

trap cleanup EXIT

function cleanup() {
    kill -9 $netnspid
}

unshare -n sleep 100 &
netnspid=$!

unshare -n perf stat $NETAVARK -f ./test/testfiles/simplebridge.json setup /proc/$netnspid/ns/net
