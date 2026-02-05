#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with explicit modes
#

load helpers

function check_iface_mtu() {
    local host_or_container=$1
    local iface=$2
    local mtu=$3

    if [ "$host_or_container" = "host" ]; then
        run_in_host_netns ip -j --details link show "$iface"
    else
        run_in_container_netns ip -j --details link show "$iface"
    fi
    assert_json "$output" ".[].mtu" "=="  "$mtu" "$iface MTU matches $mtu"
}

function check_mtu() {
    local mtu=$1
    check_iface_mtu container eth0 "$mtu"
    check_iface_mtu host veth0 "$mtu"
    check_iface_mtu host podman0 "$mtu"
}


function add_default_route() {
    local ifname=default_route
    local table="main"
    local mtu=9000
    local vrf=""
     # parse arguments
    while [[ "$#" -gt 0 ]]; do
        IFS='=' read -r arg value <<<"$1"
        case "$arg" in
        ifname)
            ifname="$value"
            ;;
        table)
            table="$value"
            ;;
        mtu)
            mtu="$value"
            ;;
        vrf)
            vrf="$value"
            ;;
        *) die "unknown argument for '$arg' test_port_fw" ;;
        esac
        shift
    done

    run_in_host_netns ip link add $ifname type dummy
    run_in_host_netns ip link set $ifname mtu $mtu
    run_in_host_netns ip addr add 192.168.0.0/24 dev $ifname
    if [[ -n "$vrf" ]]; then
        # We must add the vrf before adding the route as this call would remove the route again.
        run_in_host_netns ip link set $ifname master $vrf
    fi
    run_in_host_netns ip link set $ifname up
    run_in_host_netns ip route add default via 192.168.0.0 dev $ifname table $table
}

function add_bridge() {
    run_in_host_netns ip link add podman0 type bridge
    run_in_host_netns ip link set podman0 mtu 9001
    run_in_host_netns ip link set up podman0
}

@test "bridge - mtu from default route" {
    add_default_route
    run_netavark --file ${TESTSDIR}/testfiles/bridge-managed.json setup $(get_container_netns_path)
    check_mtu 9000
}

# check the we only use the main table by default
# https://github.com/containers/netavark/issues/1381
@test "bridge - mtu from default route in different tables" {
    # IMPORTANT: do not add the normal default route first or last
    # My kernel did not reproduce the reported issue but I was able
    # to reproduce on RHEL 10.
    add_default_route mtu=1000 ifname=def-table10 table=10
    add_default_route mtu=2000 ifname=def1
    add_default_route mtu=3000 ifname=def-table900 table=900

    run_netavark --file ${TESTSDIR}/testfiles/bridge-managed.json setup $(get_container_netns_path)
    check_mtu 2000
}

@test "bridge - mtu from existing bridge" {
    add_bridge
    run_netavark --file ${TESTSDIR}/testfiles/bridge-managed.json setup $(get_container_netns_path)
    check_mtu 9001
}

@test "bridge - mtu from config with default route" {
    add_default_route
    run_netavark --file ${TESTSDIR}/testfiles/bridge-mtu.json setup $(get_container_netns_path)
    check_mtu 9002
}

@test "bridge - mtu from config with existing bridge" {
    add_bridge
    run_netavark --file ${TESTSDIR}/testfiles/bridge-mtu.json setup $(get_container_netns_path)
    check_iface_mtu container eth0 9002
    check_iface_mtu host veth0 9002
    # The existing bridge MTU should not be overriden.
    check_iface_mtu host podman0 9001
}

@test bridge - mtu from vrf default vrf interface routing table {
    run_in_host_netns ip link add test-vrf type vrf table 100
    run_in_host_netns ip link set dev test-vrf up

    add_default_route mtu=9000
    add_default_route mtu=3000 ifname=eth-vrf vrf=test-vrf table=100

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge-vrf.json setup $(get_container_netns_path)

    # check if vrf exists
    run_in_host_netns ip -j --details link show podman0
    result="$output"
    assert_json "$result" ".[].master" "==" "test-vrf" "Bridge has the correct vrf set"

    check_mtu 3000
}
