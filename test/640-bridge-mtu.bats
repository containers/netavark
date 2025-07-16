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
    run_in_host_netns ip link add default_route type dummy
    run_in_host_netns ip link set default_route mtu 9000
    run_in_host_netns ip addr add 192.168.0.0/24 dev default_route
    run_in_host_netns ip link set default_route up
    run_in_host_netns ip route add default via 192.168.0.0
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
