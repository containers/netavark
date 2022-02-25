#!/usr/bin/env bats   -*- bats -*-
#
# macvlan driver test
#

load helpers

function setup() {
    basic_setup

    # create a extra interface which we can use to connect the macvlan to
    run_in_host_netns ip link add dummy0 type dummy
}

@test "simple macvlan setup" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" "=~" "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr" "Result contains correct IP address"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "=~" "default via 10.88.0.1" "gateway must be there in default route"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].gateway" == "10.88.0.1" "Result contains gateway address"
}

@test "macvlan setup internal" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan-internal.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" "=~" "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr" "Result contains correct IP address"

    # internal macvlan must not contain
    run_in_container_netns ip r
    assert "$output" !~ 'default' "macvlan must not contain default gateway in route at all"
}

@test "macvlan setup with mtu" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan-mtu.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].mtu" "=="  "1400" "MTU matches configured MTU"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" "=~" "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr" "Result contains correct IP address"
}
