#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with vrf
#

load helpers

@test vrf - bridge with vrf {
    run_in_host_netns ip link add test-vrf type vrf table 10
    run_in_host_netns ip link set dev test-vrf up

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge-vrf.json setup $(get_container_netns_path)

    # check if vrf exists
    run_in_host_netns ip -j --details link show podman0
    result="$output"
    assert_json "$result" ".[].linkinfo.info_slave_kind" "==" "vrf" "Bridge has a vrf set"
    assert_json "$result" ".[].master" "==" "test-vrf" "Bridge has the correct vrf set"
}

@test vrf - simple bridge {
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    run_in_host_netns ip -j --details link show podman0
    result="$output"
    assert_json "$result" ".[].linkinfo.info_slave_kind" "==" "null" "VRF is not set"
}

@test vrf - non existent vrf {
    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/simplebridge-vrf.json setup $(get_container_netns_path)
    result="$output"
    assert_json "$result" ".error" "==" "get vrf to set up bridge interface: Netlink error: No such device (os error 19)" "Attempt to set a non existent vrf"
}

