#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with static veth names
#

load helpers

@test bridge - valid veth name {
    run_netavark --file ${TESTSDIR}/testfiles/bridge-vethname.json setup $(get_container_netns_path)

    run_in_host_netns ip -j --details link show my-veth
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host veth is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" == "veth" "The veth interface is actually a veth"
    assert_json "$link_info" ".[].master" "==" "podman0" "veth is part of the correct bridge"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-vethname.json teardown $(get_container_netns_path)

    # check if the interface gets removed
    expected_rc=1 run_in_host_netns ip -j --details link show my-veth
    assert "$output" "==" 'Device "my-veth" does not exist.'
}

@test bridge - existing veth name {
    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/bridge-vethname-exists.json setup $(get_container_netns_path)
    assert_json ".error" "create veth pair: interface eth0 already exists on container namespace or podman0 exists on host namespace: Netlink error: File exists (os error 17)"

    expected_rc=1 run_in_host_netns ip -j --details link show my-veth
    assert "$output" "==" 'Device "my-veth" does not exist.'
}
