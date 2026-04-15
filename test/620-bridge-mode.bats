#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with explicit modes
#

load helpers

@test bridge - managed mode {
    run_netavark --file ${TESTSDIR}/testfiles/bridge-managed.json setup $(get_container_netns_path)

    run_in_host_netns ip -j --details link show podman0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-managed.json teardown $(get_container_netns_path)

    # make sure, that the bridge was removed
    expected_rc=1 run_in_host_netns ip -j --details link show podman0
    assert "$output" "==" 'Device "podman0" does not exist.'
}

@test bridge - unmanaged mode {
    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged.json setup $(get_container_netns_path)
    assert_json ".error" "in unmanaged mode, the bridge must already exist on the host: Netlink error: No such device (os error 19)"

    run_in_host_netns ip link add brtest0 type bridge
    run_in_host_netns ip link set brtest0 up

    run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged.json setup $(get_container_netns_path)

    run_in_host_netns ip -j --details link show brtest0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged.json teardown $(get_container_netns_path)

    # make sure, that the bridge was NOT removed
    run_in_host_netns ip -j --details link show brtest0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"
}

@test "bridge - managed mode with dhcp" {
    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/bridge-managed-dhcp.json setup $(get_container_netns_path)
    assert_json ".error" "cannot use dhcp ipam driver without using the option mode=unmanaged" "dhcp error"
}

@test bridge - unmanaged mode with aardvark-dns no bridge ip {
    run_in_host_netns ip link add brtest0 type bridge
    run_in_host_netns ip link set brtest0 up
    run_in_host_netns ip -j --details link show brtest0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged-dns.json setup $(get_container_netns_path)
    assert_json ".error" "bridge 'brtest0' in unmanaged mode has no usable IP addresses. Aardvark-dns requires at least one address (should not be an IPv6 link-local address) to bind to. Please add an IP address or disable DNS for this network (--disable-dns)."
}

@test bridge - unmanaged mode with aardvark-dns bridge ip {
    run_in_host_netns ip link add brtest0 type bridge
    run_in_host_netns sysctl -w net.ipv6.conf.brtest0.accept_dad=0
    run_in_host_netns ip link set brtest0 up
    run_in_host_netns ip -j --details link show brtest0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"

    run_in_host_netns ip addr add 10.88.0.100/16 dev brtest0
    run_in_host_netns ip addr add 2001:db8:abcd:000a:50a6:6bff:fe84:255a dev brtest0
    run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged-dns.json setup $(get_container_netns_path)

    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman"
    assert "${lines[0]}" == "10.88.0.100,2001:db8:abcd:a:50a6:6bff:fe84:255a" "aardvark-dns should bind to the unmanaged bridge IP"
}
