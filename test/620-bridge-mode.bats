#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with explicit modes
#

load helpers

VLAN_DHCP_DNSMASQ_PID=
VLAN_DHCP_PROXY_PID=

function teardown() {
    if [[ -n "$VLAN_DHCP_PROXY_PID" ]]; then
        kill "$VLAN_DHCP_PROXY_PID" 2>/dev/null || true
    fi
    if [[ -n "$VLAN_DHCP_DNSMASQ_PID" ]]; then
        kill "$VLAN_DHCP_DNSMASQ_PID" 2>/dev/null || true
    fi
    basic_teardown
}

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

@test "bridge - unmanaged mode with vlan and dhcp" {
    create_container_ns

    run_in_host_netns ip link add brtest0 type bridge vlan_filtering 1
    run_in_host_netns ip link set brtest0 up
    run_in_host_netns ip link add trunk0 type veth peer name srv0
    run_in_host_netns ip link set srv0 netns "${CONTAINER_NS_PIDS[1]}"
    run_in_host_netns ip link set trunk0 master brtest0
    run_in_host_netns ip link set trunk0 up

    expected_rc=? run_in_host_netns bridge vlan del dev trunk0 vid 1
    run_in_host_netns bridge vlan add dev trunk0 vid 20 pvid untagged
    run_in_host_netns bridge vlan add dev trunk0 vid 40

    expected_rc=? run_in_host_netns bridge vlan del dev brtest0 vid 1 self
    run_in_host_netns bridge vlan add dev brtest0 vid 20 self pvid untagged
    run_in_host_netns bridge vlan add dev brtest0 vid 40 self

    run_in_container_netns 1 ip link set lo up
    run_in_container_netns 1 ip link set srv0 up
    run_in_container_netns 1 ip addr add 10.10.20.1/24 dev srv0
    run_in_container_netns 1 ip link add link srv0 name srv0.40 type vlan id 40
    run_in_container_netns 1 ip link set srv0.40 up
    run_in_container_netns 1 ip addr add 10.10.40.1/24 dev srv0.40

    nsenter -n -m -w -t "${CONTAINER_NS_PIDS[1]}" dnsmasq \
        --no-daemon \
        --log-debug \
        --log-dhcp \
        --bind-interfaces \
        --except-interface=lo \
        --interface=srv0 \
        --interface=srv0.40 \
        --dhcp-authoritative \
        --dhcp-range=10.10.20.50,10.10.20.59,255.255.255.0,2m \
        --dhcp-range=10.10.40.50,10.10.40.59,255.255.255.0,2m \
        >"$NETAVARK_TMPDIR/vlan-dhcp-dnsmasq.log" 2>&1 &
    VLAN_DHCP_DNSMASQ_PID=$!

    nsenter -n -m -w -t "$HOST_NS_PID" mkdir -p /run/podman
    nsenter -n -m -w -t "$HOST_NS_PID" "$NETAVARK" dhcp-proxy \
        --dir /run/podman \
        --timeout 10 \
        >"$NETAVARK_TMPDIR/vlan-dhcp-proxy.log" 2>&1 &
    VLAN_DHCP_PROXY_PID=$!

    for _ in $(seq 1 50); do
        if nsenter -n -m -w -t "$HOST_NS_PID" test -S /run/podman/nv-proxy.sock; then
            break
        fi
        sleep 0.1
    done

    run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged-vlan-dhcp.json setup $(get_container_netns_path)
    setup_result="$output"
    assert_json "$setup_result" ".podman.interfaces.eth0.subnets[0].ipnet" "=~" "^10\\.10\\.40\\." "DHCP lease should come from vlan 40"
    assert_json "$setup_result" ".podman.interfaces.eth0.subnets[0].gateway" "==" "10.10.40.1" "DHCP gateway should come from vlan 40"

    run_in_host_netns ip link show brtest0.40
    assert "$output" =~ "brtest0.40" "DHCP vlan interface should exist"

    run_in_container_netns ping -c 1 -W 1 10.10.40.1
    run_helper grep -q "DHCPACK(srv0.40)" "$NETAVARK_TMPDIR/vlan-dhcp-dnsmasq.log"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-unmanaged-vlan-dhcp.json teardown $(get_container_netns_path)
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
