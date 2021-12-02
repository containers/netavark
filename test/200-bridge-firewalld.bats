#!/usr/bin/env bats   -*- bats -*-
#
# bridge firewalld iptables driver tests
#

load helpers

fw_driver=firewalld

function setup() {
    basic_setup

    # first, create a new dbus session
    DBUS_SYSTEM_BUS_ADDRESS=unix:path=$NETAVARK_TMPDIR/netavark-firewalld
    run_in_host_netns dbus-daemon --address="$DBUS_SYSTEM_BUS_ADDRESS" --print-pid --config-file="${TESTSDIR}/testfiles/firewalld-dbus.conf"
    DBUS_PID="$output"
    # export DBUS_SYSTEM_BUS_ADDRESS so firewalld and netavark will use the correct socket
    export DBUS_SYSTEM_BUS_ADDRESS

    # second, start firewalld in the netns with the dbus socket
    # do not use run_in_host_netns because we want to run this in background
    # use --nopid (we cannot change the pid file location), --nofork do not run as daemon so we can kill it by pid
    # change --system-config to make sure that we do not write any config files to the host location
    nsenter -n -t $HOST_NS_PID firewalld --nopid --nofork --system-config "$NETAVARK_TMPDIR" &>"$NETAVARK_TMPDIR/firewalld.log" &
    FIREWALLD_PID=$!
    echo "firewalld pid: $FIREWALLD_PID"

    # wait for firewalld to become ready
    timeout=5
    while [ $timeout -gt 0 ]; do
        # query firewalld with firewall-cmd
        expected_rc="?" run_in_host_netns firewall-cmd --state
        if [ "$status" -eq 0 ]; then
            break
        fi
        sleep 1
        timeout=$(($timeout - 1))
        if [ $timeout -eq 0 ]; then
            cat "$NETAVARK_TMPDIR/firewalld.log"
            die "failed to start firewalld - timeout"
        fi
    done
}

function teardown() {
    kill -9 $FIREWALLD_PID
    kill -9 $DBUS_PID

    unset DBUS_SYSTEM_BUS_ADDRESS

    basic_teardown
}

@test "check firewalld driver is in use" {
    RUST_LOG=netavark=info run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert "${lines[0]}" "==" "[INFO  netavark::firewall] Using firewalld firewall driver" "firewalld driver is in use"
}

@test "$fw_driver - simple bridge" {
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    result="$output"
    assert_json "$result" 'has("podman")' == "true" "object key exists"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<<"$result")
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" == "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" == "veth" "Container interface is a veth device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" =~ "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" == "$ipaddr" "Result contains correct IP address"

    run_in_host_netns ip -j --details link show podman0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" == "bridge" "The bridge interface is actually a bridge"

    ipaddr="10.88.0.1"
    run_in_host_netns ip addr show podman0
    assert "$output" =~ "$ipaddr" "IP address matches bridge gateway address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].gateway" == "$ipaddr" "Result contains gateway address"

    # check that the loopback adapter is up
    run_in_container_netns ip addr show lo
    assert "$output" =~ "127.0.0.1" "Loopback adapter is up (has address)"
    # TODO check firewall
    # run_in_host_netns firewall-cmd ...
}

@test "$fw_driver - ipv6 bridge" {

    ### FIXME set sysctl in netavark
    run_in_host_netns sh -c "echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad"
    #run_in_container_netns sh -c "echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad"

    #run_in_host_netns sh -c "echo 0 > /proc/sys/net/ipv6/conf/default/accept_ra"

    run_netavark --file ${TESTSDIR}/testfiles/ipv6-bridge.json setup $(get_container_netns_path)
    result="$output"
    assert_json "$result" 'has("podman1")' == "true" "object key exists"

    mac=$(jq -r '.podman1.interfaces.eth0.mac_address' <<<"$result")
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" == "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" == "veth" "Container interface is a veth device"

    ipaddr="fd10:88:a::2/64"
    run_in_container_netns ip addr show eth0
    assert "$output" =~ "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman1.interfaces.eth0.subnets[0].ipnet" == "$ipaddr" "Result contains correct IP address"

    run_in_host_netns ip -j --details link show podman1
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" == "bridge" "The bridge interface is actually a bridge"

    ipaddr="fd10:88:a::1"
    run_in_host_netns ip addr show podman1
    assert "$output" =~ "$ipaddr" "IP address matches bridge gateway address"
    assert_json "$result" ".podman1.interfaces.eth0.subnets[0].gateway" == "$ipaddr" "Result contains gateway address"

    # check that the loopback adapter is up
    run_in_container_netns ip addr show lo
    assert "$output" =~ "127.0.0.1" "Loopback adapter is up (has address)"

    run_in_host_netns ping6 -c 1 fd10:88:a::2
}

@test "$fw_driver - port forwarding ipv4 - tcp" {
    skip "TODO: pf not yet supported"
    test_port_fw
}

@test "$fw_driver - port forwarding ipv6 - tcp" {
    skip "TODO: pf not yet supported"
    test_port_fw ip=6
}

@test "$fw_driver - port forwarding dualstack - tcp" {
    skip "TODO: pf not yet supported"
    test_port_fw ip=dual
}

@test "$fw_driver - port forwarding ipv4 - udp" {
    skip "TODO: pf not yet supported"
    test_port_fw proto=udp
}

@test "$fw_driver - port forwarding ipv6 - udp" {
    skip "TODO: pf not yet supported"
    test_port_fw ip=6 proto=udp
}

@test "$fw_driver - port forwarding dualstack - udp" {
    skip "TODO: pf not yet supported"
    test_port_fw ip=dual proto=udp
}

@test "$fw_driver - port forwarding ipv4 - sctp" {
    skip "TODO: pf not yet supported"
    setup_sctp_kernel_module
    test_port_fw proto=sctp
}

@test "$fw_driver - port forwarding ipv6 - sctp" {
    skip "TODO: pf not yet supported"
    setup_sctp_kernel_module
    test_port_fw ip=6 proto=sctp
}

@test "$fw_driver - port forwarding dualstack - sctp" {
    skip "TODO: pf not yet supported"
    setup_sctp_kernel_module
    test_port_fw ip=dual proto=sctp
}
