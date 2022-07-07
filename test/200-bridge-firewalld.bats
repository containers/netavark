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
    skip "TODO: Firewalld driver swapped with iptables until firewalld 1.1.0"
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

    # run_in_host_netns sh -c "echo 0 > /proc/sys/net/ipv6/conf/default/accept_ra"

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

@test "$fw_driver - dual stack dns with alt port" {
    dns_port=$(random_port)
    NETAVARK_FW=firewalld NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json setup $(get_container_netns_path)

    # firewall-cmd --list-rich-rules does not guarantee order, use sort
    run_in_host_netns sh -c 'firewall-cmd --policy netavark_portfwd --list-rich-rules | sort'
    assert "${lines[0]}" =~ "rule family=\"ipv4\" destination address=\"10.89.3.1\" forward-port port=\"53\" protocol=\"udp\" to-port=\"$dns_port\" to-addr=\"10.89.3.1\"" "ipv4 dns redirection"
    assert "${lines[1]}" =~ "rule family=\"ipv6\" destination address=\"fd10:88:a::1\" forward-port port=\"53\" protocol=\"udp\" to-port=\"$dns_port\" to-addr=\"fd10:88:a::1\"" "ipv6 dns redirection"
    assert "${#lines[@]}" = 2 "too many rich rules"

    # test redirection actually works -- we can't use run_nc_test
    # we _also_ cannot use run_in_host_ns for this command as it echoes
    # the command back, and we only want nc reply...
    nsenter -n -t $HOST_NS_PID timeout --foreground -v --kill=10 5 \
        nc -4 --udp -l -p "$dns_port" &>"$NETAVARK_TMPDIR/nc-out" </dev/null &
    data=$(random_string)
    run_in_container_netns nc -4 --udp 10.89.3.1 53 <<<"$data"
    got=$(cat "$NETAVARK_TMPDIR/nc-out")
    assert "$got" == "$data" "ncat received data"

    # same for ipv6
    nsenter -n -t $HOST_NS_PID timeout --foreground -v --kill=10 5 \
        nc -6 --udp -l -p "$dns_port" &>"$NETAVARK_TMPDIR/nc-out" </dev/null &
    data=$(random_string)
    run_in_container_netns nc -6 --udp fd10:88:a::1 53 <<<"$data"
    got=$(cat "$NETAVARK_TMPDIR/nc-out")
    assert "$got" == "$data" "ncat received data"

    NETAVARK_FW=firewalld NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json teardown $(get_container_netns_path)
    run_in_host_netns firewall-cmd --policy netavark_portfwd --list-rich-rules
    assert "${#lines[@]}" = 0 "rich rules did not get removed on teardown"
}

@test "$fw_driver - check error message from netns thread" {
    # create interface in netns to force error
    run_in_container_netns ip link add eth0 type dummy

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert_json ".error" "IO error: failed to configure bridge and veth interface: failed while configuring network interface: from network namespace: interface eth0 already exists on container namespace" "interface exists on netns"
}

@test "$fw_driver - port forwarding ipv4 - tcp" {
    test_port_fw
}

@test "$fw_driver - port forwarding ipv6 - tcp" {
    test_port_fw ip=6
}

@test "$fw_driver - port forwarding dualstack - tcp" {
    test_port_fw ip=dual
}

@test "$fw_driver - port forwarding ipv4 - udp" {
    test_port_fw proto=udp
}

@test "$fw_driver - port forwarding ipv6 - udp" {
    test_port_fw ip=6 proto=udp
}

@test "$fw_driver - port forwarding dualstack - udp" {
    test_port_fw ip=dual proto=udp
}

@test "$fw_driver - port forwarding ipv4 - sctp" {
    setup_sctp_kernel_module
    test_port_fw proto=sctp
}

@test "$fw_driver - port forwarding ipv6 - sctp" {
    setup_sctp_kernel_module
    test_port_fw ip=6 proto=sctp
}

@test "$fw_driver - port forwarding dualstack - sctp" {
    setup_sctp_kernel_module
    test_port_fw ip=dual proto=sctp
}

@test "$fw_driver - port range forwarding ipv4 - tcp" {
    test_port_fw range=3
}

@test "$fw_driver - port range forwarding ipv6 - tcp" {
    test_port_fw ip=6 range=3
}

@test "$fw_driver - port range forwarding ipv4 - udp" {
    test_port_fw proto=udp range=3
}

@test "$fw_driver - port range forwarding ipv6 - udp" {
    test_port_fw ip=6 proto=udp range=3
}

@test "$fw_driver - port range forwarding dual - udp" {
    test_port_fw ip=dual proto=udp range=3
}

@test "$fw_driver - port range forwarding dual - tcp" {
    test_port_fw ip=dual proto=tcp range=3
}


@test "$fw_driver - port forwarding with hostip ipv4 - tcp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    run_in_host_netns ip addr
    test_port_fw hostip="172.16.0.1"
}

@test "$fw_driver - port forwarding with hostip ipv4 dual stack- tcp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    run_in_host_netns ip addr
    test_port_fw ip=dual hostip="172.16.0.1"
}

@test "$fw_driver - port range forwarding with hostip ipv6 - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 hostip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port range forwarding with hostip ipv6 dual stack - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=dual hostip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port range forwarding with hostip ipv4 - udp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw proto=udp hostip="172.16.0.1"
}

@test "$fw_driver - port range forwarding with hostip ipv6 - udp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 proto=udp hostip="fd65:8371:648b:0c06::1"
}
