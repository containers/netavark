#!/usr/bin/env bats   -*- bats -*-
#
# bridge firewalld iptables driver tests
#

load helpers

fw_driver=firewalld

function setup() {
    basic_setup
    setup_firewalld
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

@test "$fw_driver - bridge with static routes" {
    # add second interface and routes through that interface to test proper teardown
    run_in_container_netns ip link add type dummy
    run_in_container_netns ip a add 10.91.0.10/24 dev dummy0
    run_in_container_netns ip link set dummy0 up

    run_netavark --file ${TESTSDIR}/testfiles/bridge-staticroutes.json setup $(get_container_netns_path)

    # check static routes
    run_in_container_netns ip r
    assert "$output" "=~" "10.89.0.0/24 via 10.88.0.2" "static route not set"
    assert "$output" "=~" "10.90.0.0/24 via 10.88.0.3" "static route not set"
    assert "$output" "=~" "10.92.0.0/24 via 10.91.0.1" "static route not set"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-staticroutes.json teardown $(get_container_netns_path)

    # check static routes get removed
    assert "$output" "!~" "10.89.0.0/24 via 10.88.0.2" "static route not set"
    assert "$output" "!~" "10.90.0.0/24 via 10.88.0.3" "static route not set"
    assert "$output" "!~" "10.92.0.0/24 via 10.91.0.1" "static route not removed"
}

@test "$fw_driver - bridge with no default route" {
    run_netavark --file ${TESTSDIR}/testfiles/bridge-nodefaultroute.json setup $(get_container_netns_path)

    run_in_container_netns ip r
    assert "$output" "!~" "default" "default route exists"

    run_in_container_netns ip -6 r
    assert "$output" "!~" "default" "default route exists"

    run_netavark --file ${TESTSDIR}/testfiles/bridge-nodefaultroute.json teardown $(get_container_netns_path)
    assert "" "no errors"
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

@test "$fw_driver - ipv6 bridge with static routes" {
    # add second interface and routes through that interface to test proper teardown
    run_in_container_netns ip link add type dummy
    run_in_container_netns ip a add fd10:49:b::2/64 dev dummy0
    run_in_container_netns ip link set dummy0 up

    run_netavark --file ${TESTSDIR}/testfiles/ipv6-bridge-staticroutes.json setup $(get_container_netns_path)

    # check static routes
    run_in_container_netns ip -6 -br r
    assert "$output" "=~" "fd10:89:b::/64 via fd10:88:a::ac02" "static route not set"
    assert "$output" "=~" "fd10:89:c::/64 via fd10:88:a::ac03" "static route not set"
    assert "$output" "=~" "fd10:51:b::/64 via fd10:49:b::30" "static route not set"

    run_netavark --file ${TESTSDIR}/testfiles/ipv6-bridge-staticroutes.json teardown $(get_container_netns_path)

    # check static routes get removed
    run_in_container_netns ip -6 -br r
    assert "$output" "!~" "fd10:89:b::/64 via fd10:88:a::ac02" "static route not removed"
    assert "$output" "!~" "fd10:89:c::/64 via fd10:88:a::ac03" "static route not removed"
    assert "$output" "!~" "fd10:51:b::/64 via fd10:49:b::30" "static route not removed"

    run_in_container_netns ip link delete dummy0
}

@test "$fw_driver - dual stack dns with alt port" {
    skip "FIXME (#846): firewalld 2.0 broken port redirect"
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_FW=firewalld NETAVARK_DNS_PORT="$dns_port" \
        run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        setup $(get_container_netns_path)

    # check iptables
    # firewall-cmd --list-rich-rules does not guarantee order, use sort
    run_in_host_netns sh -c 'firewall-cmd --policy netavark_portfwd --list-rich-rules | sort'
    assert "${lines[0]}" =~ "rule family=\"ipv4\" destination address=\"10.89.3.1\" forward-port port=\"53\" protocol=\"udp\" to-port=\"$dns_port\" to-addr=\"10.89.3.1\"" "ipv4 dns redirection"
    assert "${lines[1]}" =~ "rule family=\"ipv6\" destination address=\"fd10:88:a::1\" forward-port port=\"53\" protocol=\"udp\" to-port=\"$dns_port\" to-addr=\"fd10:88:a::1\"" "ipv6 dns redirection"
    assert "${#lines[@]}" = 2 "too many rich rules"

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    aardvark_pid=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$ardvark_pid" =~ "[0-9]*" "aardvark pid not found"
    run_helper ps "$aardvark_pid"
    assert "${lines[1]}" =~ ".*aardvark-dns --config $NETAVARK_TMPDIR/config/aardvark-dns -p $dns_port run" "aardvark not running or bad options"

    # test redirection actually works
    run_in_container_netns dig +short "somename.dns.podman" @10.89.3.1 A "somename.dns.podman" @10.89.3.1 AAAA
    assert "${lines[0]}" =~ "10.89.3.2" "ipv4 dns resolution works 1/2"
    assert "${lines[1]}" =~ "fd10:88:a::2" "ipv6 dns resolution works 2/2"

    run_in_container_netns dig +short "somename.dns.podman" @fd10:88:a::1
    assert "${lines[0]}" =~ "10.89.3.2" "ipv6 dns resolution works"

    NETAVARK_FW=firewalld NETAVARK_DNS_PORT="$dns_port" \
        run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        teardown $(get_container_netns_path)

    # check iptables got removed
    run_in_host_netns firewall-cmd --policy netavark_portfwd --list-rich-rules
    assert "${#lines[@]}" = 0 "rich rules did not get removed on teardown"

    # check aardvark config got cleared, process killed
    expected_rc=2 run_helper ls "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    expected_rc=1 run_helper ps "$aardvark_pid"
}

@test "$fw_driver - check error message from netns thread" {
    # create interface in netns to force error
    run_in_container_netns ip link add eth0 type dummy

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert_json ".error" "create veth pair: interface eth0 already exists on container namespace: Netlink error: File exists (os error 17)" "interface exists on netns"
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
    test_port_fw hostip="172.16.0.1"
}

@test "$fw_driver - port forwarding with hostip ipv4 dual stack - tcp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw ip=dual hostip="172.16.0.1"
}

@test "$fw_driver - port forwarding with hostip ipv6 - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 hostip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port forwarding with hostip ipv6 dual stack - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=dual hostip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port forwarding with hostip ipv4 - udp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw proto=udp hostip="172.16.0.1"
}

@test "$fw_driver - port forwarding with hostip ipv6 - udp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 proto=udp hostip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port forwarding with wildcard hostip ipv4 - tcp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw hostip="0.0.0.0" connectip="172.16.0.1"
}

@test "$fw_driver - port forwarding with wildcard hostip ipv4 dual stack - tcp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw ip=dual hostip="0.0.0.0" connectip="172.16.0.1"
}

@test "$fw_driver - port forwarding with wildcard hostip ipv6 - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 hostip="::" connectip="fd65:8371:648b:0c06::1"
}

@test "$fw_driver - port forwarding with wildcard hostip ipv6 dual stack - tcp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=dual hostip="::" connectip="fd65:8371:648b:0c06::1"
}

@test "netavark error - invalid host_ip in port mappings" {
    expected_rc=1 run_netavark -f ${TESTSDIR}/testfiles/invalid-port.json setup $(get_container_netns_path)
    assert_json ".error" "invalid host ip \"abcd\" provided for port 8080" "host ip error"
}
