#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with iptables firewall driver
#

load helpers

fw_driver=iptables

@test "check iptables driver is in use" {
    RUST_LOG=netavark=info run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert "${lines[0]}" "==" "[INFO  netavark::firewall] Using iptables firewall driver" "iptables driver is in use"
}

@test "$fw_driver - internal network" {
   run_in_host_netns iptables -t nat -nvL
   before="$output"

   run_netavark --file ${TESTSDIR}/testfiles/internal.json setup $(get_container_netns_path)

   run_in_host_netns iptables -t nat -nvL
   assert "$output" == "$before" "make sure tables have not changed"

   run_in_container_netns ip route show
   assert "$output" "!~" "default" "No default route for internal networks"

   run_in_container_netns ping -c 1 10.88.0.1

   run_netavark --file ${TESTSDIR}/testfiles/internal.json teardown $(get_container_netns_path)
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
    bridge_mac=$(jq -r '.[].address' <<<"$link_info")

    run_in_host_netns ip -j link show veth0
    veth_info="$output"
    assert_json "$veth_info" ".[].address" != "$bridge_mac" "Bridge and Veth must have different mac address"

    ipaddr="10.88.0.1"
    run_in_host_netns ip addr show podman0
    assert "$output" =~ "$ipaddr" "IP address matches bridge gateway address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].gateway" == "$ipaddr" "Result contains gateway address"

    # check that the loopback adapter is up
    run_in_container_netns ip addr show lo
    assert "$output" =~ "127.0.0.1" "Loopback adapter is up (has address)"

    run_in_host_netns ping -c 1 10.88.0.2

    check_simple_bridge_iptables

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json teardown $(get_container_netns_path)

    # now check that iptables rules are gone
    run_in_host_netns iptables -S

    # check FORWARD rules
    run_in_host_netns iptables -S FORWARD
    assert "${lines[1]}" == "-A FORWARD -m comment --comment \"netavark firewall rules\" -j NETAVARK_FORWARD" "FORWARD rule"
    assert "${#lines[@]}" = 2 "too many FORWARD rules after teardown"

    # rule 1 should be DROP for any existing networks
    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${lines[1]}" == "-A NETAVARK_FORWARD -m conntrack --ctstate INVALID -j DROP" "NETAVARK_FORWARD rule 1"
    assert "${#lines[@]}" = 2 "too many NETAVARK_FORWARD rules after teardown"

    # check POSTROUTING nat rules
    run_in_host_netns iptables -S POSTROUTING -t nat
    assert "${lines[1]}" =~ "-A POSTROUTING -j NETAVARK-HOSTPORT-MASQ" "POSTROUTING HOSTPORT-MASQ rule"
    assert "${#lines[@]}" = 2 "too many POSTROUTING rules after teardown"

    # NETAVARK-1D8721804F16F chain should not exists
    expected_rc=1 run_in_host_netns iptables -nvL NETAVARK-1D8721804F16F -t nat

    # bridge should be removed on teardown
    expected_rc=1 run_in_host_netns ip addr show podman0
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

@test "$fw_driver - bridge driver must generate config for aardvark with multiple custom dns server with network dns servers and perform update" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-network-container-dns-server.json \
        setup $(get_container_netns_path)

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1 127.0.0.1,3.3.3.3" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8,1.1.1.1$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    aardvark_pid=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$ardvark_pid" =~ "[0-9]*" "aardvark pid not found"
    run_helper ps "$aardvark_pid"
    assert "${lines[1]}" =~ ".*aardvark-dns --config $NETAVARK_TMPDIR/config/aardvark-dns -p $dns_port run" "aardvark not running or bad options"

    # Use run_helper instead of run_netavark here to check network namespace detection logic.
    # See https://github.com/containers/netavark/issues/911 for details.
    NETAVARK_DNS_PORT="$dns_port" run_helper $NETAVARK --config "$NETAVARK_TMPDIR/config" --rootless "$rootless" --file ${TESTSDIR}/testfiles/dualstack-bridge-network-container-dns-server.json \
        update podman1 --network-dns-servers 8.8.8.8
    assert "$output" = ""

    # after update the pid should never change
    aardvark_pid2=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$aardvark_pid2" == "$aardvark_pid" "aardvark-dns pid after nv update"

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1 8.8.8.8" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8,1.1.1.1$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    # remove network and check running and verify if aardvark config has no nameserver
    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-network-container-dns-server.json \
        update podman1 --network-dns-servers ""

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" == "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8,1.1.1.1$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

}

# netavark must do no-op on upates when no aardvark config is there
@test "run netavark update - no-op" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-network-container-dns-server.json \
        update podman1 --network-dns-servers 8.8.8.8
}

@test "$fw_driver - ipv6 bridge" {
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

    run_netavark --file ${TESTSDIR}/testfiles/ipv6-bridge.json teardown $(get_container_netns_path)
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

@test "$fw_driver - bridge driver must generate config for aardvark with custom dns server" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-custom-dns-server.json \
        setup $(get_container_netns_path)

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    aardvark_pid=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$ardvark_pid" =~ "[0-9]*" "aardvark pid not found"
    run_helper ps "$aardvark_pid"
    assert "${lines[1]}" =~ ".*aardvark-dns --config $NETAVARK_TMPDIR/config/aardvark-dns -p $dns_port run" "aardvark not running or bad options"
}

@test "$fw_driver - bridge driver must generate config for aardvark with multiple custom dns server" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-multiple-custom-dns-server.json \
        setup $(get_container_netns_path)

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8,1.1.1.1$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    aardvark_pid=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$ardvark_pid" =~ "[0-9]*" "aardvark pid not found"
    run_helper ps "$aardvark_pid"
    assert "${lines[1]}" =~ ".*aardvark-dns --config $NETAVARK_TMPDIR/config/aardvark-dns -p $dns_port run" "aardvark not running or bad options"
}

@test "$fw_driver - bridge driver must generate config for aardvark with multiple custom dns server with network dns servers" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge-network-container-dns-server.json \
        setup $(get_container_netns_path)

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1 127.0.0.1,3.3.3.3" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename 8.8.8.8,1.1.1.1$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    aardvark_pid=$(cat "$NETAVARK_TMPDIR/config/aardvark-dns/aardvark.pid")
    assert "$ardvark_pid" =~ "[0-9]*" "aardvark pid not found"
    run_helper ps "$aardvark_pid"
    assert "${lines[1]}" =~ ".*aardvark-dns --config $NETAVARK_TMPDIR/config/aardvark-dns -p $dns_port run" "aardvark not running or bad options"
}

@test "$fw_driver - dual stack dns with alt port" {
    # get a random port directly to avoid low ports e.g. 53 would not create iptables
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        setup $(get_container_netns_path)

    # check iptables
    run_in_host_netns iptables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${lines[1]}" == "-A NETAVARK-HOSTPORT-DNAT -d 10.89.3.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.89.3.1:$dns_port" "ipv4 dns forward rule"
    run_in_host_netns ip6tables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${lines[1]}" == "-A NETAVARK-HOSTPORT-DNAT -d fd10:88:a::1/128 -p udp -m udp --dport 53 -j DNAT --to-destination [fd10:88:a::1]:$dns_port" "ipv6 dns forward rule"

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

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        teardown $(get_container_netns_path)

    # check iptables got removed
    run_in_host_netns iptables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v4 NETAVARK_HOSTPORT-DNAT rules after teardown"
    run_in_host_netns ip6tables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v6 NETAVARK_HOSTPORT-DNAT rules after teardown"

    # check aardvark config got cleared, process killed
    expected_rc=2 run_helper ls "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    expected_rc=1 run_helper ps "$aardvark_pid"
}

@test "$fw_driver - dns with default drop policy" {
    run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        setup $(get_container_netns_path)

    run_in_host_netns iptables -P INPUT DROP
    run_in_host_netns iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    # test redirection actually works
    run_in_container_netns dig +short "somename.dns.podman" @10.89.3.1 A "somename.dns.podman" @10.89.3.1 AAAA
    assert "${lines[0]}" =~ "10.89.3.2" "ipv4 dns resolution works 1/2"
    assert "${lines[1]}" =~ "fd10:88:a::2" "ipv6 dns resolution works 2/2"

    run_in_container_netns dig +short "somename.dns.podman" @fd10:88:a::1
    assert "${lines[0]}" =~ "10.89.3.2" "ipv6 dns resolution works"

    run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        teardown $(get_container_netns_path)

    # check iptables got removed
    run_in_host_netns iptables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v4 NETAVARK_HOSTPORT-DNAT rules after teardown"
    run_in_host_netns ip6tables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v6 NETAVARK_HOSTPORT-DNAT rules after teardown"

    # check aardvark config got cleared, process killed
    expected_rc=2 run_helper ls "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    expected_rc=1 run_helper ps "$aardvark_pid"
}

@test "$fw_driver - dns with default drop policy with non-default dns port" {
    # get a random port
    dns_port=$((RANDOM+10000))

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        setup $(get_container_netns_path)

    # check iptables
    run_in_host_netns iptables -t filter -S NETAVARK_INPUT
    assert "${lines[1]}" == "-A NETAVARK_INPUT -s 10.89.3.0/24 -p udp -m udp --dport $dns_port -j ACCEPT" "ipv4 dns forward rule"
    run_in_host_netns ip6tables -t filter -S NETAVARK_INPUT
    assert "${lines[1]}" == "-A NETAVARK_INPUT -s fd10:88:a::/64 -p udp -m udp --dport $dns_port -j ACCEPT" "ipv6 dns forward rule"


    run_in_host_netns iptables -P INPUT DROP
    run_in_host_netns iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # check aardvark config and running
    run_helper cat "$NETAVARK_TMPDIR/config/aardvark-dns/podman1"
    assert "${lines[0]}" =~ "10.89.3.1,fd10:88:a::1" "aardvark set to listen to all IPs"
    assert "${lines[1]}" =~ "^[0-9a-f]{64} 10.89.3.2 fd10:88:a::2 somename$" "aardvark config's container"
    assert "${#lines[@]}" = 2 "too many lines in aardvark config"

    # test redirection actually works
    run_in_container_netns dig +short "somename.dns.podman" @10.89.3.1 A "somename.dns.podman" @10.89.3.1 AAAA
    assert "${lines[0]}" =~ "10.89.3.2" "ipv4 dns resolution works 1/2"
    assert "${lines[1]}" =~ "fd10:88:a::2" "ipv6 dns resolution works 2/2"

    run_in_container_netns dig +short "somename.dns.podman" @fd10:88:a::1
    assert "${lines[0]}" =~ "10.89.3.2" "ipv6 dns resolution works"

    NETAVARK_DNS_PORT="$dns_port" run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json \
        teardown $(get_container_netns_path)

    # check iptables got removed
    run_in_host_netns iptables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v4 NETAVARK_HOSTPORT-DNAT rules after teardown"
    run_in_host_netns ip6tables -t nat -S NETAVARK-HOSTPORT-DNAT
    assert "${#lines[@]}" = 1 "too many v6 NETAVARK_HOSTPORT-DNAT rules after teardown"

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

@test "$fw_driver - port forwarding with hostip ipv4 - udp" {
    add_dummy_interface_on_host dummy0 "172.16.0.1/24"
    test_port_fw proto=udp hostip="172.16.0.1"
}

@test "$fw_driver - port forwarding with hostip ipv6 - udp" {
    add_dummy_interface_on_host dummy0 "fd65:8371:648b:0c06::1/64"
    test_port_fw ip=6 proto=udp hostip="fd65:8371:648b:0c06::1"
}

# Test that port forwarding works with strict Reverse Path Forwarding enabled on the host
@test "$fw_driver - port forwarding with two networks and RPF - tcp" {
    # First, enable strict RPF on host/container ns.
    run_in_host_netns sysctl -w net.ipv4.conf.all.rp_filter=1
    run_in_host_netns sysctl -w net.ipv4.conf.default.rp_filter=1
    run_in_container_netns sysctl -w net.ipv4.conf.all.rp_filter=1
    run_in_container_netns sysctl -w net.ipv4.conf.default.rp_filter=1

    # We need a dummy interface with a host ip,
    # if we connect directly to the bridge ip it doesn't reproduce.
    add_dummy_interface_on_host dummy0 "10.0.0.1/24"

    run_netavark --file ${TESTSDIR}/testfiles/two-networks.json setup $(get_container_netns_path)
    result="$output"

    run_in_host_netns cat /proc/sys/net/ipv4/conf/podman2/rp_filter
    assert "2" "rp_filter podman2 bridge"
    run_in_host_netns cat /proc/sys/net/ipv4/conf/podman3/rp_filter
    assert "2" "rp_filter podman3 bridge"

    run_in_container_netns cat /proc/sys/net/ipv4/conf/eth0/rp_filter
    assert "2" "rp_filter eth0 interface"
    run_in_container_netns cat /proc/sys/net/ipv4/conf/eth1/rp_filter
    assert "2" "rp_filter eth1 interface"

    # Important: Use the "host" ip here and not localhost or bridge ip.
    run_nc_test "0" "tcp" 8080 "10.0.0.1" 8080
}

@test "bridge ipam none" {
           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "bridge",
         "network_interface": "dummy0",
         "subnets": [],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "none"
         }
      }
   }
}\0
EOF

    run_netavark setup $(get_container_netns_path) <<<"$config"
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"

    run_in_container_netns ip -j --details addr show eth0
    assert_json "$link_info" ".[].addr_info" "==" "null" "No ip addresses configured"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "==" "" "No routes configured"
}

@test "bridge unknown ipam driver" {
           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "bridge",
         "network_interface": "dummy0",
         "subnets": [],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "someDriver"
         }
      }
   }
}\0
EOF

    expected_rc=1 run_netavark setup $(get_container_netns_path) <<<"$config"
    assert_json ".error" "IO error: unsupported ipam driver someDriver" "Driver is not supported error"
}

@test "$fw_driver - isolate networks" {
    # create container/networks with isolation

    # isolate1: 10.89.0.2/24, fd90::2, isolate=true
    run_netavark --file ${TESTSDIR}/testfiles/isolate1.json setup $(get_container_netns_path)

    # isolate2: 10.89.1.2/24, fd99::2, isolate=true
    create_container_ns
    run_netavark --file ${TESTSDIR}/testfiles/isolate2.json setup $(get_container_netns_path 1)

    # isolate3: 10.89.2.2/24, fd92::2, isolate=strict
    create_container_ns
    run_netavark --file ${TESTSDIR}/testfiles/isolate3.json setup $(get_container_netns_path 2)

    # isolate4: 10.89.3.2/24, fd93::2, isolate=strict
    create_container_ns
    run_netavark --file ${TESTSDIR}/testfiles/isolate4.json setup $(get_container_netns_path 3)

    # check iptables NETAVARK_ISOLATION_1 chain
    run_in_host_netns iptables -S NETAVARK_ISOLATION_1
    assert "${lines[1]}" == "-A NETAVARK_ISOLATION_1 -i isolate4 ! -o isolate4 -j NETAVARK_ISOLATION_3"
    assert "${lines[2]}" == "-A NETAVARK_ISOLATION_1 -i isolate3 ! -o isolate3 -j NETAVARK_ISOLATION_3"
    assert "${lines[3]}" == "-A NETAVARK_ISOLATION_1 -i isolate2 ! -o isolate2 -j NETAVARK_ISOLATION_2"
    assert "${lines[4]}" == "-A NETAVARK_ISOLATION_1 -i isolate1 ! -o isolate1 -j NETAVARK_ISOLATION_2"

    run_in_host_netns iptables -nvL FORWARD
    assert "${lines[2]}" =~ "NETAVARK_ISOLATION_1"

    # check iptables NETAVARK_ISOLATION_2 chain
    run_in_host_netns iptables -S NETAVARK_ISOLATION_2
    assert "${lines[1]}" == "-A NETAVARK_ISOLATION_2 -o isolate4 -j DROP"
    assert "${lines[2]}" == "-A NETAVARK_ISOLATION_2 -o isolate3 -j DROP"
    assert "${lines[3]}" == "-A NETAVARK_ISOLATION_2 -o isolate2 -j DROP"
    assert "${lines[4]}" == "-A NETAVARK_ISOLATION_2 -o isolate1 -j DROP"

    # check iptables NETAVARK_ISOLATION_3 chain
    run_in_host_netns iptables -S NETAVARK_ISOLATION_3
    assert "${lines[1]}" == "-A NETAVARK_ISOLATION_3 -j NETAVARK_ISOLATION_2"

    # ping our own ip to make sure the ips work and there is no typo
    run_in_container_netns ping -w 1 -c 1 10.89.0.2
    run_in_container_netns 1 ping -w 1 -c 1 10.89.1.2
    run_in_container_netns 2 ping -w 1 -c 1 10.89.2.2
    run_in_container_netns 3 ping -w 1 -c 1 10.89.3.2

    # make sure the isolated network cannot reach the other network

    # from network isolate1 to isolate2
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 10.89.1.2
    # from network isolate1 to isolate3
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 10.89.2.2
    # from network isolate1 to isolate4
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 10.89.3.2

    # from network isolate2 to isolate1
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 10.89.0.2
    # from network isolate2 to isolate3
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 10.89.2.2
    # from network isolate2 to isolate4
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 10.89.3.2

    # from network isolate3 to isolate1
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 10.89.0.2
    # from network isolate3 to isolate2
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 10.89.1.2
    # from network isolate3 to isolate4
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 10.89.3.2

    # from network isolate4 to isolate1
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 10.89.0.2
    # from network isolate4 to isolate2
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 10.89.1.2
    # from network isolate4 to isolate3
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 10.89.2.2

    # now the same with ipv6

    run_in_container_netns ping -w 1 -c 1 fd90::2
    run_in_container_netns 1 ping -w 1 -c 1 fd99::2
    run_in_container_netns 2 ping -w 1 -c 1 fd92::2
    run_in_container_netns 3 ping -w 1 -c 1 fd93::2

    # from network isolate1 to isolate2
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 fd99::2
    # from network isolate1 to isolate3
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 fd92::2
    # from network isolate1 to isolate4
    expected_rc=1 run_in_container_netns ping -w 1 -c 1 fd93::2

    # from network isolate2 to isolate1
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 fd90::2
    # from network isolate2 to isolate3
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 fd92::2
    # from network isolate2 to isolate4
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 fd93::2

    # from network isolate3 to isolate1
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 fd90::2
    # from network isolate3 to isolate2
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 fd99::2
    # from network isolate3 to isolate4
    expected_rc=1 run_in_container_netns 2 ping -w 1 -c 1 fd93::2

    # from network isolate4 to isolate1
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 fd90::2
    # from network isolate4 to isolate2
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 fd99::2
    # from network isolate4 to isolate3
    expected_rc=1 run_in_container_netns 3 ping -w 1 -c 1 fd92::2

    # create container/network without isolation

    # podman: 10.88.0.2/16
    create_container_ns
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path 4)

    # check iptables NETAVARK_ISOLATION_3 chain
    run_in_host_netns iptables -S NETAVARK_ISOLATION_3
    assert "${lines[1]}" == "-A NETAVARK_ISOLATION_3 -o podman0 -j DROP"
    assert "${lines[2]}" == "-A NETAVARK_ISOLATION_3 -j NETAVARK_ISOLATION_2"

    # this should be able to ping non-strict isolated containers
    # from network podman to isolate1
    run_in_container_netns 4 ping -w 1 -c 1 10.89.0.2
    # from network podman to isolate2
    run_in_container_netns 4 ping -w 1 -c 1 10.89.1.2

    # and should NOT be able to ping strict isolated containers
    # from network podman to isolate3
    expected_rc=1 run_in_container_netns 4 ping -w 1 -c 1 10.89.2.2
    # from network podman to isolate4
    expected_rc=1 run_in_container_netns 4 ping -w 1 -c 1 10.89.3.2

    # teardown all networks
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json teardown $(get_container_netns_path 4)
    run_netavark --file ${TESTSDIR}/testfiles/isolate4.json teardown $(get_container_netns_path 3)
    run_netavark --file ${TESTSDIR}/testfiles/isolate3.json teardown $(get_container_netns_path 2)
    run_netavark --file ${TESTSDIR}/testfiles/isolate2.json teardown $(get_container_netns_path 1)
    run_netavark --file ${TESTSDIR}/testfiles/isolate1.json teardown $(get_container_netns_path)

    # check that isolation rule is deleted
    run_in_host_netns iptables -nvL NETAVARK_ISOLATION_1
    assert "${lines[2]}" == "" "NETAVARK_ISOLATION_1 chain should be empty"
    run_in_host_netns iptables -nvL NETAVARK_ISOLATION_2
    assert "${lines[2]}" == "" "NETAVARK_ISOLATION_2 chain should be empty"
    run_in_host_netns iptables -S NETAVARK_ISOLATION_3
    assert "${lines[1]}" == "-A NETAVARK_ISOLATION_3 -j NETAVARK_ISOLATION_2"
}

@test "$fw_driver - test read only /proc" {
    if [ -n "$_CONTAINERS_ROOTLESS_UID" ]; then
        skip "test only supported when run as real root"
    fi

    # when the sysctl value is already set correctly we should not error
    run_in_host_netns sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
    run_in_container_netns sh -c "echo 1 > /proc/sys/net/ipv4/conf/default/arp_notify"
    run_in_host_netns sh -c "echo 2 > /proc/sys/net/ipv4/conf/default/rp_filter"
    run_in_container_netns sh -c "echo 2 > /proc/sys/net/ipv4/conf/default/rp_filter"
    run_in_host_netns mount -t proc -o ro,nosuid,nodev,noexec proc /proc

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json teardown $(get_container_netns_path)

    run_in_host_netns mount -t proc -o remount,rw /proc
    run_in_host_netns sh -c "echo 0 > /proc/sys/net/ipv4/ip_forward"
    run_in_host_netns mount -t proc -o remount,ro /proc

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert_json ".error" "Sysctl error: IO Error: Read-only file system (os error 30)" "Sysctl error because fs is read only"
}


@test "$fw_driver - bridge static mac" {
   mac="aa:bb:cc:dd:ee:ff"

           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.2"
         ],
         "static_mac": "$mac",
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "bridge",
         "network_interface": "podman1",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         }
      }
   }
}\0
EOF

   run_netavark setup $(get_container_netns_path) <<<"$config"
   result="$output"


   assert_json "$result" ".podman.interfaces.eth0.mac_address" == "$mac" "MAC matches input mac"
   # check that interface exists
   run_in_container_netns ip -j link show eth0
   link_info="$output"
   assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
   assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"

   run_in_host_netns ping -c 1 10.88.0.2
}


@test "$fw_driver - bridge teardown" {
    create_container_ns
    configs=()
    for i in 1 2; do
        read -r -d '\0' config <<EOF
{
   "container_id": "someID$i",
   "container_name": "someName$i",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.$i"
         ],
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "bridge",
         "network_interface": "podman1",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         }
      }
   }
}\0
EOF

        configs+=("$config")
    done

    run_netavark setup $(get_container_netns_path) <<<"${configs[0]}"
    run_netavark setup $(get_container_netns_path 1) <<<"${configs[1]}"

    run_netavark teardown $(get_container_netns_path) <<<"${configs[0]}"
    # bridge should still exist
    run_in_host_netns ip link show podman1

    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${lines[1]}" == "-A NETAVARK_FORWARD -m conntrack --ctstate INVALID -j DROP" "NETAVARK_FORWARD rule 1"
    assert "${lines[2]}" == "-A NETAVARK_FORWARD -d 10.88.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "NETAVARK_FORWARD rule 2"
    assert "${lines[3]}" == "-A NETAVARK_FORWARD -s 10.88.0.0/16 -j ACCEPT" "NETAVARK_FORWARD rule 3"
    assert "${#lines[@]}" = 4 "too many NETAVARK_FORWARD rules"

    run_netavark teardown $(get_container_netns_path 1) <<<"${configs[1]}"
    # bridge should be removed
    expected_rc=1 run_in_host_netns ip link show podman1

    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${lines[1]}" == "-A NETAVARK_FORWARD -m conntrack --ctstate INVALID -j DROP" "NETAVARK_FORWARD rule 1"
    assert "${#lines[@]}" = 2 "too many NETAVARK_FORWARD rules"

    run_in_host_netns ip -o link
    assert "${#lines[@]}" == 1 "only loopback adapter"
}

@test "$fw_driver - two networks" {
    run_netavark --file ${TESTSDIR}/testfiles/two-networks.json setup $(get_container_netns_path)
    result="$output"
    assert_json "$result" 'has("t1")' == "true" "t1 object key exists"
    assert_json "$result" 'has("t2")' == "true" "t2 object key exists"

    run_in_container_netns ip link del eth0
    run_in_container_netns ip link del eth1

    run_in_host_netns iptables -S -t nat
    # extra check so we can be sure that these rules exists before checking later of they are removed
    assert "$output" =~ "--to-destination 10.89.1.2:8080" "eth0 port fw rule exists"
    assert "$output" =~ "--to-destination 10.89.2.2:8080" "eth1 port fw rule exists"

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/two-networks.json teardown $(get_container_netns_path)
    # order is not deterministic so we match twice with different eth name
    assert "$output" =~ 'failed to delete container veth eth0\: Netlink error\: No such device \(os error 19\)' "correct eth0 error message"
    assert "$output" =~ 'failed to delete container veth eth1\: Netlink error\: No such device \(os error 19\)' "correct eth1 error message"

    # now make sure that it actually removed the iptables rule even with the errors
    run_in_host_netns iptables -S -t nat
    assert "$output" !~ "--to-destination 10.89.1.2:8080" "eth0 port fw rule should not exist"
    assert "$output" !~ "--to-destination 10.89.2.2:8080" "eth1 port fw rule should not exist"
}

@test "$fw_driver - ipv6 disabled error message" {
    # disable ipv6 in the netns
     run_in_host_netns sysctl net.ipv6.conf.all.disable_ipv6=1

    expected_rc=1 run_netavark --file ${TESTSDIR}/testfiles/ipv6-bridge.json setup $(get_container_netns_path)
    assert '{"error":"add ip addr to bridge: failed to add ipv6 address, is ipv6 enabled in the kernel?: Netlink error: Permission denied (os error 13)"}' "error message"
}

@test "$fw_driver - route metric from config" {
    run_netavark --file ${TESTSDIR}/testfiles/metric.json setup $(get_container_netns_path)

    run_in_container_netns ip -j route list match 0.0.0.0
    default_route="$output"
    assert_json "$default_route" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route" '.[0].metric' == "200" "Route metric set from config"

    run_in_container_netns ip -j -6 route list match ::0
    default_route_v6="$output"
    assert_json "$default_route_v6" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route_v6" '.[0].metric' == "200" "v6 route metric matches v4"
}

@test "$fw_driver - default route metric" {
    run_netavark --file ${TESTSDIR}/testfiles/dualstack-bridge.json setup $(get_container_netns_path)

    run_in_container_netns ip -j route list match 0.0.0.0
    default_route="$output"
    assert_json "$default_route" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route" '.[0].metric' == "100" "Default metric was chosen"

    run_in_container_netns ip -j -6 route list match ::0
    default_route_v6="$output"
    assert_json "$default_route_v6" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route_v6" '.[0].metric' == "100" "v6 route metric matches v4"
}

@test "netavark error - invalid host_ip in port mappings" {
    expected_rc=1 run_netavark -f ${TESTSDIR}/testfiles/invalid-port.json setup $(get_container_netns_path)
    assert_json ".error" "invalid host ip \"abcd\" provided for port 8080" "host ip error"
}

@test "$fw_driver - test firewalld reload" {
    setup_firewalld

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)

    check_simple_bridge_iptables
    assert "$(<$NETAVARK_TMPDIR/config/firewall/firewall-driver)" "==" "iptables" "firewall-driver file content"

    run_in_host_netns firewall-cmd --reload

    # After a firewalld reload we expect rules to be deleted
    # expected_rc=1 run_in_host_netns iptables -S NETAVARK_FORWARD
    # There was a firewalld change in 3.0 that it no longer flushes all rules, howver we can still check if
    # we are added to trusted.
    run_in_host_netns firewall-cmd --zone=trusted --list-sources
    assert "$output" == "" "no trusted sources"

    # start reload service on start it should restore the rules
    run_netavark_firewalld_reload

    # this run in the background so give it some time to add the rules
    sleep 1
    check_simple_bridge_iptables
    run_in_host_netns firewall-cmd --zone=trusted --list-sources
    assert "$output" == "10.88.0.0/16" "container subnet is trusted after start"

    run_in_host_netns firewall-cmd --reload
    sleep 1
    check_simple_bridge_iptables
    run_in_host_netns firewall-cmd --zone=trusted --list-sources
    assert "$output" == "10.88.0.0/16" "container subnet is trusted after reload"
}

@test "$fw_driver - port forwarding ipv4 - tcp with firewalld reload" {
    test_port_fw firewalld_reload=true
}

function check_simple_bridge_iptables() {
    # check iptables POSTROUTING chain
    run_in_host_netns iptables -S POSTROUTING -t nat
    assert "${lines[1]}" =~ "-A POSTROUTING -j NETAVARK-HOSTPORT-MASQ" "POSTROUTING HOSTPORT-MASQ rule"
    assert "${lines[2]}" =~ "-A POSTROUTING -s 10.88.0.0/16 -j NETAVARK-1D8721804F16F" "POSTROUTING container rule"
    assert "${#lines[@]}" = 3 "too many POSTROUTING rules"

    # check iptables NETAVARK-1D8721804F16F chain
    run_in_host_netns iptables -S NETAVARK-1D8721804F16F -t nat
    assert "${lines[1]}" =~ "-A NETAVARK-1D8721804F16F -d 10.88.0.0/16 -j ACCEPT" "NETAVARK-1D8721804F16F ACCEPT rule"
    assert "${lines[2]}" == "-A NETAVARK-1D8721804F16F ! -d 224.0.0.0/4 -j MASQUERADE" "NETAVARK-1D8721804F16F MASQUERADE rule"
    assert "${#lines[@]}" = 3 "too many NETAVARK-1D8721804F16F rules"

    # check FORWARD rules
    run_in_host_netns iptables -S FORWARD
    assert "${lines[1]}" == "-A FORWARD -m comment --comment \"netavark firewall rules\" -j NETAVARK_FORWARD" "FORWARD rule"
    assert "${#lines[@]}" = 2 "too many FORWARD rules"

    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${lines[1]}" == "-A NETAVARK_FORWARD -m conntrack --ctstate INVALID -j DROP" "NETAVARK_FORWARD rule 1"
    assert "${lines[2]}" == "-A NETAVARK_FORWARD -d 10.88.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "NETAVARK_FORWARD rule 2"
    assert "${lines[3]}" == "-A NETAVARK_FORWARD -s 10.88.0.0/16 -j ACCEPT" "NETAVARK_FORWARD rule 3"
    assert "${#lines[@]}" = 4 "too many NETAVARK_FORWARD rules"
}
