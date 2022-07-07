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
   after="$output"
   assert "$before" == "$after" "make sure tables have not changed"

   run_in_container_netns ip route show
   assert "default" "!~" "$output" "No default route for internal networks"

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

    ipaddr="10.88.0.1"
    run_in_host_netns ip addr show podman0
    assert "$output" =~ "$ipaddr" "IP address matches bridge gateway address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].gateway" == "$ipaddr" "Result contains gateway address"

    # check that the loopback adapter is up
    run_in_container_netns ip addr show lo
    assert "$output" =~ "127.0.0.1" "Loopback adapter is up (has address)"

    run_in_host_netns ping -c 1 10.88.0.2

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
    assert "${lines[1]}" == "-A FORWARD -m comment --comment \"netavark firewall plugin rules\" -j NETAVARK_FORWARD" "FORWARD rule"
    assert "${#lines[@]}" = 2 "too many FORWARD rules"

    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${lines[1]}" == "-A NETAVARK_FORWARD -d 10.88.0.0/16 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "NETAVARK_FORWARD rule 1"
    assert "${lines[2]}" == "-A NETAVARK_FORWARD -s 10.88.0.0/16 -j ACCEPT" "NETAVARK_FORWARD rule 2"
    assert "${#lines[@]}" = 3 "too many NETAVARK_FORWARD rules"

    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json teardown $(get_container_netns_path)

    # now check that iptables rules are gone
    run_in_host_netns iptables -S

    # check FORWARD rules
    run_in_host_netns iptables -S FORWARD
    assert "${lines[1]}" == "-A FORWARD -m comment --comment \"netavark firewall plugin rules\" -j NETAVARK_FORWARD" "FORWARD rule"
    assert "${#lines[@]}" = 2 "too many FORWARD rules after teardown"

    # rule 1 should be DROP for any existing networks
    run_in_host_netns iptables -S NETAVARK_FORWARD
    assert "${#lines[@]}" = 1 "too many NETAVARK_FORWARD rules after teardown"

    # check POSTROUTING nat rules
    run_in_host_netns iptables -S POSTROUTING -t nat
    assert "${lines[1]}" =~ "-A POSTROUTING -j NETAVARK-HOSTPORT-MASQ" "POSTROUTING HOSTPORT-MASQ rule"
    assert "${#lines[@]}" = 2 "too many POSTROUTING rules after teardown"

    # NETAVARK-1D8721804F16F chain should not exists
    expected_rc=1 run_in_host_netns iptables -nvL NETAVARK-1D8721804F16F -t nat

    # bridge should be removed on teardown
    expected_rc=1 run_in_host_netns ip addr show podman0
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
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    result1="$output"

    create_container_ns

    run_netavark --file ${TESTSDIR}/testfiles/connectbridge.json setup $(get_container_netns_path 1)
    result2="$output"

    # check iptables NETAVARK_ISOLATION chain
    run_in_host_netns iptables -nvL NETAVARK_ISOLATION
    assert "${lines[2]}" =~ "   0     0 DROP       all  --  podman1 !podman1  0.0.0.0/0            0.0.0.0/0    "

    run_in_host_netns iptables -nvL FORWARD
    assert "${lines[2]}" =~ "NETAVARK_ISOLATION"

    # make sure the isolated network cannot reach the other network
    expected_rc=1 run_in_container_netns 1 ping -w 1 -c 1 10.88.0.2

    run_netavark --file ${TESTSDIR}/testfiles/connectbridge.json teardown $(get_container_netns_path 1)

    run_netavark --file ${TESTSDIR}/testfiles/connectbridge.json setup $(get_container_netns_path)
    result2="$output"
    assert_json "$result2" 'has("podman1")' == "true" "object key exists"

    # ping from the not isolated container to isolated should work
    run_in_container_netns ping -c 1 10.89.0.2

    run_netavark --file ${TESTSDIR}/testfiles/connectbridge.json teardown $(get_container_netns_path)
    run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json teardown $(get_container_netns_path)

    # check that isolation rule is deleted
    run_in_host_netns iptables -nvL NETAVARK_ISOLATION
    assert "${lines[2]}" == "" "NETAVARK_ISOLATION chain should be empty"
}
