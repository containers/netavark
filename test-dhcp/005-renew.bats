#!/usr/bin/env bats   -*- bats -*-
#
# Test that release is working after lease timeout
#

load helpers


@test "release after timeout" {
      read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
}
  \0
EOF


    run_setup "$input_config"
    ip_before=$(jq -r '.yiaddr' <<<"$output")
    gw_before=$(jq -r '.gateways[0]' <<<"$output")
    has_ip "$ip_before" veth0
    run_in_container_netns ip -j route show default
    assert "$output" =~ "$gw_before"


    # stop dhcp and restart with new subnet to get a new ip on the next lease
    stop_dhcp
    run_in_container_netns ip add del $(gateway_from_subnet) dev br0
    run_in_container_netns ip addr
    run_in_container_netns ip route

    # get new subnet
    SUBNET_CIDR=$(random_subnet)
    run_in_container_netns ip addr add $(gateway_from_subnet) dev br0
    stripped_subnet=$(strip_last_octet_from_subnet)
    run_dhcp

    run_in_container_netns ip addr
    run_in_container_netns ip route

    # Sigh, minimum lease time in dnsmasq is 2m, give some extra time for the
    # lease roundtrip and ip changes to be applied
    sleep 125
    # after two minutes we should have a new lease and assigned the new ip
    has_ip "$stripped_subnet" veth0

    # make sure we got the new gateway set as well
    run_in_container_netns ip -j route show default
    assert "$output" =~ "$(gateway_from_subnet)"

    # extra check to make sure we got our expected log
    run_helper grep "ip or gateway for mac $CONTAINER_MAC changed" "$TMP_TESTDIR/proxy.log"
}
