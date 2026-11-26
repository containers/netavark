#!/usr/bin/env bats   -*- bats -*-
#
# Test DHCP lease renewal when the subnet changes
#

load helpers


# Testing two things at a time in this test to avoid 125s sleep multiple times and increasing CI
# minutes. Running tests in parallel may not work because bats doesn't guarantee order when running
# in parallel and we need to run the mysterious NOP in 001-basic.bats first.
#   Test 1: Lease renewal correctly updates IP addresses and default routes
#   Test 2: The no_default_route option is respected during both initial setup and renewal
@test "lease renewal updates addresses and respects no_default_route" {
    # client setup and pre-check for test 1
    read -r -d '\0' config1 <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

    run_setup "$config1"
    ip1_before=$(jq -r '.yiaddr' <<<"$output")
    gw1_before=$(jq -r '.gateways[0]' <<<"$output")
    has_ip "$ip1_before" veth0
    run_in_container_netns ip -j route show default
    assert "$output" =~ "$gw1_before"

    # need additional interfaces so we can run test 2 at the same time
    add_veth "veth2" "br0"
    run_in_container_netns ip -j link show veth2
    mac2=$(echo "$output" | jq -r .[0].address)
    add_veth "veth3" "br0"

    # client setup and pre-check for test 2
    read -r -d '\0' config2 <<EOF
{
  "host_iface": "veth3",
  "container_iface": "veth2",
  "container_mac_addr": "$mac2",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "no_default_route": true
}
  \0
EOF

    run_setup "$config2"
    ip2_before=$(jq -r '.yiaddr' <<<"$output")
    has_ip "$ip2_before" veth2
    # there should still be only one default route, not two
    run_in_container_netns ip -j route show default
    assert "$output" =~ "$gw1_before" "default route from test 1 still present"
    default_routes=$(echo "$output" | jq length)
    assert "$default_routes" == 1 "exactly one default route (no_default_route client must not add one)"

    # stop dhcp and restart with new subnet to get a new ip on the next lease
    stop_dhcp
    run_in_container_netns ip add del $(gateway_from_subnet "$SUBNET_CIDR")/24 dev br0
    run_in_container_netns ip addr
    run_in_container_netns ip route

    # get new subnet
    SUBNET_CIDR=$(random_subnet)
    run_in_container_netns ip addr add $(gateway_from_subnet "$SUBNET_CIDR")/24 dev br0
    stripped_subnet=$(strip_last_octet_from_subnet "$SUBNET_CIDR")
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
    assert "$output" =~ "$(gateway_from_subnet "$SUBNET_CIDR")" "client 1 has new default route"

    # even after the renewal, there should still be only one default route, not two
    default_routes=$(echo "$output" | jq length)
    assert "$default_routes" == 1 "still exactly one default route after renewal (no_default_route respected)"
    has_ip "$stripped_subnet" veth2

    # extra check to make sure we got our expected log
    run_helper grep "ip or gateway for mac $CONTAINER_MAC changed" "$TMP_TESTDIR/proxy.log"
    run_helper grep "ip or gateway for mac $mac2 changed" "$TMP_TESTDIR/proxy.log"
}
