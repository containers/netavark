#!/usr/bin/env bats   -*- bats -*-
#
# netavark create command tests
#

load helpers

function setup() {
    basic_setup

    # create a extra interface which we can use to connect the macvlan/ipvlan to
    run_in_host_netns ip link add dummy0 type dummy
}

@test "create - basic network create" {
    # Create a basic network configuration
    run_netavark create < ${TESTSDIR}/testfiles/create/basic.json
    result="$output"
    
    # Check that output is valid JSON
    assert_json "$result" ".name" == "testnet1" "Network name matches"
    assert_json "$result" ".driver" == "bridge" "Driver is bridge"
    assert_json "$result" ".id" == "abc123def4567890123456789012345678901234567890123456789012345678" "Network ID matches"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled"
    assert_json "$result" ".internal" == "false" "Network is not internal"
    assert_json "$result" ".ipv6_enabled" == "false" "IPv6 is disabled"
    
    # Check that network_interface is set
    assert_json "$result" 'has("network_interface")' == "true" "Network interface is set"
    assert_json "$result" ".network_interface" =~ "^podman[0-9]+$" "Network interface matches pattern"
    
    # Check that subnets are created
    assert_json "$result" 'has("subnets")' == "true" "Subnets are present"
    assert_json "$result" ".subnets | length" -ge "1" "At least one subnet exists"
    assert_json "$result" ".subnets[0].subnet" =~ "^10\\.89\\.[0-9]+\\.0/24$" "Subnet matches expected pattern"
    
    # Check that gateway is set
    assert_json "$result" ".subnets[0] | has(\"gateway\")" == "true" "Gateway is present"
    assert_json "$result" ".subnets[0].gateway" =~ "^10\\.89\\.[0-9]+\\.1$" "Gateway matches expected pattern"
    
    # Check that IPAM options are set
    assert_json "$result" 'has("ipam_options")' == "true" "IPAM options are present"
    assert_json "$result" ".ipam_options.driver" == "host-local" "IPAM driver is host-local"
    
    # Check that created timestamp is set
    assert_json "$result" 'has("created")' == "true" "Created timestamp is present"
    assert_json "$result" ".created" != "null" "Created timestamp is not null"
}

@test "create - fail when name is in used.names" {
    # Create first network
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/duplicate-name-same.json

    assert_json ".error"  "network already exists testnet1" "Error message contains 'network already exists testnet1'"
}

@test "create - bridge config" {
    run_netavark create < ${TESTSDIR}/testfiles/create/bridge.json
    result="$output"
    
    assert_json "$result" ".name" == "bridge-net" "Network name matches"
    assert_json "$result" ".driver" == "bridge" "Driver is bridge"
    assert_json "$result" ".ipam_options.driver" == "host-local" "IPAM driver is host-local"
    assert_json "$result" ".subnets | length" -ge "1" "At least one subnet exists"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled"
    assert_json "$result" ".internal" == "false" "Network is not internal"
}

@test "create - network with used interface name" {
    # First, create a network to get an interface name
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/used-interface-1.json
    assert_json ".error" "bridge name usedinterface already in use" "Error message contains 'already in use'"
}

@test "create - network with explicit subnet" {
    run_netavark create < ${TESTSDIR}/testfiles/create/explicit-subnet.json
    result="$output"
    
    assert_json "$result" ".subnets[0].subnet" == "10.100.0.0/24" "Subnet matches"
    assert_json "$result" ".subnets[0].gateway" == "10.100.0.1" "Gateway is first IP in subnet"
}

@test "create - internal network" {
    run_netavark create < ${TESTSDIR}/testfiles/create/internal.json
    result="$output"
    
    assert_json "$result" ".internal" == "true" "Network is internal"
    # Internal networks may not have gateway if DNS is disabled
    # But let's check that subnet is still created
    assert_json "$result" ".subnets | length" -ge "1" "At least one subnet exists"
}

@test "create - network with DNS enabled" {
    run_netavark create < ${TESTSDIR}/testfiles/create/dns-enabled.json
    result="$output"
    
    assert_json "$result" ".dns_enabled" == "true" "DNS is enabled"
    assert_json "$result" ".subnets[0] | has(\"gateway\")" == "true" "Gateway is present for DNS-enabled network"
}

@test "create - fail with empty network name" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/empty-name.json
    assert_json ".error" "Network name must be supplied" "Error message contains 'Network name must be supplied'"
}

@test "create - fail with invalid network name" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/invalid-name.json
    assert_json ".error" "Invalid characters in network name: must match [a-zA-Z0-9][a-zA-Z0-9_.-]" "Error message contains 'Invalid characters in network name'"
}

@test "create - fail with empty network ID" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/empty-id.json
    assert_json ".error" "Network id must be supplied" "Error message contains 'Network id must be supplied'"
}

@test "create - network with labels" {
    run_netavark create < ${TESTSDIR}/testfiles/create/labels.json
    result="$output"
    
    assert_json "$result" 'has("labels")' == "true" "Labels are present"
    assert_json "$result" ".labels.key1" == "value1" "First label matches"
    assert_json "$result" ".labels.key2" == "value2" "Second label matches"
}

@test "create - network with options" {
    run_netavark create < ${TESTSDIR}/testfiles/create/options.json
    result="$output"
    
    assert_json "$result" 'has("options")' == "true" "Options are present"
    assert_json "$result" ".options.mtu" == "1500" "MTU option matches"
}

@test "create - network with IPv6 enabled" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipv6-enabled.json
    result="$output"
    
    assert_json "$result" ".ipv6_enabled" == "true" "IPv6 is enabled"
    # Should have at least one subnet (IPv4 or IPv6)
    assert_json "$result" ".subnets | length" -ge "1" "At least one subnet exists"
}

@test "create - check used subnets with subnet in used.subnets" {
    # Create a network with check_used_subnets: true and a subnet in used.subnets
    run_netavark create < ${TESTSDIR}/testfiles/create/check-used-subnets-with-subnet.json
    result="$output"
    
    # Verify that the output subnet is not the same as the used subnet
    assert_json "$result" ".subnets[0].subnet" != "10.89.0.0/24" "Output subnet is not the used subnet"
    
    # Verify that the output subnet doesn't overlap with the used subnet
    # The used subnet is 10.89.0.0/24, so the output should be 10.89.1.0/24 or later
    # Check that it matches the pattern 10.89.X.0/24 where X >= 1
    assert_json "$result" ".subnets[0].subnet" =~ "^10\\.89\\.[1-9][0-9]*\\.0/24$" "Output subnet is 10.89.1.0/24 or later (does not overlap with 10.89.0.0/24)"
    
    # Verify it's within the pool range (10.89.0.0/16)
    assert_json "$result" ".subnets[0].subnet" =~ "^10\\.89\\." "Output subnet is within the pool range"
}


# Subnet and Gateway Tests

@test "create - bridge with subnet and custom gateway" {
    run_netavark create < ${TESTSDIR}/testfiles/create/subnet-with-gateway.json
    result="$output"
    
    assert_json "$result" ".subnets[0].subnet" == "10.100.0.0/24" "Subnet matches"
    assert_json "$result" ".subnets[0].gateway" == "10.100.0.50" "Custom gateway matches"
}

@test "create - fail with gateway not in subnet" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/gateway-not-in-subnet.json
    assert_json "$output" ".error" "=~" "not in subnet" "Error message contains 'not in subnet'"
}

@test "create - bridge with lease range start_ip" {
    run_netavark create < ${TESTSDIR}/testfiles/create/lease-range-start.json
    result="$output"
    
    assert_json "$result" ".subnets[0].subnet" == "10.100.0.0/24" "Subnet matches"
    assert_json "$result" ".subnets[0].lease_range.start_ip" == "10.100.0.20" "Lease range start_ip matches"
}

@test "create - bridge with lease range start_ip and end_ip" {
    run_netavark create < ${TESTSDIR}/testfiles/create/lease-range-both.json
    result="$output"
    
    assert_json "$result" ".subnets[0].lease_range.start_ip" == "10.100.0.20" "Lease range start_ip matches"
    assert_json "$result" ".subnets[0].lease_range.end_ip" == "10.100.0.50" "Lease range end_ip matches"
}

@test "create - fail with invalid lease range" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/lease-range-invalid.json
    assert_json "$output" ".error" "=~" "not in subnet" "Error message contains 'not in subnet'"
}



# IPv6 Auto-generation Tests
@test "create - ipv6_enabled auto-generates dual-stack" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipv6-auto-dualstack.json
    result="$output"
    
    assert_json "$result" ".ipv6_enabled" == "true" "IPv6 is enabled"
    assert_json "$result" ".subnets | length" == "2" "Two subnets created"
    
    # Check one is IPv4 and one is IPv6
    ipv4_count=$(echo "$result" | jq '[.subnets[].subnet | select(contains("."))] | length')
    ipv6_count=$(echo "$result" | jq '[.subnets[].subnet | select(contains(":"))] | length')

    assert "$ipv4_count" == "1" "Expected 1 IPv4 subnet"
    assert "$ipv6_count" == "1" "Expected 1 IPv6 subnet"
}

@test "create - ipv6_enabled with ipv4 subnet adds ipv6" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipv6-with-ipv4-subnet.json
    result="$output"

    assert_json "$result" ".ipv6_enabled" == "true" "IPv6 is enabled"
    assert_json "$result" ".subnets | length" == "2" "Two subnets created"
    assert_json "$result" ".subnets[0].subnet" == "10.100.0.0/24" "IPv4 subnet matches"

    # Check second subnet is IPv6
    assert_json "$result" ".subnets[1].subnet" "=~" ":" "Second subnet should be IPv6"
}

@test "create - ipv6 subnet auto-detects and sets ipv6_enabled" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipv6-subnet.json
    result="$output"

    assert_json "$result" ".ipv6_enabled" == "true" "IPv6 is auto-detected and enabled"
    assert_json "$result" ".subnets[0].subnet" == "fdcc::/64" "IPv6 subnet matches"
}

# NetworkDNSServers Tests
@test "create - network_dns_servers with valid IPs" {
    run_netavark create < ${TESTSDIR}/testfiles/create/network-dns-servers-valid.json
    result="$output"
    
    assert_json "$result" ".network_dns_servers[0]" == "8.8.8.8" "First DNS server matches"
    assert_json "$result" ".network_dns_servers[1]" == "1.1.1.1" "Second DNS server matches"
    assert_json "$result" ".dns_enabled" == "true" "DNS is enabled"
}

@test "create - fail with invalid IP in network_dns_servers" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/network-dns-servers-invalid-ip.json
    assert_json "$output" ".error" "=~" "invalid IP address syntax" "Error message about invalid IP"
}

@test "create - fail with network_dns_servers when dns_enabled=false" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/network-dns-servers-dns-disabled.json
    assert_json "$output" ".error" "=~" "DNS is not enabled" "Error message about DNS not enabled"
}

# MTU Option Tests
@test "create - network with mtu option" {
    run_netavark create < ${TESTSDIR}/testfiles/create/mtu-option.json
    result="$output"
    
    assert_json "$result" ".options.mtu" == "1500" "MTU option is set"
}

@test "create - fail with invalid mtu option" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/mtu-invalid.json
    assert_json "$output" ".error" "=~" "mtu" "Error message contains 'mtu'"
}

# VLAN Option Tests
@test "create - network with vlan option" {
    run_netavark create < ${TESTSDIR}/testfiles/create/vlan-option.json
    result="$output"
    
    assert_json "$result" ".options.vlan" == "100" "VLAN option is set"
}

@test "create - fail with invalid vlan option" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/vlan-invalid.json
    assert_json "$output" ".error" "=~" "vlan" "Error message contains 'vlan'"
}

# Isolate Option Tests
@test "create - network with isolate=true" {
    run_netavark create < ${TESTSDIR}/testfiles/create/isolate-true.json
    result="$output"
    
    assert_json "$result" ".options.isolate" == "true" "Isolate option is set to true"
}

@test "create - network with isolate=strict" {
    run_netavark create < ${TESTSDIR}/testfiles/create/isolate-strict.json
    result="$output"
    
    assert_json "$result" ".options.isolate" == "strict" "Isolate option is set to strict"
}

# IPAM Driver Tests
@test "create - ipam driver none disables DNS" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipam-none.json
    result="$output"
    
    assert_json "$result" ".ipam_options.driver" == "none" "IPAM driver is none"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled when ipam is none"
}

@test "create - fail ipam driver none with subnets" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/ipam-none-with-subnets.json
    assert_json "$output" ".error" "=~" "ipam.*subnets" "Error about none ipam with subnets"
}

# MACVLAN Tests
@test "create - macvlan without subnet defaults to dhcp" {
    run_netavark create < ${TESTSDIR}/testfiles/create/macvlan-dhcp.json
    result="$output"
    
    assert_json "$result" ".driver" == "macvlan" "Driver is macvlan"
    assert_json "$result" ".ipam_options.driver" == "dhcp" "IPAM driver is dhcp"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled for macvlan"
}

@test "create - macvlan with subnet" {
    run_netavark create < ${TESTSDIR}/testfiles/create/macvlan-subnet.json
    result="$output"
    
    assert_json "$result" ".driver" == "macvlan" "Driver is macvlan"
    assert_json "$result" ".ipam_options.driver" == "host-local" "IPAM driver is host-local"
    assert_json "$result" ".subnets[0].subnet" == "10.200.0.0/24" "Subnet matches"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled for macvlan"
}

@test "create - macvlan with mode option" {
    run_netavark create < ${TESTSDIR}/testfiles/create/macvlan-mode.json
    result="$output"
    
    assert_json "$result" ".driver" == "macvlan" "Driver is macvlan"
    assert_json "$result" ".options.mode" == "bridge" "Mode option is set"
}

# IPVLAN Tests
@test "create - fail ipvlan without subnet (no dhcp support)" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/ipvlan-no-subnet.json
    assert_json "$output" ".error" == "ipam driver dhcp is not supported with ipvlan" "Error about ipvlan dhcp"
}

@test "create - ipvlan with subnet" {
    run_netavark create < ${TESTSDIR}/testfiles/create/ipvlan-subnet.json
    result="$output"
    
    assert_json "$result" ".driver" == "ipvlan" "Driver is ipvlan"
    assert_json "$result" ".ipam_options.driver" == "host-local" "IPAM driver is host-local"
    assert_json "$result" ".subnets[0].subnet" == "10.200.0.0/24" "Subnet matches"
    assert_json "$result" ".dns_enabled" == "false" "DNS is disabled for ipvlan"
}

# Static Route Tests
@test "create - bridge with static route" {
    run_netavark create < ${TESTSDIR}/testfiles/create/static-route.json
    result="$output"
    
    assert_json "$result" ".routes | length" == "1" "One route is present"
    assert_json "$result" ".routes[0].destination" == "192.168.0.0/24" "Route destination matches"
    assert_json "$result" ".routes[0].gateway" == "10.100.0.254" "Route gateway matches"
}

@test "create - fail with invalid route destination (not CIDR)" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/route-invalid-dest.json
    assert_json "$output" ".error" "=~" "invalid IP address syntax" "Error message about invalid IP"
}

@test "create - fail with invalid route gateway" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/route-invalid-gw.json
    assert_json "$output" ".error" "=~" "invalid IP address syntax" "Error message about invalid IP"
}

# Tests for subnet validation against used.subnets
@test "create - fail when explicit subnet overlaps with used.subnets" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/subnet-overlaps-used.json
    assert_json "$output" ".error" "=~" "already used" "Error message contains 'already used'"
}

@test "create - fail when explicit subnet duplicates used.subnets" {
    expected_rc=1 run_netavark create < ${TESTSDIR}/testfiles/create/subnet-duplicate-used.json
    assert_json "$output" ".error" "=~" "already used" "Error message contains 'already used'"
}
