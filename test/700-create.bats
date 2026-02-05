#!/usr/bin/env bats   -*- bats -*-
#
# netavark create command tests
#

load helpers

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

