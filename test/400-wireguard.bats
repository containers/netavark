#!/usr/bin/env bats   -*- bats -*-
#
# wireguard driver test
#

load helpers

function setup() {
    basic_setup
}

@test "simple WireGuard setup" {
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard.json setup $(get_container_netns_path)
    result="$output"

    # check that interface exists
    run_in_container_netns ip -j --details link show wg-test
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "wireguard" "Container interface is a macvlan device"

    # check ip addresses
    ipaddr="10.10.0.1/16"
    ipaddr2="2001::1/64"
    ipaddr3="10.11.1.1/32"
    ipaddr4="dd01:129d:3:a992:11da:aa22:93df:1/128"
    run_in_container_netns ip addr show wg-test
    assert "$output" "=~" "$ipaddr" "WireGuard IPv4 address matches container address"
    assert "$output" "=~" "$ipaddr2" "WireGuard IPv6 address matches container address"
    assert "$output" "=~" "$ipaddr3" "IPv4 without CIDR was added to container WireGuard interface"
    assert "$output" "=~" "$ipaddr4" "IPv6 without CIDR was added to container WireGuard interface"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "=~" "10.10.0.0/16 dev wg-test proto kernel scope link src 10.10.0.1" "wireguard ipv4 gateways are correctly set up"
    assert "$output" "=~" "10.11.1.0/24 via 10.11.1.1 dev wg-test proto static metric 100" "wireguard ipv4 gateways are correctly set up"
    run_in_container_netns ip -6 r
    assert "$output" "=~" "2001::/64 dev wg-test proto kernel metric 256 pref medium" "wireguard ipv6 gateways are correctly set up"
    assert "$output" "=~" "dd01:129d:3:a992:11da:aa22:93df:1 dev wg-test proto kernel metric 256 pref medium" "wireguard ipv6 gateways are correctly set up"

    # check Interface key
    # To get the key that is compared here run echo $PRIVATE_KEY | wg pubkey on the PrivateKey from testfiles/wireguard.conf
    run_in_container_netns wg
    assert "$output" "=~" "private key: \(hidden\)" "WireGuard interface key was correctly set"
    assert "$output" "=~" "public key: HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=" "WireGuard interface key was correctly set"

    # check WireGuard Port
    assert "$output" "=~" "listening port: 51820" "WireGuard port was correctly set"

    # check IPv4 peer
    assert "$output" "=~" "peer: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=" "WireGuard peer was added"
    assert "$output" "=~" "preshared key: \(hidden\)" "WireGuard peer preshared key was correctly set"
    assert "$output" "=~" "allowed ips: 10.10.0.2/32, 10.11.1.0/24" "WireGuard peer allowed IPs were correctly set"
    assert "$output" "=~" "endpoint: 123.45.67.89:12345" "WireGuard peer endpoint was correctly set"

    # check IPv6 peer
    assert "$output" "=~" "peer: gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=" "WireGuard peer was added"
    assert "$output" "=~" "allowed ips: ffff:ffff::/32" "WireGuard peer allowed IPs were correctly set"
    
    # check mixed IPv6, IPv4 peer
    assert "$output" "=~" "peer: fMyt1P5L9yGCY41Zk8NviMqqj0S8NS5Ta9GtqwHa1Sw=" "WireGuard peer was added"
    assert "$output" "=~" "allowed ips: ffff::abcd/128, 192.168.0.0/16" "WireGuard peer allowed IPs were correctly set"

    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard.json teardown $(get_container_netns_path)
}
@test "WireGuard Address parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-address-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration Address on line 1.  No value provided.\""}' "Correct error on empty address"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-address-missing.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"invalid WireGuard configuration: Interface is missing an Address"}' "Correct error on missing address"
}

@test "WireGuard AllowedIPs parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-ipv6.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"AddrParseError(()) when parsing WireGuard peers AllowedIPs: \\\"ffff::agcd/128,192.168.0.0/16\\\". Occurs in \\\"ffff::agcd/128\\\"\""}' "Correct error on wrong IPv6"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-ipv4.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"AddrParseError(()) when parsing WireGuard peers AllowedIPs: \\\"10.292.122.3/32,10.192.124.0/24\\\". Occurs in \\\"10.292.122.3/32\\\"\""}' "Correct error on wrong IPv4"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-allowedips-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration AllowedIPs on line 8.  No value provided.\""}' "Correct error on empty AllowedIPs"

    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-allowedips-missing.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"invalid WireGuard configuration: Peer #0 is missing AllowedIPs"}' "Correct error on missing AllowedIPs"
}

@test "WireGuard endpoint parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-endpoint-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration Endpoint on line 9.  No value provided.\""}' "Correct error on empty endpoint"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-endpoint-ip.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when trying to parse Endpoint 123.45.67.389:12345 for peer 0: \\\"could not parse \\\\\\\"123.45.67.389:12345\\\\\\\"\\\"\""}' "Correct error on wrong Endpoint IP"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-endpoint-port.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when trying to parse Endpoint 123.45.67.89:123456 for peer 0: \\\"incorrect port: number too large to fit in target type\\\"\""}' "Correct error on wrong Endpoint Port"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-endpoint-hostname.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when trying to parse Endpoint test.thisdomainshouldnotexist:12345 for peer 0: \\\"could not parse \\\\\\\"test.thisdomainshouldnotexist:12345\\\\\\\"\\\"\""}' "Correct error on wrong Endpoint hostname"
}

@test "WireGuard port parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-port-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration ListenPort on line 3.  No value provided.\""}' "Correct error on empty port"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-port.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"ParseIntError { kind: PosOverflow } when parsing WireGuard interface port: \\\"222222\\\"\""}' "Correct error on incorrect port"
}

@test "WireGuard private key parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-privatekey-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration PrivateKey on line 4.  No value provided.\""}' "Correct error on empty privatekey"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-privatekey-missing.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"invalid WireGuard configuration: Interface is missing a PrivateKey"}' "Correct error on missing privatekey"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-privatekey.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"[200, 9, 243, 229, 49, 73, 181, 237, 120, 182, 56, 183, 206, 83, 13, 171, 232, 93, 218, 182, 20, 34, 2, 65, 128, 29, 223, 6, 105] when decoding base64 PrivateKey: \\\"yAnz5TFJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\\\". Is it 32 bytes?\""}' "Correct error on incorrect privatekey"
}

@test "WireGuard public key parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-publickey-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration PublicKey on line 7.  No value provided.\""}' "Correct error on empty publickey"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-publickey-missing.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"invalid WireGuard configuration: Peer #0 is missing a PublicKey"}' "Correct error on missing publickey"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-publickey.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"[197, 50, 1, 2, 27, 104, 118, 54, 250, 123, 175, 123, 66, 50, 196, 70, 221, 77, 0, 30, 38, 102, 170, 124, 14] when decoding base64 PublicKey: \\\"xTIBAhtodjb6e697QjLERt1NAB4mZqp8Dg=\\\" for peer 0. Is it 32 bytes?\""}' "Correct error on incorrect publickey"
}

@test "WireGuard preshared key parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-presharedkey-empty.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration PresharedKey on line 8.  No value provided.\""}' "Correct error on empty presharedkey"
    
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-presharedkey.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"[210, 68, 125, 27, 3, 40, 183, 170, 86, 71, 208, 240, 79, 188, 143, 200, 65, 149, 13, 160, 181, 11, 108, 119, 205, 121, 92, 129, 207] when decoding base64 PresharedKey: \\\"0kR9GwMot6pWR9DwT7yPyEGVDaC1C2x3zXlcgc8=\\\" for peer 0. Is it 32 bytes?\""}' "Correct error on incorrect presharedkey"
}

@test "WireGuard incorrect line parsing fail" {
    expected_rc=1
    run_netavark --file ${TESTSDIR}/testfiles/wireguard/wireguard-fail-broken-line.json setup $(get_container_netns_path)
    result="$output"

    assert "$output" "=" '{"error":"when parsing WireGuard config: \"when parsing WireGuard configuration Address on line: 1.\""}' "Errors on malformed line"
}
