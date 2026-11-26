#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "basic setup" {

      read -r -d '\0' input_config <<EOF
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

        run_setup "$input_config"
        # Check that gateway provided is the first IP in the subnet
        assert `echo "$output" | jq -r .siaddr` == $(gateway_from_subnet "$SUBNET_CIDR")
        container_ip=$(echo "$output" | jq -r .yiaddr)
        has_ip "$container_ip" veth0
        # Check that there was a hostname in the DHCP requests
        assert `grep -c "client provides name: foobar" "$TMP_TESTDIR/dnsmasq.log"` == 3
}

@test "no hostname" {

      read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

        # Check that there was no hostname in the DHCP requests
        assert `grep -c "client provides name" "$TMP_TESTDIR/dnsmasq.log"` == 0
}

@test "empty interface should fail" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "",
  "host_iface": "veth1",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

        expected_rc=1 run_setup "$input_config"
        assert "$output" =~ "No such device" "interface not found error"
}

@test "empty mac address should fail" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth0",
  "container_mac_addr": "",
  "host_iface": "veth1",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

        expected_rc=1 run_setup "$input_config"
        assert "$output" =~ "unable to parse mac address : cannot parse integer from empty string" "empty mac error"
}

@test "invalid interface should fail" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth990",
  "host_iface": "veth1",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

        expected_rc=1 run_setup "$input_config"
        assert "$output" =~ "No such device" "interface not found error"
}

@test "invalid mac address should fail" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth0",
  "host_iface": "veth1",
  "container_mac_addr": "123",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF


        expected_rc=1 run_setup "$input_config"
        assert "$output" =~ "unable to parse mac address 123" "mac address error"
}

@test "setup with no_default_route" {
      read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "no_default_route": true
}
  \0
EOF

        run_setup "$input_config"
        container_ip=$(echo "$output" | jq -r .yiaddr)
        has_ip "$container_ip" veth0

        # verify no default route is present when no_default_route is set
        run_in_container_netns ip -j route show default
        assert "$output" == "[]" "no default route should exist with no_default_route"
}
