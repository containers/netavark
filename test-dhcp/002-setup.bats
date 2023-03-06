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
  "ns_path": "$NS_PATH"
}
  \0
EOF

        run_setup "$input_config"
        # Check that gateway provided is the first IP in the subnet
        assert `echo "$output" | jq -r .siaddr` == $(gateway_from_subnet "$SUBNET_CIDR")
        container_ip=$(echo "$output" | jq -r .yiaddr)
        has_ip "$container_ip"
}


@test "empty interface should fail 155" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "",
  "host_iface": "veth1",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
}
  \0
EOF
        # Not providing an interface in the config should result
        # in an error and a return code of 156
        expected_rc=155 run_setup "$input_config"
}

@test "empty mac address should fail 156" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth0",
  "container_mac_addr": "",
  "host_iface": "veth1",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
}
  \0
EOF
        # Not mac address should result in an error
        # and return code of 156
        expected_rc=156 run_setup "$input_config"
}

@test "invalid interface should fail 156" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth990",
  "host_iface": "veth1",
  "container_mac_addr": "",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
}
  \0
EOF
        # A non-existent interface should result in an
        # error and return code of 156
        expected_rc=156 run_setup "$input_config"
}

@test "invalid mac address should fail 156" {
      read -r -d '\0' input_config <<EOF
{
  "container_iface": "veth0",
  "host_iface": "veth1",
  "container_mac_addr": "123",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
}
  \0
EOF

        # An invalid mac address should result in an
        # error and a return code of 156
        expected_rc=156 run_setup "$input_config"
}
