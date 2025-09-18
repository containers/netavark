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
        # The hostname should be sent at least for the DISCOVER and REQUEST messages. 
        #The third re transmission log is unpredictable given the network conditions 
        local name_count=$(grep -c "client provides name: foobar" "$TMP_TESTDIR/dnsmasq.log")
        assert "$name_count" -ge 2 "hostname should be sent at least twice"
}

@test "basic ipv6 setup" {
  read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar-v6",
  "version": 1,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
\0
EOF

  run_setup "$input_config"

  # Check that an IPv6 address was assigned
  container_ip=$(echo "$output" | jq -r .yiaddr)
  has_ip "$container_ip" veth0
  echo "DEBUG: output is >>>$output<<<"

  # Check that the default IPv6 route is set
  # in IPv6, the kernel actually sets the default route using the link-local address from the router advertisement (RA)
  gateway=$(ip netns exec "$NS_NAME" ip -6 route show default | awk '/default/ {print $3; exit}')
  run_in_container_netns ip -6 route show default
  assert "$output" =~ "via $gateway" "default ipv6 gateway should be set"
   echo "INFO: Default IPv6 gateway is $gateway"


  # Check dnsmasq log for DHCPv6 activity
  assert $(grep -c "DHCPv6" "$TMP_TESTDIR/dnsmasq.log") -gt 0
}

@test "ipv6 receives dns servers" {
  read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "$CONTAINER_MAC",
  "domain_name": "example.com",
  "host_name": "foobar-v6-dns",
  "version": 1,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
\0
EOF

  run_setup "$input_config"

  # Check that the dns_servers array in the output is not empty
  local dns_server_count
  # Clean potential debug output before parsing JSON
  dns_server_count=$(echo "$output" | jq '.dns_servers | length')

  assert "$dns_server_count" -gt 0 "dns_servers array should not be empty"

  echo "INFO: Successfully received $dns_server_count DNS server(s) via DHCPv6"

  # Sanity check that DHCPv6 communication happened
  assert $(grep -c "DHCPv6" "$TMP_TESTDIR/dnsmasq.log") -gt 0
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
