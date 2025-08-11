#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

function start_proxy() {
  RUST_LOG=debug ip netns exec "$NS_NAME" $NETAVARK dhcp-proxy --dir "$TMP_TESTDIR" --uds "$TMP_TESTDIR" &>"$TMP_TESTDIR/proxy.log" &
  PROXY_PID=$!
}

@test "basic teardown" {
      read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "${CONTAINER_MAC}",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH",
  "container_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
  \0
EOF

       run_setup "$input_config"
       # Read the lease file
       run_helper cat "$TMP_TESTDIR/nv-proxy.lease"
       before=$output
       # Check that our mac address is in the lease file which
       # ensures that it was added
       run_helper jq "has(\"$CONTAINER_MAC\")" <<<"$before"
       assert "$output" == "true"
       # Run teardown
       run_teardown "$input_config"
       # Check the dnsmasq log to confirm it received the DHCPRELEASE message.
       # The release is sent synchronously, but we sleep briefly to allow dnsmasq to flush its logs.
       # sleep 1
       # assert `grep -c "DHCPRELEASE(br0).*[[:space:]]${CONTAINER_MAC}" "$TMP_TESTDIR/dnsmasq.log"` == 1
       assert `grep -c "Successfully sent DHCPRELEASE for ${CONTAINER_MAC}" "$TMP_TESTDIR/proxy.log"` == 1
       run_helper cat "$TMP_TESTDIR/nv-proxy.lease"
       # Check that the length of the lease file is now zero
       run_helper jq ". | length" <<<"$output"
       assert "$output" == 0

}
