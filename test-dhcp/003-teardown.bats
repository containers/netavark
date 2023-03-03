#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "basic teardown" {
      read -r -d '\0' input_config <<EOF
{
  "host_iface": "veth1",
  "container_iface": "veth0",
  "container_mac_addr": "${CONTAINER_MAC}",
  "domain_name": "example.com",
  "host_name": "foobar",
  "version": 0,
  "ns_path": "$NS_PATH"
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
       run_helper cat "$TMP_TESTDIR/nv-proxy.lease"
       # Check that the length of the lease file is now zero
       run_helper jq ". | length" <<<"$output"
       assert "$output" == 0

}
