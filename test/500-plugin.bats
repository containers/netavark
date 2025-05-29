#!/usr/bin/env bats   -*- bats -*-
#
# macvlan driver test
#

load helpers


# create config for plugin with the name as first arg
function get_conf() {
    cat <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "plugin-net": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "plugin-net": {
         "name": "plugin-net",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "$1",
         "network_interface": "dummy0",
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false
      }
   }
}
EOF
}

function run_netavark_plugins() {
    run_netavark --plugin-directory $TEST_PLUGINS "$@"
}

@test "plugin - test error message" {
    config=$(get_conf error-plugin)

    expected_rc=1 run_netavark_plugins setup $(get_container_netns_path) <<<"$config"
    assert '{"error":"plugin \"error-plugin\" failed: exit code 1, message: setup error"}'

    expected_rc=1 run_netavark_plugins teardown $(get_container_netns_path) <<<"$config"
    assert '{"error":"plugin \"error-plugin\" failed: exit code 1, message: teardown error"}'
}

@test "plugin - host-device" {
    config=$(get_conf host-device-plugin)

    run_in_host_netns ip link add dummy0 type dummy

    run_netavark_plugins setup $(get_container_netns_path) <<<"$config"
    assert  "$output" =~ '"interfaces"\:\{"dummy0"\:' "status block with interface name"

    run_in_container_netns ip link show dummy0

    run_netavark_plugins teardown $(get_container_netns_path) <<<"$config"
    assert '' "no error output"

    # interface should be back in the host ns
    run_in_host_netns ip link show dummy0
}

@test "plugin - stderr" {
    config=$(get_conf stderr-plugin)

    run_netavark_plugins setup $(get_container_netns_path) <<<"$config"
    assert "${lines[0]}" == "stderr setup" "stderr log on first line"
    assert "${lines[1]}" =~ '"interfaces"' "status block"

    run_netavark_plugins teardown $(get_container_netns_path) <<<"$config"
    assert 'stderr teardown' "stderr log"
}
