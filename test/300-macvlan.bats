#!/usr/bin/env bats   -*- bats -*-
#
# macvlan driver test
#

load helpers

function setup() {
    basic_setup

    # create a extra interface which we can use to connect the macvlan to
    run_in_host_netns ip link add dummy0 type dummy
}

@test "simple macvlan setup" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" "=~" "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr" "Result contains correct IP address"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "=~" "default via 10.88.0.1" "gateway must be there in default route"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].gateway" == "10.88.0.1" "Result contains gateway address"

    run_in_container_netns cat /proc/sys/net/ipv6/conf/eth0/autoconf
    assert "0" "autoconf is disabled"

    run_netavark --file ${TESTSDIR}/testfiles/macvlan.json teardown $(get_container_netns_path)
    assert "" "no errors"
}

@test "macvlan setup with static routes" {
    # add second interface and routes through that interface to test proper teardown
    run_in_container_netns ip link add type dummy
    run_in_container_netns ip a add 10.91.0.10/24 dev dummy0
    run_in_container_netns ip link set dummy0 up

    run_netavark --file ${TESTSDIR}/testfiles/macvlan-staticroutes.json setup $(get_container_netns_path)

    # check static routes
    run_in_container_netns ip r
    assert "$output" "=~" "10.89.0.0/24 via 10.88.0.2" "static route not set"
    assert "$output" "=~" "10.90.0.0/24 via 10.88.0.3" "static route not set"
    assert "$output" "=~" "10.92.0.0/24 via 10.91.0.1" "static route not set"
    run_in_container_netns ip -6 r
    assert "$output" "=~" "fd:2f2f::/64 via fd:1f1f::20" "static route not set"

    run_netavark --file ${TESTSDIR}/testfiles/macvlan-staticroutes.json teardown $(get_container_netns_path)
    assert "" "no errors"

    # check static routes get removed
    run_in_container_netns ip r
    assert "$output" "!~" "10.89.0.0/24 via 10.88.0.2" "static route not removed"
    assert "$output" "!~" "10.90.0.0/24 via 10.88.0.3" "static route not removed"
    assert "$output" "!~" "10.92.0.0/24 via 10.91.0.1" "static route not removed"
    run_in_container_netns ip -6 r
    assert "$output" "!~" "fd:2f2f::/64 via fd:1f1f::20" "static route not removed"

    run_in_container_netns ip link delete dummy0
}

@test "macvlan setup no default route" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan-nodefaultroute.json setup $(get_container_netns_path)

    run_in_container_netns ip r
    assert "$output" "!~" "default" "default route exists"

    run_in_container_netns ip -6 r
    assert "$output" "!~" "default" "default route exists"

    run_netavark --file ${TESTSDIR}/testfiles/macvlan-nodefaultroute.json teardown $(get_container_netns_path)
    assert "" "no errors"
}

@test "macvlan setup internal" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan-internal.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2/16"
    run_in_container_netns ip addr show eth0
    assert "$output" "=~" "$ipaddr" "IP address matches container address"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr" "Result contains correct IP address"

    # internal macvlan must not contain
    run_in_container_netns ip r
    assert "$output" !~ 'default' "macvlan must not contain default gateway in route at all"
}

@test "macvlan setup with mtu" {
    run_netavark --file ${TESTSDIR}/testfiles/macvlan-mtu.json setup $(get_container_netns_path)
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].mtu" "=="  "1400" "MTU matches configured MTU"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"

    ipaddr="10.88.0.2"
    run_in_container_netns ip -j addr show eth0
    link_info="$output"
    assert_json "$link_info" ".[].addr_info[0].local" "==" "$ipaddr" "IP address matches container address"
    assert_json "$link_info" ".[].addr_info[0].prefixlen" "==" "16" "IP prefix matches container subnet"
    assert_json "$result" ".podman.interfaces.eth0.subnets[0].ipnet" "==" "$ipaddr/16" "Result contains correct IP address"
}

@test "macvlan modes" {
    for mode in bridge private vepa passthru source; do
        # echo here so we know which test failed
        echo "mode $mode"

        read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.2"
         ],
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "macvlan",
         "network_interface": "dummy0",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         },
         "options": {
            "mode": "$mode"
         }
      }
   }
}\0
EOF

    run_netavark setup $(get_container_netns_path) <<<"$config"
    run_in_container_netns ip -j --details link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].mtu" "=="  "1500" "MTU matches expected MTU"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "macvlan" "Container interface is a macvlan device"
    assert_json "$link_info" ".[].linkinfo.info_data.mode" "==" "$mode" "Container interface has correct macvlan mode"

    run_netavark teardown $(get_container_netns_path) <<<"$config"
    done
}

@test "macvlan ipam none" {
           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "macvlan",
         "network_interface": "dummy0",
         "subnets": [],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "none"
         }
      }
   }
}\0
EOF

    run_netavark setup $(get_container_netns_path) <<<"$config"
    result="$output"

    mac=$(jq -r '.podman.interfaces.eth0.mac_address' <<< "$result" )
    # check that interface exists
    run_in_container_netns ip -j link show eth0
    link_info="$output"
    assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"

    run_in_container_netns ip -j --details addr show eth0
    assert_json "$link_info" ".[].addr_info" "==" "null" "No ip addresses configured"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "==" "" "No routes configured"
}


@test "macvlan static mac" {
   mac="aa:bb:cc:dd:ee:ff"

           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.2"
         ],
         "static_mac": "$mac",
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "macvlan",
         "network_interface": "dummy0",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         }
      }
   }
}\0
EOF

   run_netavark setup $(get_container_netns_path) <<<"$config"
   result="$output"


   assert_json "$result" ".podman.interfaces.eth0.mac_address" == "$mac" "MAC matches input mac"
   # check that interface exists
   run_in_container_netns ip -j link show eth0
   link_info="$output"
   assert_json "$link_info" ".[].address" "=="  "$mac" "MAC matches container mac"
   assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
}


@test "macvlan same interface name on host" {

           read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.2"
         ],
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "macvlan",
         "network_interface": "eth0",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         }
      }
   }
}\0
EOF

   run_in_host_netns ip link add eth0 type dummy

   run_netavark setup $(get_container_netns_path) <<<"$config"

   run_in_container_netns ip link show eth0

   run_netavark teardown $(get_container_netns_path) <<<"$config"
}

@test "macvlan same interface name on container" {

   read -r -d '\0' config <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "podman": {
         "static_ips": [
            "10.88.0.2"
         ],
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "podman": {
         "name": "podman",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "macvlan",
         "network_interface": "dummy0",
         "subnets": [
            {
               "subnet": "10.88.0.0/16",
               "gateway": "10.88.0.1"
            }
         ],
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false,
         "ipam_options": {
            "driver": "host-local"
         }
      }
   }
}\0
EOF

   run_in_container_netns ip link add eth0 type dummy

   expected_rc=1 run_netavark setup $(get_container_netns_path) <<<"$config"

   # make sure the tmp interface is not leaked on the host or netns
   run_in_host_netns ip -o link show
   assert "${#lines[@]}" == 2 "only two interfaces (lo, dummy0) on the host, the tmp macvlan interface should be gone"

   run_in_container_netns ip -o link show
   assert "${#lines[@]}" == 2 "only two interfaces (lo, eth0) in the netns, the tmp macvlan interface should be gone"
}

@test "macvlan route metric from config" {
    run_netavark --file ${TESTSDIR}/testfiles/metric-macvlan.json setup $(get_container_netns_path)

    run_in_container_netns ip -j route list match 0.0.0.0
    default_route="$output"
    assert_json "$default_route" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route" '.[0].metric' == "200" "Route metric set from config"

    run_in_container_netns ip -j -6 route list match ::0
    default_route_v6="$output"
    assert_json "$default_route_v6" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route_v6" '.[0].metric' == "200" "v6 route metric matches v4"
}

@test "macvlan route metric from config with dhcp" {
    # This test verifies that metric is properly passed to DHCP proxy
    # Note: This test requires a DHCP server to be running on dummy0
    # In a real environment, this would test the actual DHCP metric functionality
    
    # Skip if no DHCP server is available
    if ! command -v dnsmasq >/dev/null 2>&1; then
        skip "dnsmasq not available for DHCP testing"
    fi
    
    # Setup a simple DHCP server on dummy0
    run_in_host_netns dnsmasq --interface=dummy0 --dhcp-range=10.89.0.10,10.89.0.100,255.255.255.0 --dhcp-option=3,10.89.0.1 &
    DHCP_PID=$!
    
    # Wait for DHCP server to start
    sleep 2
    
    run_netavark --file ${TESTSDIR}/testfiles/metric-macvlan-dhcp.json setup $(get_container_netns_path)

    run_in_container_netns ip -j route list match 0.0.0.0
    default_route="$output"
    assert_json "$default_route" '.[0].dst' == "default" "Default route was selected"
    assert_json "$default_route" '.[0].metric' == "200" "Route metric set from config with DHCP"

    # Cleanup
    kill $DHCP_PID 2>/dev/null || true
}
