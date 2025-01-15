#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with explicit modes
#

load helpers

# accepts the mode (managed/unmanaged) as first arg and
# as second arg the vlan id (int)
function createVlanConfig() {
    local mode=$1
    local vlan=$2

    read -r -d '\0' config <<EOF
{
  "container_id": "6ce776ea58b5",
  "container_name": "testcontainer",
  "networks": {
    "podman1": {
      "static_ips": [
        "10.88.0.2"
      ],
      "interface_name": "eth0"
    }
  },
  "network_info": {
    "podman1": {
      "name": "podman0",
      "id": "ed82e3a703682a9c09629d3cf45c1f1e7da5b32aeff3faf82837ef4d005356e6",
      "driver": "bridge",
      "network_interface": "podman0",
      "subnets": [
        {
          "gateway": "10.88.0.1",
          "subnet": "10.88.0.0/16"
        }
      ],
      "ipv6_enabled": true,
      "internal": false,
      "dns_enabled": false,
      "ipam_options": {
        "driver": "host-local"
      },
      "options": {
        "mode": "$mode",
        "vlan": "$vlan"
      }
    }
  }
}\0
EOF

echo "$config"
}

@test "bridge - vlan create bridge" {
    local vlan=20
    local config=$(createVlanConfig managed $vlan)

    run_netavark setup $(get_container_netns_path) <<<"$config"

    run_in_host_netns ip -j --details link show podman0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"
    assert_json "$link_info" '.[].linkinfo.info_data.vlan_filtering' == "1" "vlan_filtering enabled on the bridge"

    run_in_host_netns bridge -j vlan show
    vlan_info="$output"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[0].vlan' == "1" "default vlan 1 connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].vlan' == "$vlan" "vlan connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].flags' == '[
  "PVID",
  "Egress Untagged"
]' "vlan flags"

    run_netavark teardown $(get_container_netns_path) <<<"$config"
}

@test "bridge - vlan with existing bridge" {
    local vlan=99
    local config=$(createVlanConfig unmanaged $vlan)

    # pre create bridge in managed mode to ensure to code still enabled vlan_filtering
    run_in_host_netns ip link add podman0 type bridge
    run_in_host_netns ip link set up podman0

    run_netavark setup $(get_container_netns_path) <<<"$config"

    run_in_host_netns ip -j --details link show podman0
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' == "UP" "Host bridge interface is up"
    assert_json "$link_info" '.[].linkinfo.info_data.vlan_filtering' == "1" "vlan_filtering enabled on the bridge"

    run_in_host_netns bridge -j vlan show
    vlan_info="$output"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[0].vlan' == "1" "default vlan 1 connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].vlan' == "$vlan" "vlan connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].flags' == '[
  "PVID",
  "Egress Untagged"
]' "vlan flags"

    run_netavark teardown $(get_container_netns_path) <<<"$config"
}

@test "bridge - two vlan's on same bridge" {
    local vlan1=10
    local config1=$(createVlanConfig managed $vlan1)

    run_netavark setup $(get_container_netns_path) <<<"$config1"

    run_in_host_netns bridge -j vlan show
    vlan_info="$output"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[0].vlan' == "1" "default vlan 1 connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].vlan' == "$vlan1" "vlan1 connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].flags' == '[
  "PVID",
  "Egress Untagged"
]' "vlan flags"


    local vlan2=10
    local config2=$(createVlanConfig unmanaged $vlan2)
    create_container_ns

    run_netavark setup $(get_container_netns_path 1) <<<"$config2"

    # the second setup should have used veth1 as name

    run_in_host_netns bridge -j vlan show
    vlan_info="$output"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth0") | .vlans[1].vlan' == "$vlan1" "vlan1 connected"
    assert_json "$vlan_info" '.[] | select(.ifname=="veth1") | .vlans[1].vlan' == "$vlan2" "vlan2 connected"

    assert_json "$vlan_info" '.[] | select(.ifname=="veth1") | .vlans[1].flags' == '[
  "PVID",
  "Egress Untagged"
]' "vlan flags"

    run_netavark teardown $(get_container_netns_path) <<<"$config1"
    run_netavark teardown $(get_container_netns_path 1) <<<"$config2"
}
