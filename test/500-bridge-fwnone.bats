#!/usr/bin/env bats   -*- bats -*-
#
# bridge driver tests with none firewall driver
#

load helpers

fw_driver=none

@test "check none firewall driver is in use" {
    RUST_LOG=netavark=info NETAVARK_FW="none" run_netavark --file ${TESTSDIR}/testfiles/simplebridge.json setup $(get_container_netns_path)
    assert "${lines[0]}" "==" "[INFO  netavark::firewall] Not using firewall" "none firewall driver is in use"
}
