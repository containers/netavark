#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "netavark version" {
    run_netavark --version
    assert "netavark 0.0.1" "expected version"
}

@test "netavark error - invalid ns path" {
    expected_rc=1 run_netavark -f ${TESTSDIR}/testfiles/simplebridge.json setup /test/1
    assert_json ".error" "invalid namespace path: No such file or directory (os error 2)" "Namespace path does not exists"
}

@test "netavark error - invalid config path" {
    expected_rc=1 run_netavark -f /test/1 setup $(get_container_netns_path)
    assert_json ".error" "failed to load network options: No such file or directory (os error 2)" "Config file does not exists"
}
