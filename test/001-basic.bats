#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "netavark version" {
    run_netavark --version
    assert "$output" =~ "netavark 1\.[0-9]+\.[0-9]+(-rc|-dev)?" "expected version"

    run_netavark version
    json="$output"
    assert_json "$json" ".version" =~ "^1\.[0-9]+\.[0-9]+(-rc[0-9]|-dev)?" "correct version"
    assert_json "$json" ".commit" =~ "[0-9a-f]{40}" "shows commit sha"
    assert_json "$json" ".build_time" =~ "20.*" "show build date"
    assert_json "$json" ".target" =~ ".*" "contains target string"
}

@test "netavark error - invalid ns path" {
    expected_rc=1 run_netavark -f ${TESTSDIR}/testfiles/simplebridge.json setup /test/1
    assert_json ".error" "invalid namespace path: IO error: No such file or directory (os error 2)" "Namespace path does not exists"
}

@test "netavark error - invalid config path" {
    expected_rc=1 run_netavark -f /test/1 setup $(get_container_netns_path)
    assert_json ".error" "failed to load network options: IO error: No such file or directory (os error 2)" "Config file does not exists"
}
