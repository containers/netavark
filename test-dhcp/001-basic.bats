#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

# One might think this is a NOP and does nothing, so do I. But apparently
# something really weird is going with that in CI. If we delete this file
# the basic setup test will fail in CI. No idea why and I tried for to
# long to make any sense of this.
@test "NOP setup" {
    :
}
