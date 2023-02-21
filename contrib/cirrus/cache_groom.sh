#!/bin/bash
#
# This script is intended to be run from Cirrus-CI to prepare the
# rust targets cache for re-use during subsequent runs.  This mainly
# involves removing files and directories which change frequently
# but are cheap/quick to regenerate - i.e. prevent "cache-flapping".
# Any other use of this script is not supported and may cause harm.
#
# WARNING: This script is re-used from $DEST_BRANCH by other
# repositories.  Namely aardvark-dns and possibly others.  Check
# before removing / changing / updating.

set -eo pipefail

source $(dirname ${BASH_SOURCE[0]})/lib.sh

if [[ "$CIRRUS_CI" != true ]]; then
  die "Script is not intended for use outside of Cirrus-CI"
fi

req_env_vars CARGO_HOME CARGO_TARGET_DIR CIRRUS_BUILD_ID

# Giant-meat-cleaver HACK: It's possible (with a long-running cache key) for
# the targets and/or cargo cache to grow without-bound (gigabytes). Ref:
# https://github.com/rust-lang/cargo/issues/5026
# There isn't a good way to deal with this or account for outdated content
# in some intelligent way w/o trolling through config and code files.  So,
# Any time the Cirrus-CI build ID is evenly divisible by some number (chosen
# arbitrarily) clobber the whole thing and make the next run entirely
# re-populate cache.  This is ugly, but maybe the best option available :(
if [[ "$CIRRUS_BRANCH" == "$DEST_BRANCH" ]] && ((CIRRUS_BUILD_ID%15==0)); then
  msg "It's a cache-clobber build, yay! This build has been randomly selected for"
  msg "a forced cache-wipe!  Congratulations! This means the next build will be"
  msg "slow, and nobody will know who to to blame!.  Lucky you!  Hurray!"
  msg "(This is necessary to prevent branch-level cache from infinitely growing)"
  cd $CARGO_TARGET_DIR
  # Could use `cargo clean` for this, but it's easier to just clobber everything.
  rm -rf ./* ./.??*
  # In case somebody goes poking around, leave a calling-card hopefully leading
  # them back to this script.  I don't know of a better way to handle this :S
  touch CACHE_WAS_CLOBBERED

  cd $CARGO_HOME
  rm -rf ./* ./.??*
  touch CACHE_WAS_CLOBBERED
  exit 0
fi

# The following applies to both PRs and branch-level cache.  It attempts to remove
# things which are non-essential and/or may change frequently.  It stops short of
# trolling through config & code files to determine what is relevant or not.
# Ref: https://doc.rust-lang.org/nightly/cargo/guide/build-cache.html
#      https://github.com/Swatinem/rust-cache/tree/master/src
cd $CARGO_TARGET_DIR
for targetname in $(find ./ -type d -maxdepth 1 -mindepth 1); do
  msg "Grooming $CARGO_TARGET_DIR/$targetname..."
  cd $CARGO_TARGET_DIR/$targetname
  # Any top-level hidden files or directories
  showrun rm -rf ./.??*
  # Example targets
  showrun rm -rf ./target/debug/examples
  # Documentation
  showrun rm -rf ./target/doc
  # Internal to rust build process
  showrun rm -rf ./target/debug/deps ./target/debug/incremental ./target/debug/build
done

# The following only applies to dependent packages (crates).  It follows recommendations
# Ref: https://doc.rust-lang.org/nightly/cargo/guide/cargo-home.html#caching-the-cargo-home-in-ci
# and probably shouldn't be extended beyond what's documented.  This cache plays a major
# role in built-time reduction, but must also be prevented from causing "cache-flapping".
cd $CARGO_HOME
for dirname in $(find ./ -type d -maxdepth 2 -mindepth 1); do
  case "$dirname" in
    ./bin) ;&  # same steps as next item
    ./registry/index) ;&
    ./registry/cache) ;&
    ./git/db) continue ;;  # Keep
    *) rm -rf $dirname ;;  # Remove
  esac
done
