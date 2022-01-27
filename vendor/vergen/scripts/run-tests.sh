#!/bin/bash
set -ev

cargo clean

if [ "${TRAVIS_RUST_VERSION}" = "stable" ]; then
    cargo build
    cargo test
    cargo test --no-default-features --features build
    cargo test --no-default-features --features git
    cargo test --no-default-features --features rustc
    cargo test --no-default-features --features build,git
    cargo test --no-default-features --features build,rustc
    cargo test --no-default-features --features git,rustc
elif [ "${TRAVIS_RUST_VERSION}" = "beta" ]; then
    cargo build
    cargo test
    cargo test --no-default-features --features build
    cargo test --no-default-features --features git
    cargo test --no-default-features --features rustc
    cargo test --no-default-features --features build,git
    cargo test --no-default-features --features build,rustc
    cargo test --no-default-features --features git,rustc
else
    cargo build
    cargo test
    cargo test --no-default-features --features build
    cargo test --no-default-features --features git
    cargo test --no-default-features --features rustc
    cargo test --no-default-features --features build,git
    cargo test --no-default-features --features build,rustc
    cargo test --no-default-features --features git,rustc
fi
