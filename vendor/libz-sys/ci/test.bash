#!/usr/bin/env bash
# Script for building your rust projects.
set -e

required_arg() {
    if [ -z "$1" ]; then
        echo "Required argument $2 missing"
        exit 1
    fi
}

# $1 {path} = Path to cross/cargo executable
CROSS=$1
# $2 {string} = <Target Triple>
TARGET_TRIPLE=$2

required_arg $CROSS 'CROSS'
required_arg $TARGET_TRIPLE '<Target Triple>'

if [ "${TARGET_TRIPLE%-windows-gnu}" != "$TARGET_TRIPLE" ]; then
    # On windows-gnu targets, we need to set the PATH to include MinGW
    if [ "${TARGET_TRIPLE#x86_64-}" != "$TARGET_TRIPLE" ]; then
        PATH=/c/msys64/mingw64/bin:/c/msys64/usr/bin:$PATH
    elif [ "${TARGET_TRIPLE#i?86-}" != "$TARGET_TRIPLE" ]; then
        PATH=/c/msys64/mingw32/bin:/c/msys64/usr/bin:$PATH
    else
        echo Unknown windows-gnu target
        exit 1
    fi
fi

$CROSS test --target $TARGET_TRIPLE
$CROSS run --target $TARGET_TRIPLE --manifest-path systest/Cargo.toml
echo === zlib-ng build ===
$CROSS test --target $TARGET_TRIPLE --no-default-features --features zlib-ng
$CROSS run --target $TARGET_TRIPLE --manifest-path systest/Cargo.toml  --no-default-features --features zlib-ng
