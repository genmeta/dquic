#!/usr/bin/env bash
set -euo pipefail
# Build a writable source snapshot; this library does not track Cargo.lock.
mkdir -p /tmp/traversal-source
tar --exclude=./target --exclude=./.git --exclude=./.codegraph -cf - . \
    | tar -xf - -C /tmp/traversal-source
cd /tmp/traversal-source
lock=()
if [[ -f Cargo.lock ]]; then lock=(--locked); fi
cargo test "${lock[@]}" -p qtraversal --lib --no-run --message-format=json \
    > /build/traversal-test-artifacts.json
sed -n 's/.*"executable":"\([^" ]*\)".*/\1/p' /build/traversal-test-artifacts.json \
    > /build/traversal-test-bin
test_bin=$(cat /build/traversal-test-bin)
[[ -x $test_bin ]]
"$test_bin"
