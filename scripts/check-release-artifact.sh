#!/bin/sh
# Verifies that the release binaries are the exact artifacts a previous
# `make release` recorded, and that the toolchain, lockfile, and source state
# recorded in the stamp still match the current tree.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

TARGET=x86_64-unknown-linux-gnu
RELEASE_DIR=target/$TARGET/release
STAMP=target/sud0-release.stamp

fail() {
    printf 'check-release-artifact: %s\n' "$1" >&2
    exit 1
}

[ -f "$STAMP" ] || fail "missing $STAMP; run make release"

expected() {
    value=$(sed -n "s/^$1 //p" "$STAMP")
    [ -n "$value" ] || fail "stamp is missing the $1 line"
    printf '%s\n' "$value"
}

[ "$(expected target)" = "$TARGET" ] || fail "stamp records a different target"

current_rustc=$(rustc --version | sed 's/^rustc //')
[ "$(expected rustc)" = "$current_rustc" ] ||
    fail 'toolchain changed since the release build; run make release'

[ "$(expected source)" = "$(git rev-parse HEAD)" ] ||
    fail 'source revision changed since the release build; run make release'

current_state=$({ git rev-parse HEAD; git status --porcelain; } | sha256sum |
    cut -d ' ' -f1)
[ "$(expected state)" = "$current_state" ] ||
    fail 'working-tree state changed since the release build; run make release'

[ "$(expected lock)" = "$(sha256sum Cargo.lock | cut -d ' ' -f1)" ] ||
    fail 'Cargo.lock changed since the release build; run make release'

for binary in sud0 sud0-broker sud0-exec; do
    recorded=$(sed -n "s/^binary $binary //p" "$STAMP")
    [ -n "$recorded" ] || fail "stamp is missing the $binary digest"
    [ -f "$RELEASE_DIR/$binary" ] || fail "$RELEASE_DIR/$binary is missing"
    actual=$(sha256sum "$RELEASE_DIR/$binary" | cut -d ' ' -f1)
    [ "$actual" = "$recorded" ] ||
        fail "$binary differs from the recorded release artifact; run make release"
done
