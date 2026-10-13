#!/bin/sh
# Records the identity of the release artifacts in target/sud0-release.stamp
# after `make release` builds them.
#
# In a git checkout the identity is the commit plus the exact working-tree
# state. A release build from an extracted source archive has no git
# metadata; the caller must instead declare the archive identity in
# SUD0_SOURCE_IDENTITY (the packager's checksum pins the content).
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

TARGET=x86_64-unknown-linux-gnu
RELEASE_DIR=target/$TARGET/release
STAMP=target/sud0-release.stamp

fail() {
    printf 'release-stamp: %s\n' "$1" >&2
    exit 1
}

for binary in sud0 sud0-broker sud0-exec; do
    [ -f "$RELEASE_DIR/$binary" ] || fail "$RELEASE_DIR/$binary is missing"
done

if [ -n "${SUD0_SOURCE_IDENTITY:-}" ]; then
    source_line="identity $SUD0_SOURCE_IDENTITY"
    state_line="state none"
elif git rev-parse HEAD >/dev/null 2>&1; then
    source_line="commit $(git rev-parse HEAD)"
    state_line="state $({ git rev-parse HEAD; git status --porcelain; } |
        sha256sum | cut -d ' ' -f1)"
else
    fail 'no git checkout and no SUD0_SOURCE_IDENTITY declared'
fi

{
    printf 'target %s\n' "$TARGET"
    printf 'rustc %s\n' "$(rustc --version | sed 's/^rustc //')"
    printf 'source %s\n' "$source_line"
    printf '%s\n' "$state_line"
    printf 'lock %s\n' "$(sha256sum Cargo.lock | cut -d ' ' -f1)"
    for binary in sud0 sud0-broker sud0-exec; do
        printf 'binary %s %s\n' "$binary" \
            "$(sha256sum "$RELEASE_DIR/$binary" | cut -d ' ' -f1)"
    done
} >"$STAMP"

printf 'release identity recorded in %s\n' "$STAMP"
