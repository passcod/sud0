#!/bin/sh
# Build gate for every supported sud0 build entrypoint (make all/release/check).
#
# sud0's unsafe-code proofs are made against the exact stable toolchain and the
# x86_64-unknown-linux-gnu target this gate enforces. Direct cargo invocations
# that bypass this gate are not a supported route to shippable artifacts.
# rust-toolchain.toml selects a default toolchain but cannot enforce this:
# callers can override it with Cargo/Rustup options and environment variables.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

TARGET=x86_64-unknown-linux-gnu

fail() {
    printf 'ensure-build: %s\n' "$1" >&2
    exit 1
}

[ -z "${RUSTC_BOOTSTRAP:-}" ] ||
    fail 'RUSTC_BOOTSTRAP is set; the supported route uses the stable channel only'

check_rustflags() {
    name=$1
    value=$2
    case $value in
    *rustix_use_libc* | *rustix_no_linux_raw*)
        fail "$name selects a rejected rustix libc-backend cfg"
        ;;
    *-Z*)
        fail "$name contains unstable rustc flags"
        ;;
    *build-std*)
        fail "$name selects a custom standard library"
        ;;
    esac
}

check_rustflags RUSTFLAGS "${RUSTFLAGS:-}"
check_rustflags CARGO_ENCODED_RUSTFLAGS "${CARGO_ENCODED_RUSTFLAGS:-}"
check_rustflags RUSTFLAGS_x86_64_unknown_linux_gnu "${RUSTFLAGS_x86_64_unknown_linux_gnu:-}"
check_rustflags CARGO_ENCODED_RUSTFLAGS_x86_64_unknown_linux_gnu \
    "${CARGO_ENCODED_RUSTFLAGS_x86_64_unknown_linux_gnu:-}"

version=$(rustc --version)
release=${version#rustc }
release=${release%% *}
case $release in
*-*) fail "compiler channel is not stable: rustc $release" ;;
esac

host=$(rustc --version --verbose | sed -n 's/^host: //p')
[ "$host" = "$TARGET" ] || fail "build host $host is not $TARGET"

# Cargo feature unification, not sud0's direct feature list, decides the rustix
# backend; inspect the complete resolved graph and reject the libc backend.
if cargo tree --locked --target "$TARGET" -e features -i rustix 2>/dev/null |
    grep -q 'feature "use-libc"'; then
    fail 'resolved dependency graph enables the rustix use-libc feature (libc backend)'
fi
