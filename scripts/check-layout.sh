#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

make -C "$repo" DESTDIR="$stage" PREFIX=/usr install >/dev/null

expected=$(cat <<'FILES'
644 etc/sud0/prompt.template
644 usr/lib/systemd/system/sud0-broker.service
644 usr/share/dbus-1/system-services/nz.passcod.sud0.service
644 usr/share/dbus-1/system.d/nz.passcod.sud0.conf
644 usr/share/doc/sud0/README.md
644 usr/share/doc/sud0/SECURITY.md
644 usr/share/doc/sud0/dbus-api.md
644 usr/share/doc/sud0/dbus-api.xml
644 usr/share/licenses/sud0/LICENSE-APACHE
644 usr/share/licenses/sud0/LICENSE-MIT
644 usr/share/man/man1/sud0.1
644 usr/share/polkit-1/actions/nz.passcod.sud0.policy
755 usr/bin/sud0
755 usr/lib/sud0/sud0-broker
755 usr/lib/sud0/sud0-exec
FILES
)
actual=$(find "$stage" -type f -printf '%m %P\n' | LC_ALL=C sort)
if [ "$actual" != "$expected" ]; then
    printf '%s\n' 'staged layout differs from expected:' >&2
    printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
    exit 1
fi
if find "$stage" -type f -perm /6000 | grep -q .; then
    printf '%s\n' 'staged files contain setuid or setgid bits' >&2
    exit 1
fi

make -C "$repo" DESTDIR="$stage" PREFIX=/usr uninstall >/dev/null
if find "$stage" -type f | grep -q .; then
    printf '%s\n' 'uninstall left packaged files behind' >&2
    find "$stage" -type f -printf '%P\n' >&2
    exit 1
fi
