#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

# Validate policy and introspection XML against the locally installed grammars.
cat >"$scratch/catalog.xml" <<'EOF_CATALOG'
<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <system systemId="http://www.freedesktop.org/software/polkit/policyconfig-1.dtd" uri="/usr/share/polkit-1/policyconfig-1.dtd"/>
  <system systemId="http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd" uri="/usr/share/xml/dbus-1/introspect.dtd"/>
</catalog>
EOF_CATALOG
XML_CATALOG_FILES="$scratch/catalog.xml" xmllint --nonet --noout --valid \
    "$repo/dist/polkit/nz.passcod.sud0.policy"
XML_CATALOG_FILES="$scratch/catalog.xml" xmllint --nonet --noout --valid \
    "$repo/docs/dbus-api.xml"
xmllint --nonet --noout "$repo/dist/dbus-1/system.d/nz.passcod.sud0.conf"

# The installed busconfig DTD predates send_destination. Parse that modern
# attribute with the installed daemon in an otherwise complete throwaway config.
mkdir "$scratch/services"
cat >"$scratch/bus.conf" <<EOF_BUS
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=$scratch/bus</listen>
  <servicedir>$scratch/services</servicedir>
  <auth>EXTERNAL</auth>
  <include>$repo/dist/dbus-1/system.d/nz.passcod.sud0.conf</include>
</busconfig>
EOF_BUS
dbus-daemon --config-file="$scratch/bus.conf" --introspect >/dev/null

# Supply only dependencies needed for offline unit verification inside staging.
mkdir -p "$scratch/root/usr/lib/systemd/system" "$scratch/root/usr/lib/sud0"
cp "$repo/dist/systemd/system/sud0-broker.service" "$scratch/root/usr/lib/systemd/system/"
cp /usr/lib/systemd/system/dbus.socket "$scratch/root/usr/lib/systemd/system/"
cp "$repo/target/release/sud0-broker" "$scratch/root/usr/lib/sud0/"
mkdir -p "$scratch/root/etc/sud0"
cp "$repo/dist/prompt.template" "$scratch/root/etc/sud0/"
systemd-analyze verify --root="$scratch/root" --man=no --generators=no \
    --recursive-errors=no sud0-broker.service

"$repo/scripts/check-layout.sh"
