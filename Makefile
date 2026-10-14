.DEFAULT_GOAL := all

CARGO ?= cargo
INSTALL ?= install
PREFIX ?= /usr

# The only supported target for shippable artifacts; enforced by the build gate
# and by a compile-time guard in src/lib.rs.
TARGET := x86_64-unknown-linux-gnu
RELEASE_DIR := target/$(TARGET)/release
RELEASE_STAMP := target/sud0-release.stamp

BINDIR := $(DESTDIR)$(PREFIX)/bin
LIBEXECDIR := $(DESTDIR)$(PREFIX)/lib/sud0
DATADIR := $(DESTDIR)$(PREFIX)/share
SYSTEMDUNITDIR := $(DESTDIR)$(PREFIX)/lib/systemd/system

.PHONY: all release check install uninstall ensure-unprivileged ensure-prefix ensure-build ensure-release

ensure-unprivileged:
	@test "$$(id -u)" -ne 0 || { echo 'refusing to build or run checks as root' >&2; exit 1; }

ensure-prefix:
	@test "$(PREFIX)" = /usr || { echo 'PREFIX must be /usr because runtime paths are fixed' >&2; exit 1; }

# The checked entrypoint shared by every build route: validates the compiler
# channel and host, rejects compiler and rustix backend overrides, and proves
# the resolved rustix backend is linux_raw. See scripts/ensure-build.sh.
ensure-build:
	./scripts/ensure-build.sh

ensure-release:
	./scripts/check-release-artifact.sh

all: ensure-unprivileged ensure-build
	$(CARGO) build --locked --target $(TARGET)

# SUD0_SOURCE_IDENTITY declares the source identity for release builds from
# an extracted source archive with no git metadata; the stamp script records
# it instead of the commit and working-tree state.
release: ensure-unprivileged ensure-build
	$(CARGO) build --release --locked --bins --target $(TARGET)
	SUD0_SOURCE_IDENTITY="$(SUD0_SOURCE_IDENTITY)" ./scripts/release-stamp.sh

# Tests and clippy run in the release profile so the checked tree shares one
# compilation with the shippable artifacts and the pre-ship check exercises
# the profile that ships (clippy lints with debug_assertions off, matching
# release codegen). Local dev-profile testing stays available via
# `cargo test` directly.
check: ensure-unprivileged ensure-build
	$(CARGO) fmt -- --check
	$(CARGO) test --release --locked --all-targets --target $(TARGET)
	$(CARGO) clippy --release --locked --all-targets --target $(TARGET) -- -D warnings
	$(MAKE) release
	./scripts/check-dist.sh

install: ensure-prefix ensure-release
	$(INSTALL) -Dm755 $(RELEASE_DIR)/sud0 "$(BINDIR)/sud0"
	$(INSTALL) -Dm755 $(RELEASE_DIR)/sud0-broker "$(LIBEXECDIR)/sud0-broker"
	$(INSTALL) -Dm755 $(RELEASE_DIR)/sud0-exec "$(LIBEXECDIR)/sud0-exec"
	$(INSTALL) -Dm644 dist/prompt.template "$(DESTDIR)/etc/sud0/prompt.template"
	$(INSTALL) -Dm644 dist/polkit/nz.passcod.sud0.policy "$(DATADIR)/polkit-1/actions/nz.passcod.sud0.policy"
	$(INSTALL) -Dm644 dist/dbus-1/system.d/nz.passcod.sud0.conf "$(DATADIR)/dbus-1/system.d/nz.passcod.sud0.conf"
	$(INSTALL) -Dm644 dist/dbus-1/system-services/nz.passcod.sud0.service "$(DATADIR)/dbus-1/system-services/nz.passcod.sud0.service"
	$(INSTALL) -Dm644 dist/systemd/system/sud0-broker.service "$(SYSTEMDUNITDIR)/sud0-broker.service"
	$(INSTALL) -Dm644 LICENSE-MIT "$(DATADIR)/licenses/sud0/LICENSE-MIT"
	$(INSTALL) -Dm644 LICENSE-APACHE "$(DATADIR)/licenses/sud0/LICENSE-APACHE"

uninstall: ensure-prefix
	rm -f -- "$(BINDIR)/sud0"
	rm -f -- "$(LIBEXECDIR)/sud0-broker" "$(LIBEXECDIR)/sud0-exec"
	rm -f -- "$(DESTDIR)/etc/sud0/prompt.template"
	rm -f -- "$(DATADIR)/polkit-1/actions/nz.passcod.sud0.policy"
	rm -f -- "$(DATADIR)/dbus-1/system.d/nz.passcod.sud0.conf"
	rm -f -- "$(DATADIR)/dbus-1/system-services/nz.passcod.sud0.service"
	rm -f -- "$(SYSTEMDUNITDIR)/sud0-broker.service"
	rm -f -- "$(DATADIR)/licenses/sud0/LICENSE-MIT" "$(DATADIR)/licenses/sud0/LICENSE-APACHE"
	rmdir --ignore-fail-on-non-empty -- "$(DESTDIR)/etc/sud0" $(LIBEXECDIR) "$(DATADIR)/licenses/sud0" 2>/dev/null || true
