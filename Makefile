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

.PHONY: all release check install uninstall ensure-unprivileged ensure-prefix ensure-build ensure-committed ensure-release

ensure-unprivileged:
	@test "$$(id -u)" -ne 0 || { echo 'refusing to build or run checks as root' >&2; exit 1; }

ensure-prefix:
	@test "$(PREFIX)" = /usr || { echo 'PREFIX must be /usr because runtime paths are fixed' >&2; exit 1; }

# The checked entrypoint shared by every build route: validates the compiler
# channel and host, rejects compiler and rustix backend overrides, and proves
# the resolved rustix backend is linux_raw. See scripts/ensure-build.sh.
ensure-build:
	./scripts/ensure-build.sh

# Release artifacts must trace to an identified source state: the commit plus
# the exact working-tree diff recorded in the stamp.
ensure-committed:
	@test -n "$$(git rev-parse HEAD)" || { echo 'not a git repository' >&2; exit 1; }

ensure-release:
	./scripts/check-release-artifact.sh

all: ensure-unprivileged ensure-build
	$(CARGO) build --locked --target $(TARGET)

release: ensure-unprivileged ensure-build ensure-committed
	$(CARGO) build --release --locked --bins --target $(TARGET)
	@{ \
		printf 'target %s\n' '$(TARGET)'; \
		printf 'rustc %s\n' "$$(rustc --version | sed 's/^rustc //')"; \
		printf 'source %s\n' "$$(git rev-parse HEAD)"; \
		printf 'state %s\n' "$$({ git rev-parse HEAD; git status --porcelain; } | sha256sum | cut -d ' ' -f1)"; \
		printf 'lock %s\n' "$$(sha256sum Cargo.lock | cut -d ' ' -f1)"; \
		for binary in sud0 sud0-broker sud0-exec; do \
			printf 'binary %s %s\n' "$$binary" "$$(sha256sum $(RELEASE_DIR)/$$binary | cut -d ' ' -f1)"; \
		done; \
	} > $(RELEASE_STAMP)
	@echo 'release identity recorded in $(RELEASE_STAMP)'

check: ensure-unprivileged ensure-build
	$(CARGO) fmt -- --check
	$(CARGO) test --locked --all-targets --target $(TARGET)
	$(CARGO) clippy --locked --all-targets --target $(TARGET) -- -D warnings
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
