.DEFAULT_GOAL := all

CARGO ?= cargo
INSTALL ?= install
PREFIX ?= /usr
DESTDIR ?=

BINDIR := $(DESTDIR)$(PREFIX)/bin
LIBEXECDIR := $(DESTDIR)$(PREFIX)/lib/sud0
DATADIR := $(DESTDIR)$(PREFIX)/share
SYSTEMDUNITDIR := $(DESTDIR)$(PREFIX)/lib/systemd/system

.PHONY: all release check install uninstall ensure-unprivileged ensure-prefix

ensure-unprivileged:
	@test "$$(id -u)" -ne 0 || { echo 'refusing to build or run checks as root' >&2; exit 1; }

ensure-prefix:
	@test "$(PREFIX)" = /usr || { echo 'PREFIX must be /usr because runtime paths are fixed' >&2; exit 1; }

all: ensure-unprivileged
	$(CARGO) build --locked

release: ensure-unprivileged
	$(CARGO) build --release --locked --bins

check: ensure-unprivileged
	$(CARGO) fmt -- --check
	$(CARGO) test --locked --all-targets
	$(CARGO) clippy --locked --all-targets -- -D warnings
	$(CARGO) build --release --locked --bins
	./scripts/check-dist.sh

install: ensure-prefix
	@test -x target/release/sud0 || { echo 'target/release/sud0 is missing; run make release as an unprivileged user first' >&2; exit 1; }
	@test -x target/release/sud0-broker || { echo 'target/release/sud0-broker is missing; run make release as an unprivileged user first' >&2; exit 1; }
	@test -x target/release/sud0-exec || { echo 'target/release/sud0-exec is missing; run make release as an unprivileged user first' >&2; exit 1; }
	$(INSTALL) -Dm755 target/release/sud0 "$(BINDIR)/sud0"
	$(INSTALL) -Dm755 target/release/sud0-broker "$(LIBEXECDIR)/sud0-broker"
	$(INSTALL) -Dm755 target/release/sud0-exec "$(LIBEXECDIR)/sud0-exec"
	$(INSTALL) -Dm644 dist/prompt.template "$(DESTDIR)/etc/sud0/prompt.template"
	$(INSTALL) -Dm644 dist/polkit/nz.passcod.sud0.policy "$(DATADIR)/polkit-1/actions/nz.passcod.sud0.policy"
	$(INSTALL) -Dm644 dist/dbus-1/system.d/nz.passcod.sud0.conf "$(DATADIR)/dbus-1/system.d/nz.passcod.sud0.conf"
	$(INSTALL) -Dm644 dist/dbus-1/system-services/nz.passcod.sud0.service "$(DATADIR)/dbus-1/system-services/nz.passcod.sud0.service"
	$(INSTALL) -Dm644 dist/systemd/system/sud0-broker.service "$(SYSTEMDUNITDIR)/sud0-broker.service"
	$(INSTALL) -Dm644 docs/sud0.1 "$(DATADIR)/man/man1/sud0.1"
	$(INSTALL) -Dm644 LICENSE-MIT "$(DATADIR)/licenses/sud0/LICENSE-MIT"
	$(INSTALL) -Dm644 LICENSE-APACHE "$(DATADIR)/licenses/sud0/LICENSE-APACHE"
	$(INSTALL) -Dm644 README.md "$(DATADIR)/doc/sud0/README.md"
	$(INSTALL) -Dm644 SECURITY.md "$(DATADIR)/doc/sud0/SECURITY.md"
	$(INSTALL) -Dm644 docs/dbus-api.md "$(DATADIR)/doc/sud0/dbus-api.md"
	$(INSTALL) -Dm644 docs/dbus-api.xml "$(DATADIR)/doc/sud0/dbus-api.xml"

uninstall: ensure-prefix
	rm -f -- "$(BINDIR)/sud0"
	rm -f -- "$(LIBEXECDIR)/sud0-broker" "$(LIBEXECDIR)/sud0-exec"
	rm -f -- "$(DESTDIR)/etc/sud0/prompt.template"
	rm -f -- "$(DATADIR)/polkit-1/actions/nz.passcod.sud0.policy"
	rm -f -- "$(DATADIR)/dbus-1/system.d/nz.passcod.sud0.conf"
	rm -f -- "$(DATADIR)/dbus-1/system-services/nz.passcod.sud0.service"
	rm -f -- "$(SYSTEMDUNITDIR)/sud0-broker.service"
	rm -f -- "$(DATADIR)/man/man1/sud0.1"
	rm -f -- "$(DATADIR)/licenses/sud0/LICENSE-MIT" "$(DATADIR)/licenses/sud0/LICENSE-APACHE"
	rm -f -- "$(DATADIR)/doc/sud0/README.md" "$(DATADIR)/doc/sud0/SECURITY.md"
	rm -f -- "$(DATADIR)/doc/sud0/dbus-api.md" "$(DATADIR)/doc/sud0/dbus-api.xml"
	rmdir --ignore-fail-on-non-empty -- "$(DESTDIR)/etc/sud0" $(LIBEXECDIR) "$(DATADIR)/licenses/sud0" "$(DATADIR)/doc/sud0" 2>/dev/null || true
