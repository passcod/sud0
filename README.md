# sud0

`sud0` runs a command as root after polkit authorization.
It uses an unprivileged client, a root system-bus broker, and a fixed executor instead of a setuid binary.
Command output is not tinted or decorated.

> [!WARNING]
> This repository is pre-release software.
> The live privileged installation and end-to-end security validation described in the implementation plan have not yet been performed.

## Examples

```console
$ sud0 id
$ sud0 -d 'editing the SSH config' /usr/bin/nvim /etc/ssh/sshd_config
$ sud0 -D /var/lib/my-service --pipe /usr/bin/find . -maxdepth 1
$ sud0 --setenv TERM --pty /usr/bin/bash
$ sud0 -v
```

For the editor example, the authentication agent receives prompt text shaped like:

```text
Authentication is required to run as root:
editing the SSH config
$'/usr/bin/nvim' $'/etc/ssh/sshd_config'
in $'/home/alice'
```

The agent may surround that detail with its own UI.
Without `-d`, the description line is omitted.
The broker derives the displayed cwd from the received directory descriptor; environment overrides are represented by a count only when present, and the request digest appears only when a displayed command or cwd is truncated.
The root-owned `/etc/sud0/prompt.template` can customize presentation with the documented placeholders in [SECURITY.md](SECURITY.md); an unprivileged request cannot choose or alter it.
Arguments, descriptions, paths, and environment values can contain secrets; see [Privacy](#privacy).

Options must precede the command.
After the command begins, remaining words are command arguments even when they start with `-`; use `--` when the command name itself begins with `-`.
With no command, sud0 executes `/bin/bash` directly as root.
It does not evaluate a shell command string or support alternate users.

## Authorization

The single `nz.passcod.sud0.run` action means permission to run arbitrary root commands.
Active local sessions use polkit's native `auth_admin_keep` retention, normally about five minutes, not ten.
Inactive and other-session subjects require administrator authentication each time.
The retained grant is scoped to the action and equivalent subject, not command details, so a later command can differ from the command that caused the prompt.
`sud0 -v` validates or refreshes that same authorization without running a command.
`-n` (also `--no-ask-password`) permits a retained or otherwise non-interactive authorization but forbids a new interactive challenge.

When interaction is permitted, the client registers `/usr/bin/pkttyagent --fallback` for terminal-only sessions.
An already-running desktop agent remains preferred.

## Working directory, I/O, and environment

By default the client opens its current directory before authorization and the command enters that directory through the descriptor.
This preserves the directory object even if its pathname is renamed or replaced while authentication is pending.
`-D PATH` opens a different directory before authorization; relative paths are resolved from the caller's current directory.

A PTY is selected automatically only when stdin, stdout, and stderr are terminals; otherwise streams are connected directly in pipe mode.
`--pty` and `--pipe` override that choice.
PTY mode forwards bytes and window-size changes and restores the local terminal on exit.
Pipe mode preserves binary streams and does not allocate a terminal.

The root environment always starts with:

```text
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
HOME=/root
USER=root
LOGNAME=root
SHELL=/bin/bash
```

`--setenv NAME=VALUE` adds an explicit value.
`--setenv NAME` imports that name from the client's environment.
The option is repeatable, but baseline, activation, and security-sensitive runtime-control names are rejected; see [SECURITY.md](SECURITY.md).
Bare command names are searched only on the fixed root `PATH`; a command containing `/` is executed as the supplied pathname.

## Architecture

`/usr/bin/sud0` serializes a bounded, byte-preserving request and sends it with the opened cwd and standard-I/O descriptors over the system bus.
The root `/usr/lib/sud0/sud0-broker` derives the caller from D-Bus credentials, freezes the request, obtains polkit authorization, rechecks caller ownership, seals the request in a memfd, and asks systemd to start a transient service.
The transient service runs only `/usr/lib/sud0/sud0-exec`, which revalidates the request and descriptors and directly executes argv.

The three binaries are ordinary mode-0755 files; none is setuid or setgid.
The broker's hardening applies only to the long-lived broker service.
Arbitrary target commands run as separate transient services and do not inherit that hardening.
The [D-Bus API documentation](docs/dbus-api.md) describes the internal wire boundary.

## Requirements

- Linux 5.9 or newer, for fail-closed `close_range(..., CLOSE_RANGE_UNSHARE)` descriptor cleanup;
- systemd 257 or newer, for transient-service extra file descriptors;
- polkit with `/usr/bin/pkttyagent`;
- `/bin/bash`; and
- Rust 1.89 or newer to build the current locked dependency graph.

Rust 1.89 is the oldest compiler used successfully for the current source and lockfile; Rust 1.88 is rejected by that dependency graph.
The project currently targets Arch Linux and conventional `/usr` paths.

## Build and install

Build and check as an unprivileged user:

```console
$ make release
$ make check
```

Install the already-built release binaries and assets with privilege only for the filesystem write:

```console
$ run0 make install
$ systemctl daemon-reload
```

D-Bus starts `sud0-broker.service` on demand, so there is no service to enable.
Do not run `make release` or `make check` as root.
`PREFIX` defaults to and must remain `/usr` because the broker, executor, and service paths are security-critical constants.
Packagers can relocate that fixed filesystem tree with `DESTDIR` without privilege:

```console
$ make DESTDIR="$pkgdir" PREFIX=/usr install
```

To uninstall the known files:

```console
$ run0 make uninstall
$ systemctl daemon-reload
```

Neither target invokes `systemctl`, `run0`, or the installed program.
Uninstall removes only packaged files and removes project-specific directories only when empty.
An Arch VCS recipe is available at [`packaging/arch/PKGBUILD`](packaging/arch/PKGBUILD); it follows the current default branch and therefore deliberately uses a skipped VCS checksum rather than pretending an untagged release tarball exists.

## Troubleshooting

- `Failed to connect to system bus`: confirm the system D-Bus service is running and the activation and policy files are installed under `/usr/share/dbus-1`.
- `Failed to register authentication agent`: install polkit and verify `/usr/bin/pkttyagent`; a desktop agent may still satisfy the request.
- Authorization fails without a prompt under `-n`: run without `-n` or authorize first with `sud0 -v`.
- Broker startup or transient-unit failures: inspect `systemctl status sud0-broker.service` and `journalctl -u sud0-broker.service`.
- A bare command is not found: use an absolute pathname or install it in the fixed root `PATH`.
- PTY selection is unsuitable for a pipeline or redirected stream: pass `--pty` or `--pipe` explicitly.

The broker is D-Bus activated; `systemctl enable sud0-broker.service` is neither needed nor supported because the unit has no `[Install]` section.

## Privacy

The default authentication prompt discloses escaped argv, the broker-derived cwd, and an optional description; it adds an environment-override count and truncation digest only when applicable.
A custom root-owned template can disclose explicit environment values, cwd identity, or an unconditional digest.
A verbose local polkit configuration may log the rendered details.
Do not put secrets in command arguments, `--setenv`, paths, or `-d` unless that disclosure is acceptable.
Normal broker logs and transient-unit names do not contain argv or descriptions, and sud0 does not log command output.

See [SECURITY.md](SECURITY.md) for the threat model and vulnerability-reporting route.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.
