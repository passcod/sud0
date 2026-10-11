# sud0

## Purpose

`sud0` provides a root-only command runner for Arch Linux systems using systemd and polkit.
It preserves the useful process isolation and terminal behavior of `run0`, omits terminal tinting, shows the requested command in the authentication dialog, and uses polkit's native retained authorization.

The installed polkit implementation retains `auth_admin_keep` grants for five minutes.
`sud0` uses that native interval and does not implement a separate authorization cache.

## Trust model

The installation consists of three non-setuid Rust binaries:

- `/usr/bin/sud0` is an unprivileged command-line client and terminal forwarder.
- `/usr/lib/sud0/sud0-broker` is a root system D-Bus service that validates requests, derives caller identity from D-Bus transport credentials, asks polkit to authorize the actual caller, and creates transient services.
- `/usr/lib/sud0/sud0-exec` is the only executable launched by those transient services. It decodes a sealed request and directly executes the requested command.

The broker supplies trusted prompt details because polkit rejects details from ordinary callers to prevent authentication-dialog spoofing.
The client MUST NOT nominate the polkit subject, caller UID, caller PID, unit name, executable helper, or transient-unit properties.
The broker MUST derive caller identity from authenticated transport metadata.

The dedicated `io.github.passcod.sud0.run` action represents permission to run arbitrary root commands through `sud0`.
Its active-session default is `auth_admin_keep`; inactive and other-session defaults are `auth_admin`.
Polkit's retained grant is keyed by action and subject equivalence, not by command details, so commands after the first challenge may differ during the retained window.

## Request and prompt binding

Command arguments, working-directory display text, and environment values are Unix byte strings.
The protocol MUST preserve non-UTF-8 values and MUST reject embedded NUL bytes.
The broker MUST apply explicit count and byte limits before authorization and before allocation during decoding.
The working-directory descriptor, not its display text, is the authority used for execution.

The broker freezes every accepted request before authorization.
The polkit prompt and executor payload MUST be derived from that same immutable request.
The broker MUST NOT parse prompt text or reread mutable client request data after authorization.

The command shown to the user is a deterministic shell-escaped representation of argv.
The display formatter MUST render controls, escape bytes, newlines, bidi controls, invalid UTF-8, and markup-significant input without embedding unsafe literal characters.
Long displays MUST be truncated at defined boundaries and identify the complete request with a digest.
Prompt text is descriptive; execution always uses structured argv without a shell.

The client accepts `-d/--description TEXT` for human context.
A described challenge has the form `Authentication is required to run a command as root for: <description> (<escaped argv>)`.
The broker MUST sanitize and bound the UTF-8 description independently from argv.
The description MUST NOT influence policy, request identity, execution, transient-unit metadata, or logs.
Without a description, the challenged prompt shows the escaped argv alone.

Command-line arguments and descriptions can contain secrets.
The authentication agent receives the displayed text, and a locally configured verbose polkit daemon may record request details.

## Execution transaction

For every request, the client opens the invoking working directory before authorization and passes that directory descriptor to the broker.
`-D/--chdir` instead opens the requested target before authorization.
This preserves the invoking directory by default and binds execution to the opened object even if its pathname is subsequently renamed or replaced.

For every request, the broker:

1. Copies request bytes and the opened working-directory descriptor into broker-owned state.
2. Validates structure, limits, NUL exclusion, environment names, option combinations, and the directory descriptor.
3. Freezes the request and creates its prompt rendering.
4. Calls PolicyKit1 for the actual caller and `io.github.passcod.sud0.run`.
5. Stops without creating a service on denial, dismissal, cancellation, malformed input, or caller disappearance.
6. Rechecks that the originating system-bus name is still owned.
7. Encodes the same frozen execution request in a memfd and seals it against writes, growth, shrinkage, and further seal changes.
8. Allocates a PTY when requested, or duplicates the caller's standard descriptors for pipe mode.
9. Calls systemd's `StartTransientUnit` directly.
10. Starts only `/usr/lib/sud0/sud0-exec`, passing the sealed request and opened working directory as two fixed, named extra descriptors.
11. Tracks startup, exit status, signals, ownership, cancellation, and cleanup.

The broker MUST NOT invoke `systemd-run`, accept arbitrary systemd properties, or include argv in unit names, descriptions, or normal diagnostics.
Invocation operations MUST be available only to the unique bus name that created them.
If that owner disappears, pending authorization MUST be cancelled and a launched transient command MUST be stopped.

The executor requires real, effective, and saved UID 0 and exactly the expected sealed-request and working-directory descriptors.
It verifies the request descriptor, seals, protocol, limits, and request digest again, and verifies that the working-directory descriptor refers to a directory.
It constructs a minimal root environment, changes directory with `fchdir` on the opened object, resolves bare commands only against a fixed root-safe `PATH`, closes unrelated descriptors, and directly executes argv.
It MUST NOT invoke a shell, expand variables, or interpret prompt quoting.

## Terminal behavior

The client selects PTY mode when stdin, stdout, and stderr are terminals and selects pipe mode otherwise, unless explicitly overridden.
Authorization completes before the client changes its terminal to raw mode, allowing the authentication agent to use the terminal normally.

In PTY mode, the broker allocates a fresh PTY after authorization and passes its slave to the transient service.
The client receives the master only after successful startup, forwards bytes transparently, propagates window dimensions, preserves foreground signal behavior, and restores terminal attributes on all exits.

`sud0` MUST NOT emit terminal background tinting, SGR decoration, OSC titles, shell prompt prefixes, or command-output logs.
Pipe mode MUST preserve binary streams without allocating a PTY.

When interaction is allowed, the client registers `/usr/bin/pkttyagent --fallback` for its system-bus identity so terminal-only sessions work while an existing desktop authentication agent remains preferred.

## Initial command-line interface

The initial interface is:

```text
sud0 [OPTIONS] [--] COMMAND [ARGUMENT…]
```

It supports:

- `-d, --description TEXT`
- `-D, --chdir PATH`
- repeatable `--setenv NAME[=VALUE]`
- `--pty`
- `--pipe`
- `-n, --non-interactive` and `--no-ask-password`
- `-v, --validate`
- `-h, --help`
- `-V, --version`

With no command, `sud0` starts a documented fixed root shell and includes its resolved argv in the prompt.
The initial version does not support alternate users or groups, shell evaluation, arbitrary transient-unit settings, background or disowned units, remotes, containers, custom tinting, or custom authorization durations.

## Installation

The Arch package installs:

- `/usr/bin/sud0`
- `/usr/lib/sud0/sud0-broker`
- `/usr/lib/sud0/sud0-exec`
- the dedicated polkit action
- system-bus ownership, call-policy, and activation files
- a hardened `sud0-broker.service`
- documentation and a manual page

Trusted files MUST be root-owned and MUST NOT be writable by ordinary users.
No installed file uses setuid or setgid mode.
The broker service is restricted to the filesystem, AF_UNIX, PTY, D-Bus, descriptor, and transient-unit operations its role requires.
Systems without the required systemd and polkit interfaces fail closed.

The project also provides a `DESTDIR` installation path, an Arch `PKGBUILD`, and a committed `Cargo.lock` with fully pinned direct dependency versions.
