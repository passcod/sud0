# Security policy

## Supported versions

Security fixes are provided for the latest released version and the current default branch.
Pre-release snapshots may change their D-Bus and frozen-request formats without compatibility guarantees.

## Reporting a vulnerability

Please use the repository's [private vulnerability reporting form](https://github.com/passcod/sud0/security/advisories/new) rather than a public issue.
Include the affected version or commit, expected security boundary, reproduction details, and impact where possible.

## Threat model and trusted computing base

`sud0` allows a local subject accepted by polkit to execute arbitrary commands as root.
It protects the boundary between an unprivileged D-Bus client and that root execution, not a system already controlled by root or by a compromised polkit, systemd, kernel, or authentication agent.
The trusted computing base includes the kernel, system D-Bus daemon, systemd system manager, polkit daemon and selected authentication agent, the root-owned sud0 broker and executor, and the root-owned files they load.

No sud0 file is setuid or setgid.
The installed broker, executor, policies, activation entry, and service unit must be owned by root and not writable by ordinary users.
The broker runs as root; the polkit action deliberately has no executable-owner annotation.

The system-bus policy allows only root to own `io.github.passcod.sud0`, while ordinary users may send calls to it.
For each call the broker derives the caller UID and unique bus name from authenticated D-Bus transport credentials.
The client cannot nominate its polkit subject, UID, PID, transient-unit properties, helper path, or unit name.
Dynamic invocation objects are bound to their creating unique bus name; owner loss cancels pending or running work.

Before authorization the broker copies and validates the request and takes ownership of the opened cwd descriptor.
After authorization it verifies that the bus owner still exists, places the same frozen request in a write/grow/shrink/seal-protected memfd, and passes that memfd and cwd descriptor to a fixed executor through systemd.
The executor rechecks root real/effective/saved UIDs, descriptor names and count, memfd seals, request digest and bounds, and the cwd descriptor type.
It changes directory through the descriptor, so pathname replacement does not redirect execution.

## Authorization and prompt disclosure

The `io.github.passcod.sud0.run` action authorizes arbitrary root command execution.
Its defaults require administrator authentication for any or inactive sessions and use `auth_admin_keep` for active sessions.
Polkit's native retained authorization is normally about five minutes; sud0 has no separate timer or cache.
Retention is keyed by action and equivalent subject, not by command details, so another command can reuse a retained grant.

The broker gives polkit a sanitized rendering of argv and the optional description.
Those values may contain secrets and are disclosed to the authentication agent; verbose local polkit logging may also record them.
Prompt text is presentation only and is never parsed for execution.

## Command resolution and environment

Commands run directly without shell parsing.
A command containing `/` is executed as that pathname.
A bare command is searched as root in `/usr/local/sbin:/usr/local/bin:/usr/bin`; administrators must therefore protect every directory and executable on that path because replacing one changes what root executes.
With no command, the fixed `/bin/bash` executable is used.

The executor constructs `PATH`, `HOME`, `USER`, `LOGNAME`, and `SHELL` itself.
Requested environment names are syntactically constrained, unique, bounded, and may not replace those values or activation variables.
It also rejects `IFS`, `ENV`, `BASH_ENV`, and loader, allocator, locale-conversion, Python, Perl, Ruby, Node, Java, Go, Rust compiler, rustdoc, and Cargo control-variable families.
This denylist reduces privileged-runtime injection but does not make arbitrary environment values safe for every possible target program; callers and administrators must understand the invoked program's own environment interface.

## Metadata and resource bounds

Normal broker diagnostics and transient unit names/descriptions contain neither argv nor descriptions.
Random identifiers are used for authorization and transient-unit correlation.
Requests cap aggregate data, element counts, individual argument and environment sizes, cwd text, and prompt rendering before root execution.
These bounds limit broker allocations but do not constrain the CPU, memory, filesystem, or device use of an authorized target command.
Target commands run in separate transient services and do not inherit the broker service's hardening directives.
