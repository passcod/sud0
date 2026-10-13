# Deployment contract

The runtime assumptions every sud0 deployment must satisfy. These are
deployment requirements for the installed binaries, not properties the Rust
source can prove; the privileged-executor safety proofs assume them.

## Minimum platform

- Linux with `close_range(2)` including `CLOSE_RANGE_UNSHARE` (5.9+),
  memfd seals `F_ADD_SEALS`/`F_GET_SEALS` (5.1+ for `F_SEAL_WRITE`), and
  pidfds `pidfd_open(2)` (5.3+).
- systemd 257 or newer for the transient-service properties the broker
  sets (`ExtraFileDescriptors` with per-descriptor names,
  `StandardInputFileDescriptor`, `StandardOutputFileDescriptor`,
  `StandardErrorFileDescriptor`, `AddRef`, `CollectMode`) and for
  descriptor activation of `sud0-exec` from those stored descriptors.
- A mounted procfs at `/proc` with default visibility for the broker: the
  broker holds no capabilities, so a `hidepid=2`-equivalent procfs (e.g.
  `ProtectProc=invisible`) makes invoking-user process directories return
  `ENOENT` and breaks caller authentication. The shipped
  `sud0-broker.service` therefore does not set `ProtectProc`; administrators
  hardening the unit must keep the broker able to read `/proc/<pid>/stat`
  and `/proc/<pid>/status` of invoking-user processes, or replace those
  identity checks before re-enabling it.
- A system D-Bus daemon that supports `GetConnectionCredentials` with
  process-descriptor (pidfd) credentials for the broker's caller.
- polkit with `/usr/bin/pkttyagent` supporting `--fallback`,
  `--process=<pid>`, and `--notify-fd=<fd>` for terminal fallback
  authentication. The parent process of the invoking user must be alive and
  owned by the same uid at authorization time; the broker pins it with a
  pidfd and revalidates it against PID reuse and reparenting.

## Descriptor activation

The broker starts `sud0-exec` through systemd descriptor activation with
exactly two stored descriptors: 3 (`sud0-request`, a sealed request
memfd) and 4 (`sud0-cwd`, an `O_PATH` directory descriptor). The executor
validates `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES` before claiming
them; any other inherited descriptors are closed with
`CLOSE_RANGE_UNSHARE` starting at descriptor 5.

## Sandbox reconciliation

`sud0-broker.service` keeps `ProtectSystem=strict`,
`PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, an empty
`CapabilityBoundingSet=`, and `NoNewPrivileges=yes`. `ProtectProc` was
removed because the broker's authenticated caller checks read
`/proc/<pid>/stat` (parent pid) and `/proc/<pid>/status` (effective uid)
of invoking-user processes; the kernel gates those reads under
`hidepid=2` on `CAP_SYS_PTRACE` or a matching uid, and the empty
capability set removes the former. Granting `CAP_SYS_PTRACE` instead would
give the D-Bus-facing broker a broader capability (ptrace over every
process) than default procfs visibility provides, so the weaker but
sufficient default visibility is the documented contract.

## Provenance

The only supported route to shippable artifacts is `make release` (or
`make check`, which includes it), which enforces the stable toolchain,
the `x86_64-unknown-linux-gnu` target, and the rustix `linux_raw` backend,
and records the toolchain, source revision, working-tree state, lockfile
digest, and binary digests in `target/sud0-release.stamp`. `make install`
consumes artifacts only when that stamp still matches the current tree.
Direct `cargo` invocations that bypass the gate are development builds
only. The `-git` Arch package builds from a moving branch and is a
development artifact; release packages must pin an immutable source
identity and checksum (see `packaging/arch-release/`; a release build from
an extracted archive declares its source identity via
`SUD0_SOURCE_IDENTITY` instead of git metadata).
