# TCB audit log: sud0

This is the canonical trust log for sud0's unsafe-code proofs. Every
proposition the source-level safety proofs consume without deriving from
Rust-authoritative text is recorded here. It does not make assumptions
respectable; it makes the exact conditional theorems reviewable.

## Identity

- **Log ID:** sud0-tcb-1
- **Audit scope:** handwritten unsafe code, unsafe contracts, and
  proof-bearing safe-call boundaries in the sud0 crate, after the unsafe
  Rust remediation (see `docs/plans/unsafe-rust-remediation.md`).
- **Rust/toolchain scope:** stable channel only, selected at build time by
  the checked make entrypoint. At the time of writing: rustc 1.99.0
  (`b940084d7`, 2026-09-28), host and target `x86_64-unknown-linux-gnu`.
  Every stable toolchain update is a re-audit trigger for all entries
  marked `toolchain` below.
- **Target scope:** `x86_64-unknown-linux-gnu` only (enforced by the build
  gate and a `compile_error!` guard in `src/lib.rs`).
- **Dependency identity:** `Cargo.lock` at the audited source revision;
  the release stamp records the lockfile digest for each built artifact.
- **Owners/reviewers:** the sud0 maintainers.

## Trust policy

- Rust language and standard-library semantics are taken only from
  versioned Rust Reference and standard-library documentation for the
  selected stable release (AXIOM entries).
- Deliberately selected safe dependency APIs are trusted to behave as
  documented for the exact locked version and enabled features
  (SAFE-DEP entries).
- Third-party unsafe implementations consumed through safe wrappers are
  either audited to the relevant implementation fact (recorded here) or
  admitted explicitly (UNSAFE-DEP/EXTERNAL-SPEC entries).
- Kernel, libc, and platform behaviors are admitted as EXTERNAL-SPEC
  entries with the narrowest consumed proposition.
- Deployment restrictions qualify only binary/application claims; they are
  never hidden premises of library soundness (see `docs/deployment.md`).

## Entry index

| ID | Category | Trusted proposition (short) | Identity | Disposition | Re-audit trigger |
|---|---|---|---|---|---|
| AXIOM-RUST | AXIOM | Rust abstract semantics per versioned Reference/stdlib docs | stable 1.99.0 | accepted | stable update |
| SAFE-RUSTIX | SAFE-DEP | Typed rustix APIs behave as documented | rustix 1.1.5, features fs/process/std/termios, linux_raw backend | accepted | version/feature/backend change |
| RUSTIX-PREFORK | UNSAFE-DEP | `ioctl_fionclex` linux_raw path is nonallocating, nonlocking, inline `ioctl` syscall with null third arg | rustix 1.1.5 | accepted (audited) | version/backend change |
| SAFE-NIX | SAFE-DEP | Typed nix APIs behave as documented | nix 0.31.3, features fs/process/signal/term/user | accepted | version change |
| LIBC-DECL | EXTERNAL-SPEC | libc crate declarations match glibc ABI: `close_range` fixed 3-int prototype; `ioctl` variadic; constants | libc 0.2.190 / glibc | accepted | version change |
| GLIBC-IOCTL-VAARG | EXTERNAL-SPEC | glibc `ioctl` wrapper executes `va_arg(ap, void *)` unconditionally | glibc 2.44 (rev 1848099f06...) | accepted | glibc major/minor change |
| LINUX-SYSCALLS | EXTERNAL-SPEC | TIOCSCTTY force-flag word; close_range+UNSHARE; FD_CLOEXEC at execve; O_PATH rejects ioctl; memfd seals; pidfds | Linux 5.9+ semantics | accepted | kernel interface change |
| LINUX-PROCFs | EXTERNAL-SPEC | hidepid≥2 gates `/proc/<pid>` on ptrace-may-access (CAP_SYS_PTRACE or matching uid) | Linux fs/proc/base.c | accepted | kernel change |
| TOKIO-GEN | IMPLEMENTATION | tokio macros may emit `Pin::new_unchecked` into this crate's expansion; AsyncFd requires nonblocking fds | tokio 1.53.2 | accepted | version change |
| TOKIO-CHILD | IMPLEMENTATION | tokio Child drop detaches unless kill_on_drop; wait/try_wait reap semantics | tokio 1.53.2 | accepted | version change |
| STD-EXEC-PIPE | IMPLEMENTATION | std pre_exec: post-fork error pipe reaps intermediate child; child panics abort; child is single-threaded post-fork | std 1.99.0 (sys/process/unix) | accepted (audited) | stable update |
| STD-ERRNO | IMPLEMENTATION | `io::Error::from_raw_os_error` is a pure constructor: no errno read, no global state | std 1.99.0 | accepted | stable update |
| ZBUS | SAFE-DEP | D-Bus message encoding and FD transfer (pidfd credentials) behave as documented | zbus 5.19.0 / zvariant 5.15.0, feature tokio | accepted | version change |
| DEPLOY | ENVIRONMENT | Deployment restrictions per `docs/deployment.md` (executor caller contract, sandbox, provenance) | deployment doc | accepted | deployment change |
| BUILD-GATE | IMPLEMENTATION | The checked make entrypoint proves toolchain channel/host, fixed target, and rustix linux_raw backend for shippable artifacts | scripts/ensure-build.sh | accepted | gate or toolchain change |
| REJECT-RUSTIX-TIOCSCTTY | rejected | — | rustix 1.1.5 `ioctl_tiocsctty` | rejected | upstream fix; [filed](https://github.com/bytecodealliance/rustix/issues/1703) |

## Detailed entries

### AXIOM-RUST — Rust authority

- **Proposition:** the Rust abstract semantics (memory model, unsafe
  rules, drop/elaboration order, closure semantics, `unsafe` context
  propagation) are those of the versioned Rust Reference and
  standard-library documentation for the selected stable release.
- **Why needed:** every local SAFETY proof bottoms out in language
  semantics.
- **Limitation:** claims are source-level. Binary-level claims need the
  additional toolchain entry below. A guarantee documented for an older
  release applies to a later stable release only through Rust's
  backwards-compatibility commitment; treat each stable update as a
  re-audit trigger rather than assuming continuity.

### SAFE-RUSTIX — typed rustix operations

- **Proposition:** for rustix 1.1.5 with features `fs`, `process`,
  `std`, `termios` under the `linux_raw` backend, the safe APIs
  `io::fcntl_getfd`, `io::fcntl_setfd`, `io::ioctl_fionclex`,
  `fs::fcntl_getfl`, `fs::fcntl_setfl`, `fs::fcntl_get_seals`,
  `fs::fcntl_add_seals`, `fs::fstat`, `fs::fcntl_dupfd_cloexec`,
  `process::getpgrp`, `process::pidfd_open`, `termios::isatty`,
  `termios::tcgetsid`, `termios::tcgetpgrp`, `termios::tcgetattr`,
  `termios::tcsetattr`, `termios::tcgetwinsize` behave as documented in
  their doc comments, and their `linux_raw` lowering passes no
  C-variadic arguments (unlike rustix's libc backend, whose
  `fcntl_getfd`/`fcntl_setfd` reach glibc's variadic `fcntl` with
  missing/incompatible arguments — the reason the libc backend is
  rejected by the build gate).
- **Also consumed:** rustix maps a successful zero result of Linux
  `TIOCGPGRP` to `Errno::NOTSUP` (documented on `tcgetpgrp`); sud0 maps
  it back to `Some(0)` in the executor.
- **Verification performed:** implementations inspected in the extracted
  crate source (`src/io/fcntl.rs`, `src/io/ioctl.rs`, `src/fs/fcntl.rs`,
  `src/fs/memfd_create.rs`, `src/backend/linux_raw/...`).
- **Re-audit trigger:** rustix version change, feature-set change, or any
  configuration selecting the libc backend.

### RUSTIX-PREFORK — pre-exec rustix path

- **Proposition:** in rustix 1.1.5 under `linux_raw`,
  `io::ioctl_fionclex` constructs `ioctl::NoArg` (whose `as_ptr` returns
  `null_mut()`), passes it through `ioctl_readonly`, and lowers to the
  inline `syscall!(__NR_ioctl, fd, FIONCLEX, NULL)` — no allocation, no
  locks, no errno storage access, no signal-handler interaction. It is
  therefore usable in the post-fork pre-exec child, where POSIX does not
  list `ioctl` as async-signal-safe.
- **Verification performed:** source audit of `src/ioctl/patterns.rs`
  (`NoArg`), `src/ioctl/mod.rs`, and
  `src/backend/linux_raw/io/syscalls.rs` of the extracted crate.
- **Re-audit trigger:** rustix version or backend change. If a future
  release cannot be closed, replace with an audited direct-syscall leaf
  or eliminate the pre-exec closure.

### SAFE-NIX — typed nix operations

- **Proposition:** for nix 0.31.3 (features `fs`, `process`, `signal`,
  `term`, `user`), the safe APIs used by sud0 (`unistd::execve`,
  `unistd::fchdir`, `unistd::pipe2`, `unistd::read`, `unistd::write`,
  `unistd::getpid/getppid/getsid/setsid/getresuid`, `sys::memfd`,
  `sys::stat::{fstat,open}`, `sys::signal::kill`, `sys::wait::waitpid`)
  behave as documented and do not reach glibc's variadic `fcntl`
  dispatcher on any sud0 call path. (The project's own nix `fcntl` uses
  were removed in this remediation.)

### LIBC-DECL — libc declarations

- **Proposition:** the `libc` crate 0.2.190 declares `close_range` with
  the fixed, non-variadic prototype
  `unsafe extern "C" fn(c_uint, c_uint, c_int) -> c_int` and `ioctl` as a
  variadic function
  `unsafe extern "C" fn(c_int, c_ulong, ...) -> c_int`; the constants
  `TIOCSCTTY`, `CLOSE_RANGE_UNSHARE`, `FD_CLOEXEC`, `O_ACCMODE`,
  `O_WRONLY`, `O_PATH`, `ENOTTY`, `ENXIO` match the glibc/x86-64 ABI
  values. sud0's two remaining direct libc leaves
  (`executor::close_unrelated_fds`, `executor::acquire_controlling_terminal`)
  consume exactly these declarations.

### GLIBC-IOCTL-VAARG — glibc variadic ioctl wrapper

- **Proposition:** glibc's `ioctl` wrapper executes `va_arg(ap, void *)`
  unconditionally for every command (observed in glibc 2.44 at revision
  `1848099f063e99d4ffecbd7667766d54862398b9`). The
  `acquire_controlling_terminal` leaf therefore passes an actual
  `*mut c_void` null value — the exact type `va_arg` extracts — instead of
  the integer `0` the previous code passed, which was undefined behavior
  under ISO C23 7.16.1.1.
- **Re-audit trigger:** glibc release change to the `ioctl` wrapper.

### LINUX-SYSCALLS — kernel semantics

- **Propositions consumed:**
  - `TIOCSCTTY` consumes its third syscall word as an integer force flag;
    a null pointer argument lowers to the zero word and requests
    assignment without stealing an existing controlling terminal.
  - `close_range(5, UINT_MAX, CLOSE_RANGE_UNSHARE)` installs a private
    descriptor table and then closes the inclusive range; failure is
    reported as `-1`/errno.
  - `execve` atomically closes descriptors marked `FD_CLOEXEC` on
    success.
  - `ioctl(FIOCLEX)` is rejected on `O_PATH` descriptors; descriptor
    close-on-exec marking for the `O_PATH` working-directory descriptor
    must use `fcntl(F_SETFD)` (why `ioctl_fioclex` is used only for the
    notification pipe, never for descriptor 4).
  - memfd seals (`F_ADD_SEALS`, `F_GET_SEALS`, `F_SEAL_WRITE|SHRINK|GROW|SEAL`)
    behave as documented in `fcntl(2)` and `memfd_create(2)`.
  - `pidfd_open(2)` and `/proc/self/fdinfo` Pid fields pin process
    identity as consumed by the broker's authentication revalidation.

### LINUX-PROCFs — procfs visibility gating

- **Proposition:** a procfs mounted with `hidepid=2` (systemd
  `ProtectProc=invisible`) gates every `/proc/<pid>` access on
  `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)`, which succeeds
  only for a matching uid or `CAP_SYS_PTRACE` in the target's user
  namespace; failures return `ENOENT` (fs/proc/base.c,
  `proc_pid_permission`/`has_pid_permissions`). The broker holds no
  capabilities, so it cannot read invoking-user process metadata under
  such a mount; the shipped unit therefore leaves `ProtectProc` at its
  default (see `docs/deployment.md`).

### TOKIO-GEN — generated tokio code and AsyncFd

- **Proposition:** tokio's `#[tokio::main]`/`select!`/`pin!` macros may
  emit `Pin::new_unchecked` and other unsafe code into this crate's
  expansion; that generated code is trusted for tokio 1.53.2. `AsyncFd`
  requires registered descriptors to be nonblocking; every sud0
  `AsyncFd` is now constructed over an `O_NONBLOCK` descriptor.

### TOKIO-CHILD — tokio child lifecycle

- **Proposition:** dropping a tokio `Child` without reaping detaches the
  process unless `kill_on_drop` is set; `wait()`/`try_wait()` reap;
  `start_kill()` sends SIGKILL. sud0 arms an explicit `ChildGuard` and
  explicit terminate-and-reap paths so detachment never happens on a code
  path of ours; `kill_on_drop` additionally covers the residual edge of
  a drop during runtime shutdown where no reaper task can be spawned.

### STD-EXEC-PIPE — std process post-fork behavior

- **Proposition:** in the stable standard library (audited in
  `library/std/src/sys/process/unix/unix.rs` of rustc 1.99.0): a
  `pre_exec` closure error is written to the parent over a CLOEXEC pipe
  and the intermediate child is reaped (`p.wait()`) before `spawn`
  returns the error; the child arms `panic::always_abort` at fork so
  closure panics abort only the child; post-fork the child is
  single-threaded.
- **Re-audit trigger:** every stable toolchain update.

### STD-ERRNO — std error construction

- **Proposition:** `std::io::Error::from_raw_os_error(code)` is a pure
  constructor storing the code in the error value: it reads no errno
  storage and touches no process-global state, so it is usable in the
  pre-exec child (unlike `last_os_error`, which reads libc errno).
- **Re-audit trigger:** every stable toolchain update.

### ZBUS — D-Bus transport

- **Proposition:** zbus 5.19.0/zvariant 5.15.0 (feature `tokio`) encode
  and decode messages and transfer descriptors (notably the pidfd in
  `GetConnectionCredentials` results) as documented.

### DEPLOY — deployment restrictions

- **Proposition:** the deployment contract in `docs/deployment.md` holds
  for the installed system (executor caller contract, descriptor
  activation shape, sandbox/procfs compatibility, polkit/pkttyagent
  presence, provenance chain). These qualify only binary claims; no
  library-soundness proof depends on them.

### BUILD-GATE — build and toolchain enforcement

- **Proposition:** `make all/release/check` (via `scripts/ensure-build.sh`)
  prove for shippable artifacts that the compiler is a stable release on
  an `x86_64-unknown-linux-gnu` host, that every build command passes
  `--target x86_64-unknown-linux-gnu`, that `RUSTC_BOOTSTRAP`,
  unstable/custom-std rustflags, and rustix libc-backend cfgs/features
  are rejected, and that the resolved rustix graph does not enable
  `use-libc`. Direct `cargo` invocations bypassing the gate are
  development-only. `rust-toolchain.toml` selects a default but is not
  the enforcement boundary.

### REJECT-RUSTIX-TIOCSCTTY — rejected premise

- **Proposition (rejected):** rustix `process::ioctl_tiocsctty` (present
  since v0.38.9, commit 241da539, through 1.1.5 and current main)
  documents `ioctl(fd, TIOCSCTTY, 0)` but its `Ioctl::as_ptr`
  implementation passes `as_ptr(&0_u32)` — the non-null address of a
  stack-local zero — as the third syscall word. Linux's `tiocsctty()`
  requires that word to be exactly 1 (with `CAP_SYS_ADMIN`) to request
  force-steal (drivers/tty/tty_jobctrl.c; the `arg == 1` check is
  unchanged since 2.6.12), and a stack address is never 1, so the
  observable behavior coincidentally matches the documented non-forcing
  operation today. The API is nevertheless rejected: it does not deliver
  its documented argument word, the force form is unreachable through it,
  and consumers reasoning from the documentation get a false model of
  the syscall. sud0 retains the local null-pointer `libc::ioctl` leaf
  until an upstream-corrected release is audited. Upstream has been
  notified: <https://github.com/bytecodealliance/rustix/issues/1703>
