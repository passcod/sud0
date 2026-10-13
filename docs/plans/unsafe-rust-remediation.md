# Remediate the unsafe Rust audit

## Objective

Remediate the unsafe Rust findings recorded against source commit `bff054962bc1fbc7a9c5e9408e7b1e596b2c0a8f`.

Reduce handwritten unsafe code and its trusted computing base where maintained typed dependencies provide the required operation.

Retain the privileged execution architecture, descriptor-backed request and working-directory transfer, fixed executor binary, terminal setup, and fallback PolicyKit authentication agent.

Treat every implemented change as a new artifact requiring a fresh unsafe-code audit; the proposals below do not alter the verdict for the audited snapshot.

## Decisions already made

The project supports the current stable Rust channel only.

The project does not promise an MSRV or support for older stable releases.

`rust-version` and the Arch package's matching version floor will be removed.

A tracked `rust-toolchain.toml` will select `stable` and the components used by the project checks.

At the time this plan was written, the local stable toolchain was already Rust 1.99.0 (`b940084d7`, 2026-09-28).

Dependencies may be added or changed when they replace handwritten unsafe code with a narrower, maintained contract.

A dependency is not accepted merely because its public entry point is safe; its exact implementation and fallbacks must remove rather than conceal the relevant proof obligation.

## Current-artifact findings

### FFI-1: direct variadic libc calls reach undefined behavior in the audited glibc C source

The executor calls `fcntl(fd, F_GETFD)` without a third argument and calls `fcntl(fd, F_SETFD, int)` at `src/executor.rs:143` and `src/executor.rs:152`.

The authentication-agent pre-exec closure calls `fcntl(fd, F_SETFD, int)` at `src/auth_agent.rs:85`.

Safe project calls into nix also reach its libc-backed variadic `fcntl` dispatcher for request seals and status flags in `src/sealed_request.rs`—including its tests—and for nonblocking status flags in `src/terminal.rs`.

Those paths include missing third arguments for getters and integer third arguments for setters.

The executor calls `ioctl(fd, TIOCSCTTY, int)` at `src/executor.rs:269`.

These calls conform to their public POSIX and Linux command signatures.

The audited glibc 2.44 source at revision `1848099f063e99d4ffecbd7667766d54862398b9d` nevertheless evaluates `va_arg(ap, void *)` unconditionally in both wrappers.

For `F_GETFD`, no actual next argument exists.

For `F_SETFD` and `TIOCSCTTY`, the promoted actual argument is an integer rather than `void *`.

ISO C23 section 7.16.1.1 defines both cases as undefined behavior, and the Rust Reference states that undefined behavior in called C code affects the whole program.

This establishes a conditional `UNSOUND` source-language result for the exact glibc implementation under ISO C semantics.

It does not by itself establish that the installed x86-64 machine code misbehaves, because glibc deliberately relies on GNU compiler and SysV ABI behavior that was not established by the audited contracts.

The adjacent safety comments describe the public command behavior but do not account for the foreign wrapper implementation.

### CFG-1: the supported configuration domain is not closed

`Cargo.toml` currently declares Rust 1.89 as a lower bound without defining a channel or upper bound.

Cargo ignores compiler prerelease identifiers while enforcing `rust-version`, so that field is not a stable-channel policy.

The source and manifest do not enforce a target, libc, linker, panic strategy, profile, target-feature, custom-cfg, dependency-resolution, or rustix-backend policy.

The Arch package is restricted to an x86-64 host and prefetches for `x86_64-unknown-linux-gnu`, but its actual Make/Cargo build does not pass an explicit target; generic Cargo source use exposes a broader and underdetermined set.

Observed musl and FreeBSD builds fail at Linux/GNU-specific APIs; those failures are evidence of missing target policy, not undefined behavior.

Rust 1.89 and 1.98 produce materially different expanded artifacts, including compiler-generated unsafe helpers, so endpoint builds do not prove an open toolchain interval.

### TEST-ENV-1: the test-only `env::remove_var` proof is insufficient

`src/client_request.rs:101` mutates the process environment in a normal libtest harness.

Its safety comment establishes only that the generated variable name is unique to the process.

Rust requires process-wide exclusion of concurrent environment access outside the synchronized `std::env` implementation on non-Windows targets.

Libtest runs tests in parallel by default, and this repository does not enforce the required exclusion.

Variable-name uniqueness, variable absence, a crate-local mutex, or `--test-threads=1` does not prove the complete contract.

No complete overlapping foreign-reader witness was established, so this obligation is `UNPROVED`, not certified `UNSOUND`.

### PREEXEC-1: the authentication-agent safety proof omits material obligations

The proof at `src/auth_agent.rs:77-82` omits the exact errno-capture and `io::Error` construction path, platform qualification, spawn exits, cancellation and drop paths, and generated Tokio pinning behavior.

For Rust 1.98, the statement that error construction does not access shared Rust state is false because raw OS error construction accesses a global atomic pointer.

The local descriptor-lifetime argument can be reconstructed for the inspected GNU/Linux implementations, but the proof artifact does not contain it.

### POST-1: `executor::run` does not define “failing closed”

`src/executor.rs:31` promises that an error is returned after “failing closed” without defining the resulting descriptor, working-directory, session, process-group, or controlling-terminal state.

Valid error paths can retain earlier `FD_CLOEXEC`, current-directory, session, or controlling-terminal effects.

The current ownership transfer through `IntoRawFd` also leaves raw close responsibility outstanding if `close_range` fails.

The close-range safety comment says descriptor owners were dropped, but they were consumed and their raw close responsibility was transferred.

The vague postcondition cannot be proved or precisely falsified, so it is `UNPROVED` rather than `CONTRACT-BROKEN`.

### ASYNCFD-1: the authentication notification pipe is blocking

`src/auth_agent.rs:60-63` creates the pipe with `O_CLOEXEC` but not `O_NONBLOCK` and then registers the read end with Tokio `AsyncFd`.

Tokio 1.53.2 requires an `AsyncFd` descriptor to be nonblocking.

A stale or false readiness observation can therefore block a runtime worker in `src/auth_agent.rs:127`.

This is a progress and runtime-correctness defect, not an established Rust undefined-behavior witness.

### TCB-1: generated and dependency unsafe code is not represented by a project trust model

Tokio macros emit `Pin::new_unchecked` into the crate's expanded artifact.

Tokio, Mio, signal-hook-registry, pin-project-lite, Zbus, Zvariant, nix, rustix, libc, proc macros, the compiler, Linux, systemd, D-Bus, and PolicyKit supply propositions consumed by the source-level and deployed-binary arguments.

The lockfile freezes identities for locked project builds but does not prove undocumented behavior or cover unlocked downstream resolution.

The project has no canonical TCB log that states the exact dependency and platform propositions it accepts.

### BUILD-1: packaged artifact provenance is not enforced uniformly

The Arch VCS package follows a moving default branch and skips a source checksum, so it does not select the audited source revision.

`make install` has no build prerequisite and can install stale files from `target/release`.

This does not make the Rust source unsound, but it prevents a deployed-binary claim from establishing that the installed artifacts came from the reviewed source.

### DEPLOY-1: runtime assumptions and the service sandbox need an explicit reconciliation

The program depends on Linux memfd seals, pidfds, `close_range`, procfs process metadata, systemd transient-unit properties, D-Bus descriptor transfer, PolicyKit, and a visible caller/parent process relationship.

No complete runtime capability policy or minimum kernel/systemd contract is stated.

The shipped service sets `ProtectProc=invisible` while broker authentication reads `/proc/<pid>/stat` and `/proc/<pid>/status` for processes owned by invoking users.

Whether the installed sandbox permits those reads must be resolved as a deployment requirement rather than assumed.

## Dependency assessment

### Existing rustix dependency

Use `rustix` for operations it models with typed safe APIs whose implementations satisfy the required contracts:

- `rustix::io::{fcntl_getfd, fcntl_setfd}` under the enforced `linux_raw` backend to preserve and set `FD_CLOEXEC` on both activation descriptors, including the `O_PATH` working-directory descriptor;
- `rustix::io::ioctl_fionclex` to clear `FD_CLOEXEC` on the notification descriptor;
- `rustix::fs::{fcntl_getfl, fcntl_setfl, fcntl_get_seals, fcntl_add_seals}` for status flags and request sealing;
- `rustix::process::getpgrp` for the current process group;
- `rustix::termios::{isatty, tcgetsid, tcgetpgrp}` for terminal queries; and
- `rustix::fs::fstat` for terminal device identity.

Do not use `ioctl_fioclex` for the activation descriptors: Linux does not support that ioctl on the `O_PATH` descriptor used for the working directory.

Rustix 1.1.5's libc backend implements `fcntl_getfd`/`fcntl_setfd` with the same missing and incompatible C-variadic arguments as the current source, so those APIs are acceptable here only with the enforced `linux_raw` backend.

Do not use rustix 1.1.5's `rustix::process::ioctl_tiocsctty` implementation.

Although its documentation promises `ioctl(fd, TIOCSCTTY, 0)`, its argument adapter passes the address of a local zero.

Linux consumes the third syscall word as an integer force flag, so a non-null address requests forcing rather than the documented non-forcing operation.

Prefer an upstream-corrected rustix API whose adapter passes a null pointer value.

If no corrected release is available during implementation, retain one local leaf call that passes an actual `*mut c_void` null argument to `libc::ioctl`; that argument both matches glibc's unconditional `va_arg(void *)` and lowers to the zero word Linux requires.

Enable every directly consumed rustix feature explicitly, including `fs`, rather than relying on transitive feature unification.

This removes the incompatible or missing C-variadic arguments and the local `MaybeUninit<libc::stat>` proof.

The project will trust the exact documented safe rustix API behavior and record any implementation behavior required in the TCB.

Rustix backend selection remains a material configuration input for the TCB and generated artifact.

The selected ioctl operations pass pointer-typed variadic arguments correctly through either backend, but rustix's `fcntl` operations require its `linux_raw` backend to avoid the same libc dispatcher defect.

Make the supported build entrypoint reject rustix's `use-libc` feature, `rustix_use_libc` and `rustix_no_linux_raw` cfgs, Miri artifacts, and any other configuration that selects the libc backend.

Inspect the complete resolved feature graph rather than only sud0's direct feature list, because Cargo feature unification can enable `use-libc` transitively.

The fixed `x86_64-unknown-linux-gnu` stable target otherwise selects rustix's `linux_raw` backend by default.

Do not claim support for direct Cargo invocations that bypass the configuration gate.

### close-range crates considered and rejected

`close_fds` 0.3.2 is not suitable for the executor transaction.

Its close-on-exec fallback performs the same direct variadic libc `fcntl` calls, suppresses setter errors, and falls back to descriptor enumeration when `close_range` is unavailable.

Its immediate-close API is unsafe and does not provide the executor's required `CLOSE_RANGE_UNSHARE` failure semantics.

`fuxix` 0.2.0 is not suitable as a wholesale syscall replacement.

It duplicates a broad portion of rustix/nix, contains the same direct variadic `fcntl` pattern, and falls back from `close_range` to filesystem enumeration.

`agent-bridle-fdguard` 0.8.0-rc.5 addresses a different pre-exec ambient-descriptor problem, is a release candidate, uses variadic `libc::syscall`, and does not provide this executor's ownership or `CLOSE_RANGE_UNSHARE` contract.

Generic raw-syscall crates such as `linux-syscalls` or `syscalls` avoid glibc's C variadic wrappers but expose unsafe generic syscall APIs and add inline-assembly and architecture implementations to the TCB.

They are not justified for one fixed, nonvariadic operation while `libc::close_range` already has the exact typed signature required by this Linux/GNU executor.

### Activation-descriptor crates considered and rejected

The sampled activation crates do not improve the boundary enough to replace the current specialized validation.

`sd-listen-fds` 0.2.0 exposes a safe function that constructs owned descriptors from environment claims without first proving the descriptors open.

`listen-fds` 0.1.0 leaves its constructor unsafe, mutates the process environment, and uses direct variadic libc `fcntl` calls.

`libsystemd` 0.7.2 represents received descriptors as cloneable raw integers rather than strict `OwnedFd` capabilities and optionally mutates the environment.

The executor should retain its narrow unsafe ownership ingress and make its deployment contract precise instead of adopting these broader boundaries.

## Recommended design

### Use current stable Rust as a rolling support policy

Remove `rust-version` from `Cargo.toml`.

Change the Arch build dependency from `rust>=1.89` to the distribution's unversioned stable Rust package.

Add `rust-toolchain.toml` with `channel = "stable"` and the `rustfmt` and `clippy` components.

Define support as the stable toolchain selected at build and audit time, not every release that has ever appeared on the stable channel.

Treat each stable toolchain update as a source/generated-artifact re-audit trigger.

Make one checked Make/build entrypoint the only supported route to shippable artifacts.

Have it validate the actual compiler channel and host, pass `--target x86_64-unknown-linux-gnu` to every build command, reject `RUSTC_BOOTSTRAP`, encoded or ordinary unstable/custom-std flags, and the rustix backend overrides below, and emit the source/toolchain/target/dependency identity used by installation and packaging.

A `rust-toolchain.toml` selects a default but is not this enforcement boundary: callers can override it with Cargo/Rustup options and environment variables.

### State and enforce the platform target

Recommended initial scope: `x86_64-unknown-linux-gnu`, matching the package architecture and GNU/Linux deployment currently represented in the repository.

Enforce the scope through the checked shippable-artifact entrypoint and an explicit compile-time target guard rather than relying on missing symbols to reject nearby targets accidentally.

If broader GNU/Linux architecture support is desired, replace the single-triple rule with an explicit finite architecture policy and audit each architecture's ABI, syscall, libc layout, and generated artifact before adding it.

Do not describe musl, Android, other Unix systems, custom targets, or arbitrary path/git builds as supported merely because some subset compiles.

### Keep activation descriptors owned through the transaction

After activation metadata validation, claim descriptors 3 and 4 exactly once as `OwnedFd` values under `executor::run`'s unsafe caller contract.

Convert descriptor 3 safely from `OwnedFd` into `File`.

Validate descriptor 4 through `WorkingDirectoryFd::try_from`.

Set `FD_CLOEXEC` on both through typed rustix APIs while their owners remain live.

Change the bulk-close range to start at descriptor 5 instead of descriptor 3.

Give the leaf helper an explicit precondition that no live Rust owner refers to any descriptor in `[5, UINT_MAX]`.

Prove that precondition at the call site for every local and generated owner; otherwise closing a descriptor behind an owner could let its destructor close a later reuse of that number.

Retain `CLOSE_RANGE_UNSHARE` and the exact nonvariadic `libc::close_range` call in one leaf helper with a complete Linux/GNU proof.

Delete both `IntoRawFd` ownership relinquishments.

On successful `close_range`, descriptors 3 and 4 remain valid and owned for every attempted `execve`; successful `execve` closes them atomically because of `FD_CLOEXEC`.

If every `execve` candidate fails, normal Rust destruction closes descriptors 3 and 4 before the error escapes.

If bulk closure fails, normal Rust destruction still closes descriptors 3 and 4, while the binary terminates without executing the requested command.

This design removes the current raw-responsibility interval and prevents descriptor-number reuse from racing a later owner destructor.

### Replace the remaining executor libc queries with checked interfaces

Replace direct `getpgrp`, `isatty`, `fstat`, `tcgetsid`, and `tcgetpgrp` calls with typed rustix operations.

For `TIOCSCTTY`, use a corrected rustix release if one is available and its exact implementation has been checked.

Otherwise isolate the null-pointer `libc::ioctl` fallback in one private Linux/GNU leaf helper with an adjacent proof of its C variadic type, glibc extraction, and Linux integer-word semantics.

Preserve the current `ENOTTY`-to-`None` distinction for relationship queries.

Handle rustix's Linux `tcgetpgrp` mapping of a successful zero result to `OPNOTSUPP` explicitly.

Map it to `Some(0)` if exact current behavior is retained, or define and document a deliberate rejection before changing the terminal-readiness contract.

Preserve the post-operation terminal snapshot and shape validation rather than trusting `TIOCSCTTY` success alone.

Keep direct `libc` operations only in the isolated `close_range` leaf and, if still required, the isolated `TIOCSCTTY` leaf.

Remove direct `libc` use entirely if corrected dependency APIs cover both boundaries and reexport every remaining required constant/type.

### Keep `pre_exec`, but reduce its child closure to a typed rustix operation

Create the notification pipe with `O_CLOEXEC | O_NONBLOCK`.

Retain ownership of the write end in the suspended `start` future until synchronous spawn returns.

In the pre-exec closure, clear only `FD_CLOEXEC` using `rustix::io::ioctl_fionclex` under the enforced `linux_raw` backend.

POSIX does not list `ioctl` as async-signal-safe, so do not infer post-fork suitability from the safe API signature.

Audit and record the exact rustix version's complete raw-backend path—borrow conversion, wrapper, inline syscall, and result decoding—as a nonallocating, nonlocking Linux operation suitable for this child.

If that path cannot be closed, use one explicitly audited direct-syscall leaf or eliminate `pre_exec` rather than falling back to libc `ioctl`.

On failure, convert the `rustix::io::Errno` already returned by the operation with `io::Error::from_raw_os_error(error.raw_os_error())`; do not re-read libc errno with `last_os_error`.

Record a release-specific proof or TCB proposition for the exact stable standard-library error-construction path, including its global atomic pointer operations, and re-audit it on every stable update.

Update the adjacent safety proof with child/parent descriptor-table separation, every spawn exit, panic-abort behavior, cancellation, and ownership disposition.

Arm a child-lifetime guard immediately after spawn and disarm it only when ownership transfers into `AuthenticationAgent`.

Every registration error, `try_wait` error, future cancellation, and panic-unwind path after spawn must initiate termination and guarantee reaping rather than letting Tokio's default child drop detach a live process.

Preserve bounded shutdown behavior while making completion observable to the owner; do not treat `kill_on_drop` alone as proof of reaping.

Do not adopt `command-fds` for this one descriptor: its implementation uses nix `fcntl(F_SETFD)` and therefore retains the glibc variadic problem that motivates the change.

A future `posix_spawn`-based process abstraction could eliminate the pre-exec closure, but replacing Tokio's `Child` lifecycle and wait/reap integration is a larger architectural change and is not required for this remediation.

### Remove process-global environment mutation from the test

Move the missing-variable case into the existing recursively spawned child process.

Use safe `Command::env_remove` to construct the child's environment before spawn.

Use a dedicated marker to select the child assertion without mutating the running test process.

Delete the unsafe `env::remove_var` call and its insufficient safety comment.

### Define executor outcomes literally

Replace “failing closed” with explicit outcome clauses.

On success, `execve` replaces the process image and the activation descriptors do not survive because they carry `FD_CLOEXEC`.

On every error before terminal/session setup—including partial activation-descriptor claiming or marking—the function returns without executing caller-controlled code, closes every descriptor already claimed through ordinary ownership, and states any effect retained on an open descriptor not yet claimed.

On later errors, the function still closes every internally claimed descriptor and executes no requested command, but may retain already-applied current-directory, session, process-group, controlling-terminal, or descriptor-flag effects.

A failed `close_range` does not claim that unrelated inherited descriptors were closed.

The dedicated `sud0-exec` entrypoint prints the error and terminates the process; the binary-level deployment theorem may rely on process termination to release any remaining inherited descriptors.

Correct the close-range proof to distinguish live owners, ownership transfer, close-on-exec marking, kernel range closure, and normal destruction.

### Establish a project TCB log

Add one canonical TCB audit log beside the remediation documentation rather than scattering broad trust statements across comments.

Give separate entries to Rust/std authority, safe nix APIs, safe rustix APIs, rustix implementation behavior used post-fork, Tokio generated pinning/runtime families, Zbus/Zvariant message and FD handling, libc declarations/layouts, Linux syscall and procfs behavior, systemd descriptor/transient-unit behavior, and deployment restrictions.

State exact versions, enabled features, target/backend applicability, consumed propositions, owners, and re-audit triggers.

Do not use entries such as “dependencies are sound,” “Linux works,” or “the compiler is correct.”

Keep source-level soundness, exact compiled-binary behavior, and deployed-application assumptions as separate claims.

### Make artifact provenance explicit

Make `install` consume an explicit fresh release-build target or a caller-supplied artifact directory whose identity is checked.

Do not let the default installation path silently consume arbitrary pre-existing `target/release` files.

For release packaging, replace the moving VCS source and skipped checksum with an immutable source identity and integrity check.

Keep the development `-git` package clearly distinct from a release package and do not use it as proof of an audited release artifact.

### Reconcile the deployment sandbox

State the minimum Linux, systemd, procfs, D-Bus, PolicyKit, and authentication-agent capabilities actually consumed.

Resolve whether `ProtectProc=invisible` permits the broker's authenticated reads of invoking-user process metadata.

If it does not, change the unit or replace procfs-derived identity checks with a kernel/systemd interface that works inside the intended sandbox.

Preserve process identity across PID reuse with pidfds and retain the parent/UID revalidation sequence.

## Alternative approaches

### Replace `libc::close_range` with a generic raw-syscall crate

This avoids dynamic libc symbol/version dependence and can support non-GNU Linux targets.

It also adds unsafe generic syscall and architecture-specific inline-assembly implementations to the TCB, still requires a local safe wrapper contract, and does not by itself solve descriptor ownership.

Choose this only if the supported target expands beyond GNU/Linux or avoiding the glibc 2.34 symbol becomes a concrete deployment requirement.

### Adopt a maintained focused close-range wrapper

No sampled current crate supplied all required properties: a typed operation, `CLOSE_RANGE_UNSHARE`, exact failure propagation, no filesystem fallback, no direct C-variadic fallback, and an explicit Linux support policy.

An upstream rustix API providing this operation would be preferable to a new local abstraction when available.

Until then, one nonvariadic `libc::close_range` call is a smaller proof boundary than the sampled alternatives.

### Upstream the controlling-terminal correction

Report rustix 1.1.5's mismatch between its documented `TIOCSCTTY` zero argument and the non-null pointer its adapter passes.

A corrected maintained rustix operation is preferable because it centralizes platform-specific lowering behind the existing typed API.

Do not block local remediation on an upstream release: the private null-pointer `libc::ioctl` leaf has a narrower contract than adding another general ioctl or syscall crate.

### Move all process setup into a dedicated spawning crate

A lower-level `posix_spawn` or clone/exec abstraction could own FD mapping, close-on-exec policy, post-fork restrictions, and child lifecycle in one place.

This could remove both current unsafe boundaries from sud0 source.

It would also replace substantial standard-library and Tokio process behavior, enlarge the migration, and introduce a larger unsafe dependency surface.

Defer this unless the narrow remediation leaves a concrete unresolved obligation.

### Keep the GNU ABI extension as an accepted TCB premise

The project could document and accept the exact compiler/glibc/SysV behavior that makes the current variadic wrapper implementation work in emitted machine code.

This would preserve the current implementation but leave the C-source theorem `UNSOUND`, couple the project to one foreign implementation technique, and require binary-level rather than source-level reasoning at every affected call.

Do not choose this while typed dependency APIs remove the calls cleanly.

## Implementation sequence

1. Commit this remediation plan as the controlling implementation plan.
2. Replace the open Rust-version range with the rolling current-stable policy and enforce the chosen target policy.
3. Make rustix feature selection explicit, enforce its `linux_raw` backend for supported builds, replace every reachable nix/libc `fcntl` path with checked rustix operations, and isolate `TIOCSCTTY` behind either a corrected rustix release or the exact null-pointer fallback.
4. Redesign executor descriptor ownership so descriptors 3 and 4 remain owned while only descriptors 5 and above are closed with `CLOSE_RANGE_UNSHARE`, with no live owner inside that range.
5. Make the authentication notification pipe nonblocking, replace its pre-exec `fcntl` with the typed rustix close-on-exec operation, and guard every spawned child until ownership transfer.
6. Remove test-process environment mutation in favor of child environment construction.
7. Replace vague executor outcome prose and incomplete safety comments with complete contracts and local proofs.
8. Add the canonical TCB log and record exact dependency, generated-code, platform, and deployment premises.
9. Make installation and release packaging consume immutable, identified artifacts.
10. Reconcile the service sandbox with procfs-based caller authentication and document the supported deployment predicate.

## Completion conditions

No supported artifact has a reachable `fcntl` or `ioctl` path with a missing or C-incompatible variadic argument.

Any retained direct variadic `ioctl` leaf passes the exact pointer type extracted by libc and the exact argument word consumed by Linux.

The supported build entrypoint proves the resolved rustix backend is `linux_raw` and rejects every known backend override.

The test harness contains no unsafe process-environment mutation.

Every `AsyncFd` is constructed over a descriptor configured nonblocking before registration.

Every authentication-agent child is terminated and reaped, or transferred to its long-lived owner, on every post-spawn exit and cancellation path.

The executor has no interval in which responsibility for descriptors 3 or 4 exists only as discarded raw integers.

At the bulk-close call, no live Rust owner refers to a descriptor in `[5, UINT_MAX]`.

Every executor error outcome states which owned descriptors close and which process-global effects may remain.

The supported Rust channel and target set are explicit and enforced before a shippable artifact is produced.

Every generated-code, unsafe-dependency, external-platform, and deployment premise consumed by the new audit appears in the canonical TCB log with an explicit disposition.

Release installation has a reviewable source-to-artifact identity chain.

The service sandbox and procfs authentication path have one compatible, documented deployment contract.
