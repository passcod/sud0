# D-Bus API

The D-Bus interface is an implementation boundary between the `sud0` client and the root broker.
It is versioned by interface names, but it is not intended as a stable API for unrelated clients during the 0.x series.
The machine-readable introspection fixture is [`dbus-api.xml`](dbus-api.xml); its Rust tuple signatures are checked against the types compiled into the broker.

## Service and objects

The root broker owns `io.github.passcod.sud0` on the system bus and exports `io.github.passcod.sud0.Manager1` at `/io/github/passcod/sud0`.
`Run` returns a random object below `/io/github/passcod/sud0/invocation/` that implements `io.github.passcod.sud0.Invocation1`.
Each invocation records the caller's authenticated unique bus name.
Every invocation method rejects any other bus connection with `io.github.passcod.sud0.Error.AccessDenied`.
When that unique name loses ownership, the broker cancels authorization or the running transient service and removes its descriptor state.

## Manager1

`Run((aysh(yah)b(qqqq)) request) -> (o invocation)` accepts:

1. `ay`: a canonical encoded `FrozenRequest` containing argv, display cwd, explicit environment, I/O mode, and digest;
2. `s`: an optional human description represented using zvariant's option convention;
3. `h`: the already-opened working-directory descriptor;
4. `(yah)`: standard-I/O kind (`0` for PTY, `1` for pipes) and descriptors (none for PTY, exactly stdin/stdout/stderr for pipes);
5. `b`: whether polkit may show an interactive challenge; and
6. `(qqqq)`: optional initial rows, columns, horizontal pixels, and vertical pixels for PTY mode.

The two optional values use zvariant's sentinel representation: an empty string means no description, and an all-zero window tuple means no initial size.
A supplied PTY size must have nonzero rows and columns, so that sentinel cannot represent a valid size.
The broker fully copies and validates this input before authorization.
The cwd descriptor, rather than its display pathname, determines the execution directory.

`Validate(b allow_interaction) -> (b authorized)` checks the same polkit action without launching a command.
A denial or dismissed challenge returns `false`; transport and authorization-service failures are D-Bus errors.

## Invocation1

`Status() -> ((ybyiibs) status)` returns immediately.
`Wait() -> ((ybyiibs) status)` waits for a terminal state and schedules object removal.
The status fields are phase, terminal flag, outcome, exit status, signal number, core-dump flag, and a bounded category string.

Phases are `0` authorizing, `1` starting, `2` running, `3` complete, `4` failed, `5` cancelled, and `6` denied.
Outcomes are `0` none, `1` exited, `2` signaled, and `3` service failure.
Exit status is meaningful only for outcome `1`; signal and core-dump fields are meaningful only for outcome `2`.
The category identifies a failure class and does not contain argv, descriptions, or service result details.

`Cancel()` requests cancellation of authorization or the transient command.
`TakePty() -> (h pty)` returns a duplicate of the PTY master after startup and fails for pipe invocations.
`SetWindowSize((qqqq) size)` updates a PTY's rows, columns, and pixel dimensions.
`Release()` removes a completed invocation without waiting again.

## Errors

Broker-defined errors have the prefix `io.github.passcod.sud0.Error` and members `AccessDenied`, `InvalidRequest`, `NotReady`, `NotAvailable`, and `Failed`.
Malformed requests fail before authorization.
Internal zbus errors can also be returned using their native D-Bus error names.
