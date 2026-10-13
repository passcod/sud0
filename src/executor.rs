use std::convert::Infallible;
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use nix::errno::Errno as NixErrno;
use nix::unistd::{execve, getpid, getresuid, getsid, setsid};
use rustix::fs::fstat;
use rustix::io::{Errno, FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::process::getpgrp;
use rustix::termios::{isatty, tcgetpgrp, tcgetsid};
use thiserror::Error;

use crate::constants::{
    ACTIVATION_FD_COUNT, ACTIVATION_FD_NAMES, CWD_FD, REQUEST_FD, ROOT_PATH, ROOT_SHELL,
};
use crate::{
    FrozenRequest, IoMode, SealedRequestError, WorkingDirectoryError, WorkingDirectoryFd,
    decode_sealed_request,
};

const BASELINE_ENVIRONMENT: &[(&str, &str)] = &[
    ("PATH", ROOT_PATH),
    ("HOME", "/root"),
    ("USER", "root"),
    ("LOGNAME", "root"),
    ("SHELL", ROOT_SHELL),
];

/// First descriptor closed by the bulk close-range step: every descriptor the
/// transaction does not own.
const FIRST_UNRELATED_FD: libc::c_uint = (CWD_FD + 1) as libc::c_uint;

/// Runs the fixed privileged executor transaction.
///
/// # Outcomes
///
/// On success, `execve` replaces the process image. The two activation
/// descriptors do not survive because they carry `FD_CLOEXEC`, and no other
/// descriptor numbered 3 or above survives the transaction.
///
/// On every error before terminal and session setup — including partial
/// activation-descriptor claiming or close-on-exec marking — the function
/// returns without executing caller-controlled code. Each descriptor it
/// claimed is closed by normal ownership destruction before the error
/// escapes; an open descriptor it never claimed keeps its prior state
/// untouched. No current-directory, session, process-group,
/// controlling-terminal, or close-range effect has been applied at that point.
///
/// On later errors the function likewise executes no requested command and
/// closes every descriptor it claimed through normal ownership destruction,
/// but effects already applied may remain: `FD_CLOEXEC` marks on descriptors
/// 3 and 4, the working-directory change, a new session and process group, and
/// an acquired controlling terminal. A failed bulk close additionally leaves
/// inherited descriptors numbered 5 and above open; the dedicated
/// `sud0-exec` entrypoint terminates the process on any error, releasing them.
///
/// # Safety
///
/// The caller must be the initial, single-threaded entry point of a freshly
/// executed process. Descriptors 3 and 4 must be open and uniquely owned by
/// this transaction; no Rust value, thread, signal handler, or other code may
/// own, close, duplicate, or replace them during the call. No live Rust value
/// may own any descriptor numbered 5 or above when this function reaches its
/// bulk-close step. No signal handler or callback may mutate the descriptor
/// table during the call.
pub unsafe fn run() -> Result<Infallible, ExecutorError> {
    require_root_uids()?;
    validate_process_activation_environment()?;
    let (request_file, working_directory) = take_activation_fds()?;
    let request = decode_sealed_request(&request_file)?;

    prepare_terminal(request.io_mode())?;
    let argv = build_argv(&request);
    let environment = build_environment(&request);
    let candidates = command_candidates(&argv[0]);

    nix::unistd::fchdir(&working_directory).map_err(ExecutorError::ChangeDirectory)?;

    // SAFETY: The precondition of `close_unrelated_fds` is that no live Rust
    // value owns, or can close, any descriptor numbered 5 or above. Artifact
    // facts: every descriptor-owning value this function created came from
    // `take_activation_fds` and is one of `request_file` (descriptor 3) or
    // `working_directory` (descriptor 4); `decode_sealed_request`,
    // `prepare_terminal`, `build_argv`, `build_environment`,
    // `command_candidates`, and `fchdir` create no descriptor owners; no
    // thread, tokio task, signal handler, or foreign callback exists in this
    // initial single-threaded process to hold or later create one, and no
    // generated code from this crate or its dependencies runs on this path
    // before the bulk close. The standard descriptors 0–2 are below the
    // closed range. The precondition therefore holds.
    unsafe { close_unrelated_fds() }?;

    // `request_file` and `working_directory` stay owned through every
    // attempted `execve`: on success their `FD_CLOEXEC` marks make `execve`
    // close descriptors 3 and 4 atomically, and on failure their normal
    // destruction below closes them before the error escapes.
    let error = try_exec_candidates(&candidates, |path| {
        execve(path, &argv, &environment).map(|never| match never {})
    });
    Err(ExecutorError::Execute(error))
}

fn require_root_uids() -> Result<(), ExecutorError> {
    let ids = getresuid().map_err(ExecutorError::ReadUserIds)?;
    if ids.real.is_root() && ids.effective.is_root() && ids.saved.is_root() {
        Ok(())
    } else {
        Err(ExecutorError::NotFullyRoot)
    }
}

fn validate_process_activation_environment() -> Result<(), ExecutorError> {
    let listen_pid = env::var_os("LISTEN_PID");
    let listen_fds = env::var_os("LISTEN_FDS");
    let listen_fdnames = env::var_os("LISTEN_FDNAMES");
    validate_activation_environment(
        getpid().as_raw(),
        listen_pid.as_deref().map(OsStr::as_bytes),
        listen_fds.as_deref().map(OsStr::as_bytes),
        listen_fdnames.as_deref().map(OsStr::as_bytes),
    )
    .map_err(ExecutorError::Activation)
}

/// Strictly validates the three raw systemd descriptor-activation values.
fn validate_activation_environment(
    current_pid: i32,
    listen_pid: Option<&[u8]>,
    listen_fds: Option<&[u8]>,
    listen_fdnames: Option<&[u8]>,
) -> Result<(), ActivationError> {
    let expected_pid =
        u32::try_from(current_pid).map_err(|_| ActivationError::InvalidCurrentPid)?;
    if parse_decimal(listen_pid.ok_or(ActivationError::MissingListenPid)?)? != expected_pid {
        return Err(ActivationError::WrongListenPid);
    }
    if parse_decimal(listen_fds.ok_or(ActivationError::MissingListenFds)?)? != ACTIVATION_FD_COUNT {
        return Err(ActivationError::WrongListenFds);
    }
    if listen_fdnames.ok_or(ActivationError::MissingListenFdNames)?
        != ACTIVATION_FD_NAMES.as_bytes()
    {
        return Err(ActivationError::WrongListenFdNames);
    }
    Ok(())
}

fn parse_decimal(value: &[u8]) -> Result<u32, ActivationError> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(ActivationError::InvalidDecimal);
    }
    value.iter().try_fold(0_u32, |parsed, byte| {
        parsed
            .checked_mul(10)
            .and_then(|parsed| parsed.checked_add(u32::from(byte - b'0')))
            .ok_or(ActivationError::InvalidDecimal)
    })
}

fn take_activation_fds() -> Result<(File, WorkingDirectoryFd), ExecutorError> {
    let request_fd = claim_activation_fd(REQUEST_FD)?;
    let request_file = File::from(request_fd);
    let cwd_fd = claim_activation_fd(CWD_FD)?;
    let working_directory =
        WorkingDirectoryFd::try_from(cwd_fd).map_err(ExecutorError::WorkingDirectory)?;
    Ok((request_file, working_directory))
}

/// Claims one systemd activation descriptor as an owned descriptor marked
/// close-on-exec.
///
/// On failure the claimed descriptor is closed by normal `OwnedFd` destruction
/// before the error escapes; a descriptor never claimed is left untouched.
///
/// The `fcntl` operations are safe typed rustix APIs whose `linux_raw`
/// lowering — the backend the checked build entrypoint enforces and
/// docs/tcb.md records — passes no C-variadic arguments.
fn claim_activation_fd(fd: RawFd) -> Result<OwnedFd, ExecutorError> {
    // SAFETY: `executor::run`'s caller contract establishes that `fd` is open
    // and uniquely owned by this transaction at this point. Before this claim,
    // the process has executed only `getresuid`, `getpid`, and
    // `std::env::var_os`, none of which open, close, or reallocate
    // descriptors, so even if that contract were violated and `fd` were
    // closed, no reuse of the number could have occurred and the error-path
    // destruction below can only produce `EBADF`. `from_raw_fd` here is the
    // sole ownership ingress for the descriptor; normal `OwnedFd` destruction
    // owns closing it on every subsequent path.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let flags = fcntl_getfd(&owned).map_err(|source| ExecutorError::ActivationDescriptor {
        fd,
        source: io::Error::from(source),
    })?;
    fcntl_setfd(&owned, flags | FdFlags::CLOEXEC).map_err(|source| {
        ExecutorError::SetCloseOnExec {
            fd,
            source: io::Error::from(source),
        }
    })?;
    Ok(owned)
}

/// Builds the explicit command environment without consulting ambient process values.
fn build_environment(request: &FrozenRequest) -> Vec<CString> {
    BASELINE_ENVIRONMENT
        .iter()
        .map(|(name, value)| environment_assignment(name, value))
        .chain(
            request
                .environment()
                .iter()
                .map(|(name, value)| environment_assignment(name, value)),
        )
        .collect()
}

fn environment_assignment(name: &str, value: &str) -> CString {
    CString::new(format!("{name}={value}"))
        .expect("validated frozen environment cannot contain NUL")
}

fn build_argv(request: &FrozenRequest) -> Vec<CString> {
    request
        .argv()
        .iter()
        .map(|argument| CString::new(argument.as_str()).expect("validated argv cannot contain NUL"))
        .collect()
}

/// Resolves only the pathnames the executor may pass to `execve(2)`.
fn command_candidates(argv0: &CStr) -> Vec<CString> {
    if argv0.to_bytes().contains(&b'/') {
        return vec![argv0.to_owned()];
    }

    ROOT_PATH
        .split(':')
        .map(|component| {
            let component = component.as_bytes();
            let mut candidate = Vec::with_capacity(component.len() + 1 + argv0.to_bytes().len());
            candidate.extend_from_slice(component);
            candidate.push(b'/');
            candidate.extend_from_slice(argv0.to_bytes());
            CString::new(candidate)
                .expect("fixed path components and validated argv cannot contain NUL")
        })
        .collect()
}

fn try_exec_candidates(
    candidates: &[CString],
    mut execute: impl FnMut(&CStr) -> Result<(), NixErrno>,
) -> NixErrno {
    let mut saw_access_denied = false;
    for candidate in candidates {
        match execute(candidate) {
            Ok(()) => unreachable!("successful exec does not return"),
            Err(NixErrno::EACCES) => saw_access_denied = true,
            Err(NixErrno::ENOENT | NixErrno::ENOTDIR) => {}
            Err(error) => return error,
        }
    }
    if saw_access_denied {
        NixErrno::EACCES
    } else {
        NixErrno::ENOENT
    }
}

/// Closes every inherited descriptor numbered 5 and above in a freshly
/// unshared descriptor table.
///
/// # Safety
///
/// The caller must ensure that no live Rust value owns, or can close, any
/// descriptor numbered 5 or above at the moment of the call: the kernel closes
/// those descriptors here, so a surviving owner's destructor could later close
/// an unrelated reuse of the same descriptor number. The caller must also
/// ensure the process is single-threaded with no concurrent descriptor-table
/// mutation.
unsafe fn close_unrelated_fds() -> Result<(), ExecutorError> {
    // SAFETY (leaf proof):
    // Obligation: `libc::close_range` is declared with the fixed,
    // non-variadic prototype `extern "C" fn(c_uint, c_uint, c_int) -> c_int`;
    // this call passes exactly the three declared integer arguments, so no C
    // variadic extraction occurs, and the function dereferences no Rust
    // memory.
    // Artifact facts: the lower bound is the `FIRST_UNRELATED_FD` constant
    // (descriptor 5, one past the highest owned activation descriptor); the
    // upper bound is `c_uint::MAX`; the flags value is `CLOSE_RANGE_UNSHARE`
    // cast to the declared `c_int`.
    // Semantics (TCB, docs/tcb.md): Linux `close_range(2)` with
    // `CLOSE_RANGE_UNSHARE` first installs a private descriptor table for the
    // calling process and then closes every descriptor in the inclusive
    // range. A rejected or unsupported operation returns -1 and sets errno,
    // which the error path reports, failing closed.
    let result = unsafe {
        libc::close_range(
            FIRST_UNRELATED_FD,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_UNSHARE as libc::c_int,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ExecutorError::CloseDescriptors(io::Error::last_os_error()))
    }
}

fn prepare_terminal(mode: IoMode) -> Result<(), ExecutorError> {
    if mode == IoMode::Pipe {
        return Ok(());
    }

    let before = terminal_snapshot()?;
    validate_terminal_shape(&before)?;
    if terminal_is_ready(&before) {
        if before.session == before.pid {
            return Ok(());
        }
        return Err(ExecutorError::InvalidControllingTerminal);
    }

    if before.session != before.pid {
        setsid().map_err(ExecutorError::CreateSession)?;
    }

    acquire_controlling_terminal(io::stdin().as_fd())?;

    let after = terminal_snapshot()?;
    validate_terminal_shape(&after)?;
    if terminal_is_ready(&after) && after.session == after.pid {
        Ok(())
    } else {
        Err(ExecutorError::InvalidControllingTerminal)
    }
}

/// Assigns the validated terminal on `fd` as this process's controlling
/// terminal without the force-steal mode.
fn acquire_controlling_terminal(fd: BorrowedFd<'_>) -> Result<(), ExecutorError> {
    // SAFETY (leaf proof):
    // Obligation: glibc's `ioctl` wrapper is declared
    // `int ioctl(int, unsigned long, ...)`; its implementation executes
    // `va_arg(ap, void *)` unconditionally for every command. The third
    // argument passed here is `std::ptr::null_mut::<libc::c_void>()`, a value
    // whose type is exactly the `void *` that `va_arg` extracts, so the
    // extraction is defined (ISO C23 7.16.1.1).
    // Semantics (TCB, docs/tcb.md): Linux consumes the third syscall word of
    // `TIOCSCTTY` as an integer force flag; the null pointer argument lowers
    // to the all-zero word, requesting assignment without stealing a
    // controlling terminal from another session. An ineligible descriptor is
    // reported as an error.
    // The call dereferences no Rust memory and retains no pointer, and its
    // effects are re-verified by the terminal snapshot the caller takes
    // immediately afterwards.
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::TIOCSCTTY,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result == -1 {
        return Err(ExecutorError::AcquireControllingTerminal(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

struct TerminalSnapshot {
    pid: i32,
    process_group: i32,
    session: i32,
    terminals: [TerminalState; 3],
}

struct TerminalState {
    device: u64,
    terminal_session: Option<i32>,
    foreground_group: Option<i32>,
}

fn terminal_snapshot() -> Result<TerminalSnapshot, ExecutorError> {
    let pid = getpid().as_raw();
    let session = getsid(None).map_err(ExecutorError::ReadSession)?.as_raw();
    let process_group = getpgrp().as_raw_pid();
    let terminals = [
        terminal_state(io::stdin().as_fd())?,
        terminal_state(io::stdout().as_fd())?,
        terminal_state(io::stderr().as_fd())?,
    ];
    Ok(TerminalSnapshot {
        pid,
        process_group,
        session,
        terminals,
    })
}

fn terminal_state(fd: BorrowedFd<'_>) -> Result<TerminalState, ExecutorError> {
    if !isatty(fd) {
        return Err(ExecutorError::PtyRequiresTerminal { fd: fd.as_raw_fd() });
    }

    let stat = fstat(fd).map_err(|source| ExecutorError::InspectTerminal {
        fd: fd.as_raw_fd(),
        source: io::Error::from(source),
    })?;
    let terminal_session = terminal_relationship(fd, TerminalQuery::Session)?;
    let foreground_group = terminal_relationship(fd, TerminalQuery::ForegroundGroup)?;

    Ok(TerminalState {
        device: stat.st_rdev,
        terminal_session,
        foreground_group,
    })
}

enum TerminalQuery {
    Session,
    ForegroundGroup,
}

fn terminal_relationship(
    fd: BorrowedFd<'_>,
    query: TerminalQuery,
) -> Result<Option<i32>, ExecutorError> {
    let value = match query {
        TerminalQuery::Session => tcgetsid(fd).map(|pid| pid.as_raw_pid()),
        TerminalQuery::ForegroundGroup => tcgetpgrp(fd).map(|pid| pid.as_raw_pid()),
    };
    match value {
        Ok(value) => Ok(Some(value)),
        Err(error) if error == Errno::NOTTY => Ok(None),
        // rustix maps a successful zero foreground process group (an
        // unassigned terminal) to NOTSUP; retain the exact zero value the
        // libc `tcgetpgrp` call previously returned so the readiness contract
        // is unchanged.
        Err(Errno::NOTSUP) if matches!(query, TerminalQuery::ForegroundGroup) => Ok(Some(0)),
        Err(source) => Err(match query {
            TerminalQuery::Session => ExecutorError::ReadTerminalSession {
                fd: fd.as_raw_fd(),
                source: io::Error::from(source),
            },
            TerminalQuery::ForegroundGroup => ExecutorError::ReadForegroundGroup {
                fd: fd.as_raw_fd(),
                source: io::Error::from(source),
            },
        }),
    }
}

fn validate_terminal_shape(snapshot: &TerminalSnapshot) -> Result<(), ExecutorError> {
    let expected_device = snapshot.terminals[0].device;
    if snapshot
        .terminals
        .iter()
        .any(|terminal| terminal.device != expected_device)
    {
        return Err(ExecutorError::MismatchedTerminals);
    }
    Ok(())
}

fn terminal_is_ready(snapshot: &TerminalSnapshot) -> bool {
    snapshot.terminals.iter().all(|terminal| {
        terminal.terminal_session == Some(snapshot.session)
            && terminal.foreground_group == Some(snapshot.process_group)
    })
}

/// A malformed systemd descriptor-activation environment.
#[derive(Debug, PartialEq, Error)]
pub enum ActivationError {
    #[error("LISTEN_PID is missing")]
    MissingListenPid,
    #[error("LISTEN_FDS is missing")]
    MissingListenFds,
    #[error("LISTEN_FDNAMES is missing")]
    MissingListenFdNames,
    #[error("activation count or process ID is not a strict unsigned decimal integer")]
    InvalidDecimal,
    #[error("current process ID is invalid")]
    InvalidCurrentPid,
    #[error("LISTEN_PID does not identify this process")]
    WrongListenPid,
    #[error("LISTEN_FDS does not specify exactly two descriptors")]
    WrongListenFds,
    #[error("LISTEN_FDNAMES does not contain the two required descriptor names in order")]
    WrongListenFdNames,
}

/// A privileged executor validation or process-setup failure.
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("failed to inspect real, effective, and saved user IDs: {0}")]
    ReadUserIds(NixErrno),
    #[error("real, effective, and saved user IDs must all be zero")]
    NotFullyRoot,
    #[error("invalid descriptor activation environment: {0}")]
    Activation(ActivationError),
    #[error("expected activation descriptor {fd} is unavailable: {source}")]
    ActivationDescriptor { fd: RawFd, source: io::Error },
    #[error("failed to set close-on-exec on activation descriptor {fd}: {source}")]
    SetCloseOnExec { fd: RawFd, source: io::Error },
    #[error("invalid sealed request descriptor: {0}")]
    SealedRequest(#[from] SealedRequestError),
    #[error("invalid working-directory descriptor: {0}")]
    WorkingDirectory(#[from] WorkingDirectoryError),
    #[error("PTY mode requires terminal descriptor {fd}")]
    PtyRequiresTerminal { fd: RawFd },
    #[error("failed to inspect terminal descriptor {fd}: {source}")]
    InspectTerminal { fd: RawFd, source: io::Error },
    #[error("failed to read the current session: {0}")]
    ReadSession(NixErrno),
    #[error("failed to read the terminal session for descriptor {fd}: {source}")]
    ReadTerminalSession { fd: RawFd, source: io::Error },
    #[error("failed to read the foreground process group for descriptor {fd}: {source}")]
    ReadForegroundGroup { fd: RawFd, source: io::Error },
    #[error("PTY standard descriptors do not refer to the same terminal")]
    MismatchedTerminals,
    #[error("failed to create a fresh terminal session: {0}")]
    CreateSession(NixErrno),
    #[error("failed to acquire the controlling terminal without force: {0}")]
    AcquireControllingTerminal(io::Error),
    #[error("controlling terminal session or foreground process group verification failed")]
    InvalidControllingTerminal,
    #[error("failed to change to the opened working directory: {0}")]
    ChangeDirectory(NixErrno),
    #[error("failed to close inherited descriptors: {0}")]
    CloseDescriptors(io::Error),
    #[error("command execution failed: {0}")]
    Execute(NixErrno),
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn request(argv: &[&str], environment: &[(&str, &str)]) -> FrozenRequest {
        FrozenRequest::new(
            argv.iter().map(|value| (*value).to_owned()).collect(),
            environment
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            IoMode::Pipe,
        )
        .unwrap()
    }

    #[test]
    fn activation_environment_requires_exact_raw_values() {
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b"42"),
                Some(b"2"),
                Some(b"sud0-request:sud0-cwd")
            ),
            Ok(())
        );
        assert_eq!(
            validate_activation_environment(42, None, Some(b"2"), Some(b"sud0-request:sud0-cwd")),
            Err(ActivationError::MissingListenPid)
        );
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b" 42"),
                Some(b"2"),
                Some(b"sud0-request:sud0-cwd")
            ),
            Err(ActivationError::InvalidDecimal)
        );
        assert_eq!(
            validate_activation_environment(42, Some(b"42"), Some(b"1\0"), Some(b"sud0-request")),
            Err(ActivationError::InvalidDecimal)
        );
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b"43"),
                Some(b"2"),
                Some(b"sud0-request:sud0-cwd")
            ),
            Err(ActivationError::WrongListenPid)
        );
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b"42"),
                Some(b"1"),
                Some(b"sud0-request:sud0-cwd")
            ),
            Err(ActivationError::WrongListenFds)
        );
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b"42"),
                Some(b"2"),
                Some(b"sud0-request:sud0-cwd:extra")
            ),
            Err(ActivationError::WrongListenFdNames)
        );
        assert_eq!(
            validate_activation_environment(
                42,
                Some(b"42949672960"),
                Some(b"2"),
                Some(b"sud0-request:sud0-cwd")
            ),
            Err(ActivationError::InvalidDecimal)
        );
    }

    #[test]
    fn environment_is_explicit_and_preserves_utf8_values() {
        let request = request(&["env"], &[("TERM", "xterm"), ("LANG", "mi_NZ")]);
        let environment = build_environment(&request);
        let values: Vec<&str> = environment
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();

        assert_eq!(
            &values[..BASELINE_ENVIRONMENT.len()],
            [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin",
                "HOME=/root",
                "USER=root",
                "LOGNAME=root",
                "SHELL=/bin/bash",
            ]
        );
        assert!(values.contains(&"TERM=xterm"));
        assert!(values.contains(&"LANG=mi_NZ"));
        assert!(!values.iter().any(|entry| entry.starts_with("LISTEN_")));
    }

    #[test]
    fn path_candidates_use_only_fixed_absolute_components() {
        let bare = CString::new("tool").unwrap();
        let paths: Vec<Vec<u8>> = command_candidates(&bare)
            .into_iter()
            .map(|path| path.into_bytes())
            .collect();
        assert_eq!(
            paths,
            [
                b"/usr/local/sbin/tool".to_vec(),
                b"/usr/local/bin/tool".to_vec(),
                b"/usr/bin/tool".to_vec(),
            ]
        );

        for direct in ["/opt/tool", "./tool", "dir/tool"] {
            let direct = CString::new(direct).unwrap();
            assert_eq!(command_candidates(&direct), [direct]);
        }
    }

    #[test]
    fn search_remembers_access_denied_but_does_not_fallback_on_bad_format() {
        let candidates = command_candidates(CString::new("tool").unwrap().as_c_str());
        let visited = RefCell::new(Vec::new());
        let errors =
            RefCell::new(vec![NixErrno::ENOENT, NixErrno::EACCES, NixErrno::ENOENT].into_iter());
        let result = try_exec_candidates(&candidates, |path| {
            visited.borrow_mut().push(path.to_owned());
            Err(errors.borrow_mut().next().unwrap())
        });
        assert_eq!(result, NixErrno::EACCES);
        assert_eq!(visited.borrow().len(), 3);

        let visited = RefCell::new(Vec::new());
        let result = try_exec_candidates(&candidates, |path| {
            visited.borrow_mut().push(path.to_owned());
            Err(NixErrno::ENOEXEC)
        });
        assert_eq!(result, NixErrno::ENOEXEC);
        assert_eq!(visited.borrow().len(), 1);
    }
}
