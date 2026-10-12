use std::convert::Infallible;
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use nix::errno::Errno;
use nix::unistd::{execve, getpid, getresuid, getsid, setsid};
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

/// Runs the fixed privileged executor transaction.
///
/// It either replaces the current process image or returns an error after failing closed.
///
/// # Safety
///
/// The caller must be the initial, single-threaded entry point of a freshly executed process.
/// Descriptors 3 and 4 must be open and uniquely owned by this transaction; no Rust value or other
/// code may own, close, duplicate, or replace them during the call. No live Rust value may own any
/// descriptor at or above 3 when this function reaches its close-range step, other than the two
/// values created internally and relinquished immediately before that step. No signal handler or
/// callback may mutate the descriptor table during the call.
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

    // Transfer responsibility for closing descriptors 3 and 4 to `close_unrelated_fds`; keeping an
    // owner alive across that call would let its destructor close a future reuse of either number.
    let request_fd = request_file.into_raw_fd();
    let cwd_fd = working_directory.into_owned_fd().into_raw_fd();
    debug_assert_eq!((request_fd, cwd_fd), (REQUEST_FD, CWD_FD));
    close_unrelated_fds()?;

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
    current_pid: libc::pid_t,
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
    set_close_on_exec(REQUEST_FD)?;
    set_close_on_exec(CWD_FD)?;

    // SAFETY: The successful `fcntl` calls in `set_close_on_exec` establish that descriptor 3 is
    // open. This function is the sole ownership ingress for it, and `File` takes responsibility for
    // closing it. No other Rust owner exists.
    let request_file = unsafe { File::from_raw_fd(REQUEST_FD) };
    // SAFETY: The same argument applies to open descriptor 4. The resulting `OwnedFd` is immediately
    // passed through the directory validation boundary before any use as a working directory.
    let cwd_fd = unsafe { OwnedFd::from_raw_fd(CWD_FD) };
    let working_directory = WorkingDirectoryFd::try_from(cwd_fd)?;
    Ok((request_file, working_directory))
}

fn set_close_on_exec(fd: RawFd) -> Result<(), ExecutorError> {
    // SAFETY: `fcntl(F_GETFD)` and `fcntl(F_SETFD)` consume only the integer descriptor and flag
    // value; they dereference no Rust pointers. A successful `F_GETFD` establishes that `fd` is
    // open, and this single-threaded executor performs no operation that can close or replace it
    // before `F_SETFD`. A successful `F_SETFD` preserves ownership and establishes `FD_CLOEXEC`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(ExecutorError::ActivationDescriptor {
            fd,
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: The successful `F_GETFD` above established that `fd` remains open, and this call passes
    // no pointer-valued variadic argument.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(ExecutorError::SetCloseOnExec {
            fd,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
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
    mut execute: impl FnMut(&CStr) -> Result<(), Errno>,
) -> Errno {
    let mut saw_access_denied = false;
    for candidate in candidates {
        match execute(candidate) {
            Ok(()) => unreachable!("successful exec does not return"),
            Err(Errno::EACCES) => saw_access_denied = true,
            Err(Errno::ENOENT | Errno::ENOTDIR) => {}
            Err(error) => return error,
        }
    }
    if saw_access_denied {
        Errno::EACCES
    } else {
        Errno::ENOENT
    }
}

fn close_unrelated_fds() -> Result<(), ExecutorError> {
    // SAFETY: `close_range` accepts only integer bounds and flags, dereferences no Rust memory, and
    // runs after every Rust owner of a descriptor at or above 3 has been dropped. The process is
    // single-threaded, while `CLOSE_RANGE_UNSHARE` also requests a private descriptor table before
    // closing the complete range. Kernel rejection, including lack of support, is returned as an
    // error and therefore fails closed.
    let result = unsafe {
        libc::close_range(
            REQUEST_FD as libc::c_uint,
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

    // SAFETY: `TIOCSCTTY` with argument zero consumes no pointer and asks the kernel to assign the
    // already-validated terminal on fd 0 without the force-steal mode. An invalid or ineligible
    // descriptor is reported as an error. The subsequent snapshot verifies all required effects.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) } == -1 {
        return Err(ExecutorError::AcquireControllingTerminal(
            io::Error::last_os_error(),
        ));
    }

    let after = terminal_snapshot()?;
    validate_terminal_shape(&after)?;
    if terminal_is_ready(&after) && after.session == after.pid {
        Ok(())
    } else {
        Err(ExecutorError::InvalidControllingTerminal)
    }
}

#[derive(Debug)]
struct TerminalSnapshot {
    pid: libc::pid_t,
    process_group: libc::pid_t,
    session: libc::pid_t,
    terminals: [TerminalState; 3],
}

#[derive(Debug)]
struct TerminalState {
    device: libc::dev_t,
    terminal_session: Option<libc::pid_t>,
    foreground_group: Option<libc::pid_t>,
}

fn terminal_snapshot() -> Result<TerminalSnapshot, ExecutorError> {
    let pid = getpid().as_raw();
    let session = getsid(None).map_err(ExecutorError::ReadSession)?.as_raw();

    // SAFETY: `getpgrp` has no arguments or memory access supplied by Rust and cannot violate Rust
    // memory invariants.
    let process_group = unsafe { libc::getpgrp() };
    let terminals = [
        terminal_state(libc::STDIN_FILENO)?,
        terminal_state(libc::STDOUT_FILENO)?,
        terminal_state(libc::STDERR_FILENO)?,
    ];
    Ok(TerminalSnapshot {
        pid,
        process_group,
        session,
        terminals,
    })
}

fn terminal_state(fd: RawFd) -> Result<TerminalState, ExecutorError> {
    // SAFETY: `isatty` consumes only an integer descriptor and dereferences no Rust memory.
    if unsafe { libc::isatty(fd) } != 1 {
        return Err(ExecutorError::PtyRequiresTerminal { fd });
    }

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable, correctly aligned storage for one `libc::stat`; `fstat`
    // initializes it on success and does not retain the pointer.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == -1 {
        return Err(ExecutorError::InspectTerminal {
            fd,
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: The successful `fstat` immediately above initialized the complete `libc::stat` value.
    let stat = unsafe { stat.assume_init() };

    // SAFETY: `tcgetsid` and `tcgetpgrp` consume only an integer descriptor and return errors for
    // descriptors without the required terminal relationship; they access no Rust memory.
    let terminal_session = terminal_relationship(fd, TerminalQuery::Session)?;
    // SAFETY: As above, this query consumes only the validated integer terminal descriptor.
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
    fd: RawFd,
    query: TerminalQuery,
) -> Result<Option<libc::pid_t>, ExecutorError> {
    // SAFETY: Both operations consume only an integer descriptor and access no Rust memory.
    let value = unsafe {
        match query {
            TerminalQuery::Session => libc::tcgetsid(fd),
            TerminalQuery::ForegroundGroup => libc::tcgetpgrp(fd),
        }
    };
    if value != -1 {
        return Ok(Some(value));
    }

    let source = io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ENOTTY) {
        return Ok(None);
    }
    Err(match query {
        TerminalQuery::Session => ExecutorError::ReadTerminalSession { fd, source },
        TerminalQuery::ForegroundGroup => ExecutorError::ReadForegroundGroup { fd, source },
    })
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
#[derive(Debug, PartialEq, Eq, Error)]
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
    ReadUserIds(Errno),
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
    ReadSession(Errno),
    #[error("failed to read the terminal session for descriptor {fd}: {source}")]
    ReadTerminalSession { fd: RawFd, source: io::Error },
    #[error("failed to read the foreground process group for descriptor {fd}: {source}")]
    ReadForegroundGroup { fd: RawFd, source: io::Error },
    #[error("PTY standard descriptors do not refer to the same terminal")]
    MismatchedTerminals,
    #[error("failed to create a fresh terminal session: {0}")]
    CreateSession(Errno),
    #[error("failed to acquire the controlling terminal without force: {0}")]
    AcquireControllingTerminal(io::Error),
    #[error("controlling terminal session or foreground process group verification failed")]
    InvalidControllingTerminal,
    #[error("failed to change to the opened working directory: {0}")]
    ChangeDirectory(Errno),
    #[error("failed to close inherited descriptors: {0}")]
    CloseDescriptors(io::Error),
    #[error("command execution failed: {0}")]
    Execute(Errno),
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
        let errors = RefCell::new(vec![Errno::ENOENT, Errno::EACCES, Errno::ENOENT].into_iter());
        let result = try_exec_candidates(&candidates, |path| {
            visited.borrow_mut().push(path.to_owned());
            Err(errors.borrow_mut().next().unwrap())
        });
        assert_eq!(result, Errno::EACCES);
        assert_eq!(visited.borrow().len(), 3);

        let visited = RefCell::new(Vec::new());
        let result = try_exec_candidates(&candidates, |path| {
            visited.borrow_mut().push(path.to_owned());
            Err(Errno::ENOEXEC)
        });
        assert_eq!(result, Errno::ENOEXEC);
        assert_eq!(visited.borrow().len(), 1);
    }
}
