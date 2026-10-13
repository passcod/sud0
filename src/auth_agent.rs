use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::process::{ExitStatus, Stdio};

use nix::fcntl::OFlag;
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, pipe2};
use rustix::io::ioctl_fionclex;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};

const PKTTYAGENT_PATH: &str = "/usr/bin/pkttyagent";

pub struct AuthenticationAgent {
    child: Option<Child>,
}

#[derive(Debug, Error)]
pub enum AuthenticationAgentError {
    #[error("failed to create authentication-agent notification pipe: {0}")]
    Pipe(nix::errno::Errno),
    #[error("failed to monitor authentication-agent notification pipe: {0}")]
    Monitor(io::Error),
    #[error("no controlling terminal is available for {PKTTYAGENT_PATH}")]
    NoControllingTerminal,
    #[error("failed to start {PKTTYAGENT_PATH}: {0}")]
    Spawn(io::Error),
    #[error("authentication agent exited before registering ({0})")]
    EarlyExit(ExitStatus),
    #[error("failed while waiting for authentication-agent registration: {0}")]
    Registration(io::Error),
}

impl AuthenticationAgent {
    /// Starts a fallback agent for the invoking parent process and waits until it has registered.
    ///
    /// The broker authorizes this same parent process so sequential sud0 children share polkit's
    /// native process-family retention scope. `--fallback` makes a session agent preferable while
    /// retaining this agent for terminal-only sessions. Callers may retain a startup error while
    /// trying broker authorization: a desktop
    /// agent can still satisfy it, but the startup error gives a clear cause if authorization fails.
    pub async fn start() -> Result<Self, AuthenticationAgentError> {
        let terminal = std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ENXIO) {
                    AuthenticationAgentError::NoControllingTerminal
                } else {
                    AuthenticationAgentError::Spawn(error)
                }
            })?;
        let terminal_out = terminal
            .try_clone()
            .map_err(AuthenticationAgentError::Spawn)?;
        let terminal_err = terminal
            .try_clone()
            .map_err(AuthenticationAgentError::Spawn)?;
        let (read_end, write_end) =
            pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).map_err(AuthenticationAgentError::Pipe)?;
        let notify_fd = write_end.as_raw_fd();
        let read_end = AsyncFd::new(read_end).map_err(AuthenticationAgentError::Monitor)?;
        let parent_pid = nix::unistd::getppid();
        if parent_pid.as_raw() <= 1 {
            return Err(AuthenticationAgentError::NoControllingTerminal);
        }
        let mut command = Command::new(PKTTYAGENT_PATH);
        // Termination is normally explicit through `ChildGuard` or
        // `AuthenticationAgent`; kill-on-drop only covers the residual edge
        // where a drop path can neither await nor re-spawn a reaper because
        // the runtime is shutting down.
        command
            .kill_on_drop(true)
            .arg("--fallback")
            .arg(format!("--process={}", parent_pid.as_raw()))
            .arg(format!("--notify-fd={notify_fd}"))
            .stdin(Stdio::from(terminal))
            .stdout(Stdio::from(terminal_out))
            .stderr(Stdio::from(terminal_err));

        // SAFETY: The closure runs in the forked child between fork and exec.
        // `notify_fd` is a plain integer copied before the fork. At the fork the
        // kernel copies the parent's descriptor table into the child, so
        // descriptor `notify_fd` is open in this child; the parent keeps the
        // only Rust owner (`write_end`, held live by this suspended future
        // until `spawn` returns) and descriptor-table changes in the child
        // cannot affect the parent. `BorrowedFd::borrow_raw` therefore wraps
        // an open descriptor for the duration of one call. The typed
        // `ioctl_fionclex` operation clears the close-on-exec flag so
        // pkttyagent inherits exactly this notification descriptor across
        // exec; POSIX does not list `ioctl` as async-signal-safe, so this
        // release's exact linux_raw lowering — an inline, nonallocating,
        // nonlocking `ioctl` syscall with a null third argument — is recorded
        // as a trusted proposition in docs/tcb.md. The error conversion uses
        // the errno value already returned by the syscall, never libc errno
        // storage in this child. Every spawn exit is covered: a spawn error
        // before or at the fork never runs the closure; a closure error is
        // reported to the parent through the standard library's post-fork
        // error pipe, which reaps the intermediate child before returning the
        // error; a closure panic aborts only the child (the standard library
        // arms `panic::always_abort` in the forked child); cancellation or an
        // error after a successful spawn cannot reach this closure again.
        unsafe {
            command.pre_exec(move || {
                let write_end = BorrowedFd::borrow_raw(notify_fd);
                ioctl_fionclex(write_end)
                    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
            });
        }

        let child = command.spawn().map_err(AuthenticationAgentError::Spawn)?;
        drop(write_end);
        let mut child = ChildGuard::arm(child);

        let registration = wait_for_registration(&read_end);
        tokio::pin!(registration);
        tokio::select! {
            result = &mut registration => {
                result.map_err(AuthenticationAgentError::Registration)?;
                if let Some(status) = child.try_wait().map_err(AuthenticationAgentError::Registration)? {
                    return Err(AuthenticationAgentError::EarlyExit(status));
                }
            }
            result = child.wait() => {
                let status = result.map_err(AuthenticationAgentError::Registration)?;
                return Err(AuthenticationAgentError::EarlyExit(status));
            }
        }

        Ok(Self {
            child: Some(child.transfer()),
        })
    }

    pub async fn stop(mut self) {
        if let Some(child) = self.child.take() {
            terminate_and_reap(child).await;
        }
    }
}

/// Holds the spawned agent child from `spawn` until ownership transfers into
/// `AuthenticationAgent`.
///
/// Every drop path that does not transfer ownership terminates the child and
/// reaps it, so a registration failure, a cancelled `start` future, or a
/// panic unwind can never leave a live or zombie `pkttyagent` behind.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn arm(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Disarms the guard, transferring ownership to the long-lived caller.
    fn transfer(mut self) -> Child {
        self.child.take().expect("armed guard holds a child")
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child
            .as_mut()
            .expect("armed guard holds a child")
            .wait()
            .await
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .expect("armed guard holds a child")
            .try_wait()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(terminate_and_reap(child));
        } else {
            terminate_and_reap_blocking(&mut child);
        }
    }
}

async fn wait_for_registration(read_end: &AsyncFd<OwnedFd>) -> io::Result<()> {
    loop {
        let mut ready = read_end.readable().await?;
        match ready.try_io(|fd| {
            let mut byte = [0_u8; 1];
            match nix::unistd::read(fd.get_ref(), &mut byte) {
                Ok(0) => Ok(()),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authentication agent wrote unexpected notification data",
                )),
                Err(error) => Err(io::Error::from_raw_os_error(error as i32)),
            }
        }) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn terminate_and_reap(mut child: Child) {
    terminate(&mut child);
    let _ = child.wait().await;
}

/// Terminates the child unless it has already exited, then reaps it without a
/// runtime context. Used only on drop paths that cannot await.
fn terminate_and_reap_blocking(child: &mut Child) {
    terminate(child);
    if let Some(id) = child.id() {
        let _ = nix::sys::wait::waitpid(Pid::from_raw(id as i32), None);
    }
}

fn terminate(child: &mut Child) {
    if let Some(id) = child.id()
        && child.try_wait().ok().flatten().is_none()
    {
        let _ = kill(Pid::from_raw(id as i32), Signal::SIGTERM);
    }
}

impl Drop for AuthenticationAgent {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(terminate_and_reap(child));
        } else {
            terminate_and_reap_blocking(&mut child);
        }
    }
}
