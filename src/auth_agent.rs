use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{ExitStatus, Stdio};

use nix::fcntl::OFlag;
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, pipe2};
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
            pipe2(OFlag::O_CLOEXEC).map_err(AuthenticationAgentError::Pipe)?;
        let notify_fd = write_end.as_raw_fd();
        let read_end = AsyncFd::new(read_end).map_err(AuthenticationAgentError::Monitor)?;
        let parent_pid = nix::unistd::getppid();
        if parent_pid.as_raw() <= 1 {
            return Err(AuthenticationAgentError::NoControllingTerminal);
        }
        let mut command = Command::new(PKTTYAGENT_PATH);
        command
            .arg("--fallback")
            .arg(format!("--process={}", parent_pid.as_raw()))
            .arg(format!("--notify-fd={notify_fd}"))
            .stdin(Stdio::from(terminal))
            .stdout(Stdio::from(terminal_out))
            .stderr(Stdio::from(terminal_err));

        // SAFETY: The closure runs after fork and before exec. `notify_fd` is copied as an integer
        // before spawning and names the still-owned `write_end`; the parent cannot close it until
        // `spawn` returns. `fcntl(F_SETFD)` is async-signal-safe under POSIX, touches only the
        // descriptor-local close-on-exec flag, does not allocate or access shared Rust state, and
        // reports failure through the required `io::Result`. Clearing FD_CLOEXEC is necessary so
        // pkttyagent inherits exactly this notification descriptor across exec.
        unsafe {
            command.pre_exec(move || {
                let result = libc::fcntl(notify_fd, libc::F_SETFD, 0);
                if result == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }

        let mut child = command.spawn().map_err(AuthenticationAgentError::Spawn)?;
        drop(write_end);

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

        Ok(Self { child: Some(child) })
    }

    pub async fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            terminate_and_reap(&mut child).await;
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

async fn terminate_and_reap(child: &mut Child) {
    let Some(id) = child.id() else {
        let _ = child.wait().await;
        return;
    };
    if child.try_wait().ok().flatten().is_none() {
        let _ = kill(Pid::from_raw(id as i32), Signal::SIGTERM);
    }
    let _ = child.wait().await;
}

impl Drop for AuthenticationAgent {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Some(id) = child.id() {
            let _ = kill(Pid::from_raw(id as i32), Signal::SIGTERM);
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}
