use std::os::fd::{AsFd, OwnedFd};

use futures_util::StreamExt;
use nix::pty::{Winsize, openpty};
use thiserror::Error;
use tokio::sync::{oneshot, watch};
use zbus::zvariant::{Fd, OwnedObjectPath, Value};

use crate::broker_auth::CancellationReason;
use crate::constants::{CWD_FD_NAME, EXECUTOR_PATH, REQUEST_FD_NAME, TRANSIENT_UNIT_DESCRIPTION};
use crate::{
    FrozenRequest, PreparedIo, SealedRequestError, SealedRequestFd, WindowSize, WorkingDirectoryFd,
};

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_blocking = false
)]
trait SystemdManager {
    fn subscribe(&self) -> zbus::Result<()>;
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn unref_unit(&self, name: &str) -> zbus::Result<()>;
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: Vec<(&str, Value<'_>)>,
        aux: Vec<(&str, Vec<(&str, Value<'_>)>)>,
    ) -> zbus::Result<OwnedObjectPath>;

    #[zbus(signal)]
    fn job_removed(
        &self,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;
}

#[zbus::proxy(interface = "org.freedesktop.systemd1.Unit", gen_blocking = false)]
trait SystemdUnit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

#[zbus::proxy(interface = "org.freedesktop.systemd1.Service", gen_blocking = false)]
trait SystemdService {
    #[zbus(property)]
    fn result(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn exec_main_code(&self) -> zbus::Result<i32>;
    #[zbus(property)]
    fn exec_main_status(&self) -> zbus::Result<i32>;
}

/// A service completion value that preserves normal exits and signals without shell conventions.
#[derive(Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    Exited(i32),
    Signaled(i32),
    ServiceFailure,
}

/// Resources retained through authorization and consumed exactly once for launch.
#[derive(Debug)]
pub struct LaunchRequest {
    request: FrozenRequest,
    cwd: WorkingDirectoryFd,
    io: PreparedIo,
}

impl LaunchRequest {
    pub const fn new(request: FrozenRequest, cwd: WorkingDirectoryFd, io: PreparedIo) -> Self {
        Self { request, cwd, io }
    }

    fn prepare(self) -> Result<PreparedLaunch, LaunchError> {
        // This is intentionally the first sealed-request creation point. Callers construct a
        // LaunchRequest only after authorization and the final owner recheck.
        let sealed = SealedRequestFd::create(&self.request)?;
        let io = match self.io {
            PreparedIo::Pty { initial_size } => {
                let winsize = Winsize {
                    ws_row: initial_size.rows,
                    ws_col: initial_size.columns,
                    ws_xpixel: initial_size.x_pixels,
                    ws_ypixel: initial_size.y_pixels,
                };
                let pty = openpty(Some(&winsize), None).map_err(LaunchError::OpenPty)?;
                LaunchIo::Pty {
                    master: pty.master,
                    slave: pty.slave,
                }
            }
            PreparedIo::Pipe {
                stdin,
                stdout,
                stderr,
            } => LaunchIo::Pipe {
                stdin,
                stdout,
                stderr,
            },
        };
        Ok(PreparedLaunch {
            sealed,
            cwd: self.cwd,
            io,
        })
    }
}

/// Applies a validated size to a retained PTY master.
pub fn set_pty_window_size(fd: &OwnedFd, size: WindowSize) -> Result<(), LaunchError> {
    let size = size
        .validate()
        .map_err(|_| LaunchError::InvalidWindowSize)?;
    let size = rustix::termios::Winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: size.x_pixels,
        ws_ypixel: size.y_pixels,
    };
    rustix::termios::tcsetwinsize(fd, size).map_err(LaunchError::SetWindowSize)
}

#[derive(Debug)]
struct PreparedLaunch {
    sealed: SealedRequestFd,
    cwd: WorkingDirectoryFd,
    io: LaunchIo,
}

#[derive(Debug)]
enum LaunchIo {
    Pty {
        master: OwnedFd,
        slave: OwnedFd,
    },
    Pipe {
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    },
}

impl LaunchIo {
    fn standard_fds(&self) -> [&OwnedFd; 3] {
        match self {
            Self::Pty { slave, .. } => [slave, slave, slave],
            Self::Pipe {
                stdin,
                stdout,
                stderr,
            } => [stdin, stdout, stderr],
        }
    }
}

fn transient_properties(prepared: &PreparedLaunch) -> Vec<(&'static str, Value<'_>)> {
    let [stdin, stdout, stderr] = prepared.io.standard_fds();
    let exec_start = vec![(
        EXECUTOR_PATH.to_owned(),
        vec![EXECUTOR_PATH.to_owned()],
        false,
    )];
    let extra_fds = vec![
        (
            Fd::from(prepared.sealed.as_fd()),
            REQUEST_FD_NAME.to_owned(),
        ),
        (Fd::from(prepared.cwd.as_fd()), CWD_FD_NAME.to_owned()),
    ];
    vec![
        ("Description", Value::new(TRANSIENT_UNIT_DESCRIPTION)),
        ("Type", Value::new("exec")),
        ("ExecStart", Value::new(exec_start)),
        ("User", Value::new("root")),
        (
            "StandardInputFileDescriptor",
            Value::new(Fd::from(stdin.as_fd())),
        ),
        (
            "StandardOutputFileDescriptor",
            Value::new(Fd::from(stdout.as_fd())),
        ),
        (
            "StandardErrorFileDescriptor",
            Value::new(Fd::from(stderr.as_fd())),
        ),
        ("ExtraFileDescriptors", Value::new(extra_fds)),
        ("AddRef", Value::new(true)),
        ("CollectMode", Value::new("inactive-or-failed")),
    ]
}

/// Successful startup handle. The PTY master is present only for PTY requests and is not exposed
/// until systemd reports the `Type=exec` start job as `done`.
#[derive(Debug)]
pub struct StartedUnit {
    pub pty_master: Option<OwnedFd>,
    pub completion: UnitCompletion,
}

#[derive(Debug)]
pub struct UnitCompletion {
    receiver: oneshot::Receiver<Result<CommandOutcome, LaunchError>>,
}

impl UnitCompletion {
    pub async fn wait(self) -> Result<CommandOutcome, LaunchError> {
        self.receiver.await.map_err(|_| LaunchError::TrackerLost)?
    }
}

/// Direct systemd transient-service launcher sharing one stable system-bus connection.
#[derive(Debug, Clone)]
pub struct SystemdLauncher {
    connection: zbus::Connection,
}

impl SystemdLauncher {
    /// Creates a launcher and subscribes this connection to systemd manager signals exactly once.
    ///
    /// systemd tracks subscriptions by D-Bus sender and rejects duplicate `Subscribe` calls, so the
    /// launcher must be constructed once for the broker connection and then cloned for requests.
    pub async fn new(connection: zbus::Connection) -> Result<Self, LaunchError> {
        let manager = SystemdManagerProxy::new(&connection)
            .await
            .map_err(LaunchError::Systemd)?;
        manager.subscribe().await.map_err(LaunchError::Systemd)?;
        Ok(Self { connection })
    }

    pub async fn launch(
        &self,
        request: LaunchRequest,
        mut cancellation: watch::Receiver<Option<CancellationReason>>,
    ) -> Result<StartedUnit, LaunchError> {
        if cancellation.borrow().is_some() {
            return Err(LaunchError::Cancelled);
        }
        let prepared = request.prepare()?;
        let unit_name = random_unit_name()?;
        let manager = SystemdManagerProxy::new(&self.connection)
            .await
            .map_err(LaunchError::Systemd)?;
        let mut jobs = manager
            .receive_job_removed()
            .await
            .map_err(LaunchError::Systemd)?;

        let properties = transient_properties(&prepared);
        let job = manager
            .start_transient_unit(&unit_name, "fail", properties, Vec::new())
            .await
            .map_err(LaunchError::Systemd)?;

        let startup_result = loop {
            tokio::select! {
                biased;
                changed = cancellation.changed() => {
                    let _ = changed;
                    match manager.stop_unit(&unit_name, "replace").await {
                        Ok(_) => break Err(LaunchError::Cancelled),
                        Err(error) => break Err(LaunchError::Systemd(error)),
                    }
                }
                signal = jobs.next() => {
                    let Some(signal) = signal else {
                        break Err(LaunchError::SignalStreamEnded);
                    };
                    let args = match signal.args() {
                        Ok(args) => args,
                        Err(error) => break Err(LaunchError::Systemd(error)),
                    };
                    if args.job() == &job && args.unit() == &unit_name {
                        if args.result() == "done" {
                            break Ok(());
                        }
                        break Err(LaunchError::StartupJob);
                    }
                }
            }
        };

        let unit_path = match manager.get_unit(&unit_name).await {
            Ok(path) => path,
            Err(error) => {
                let primary = startup_result.err().unwrap_or(LaunchError::Systemd(error));
                let stop = manager.stop_unit(&unit_name, "replace").await;
                let unref = manager.unref_unit(&unit_name).await;
                if let Err(cleanup) = stop {
                    return Err(LaunchError::Cleanup(cleanup));
                }
                if let Err(cleanup) = unref {
                    return Err(LaunchError::Cleanup(cleanup));
                }
                return Err(primary);
            }
        };
        if let Err(error) = startup_result {
            let _ = track_completion(&self.connection, &unit_name, unit_path, cancellation).await;
            return Err(error);
        }
        let pty_master = match prepared.io {
            LaunchIo::Pty { master, .. } => Some(master),
            LaunchIo::Pipe { .. } => None,
        };
        let connection = self.connection.clone();
        let tracker_name = unit_name.clone();
        let (completion_tx, completion) = oneshot::channel();
        tokio::spawn(async move {
            let result =
                track_completion(&connection, &tracker_name, unit_path, cancellation).await;
            let _ = completion_tx.send(result);
        });

        Ok(StartedUnit {
            pty_master,
            completion: UnitCompletion {
                receiver: completion,
            },
        })
    }
}

async fn track_completion(
    connection: &zbus::Connection,
    unit_name: &str,
    unit_path: OwnedObjectPath,
    cancellation: watch::Receiver<Option<CancellationReason>>,
) -> Result<CommandOutcome, LaunchError> {
    let manager = SystemdManagerProxy::new(connection)
        .await
        .map_err(LaunchError::Systemd)?;
    let outcome =
        track_completion_inner(connection, &manager, unit_name, unit_path, cancellation).await;
    let stop_after_error = if outcome.is_err() {
        manager
            .stop_unit(unit_name, "replace")
            .await
            .map(|_| ())
            .map_err(LaunchError::Cleanup)
    } else {
        Ok(())
    };

    // The AddRef acquired by StartTransientUnit is released from this single epilogue, after the
    // inner tracker has captured final properties or reported why it could not do so.
    let unref = manager
        .unref_unit(unit_name)
        .await
        .map_err(LaunchError::Systemd);
    match (outcome, stop_after_error, unref) {
        (Ok(outcome), Ok(()), Ok(())) => Ok(outcome),
        (Err(error), Ok(()), _) => Err(error),
        (_, Err(error), _) | (_, _, Err(error)) => Err(error),
    }
}

async fn track_completion_inner(
    connection: &zbus::Connection,
    manager: &SystemdManagerProxy<'_>,
    unit_name: &str,
    unit_path: OwnedObjectPath,
    mut cancellation: watch::Receiver<Option<CancellationReason>>,
) -> Result<CommandOutcome, LaunchError> {
    let unit = SystemdUnitProxy::builder(connection)
        .destination("org.freedesktop.systemd1")
        .map_err(LaunchError::Systemd)?
        .path(unit_path.clone())
        .map_err(LaunchError::Systemd)?
        .build()
        .await
        .map_err(LaunchError::Systemd)?;
    let service = SystemdServiceProxy::builder(connection)
        .destination("org.freedesktop.systemd1")
        .map_err(LaunchError::Systemd)?
        .path(unit_path)
        .map_err(LaunchError::Systemd)?
        .build()
        .await
        .map_err(LaunchError::Systemd)?;
    let mut state_changes = unit.receive_active_state_changed().await;
    let mut stop_requested = false;

    loop {
        let state = unit.active_state().await.map_err(LaunchError::Systemd)?;
        if state == "inactive" || state == "failed" {
            let result = service.result().await.map_err(LaunchError::Systemd)?;
            let code = service
                .exec_main_code()
                .await
                .map_err(LaunchError::Systemd)?;
            let status = service
                .exec_main_status()
                .await
                .map_err(LaunchError::Systemd)?;
            return Ok(map_service_outcome(&result, code, status));
        }

        tokio::select! {
            changed = cancellation.changed(), if !stop_requested => {
                let _ = changed;
                stop_requested = true;
                manager
                    .stop_unit(unit_name, "replace")
                    .await
                    .map_err(LaunchError::Systemd)?;
            }
            update = state_changes.next() => {
                update.ok_or(LaunchError::SignalStreamEnded)?;
                // Signals are wakeups only; the next iteration rereads authoritative state.
            }
        }
    }
}

pub fn map_service_outcome(result: &str, code: i32, status: i32) -> CommandOutcome {
    match (result, code) {
        ("success" | "exit-code", libc::CLD_EXITED) => CommandOutcome::Exited(status),
        ("success" | "signal", libc::CLD_KILLED) | ("success" | "core-dump", libc::CLD_DUMPED) => {
            CommandOutcome::Signaled(status)
        }
        _ => CommandOutcome::ServiceFailure,
    }
}

fn random_unit_name() -> Result<String, LaunchError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(LaunchError::Random)?;
    Ok(format!("sud0-{}.service", hex::encode(random)))
}

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error("failed to create sealed request")]
    Seal(#[from] SealedRequestError),
    #[error("failed to allocate PTY: {0}")]
    OpenPty(nix::errno::Errno),
    #[error("PTY dimensions must have nonzero rows and columns")]
    InvalidWindowSize,
    #[error("failed to set PTY window size: {0}")]
    SetWindowSize(rustix::io::Errno),
    #[error("failed to obtain a random unit identifier: {0}")]
    Random(getrandom::Error),
    #[error("systemd operation failed")]
    Systemd(#[source] zbus::Error),
    #[error("systemd cleanup failed")]
    Cleanup(#[source] zbus::Error),
    #[error("systemd signal stream ended")]
    SignalStreamEnded,
    #[error("transient service startup failed")]
    StartupJob,
    #[error("invocation was cancelled")]
    Cancelled,
    #[error("unit completion tracker stopped unexpectedly")]
    TrackerLost,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::IoMode;

    fn request(mode: IoMode) -> FrozenRequest {
        FrozenRequest::new(vec!["/usr/bin/true".to_owned()], Vec::new(), mode).unwrap()
    }

    fn cwd() -> WorkingDirectoryFd {
        WorkingDirectoryFd::try_from(OwnedFd::from(File::open("/").unwrap())).unwrap()
    }

    #[test]
    fn pty_is_allocated_with_requested_initial_size_after_launch_preparation() {
        let prepared = LaunchRequest::new(
            request(IoMode::Pty),
            cwd(),
            PreparedIo::Pty {
                initial_size: WindowSize {
                    rows: 31,
                    columns: 97,
                    x_pixels: 0,
                    y_pixels: 0,
                },
            },
        )
        .prepare()
        .unwrap();
        let LaunchIo::Pty { master, slave } = prepared.io else {
            panic!("expected PTY");
        };
        let actual = rustix::termios::tcgetwinsize(&slave).unwrap();
        assert_eq!(actual.ws_row, 31);
        assert_eq!(actual.ws_col, 97);
        assert!(nix::unistd::isatty(&master).unwrap());
        assert_ne!(master.as_raw_fd(), slave.as_raw_fd());
    }

    #[test]
    fn pipe_descriptors_are_preserved_in_exact_order() {
        let descriptors: [OwnedFd; 3] = std::array::from_fn(|_| {
            OwnedFd::from(
                File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .unwrap(),
            )
        });
        let raw = descriptors.each_ref().map(AsRawFd::as_raw_fd);
        let [stdin, stdout, stderr] = descriptors;
        let prepared = LaunchRequest::new(
            request(IoMode::Pipe),
            cwd(),
            PreparedIo::Pipe {
                stdin,
                stdout,
                stderr,
            },
        )
        .prepare()
        .unwrap();
        assert_eq!(prepared.io.standard_fds().map(AsRawFd::as_raw_fd), raw);
    }

    #[test]
    fn service_result_mapping_preserves_exit_and_signal_semantics() {
        assert_eq!(
            map_service_outcome("success", libc::CLD_EXITED, 0),
            CommandOutcome::Exited(0)
        );
        assert_eq!(
            map_service_outcome("exit-code", libc::CLD_EXITED, 23),
            CommandOutcome::Exited(23)
        );
        assert_eq!(
            map_service_outcome("success", libc::CLD_KILLED, libc::SIGTERM),
            CommandOutcome::Signaled(libc::SIGTERM)
        );
        assert_eq!(
            map_service_outcome("success", libc::CLD_DUMPED, libc::SIGSEGV),
            CommandOutcome::Signaled(libc::SIGSEGV)
        );
        assert_eq!(
            map_service_outcome("protocol", 0, 0),
            CommandOutcome::ServiceFailure
        );
    }

    #[test]
    fn generated_names_are_collision_resistant_service_units() {
        let first = random_unit_name().unwrap();
        let second = random_unit_name().unwrap();
        assert!(first.starts_with("sud0-"));
        assert!(first.ends_with(".service"));
        assert_ne!(first, second);
        assert!(!first.contains('/'));
    }

    #[test]
    fn fixed_property_contract_has_exact_order_and_wire_types() {
        let fd = || {
            OwnedFd::from(
                File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .unwrap(),
            )
        };
        let prepared = LaunchRequest::new(
            request(IoMode::Pipe),
            cwd(),
            PreparedIo::Pipe {
                stdin: fd(),
                stdout: fd(),
                stderr: fd(),
            },
        )
        .prepare()
        .unwrap();
        let properties = transient_properties(&prepared);
        let actual: Vec<_> = properties
            .iter()
            .map(|(name, value)| (*name, value.value_signature().to_string()))
            .collect();
        assert_eq!(
            actual,
            [
                ("Description", "s".to_owned()),
                ("Type", "s".to_owned()),
                ("ExecStart", "a(sasb)".to_owned()),
                ("User", "s".to_owned()),
                ("StandardInputFileDescriptor", "h".to_owned()),
                ("StandardOutputFileDescriptor", "h".to_owned()),
                ("StandardErrorFileDescriptor", "h".to_owned()),
                ("ExtraFileDescriptors", "a(hs)".to_owned()),
                ("AddRef", "b".to_owned()),
                ("CollectMode", "s".to_owned()),
            ]
        );
        assert_eq!(TRANSIENT_UNIT_DESCRIPTION, "sud0 privileged command");
        assert_eq!(EXECUTOR_PATH, "/usr/lib/sud0/sud0-exec");
    }

    #[test]
    fn resize_uses_safe_terminal_api_and_rejects_zero_dimensions() {
        let pty = openpty(None, None).unwrap();
        let size = WindowSize {
            rows: 42,
            columns: 123,
            x_pixels: 0,
            y_pixels: 0,
        };
        set_pty_window_size(&pty.master, size).unwrap();
        let actual = rustix::termios::tcgetwinsize(&pty.slave).unwrap();
        assert_eq!(actual.ws_row, 42);
        assert_eq!(actual.ws_col, 123);
        assert!(matches!(
            set_pty_window_size(&pty.master, WindowSize { rows: 0, ..size }),
            Err(LaunchError::InvalidWindowSize)
        ));
    }
}
