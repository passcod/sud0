use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use thiserror::Error;
use zbus::Connection;
use zbus::zvariant::Optional;

use crate::auth_agent::{AuthenticationAgent, AuthenticationAgentError};
use crate::client_request::PreparedClientRequest;
use crate::constants::BROKER_BUS_NAME;
use crate::{
    InvocationProxy, InvocationStatusWire, IoMode, ManagerProxy, RunWire, StdioWire, WindowSize,
};

const PHASE_RUNNING: u8 = 2;
const PHASE_COMPLETE: u8 = 3;
const OUTCOME_EXITED: u8 = 1;
const OUTCOME_SIGNALED: u8 = 2;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to connect to the system bus: {0}")]
    Connect(zbus::Error),
    #[error("failed to create broker proxy: {0}")]
    Proxy(zbus::Error),
    #[error("failed to communicate with the privilege broker: {0}")]
    Broker(zbus::Error),
    #[error(transparent)]
    AuthenticationAgent(#[from] AuthenticationAgentError),
    #[error("failed to duplicate standard descriptor: {0}")]
    DuplicateStdio(rustix::io::Errno),
    #[error("broker returned an invalid invocation status")]
    InvalidStatus,
    #[error("authorization was denied")]
    Denied,
    #[error("invocation was cancelled")]
    Cancelled,
    #[error("privilege broker failed during {0}")]
    InvocationFailed(String),
}

pub struct BrokerClient {
    connection: Connection,
}

pub struct Invocation {
    proxy: InvocationProxy<'static>,
    cleanup_needed: AtomicBool,
}

pub enum Startup {
    Running,
    Terminal(InvocationStatusWire),
}

impl BrokerClient {
    pub async fn connect() -> Result<Self, ClientError> {
        let connection = Connection::system().await.map_err(ClientError::Connect)?;
        Ok(Self { connection })
    }

    pub async fn run(
        &self,
        prepared: PreparedClientRequest,
        initial_size: Option<WindowSize>,
        allow_interaction: bool,
    ) -> Result<(Invocation, Startup), ClientError> {
        let mode = prepared.request.io_mode();
        let stdio = match mode {
            IoMode::Pty => StdioWire::pty(),
            IoMode::Pipe => StdioWire::pipe(
                duplicate_cloexec(std::io::stdin().as_fd())?,
                duplicate_cloexec(std::io::stdout().as_fd())?,
                duplicate_cloexec(std::io::stderr().as_fd())?,
            ),
        };
        let request = prepared.request.encode();
        let wire = RunWire {
            request,
            description: Optional::from(
                prepared
                    .description
                    .as_ref()
                    .map(|description| description.as_str().to_owned()),
            ),
            cwd: prepared.cwd.into_owned_fd().into(),
            stdio,
            allow_interaction,
            window_size: Optional::from(initial_size),
        };
        let (agent, agent_error) = start_agent(allow_interaction).await;
        let setup = async {
            let manager = ManagerProxy::new(&self.connection)
                .await
                .map_err(ClientError::Proxy)?;
            let path = manager.run(wire).await.map_err(ClientError::Broker)?;
            let proxy = InvocationProxy::builder(&self.connection)
                .destination(BROKER_BUS_NAME)
                .and_then(|builder| builder.path(path))
                .map_err(ClientError::Proxy)?
                .build()
                .await
                .map_err(ClientError::Proxy)?;
            let invocation = Invocation {
                proxy,
                cleanup_needed: AtomicBool::new(true),
            };
            let startup = invocation.wait_for_startup().await;
            Ok::<_, ClientError>((invocation, startup))
        }
        .await;
        if let Some(agent) = agent {
            agent.stop().await;
        }
        let (invocation, startup) = setup?;
        match startup {
            Ok(Startup::Running) => Ok((invocation, Startup::Running)),
            Ok(Startup::Terminal(status)) => {
                if let Some(error) = agent_error
                    && status.phase == 4
                    && status.error_category == "authorization"
                {
                    return Err(ClientError::AuthenticationAgent(error));
                }
                if should_drain_completed_pty(mode, &status) {
                    Ok((invocation, Startup::Running))
                } else {
                    Ok((invocation, Startup::Terminal(status)))
                }
            }
            Err(error) => {
                invocation.cancel().await;
                let _ = invocation.wait().await;
                Err(error)
            }
        }
    }
}

fn should_drain_completed_pty(mode: IoMode, status: &InvocationStatusWire) -> bool {
    mode == IoMode::Pty && status.phase == PHASE_COMPLETE
}

impl Invocation {
    pub async fn wait_for_startup(&self) -> Result<Startup, ClientError> {
        loop {
            let status = self.proxy.status().await.map_err(ClientError::Broker)?;
            if status.phase == PHASE_RUNNING {
                return Ok(Startup::Running);
            }
            if status.is_terminal() {
                return Ok(Startup::Terminal(status));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits for authoritative broker completion.
    ///
    /// The broker's `Wait` operation also marks the invocation released and schedules object
    /// removal, so a successful return disarms client-side cleanup.
    pub async fn wait(&self) -> Result<InvocationStatusWire, ClientError> {
        let status = self.proxy.wait().await.map_err(ClientError::Broker)?;
        self.cleanup_needed.store(false, Ordering::Release);
        Ok(status)
    }

    pub async fn cancel(&self) {
        let _ = self.proxy.cancel().await;
    }

    pub async fn take_pty(&self) -> Result<OwnedFd, ClientError> {
        self.proxy
            .take_pty()
            .await
            .map(OwnedFd::from)
            .map_err(ClientError::Broker)
    }

    pub async fn set_window_size(&self, size: WindowSize) -> Result<(), ClientError> {
        self.proxy
            .set_window_size(size)
            .await
            .map_err(ClientError::Broker)
    }
}

impl Drop for Invocation {
    fn drop(&mut self) {
        if !self.cleanup_needed.swap(false, Ordering::AcqRel) {
            return;
        }
        let proxy = self.proxy.clone();
        tokio::spawn(async move {
            let _ = proxy.cancel().await;
            let _ = proxy.wait().await;
        });
    }
}

pub fn exit_code(status: &InvocationStatusWire) -> Result<u8, ClientError> {
    if !status.is_terminal() {
        return Err(ClientError::InvalidStatus);
    }
    if status.phase == PHASE_COMPLETE && status.outcome == OUTCOME_EXITED {
        return u8::try_from(status.status).map_err(|_| ClientError::InvalidStatus);
    }
    if status.phase == PHASE_COMPLETE && status.outcome == OUTCOME_SIGNALED {
        if !(1..=127).contains(&status.signal) {
            return Err(ClientError::InvalidStatus);
        }
        return Ok((128 + status.signal) as u8);
    }
    match status.phase {
        5 => Err(ClientError::Cancelled),
        6 => Err(ClientError::Denied),
        _ => Err(ClientError::InvocationFailed(status.error_category.clone())),
    }
}

fn duplicate_cloexec(fd: impl AsFd) -> Result<OwnedFd, ClientError> {
    rustix::io::fcntl_dupfd_cloexec(fd, 3).map_err(ClientError::DuplicateStdio)
}

async fn start_agent(
    allow_interaction: bool,
) -> (
    Option<AuthenticationAgent>,
    Option<AuthenticationAgentError>,
) {
    if !allow_interaction {
        return (None, None);
    }
    match AuthenticationAgent::start().await {
        Ok(agent) => (Some(agent), None),
        Err(error) => (None, Some(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(phase: u8, outcome: u8, code: i32, signal: i32) -> InvocationStatusWire {
        InvocationStatusWire {
            phase,
            outcome,
            status: code,
            signal,
            error_category: String::new(),
        }
    }

    #[test]
    fn maps_exit_and_signal_statuses() {
        assert_eq!(exit_code(&status(3, 1, 42, 0)).unwrap(), 42);
        assert_eq!(exit_code(&status(3, 1, 255, 0)).unwrap(), 255);
        assert_eq!(exit_code(&status(3, 2, 0, 9)).unwrap(), 137);
        assert!(matches!(
            exit_code(&status(6, 0, 0, 0)),
            Err(ClientError::Denied)
        ));
        assert!(matches!(
            exit_code(&status(5, 0, 0, 0)),
            Err(ClientError::Cancelled)
        ));
    }

    #[test]
    fn completed_pty_is_drained_after_startup_phase_race() {
        let complete = status(PHASE_COMPLETE, OUTCOME_EXITED, 0, 0);
        assert!(should_drain_completed_pty(IoMode::Pty, &complete));
        assert!(!should_drain_completed_pty(IoMode::Pipe, &complete));
        assert!(!should_drain_completed_pty(
            IoMode::Pty,
            &status(4, 0, 0, 0)
        ));
    }
}
