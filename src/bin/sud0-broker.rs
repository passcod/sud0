use std::process::ExitCode;

use sud0::constants::{BROKER_BUS_NAME, BROKER_MANAGER_PATH};
use sud0::{BrokerManager, SystemdLauncher};
use tokio::sync::watch;
use tracing::{error, info};
use zbus::connection::Builder;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .without_time()
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(error = %error, "broker stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), BrokerError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(BrokerError::NotRoot);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection = Builder::system()?.name(BROKER_BUS_NAME)?.build().await?;
    let launcher = SystemdLauncher::new(connection.clone()).await?;
    connection
        .object_server()
        .at(
            BROKER_MANAGER_PATH,
            BrokerManager::new(connection.clone(), launcher, shutdown_rx),
        )
        .await?;

    info!("broker ready");
    wait_for_shutdown().await?;
    let _ = shutdown_tx.send(true);
    info!("broker shutting down");
    Ok(())
}

async fn wait_for_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

#[derive(Debug, thiserror::Error)]
enum BrokerError {
    #[error("sud0-broker must run as root")]
    NotRoot,
    #[error("D-Bus broker setup failed")]
    ZBus(#[from] zbus::Error),
    #[error("systemd launcher setup failed")]
    Launcher(#[from] sud0::LaunchError),
    #[error("failed to install shutdown signal handlers")]
    Signal(#[from] std::io::Error),
}
