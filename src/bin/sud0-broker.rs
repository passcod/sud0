use std::process::ExitCode;

use sud0::constants::{BROKER_BUS_NAME, BROKER_MANAGER_PATH, PROMPT_TEMPLATE_PATH};
use sud0::{BrokerManager, PromptTemplate, SystemdLauncher};
use tokio::sync::watch;
use zbus::connection::Builder;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sud0-broker: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), BrokerError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(BrokerError::NotRoot);
    }

    let template =
        std::fs::read_to_string(PROMPT_TEMPLATE_PATH).map_err(BrokerError::TemplateIo)?;
    let template = PromptTemplate::parse(template)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let connection = Builder::system()?.build().await?;
    let launcher = SystemdLauncher::new(connection.clone()).await?;
    connection
        .object_server()
        .at(
            BROKER_MANAGER_PATH,
            BrokerManager::new(connection.clone(), launcher, template, shutdown_rx),
        )
        .await?;
    connection.request_name(BROKER_BUS_NAME).await?;

    wait_for_shutdown().await?;
    let _ = shutdown_tx.send(true);
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
    #[error("failed to read root-owned prompt template")]
    TemplateIo(std::io::Error),
    #[error("invalid root-owned prompt template")]
    Template(#[from] sud0::PromptTemplateError),
    #[error("D-Bus broker setup failed")]
    ZBus(#[from] zbus::Error),
    #[error("systemd launcher setup failed")]
    Launcher(#[from] sud0::LaunchError),
    #[error("failed to install shutdown signal handlers")]
    Signal(#[from] std::io::Error),
}
