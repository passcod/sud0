use std::os::fd::{AsFd, OwnedFd};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use thiserror::Error;
use tokio::signal::unix::{Signal, SignalKind, signal};

use sud0::cli::Cli;
use sud0::client::{BrokerClient, ClientError, Invocation, Startup, exit_code};
use sud0::client_request::{
    ClientRequestError, PreparedClientRequest, choose_io_mode, stdio_are_ttys,
};
use sud0::terminal::{Pump, PumpEvent, TerminalError, TerminalGuard, suspend_process, window_size};
use sud0::{InvocationStatusWire, IoMode};

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Request(#[from] ClientRequestError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error("failed to install {0} signal handler: {1}")]
    Signal(&'static str, std::io::Error),
    #[error("PTY mode requires at least one local terminal descriptor")]
    NoLocalTerminal,
    #[error("failed to duplicate local terminal descriptor: {0}")]
    DuplicateTerminal(rustix::io::Errno),
}

struct Signals {
    winch: Signal,
    term: Signal,
    hup: Signal,
    quit: Signal,
    interrupt: Signal,
    tstp: Signal,
}

enum SignalEvent {
    WindowChange,
    Terminate(i32),
    Suspend,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.command.is_empty() {
        Cli::command().print_help().expect("failed to print help");
        println!();
        return ExitCode::SUCCESS;
    }

    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sud0: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<u8, AppError> {
    let allow_interaction = !cli.non_interactive;
    let client = BrokerClient::connect().await?;
    let tty = stdio_are_ttys();
    let mode = choose_io_mode(cli.pty, cli.pipe, tty);
    let terminal = match mode {
        IoMode::Pty => Some(duplicate_terminal(&tty)?),
        IoMode::Pipe => None,
    };
    let initial_size = terminal
        .as_ref()
        .map(|terminal| window_size(terminal.as_fd()))
        .transpose()?;
    let prepared = PreparedClientRequest::from_cli(cli, mode)?;
    let (invocation, startup) = client
        .run(prepared, initial_size, allow_interaction)
        .await?;
    match startup {
        Startup::Terminal(_) => {
            let status = invocation.wait().await?;
            exit_code(&status).map_err(AppError::Client)
        }
        Startup::Running => match mode {
            IoMode::Pipe => finish_pipe(&invocation).await,
            IoMode::Pty => {
                finish_pty(&invocation, terminal.expect("PTY mode has a terminal")).await
            }
        },
    }
}

async fn finish_pipe(invocation: &Invocation) -> Result<u8, AppError> {
    let mut signals = Signals::new()?;
    let status = tokio::select! {
        status = invocation.wait() => status?,
        caught = signals.termination() => {
            invocation.cancel().await;
            let _ = invocation.wait().await?;
            return Ok(128_u8.saturating_add(caught as u8));
        }
    };
    exit_code(&status).map_err(AppError::Client)
}

async fn finish_pty(invocation: &Invocation, terminal_fd: OwnedFd) -> Result<u8, AppError> {
    let master = invocation.take_pty().await?;
    let mut signals = Signals::new()?;
    let mut terminal = TerminalGuard::enter(terminal_fd.as_fd())?;
    let mut pump = Pump::start(master)?;
    let mut status: Option<InvocationStatusWire> = None;
    let mut input_done = false;
    let mut output_done = false;
    let mut caught_signal = None;
    let mut forwarding_error = None;

    while status.is_none() || !output_done {
        tokio::select! {
            result = invocation.wait(), if status.is_none() => {
                match result {
                    Ok(terminal_status) => status = Some(terminal_status),
                    Err(error) => {
                        forwarding_error = Some(AppError::Client(error));
                        invocation.cancel().await;
                        break;
                    }
                }
            }
            event = pump.next_event(), if !input_done || !output_done => {
                match event {
                    PumpEvent::Input(result) => {
                        input_done = true;
                        if let Err(error) = result {
                            forwarding_error = Some(AppError::Terminal(error));
                            invocation.cancel().await;
                        }
                    }
                    PumpEvent::Output(result) => {
                        output_done = true;
                        if let Err(error) = result {
                            forwarding_error = Some(AppError::Terminal(error));
                            invocation.cancel().await;
                        }
                    }
                }
            }
            event = signals.next_event() => match event {
                SignalEvent::WindowChange => {
                    if let Ok(size) = window_size(terminal_fd.as_fd())
                        && let Err(error) = invocation.set_window_size(size).await
                    {
                        forwarding_error = Some(AppError::Client(error));
                        invocation.cancel().await;
                    }
                }
                SignalEvent::Terminate(caught) => {
                    if caught_signal.is_none() {
                        caught_signal = Some(caught);
                        invocation.cancel().await;
                        pump.stop_input();
                    }
                }
                SignalEvent::Suspend => {
                    suspend_process(&mut terminal)?;
                    if let Ok(size) = window_size(terminal_fd.as_fd()) {
                        invocation.set_window_size(size).await?;
                    }
                }
            }
        }
    }

    pump.stop_input();
    if !input_done && let Err(error) = pump.join_input().await {
        forwarding_error.get_or_insert(AppError::Terminal(error));
    }
    if !output_done && let Err(error) = pump.join_output().await {
        forwarding_error.get_or_insert(AppError::Terminal(error));
    }
    terminal.restore()?;

    let status = match status {
        Some(status) => status,
        None => invocation.wait().await?,
    };
    if let Some(signal) = caught_signal {
        return Ok(128_u8.saturating_add(signal as u8));
    }
    if let Some(error) = forwarding_error {
        return Err(error);
    }
    exit_code(&status).map_err(AppError::Client)
}

impl Signals {
    fn new() -> Result<Self, AppError> {
        Ok(Self {
            winch: signal_named(SignalKind::window_change(), "SIGWINCH")?,
            term: signal_named(SignalKind::terminate(), "SIGTERM")?,
            hup: signal_named(SignalKind::hangup(), "SIGHUP")?,
            quit: signal_named(SignalKind::quit(), "SIGQUIT")?,
            interrupt: signal_named(SignalKind::interrupt(), "SIGINT")?,
            tstp: signal_named(SignalKind::from_raw(libc::SIGTSTP), "SIGTSTP")?,
        })
    }

    async fn termination(&mut self) -> i32 {
        tokio::select! {
            _ = self.term.recv() => libc::SIGTERM,
            _ = self.hup.recv() => libc::SIGHUP,
            _ = self.quit.recv() => libc::SIGQUIT,
            _ = self.interrupt.recv() => libc::SIGINT,
        }
    }

    async fn next_event(&mut self) -> SignalEvent {
        tokio::select! {
            _ = self.winch.recv() => SignalEvent::WindowChange,
            _ = self.term.recv() => SignalEvent::Terminate(libc::SIGTERM),
            _ = self.hup.recv() => SignalEvent::Terminate(libc::SIGHUP),
            _ = self.quit.recv() => SignalEvent::Terminate(libc::SIGQUIT),
            _ = self.interrupt.recv() => SignalEvent::Terminate(libc::SIGINT),
            _ = self.tstp.recv() => SignalEvent::Suspend,
        }
    }
}

fn signal_named(kind: SignalKind, name: &'static str) -> Result<Signal, AppError> {
    signal(kind).map_err(|error| AppError::Signal(name, error))
}

fn duplicate_terminal(tty: &[bool; 3]) -> Result<OwnedFd, AppError> {
    let descriptor = tty
        .iter()
        .position(|is_tty| *is_tty)
        .ok_or(AppError::NoLocalTerminal)?;
    match descriptor {
        0 => rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3),
        1 => rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3),
        2 => rustix::io::fcntl_dupfd_cloexec(std::io::stderr(), 3),
        _ => unreachable!("terminal index comes from a three-element array"),
    }
    .map_err(AppError::DuplicateTerminal)
}
