use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::sync::Arc;

use nix::fcntl::{OFlag, open};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use thiserror::Error;
use tokio::io::{Interest, unix::AsyncFd};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::WindowSize;

const BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum TerminalError {
    #[error("failed to inspect terminal attributes: {0}")]
    GetAttributes(rustix::io::Errno),
    #[error("failed to enter raw terminal mode: {0}")]
    EnterRaw(rustix::io::Errno),
    #[error("failed to restore terminal attributes: {0}")]
    Restore(rustix::io::Errno),
    #[error("failed to read terminal window size: {0}")]
    WindowSize(rustix::io::Errno),
    #[error("terminal has an invalid zero-sized window")]
    InvalidWindowSize,
    #[error("failed to reopen local {stream}: {source}")]
    Reopen {
        stream: &'static str,
        source: nix::errno::Errno,
    },
    #[error("failed to configure PTY master: {0}")]
    ConfigureMaster(rustix::io::Errno),
    #[error("terminal input forwarding failed: {0}")]
    Input(io::Error),
    #[error("terminal output forwarding failed: {0}")]
    Output(io::Error),
    #[error("terminal forwarding task failed: {0}")]
    Task(tokio::task::JoinError),
}

pub struct TerminalGuard {
    terminal: OwnedFd,
    original: Termios,
    raw: bool,
}

pub struct Pump {
    shutdown: watch::Sender<bool>,
    input: JoinHandle<io::Result<()>>,
    output: JoinHandle<io::Result<()>>,
    input_joined: bool,
    output_joined: bool,
}

pub enum PumpEvent {
    Input(Result<(), TerminalError>),
    Output(Result<(), TerminalError>),
}

impl TerminalGuard {
    pub fn enter(fd: BorrowedFd<'_>) -> Result<Self, TerminalError> {
        let terminal =
            rustix::io::fcntl_dupfd_cloexec(fd, 3).map_err(TerminalError::GetAttributes)?;
        let original = tcgetattr(&terminal).map_err(TerminalError::GetAttributes)?;
        let mut raw_attributes = original.clone();
        raw_attributes.make_raw();
        tcsetattr(&terminal, OptionalActions::Now, &raw_attributes)
            .map_err(TerminalError::EnterRaw)?;
        Ok(Self {
            terminal,
            original,
            raw: true,
        })
    }

    pub fn restore(&mut self) -> Result<(), TerminalError> {
        if self.raw {
            tcsetattr(&self.terminal, OptionalActions::Now, &self.original)
                .map_err(TerminalError::Restore)?;
            self.raw = false;
        }
        Ok(())
    }

    pub fn reenter(&mut self) -> Result<(), TerminalError> {
        if !self.raw {
            let mut raw_attributes = self.original.clone();
            raw_attributes.make_raw();
            tcsetattr(&self.terminal, OptionalActions::Now, &raw_attributes)
                .map_err(TerminalError::EnterRaw)?;
            self.raw = true;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.raw {
            let _ = tcsetattr(&self.terminal, OptionalActions::Now, &self.original);
        }
    }
}

impl Pump {
    pub fn start(master: OwnedFd) -> Result<Self, TerminalError> {
        let input = reopen_descriptor(0, OFlag::O_RDONLY, "stdin")?;
        let output = reopen_descriptor(1, OFlag::O_WRONLY, "stdout")?;
        Self::start_with_fds(master, input, output)
    }

    fn start_with_fds(
        master: OwnedFd,
        input: OwnedFd,
        output: OwnedFd,
    ) -> Result<Self, TerminalError> {
        set_nonblocking(&master).map_err(TerminalError::ConfigureMaster)?;
        let master = Arc::new(
            AsyncFd::with_interest(master, Interest::READABLE | Interest::WRITABLE)
                .map_err(TerminalError::Output)?,
        );
        let input = Arc::new(
            AsyncFd::with_interest(input, Interest::READABLE).map_err(TerminalError::Input)?,
        );
        let output = Arc::new(
            AsyncFd::with_interest(output, Interest::WRITABLE).map_err(TerminalError::Output)?,
        );
        let (shutdown, shutdown_rx) = watch::channel(false);
        let input_task = tokio::spawn(forward_input(input, master.clone(), shutdown_rx));
        let output_task = tokio::spawn(forward_output(master, output));
        Ok(Self {
            shutdown,
            input: input_task,
            output: output_task,
            input_joined: false,
            output_joined: false,
        })
    }

    pub fn stop_input(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn join_input(&mut self) -> Result<(), TerminalError> {
        let result = (&mut self.input)
            .await
            .map_err(TerminalError::Task)?
            .map_err(TerminalError::Input);
        self.input_joined = true;
        result
    }

    pub async fn join_output(&mut self) -> Result<(), TerminalError> {
        let result = (&mut self.output)
            .await
            .map_err(TerminalError::Task)?
            .map_err(TerminalError::Output);
        self.output_joined = true;
        result
    }

    pub async fn next_event(&mut self) -> PumpEvent {
        match (self.input_joined, self.output_joined) {
            (false, false) => tokio::select! {
                result = &mut self.input => {
                    self.input_joined = true;
                    PumpEvent::Input(
                        result.map_err(TerminalError::Task).and_then(|value| value.map_err(TerminalError::Input))
                    )
                }
                result = &mut self.output => {
                    self.output_joined = true;
                    PumpEvent::Output(
                        result.map_err(TerminalError::Task).and_then(|value| value.map_err(TerminalError::Output))
                    )
                }
            },
            (false, true) => PumpEvent::Input(self.join_input().await),
            (true, false) => PumpEvent::Output(self.join_output().await),
            (true, true) => std::future::pending().await,
        }
    }
}

pub fn window_size(fd: BorrowedFd<'_>) -> Result<WindowSize, TerminalError> {
    let size = tcgetwinsize(fd).map_err(TerminalError::WindowSize)?;
    let size = WindowSize {
        rows: size.ws_row,
        columns: size.ws_col,
        x_pixels: size.ws_xpixel,
        y_pixels: size.ws_ypixel,
    };
    if size.rows == 0 || size.columns == 0 {
        return Err(TerminalError::InvalidWindowSize);
    }
    Ok(size)
}

pub fn suspend_process(guard: &mut TerminalGuard) -> Result<(), TerminalError> {
    guard.restore()?;
    let _ = kill(Pid::this(), Signal::SIGSTOP);
    guard.reenter()
}

fn reopen_descriptor(
    descriptor: i32,
    access: OFlag,
    stream: &'static str,
) -> Result<OwnedFd, TerminalError> {
    open(
        format!("/proc/self/fd/{descriptor}").as_str(),
        access | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|source| TerminalError::Reopen { stream, source })
}

fn set_nonblocking(fd: &OwnedFd) -> Result<(), rustix::io::Errno> {
    let flags = fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

async fn forward_input(
    input: Arc<AsyncFd<OwnedFd>>,
    master: Arc<AsyncFd<OwnedFd>>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let count = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = read_ready(&input, &mut buffer, false) => result?,
        };
        if count == 0 {
            return Ok(());
        }
        write_all_ready(&master, &buffer[..count]).await?;
    }
}

async fn forward_output(
    master: Arc<AsyncFd<OwnedFd>>,
    output: Arc<AsyncFd<OwnedFd>>,
) -> io::Result<()> {
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let count = read_ready(&master, &mut buffer, true).await?;
        if count == 0 {
            return Ok(());
        }
        write_all_ready(&output, &buffer[..count]).await?;
    }
}

async fn read_ready(
    fd: &AsyncFd<OwnedFd>,
    buffer: &mut [u8],
    eio_is_eof: bool,
) -> io::Result<usize> {
    loop {
        let mut ready = fd.readable().await?;
        match ready.try_io(|inner| match nix::unistd::read(inner.get_ref(), buffer) {
            Ok(count) => Ok(count),
            Err(nix::errno::Errno::EINTR) => Err(io::Error::from(io::ErrorKind::Interrupted)),
            Err(nix::errno::Errno::EIO) if eio_is_eof => Ok(0),
            Err(error) => Err(io::Error::from_raw_os_error(error as i32)),
        }) {
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn write_all_ready(fd: &AsyncFd<OwnedFd>, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut ready = fd.writable().await?;
        match ready.try_io(|inner| match nix::unistd::write(inner.get_ref(), bytes) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "descriptor accepted zero output bytes",
            )),
            Ok(count) => Ok(count),
            Err(nix::errno::Errno::EINTR) => Err(io::Error::from(io::ErrorKind::Interrupted)),
            Err(error) => Err(io::Error::from_raw_os_error(error as i32)),
        }) {
            Ok(Ok(count)) => bytes = &bytes[count..],
            Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use nix::pty::{Winsize, openpty};

    use super::*;

    fn nonblocking(stream: UnixStream) -> OwnedFd {
        stream.set_nonblocking(true).unwrap();
        stream.into()
    }

    #[tokio::test]
    async fn pump_is_byte_transparent_and_injects_nothing() {
        let (local_input, pump_input) = UnixStream::pair().unwrap();
        let (pump_master, command_side) = UnixStream::pair().unwrap();
        let (pump_output, local_output) = UnixStream::pair().unwrap();
        let mut pump = Pump::start_with_fds(
            nonblocking(pump_master),
            nonblocking(pump_input),
            nonblocking(pump_output),
        )
        .unwrap();
        let input = b"\0\xff\x1b[31mraw\x1b]0;title\x07\r\n";
        let output = b"\xfe\0\x1b[0m\n";
        let mut input_writer = local_input;
        let mut command_reader = command_side.try_clone().unwrap();
        let mut command_writer = command_side;
        let mut output_reader = local_output;

        input_writer.write_all(input).unwrap();
        input_writer.shutdown(Shutdown::Write).unwrap();
        let received_input = tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0; input.len()];
            command_reader.read_exact(&mut bytes).unwrap();
            bytes
        })
        .await
        .unwrap();
        assert_eq!(received_input, input);

        command_writer.write_all(output).unwrap();
        command_writer.shutdown(Shutdown::Write).unwrap();
        let received_output = tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            output_reader.read_to_end(&mut bytes).unwrap();
            bytes
        })
        .await
        .unwrap();
        pump.stop_input();
        pump.join_input().await.unwrap();
        pump.join_output().await.unwrap();
        assert_eq!(received_output, output);
    }

    #[tokio::test]
    async fn input_eof_does_not_stop_output() {
        let (local_input, pump_input) = UnixStream::pair().unwrap();
        let (pump_master, mut command_side) = UnixStream::pair().unwrap();
        let (pump_output, mut local_output) = UnixStream::pair().unwrap();
        let mut pump = Pump::start_with_fds(
            nonblocking(pump_master),
            nonblocking(pump_input),
            nonblocking(pump_output),
        )
        .unwrap();
        local_input.shutdown(Shutdown::Write).unwrap();
        pump.join_input().await.unwrap();

        command_side.write_all(b"after eof").unwrap();
        command_side.shutdown(Shutdown::Write).unwrap();
        pump.join_output().await.unwrap();
        let mut bytes = Vec::new();
        local_output.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"after eof");
    }

    #[tokio::test]
    async fn pty_master_eio_is_clean_hangup() {
        let pty = openpty(None, None).unwrap();
        let (local_input, pump_input) = UnixStream::pair().unwrap();
        let (pump_output, local_output) = UnixStream::pair().unwrap();
        drop(local_input);
        drop(local_output);
        let mut pump = Pump::start_with_fds(
            pty.master,
            nonblocking(pump_input),
            nonblocking(pump_output),
        )
        .unwrap();
        drop(pty.slave);
        pump.stop_input();
        pump.join_input().await.unwrap();
        pump.join_output().await.unwrap();
    }

    #[test]
    fn captures_full_window_size() {
        let expected = Winsize {
            ws_row: 43,
            ws_col: 117,
            ws_xpixel: 900,
            ws_ypixel: 700,
        };
        let pty = openpty(Some(&expected), None).unwrap();
        assert_eq!(
            window_size(pty.slave.as_fd()).unwrap(),
            WindowSize {
                rows: 43,
                columns: 117,
                x_pixels: 900,
                y_pixels: 700,
            }
        );
    }

    fn termios_snapshot(termios: &Termios) -> (u32, u32, u32, u32, String, u32, u32) {
        (
            termios.input_modes.bits(),
            termios.output_modes.bits(),
            termios.control_modes.bits(),
            termios.local_modes.bits(),
            format!("{:?}", termios.special_codes),
            termios.input_speed(),
            termios.output_speed(),
        )
    }

    #[test]
    fn terminal_guard_restores_exact_attributes() {
        let pty = openpty(None, None).unwrap();
        let before = tcgetattr(&pty.slave).unwrap();
        let snapshot = termios_snapshot(&before);
        {
            let _guard = TerminalGuard::enter(pty.slave.as_fd()).unwrap();
            let during = tcgetattr(&pty.slave).unwrap();
            assert_ne!(termios_snapshot(&during), snapshot);
        }
        assert_eq!(termios_snapshot(&tcgetattr(&pty.slave).unwrap()), snapshot);
    }
}
