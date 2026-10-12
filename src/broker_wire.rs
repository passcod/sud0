use std::os::fd::OwnedFd;

use thiserror::Error;
use zbus::zvariant::{Optional, OwnedFd as ZOwnedFd, Type};

use crate::{
    DescriptionError, FrozenRequest, HumanDescription, IoMode, ProtocolError,
    WorkingDirectoryError, WorkingDirectoryFd,
};

/// Initial terminal dimensions supplied for a broker-allocated PTY.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Type,
)]
pub struct WindowSize {
    pub rows: u16,
    pub columns: u16,
    pub x_pixels: u16,
    pub y_pixels: u16,
}

impl WindowSize {
    pub fn validate(self) -> Result<Self, PrepareError> {
        if self.rows == 0 || self.columns == 0 {
            return Err(PrepareError::InvalidWindowSize);
        }
        Ok(self)
    }
}

/// Mode-specific descriptors accepted by the public broker `Run` method.
///
/// D-Bus has no sum type, so the wire form carries an explicit discriminator and a descriptor array.
/// `PTY` is encoded as kind `0` with no descriptors. `Pipe` is kind `1` with stdin, stdout, and
/// stderr in that exact order. The broker consumes and validates this value before authorization.
#[derive(serde::Serialize, serde::Deserialize, Type)]
pub struct StdioWire {
    pub kind: u8,
    pub descriptors: Vec<ZOwnedFd>,
}

impl StdioWire {
    pub const PTY_KIND: u8 = 0;
    pub const PIPE_KIND: u8 = 1;

    pub fn pty() -> Self {
        Self {
            kind: Self::PTY_KIND,
            descriptors: Vec::new(),
        }
    }

    pub fn pipe(stdin: OwnedFd, stdout: OwnedFd, stderr: OwnedFd) -> Self {
        Self {
            kind: Self::PIPE_KIND,
            descriptors: vec![stdin.into(), stdout.into(), stderr.into()],
        }
    }
}

/// Complete, bounded client input for one broker run request.
///
/// The UTF-8 execution request uses the private Postcard protocol. Presentation data and descriptor
/// capabilities remain separate from execution data.
#[derive(serde::Serialize, serde::Deserialize, Type)]
pub struct RunWire {
    pub request: Vec<u8>,
    pub description: Optional<String>,
    pub cwd: ZOwnedFd,
    pub stdio: StdioWire,
    pub allow_interaction: bool,
    pub window_size: Optional<WindowSize>,
}

/// Broker-owned input frozen before authorization begins.
pub struct PreparedRequest {
    request: FrozenRequest,
    description: Option<HumanDescription>,
    cwd: WorkingDirectoryFd,
    io: PreparedIo,
    allow_interaction: bool,
}

impl PreparedRequest {
    pub fn from_wire(wire: RunWire) -> Result<Self, PrepareError> {
        let request = FrozenRequest::decode(&wire.request)?;
        let description = Option::<String>::from(wire.description)
            .map(HumanDescription::new)
            .transpose()?;
        let cwd = WorkingDirectoryFd::try_from(OwnedFd::from(wire.cwd))?;
        let io = PreparedIo::from_wire(
            request.io_mode(),
            wire.stdio,
            Option::<WindowSize>::from(wire.window_size),
        )?;

        Ok(Self {
            request,
            description,
            cwd,
            io,
            allow_interaction: wire.allow_interaction,
        })
    }

    pub fn request(&self) -> &FrozenRequest {
        &self.request
    }

    pub fn description(&self) -> Option<&HumanDescription> {
        self.description.as_ref()
    }

    pub fn cwd(&self) -> &WorkingDirectoryFd {
        &self.cwd
    }

    pub const fn allow_interaction(&self) -> bool {
        self.allow_interaction
    }

    pub fn into_launch_parts(self) -> (FrozenRequest, WorkingDirectoryFd, PreparedIo) {
        (self.request, self.cwd, self.io)
    }
}

/// Owned standard-I/O capabilities whose shape agrees with the frozen request mode.
pub enum PreparedIo {
    Pty {
        initial_size: WindowSize,
    },
    Pipe {
        stdin: OwnedFd,
        stdout: OwnedFd,
        stderr: OwnedFd,
    },
}

impl PreparedIo {
    fn from_wire(
        expected: IoMode,
        wire: StdioWire,
        window_size: Option<WindowSize>,
    ) -> Result<Self, PrepareError> {
        match (
            expected,
            wire.kind,
            wire.descriptors.as_slice(),
            window_size,
        ) {
            (IoMode::Pty, StdioWire::PTY_KIND, [], Some(size)) => Ok(Self::Pty {
                initial_size: size.validate()?,
            }),
            (IoMode::Pipe, StdioWire::PIPE_KIND, [_, _, _], None) => {
                let [stdin, stdout, stderr] = wire.descriptors.try_into().unwrap();
                Ok(Self::Pipe {
                    stdin: stdin.into(),
                    stdout: stdout.into(),
                    stderr: stderr.into(),
                })
            }
            _ => Err(PrepareError::IoModeMismatch),
        }
    }
}

/// Failure to turn untrusted D-Bus values into broker-owned invariant-bearing state.
#[derive(Debug, Error)]
pub enum PrepareError {
    #[error("invalid encoded request")]
    Request(#[from] ProtocolError),
    #[error("invalid presentation description")]
    Description(#[from] DescriptionError),
    #[error("invalid working-directory descriptor")]
    WorkingDirectory(#[from] WorkingDirectoryError),
    #[error("request I/O mode does not match supplied descriptors")]
    IoModeMismatch,
    #[error("PTY dimensions must have nonzero rows and columns")]
    InvalidWindowSize,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use zbus::zvariant::Optional;

    use super::*;

    fn request(mode: IoMode) -> FrozenRequest {
        FrozenRequest::new(
            vec!["/usr/bin/id".to_owned(), "--user".to_owned()],
            Vec::new(),
            mode,
        )
        .unwrap()
    }

    fn directory_fd() -> OwnedFd {
        File::open("/").unwrap().into()
    }

    fn null_fd() -> OwnedFd {
        File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap()
            .into()
    }

    fn wire(mode: IoMode, stdio: StdioWire, size: Option<WindowSize>) -> RunWire {
        RunWire {
            request: request(mode).encode(),
            description: Optional::from(Some("maintenance".to_owned())),
            cwd: directory_fd().into(),
            stdio,
            allow_interaction: true,
            window_size: Optional::from(size),
        }
    }

    #[test]
    fn prepares_pipe_request_and_owns_each_descriptor() {
        let descriptors = [null_fd(), null_fd(), null_fd()];
        let raw = descriptors.each_ref().map(AsRawFd::as_raw_fd);
        let [stdin, stdout, stderr] = descriptors;
        let prepared = PreparedRequest::from_wire(wire(
            IoMode::Pipe,
            StdioWire::pipe(stdin, stdout, stderr),
            None,
        ))
        .unwrap();

        assert_eq!(prepared.request(), &request(IoMode::Pipe));
        assert_eq!(prepared.description().unwrap().as_str(), "maintenance");
        let (
            _,
            _,
            PreparedIo::Pipe {
                stdin,
                stdout,
                stderr,
            },
        ) = prepared.into_launch_parts()
        else {
            panic!("expected pipe mode");
        };
        assert_eq!(
            [stdin.as_raw_fd(), stdout.as_raw_fd(), stderr.as_raw_fd()],
            raw
        );
    }

    #[test]
    fn accepts_pty_only_with_initial_dimensions_and_no_descriptors() {
        let size = WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        };
        let prepared =
            PreparedRequest::from_wire(wire(IoMode::Pty, StdioWire::pty(), Some(size))).unwrap();
        assert!(matches!(
            prepared.into_launch_parts().2,
            PreparedIo::Pty { initial_size } if initial_size == size
        ));
    }

    #[test]
    fn rejects_every_mode_descriptor_mismatch() {
        let size = WindowSize {
            rows: 24,
            columns: 80,
            x_pixels: 0,
            y_pixels: 0,
        };
        let cases = [
            wire(IoMode::Pty, StdioWire::pty(), None),
            wire(
                IoMode::Pty,
                StdioWire::pipe(null_fd(), null_fd(), null_fd()),
                Some(size),
            ),
            wire(IoMode::Pipe, StdioWire::pty(), Some(size)),
            RunWire {
                stdio: StdioWire {
                    kind: StdioWire::PIPE_KIND,
                    descriptors: vec![null_fd().into(), null_fd().into()],
                },
                ..wire(IoMode::Pipe, StdioWire::pty(), None)
            },
        ];

        for case in cases {
            assert!(matches!(
                PreparedRequest::from_wire(case),
                Err(PrepareError::IoModeMismatch)
            ));
        }
    }

    #[test]
    fn rejects_non_directory_cwd_before_auth() {
        let cwd: OwnedFd = tempfile::tempfile().unwrap().into();
        let request = request(IoMode::Pipe);
        let result = PreparedRequest::from_wire(RunWire {
            request: request.encode(),
            description: Optional::from(None),
            cwd: cwd.into(),
            stdio: StdioWire::pipe(null_fd(), null_fd(), null_fd()),
            allow_interaction: false,
            window_size: Optional::from(None),
        });
        assert!(matches!(
            result,
            Err(PrepareError::WorkingDirectory(
                WorkingDirectoryError::NotDirectory
            ))
        ));
    }

    #[test]
    fn rejects_mutated_protocol_and_oversized_description() {
        let mut malformed = wire(
            IoMode::Pipe,
            StdioWire::pipe(null_fd(), null_fd(), null_fd()),
            None,
        );
        malformed.request[0] ^= 1;
        assert!(matches!(
            PreparedRequest::from_wire(malformed),
            Err(PrepareError::Request(_))
        ));

        let mut description = wire(
            IoMode::Pipe,
            StdioWire::pipe(null_fd(), null_fd(), null_fd()),
            None,
        );
        description.description = Optional::from(Some("x".repeat(513)));
        assert!(matches!(
            PreparedRequest::from_wire(description),
            Err(PrepareError::Description(_))
        ));
    }

    #[test]
    fn invalid_window_dimensions_are_rejected() {
        let result = PreparedRequest::from_wire(wire(
            IoMode::Pty,
            StdioWire::pty(),
            Some(WindowSize {
                rows: 0,
                columns: 80,
                x_pixels: 0,
                y_pixels: 0,
            }),
        ));
        assert!(matches!(result, Err(PrepareError::InvalidWindowSize)));
    }
}
