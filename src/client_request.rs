use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::cli::Cli;
use crate::constants::ROOT_SHELL;
use crate::{
    FrozenRequest, HumanDescription, IoMode, RequestOptions, WorkingDirectoryError,
    WorkingDirectoryFd,
};

#[derive(Debug)]
pub struct PreparedClientRequest {
    pub request: FrozenRequest,
    pub description: Option<HumanDescription>,
    pub cwd: WorkingDirectoryFd,
}

#[derive(Debug, Error)]
pub enum ClientRequestError {
    #[error("working-directory path contains a NUL byte")]
    WorkingDirectoryNul,
    #[error("failed to determine the current directory: {0}")]
    CurrentDirectory(std::io::Error),
    #[error(transparent)]
    WorkingDirectory(#[from] WorkingDirectoryError),
    #[error("environment variable {name:?} is not present")]
    MissingEnvironment { name: OsString },
    #[error(transparent)]
    InvalidRequest(#[from] crate::RequestError),
    #[error(transparent)]
    InvalidDescription(#[from] crate::DescriptionError),
}

impl PreparedClientRequest {
    pub fn from_cli(cli: &Cli, io_mode: IoMode) -> Result<Self, ClientRequestError> {
        let (cwd, display_path) = prepare_working_directory(cli.chdir.as_deref())?;
        let argv = command_argv(&cli.command);
        let environment = parse_environment(&cli.setenv)?;
        let request = FrozenRequest::new(
            argv,
            Some(display_path.into_os_string().into_vec()),
            environment,
            RequestOptions::for_io_mode(io_mode),
        )?;
        let description = cli
            .description
            .as_ref()
            .map(|text| HumanDescription::new(text.clone()))
            .transpose()?;

        Ok(Self {
            request,
            description,
            cwd,
        })
    }
}

pub fn choose_io_mode(explicit_pty: bool, explicit_pipe: bool, tty: [bool; 3]) -> IoMode {
    if explicit_pty {
        IoMode::Pty
    } else if explicit_pipe {
        IoMode::Pipe
    } else if tty.into_iter().all(|is_tty| is_tty) {
        IoMode::Pty
    } else {
        IoMode::Pipe
    }
}

pub fn stdio_are_ttys() -> [bool; 3] {
    [
        is_tty(std::io::stdin().as_fd()),
        is_tty(std::io::stdout().as_fd()),
        is_tty(std::io::stderr().as_fd()),
    ]
}

fn is_tty(fd: BorrowedFd<'_>) -> bool {
    nix::unistd::isatty(fd).unwrap_or(false)
}

fn command_argv(command: &[OsString]) -> Vec<Vec<u8>> {
    if command.is_empty() {
        vec![ROOT_SHELL.as_bytes().to_vec()]
    } else {
        command
            .iter()
            .map(|argument| argument.as_bytes().to_vec())
            .collect()
    }
}

fn parse_environment(values: &[OsString]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ClientRequestError> {
    values
        .iter()
        .map(|value| {
            let bytes = value.as_bytes();
            if let Some(separator) = bytes.iter().position(|byte| *byte == b'=') {
                return Ok((bytes[..separator].to_vec(), bytes[separator + 1..].to_vec()));
            }

            let name = OsStr::from_bytes(bytes);
            let imported =
                env::var_os(name).ok_or_else(|| ClientRequestError::MissingEnvironment {
                    name: value.clone(),
                })?;
            Ok((bytes.to_vec(), imported.into_vec()))
        })
        .collect()
}

fn prepare_working_directory(
    requested: Option<&OsStr>,
) -> Result<(WorkingDirectoryFd, PathBuf), ClientRequestError> {
    match requested {
        None => {
            let path = c_path(OsStr::from_bytes(b"."))?;
            let cwd = WorkingDirectoryFd::open(&path)?;
            let display = env::current_dir().map_err(ClientRequestError::CurrentDirectory)?;
            Ok((cwd, display))
        }
        Some(path) => {
            let c_path = c_path(path)?;
            let cwd = WorkingDirectoryFd::open(&c_path)?;
            let path = Path::new(path);
            let display = if path.is_absolute() {
                path.to_path_buf()
            } else {
                env::current_dir()
                    .map_err(ClientRequestError::CurrentDirectory)?
                    .join(path)
            };
            Ok((cwd, display))
        }
    }
}

fn c_path(path: &OsStr) -> Result<CString, ClientRequestError> {
    CString::new(path.as_bytes()).map_err(|_| ClientRequestError::WorkingDirectoryNul)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    use nix::sys::stat::fstat;
    use tempfile::tempdir;

    use super::*;
    use crate::cli::Cli;

    fn cli() -> Cli {
        Cli {
            description: None,
            chdir: None,
            setenv: Vec::new(),
            pty: false,
            pipe: false,
            non_interactive: false,
            validate: false,
            command: Vec::new(),
        }
    }

    #[test]
    fn defaults_to_fixed_root_shell_without_interpretation() {
        let argv = command_argv(&[]);
        assert_eq!(argv, vec![b"/bin/bash".to_vec()]);

        let explicit = command_argv(&[OsString::from("echo; id"), OsString::from("$HOME")]);
        assert_eq!(explicit, vec![b"echo; id".to_vec(), b"$HOME".to_vec()]);
    }

    #[test]
    fn explicit_environment_splits_only_first_equals_and_preserves_bytes() {
        let value = OsString::from_vec(vec![b'N', b'=', b'a', b'=', 0xff]);
        let parsed = parse_environment(&[value]).unwrap();
        assert_eq!(parsed, vec![(b"N".to_vec(), vec![b'a', b'=', 0xff])]);
    }

    #[test]
    fn bare_environment_imports_os_value() {
        let name = OsString::from(format!("SUD0_TEST_ENV_{}", std::process::id()));
        // SAFETY: This test uses a process-unique name and does not concurrently read or mutate it.
        unsafe { env::set_var(&name, OsStr::from_bytes(&[b'v', 0xff])) };
        let parsed = parse_environment(std::slice::from_ref(&name)).unwrap();
        // SAFETY: See the matching set_var above.
        unsafe { env::remove_var(&name) };
        assert_eq!(parsed, vec![(name.as_bytes().to_vec(), vec![b'v', 0xff])]);
    }

    #[test]
    fn missing_bare_environment_is_an_error() {
        let name = OsString::from(format!("SUD0_TEST_MISSING_{}", std::process::id()));
        // SAFETY: This test uses a process-unique name and does not concurrently read or mutate it.
        unsafe { env::remove_var(&name) };
        assert!(matches!(
            parse_environment(std::slice::from_ref(&name)),
            Err(ClientRequestError::MissingEnvironment { .. })
        ));
    }

    #[test]
    fn frozen_request_enforces_environment_policy() {
        let mut input = cli();
        input.setenv.push(OsString::from("PATH=/tmp"));
        let error = PreparedClientRequest::from_cli(&input, IoMode::Pipe).unwrap_err();
        assert!(matches!(
            error,
            ClientRequestError::InvalidRequest(
                crate::RequestError::ProtectedEnvironmentName { .. }
            )
        ));
    }

    #[test]
    fn io_mode_selection_honors_overrides_and_all_three_terminals() {
        assert_eq!(choose_io_mode(true, false, [false; 3]), IoMode::Pty);
        assert_eq!(choose_io_mode(false, true, [true; 3]), IoMode::Pipe);
        assert_eq!(choose_io_mode(false, false, [true; 3]), IoMode::Pty);
        assert_eq!(
            choose_io_mode(false, false, [true, true, false]),
            IoMode::Pipe
        );
    }

    #[test]
    fn default_display_is_absolute_and_fd_identifies_current_directory() {
        let (opened, display) = prepare_working_directory(None).unwrap();
        assert!(display.is_absolute());
        let current = std::fs::File::open(".").unwrap();
        let opened_stat = fstat(opened.as_fd()).unwrap();
        let current_stat = fstat(current.as_fd()).unwrap();
        assert_eq!(
            (opened_stat.st_dev, opened_stat.st_ino),
            (current_stat.st_dev, current_stat.st_ino)
        );
    }

    #[test]
    fn relative_chdir_display_is_lexical_and_open_fd_survives_rename() {
        let parent = tempdir().unwrap();
        let original = parent.path().join("original");
        let renamed = parent.path().join("renamed");
        std::fs::create_dir(&original).unwrap();
        let relative = original.strip_prefix(env::current_dir().unwrap()).ok();
        let requested = relative.unwrap_or(original.as_path());
        let (opened, display) = prepare_working_directory(Some(requested.as_os_str())).unwrap();
        let before = fstat(opened.as_fd()).unwrap();
        std::fs::rename(&original, &renamed).unwrap();
        let after = fstat(opened.as_fd()).unwrap();

        let expected = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            env::current_dir().unwrap().join(requested)
        };
        assert_eq!(display, expected);
        assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
    }

    #[test]
    fn chdir_rejects_embedded_nul() {
        let path = OsString::from_vec(vec![b'.', 0, b'x']);
        assert!(matches!(
            prepare_working_directory(Some(&path)),
            Err(ClientRequestError::WorkingDirectoryNul)
        ));
    }
}
