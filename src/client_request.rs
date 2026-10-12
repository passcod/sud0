use std::env;
use std::os::fd::{AsFd, BorrowedFd};

use thiserror::Error;

use crate::cli::Cli;
use crate::{FrozenRequest, HumanDescription, IoMode, WorkingDirectoryError, WorkingDirectoryFd};

pub struct PreparedClientRequest {
    pub request: FrozenRequest,
    pub description: Option<HumanDescription>,
    pub cwd: WorkingDirectoryFd,
}

#[derive(Debug, Error)]
pub enum ClientRequestError {
    #[error(transparent)]
    WorkingDirectory(#[from] WorkingDirectoryError),
    #[error("environment variable {name:?} is not present")]
    MissingEnvironment { name: String },
    #[error("environment variable {name:?} is not valid UTF-8")]
    NonUtf8Environment { name: String },
    #[error(transparent)]
    InvalidRequest(#[from] crate::RequestError),
    #[error(transparent)]
    InvalidDescription(#[from] crate::DescriptionError),
}

impl PreparedClientRequest {
    pub fn from_cli(cli: Cli, io_mode: IoMode) -> Result<Self, ClientRequestError> {
        let cwd = prepare_working_directory(cli.chdir.as_deref())?;
        let environment = parse_environment(&cli.setenv)?;
        let request = FrozenRequest::new(cli.command, environment, io_mode)?;
        let description = cli.description.map(HumanDescription::new).transpose()?;

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

fn parse_environment(values: &[String]) -> Result<Vec<(String, String)>, ClientRequestError> {
    values
        .iter()
        .map(|value| match value.split_once('=') {
            Some((name, value)) => Ok((name.to_owned(), value.to_owned())),
            None => match env::var(value) {
                Ok(imported) => Ok((value.clone(), imported)),
                Err(env::VarError::NotPresent) => Err(ClientRequestError::MissingEnvironment {
                    name: value.clone(),
                }),
                Err(env::VarError::NotUnicode(_)) => Err(ClientRequestError::NonUtf8Environment {
                    name: value.clone(),
                }),
            },
        })
        .collect()
}

fn prepare_working_directory(
    requested: Option<&str>,
) -> Result<WorkingDirectoryFd, ClientRequestError> {
    WorkingDirectoryFd::open(requested.unwrap_or(".")).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;

    use super::*;

    #[test]
    fn environment_splits_first_equals_and_reports_missing_import() {
        assert_eq!(
            parse_environment(&["NAME=a=b".to_owned()]).unwrap(),
            [("NAME".to_owned(), "a=b".to_owned())]
        );
        let path = env::var("PATH").unwrap();
        assert_eq!(
            parse_environment(&["PATH".to_owned()]).unwrap(),
            [("PATH".to_owned(), path)]
        );

        let name = format!("SUD0_TEST_MISSING_{}", std::process::id());
        // SAFETY: This process-unique variable is not concurrently accessed by another test.
        unsafe { env::remove_var(&name) };
        assert!(matches!(
            parse_environment(std::slice::from_ref(&name)),
            Err(ClientRequestError::MissingEnvironment { .. })
        ));

        if let Ok(name) = env::var("SUD0_TEST_NON_UTF8_NAME") {
            assert!(matches!(
                parse_environment(&[name]),
                Err(ClientRequestError::NonUtf8Environment { .. })
            ));
        } else {
            let name = format!("SUD0_TEST_NON_UTF8_{}", std::process::id());
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("client_request::tests::environment_splits_first_equals_and_reports_missing_import")
                .env("SUD0_TEST_NON_UTF8_NAME", &name)
                .env(name, OsString::from_vec(vec![b'v', 0xff]))
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn io_mode_selection_honors_overrides_and_terminals() {
        assert_eq!(choose_io_mode(true, false, [false; 3]), IoMode::Pty);
        assert_eq!(choose_io_mode(false, true, [true; 3]), IoMode::Pipe);
        assert_eq!(choose_io_mode(false, false, [true; 3]), IoMode::Pty);
        assert_eq!(
            choose_io_mode(false, false, [true, true, false]),
            IoMode::Pipe
        );
    }
}
