use std::env;
use std::io::IsTerminal;

use thiserror::Error;

use crate::cli::Cli;
use crate::{FrozenRequest, IoMode, WorkingDirectoryError, WorkingDirectoryFd};

pub struct PreparedClientRequest {
    pub request: FrozenRequest,
    pub description: Option<String>,
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
}

impl PreparedClientRequest {
    pub fn from_cli(cli: Cli, io_mode: IoMode) -> Result<Self, ClientRequestError> {
        let cwd = WorkingDirectoryFd::open(cli.chdir.as_deref().unwrap_or("."))?;
        let environment = parse_environment(&cli.setenv)?;
        let request = FrozenRequest::new(cli.command, environment, io_mode)?;

        Ok(Self {
            request,
            description: cli.description,
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
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    ]
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

        // The missing- and non-UTF-8-variable cases run in a recursively
        // spawned child process so the test process never mutates or injects
        // invalid values into its own process-global environment.
        if env::var_os("SUD0_TEST_CHILD_ENVIRONMENT").is_some() {
            let missing = env::var("SUD0_TEST_MISSING_NAME").unwrap();
            assert!(matches!(
                parse_environment(&[missing]),
                Err(ClientRequestError::MissingEnvironment { .. })
            ));
            let invalid = env::var("SUD0_TEST_NON_UTF8_NAME").unwrap();
            assert!(matches!(
                parse_environment(&[invalid]),
                Err(ClientRequestError::NonUtf8Environment { .. })
            ));
            return;
        }

        let missing_name = format!("SUD0_TEST_MISSING_{}", std::process::id());
        let invalid_name = format!("SUD0_TEST_NON_UTF8_{}", std::process::id());
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "client_request::tests::environment_splits_first_equals_and_reports_missing_import",
            )
            .env_remove(&missing_name)
            .env("SUD0_TEST_CHILD_ENVIRONMENT", "1")
            .env("SUD0_TEST_MISSING_NAME", &missing_name)
            .env("SUD0_TEST_NON_UTF8_NAME", &invalid_name)
            .env(&invalid_name, OsString::from_vec(vec![b'v', 0xff]))
            .status()
            .unwrap();
        assert!(status.success());
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
