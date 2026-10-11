use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::constants::{
    MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, MAX_CWD_BYTES, MAX_ENVIRONMENT_NAME_BYTES,
    MAX_ENVIRONMENT_VALUE_BYTES, MAX_ENVIRONMENT_VARIABLES, MAX_REQUEST_DATA_BYTES,
    PROTOCOL_VERSION,
};
use crate::error::RequestError;
use crate::protocol::encode_payload;

const OPTION_PTY: u8 = 1 << 0;
const OPTION_PIPE: u8 = 1 << 1;
const KNOWN_OPTION_BITS: u8 = OPTION_PTY | OPTION_PIPE;
const DIGEST_DOMAIN: &[u8] = b"sud0 FrozenRequest execution digest\0";

/// How standard streams are connected to the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    Pty,
    Pipe,
}

/// Validated execution options carried by a frozen request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestOptions {
    io_mode: IoMode,
}

impl RequestOptions {
    pub const fn for_io_mode(io_mode: IoMode) -> Self {
        Self { io_mode }
    }

    pub fn new(pty: bool, pipe: bool) -> Result<Self, RequestError> {
        match (pty, pipe) {
            (true, false) => Ok(Self::for_io_mode(IoMode::Pty)),
            (false, true) => Ok(Self::for_io_mode(IoMode::Pipe)),
            _ => Err(RequestError::InvalidIoMode),
        }
    }

    pub const fn io_mode(self) -> IoMode {
        self.io_mode
    }

    pub(crate) const fn flags(self) -> u8 {
        match self.io_mode {
            IoMode::Pty => OPTION_PTY,
            IoMode::Pipe => OPTION_PIPE,
        }
    }

    pub(crate) fn from_flags(flags: u8) -> Result<Self, RequestError> {
        let unknown = flags & !KNOWN_OPTION_BITS;
        if unknown != 0 {
            return Err(RequestError::UnknownOptionBits { bits: unknown });
        }
        Self::new(flags & OPTION_PTY != 0, flags & OPTION_PIPE != 0)
    }
}

/// One explicit environment assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentVariable {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl EnvironmentVariable {
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// An immutable, validated execution request.
///
/// Presentation-only data, including the optional human description, is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenRequest {
    argv: Vec<Vec<u8>>,
    working_directory: Option<Vec<u8>>,
    environment: Vec<EnvironmentVariable>,
    options: RequestOptions,
    execution_digest: [u8; 32],
}

impl FrozenRequest {
    pub fn new(
        argv: Vec<Vec<u8>>,
        working_directory: Option<Vec<u8>>,
        environment: Vec<(Vec<u8>, Vec<u8>)>,
        options: RequestOptions,
    ) -> Result<Self, RequestError> {
        validate_argv(&argv)?;
        validate_working_directory(working_directory.as_deref())?;
        let environment = validate_environment(environment)?;
        validate_total_size(&argv, working_directory.as_deref(), &environment)?;

        let mut request = Self {
            argv,
            working_directory,
            environment,
            options,
            execution_digest: [0; 32],
        };
        request.execution_digest = request.calculate_execution_digest();
        Ok(request)
    }

    pub fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    pub fn working_directory(&self) -> Option<&[u8]> {
        self.working_directory.as_deref()
    }

    pub fn environment(&self) -> &[EnvironmentVariable] {
        &self.environment
    }

    pub const fn options(&self) -> RequestOptions {
        self.options
    }

    pub const fn execution_digest(&self) -> &[u8; 32] {
        &self.execution_digest
    }

    pub fn execution_digest_hex(&self) -> String {
        hex::encode(self.execution_digest)
    }

    fn calculate_execution_digest(&self) -> [u8; 32] {
        let payload =
            encode_payload(self).expect("validated request must have an encodable payload");
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(PROTOCOL_VERSION.to_be_bytes());
        hasher.update(payload);
        hasher.finalize().into()
    }
}

fn validate_argv(argv: &[Vec<u8>]) -> Result<(), RequestError> {
    if argv.is_empty() {
        return Err(RequestError::EmptyArgv);
    }
    if argv.len() > MAX_ARGUMENTS {
        return Err(RequestError::TooManyArguments {
            actual: argv.len(),
            maximum: MAX_ARGUMENTS,
        });
    }

    for (index, argument) in argv.iter().enumerate() {
        if index == 0 && argument.is_empty() {
            return Err(RequestError::EmptyProgram);
        }
        if argument.len() > MAX_ARGUMENT_BYTES {
            return Err(RequestError::ArgumentTooLong {
                index,
                actual: argument.len(),
                maximum: MAX_ARGUMENT_BYTES,
            });
        }
        reject_nul(argument, "command argument")?;
    }
    Ok(())
}

fn validate_working_directory(working_directory: Option<&[u8]>) -> Result<(), RequestError> {
    let Some(working_directory) = working_directory else {
        return Ok(());
    };
    if working_directory.is_empty() {
        return Err(RequestError::EmptyWorkingDirectory);
    }
    if working_directory.len() > MAX_CWD_BYTES {
        return Err(RequestError::WorkingDirectoryTooLong {
            actual: working_directory.len(),
            maximum: MAX_CWD_BYTES,
        });
    }
    reject_nul(working_directory, "working directory")
}

fn validate_environment(
    environment: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<EnvironmentVariable>, RequestError> {
    if environment.len() > MAX_ENVIRONMENT_VARIABLES {
        return Err(RequestError::TooManyEnvironmentVariables {
            actual: environment.len(),
            maximum: MAX_ENVIRONMENT_VARIABLES,
        });
    }

    let mut seen = HashSet::with_capacity(environment.len());
    let mut validated = Vec::with_capacity(environment.len());
    for (index, (name, value)) in environment.into_iter().enumerate() {
        validate_environment_name(index, &name)?;
        if !seen.insert(name.clone()) {
            return Err(RequestError::DuplicateEnvironmentName { name });
        }
        if value.len() > MAX_ENVIRONMENT_VALUE_BYTES {
            return Err(RequestError::EnvironmentValueTooLong {
                index,
                actual: value.len(),
                maximum: MAX_ENVIRONMENT_VALUE_BYTES,
            });
        }
        reject_nul(&value, "environment variable value")?;
        validated.push(EnvironmentVariable { name, value });
    }
    validated.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(validated)
}

fn validate_environment_name(index: usize, name: &[u8]) -> Result<(), RequestError> {
    if name.is_empty() {
        return Err(RequestError::EmptyEnvironmentName { index });
    }
    if name.len() > MAX_ENVIRONMENT_NAME_BYTES {
        return Err(RequestError::EnvironmentNameTooLong {
            index,
            actual: name.len(),
            maximum: MAX_ENVIRONMENT_NAME_BYTES,
        });
    }

    for (offset, &byte) in name.iter().enumerate() {
        let valid = if offset == 0 {
            byte == b'_' || byte.is_ascii_alphabetic()
        } else {
            byte == b'_' || byte.is_ascii_alphanumeric()
        };
        if !valid {
            return Err(RequestError::InvalidEnvironmentName {
                index,
                offset,
                byte,
            });
        }
    }
    Ok(())
}

fn validate_total_size(
    argv: &[Vec<u8>],
    working_directory: Option<&[u8]>,
    environment: &[EnvironmentVariable],
) -> Result<(), RequestError> {
    let total = argv
        .iter()
        .try_fold(0usize, |total, argument| total.checked_add(argument.len()))
        .and_then(|total| total.checked_add(working_directory.map_or(0, <[u8]>::len)))
        .and_then(|total| {
            environment.iter().try_fold(total, |total, variable| {
                total
                    .checked_add(variable.name.len())?
                    .checked_add(variable.value.len())
            })
        })
        .ok_or(RequestError::RequestTooLarge {
            actual: usize::MAX,
            maximum: MAX_REQUEST_DATA_BYTES,
        })?;

    if total > MAX_REQUEST_DATA_BYTES {
        return Err(RequestError::RequestTooLarge {
            actual: total,
            maximum: MAX_REQUEST_DATA_BYTES,
        });
    }
    Ok(())
}

fn reject_nul(value: &[u8], field: &'static str) -> Result<(), RequestError> {
    if value.contains(&0) {
        Err(RequestError::EmbeddedNul { field })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> RequestOptions {
        RequestOptions::for_io_mode(IoMode::Pipe)
    }

    #[test]
    fn options_require_exactly_one_io_mode() {
        assert_eq!(
            RequestOptions::new(false, false),
            Err(RequestError::InvalidIoMode)
        );
        assert_eq!(
            RequestOptions::new(true, true),
            Err(RequestError::InvalidIoMode)
        );
        assert_eq!(
            RequestOptions::new(true, false).unwrap().io_mode(),
            IoMode::Pty
        );
        assert_eq!(
            RequestOptions::new(false, true).unwrap().io_mode(),
            IoMode::Pipe
        );
    }

    #[test]
    fn validates_program_and_nuls() {
        assert_eq!(
            FrozenRequest::new(Vec::new(), None, Vec::new(), options()),
            Err(RequestError::EmptyArgv)
        );
        assert_eq!(
            FrozenRequest::new(vec![Vec::new()], None, Vec::new(), options()),
            Err(RequestError::EmptyProgram)
        );
        assert!(matches!(
            FrozenRequest::new(
                vec![b"echo".to_vec(), b"a\0b".to_vec()],
                None,
                Vec::new(),
                options()
            ),
            Err(RequestError::EmbeddedNul {
                field: "command argument"
            })
        ));
    }

    #[test]
    fn validates_working_directory() {
        assert_eq!(
            FrozenRequest::new(
                vec![b"true".to_vec()],
                Some(Vec::new()),
                Vec::new(),
                options()
            ),
            Err(RequestError::EmptyWorkingDirectory)
        );
        assert!(matches!(
            FrozenRequest::new(
                vec![b"true".to_vec()],
                Some(b"/tmp\0elsewhere".to_vec()),
                Vec::new(),
                options()
            ),
            Err(RequestError::EmbeddedNul {
                field: "working directory"
            })
        ));
    }

    #[test]
    fn validates_environment_names_values_and_duplicates() {
        for invalid in [b"".as_slice(), b"1BAD", b"BAD-NAME", b"BAD=NAME", &[0xff]] {
            assert!(
                FrozenRequest::new(
                    vec![b"true".to_vec()],
                    None,
                    vec![(invalid.to_vec(), Vec::new())],
                    options()
                )
                .is_err()
            );
        }
        assert!(matches!(
            FrozenRequest::new(
                vec![b"true".to_vec()],
                None,
                vec![(b"GOOD".to_vec(), b"bad\0value".to_vec())],
                options()
            ),
            Err(RequestError::EmbeddedNul {
                field: "environment variable value"
            })
        ));
        assert!(matches!(
            FrozenRequest::new(
                vec![b"true".to_vec()],
                None,
                vec![
                    (b"DUP".to_vec(), b"one".to_vec()),
                    (b"DUP".to_vec(), b"two".to_vec())
                ],
                options()
            ),
            Err(RequestError::DuplicateEnvironmentName { .. })
        ));
    }

    #[test]
    fn canonicalizes_environment_order() {
        let request = FrozenRequest::new(
            vec![b"true".to_vec()],
            None,
            vec![
                (b"Z_VAR".to_vec(), b"last".to_vec()),
                (b"A_VAR".to_vec(), b"first".to_vec()),
            ],
            options(),
        )
        .unwrap();
        let names: Vec<_> = request
            .environment()
            .iter()
            .map(EnvironmentVariable::name)
            .collect();
        assert_eq!(names, [b"A_VAR".as_slice(), b"Z_VAR".as_slice()]);
    }

    #[test]
    fn enforces_individual_and_aggregate_limits() {
        assert!(matches!(
            FrozenRequest::new(
                vec![vec![b'x'; MAX_ARGUMENT_BYTES + 1]],
                None,
                Vec::new(),
                options()
            ),
            Err(RequestError::ArgumentTooLong { .. })
        ));

        let argv = (0..9).map(|_| vec![b'x'; MAX_ARGUMENT_BYTES]).collect();
        assert!(matches!(
            FrozenRequest::new(argv, None, Vec::new(), options()),
            Err(RequestError::RequestTooLarge { .. })
        ));
    }
}
