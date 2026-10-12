use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::constants::{
    ACTIVATION_ENVIRONMENT_NAMES, BASELINE_ENVIRONMENT_NAMES, MAX_ARGUMENT_BYTES, MAX_ARGUMENTS,
    MAX_ENVIRONMENT_NAME_BYTES, MAX_ENVIRONMENT_VALUE_BYTES, MAX_ENVIRONMENT_VARIABLES,
    MAX_REQUEST_DATA_BYTES,
};
use crate::error::RequestError;

/// How standard streams are connected to the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoMode {
    Pty,
    Pipe,
}

/// One explicit environment assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    name: String,
    value: String,
}

impl EnvironmentVariable {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

/// An immutable, validated execution request.
///
/// Presentation-only data and the descriptor-backed working directory are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenRequest {
    argv: Vec<String>,
    environment: Vec<EnvironmentVariable>,
    io_mode: IoMode,
}

impl FrozenRequest {
    pub fn new(
        argv: Vec<String>,
        environment: Vec<(String, String)>,
        io_mode: IoMode,
    ) -> Result<Self, RequestError> {
        validate_argv(&argv)?;
        let environment = validate_environment(environment)?;
        validate_total_size(&argv, &environment)?;
        Ok(Self {
            argv,
            environment,
            io_mode,
        })
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn environment(&self) -> &[EnvironmentVariable] {
        &self.environment
    }

    pub const fn io_mode(&self) -> IoMode {
        self.io_mode
    }
}

fn validate_argv(argv: &[String]) -> Result<(), RequestError> {
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

fn validate_environment(
    environment: Vec<(String, String)>,
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
        if is_protected_environment_name(&name) {
            return Err(RequestError::ProtectedEnvironmentName { index, name });
        }
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

fn validate_environment_name(index: usize, name: &str) -> Result<(), RequestError> {
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

    for (offset, byte) in name.bytes().enumerate() {
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

fn is_protected_environment_name(name: &str) -> bool {
    BASELINE_ENVIRONMENT_NAMES.contains(&name)
        || ACTIVATION_ENVIRONMENT_NAMES.contains(&name)
        || name == "IFS"
        || name == "ENV"
        || name == "BASH_ENV"
        || name.starts_with("LD_")
        || name.starts_with("GLIBC_TUNABLES")
        || name.starts_with("MALLOC_")
        || name.starts_with("GCONV_")
        || name.starts_with("LOCPATH")
        || name.starts_with("PYTHON")
        || name.starts_with("PERL")
        || name.starts_with("RUBY")
        || name.starts_with("GEM_")
        || name.starts_with("NODE_")
        || name == "NODE_PATH"
        || name.starts_with("JAVA_TOOL_OPTIONS")
        || name.starts_with("JDK_JAVA_OPTIONS")
        || name.starts_with("CLASSPATH")
        || name.starts_with("GODEBUG")
        || name.starts_with("RUSTC_")
        || name.starts_with("RUSTDOC_")
        || name.starts_with("CARGO_")
}

fn validate_total_size(
    argv: &[String],
    environment: &[EnvironmentVariable],
) -> Result<(), RequestError> {
    let total = argv.iter().map(String::len).sum::<usize>()
        + environment
            .iter()
            .map(|variable| variable.name.len() + variable.value.len())
            .sum::<usize>();
    if total > MAX_REQUEST_DATA_BYTES {
        return Err(RequestError::RequestTooLarge {
            actual: total,
            maximum: MAX_REQUEST_DATA_BYTES,
        });
    }
    Ok(())
}

fn reject_nul(value: &str, field: &'static str) -> Result<(), RequestError> {
    if value.contains('\0') {
        Err(RequestError::EmbeddedNul { field })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(
        argv: Vec<&str>,
        environment: Vec<(&str, &str)>,
    ) -> Result<FrozenRequest, RequestError> {
        FrozenRequest::new(
            argv.into_iter().map(str::to_owned).collect(),
            environment
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            IoMode::Pipe,
        )
    }

    #[test]
    fn validates_argv_structure_and_limits() {
        assert_eq!(request(vec![], vec![]), Err(RequestError::EmptyArgv));
        assert_eq!(request(vec![""], vec![]), Err(RequestError::EmptyProgram));
        assert!(matches!(
            request(vec!["echo", "a\0b"], vec![]),
            Err(RequestError::EmbeddedNul { .. })
        ));
        assert!(matches!(
            FrozenRequest::new(
                vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)],
                vec![],
                IoMode::Pipe
            ),
            Err(RequestError::ArgumentTooLong { .. })
        ));
    }

    #[test]
    fn validates_environment_policy() {
        for invalid in ["", "1BAD", "BAD-NAME", "BAD=NAME", "é"] {
            assert!(request(vec!["true"], vec![(invalid, "")]).is_err());
        }
        assert!(matches!(
            request(vec!["true"], vec![("GOOD", "bad\0value")]),
            Err(RequestError::EmbeddedNul { .. })
        ));
        assert!(matches!(
            request(vec!["true"], vec![("DUP", "one"), ("DUP", "two")]),
            Err(RequestError::DuplicateEnvironmentName { .. })
        ));

        for protected in [
            "PATH",
            "HOME",
            "LISTEN_PID",
            "IFS",
            "LD_PRELOAD",
            "GLIBC_TUNABLES",
            "MALLOC_ARENA_MAX",
            "GCONV_PATH",
            "LOCPATH",
            "PYTHONPATH",
            "PERL5OPT",
            "RUBYOPT",
            "GEM_HOME",
            "NODE_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "GODEBUG",
            "RUSTC_WRAPPER",
            "RUSTDOC_WRAPPER",
            "CARGO_HOME",
        ] {
            assert!(
                matches!(
                    request(vec!["true"], vec![(protected, "value")]),
                    Err(RequestError::ProtectedEnvironmentName { .. })
                ),
                "{protected}"
            );
        }
    }

    #[test]
    fn enforces_quantitative_limits() {
        assert!(matches!(
            FrozenRequest::new(
                vec!["x".to_owned(); MAX_ARGUMENTS + 1],
                vec![],
                IoMode::Pipe
            ),
            Err(RequestError::TooManyArguments { .. })
        ));
        assert!(matches!(
            FrozenRequest::new(
                vec!["true".to_owned()],
                vec![("X".to_owned(), String::new()); MAX_ENVIRONMENT_VARIABLES + 1],
                IoMode::Pipe
            ),
            Err(RequestError::TooManyEnvironmentVariables { .. })
        ));
        assert!(matches!(
            request(
                vec!["true"],
                vec![(&"X".repeat(MAX_ENVIRONMENT_NAME_BYTES + 1), "")]
            ),
            Err(RequestError::EnvironmentNameTooLong { .. })
        ));
        assert!(matches!(
            request(
                vec!["true"],
                vec![("X", &"x".repeat(MAX_ENVIRONMENT_VALUE_BYTES + 1))]
            ),
            Err(RequestError::EnvironmentValueTooLong { .. })
        ));
        let argv = (0..9).map(|_| "x".repeat(MAX_ARGUMENT_BYTES)).collect();
        assert!(matches!(
            FrozenRequest::new(argv, vec![], IoMode::Pipe),
            Err(RequestError::RequestTooLarge { .. })
        ));
    }

    #[test]
    fn canonicalizes_environment_order() {
        let request = request(vec!["true"], vec![("Z_VAR", "last"), ("A_VAR", "first")]).unwrap();
        assert_eq!(
            request
                .environment()
                .iter()
                .map(EnvironmentVariable::name)
                .collect::<Vec<_>>(),
            ["A_VAR", "Z_VAR"]
        );
    }
}
