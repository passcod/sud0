//! Shared protocol and presentation primitives for sud0.

pub mod constants;
pub mod cwd;
pub mod error;
pub mod executor;
pub mod prompt;
pub mod protocol;
pub mod request;
pub mod sealed_request;

pub use cwd::{WorkingDirectoryError, WorkingDirectoryFd};
pub use error::{DescriptionError, ProtocolError, RequestError};
pub use prompt::{HumanDescription, format_command, format_prompt};
pub use request::{EnvironmentVariable, FrozenRequest, IoMode, RequestOptions};
pub use sealed_request::{SealedRequestError, SealedRequestFd, decode_sealed_request};
