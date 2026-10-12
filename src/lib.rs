//! Shared protocol and presentation primitives for sud0.

pub mod auth_agent;
pub mod broker_auth;
pub mod broker_service;
pub mod broker_systemd;
pub mod broker_wire;
pub mod cli;
pub mod client;
pub mod client_request;
pub mod constants;
pub mod cwd;
pub mod error;
pub mod executor;
pub mod prompt;
pub mod protocol;
pub mod request;
pub mod sealed_request;
pub mod terminal;

pub use broker_auth::{
    AuthorizationOutcome, AuthorizationRequest, CallerIdentity, Cancellation, CancellationReason,
};
pub use broker_service::{BrokerManager, InvocationProxy, InvocationStatusWire, ManagerProxy};
pub use broker_systemd::{
    CommandOutcome, LaunchError, StartedUnit, SystemdLauncher, set_pty_window_size,
};
pub use broker_wire::{PreparedIo, PreparedRequest, RunWire, StdioWire, WindowSize};
pub use cwd::{WorkingDirectoryError, WorkingDirectoryFd};
pub use error::{DescriptionError, ProtocolError, RequestError};
pub use prompt::{HumanDescription, PromptTemplate, PromptTemplateError};
pub use request::{FrozenRequest, IoMode};
pub use sealed_request::{SealedRequestError, SealedRequestFd, decode_sealed_request};
