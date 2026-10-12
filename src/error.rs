use thiserror::Error;

/// A request violates a structural or resource limit.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum RequestError {
    #[error("a request must contain at least one command argument")]
    EmptyArgv,
    #[error("command argument zero must not be empty")]
    EmptyProgram,
    #[error("request has {actual} arguments; the maximum is {maximum}")]
    TooManyArguments { actual: usize, maximum: usize },
    #[error("argument {index} has {actual} bytes; the maximum is {maximum}")]
    ArgumentTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("{field} contains a NUL byte")]
    EmbeddedNul { field: &'static str },
    #[error("request has {actual} environment variables; the maximum is {maximum}")]
    TooManyEnvironmentVariables { actual: usize, maximum: usize },
    #[error("environment variable {index} has an empty name")]
    EmptyEnvironmentName { index: usize },
    #[error("environment variable {index} name has {actual} bytes; the maximum is {maximum}")]
    EnvironmentNameTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("environment variable {index} has invalid name byte 0x{byte:02x} at offset {offset}")]
    InvalidEnvironmentName {
        index: usize,
        offset: usize,
        byte: u8,
    },
    #[error("environment variable name {name:?} occurs more than once")]
    DuplicateEnvironmentName { name: String },
    #[error("environment variable {index} uses protected name {name:?}")]
    ProtectedEnvironmentName { index: usize, name: String },
    #[error("environment variable {index} value has {actual} bytes; the maximum is {maximum}")]
    EnvironmentValueTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("request data has {actual} bytes; the maximum is {maximum}")]
    RequestTooLarge { actual: usize, maximum: usize },
}

/// Encoding or decoding a frozen request failed.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("encoded request has {actual} bytes; the maximum is {maximum}")]
    EncodedRequestTooLarge { actual: usize, maximum: usize },
    #[error("failed to decode request: {0}")]
    Decode(postcard::Error),
    #[error("request has trailing data")]
    TrailingData,
    #[error("request protocol version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error(transparent)]
    InvalidRequest(#[from] RequestError),
}

/// A human description exceeds its independent input bound.
#[derive(Debug, Error)]
pub enum DescriptionError {
    #[error("description has {actual} bytes; the maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
}
