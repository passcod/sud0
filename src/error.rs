use thiserror::Error;

/// A request violates a structural or resource limit.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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
    #[error("working directory must not be empty")]
    EmptyWorkingDirectory,
    #[error("working directory has {actual} bytes; the maximum is {maximum}")]
    WorkingDirectoryTooLong { actual: usize, maximum: usize },
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
    DuplicateEnvironmentName { name: Vec<u8> },
    #[error("environment variable {index} value has {actual} bytes; the maximum is {maximum}")]
    EnvironmentValueTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("exactly one of PTY mode and pipe mode must be selected")]
    InvalidIoMode,
    #[error("request contains unknown option bits 0x{bits:02x}")]
    UnknownOptionBits { bits: u8 },
    #[error("request data has {actual} bytes; the maximum is {maximum}")]
    RequestTooLarge { actual: usize, maximum: usize },
}

/// Encoding or decoding a frozen request failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("encoded request has {actual} bytes; the maximum is {maximum}")]
    EncodedRequestTooLarge { actual: usize, maximum: usize },
    #[error("integer overflow while calculating the encoded request length")]
    LengthOverflow,
    #[error("length {length} cannot be represented by the wire format")]
    LengthNotRepresentable { length: usize },
    #[error("request is truncated while reading {field}")]
    Truncated { field: &'static str },
    #[error("request has invalid protocol magic")]
    InvalidMagic,
    #[error("protocol version {version} is not supported")]
    UnsupportedVersion { version: u16 },
    #[error("declared payload length {declared} does not match the {actual} available bytes")]
    InvalidPayloadLength { declared: usize, actual: usize },
    #[error("request has trailing payload bytes")]
    TrailingPayload,
    #[error("request payload is not in canonical form")]
    NonCanonicalPayload,
    #[error("request digest does not match its payload")]
    DigestMismatch,
    #[error(transparent)]
    InvalidRequest(#[from] RequestError),
}

/// A human description exceeds its independent input bound.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DescriptionError {
    #[error("description has {actual} bytes; the maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
}
