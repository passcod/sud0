//! Limits shared by every protocol participant.

/// Wire-format magic, including a trailing byte that cannot occur in a text label.
pub const PROTOCOL_MAGIC: &[u8; 8] = b"SUD0FRZ\0";
/// Current `FrozenRequest` wire-format version.
pub const PROTOCOL_VERSION: u16 = 1;
/// SHA-256 digest length in bytes.
pub const DIGEST_BYTES: usize = 32;

/// Maximum combined bytes in argv, cwd, and environment names and values.
pub const MAX_REQUEST_DATA_BYTES: usize = 1024 * 1024;
/// Maximum encoded request size accepted before decoding begins.
pub const MAX_ENCODED_REQUEST_BYTES: usize = MAX_REQUEST_DATA_BYTES + 64 * 1024;
/// Maximum number of command arguments.
pub const MAX_ARGUMENTS: usize = 4096;
/// Maximum byte length of one command argument.
pub const MAX_ARGUMENT_BYTES: usize = 128 * 1024;
/// Maximum byte length of the working directory.
pub const MAX_CWD_BYTES: usize = 16 * 1024;
/// Maximum number of explicitly supplied environment variables.
pub const MAX_ENVIRONMENT_VARIABLES: usize = 4096;
/// Maximum byte length of an environment variable name.
pub const MAX_ENVIRONMENT_NAME_BYTES: usize = 255;
/// Maximum byte length of one environment variable value.
pub const MAX_ENVIRONMENT_VALUE_BYTES: usize = 128 * 1024;

/// Maximum byte length accepted for a human description before rendering.
pub const MAX_DESCRIPTION_BYTES: usize = 512;
/// Maximum rendered byte length of a human description.
pub const MAX_DESCRIPTION_DISPLAY_BYTES: usize = 1024;
/// Maximum rendered byte length of the argv portion of a prompt.
pub const MAX_COMMAND_DISPLAY_BYTES: usize = 1024;
