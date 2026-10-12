//! Security contracts and limits shared by every protocol participant.

/// The systemd activation descriptor name accepted for the sealed request.
pub const REQUEST_FD_NAME: &str = "sud0-request";
/// The descriptor assigned to the sealed request by systemd activation.
pub const REQUEST_FD: i32 = 3;
/// The systemd activation descriptor name accepted for the opened working directory.
pub const CWD_FD_NAME: &str = "sud0-cwd";
/// The descriptor assigned to the opened working directory by systemd activation.
pub const CWD_FD: i32 = 4;
/// Exact colon-separated systemd activation names, in descriptor order.
pub const ACTIVATION_FD_NAMES: &str = "sud0-request:sud0-cwd";
/// Exact number of systemd activation descriptors.
pub const ACTIVATION_FD_COUNT: u32 = 2;

/// Fixed root command search path; ambient `PATH` is never consulted.
pub const ROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin";
/// Fixed root `SHELL` environment value.
pub const ROOT_SHELL: &str = "/bin/bash";
/// Installed executor path used by transient services.
pub const EXECUTOR_PATH: &str = "/usr/lib/sud0/sud0-exec";

/// Well-known system-bus name owned by the broker.
pub const BROKER_BUS_NAME: &str = "nz.passcod.sud0";
/// Stable object path exposing the broker manager.
pub const BROKER_MANAGER_PATH: &str = "/nz/passcod/sud0";
/// The only PolicyKit action the broker may request.
pub const POLKIT_RUN_ACTION: &str = "nz.passcod.sud0.run";
/// Fixed non-sensitive description for transient command services.
pub const TRANSIENT_UNIT_DESCRIPTION: &str = "sud0 privileged command";
/// Root-owned prompt template loaded once when the broker starts.
pub const PROMPT_TEMPLATE_PATH: &str = "/etc/sud0/prompt.template";

/// Environment names supplied by the executor rather than by a request.
pub const BASELINE_ENVIRONMENT_NAMES: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "SHELL"];
/// systemd activation names that must not survive into or be replaced by a command request.
pub const ACTIVATION_ENVIRONMENT_NAMES: &[&str] = &["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"];

/// Current private `FrozenRequest` encoding version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum combined bytes in argv and environment names and values.
pub const MAX_REQUEST_DATA_BYTES: usize = 1024 * 1024;
/// Maximum encoded request size accepted before decoding begins.
pub const MAX_ENCODED_REQUEST_BYTES: usize = MAX_REQUEST_DATA_BYTES + 64 * 1024;
/// Maximum number of command arguments.
pub const MAX_ARGUMENTS: usize = 4096;
/// Maximum byte length of one command argument.
pub const MAX_ARGUMENT_BYTES: usize = 128 * 1024;
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
/// Maximum rendered byte length of the broker-derived working-directory path.
pub const MAX_CWD_DISPLAY_BYTES: usize = 512;
/// Maximum UTF-8 byte length of the root-owned prompt template.
pub const MAX_PROMPT_TEMPLATE_BYTES: usize = 4096;
/// Maximum rendered prompt size after placeholder expansion.
pub const MAX_PROMPT_BYTES: usize = 8192;

pub(crate) fn random_identifier() -> Result<String, getrandom::Error> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)?;
    Ok(format!("{:032x}", u128::from_ne_bytes(random)))
}
