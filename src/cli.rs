use clap::{ArgAction, Parser};

/// Run a command as root.
#[derive(Debug, Parser)]
#[command(name = "sud0", version, about, trailing_var_arg = true)]
pub struct Cli {
    /// Human-readable reason shown in the authentication prompt
    #[arg(short = 'd', long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Run the command in this working directory
    #[arg(short = 'D', long, value_name = "PATH")]
    pub chdir: Option<String>,

    /// Set or import an environment variable
    #[arg(long, value_name = "NAME[=VALUE]", action = ArgAction::Append)]
    pub setenv: Vec<String>,

    /// Allocate a pseudo-terminal
    #[arg(long, conflicts_with = "pipe")]
    pub pty: bool,

    /// Pass stdin, stdout, and stderr directly
    #[arg(long, conflicts_with = "pty")]
    pub pipe: bool,

    /// Do not permit an interactive authentication challenge
    #[arg(short = 'n', long, visible_alias = "no-ask-password")]
    pub non_interactive: bool,

    /// Command and arguments to run
    #[arg(value_name = "COMMAND [ARG...]")]
    pub command: Vec<String>,
}
