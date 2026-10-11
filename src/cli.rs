use std::ffi::OsString;

use clap::{ArgAction, Parser};

/// Run a command as root through the sud0 privilege broker.
#[derive(Debug, Parser)]
#[command(name = "sud0", version, about, trailing_var_arg = true)]
pub struct Cli {
    /// Human-readable reason shown in the authentication prompt
    #[arg(short = 'd', long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Run the command in this working directory
    #[arg(short = 'D', long, value_name = "PATH")]
    pub chdir: Option<OsString>,

    /// Set or import an environment variable
    #[arg(long, value_name = "NAME[=VALUE]", action = ArgAction::Append)]
    pub setenv: Vec<OsString>,

    /// Allocate a pseudo-terminal
    #[arg(long, conflicts_with = "pipe")]
    pub pty: bool,

    /// Pass stdin, stdout, and stderr directly
    #[arg(long, conflicts_with = "pty")]
    pub pipe: bool,

    /// Do not permit an interactive authentication challenge
    #[arg(short = 'n', long, visible_alias = "no-ask-password")]
    pub non_interactive: bool,

    /// Validate or refresh authorization without running a command
    #[arg(short = 'v', long)]
    pub validate: bool,

    /// Command and arguments to run; defaults to /bin/bash
    #[arg(value_name = "COMMAND [ARG...]")]
    pub command: Vec<OsString>,
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    use clap::{CommandFactory, Parser};

    use super::Cli;

    fn bytes(values: &[std::ffi::OsString]) -> Vec<&[u8]> {
        values.iter().map(|value| value.as_bytes()).collect()
    }

    #[test]
    fn preserves_non_utf8_command_and_option_values() {
        let command = std::ffi::OsString::from_vec(vec![b'c', 0xff]);
        let argument = std::ffi::OsString::from_vec(vec![b'a', 0xfe]);
        let directory = std::ffi::OsString::from_vec(vec![b'/', b'd', 0xfd]);
        let environment = std::ffi::OsString::from_vec(vec![b'X', b'=', 0xfc]);
        let cli = Cli::try_parse_from([
            std::ffi::OsString::from("sud0"),
            std::ffi::OsString::from("-D"),
            directory.clone(),
            std::ffi::OsString::from("--setenv"),
            environment.clone(),
            command.clone(),
            argument.clone(),
        ])
        .unwrap();

        assert_eq!(
            cli.chdir.as_deref().unwrap().as_bytes(),
            directory.as_bytes()
        );
        assert_eq!(cli.setenv[0].as_bytes(), environment.as_bytes());
        assert_eq!(
            bytes(&cli.command),
            vec![command.as_bytes(), argument.as_bytes()]
        );
    }

    #[test]
    fn command_starts_trailing_arguments() {
        let cli = Cli::try_parse_from(["sud0", "printf", "--pty", "-n"]).unwrap();
        assert!(!cli.pty);
        assert!(!cli.non_interactive);
        assert_eq!(
            bytes(&cli.command),
            vec![b"printf".as_slice(), b"--pty", b"-n"]
        );
    }

    #[test]
    fn double_dash_allows_hyphenated_command() {
        let cli = Cli::try_parse_from(["sud0", "--", "--program", "-x"]).unwrap();
        assert_eq!(bytes(&cli.command), vec![b"--program".as_slice(), b"-x"]);
    }

    #[test]
    fn options_before_command_and_alias_are_recognized() {
        let cli = Cli::try_parse_from([
            "sud0",
            "--pty",
            "--no-ask-password",
            "-d",
            "maintenance",
            "id",
        ])
        .unwrap();
        assert!(cli.pty);
        assert!(cli.non_interactive);
        assert_eq!(cli.description.as_deref(), Some("maintenance"));
        assert_eq!(bytes(&cli.command), vec![b"id".as_slice()]);
    }

    #[test]
    fn pty_and_pipe_conflict() {
        let error = Cli::try_parse_from(["sud0", "--pty", "--pipe", "id"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn no_command_is_accepted() {
        let cli = Cli::try_parse_from(["sud0"]).unwrap();
        assert!(cli.command.is_empty());
    }

    #[test]
    fn help_is_renderable_for_manual_generation() {
        Cli::command().debug_assert();
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("sud0 [OPTIONS] [COMMAND [ARG...]...]")
                || help.contains("sud0 [OPTIONS] [COMMAND")
        );
        assert!(help.contains("--no-ask-password"));
        assert!(help.contains("--setenv"));
    }
}
