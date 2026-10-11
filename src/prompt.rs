use sha2::{Digest, Sha256};

use crate::WorkingDirectoryIdentity;
use crate::constants::{
    MAX_COMMAND_DISPLAY_BYTES, MAX_DESCRIPTION_BYTES, MAX_DESCRIPTION_DISPLAY_BYTES,
};
use crate::error::DescriptionError;
use crate::request::FrozenRequest;

const DESCRIPTION_DIGEST_DOMAIN: &[u8] = b"sud0 human description digest\0";
const PROMPT_PREFIX: &str = "Authentication is required to run a command as root for: ";

/// Validated presentation-only context supplied by a human caller.
///
/// This type is intentionally not part of [`FrozenRequest`], its wire format, or its execution
/// digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanDescription {
    text: String,
}

impl HumanDescription {
    pub fn new(text: impl Into<String>) -> Result<Self, DescriptionError> {
        let text = text.into();
        if text.len() > MAX_DESCRIPTION_BYTES {
            return Err(DescriptionError::TooLong {
                actual: text.len(),
                maximum: MAX_DESCRIPTION_BYTES,
            });
        }
        Ok(Self { text })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Sanitizes controls, bidi controls, and markup-significant characters and applies the
    /// independent description display bound.
    pub fn display(&self) -> String {
        let atoms: Vec<String> = self
            .text
            .chars()
            .map(escape_description_character)
            .collect();
        let full_length: usize = atoms.iter().map(String::len).sum();
        if full_length <= MAX_DESCRIPTION_DISPLAY_BYTES {
            return atoms.concat();
        }

        let digest = description_digest(self.text.as_bytes());
        let marker = format!("... [truncated; sha256:{}]", hex::encode(digest));
        let budget = MAX_DESCRIPTION_DISPLAY_BYTES - marker.len();
        let mut display = String::with_capacity(MAX_DESCRIPTION_DISPLAY_BYTES);
        for atom in atoms {
            if display.len() + atom.len() > budget {
                break;
            }
            display.push_str(&atom);
        }
        display.push_str(&marker);
        display
    }
}

/// Formats argv as shell-compatible ANSI-C quoted byte strings.
///
/// Every unsafe or non-ASCII byte is represented by a fixed-width octal escape. If the complete
/// rendering exceeds its bound, the prefix ends at a byte-escape or argument boundary, closes any
/// open quote, and carries the complete execution digest.
pub fn format_command(request: &FrozenRequest) -> String {
    let full_length = request
        .argv()
        .iter()
        .enumerate()
        .map(|(index, argument)| usize::from(index != 0) + escaped_argument_length(argument))
        .sum::<usize>();
    if full_length <= MAX_COMMAND_DISPLAY_BYTES {
        let mut display = String::with_capacity(full_length);
        for (index, argument) in request.argv().iter().enumerate() {
            if index != 0 {
                display.push(' ');
            }
            push_escaped_argument(&mut display, argument);
        }
        return display;
    }

    let marker = format!(
        " ... [truncated; sha256:{}]",
        request.execution_digest_hex()
    );
    let budget = MAX_COMMAND_DISPLAY_BYTES - marker.len();
    let mut display = String::with_capacity(MAX_COMMAND_DISPLAY_BYTES);

    for (index, argument) in request.argv().iter().enumerate() {
        let separator_length = usize::from(index != 0);
        let required_for_empty = separator_length + 3;
        if display.len() + required_for_empty > budget {
            break;
        }

        let first_atom_length = argument
            .first()
            .map_or(0, |byte| escaped_byte_length(*byte));
        if !argument.is_empty() && display.len() + required_for_empty + first_atom_length > budget {
            break;
        }

        if index != 0 {
            display.push(' ');
        }
        display.push_str("$'");
        let mut complete = true;
        for &byte in argument {
            let atom_length = escaped_byte_length(byte);
            if display.len() + atom_length + 1 > budget {
                complete = false;
                break;
            }
            push_escaped_byte(&mut display, byte);
        }
        display.push('\'');
        if !complete {
            break;
        }
    }
    display.push_str(&marker);
    display
}

/// Composes challenged text from presentation context and all execution-affecting request data.
pub fn format_prompt(
    request: &FrozenRequest,
    description: Option<&HumanDescription>,
    cwd_identity: WorkingDirectoryIdentity,
) -> String {
    let command = format_command(request);
    let cwd = request
        .working_directory()
        .map(escape_display_bytes)
        .unwrap_or_else(|| "<unavailable>".to_owned());
    let execution = format!(
        "{command}; cwd={cwd} [mount={}, inode={}]; env={} variable(s); request-sha256={}",
        cwd_identity.mount_id(),
        cwd_identity.inode(),
        request.environment().len(),
        request.execution_digest_hex(),
    );
    match description {
        Some(description) => format!("{PROMPT_PREFIX}{} ({execution})", description.display()),
        None => format!("{PROMPT_PREFIX}{execution}"),
    }
}

fn escape_display_bytes(value: &[u8]) -> String {
    let mut output = String::with_capacity(escaped_argument_length(value));
    push_escaped_argument(&mut output, value);
    output
}

fn escaped_argument_length(argument: &[u8]) -> usize {
    3 + argument
        .iter()
        .map(|byte| escaped_byte_length(*byte))
        .sum::<usize>()
}

fn push_escaped_argument(output: &mut String, argument: &[u8]) {
    output.push_str("$'");
    for &byte in argument {
        push_escaped_byte(output, byte);
    }
    output.push('\'');
}

const fn escaped_byte_length(byte: u8) -> usize {
    if is_safe_shell_display_byte(byte) {
        1
    } else {
        4
    }
}

fn push_escaped_byte(output: &mut String, byte: u8) {
    if is_safe_shell_display_byte(byte) {
        output.push(char::from(byte));
    } else {
        output.push('\\');
        output.push(char::from(b'0' + ((byte >> 6) & 0o3)));
        output.push(char::from(b'0' + ((byte >> 3) & 0o7)));
        output.push(char::from(b'0' + (byte & 0o7)));
    }
}

const fn is_safe_shell_display_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e) && !matches!(byte, b'\'' | b'\\' | b'<' | b'>' | b'&')
}

fn escape_description_character(character: char) -> String {
    match character {
        '\\' => "\\\\".to_owned(),
        '\n' => "\\n".to_owned(),
        '\r' => "\\r".to_owned(),
        '\t' => "\\t".to_owned(),
        '<' | '>' | '&' => format!("\\u{{{:x}}}", character as u32),
        character
            if character.is_control()
                || is_visual_line_break(character)
                || is_bidi_control(character) =>
        {
            format!("\\u{{{:x}}}", character as u32)
        }
        character => character.to_string(),
    }
}

const fn is_visual_line_break(character: char) -> bool {
    matches!(character, '\u{2028}' | '\u{2029}')
}

const fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{206f}'
    )
}

fn description_digest(description: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTION_DIGEST_DOMAIN);
    hasher.update(description);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::constants::{MAX_COMMAND_DISPLAY_BYTES, MAX_DESCRIPTION_DISPLAY_BYTES};
    use crate::request::{IoMode, RequestOptions};

    fn request(argv: Vec<Vec<u8>>) -> FrozenRequest {
        FrozenRequest::new(
            argv,
            Some(b"/tmp".to_vec()),
            vec![(b"LANG".to_vec(), b"C".to_vec())],
            RequestOptions::for_io_mode(IoMode::Pipe),
        )
        .unwrap()
    }

    #[test]
    fn command_format_is_shell_compatible_and_byte_preserving() {
        let request = request(vec![
            b"echo".to_vec(),
            b"two words".to_vec(),
            b"quote'\\".to_vec(),
            vec![b'l', b'i', b'n', b'e', b'\n', 0xff],
        ]);
        assert_eq!(
            format_command(&request),
            "$'echo' $'two words' $'quote\\047\\134' $'line\\012\\377'"
        );
    }

    #[test]
    fn command_format_never_embeds_controls_markup_or_non_ascii() {
        let request = request(vec![
            b"cmd".to_vec(),
            b"<&>\n\r\t".to_vec(),
            "\u{202e}".as_bytes().to_vec(),
            vec![0x80, 0xff],
        ]);
        let display = format_command(&request);
        assert!(display.is_ascii());
        assert!(!display.contains(['<', '>', '&', '\n', '\r', '\t']));
        assert!(display.contains("\\074\\046\\076\\012\\015\\011"));
    }

    #[test]
    fn empty_argument_remains_visible() {
        let request = request(vec![b"printf".to_vec(), Vec::new()]);
        assert_eq!(format_command(&request), "$'printf' $''");
    }

    #[test]
    fn description_sanitizes_controls_bidi_markup_and_backslash() {
        let description =
            HumanDescription::new("deploy <thing> & wait\n\u{2028}\u{202e}\u{206f}\\n").unwrap();
        let display = description.display();
        assert_eq!(
            display,
            "deploy \\u{3c}thing\\u{3e} \\u{26} wait\\n\\u{2028}\\u{202e}\\u{206f}\\\\n"
        );
        assert!(!display.contains(['<', '>', '&', '\n', '\r']));
    }

    #[test]
    fn prompts_bind_command_cwd_environment_and_directory_identity() {
        let request = FrozenRequest::new(
            vec![b"id".to_vec()],
            Some(b"/tmp".to_vec()),
            vec![(b"LANG".to_vec(), b"C".to_vec())],
            RequestOptions::for_io_mode(IoMode::Pipe),
        )
        .unwrap();
        let identity = WorkingDirectoryIdentity::new_for_test(7, 11);
        let prompt = format_prompt(&request, None, identity);
        assert!(prompt.starts_with(PROMPT_PREFIX));
        assert!(prompt.contains("$'id'; cwd=$'/tmp' [mount=7, inode=11]; env=1 variable(s)"));
        assert!(prompt.ends_with(&format!(
            "request-sha256={}",
            request.execution_digest_hex()
        )));

        let description = HumanDescription::new("inspect account").unwrap();
        let described = format_prompt(&request, Some(&description), identity);
        assert!(described.starts_with(&format!("{PROMPT_PREFIX}inspect account (")));
        assert!(described.ends_with(')'));
    }

    #[test]
    fn description_is_independently_bounded() {
        let oversized = "a".repeat(MAX_DESCRIPTION_BYTES + 1);
        assert_eq!(
            HumanDescription::new(oversized),
            Err(DescriptionError::TooLong {
                actual: MAX_DESCRIPTION_BYTES + 1,
                maximum: MAX_DESCRIPTION_BYTES,
            })
        );
    }

    #[test]
    fn command_truncates_at_escape_boundary_and_includes_execution_digest() {
        let request = request(vec![b"x".repeat(MAX_COMMAND_DISPLAY_BYTES)]);
        let display = format_command(&request);
        assert_eq!(display.len(), MAX_COMMAND_DISPLAY_BYTES);
        assert!(display.ends_with(&format!(
            " ... [truncated; sha256:{}]",
            request.execution_digest_hex()
        )));
        assert!(display.contains("' ... [truncated; sha256:"));
    }

    #[test]
    fn description_truncates_at_character_boundary_and_includes_own_digest() {
        let description = HumanDescription::new("\0".repeat(MAX_DESCRIPTION_BYTES)).unwrap();
        let display = description.display();
        assert!(display.len() <= MAX_DESCRIPTION_DISPLAY_BYTES);
        assert!(display.contains("[truncated; sha256:"));
        assert!(display.is_char_boundary(display.len()));
        assert!(!display.chars().any(char::is_control));
    }

    #[test]
    fn presentation_description_cannot_change_payload_or_execution_digest() {
        let request = request(vec![b"id".to_vec()]);
        let encoded = request.encode().unwrap();
        let digest = *request.execution_digest();
        let first = HumanDescription::new("first reason").unwrap();
        let second = HumanDescription::new("unrelated reason").unwrap();

        assert_ne!(
            format_prompt(
                &request,
                Some(&first),
                WorkingDirectoryIdentity::new_for_test(7, 11),
            ),
            format_prompt(
                &request,
                Some(&second),
                WorkingDirectoryIdentity::new_for_test(7, 11),
            )
        );
        assert_eq!(request.encode().unwrap(), encoded);
        assert_eq!(*request.execution_digest(), digest);
    }

    proptest! {
        #[test]
        fn arbitrary_command_bytes_render_safely(
            program in vec(1_u8..=255, 1..64),
            arguments in vec(vec(1_u8..=255, 0..256), 0..16),
        ) {
            let mut argv = vec![program];
            argv.extend(arguments);
            let display = format_command(&request(argv));

            prop_assert!(display.len() <= MAX_COMMAND_DISPLAY_BYTES);
            prop_assert!(display.is_ascii());
            prop_assert!(!display.bytes().any(|byte| byte.is_ascii_control()));
            prop_assert!(!display.contains(['<', '>', '&']));
        }

        #[test]
        fn arbitrary_descriptions_render_without_unsafe_literals(text in ".{0,128}") {
            let description = HumanDescription::new(text).unwrap();
            let display = description.display();

            prop_assert!(display.len() <= MAX_DESCRIPTION_DISPLAY_BYTES);
            prop_assert!(!display.chars().any(char::is_control));
            prop_assert!(!display.chars().any(is_visual_line_break));
            prop_assert!(!display.chars().any(is_bidi_control));
            prop_assert!(!display.contains(['<', '>', '&']));
        }
    }
}
