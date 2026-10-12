use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::WorkingDirectoryIdentity;
use crate::constants::{
    MAX_COMMAND_DISPLAY_BYTES, MAX_CWD_DISPLAY_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_DESCRIPTION_DISPLAY_BYTES, MAX_ENVIRONMENT_DISPLAY_BYTES, MAX_PROMPT_BYTES,
    MAX_PROMPT_TEMPLATE_BYTES,
};
use crate::error::DescriptionError;
use crate::request::FrozenRequest;

const DESCRIPTION_DIGEST_DOMAIN: &[u8] = b"sud0 human description digest\0";
const ALLOWED_PLACEHOLDERS: &[&str] = &[
    "description",
    "description_line",
    "command",
    "cwd",
    "cwd_identity",
    "environment",
    "environment_line",
    "request_digest",
    "digest_line",
];

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

/// Formats argv as shell-compatible words.
///
/// Plain words remain unquoted, printable values use single quotes when needed, and unsafe or
/// non-ASCII bytes use ANSI-C quoting with fixed-width octal escapes. If the complete rendering
/// exceeds its bound, the prefix ends at a byte-escape or argument boundary, closes any open quote,
/// and carries the complete execution digest.
pub fn format_command(request: &FrozenRequest) -> String {
    format_command_with_state(request).0
}

fn format_command_with_state(request: &FrozenRequest) -> (String, bool) {
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
        return (display, false);
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
    (display, true)
}

/// A validated root-owned format for authentication messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptTemplate {
    parts: Vec<PromptPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptPart {
    Literal(String),
    Placeholder(String),
}

impl PromptTemplate {
    pub fn parse(text: String) -> Result<Self, PromptTemplateError> {
        if text.len() > MAX_PROMPT_TEMPLATE_BYTES {
            return Err(PromptTemplateError::TooLong {
                actual: text.len(),
                maximum: MAX_PROMPT_TEMPLATE_BYTES,
            });
        }

        let mut parts = Vec::new();
        let mut offset = 0;
        while offset < text.len() {
            let rest = &text[offset..];
            let open = rest.find('{');
            let unexpected_close = rest.find('}');
            if unexpected_close.is_some_and(|close| open.is_none_or(|open| close < open)) {
                return Err(PromptTemplateError::UnexpectedClose);
            }
            let Some(open) = open else {
                parts.push(PromptPart::Literal(rest.to_owned()));
                break;
            };
            if open != 0 {
                parts.push(PromptPart::Literal(rest[..open].to_owned()));
            }
            let after_open = &rest[open + 1..];
            let close = after_open
                .find('}')
                .ok_or(PromptTemplateError::UnclosedPlaceholder)?;
            let name = &after_open[..close];
            if !ALLOWED_PLACEHOLDERS.contains(&name) {
                return Err(PromptTemplateError::UnknownPlaceholder(name.to_owned()));
            }
            parts.push(PromptPart::Placeholder(name.to_owned()));
            offset += open + close + 2;
        }
        Ok(Self { parts })
    }

    pub fn render(
        &self,
        request: &FrozenRequest,
        description: Option<&HumanDescription>,
        cwd_path: &[u8],
        cwd_identity: WorkingDirectoryIdentity,
    ) -> Result<String, PromptTemplateError> {
        let (command, command_truncated) = format_command_with_state(request);
        let (cwd, cwd_truncated) = bounded_byte_display(cwd_path, MAX_CWD_DISPLAY_BYTES, request);
        let description = description
            .map(HumanDescription::display)
            .unwrap_or_default();
        let environment = format_environment(request);
        let environment_count = request.environment().len();
        let request_digest = request.execution_digest_hex();
        let cwd_identity = format!(
            "mount={}, inode={}",
            cwd_identity.mount_id(),
            cwd_identity.inode()
        );
        let description_line = if description.is_empty() {
            String::new()
        } else {
            format!("\n{description}")
        };
        let environment_line = if environment_count == 0 {
            String::new()
        } else {
            format!("\nwith {environment_count} environment override(s)")
        };
        let digest_line = if command_truncated || cwd_truncated {
            format!("\nrequest sha256: {request_digest}")
        } else {
            String::new()
        };
        let values = [
            ("description", description.as_str()),
            ("description_line", description_line.as_str()),
            ("command", command.as_str()),
            ("cwd", cwd.as_str()),
            ("cwd_identity", cwd_identity.as_str()),
            ("environment", environment.as_str()),
            ("environment_line", environment_line.as_str()),
            ("request_digest", request_digest.as_str()),
            ("digest_line", digest_line.as_str()),
        ];

        let mut rendered = String::new();
        for part in &self.parts {
            match part {
                PromptPart::Literal(literal) => rendered.push_str(literal),
                PromptPart::Placeholder(name) => rendered.push_str(
                    values
                        .iter()
                        .find_map(|(candidate, value)| (*candidate == name).then_some(*value))
                        .expect("validated placeholder has a render value"),
                ),
            }
            if rendered.len() > MAX_PROMPT_BYTES {
                return Err(PromptTemplateError::RenderedTooLong {
                    actual: rendered.len(),
                    maximum: MAX_PROMPT_BYTES,
                });
            }
        }
        Ok(rendered.trim_end().to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PromptTemplateError {
    #[error("prompt template has {actual} bytes; the maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("prompt template has an unclosed placeholder")]
    UnclosedPlaceholder,
    #[error("prompt template has an unexpected closing brace")]
    UnexpectedClose,
    #[error("prompt template uses unknown placeholder {0:?}")]
    UnknownPlaceholder(String),
    #[error("rendered prompt has {actual} bytes; the maximum is {maximum}")]
    RenderedTooLong { actual: usize, maximum: usize },
}

/// Composes challenged text from a trusted template and execution context.
pub fn format_prompt(
    template: &PromptTemplate,
    request: &FrozenRequest,
    description: Option<&HumanDescription>,
    cwd_path: &[u8],
    cwd_identity: WorkingDirectoryIdentity,
) -> Result<String, PromptTemplateError> {
    template.render(request, description, cwd_path, cwd_identity)
}

fn format_environment(request: &FrozenRequest) -> String {
    if request.environment().is_empty() {
        return "none".to_owned();
    }

    let mut full = String::new();
    for (index, variable) in request.environment().iter().enumerate() {
        if index != 0 {
            full.push(' ');
        }
        push_escaped_argument(&mut full, variable.name());
        full.push('=');
        push_escaped_argument(&mut full, variable.value());
    }
    if full.len() <= MAX_ENVIRONMENT_DISPLAY_BYTES {
        return full;
    }

    let marker = format!(
        "... [truncated; request-sha256={}]",
        request.execution_digest_hex()
    );
    let budget = MAX_ENVIRONMENT_DISPLAY_BYTES - marker.len();
    let mut output = String::with_capacity(MAX_ENVIRONMENT_DISPLAY_BYTES);
    for variable in request.environment() {
        let mut assignment = String::new();
        push_escaped_argument(&mut assignment, variable.name());
        assignment.push('=');
        push_escaped_argument(&mut assignment, variable.value());
        let separator = usize::from(!output.is_empty());
        if output.len() + separator + assignment.len() > budget {
            break;
        }
        if separator != 0 {
            output.push(' ');
        }
        output.push_str(&assignment);
    }
    output.push_str(&marker);
    output
}

fn bounded_byte_display(value: &[u8], maximum: usize, request: &FrozenRequest) -> (String, bool) {
    let mut full = String::with_capacity(escaped_argument_length(value));
    push_escaped_argument(&mut full, value);
    if full.len() <= maximum {
        return (full, false);
    }

    let marker = format!(
        "... [truncated; request-sha256={}]",
        request.execution_digest_hex()
    );
    let budget = maximum - marker.len();
    let mut output = String::with_capacity(maximum);
    output.push_str("$'");
    for &byte in value {
        let atom_length = escaped_byte_length(byte);
        if output.len() + atom_length + 1 > budget {
            break;
        }
        push_escaped_byte(&mut output, byte);
    }
    output.push('\'');
    output.push_str(&marker);
    (output, true)
}

fn escaped_argument_length(argument: &[u8]) -> usize {
    if !argument.is_empty() && argument.iter().all(|byte| is_unquoted_shell_byte(*byte)) {
        argument.len()
    } else if argument
        .iter()
        .all(|byte| is_single_quoted_shell_byte(*byte))
    {
        argument.len() + 2
    } else {
        3 + argument
            .iter()
            .map(|byte| escaped_byte_length(*byte))
            .sum::<usize>()
    }
}

fn push_escaped_argument(output: &mut String, argument: &[u8]) {
    if !argument.is_empty() && argument.iter().all(|byte| is_unquoted_shell_byte(*byte)) {
        output.extend(argument.iter().map(|byte| char::from(*byte)));
    } else if argument
        .iter()
        .all(|byte| is_single_quoted_shell_byte(*byte))
    {
        output.push('\'');
        output.extend(argument.iter().map(|byte| char::from(*byte)));
        output.push('\'');
    } else {
        output.push_str("$'");
        for &byte in argument {
            push_escaped_byte(output, byte);
        }
        output.push('\'');
    }
}

const fn is_unquoted_shell_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
        )
}

const fn is_single_quoted_shell_byte(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e) && !matches!(byte, b'\'' | b'<' | b'>' | b'&')
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
            "echo 'two words' $'quote\\047\\134' $'line\\012\\377'"
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
        assert_eq!(format_command(&request), "printf ''");
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

    fn default_template() -> PromptTemplate {
        PromptTemplate::parse(include_str!("../dist/prompt.template").to_owned()).unwrap()
    }

    #[test]
    fn default_prompt_is_compact_and_uses_broker_derived_cwd() {
        let request = FrozenRequest::new(
            vec![b"id".to_vec()],
            Some(b"/claimed".to_vec()),
            vec![(b"LANG".to_vec(), b"C".to_vec())],
            RequestOptions::for_io_mode(IoMode::Pipe),
        )
        .unwrap();
        let identity = WorkingDirectoryIdentity::new_for_test(7, 11);
        let description = HumanDescription::new("inspect account").unwrap();
        let prompt = format_prompt(
            &default_template(),
            &request,
            Some(&description),
            b"/actual",
            identity,
        )
        .unwrap();
        assert_eq!(
            prompt,
            "Authentication is required to run as root:\ninspect account\nid\nin /actual\nwith 1 environment override(s)"
        );
        assert!(!prompt.contains("/claimed"));
        assert!(!prompt.contains("mount="));
        assert!(!prompt.contains("sha256"));
        assert!(!prompt.contains("LANG"));
    }

    #[test]
    fn forensic_template_exposes_optional_context() {
        let request = request(vec![b"id".to_vec()]);
        let template = PromptTemplate::parse(
            "{command}|{cwd}|{cwd_identity}|{environment}|{request_digest}".to_owned(),
        )
        .unwrap();
        let prompt = format_prompt(
            &template,
            &request,
            None,
            b"/actual",
            WorkingDirectoryIdentity::new_for_test(7, 11),
        )
        .unwrap();
        assert!(
            prompt.contains("id|/actual|mount=7, inode=11|LANG=C|"),
            "{prompt:?}"
        );
        assert!(prompt.ends_with(&request.execution_digest_hex()));
    }

    #[test]
    fn template_rejects_malformed_braces_and_unknown_placeholders() {
        assert_eq!(
            PromptTemplate::parse("before } {command}".to_owned()),
            Err(PromptTemplateError::UnexpectedClose)
        );
        assert_eq!(
            PromptTemplate::parse("{command".to_owned()),
            Err(PromptTemplateError::UnclosedPlaceholder)
        );
        assert_eq!(
            PromptTemplate::parse("{unknown}".to_owned()),
            Err(PromptTemplateError::UnknownPlaceholder(
                "unknown".to_owned()
            ))
        );
    }

    #[test]
    fn rendered_values_are_never_reparsed_as_placeholders() {
        let request = request(vec![b"id".to_vec()]);
        let description = HumanDescription::new("literal {command}").unwrap();
        let template = PromptTemplate::parse("{description}".to_owned()).unwrap();
        assert_eq!(
            format_prompt(
                &template,
                &request,
                Some(&description),
                b"/actual",
                WorkingDirectoryIdentity::new_for_test(7, 11),
            )
            .unwrap(),
            "literal {command}"
        );
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
        let request = request(vec![b"x".repeat(MAX_COMMAND_DISPLAY_BYTES + 1)]);
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
                &default_template(),
                &request,
                Some(&first),
                b"/actual",
                WorkingDirectoryIdentity::new_for_test(7, 11),
            ),
            format_prompt(
                &default_template(),
                &request,
                Some(&second),
                b"/actual",
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
