use thiserror::Error;

use crate::constants::{
    MAX_COMMAND_DISPLAY_BYTES, MAX_CWD_DISPLAY_BYTES, MAX_DESCRIPTION_BYTES,
    MAX_DESCRIPTION_DISPLAY_BYTES, MAX_PROMPT_BYTES, MAX_PROMPT_TEMPLATE_BYTES,
};
use crate::error::DescriptionError;
use crate::request::FrozenRequest;

const ALLOWED_PLACEHOLDERS: &[&str] = &["command", "cwd", "description_line", "environment_line"];

/// Validated presentation-only context supplied by a human caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanDescription(String);

impl HumanDescription {
    pub fn new(text: impl Into<String>) -> Result<Self, DescriptionError> {
        let text = text.into();
        if text.len() > MAX_DESCRIPTION_BYTES {
            return Err(DescriptionError::TooLong {
                actual: text.len(),
                maximum: MAX_DESCRIPTION_BYTES,
            });
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated root-owned Leon template for authentication messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptTemplate {
    source: String,
}

impl PromptTemplate {
    pub fn parse(source: String) -> Result<Self, PromptTemplateError> {
        if source.len() > MAX_PROMPT_TEMPLATE_BYTES {
            return Err(PromptTemplateError::TemplateTooLong {
                actual: source.len(),
                maximum: MAX_PROMPT_TEMPLATE_BYTES,
            });
        }
        let template = leon::Template::parse(&source).map_err(PromptTemplateError::Parse)?;
        if let Some(key) = template
            .keys()
            .find(|key| !ALLOWED_PLACEHOLDERS.contains(key))
        {
            return Err(PromptTemplateError::UnknownPlaceholder((*key).to_owned()));
        }
        Ok(Self { source })
    }

    pub fn render(
        &self,
        request: &FrozenRequest,
        description: Option<&HumanDescription>,
        cwd_path: &str,
    ) -> Result<String, PromptTemplateError> {
        let command = format_command(request)?;
        let cwd = sanitized_with_limit(cwd_path, MAX_CWD_DISPLAY_BYTES, "working directory")?;
        let description = match description {
            Some(description) => sanitized_with_limit(
                description.as_str(),
                MAX_DESCRIPTION_DISPLAY_BYTES,
                "description",
            )?,
            None => String::new(),
        };
        let description_line = if description.is_empty() {
            String::new()
        } else {
            format!("\n{description}")
        };
        let environment_line = match request.environment().len() {
            0 => String::new(),
            count => format!("\nwith {count} environment override(s)"),
        };
        let values = [
            ("command", command.as_str()),
            ("cwd", cwd.as_str()),
            ("description_line", description_line.as_str()),
            ("environment_line", environment_line.as_str()),
        ];
        let template = leon::Template::parse(&self.source)
            .expect("validated prompt template must remain parseable");
        let rendered = template
            .render(&values)
            .map_err(PromptTemplateError::Render)?;
        if rendered.len() > MAX_PROMPT_BYTES {
            return Err(PromptTemplateError::PromptTooLong {
                actual: rendered.len(),
                maximum: MAX_PROMPT_BYTES,
            });
        }
        Ok(rendered.trim_end().to_owned())
    }
}

/// Formats argv as a bounded, non-shell human-readable sequence.
fn format_command(request: &FrozenRequest) -> Result<String, PromptTemplateError> {
    let mut display = String::from("[");
    for (index, argument) in request.argv().iter().enumerate() {
        if index != 0 {
            display.push_str(", ");
        }
        display.push('"');
        push_sanitized(&mut display, argument);
        display.push('"');
    }
    display.push(']');
    if display.len() > MAX_COMMAND_DISPLAY_BYTES {
        return Err(PromptTemplateError::ValueTooLong {
            field: "command",
            actual: display.len(),
            maximum: MAX_COMMAND_DISPLAY_BYTES,
        });
    }
    Ok(display)
}

fn sanitized_with_limit(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<String, PromptTemplateError> {
    let mut display = String::new();
    push_sanitized(&mut display, value);
    if display.len() > maximum {
        return Err(PromptTemplateError::ValueTooLong {
            field,
            actual: display.len(),
            maximum,
        });
    }
    Ok(display)
}

fn push_sanitized(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' | '>' | '&' => push_unicode_escape(output, character),
            character
                if character.is_control()
                    || is_visual_line_break(character)
                    || is_bidi_control(character) =>
            {
                push_unicode_escape(output, character);
            }
            character => output.push(character),
        }
    }
}

fn push_unicode_escape(output: &mut String, character: char) {
    use std::fmt::Write;
    write!(output, "\\u{{{:x}}}", character as u32).expect("writing to a String cannot fail");
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

#[derive(Debug, Error)]
pub enum PromptTemplateError {
    #[error("prompt template has {actual} bytes; the maximum is {maximum}")]
    TemplateTooLong { actual: usize, maximum: usize },
    #[error("invalid prompt template: {0}")]
    Parse(leon::ParseError),
    #[error("prompt template uses unknown placeholder {0:?}")]
    UnknownPlaceholder(String),
    #[error("failed to render prompt template: {0}")]
    Render(leon::RenderError),
    #[error("rendered {field} has {actual} bytes; the maximum is {maximum}")]
    ValueTooLong {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("rendered prompt has {actual} bytes; the maximum is {maximum}")]
    PromptTooLong { actual: usize, maximum: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IoMode;

    fn request(argv: &[&str]) -> FrozenRequest {
        FrozenRequest::new(
            argv.iter().map(|value| (*value).to_owned()).collect(),
            vec![("LANG".to_owned(), "C".to_owned())],
            IoMode::Pipe,
        )
        .unwrap()
    }

    fn default_template() -> PromptTemplate {
        PromptTemplate::parse(include_str!("../dist/prompt.template").to_owned()).unwrap()
    }

    #[test]
    fn command_display_preserves_boundaries_and_escapes_unsafe_text() {
        let display = format_command(&request(&[
            "echo",
            "two words",
            "",
            "quote\"\\",
            "<&>\n\r\t\u{7f}\u{2028}\u{2029}\u{061c}\u{200e}\u{202e}\u{2066}\u{206f}",
        ]))
        .unwrap();
        assert_eq!(
            display,
            "[\"echo\", \"two words\", \"\", \"quote\\\"\\\\\", \"\\u{3c}\\u{26}\\u{3e}\\n\\r\\t\\u{7f}\\u{2028}\\u{2029}\\u{61c}\\u{200e}\\u{202e}\\u{2066}\\u{206f}\"]"
        );
    }

    #[test]
    fn default_prompt_uses_only_broker_derived_context() {
        let description = HumanDescription::new("inspect <account>").unwrap();
        let prompt = default_template()
            .render(&request(&["id"]), Some(&description), "/actual")
            .unwrap();
        assert_eq!(
            prompt,
            "Authentication is required to run as root:\ninspect \\u{3c}account\\u{3e}\n[\"id\"]\nin /actual\nwith 1 environment override(s)"
        );
    }

    #[test]
    fn template_rejects_malformed_and_unknown_placeholders() {
        assert!(matches!(
            PromptTemplate::parse("{command".to_owned()),
            Err(PromptTemplateError::Parse(_))
        ));
        assert!(matches!(
            PromptTemplate::parse("{environment}".to_owned()),
            Err(PromptTemplateError::UnknownPlaceholder(_))
        ));
    }

    #[test]
    fn values_are_not_reparsed_and_presentation_bounds_are_enforced() {
        let description = HumanDescription::new("literal {command}").unwrap();
        let template = PromptTemplate::parse("{description_line}".to_owned()).unwrap();
        assert_eq!(
            template
                .render(&request(&["id"]), Some(&description), "/")
                .unwrap(),
            "\nliteral {command}"
        );

        assert!(matches!(
            PromptTemplate::parse("x".repeat(MAX_PROMPT_TEMPLATE_BYTES + 1)),
            Err(PromptTemplateError::TemplateTooLong { .. })
        ));
        let oversized = "x".repeat(MAX_COMMAND_DISPLAY_BYTES);
        assert!(matches!(
            format_command(&request(&[&oversized])),
            Err(PromptTemplateError::ValueTooLong {
                field: "command",
                ..
            })
        ));
        let description = HumanDescription::new("<".repeat(MAX_DESCRIPTION_BYTES)).unwrap();
        assert!(matches!(
            template.render(&request(&["id"]), Some(&description), "/"),
            Err(PromptTemplateError::ValueTooLong {
                field: "description",
                ..
            })
        ));
        let template = PromptTemplate::parse("{cwd}".to_owned()).unwrap();
        assert!(matches!(
            template.render(&request(&["id"]), None, &"<".repeat(MAX_CWD_DISPLAY_BYTES)),
            Err(PromptTemplateError::ValueTooLong {
                field: "working directory",
                ..
            })
        ));
        let template = PromptTemplate::parse("{command}".repeat(9)).unwrap();
        let command = "x".repeat(MAX_COMMAND_DISPLAY_BYTES - 4);
        assert!(matches!(
            template.render(&request(&[&command]), None, "/"),
            Err(PromptTemplateError::PromptTooLong { .. })
        ));
    }
}
