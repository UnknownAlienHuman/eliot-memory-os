use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextEncodingViolation {
    pub path: String,
    pub reason: String,
}

pub fn mojibake(text: &str) -> Option<&'static str> {
    let chars = text.chars().collect::<Vec<_>>();
    if chars.contains(&'\u{fffd}') {
        return Some("replacement_char");
    }

    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '?' {
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < chars.len() && chars[end] == '?' {
            end += 1;
        }
        if end - index >= 3 {
            let before = &chars[index.saturating_sub(8)..index];
            let after = &chars[end..(end + 8).min(chars.len())];
            if before
                .iter()
                .chain(after)
                .any(|character| ('\u{0400}'..='\u{04ff}').contains(character))
            {
                return Some("qmark_run");
            }
        }
        index = end;
    }
    None
}

pub fn inspect_text_encoding(value: &Value) -> Vec<TextEncodingViolation> {
    fn inspect(value: &Value, path: &str, violations: &mut Vec<TextEncodingViolation>) {
        match value {
            Value::String(text) => {
                if let Some(reason) = mojibake(text) {
                    violations.push(TextEncodingViolation {
                        path: path.to_owned(),
                        reason: reason.to_owned(),
                    });
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    inspect(item, &format!("{path}[{index}]"), violations);
                }
            }
            Value::Object(fields) => {
                for (name, field) in fields {
                    inspect(field, &format!("{path}.{name}"), violations);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    let mut violations = Vec::new();
    inspect(value, "$", &mut violations);
    violations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    violations.dedup();
    violations
}
