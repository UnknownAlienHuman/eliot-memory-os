use std::collections::{BTreeSet, HashSet};

const STOP_EN: &[&str] = &[
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "is", "are", "was", "were", "be",
    "been", "it", "this", "that", "these", "those", "with", "as", "by", "at", "from", "we", "you",
    "i", "do", "does", "did", "can", "could", "should", "would", "when", "what", "how", "why",
];
const STOP_RU: &[&str] = &[
    "и",
    "в",
    "во",
    "не",
    "на",
    "я",
    "с",
    "со",
    "как",
    "а",
    "то",
    "все",
    "она",
    "так",
    "его",
    "но",
    "да",
    "ты",
    "к",
    "у",
    "же",
    "вы",
    "за",
    "бы",
    "по",
    "ее",
    "мне",
    "было",
    "вот",
    "от",
    "о",
    "из",
    "ему",
    "когда",
    "что",
    "это",
    "для",
    "или",
    "если",
    "при",
];

#[must_use]
pub fn normalize_unicode_lowercase(raw: &str) -> String {
    raw.chars().flat_map(char::to_lowercase).collect()
}

fn slash_normalize(raw: &str) -> String {
    let without_extended = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let mut result = String::with_capacity(without_extended.len());
    let mut previous_slash = false;
    for character in without_extended.chars() {
        let character = if character == '\\' { '/' } else { character };
        if character == '/' {
            if previous_slash {
                continue;
            }
            previous_slash = true;
        } else {
            previous_slash = false;
        }
        result.push(character);
    }
    result
}

fn normalize_relative_boundary_value(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let normalized = normalized.trim();
    let normalized = normalized.trim_start_matches("./");
    let normalized = normalized.trim_matches('/');

    if normalized.is_empty() {
        ".".to_owned()
    } else {
        normalized.to_owned()
    }
}

#[must_use]
pub fn path_matches_boundary(path: &str, boundary: &str) -> bool {
    let path = normalize_relative_boundary_value(path);
    let boundary = normalize_relative_boundary_value(boundary);

    if boundary == "." {
        return true;
    }

    path == boundary
        || path
            .strip_prefix(boundary.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[must_use]
pub fn normalize_path(raw: &str, project_root: Option<&str>) -> String {
    let mut path = normalize_unicode_lowercase(&slash_normalize(raw.trim()));
    if let Some(root) = project_root {
        let root = normalize_unicode_lowercase(&slash_normalize(root.trim()))
            .trim_end_matches('/')
            .to_owned();
        if path == root {
            path.clear();
        } else if let Some(suffix) = path.strip_prefix(&format!("{root}/")) {
            path = suffix.to_owned();
        }
    }
    while let Some(suffix) = path.strip_prefix("./") {
        path = suffix.to_owned();
    }
    path = path
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_owned();
    path
}

#[must_use]
pub fn normalize_observed_path(raw: &str) -> String {
    let trimmed = raw.trim_matches(|character: char| {
        matches!(
            character,
            '`' | '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
        )
    });
    let normalized = normalize_path(trimmed, None);
    normalized
        .strip_prefix("file:")
        .unwrap_or(&normalized)
        .split('#')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[must_use]
pub fn path_cue_tokens(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(normalize_observed_path)
        .filter(|path| {
            path.contains('/')
                && path
                    .rsplit('/')
                    .next()
                    .is_some_and(|leaf| leaf.contains('.') || leaf == "src")
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_identifier(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

#[must_use]
pub fn normalize_symbol(raw: &str) -> String {
    let characters = raw.trim().chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(raw.len());
    for (index, character) in characters.iter().copied().enumerate() {
        let separator = matches!(character, '.' | '#')
            && index > 0
            && index + 1 < characters.len()
            && is_identifier(characters[index - 1])
            && is_identifier(characters[index + 1]);
        if separator {
            normalized.push_str("::");
        } else {
            normalized.push(character);
        }
    }
    while normalized.contains("::::") {
        normalized = normalized.replace("::::", "::");
    }
    normalize_unicode_lowercase(&normalized)
}

#[must_use]
pub fn normalize_query_tokens(raw: &str) -> Vec<String> {
    let lower = normalize_unicode_lowercase(raw);
    let mut seen = HashSet::new();
    lower
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| {
            !token.is_empty()
                && !STOP_EN.contains(token)
                && !STOP_RU.contains(token)
                && seen.insert((*token).to_owned())
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[must_use]
pub fn command_pattern(argv: &[String]) -> String {
    let Some(executable) = argv.first() else {
        return String::new();
    };
    let basename = executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(executable)
        .trim();
    let mut pattern = normalize_unicode_lowercase(basename);
    if let Some(argument) = argv
        .iter()
        .skip(1)
        .find(|argument| !argument.starts_with('-'))
    {
        if !pattern.is_empty() {
            pattern.push(' ');
        }
        pattern.push_str(&normalize_unicode_lowercase(argument.trim()));
    }
    pattern
}

fn remove_quoted_contents(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut quote = None;
    for character in raw.chars() {
        match quote {
            Some(active) if character == active => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                result.push(' ');
            }
            None => result.push(character),
        }
    }
    result
}

fn normalize_error_message(raw: &str) -> String {
    let raw = remove_quoted_contents(&normalize_unicode_lowercase(raw));
    let characters = raw.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(raw.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index].is_ascii_hexdigit() {
            let start = index;
            while index < characters.len() && characters[index].is_ascii_hexdigit() {
                index += 1;
            }
            let run = &characters[start..index];
            if run.iter().all(char::is_ascii_digit) {
                normalized.push('#');
            } else if run.len() >= 8 {
                normalized.push('@');
            } else {
                normalized.extend(run);
            }
            continue;
        }
        if characters[index].is_numeric() {
            while index < characters.len() && characters[index].is_numeric() {
                index += 1;
            }
            normalized.push('#');
            continue;
        }
        normalized.push(characters[index]);
        index += 1;
    }
    normalized
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect()
}

#[must_use]
pub fn error_signature(
    tool_id: &str,
    rule_id: &str,
    message: &str,
    path: &str,
    project_root: Option<&str>,
) -> String {
    let message = normalize_error_message(message);
    let path_without_digits = normalize_path(path, project_root)
        .chars()
        .filter(|character| !character.is_numeric())
        .collect::<String>();
    let mut hasher = blake3::Hasher::new();
    for component in [tool_id, rule_id, &message, &path_without_digits] {
        hasher.update(component.as_bytes());
        hasher.update(b"|");
    }
    format!("sig:{}", hasher.finalize().to_hex())
}
