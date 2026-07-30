use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum byte sequence accepted by the common pre-persistence secret scan.
pub const MAX_SECRET_BOUNDARY_BYTES: usize = 8 * 1024 * 1024;

const SAFE_SECRET_PLACEHOLDERS: &[&[u8]] = &[
    b"[redacted]",
    b"<redacted>",
    b"redacted",
    b"placeholder",
    b"example",
    b"not-set",
    b"undefined",
    b"${secret}",
];

/// Non-sensitive classification emitted when content is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBoundaryRule {
    OutputTooLarge,
    PrivateKeyBlock,
    AuthorizationHeader,
    CredentialAssignment,
    StructuredToken,
    ProviderTokenPrefix,
}

impl SecretBoundaryRule {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputTooLarge => "output_too_large",
            Self::PrivateKeyBlock => "private_key_block",
            Self::AuthorizationHeader => "authorization_header",
            Self::CredentialAssignment => "credential_assignment",
            Self::StructuredToken => "structured_token",
            Self::ProviderTokenPrefix => "provider_token_prefix",
        }
    }
}

impl fmt::Display for SecretBoundaryRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Category-only secret rejection. It intentionally contains neither the
/// matching value nor a digest derived from the rejected bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecretBoundaryViolation {
    pub rule: SecretBoundaryRule,
}

impl fmt::Display for SecretBoundaryViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "secret boundary rejected content: {}", self.rule)
    }
}

impl std::error::Error for SecretBoundaryViolation {}

/// Inspects bytes before any durable write, parse, or content-derived digest.
///
/// The scanner is deliberately deterministic, bounded, and ASCII-oriented so
/// it can operate on text or binary envelopes without decoding the content.
pub fn inspect_secret_bytes(bytes: &[u8]) -> Result<(), SecretBoundaryViolation> {
    if bytes.len() > MAX_SECRET_BOUNDARY_BYTES {
        return reject(SecretBoundaryRule::OutputTooLarge);
    }
    let lower = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    if contains(&lower, b"-----begin private key-----")
        || contains(&lower, b"-----begin rsa private key-----")
        || contains(&lower, b"-----begin ec private key-----")
        || contains(&lower, b"-----begin openssh private key-----")
    {
        return reject(SecretBoundaryRule::PrivateKeyBlock);
    }
    if contains_authorization_value(&lower) {
        return reject(SecretBoundaryRule::AuthorizationHeader);
    }
    if contains_credential_assignment(&lower) {
        return reject(SecretBoundaryRule::CredentialAssignment);
    }
    if contains_structured_token(bytes) {
        return reject(SecretBoundaryRule::StructuredToken);
    }
    if contains_provider_token_prefix(bytes) {
        return reject(SecretBoundaryRule::ProviderTokenPrefix);
    }
    Ok(())
}

fn reject(rule: SecretBoundaryRule) -> Result<(), SecretBoundaryViolation> {
    Err(SecretBoundaryViolation { rule })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_authorization_value(lower: &[u8]) -> bool {
    lower
        .split(|byte| matches!(byte, b'\r' | b'\n'))
        .any(|line| {
            let Some(index) = find(line, b"authorization") else {
                return false;
            };
            let tail = &line[index + b"authorization".len()..];
            let tail = trim_ascii(tail);
            let Some(tail) = tail.strip_prefix(b":").or_else(|| tail.strip_prefix(b"=")) else {
                return false;
            };
            let value = trim_ascii(tail);
            [b"bearer ".as_slice(), b"basic ".as_slice()]
                .into_iter()
                .any(|prefix| {
                    value.starts_with(prefix)
                        && meaningful_secret_value(trim_ascii(&value[prefix.len()..]))
                })
        })
}

fn contains_credential_assignment(lower: &[u8]) -> bool {
    const KEYS: &[&[u8]] = &[
        b"password",
        b"passwd",
        b"secret",
        b"api_key",
        b"apikey",
        b"access_token",
        b"refresh_token",
        b"client_secret",
        b"private_key",
    ];
    lower
        .split(|byte| matches!(byte, b'\r' | b'\n'))
        .any(|line| {
            KEYS.iter().any(|key| {
                matches_for_each(line, key, |before, after| {
                    let previous_ok = before
                        .last()
                        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
                    if !previous_ok {
                        return false;
                    }
                    let after = trim_ascii_start(after);
                    let after = after.strip_prefix(b"\"").unwrap_or(after);
                    let after = trim_ascii_start(after);
                    let Some(value) = after
                        .strip_prefix(b":")
                        .or_else(|| after.strip_prefix(b"="))
                    else {
                        return false;
                    };
                    meaningful_secret_value(trim_ascii(value))
                })
            })
        })
}

fn meaningful_secret_value(value: &[u8]) -> bool {
    let value = trim_ascii(value);
    let value = value.strip_prefix(b"\"").unwrap_or(value);
    let end = value
        .iter()
        .position(|byte| matches!(byte, b'\"' | b'\'' | b',' | b';' | b'}'))
        .unwrap_or(value.len());
    let value = trim_ascii(&value[..end]);
    if value.len() < 8 {
        return false;
    }
    !SAFE_SECRET_PLACEHOLDERS.contains(&value)
        && !value.iter().all(|byte| matches!(byte, b'*' | b'x'))
        && !value.starts_with(b"$env:")
        && !value.starts_with(b"%")
}

fn contains_structured_token(bytes: &[u8]) -> bool {
    bytes.split(|byte| !is_token_byte(*byte)).any(|token| {
        if !token.starts_with(b"eyJ") {
            return false;
        }
        let parts = token.split(|byte| *byte == b'.').collect::<Vec<_>>();
        parts.len() == 3 && parts[0].len() >= 12 && parts[1].len() >= 12 && parts[2].len() >= 12
    })
}

fn contains_provider_token_prefix(bytes: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"AKIA",
        b"ASIA",
        b"ghp_",
        b"github_pat_",
        b"sk-",
        b"xoxb-",
        b"xoxp-",
        b"AIza",
    ];
    PREFIXES.iter().any(|prefix| {
        matches_for_each(bytes, prefix, |before, after| {
            let token_boundary = before.last().is_none_or(|byte| !is_token_byte(*byte));
            token_boundary
                && after
                    .iter()
                    .take_while(|byte| is_token_byte(**byte))
                    .take(16)
                    .count()
                    >= 16
        })
    })
}

fn matches_for_each(
    haystack: &[u8],
    needle: &[u8],
    mut predicate: impl FnMut(&[u8], &[u8]) -> bool,
) -> bool {
    let mut offset = 0;
    while let Some(relative) = find(&haystack[offset..], needle) {
        let index = offset + relative;
        if predicate(&haystack[..index], &haystack[index + needle.len()..]) {
            return true;
        }
        offset = index + needle.len();
    }
    false
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(bytes))
}

fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}

fn trim_ascii_end(mut bytes: &[u8]) -> &[u8] {
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{SecretBoundaryRule, inspect_secret_bytes};

    #[test]
    fn rejects_secret_classes_without_returning_values() -> Result<(), &'static str> {
        for (input, rule) in [
            (
                "-----BEGIN PRIVATE KEY-----\nsynthetic\n",
                SecretBoundaryRule::PrivateKeyBlock,
            ),
            (
                "Authorization: Bearer synthetic-token-value-12345",
                SecretBoundaryRule::AuthorizationHeader,
            ),
            (
                "client_secret = \"synthetic-value-12345\"",
                SecretBoundaryRule::CredentialAssignment,
            ),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.signaturevalue1234",
                SecretBoundaryRule::StructuredToken,
            ),
            (
                "ghp_syntheticTokenValue1234567890",
                SecretBoundaryRule::ProviderTokenPrefix,
            ),
        ] {
            let Some(violation) = inspect_secret_bytes(input.as_bytes()).err() else {
                return Err("secret fixture was unexpectedly accepted");
            };
            assert_eq!(violation.rule, rule);
            assert!(!violation.to_string().contains("synthetic"));
        }
        Ok(())
    }

    #[test]
    fn permits_redacted_and_metadata_only_content() -> Result<(), super::SecretBoundaryViolation> {
        for input in [
            r#"{"secret_values_redacted":true,"tokens_used":12}"#,
            r#"password_file = "%LOCALAPPDATA%/Eliot/secrets/value.txt""#,
            r#"{"client_secret":"[redacted]"}"#,
            "the password field is resolved internally",
        ] {
            inspect_secret_bytes(input.as_bytes())?;
        }
        Ok(())
    }

    #[test]
    fn secret_prefix_requires_token_boundary() -> Result<(), super::SecretBoundaryViolation> {
        inspect_secret_bytes(b"prefixsk-synthetic-token-value-12345")
    }

    #[test]
    fn canonical_task_intent_oracle_version_is_not_a_provider_token()
    -> Result<(), super::SecretBoundaryViolation> {
        inspect_secret_bytes(b"eliot-task-intent-oracle-v1")
    }

    #[test]
    fn actual_openai_style_prefix_is_still_rejected() {
        for input in [
            b"sk-synthetic-token-value-12345".as_slice(),
            b"token=sk-synthetic-token-value-12345".as_slice(),
        ] {
            assert_eq!(
                inspect_secret_bytes(input).map_err(|violation| violation.rule),
                Err(SecretBoundaryRule::ProviderTokenPrefix)
            );
        }
    }
}
