//! Sensitive-diagnostic redaction: secrets never cross the vocabulary boundary.
//!
//! A diagnostic may quote the material it describes, and quoted material may
//! contain secrets. [`RedactedDiagnostic`] carries only the redacted form: the
//! original value is never stored, and validation rejects any record that still
//! contains a sensitive marker.
//!
//! Redaction follows one closed rule, applied fail-closed per the privacy Hard
//! Boundary: a sensitive marker redacts itself and everything after it on the
//! same line, and a `-----BEGIN-----` block redacts through its `-----END-----`
//! line. Over-redaction is always preferred to a leak.

use serde::{Deserialize, Serialize};

use crate::{CueContractError, CueKind, Digest, bounds};

/// Closed marker set that forces redaction, matched `ASCII`-case-insensitively.
pub const SENSITIVE_MARKERS: &[&str] = &[
    "secret",
    "passwd",
    "password",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "token",
    "bearer",
    "authorization",
    "cookie",
    "private_key",
    "credential",
    "-----begin",
];

/// Replacement text substituted for one redacted span.
pub const REDACTED_SPAN: &str = "[redacted]";

/// Line marker that opens a multi-line sensitive block.
const BEGIN_MARKER: &str = "-----begin";

/// Line marker that closes a multi-line sensitive block.
const END_MARKER: &str = "-----end";

#[derive(Serialize)]
struct DiagnosticPreimage<'a> {
    schema_revision: &'a str,
    kind: &'a CueKind,
    redacted_value: &'a str,
}

/// A diagnostic that has passed through redaction.
///
/// Only the redacted value is retained. There is no field for the original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RedactedDiagnostic {
    /// What kind of cue the diagnostic describes.
    pub kind: CueKind,
    /// The diagnostic with every sensitive span replaced by `[redacted]`.
    pub redacted_value: String,
    /// Digest over the redacted value.
    pub digest: Digest,
}

impl RedactedDiagnostic {
    /// Redacts a diagnostic value under the closed marker rule.
    ///
    /// # Errors
    /// Rejects blank input and input whose redacted form exceeds the declared
    /// text bound. Clean input passes through unchanged. Line breaks and tabs
    /// are legitimate diagnostic content and are preserved, not rejected.
    pub fn redact(kind: CueKind, value: &str) -> Result<Self, CueContractError> {
        diagnostic_text(value, "diagnostic.value")?;
        let redacted_value = apply_redaction(value)?;
        diagnostic_text(&redacted_value, "diagnostic.redacted_value")?;
        let digest = Digest::new(eliot_contracts::sha256_hex(redacted_value.as_bytes()))?;
        Ok(Self {
            kind,
            redacted_value,
            digest,
        })
    }

    /// Returns the versioned canonical JSON preimage, excluding `digest`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        self.validate_shape()?;
        let preimage = DiagnosticPreimage {
            schema_revision: crate::CONTRACT_REVISION,
            kind: &self.kind,
            redacted_value: &self.redacted_value,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "diagnostic.canonical_payload",
            }
        })?;
        let mut total = 0;
        bounds::bytes(&mut total, bytes.len(), "diagnostic.canonical_payload")?;
        Ok(bytes)
    }

    /// Computes this diagnostic's canonical digest.
    pub fn canonical_digest(&self) -> Result<Digest, CueContractError> {
        let bytes = self.canonical_payload_bytes()?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a redacted value that still contains a sensitive marker, an
    /// unbounded value, and a digest that does not match the redacted value.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        let expected = Digest::new(eliot_contracts::sha256_hex(self.redacted_value.as_bytes()))?;
        if self.digest != expected {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        diagnostic_text(&self.redacted_value, "diagnostic.redacted_value")?;
        if find_marker(&self.redacted_value).is_some() {
            return Err(CueContractError::InvalidText {
                field: "diagnostic.redacted_value",
            });
        }
        Ok(())
    }
}

/// Bounded diagnostic text: like [`bounds`] text, but line breaks and tabs are
/// legitimate diagnostic content rather than control characters.
fn diagnostic_text(value: &str, field: &'static str) -> Result<(), CueContractError> {
    if value.len() > bounds::MAX_TEXT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: bounds::MAX_TEXT_BYTES,
        });
    }
    if value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(CueContractError::InvalidText { field });
    }
    Ok(())
}

/// Applies the closed redaction rule. Total over all inputs, deterministic.
///
/// Every cut lands on an `ASCII` byte, which is always a character boundary,
/// so the output is always well-formed `UTF-8`.
fn apply_redaction(value: &str) -> Result<String, CueContractError> {
    let bytes = value.as_bytes();
    let folded = value.to_ascii_lowercase();
    let folded_bytes = folded.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(marker_len) = match_marker_at(folded_bytes, index) {
            if folded_bytes[index..].starts_with(BEGIN_MARKER.as_bytes()) {
                index = end_of_block(folded_bytes, index + marker_len);
            } else {
                index = end_of_line(bytes, index + marker_len);
            }
            output.extend_from_slice(REDACTED_SPAN.as_bytes());
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| CueContractError::InvalidText {
        field: "diagnostic.redacted_value",
    })
}

/// Returns the length of the longest sensitive marker matching at `index`.
fn match_marker_at(folded: &[u8], index: usize) -> Option<usize> {
    let mut longest: Option<usize> = None;
    for marker in SENSITIVE_MARKERS {
        let marker_bytes = marker.as_bytes();
        if folded[index..].starts_with(marker_bytes)
            && longest.is_none_or(|best| marker_bytes.len() > best)
        {
            longest = Some(marker_bytes.len());
        }
    }
    longest
}

/// Finds the first sensitive marker in a redacted value, if any.
fn find_marker(value: &str) -> Option<&'static str> {
    let folded = value.to_ascii_lowercase();
    let folded_bytes = folded.as_bytes();
    for marker in SENSITIVE_MARKERS {
        let marker_bytes = marker.as_bytes();
        if marker_bytes.len() <= folded_bytes.len()
            && folded_bytes
                .windows(marker_bytes.len())
                .any(|window| window == marker_bytes)
        {
            return Some(marker);
        }
    }
    None
}

/// End of the sensitive block: end of the `-----END-----` line when present,
/// else end of the current line, else end of input.
fn end_of_block(folded: &[u8], from: usize) -> usize {
    let mut cursor = from;
    while cursor < folded.len() {
        if folded[cursor..].starts_with(END_MARKER.as_bytes()) {
            return end_of_line(folded, cursor + END_MARKER.len());
        }
        cursor += 1;
    }
    end_of_line(folded, from)
}

/// End of the current line: the next `\n`, or end of input.
fn end_of_line(bytes: &[u8], from: usize) -> usize {
    let mut cursor = from;
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        cursor += 1;
    }
    cursor
}
