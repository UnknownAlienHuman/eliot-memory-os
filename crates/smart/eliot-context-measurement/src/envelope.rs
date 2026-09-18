//! Exact serialized-envelope validation: UTF-8 shape, leaf and route
//! bounds, declared length, content digest, serializer/schema identity and
//! the supported A-15 contract revision.

use eliot_context_contracts::{CONTEXT_CONTRACT_VERSION, ContextError};
use eliot_contracts::{ContractVersion, sha256_hex};

use crate::{MAX_IDENTITY_TEXT_BYTES, MAX_MEASUREMENT_BYTES};

/// Serializer/schema identity bound to one measurement.
#[derive(Clone, Debug)]
pub struct SerializerIdentity {
    /// Required serializer identity.
    pub serializer_id: String,
    /// Required serializer revision.
    pub serializer_version: String,
    /// Required serializer-options digest (lowercase SHA-256 hex).
    pub serializer_options_digest: String,
    /// Required payload schema revision; only the accepted A-15 revision passes.
    pub schema_revision: ContractVersion,
}

impl SerializerIdentity {
    /// Validate identity texts, options-digest shape and supported revision.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_identity_text(&self.serializer_id, "measurement.serializer_id")?;
        validate_identity_text(&self.serializer_version, "measurement.serializer_version")?;
        validate_digest(
            &self.serializer_options_digest,
            "measurement.serializer_options_digest",
        )?;
        if self.schema_revision != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField("measurement.schema_version"));
        }
        Ok(())
    }
}

/// Validated exact envelope: actual byte length and content digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEnvelope {
    /// Exact UTF-8 byte length of the final serialized envelope.
    pub byte_len: u64,
    /// `sha256_hex` of the exact envelope bytes.
    pub digest: String,
}

/// Validate bounded identity text: bounded length, non-blank, no controls.
pub(crate) fn validate_identity_text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.len() > MAX_IDENTITY_TEXT_BYTES {
        return Err(ContextError::Bounds { field });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContextError::InvalidField(field));
    }
    Ok(())
}

/// Validate a lowercase SHA-256 hex digest shape.
pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ContextError::InvalidDigest(field));
    }
    Ok(())
}

/// Validate one exact serialized envelope.
///
/// A declared length that disagrees with the actual bytes is a typed error,
/// never silently corrected. A well-formed digest over different bytes is an
/// identity conflict, not a quiet rebind.
pub fn validate_envelope(
    payload: &[u8],
    declared_len: u64,
    content_digest: &str,
    max_serialized_bytes: u64,
) -> Result<ValidatedEnvelope, ContextError> {
    if max_serialized_bytes == 0 {
        return Err(ContextError::Bounds {
            field: "measurement.max_serialized_bytes",
        });
    }
    let actual = u64::try_from(payload.len()).map_err(|_| ContextError::Overflow)?;
    if actual > MAX_MEASUREMENT_BYTES {
        return Err(ContextError::Bounds {
            field: "measurement.rendered_bytes",
        });
    }
    if actual > max_serialized_bytes {
        return Err(ContextError::Bounds {
            field: "measurement.rendered_bytes",
        });
    }
    std::str::from_utf8(payload)
        .map_err(|_| ContextError::InvalidField("measurement.payload_utf8"))?;
    if declared_len != actual {
        return Err(ContextError::InvalidField("measurement.declared_len"));
    }
    validate_digest(content_digest, "measurement.content_digest")?;
    let digest = sha256_hex(payload);
    if digest != content_digest {
        return Err(ContextError::IdentityConflict);
    }
    Ok(ValidatedEnvelope {
        byte_len: actual,
        digest,
    })
}
