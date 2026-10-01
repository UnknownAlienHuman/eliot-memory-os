//! Neutral reference and readback contract for retained native-worker provider
//! material.
//!
//! The claim operation is the dispatch identity used to locate the immutable
//! material. A provider subprocess has its own operation identity inside the
//! closed material body; it is never inferred from the supervisor or claim
//! operation. This crate validates byte integrity only and does not interpret
//! provider authority or decode provider-specific fields.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Maximum canonical JSON body returned for one retained provider material
/// readback. The bound applies before JSON parsing.
pub const MAX_NATIVE_WORKER_RETAINED_PROVIDER_MATERIAL_BYTES: usize = 512 * 1024;

/// Exact dispatch-scoped identity of one retained provider material object.
///
/// `dispatch_operation_id` is the original claim/dispatch operation. The
/// provider-specific child operation remains inside the owner-issued material
/// body and must be independently matched to its sealed `ProcessRequest` by
/// the native-worker execution owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedProviderMaterialRefV1 {
    /// Original ORS claim identity.
    pub claim_id: String,
    /// Original dispatch/claim operation identity.
    pub dispatch_operation_id: String,
    /// Original admitted attempt identity.
    pub attempt_id: String,
    /// Original native-worker executable-binding digest.
    pub binding_digest: String,
    /// Opaque owner reference; it is never treated as a filesystem path.
    pub material_ref: String,
    /// SHA-256 of the exact canonical JSON material bytes.
    pub material_sha256: String,
}

impl NativeWorkerRetainedProviderMaterialRefV1 {
    /// Validates the complete reference without interpreting its owner scope.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (&self.claim_id, "native_worker_material.claim_id"),
            (
                &self.dispatch_operation_id,
                "native_worker_material.dispatch_operation_id",
            ),
            (&self.attempt_id, "native_worker_material.attempt_id"),
            (&self.material_ref, "native_worker_material.material_ref"),
        ] {
            validate_text(value, field)?;
        }
        for (value, field) in [
            (&self.binding_digest, "native_worker_material.binding_digest"),
            (&self.material_sha256, "native_worker_material.material_sha256"),
        ] {
            validate_sha256(value, field)?;
        }
        Ok(())
    }
}

/// Authenticated owner readback: original reference plus its unchanged
/// canonical JSON bytes encoded as UTF-8.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedProviderMaterialReadbackV1 {
    /// Exact owner-issued lookup reference.
    pub reference: NativeWorkerRetainedProviderMaterialRefV1,
    /// Exact canonical UTF-8 JSON bytes issued by the owner.
    pub canonical_material_json: String,
}

impl NativeWorkerRetainedProviderMaterialReadbackV1 {
    /// Validates exact lookup identity, canonical encoding and the original
    /// material digest. Provider-specific schemas are left to their owner.
    pub fn validate_for(
        &self,
        expected: &NativeWorkerRetainedProviderMaterialRefV1,
    ) -> Result<(), ProtocolError> {
        self.reference.validate()?;
        if &self.reference != expected {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.reference",
                reason: "readback does not bind the requested original identity",
            });
        }
        if self.canonical_material_json.len()
            > MAX_NATIVE_WORKER_RETAINED_PROVIDER_MATERIAL_BYTES
        {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.canonical_material_json",
                reason: "retained material exceeds its byte bound",
            });
        }
        let value: serde_json::Value = serde_json::from_str(&self.canonical_material_json)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if !value.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.canonical_material_json",
                reason: "retained material must be a JSON object",
            });
        }
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if canonical.as_slice() != self.canonical_material_json.as_bytes() {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.canonical_material_json",
                reason: "readback bytes are not canonical JSON",
            });
        }
        if sha256_hex(&canonical) != self.reference.material_sha256 {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.material_sha256",
                reason: "readback bytes do not match the original owner digest",
            });
        }
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty()
        || value.len() > 1024
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be bounded non-blank text without controls",
        });
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(material: &[u8]) -> NativeWorkerRetainedProviderMaterialRefV1 {
        NativeWorkerRetainedProviderMaterialRefV1 {
            claim_id: "claim:1".to_owned(),
            dispatch_operation_id: "native-dispatch:1".to_owned(),
            attempt_id: "attempt:1".to_owned(),
            binding_digest: "a".repeat(64),
            material_ref: "provider-material:1".to_owned(),
            material_sha256: sha256_hex(material),
        }
    }

    #[test]
    fn retained_provider_material_readback_accepts_exact_original_bytes() {
        let value = serde_json::json!({
            "provider_operation_id": "provider-child:1",
            "schema": "claude-attempt-material.v1",
        });
        let bytes = canonical_json_bytes(&value).expect("canonical JSON");
        let text = String::from_utf8(bytes.clone()).expect("UTF-8");
        let reference = reference(&bytes);
        let readback = NativeWorkerRetainedProviderMaterialReadbackV1 {
            reference: reference.clone(),
            canonical_material_json: text,
        };
        readback.validate_for(&reference).expect("exact owner readback");
    }

    #[test]
    fn retained_provider_material_readback_refuses_changed_bytes() {
        let original = br#"{"provider_operation_id":"provider-child:1","schema":"claude-attempt-material.v1"}"#;
        let reference = reference(original);
        let readback = NativeWorkerRetainedProviderMaterialReadbackV1 {
            reference: reference.clone(),
            canonical_material_json:
                r#"{"provider_operation_id":"provider-child:2","schema":"claude-attempt-material.v1"}"#
                    .to_owned(),
        };
        assert!(readback.validate_for(&reference).is_err());
    }
}
