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

/// Owner-issued correlation for the provider child process associated with a
/// retained provider material body. This is inert identity only: it carries
/// neither a process request nor dispatch-permit authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerProviderProcessIdentityV1 {
    /// Stable child operation issued by the Kernel process owner.
    pub provider_operation_id: String,
    /// Exact sealed provider `ProcessRequest` invocation digest.
    pub provider_process_invocation_digest: String,
    /// Exact executable digest in that provider process intent.
    pub provider_executable_digest: String,
    /// Opaque reference to the in-process retained sealed request owner row.
    /// It is never interpreted as a filesystem path or request encoding.
    pub process_ref: String,
}

impl NativeWorkerProviderProcessIdentityV1 {
    /// Validates the independently owner-issued process identity shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (
                &self.provider_operation_id,
                "native_worker_provider_process.provider_operation_id",
            ),
            (
                &self.process_ref,
                "native_worker_provider_process.process_ref",
            ),
        ] {
            validate_text(value, field)?;
        }
        for (value, field) in [
            (
                &self.provider_process_invocation_digest,
                "native_worker_provider_process.provider_process_invocation_digest",
            ),
            (
                &self.provider_executable_digest,
                "native_worker_provider_process.provider_executable_digest",
            ),
        ] {
            validate_sha256(value, field)?;
        }
        Ok(())
    }
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
    /// Independently retained identity of the sealed provider process.
    pub provider_process: NativeWorkerProviderProcessIdentityV1,
    /// Exact canonical UTF-8 JSON bytes issued by the owner.
    pub canonical_material_json: String,
}

impl NativeWorkerRetainedProviderMaterialReadbackV1 {
    /// Validates exact lookup identity, canonical encoding and the original
    /// material digest. Provider-specific schemas are left to their owner.
    pub fn validate_for(
        &self,
        expected: &NativeWorkerRetainedProviderMaterialRefV1,
        expected_process: &NativeWorkerProviderProcessIdentityV1,
    ) -> Result<(), ProtocolError> {
        self.reference.validate()?;
        if &self.reference != expected {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.reference",
                reason: "readback does not bind the requested original identity",
            });
        }
        self.provider_process.validate()?;
        if &self.provider_process != expected_process {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.provider_process",
                reason: "readback does not bind the independently retained provider process",
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
        let provider_operation_id = value
            .get("provider_operation_id")
            .and_then(serde_json::Value::as_str);
        let provider_process_invocation_digest = value
            .get("provider_process_invocation_digest")
            .and_then(serde_json::Value::as_str);
        let provider_executable_digest = value
            .get("provider_executable_digest")
            .and_then(serde_json::Value::as_str);
        let process_ref = value.get("process_ref").and_then(serde_json::Value::as_str);
        if provider_operation_id != Some(expected_process.provider_operation_id.as_str())
            || provider_process_invocation_digest
                != Some(expected_process.provider_process_invocation_digest.as_str())
            || provider_executable_digest
                != Some(expected_process.provider_executable_digest.as_str())
            || process_ref != Some(expected_process.process_ref.as_str())
        {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material.provider_process",
                reason: "canonical material does not match the owner-retained process identity",
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

    fn provider_process() -> NativeWorkerProviderProcessIdentityV1 {
        NativeWorkerProviderProcessIdentityV1 {
            provider_operation_id: "provider-child:1".to_owned(),
            provider_process_invocation_digest: "b".repeat(64),
            provider_executable_digest: "c".repeat(64),
            process_ref: "provider-process-request:1".to_owned(),
        }
    }

    #[test]
    fn retained_provider_material_readback_accepts_exact_original_bytes() {
        let value = serde_json::json!({
            "provider_operation_id": "provider-child:1",
            "provider_process_invocation_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "provider_executable_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "process_ref": "provider-process-request:1",
            "schema": "claude-attempt-material.v1",
        });
        let bytes = canonical_json_bytes(&value).expect("canonical JSON");
        let text = String::from_utf8(bytes.clone()).expect("UTF-8");
        let reference = reference(&bytes);
        let readback = NativeWorkerRetainedProviderMaterialReadbackV1 {
            reference: reference.clone(),
            provider_process: provider_process(),
            canonical_material_json: text,
        };
        readback
            .validate_for(&reference, &provider_process())
            .expect("exact owner readback");
    }

    #[test]
    fn retained_provider_material_readback_refuses_changed_bytes() {
        let original = br#"{"provider_executable_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","provider_operation_id":"provider-child:1","provider_process_invocation_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","process_ref":"provider-process-request:1","schema":"claude-attempt-material.v1"}"#;
        let reference = reference(original);
        let readback = NativeWorkerRetainedProviderMaterialReadbackV1 {
            reference: reference.clone(),
            provider_process: provider_process(),
            canonical_material_json:
                r#"{"provider_executable_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","provider_operation_id":"provider-child:2","provider_process_invocation_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","process_ref":"provider-process-request:1","schema":"claude-attempt-material.v1"}"#
                    .to_owned(),
        };
        assert!(readback
            .validate_for(&reference, &provider_process())
            .is_err());
    }
}
