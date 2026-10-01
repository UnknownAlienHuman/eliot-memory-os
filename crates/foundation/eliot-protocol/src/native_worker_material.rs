//! Neutral reference and readback contract for retained native-worker provider
//! material.
//!
//! The claim operation is the dispatch identity used to locate the immutable
//! material. A provider subprocess has its own operation identity inside the
//! closed material body; it is never inferred from the supervisor or claim
//! operation. This crate validates byte integrity only and does not interpret
//! provider authority or decode provider-specific fields.

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Maximum canonical JSON body returned for one retained provider material
/// readback. The bound applies before JSON parsing.
pub const MAX_NATIVE_WORKER_RETAINED_PROVIDER_MATERIAL_BYTES: usize = 512 * 1024;
/// Upper bound for one inert provider-process admission projection.
pub const MAX_NATIVE_WORKER_PROVIDER_PROCESS_ADMISSION_BYTES: usize = 128 * 1024;
/// Authenticated Kernel operation that resolves the original material
/// reference from the active ORS claim row.
pub const NATIVE_WORKER_RETAINED_PROVIDER_MATERIAL_RESOLVE_OPERATION: &str =
    "native_worker.retained_material.resolve";
/// Authenticated Kernel operation that reads the original canonical material.
pub const NATIVE_WORKER_RETAINED_PROVIDER_MATERIAL_READ_OPERATION: &str =
    "native_worker.retained_material.read";
/// Authenticated Kernel operation that reads the separately sealed provider
/// process admission and grant.
pub const NATIVE_WORKER_PROVIDER_PROCESS_READ_OPERATION: &str =
    "native_worker.provider_process.read";

/// Authenticated lookup request for the original claim-scoped material
/// reference. Every field comes from the admitted worker session and exact
/// claim presentation; the reference itself is returned only from the
/// immutable ORS claim row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedProviderMaterialResolveRequestV1 {
    /// Original ORS claim identity.
    pub claim_id: String,
    /// Original dispatch/claim operation identity.
    pub dispatch_operation_id: String,
    /// Original admitted attempt identity.
    pub attempt_id: String,
    /// Original native-worker executable-binding digest.
    pub binding_digest: String,
    /// Worker registration generation presenting the lookup.
    pub worker_generation: u64,
    /// Exact admitted state fence.
    pub state_fence: StateFence,
    /// Exact admitted authority epoch.
    pub authority_epoch: EpochId,
}

impl NativeWorkerRetainedProviderMaterialResolveRequestV1 {
    /// Validates request shape and the fence/epoch join. Kernel still checks
    /// the authenticated session and live ORS/current-owner state.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (&self.claim_id, "native_worker_material_resolve.claim_id"),
            (
                &self.dispatch_operation_id,
                "native_worker_material_resolve.dispatch_operation_id",
            ),
            (&self.attempt_id, "native_worker_material_resolve.attempt_id"),
        ] {
            validate_text(value, field)?;
        }
        validate_sha256(
            &self.binding_digest,
            "native_worker_material_resolve.binding_digest",
        )?;
        if self.worker_generation == 0 {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material_resolve.worker_generation",
                reason: "must be nonzero",
            });
        }
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_material_resolve.authority_epoch",
                reason: "must equal the exact state-fence authority epoch",
            });
        }
        Ok(())
    }
}

/// Exact current-claim result of resolving the original material reference.
/// `Pending` and `Unknown` both carry no launch authority; only `Found` may be
/// followed by the separate authenticated read calls.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWorkerRetainedProviderMaterialResolveResponseV1 {
    /// Current active claim row contains this exact immutable owner reference.
    Found {
        /// Exact retained claim-scoped material reference.
        reference: NativeWorkerRetainedProviderMaterialRefV1,
        /// Exact independently retained provider child identity.
        provider_process: NativeWorkerProviderProcessIdentityV1,
    },
    /// The same identity is not yet published for use; retry/readback may
    /// continue under the same claim only.
    Pending {
        /// Bounded diagnostic reason, with no authority-bearing fields.
        reason: String,
    },
    /// Currentness or identity could not be established; caller must fail
    /// closed and reconcile the same operation.
    Unknown {
        /// Bounded diagnostic reason, with no authority-bearing fields.
        reason: String,
    },
}

/// Authenticated read request for exact owner-retained canonical material.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedProviderMaterialReadRequestV1 {
    /// Exact original reference returned by the Kernel resolve operation.
    pub reference: NativeWorkerRetainedProviderMaterialRefV1,
}

/// Exact read result for claim-scoped provider material.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWorkerRetainedProviderMaterialReadResponseV1 {
    /// Exact immutable bytes and provider-process identity from their owners.
    Found {
        /// Full readback checked against the request and current claim row.
        readback: NativeWorkerRetainedProviderMaterialReadbackV1,
    },
    /// Material is not yet available under this original claim identity.
    Pending {
        /// Bounded diagnostic reason.
        reason: String,
    },
    /// Claim or owner currentness could not be established.
    Unknown {
        /// Bounded diagnostic reason.
        reason: String,
    },
}

/// Authenticated request for the separately sealed provider process owner row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerProviderProcessReadRequestV1 {
    /// The claim-scoped material reference returned by Kernel resolve.
    pub reference: NativeWorkerRetainedProviderMaterialRefV1,
    /// The provider child identity independently bound to the retained body.
    pub provider_process: NativeWorkerProviderProcessIdentityV1,
}

/// Inert, wire-safe fields needed by the child to reconstruct one provider
/// dispatch grant locally. This projection carries no permit or ProcessRequest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerProviderProcessGrantV1 {
    /// Digest binding the exact provider admission and grant fields.
    pub grant_digest: String,
    /// Current authority epoch for the child-side fence constructor.
    pub authority_epoch: EpochId,
    /// Current activation generation for the child-side fence constructor.
    pub fence_generation: u64,
    /// Owner-issued per-operation fence nonce.
    pub fence_nonce: String,
    /// Owner-issued per-operation action lease reference.
    pub idempotency_key: String,
    /// Grant issue time in Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl NativeWorkerProviderProcessGrantV1 {
    /// Validates the grant's inert shape and freshness window.
    pub fn validate(&self, expected: &NativeWorkerProviderProcessIdentityV1) -> Result<(), ProtocolError> {
        validate_sha256(&self.grant_digest, "native_worker_provider_grant.grant_digest")?;
        validate_text(&self.fence_nonce, "native_worker_provider_grant.fence_nonce")?;
        validate_text(
            &self.idempotency_key,
            "native_worker_provider_grant.idempotency_key",
        )?;
        if self.fence_generation == 0
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_grant.window",
                reason: "generation and issue time must be positive and expiry must follow issue",
            });
        }
        expected.validate()?;
        Ok(())
    }
}

/// Authenticated owner readback for the original sealed provider process
/// admission. The request JSON is inert and is never itself a ProcessRequest;
/// the child validates it and constructs the non-deserializable ProcessRequest
/// locally using the separate grant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerProviderProcessReadbackV1 {
    /// Exact provider operation/executable identity.
    pub provider_process: NativeWorkerProviderProcessIdentityV1,
    /// Canonical JSON bytes for the original
    /// `ProcessExecutionAdmissionRequest`.
    pub admission_request_json: String,
    /// SHA-256 of those exact canonical admission request bytes.
    pub admission_request_sha256: String,
    /// Separate Kernel-issued one-shot grant projection.
    pub grant: NativeWorkerProviderProcessGrantV1,
}

impl NativeWorkerProviderProcessReadbackV1 {
    /// Validates canonical admission bytes, exact provider operation and
    /// executable, and the independent grant projection.
    pub fn validate_for(
        &self,
        expected: &NativeWorkerProviderProcessIdentityV1,
    ) -> Result<(), ProtocolError> {
        self.provider_process.validate()?;
        if &self.provider_process != expected {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_process_readback.identity",
                reason: "readback differs from the original provider-process identity",
            });
        }
        if self.admission_request_json.len() > MAX_NATIVE_WORKER_PROVIDER_PROCESS_ADMISSION_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_process_readback.admission_request_json",
                reason: "admission projection exceeds its byte bound",
            });
        }
        let value: serde_json::Value = serde_json::from_str(&self.admission_request_json)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if !value.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_process_readback.admission_request_json",
                reason: "admission request must be a JSON object",
            });
        }
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if canonical.as_slice() != self.admission_request_json.as_bytes()
            || sha256_hex(&canonical) != self.admission_request_sha256
        {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_process_readback.admission_request_sha256",
                reason: "digest must bind the exact canonical owner request bytes",
            });
        }
        let intent = value.get("intent").and_then(serde_json::Value::as_object);
        let operation_id = intent
            .and_then(|intent| intent.get("operation_id"))
            .and_then(serde_json::Value::as_str);
        let executable_digest = intent
            .and_then(|intent| intent.get("executable_sha256"))
            .and_then(serde_json::Value::as_str);
        let process_generation = intent
            .and_then(|intent| intent.get("generation"))
            .and_then(serde_json::Value::as_u64);
        let state_fence = value
            .get("state_fence")
            .and_then(serde_json::Value::as_object);
        let fence_epoch = state_fence.and_then(|fence| fence.get("authority_epoch"));
        let fence_generation = state_fence
            .and_then(|fence| fence.get("generation"))
            .and_then(serde_json::Value::as_u64);
        let fence_nonce = state_fence
            .and_then(|fence| fence.get("nonce"))
            .and_then(serde_json::Value::as_str);
        let expected_epoch = serde_json::to_value(&self.grant.authority_epoch)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if operation_id != Some(expected.provider_operation_id.as_str())
            || executable_digest != Some(expected.provider_executable_digest.as_str())
            || process_generation != Some(self.grant.fence_generation)
            || fence_generation != Some(self.grant.fence_generation)
            || fence_nonce != Some(self.grant.fence_nonce.as_str())
            || fence_epoch != Some(&expected_epoch)
        {
            return Err(ProtocolError::InvalidField {
                field: "native_worker_provider_process_readback.admission_request_json",
                reason: "request does not carry the exact provider operation and executable",
            });
        }
        self.grant.validate(expected)?;
        Ok(())
    }
}

/// Exact read result for the separately sealed provider process request and
/// dispatch grant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWorkerProviderProcessReadResponseV1 {
    /// Current owner row has the exact provider-process admission.
    Found {
        /// Owner readback and separate grant projection.
        readback: NativeWorkerProviderProcessReadbackV1,
    },
    /// Provider-process admission has not yet been published.
    Pending {
        /// Bounded diagnostic reason.
        reason: String,
    },
    /// Currentness or owner identity could not be established.
    Unknown {
        /// Bounded diagnostic reason.
        reason: String,
    },
}

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
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            NonZeroU64::new(3).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(test_epoch(), ResourceGeneration::new(7).expect("generation"))
    }

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

    #[test]
    fn retained_material_resolve_binds_the_exact_fence_and_epoch() {
        let epoch = test_epoch();
        let request = NativeWorkerRetainedProviderMaterialResolveRequestV1 {
            claim_id: "claim:1".to_owned(),
            dispatch_operation_id: "dispatch:1".to_owned(),
            attempt_id: "attempt:1".to_owned(),
            binding_digest: "a".repeat(64),
            worker_generation: 7,
            state_fence: test_fence(),
            authority_epoch: epoch.clone(),
        };
        request.validate().expect("exact claim fence");
        let mut foreign = request;
        foreign.authority_epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440001")
                .expect("foreign lineage"),
            NonZeroU64::new(3).expect("sequence"),
        )
        .expect("foreign epoch");
        assert!(foreign.validate().is_err(), "foreign epoch must refuse");
    }

    #[test]
    fn provider_process_readback_binds_original_operation_and_grant() {
        let epoch = test_epoch();
        let provider_process = provider_process();
        let request = serde_json::json!({
            "intent": {
                "operation_id": provider_process.provider_operation_id.clone(),
                "executable_sha256": provider_process.provider_executable_digest.clone(),
                "generation": 7,
            },
            "state_fence": {
                "authority_epoch": epoch.clone(),
                "generation": 7,
                "nonce": "provider-fence-1",
            },
        });
        let canonical = canonical_json_bytes(&request).expect("canonical request");
        let readback = NativeWorkerProviderProcessReadbackV1 {
            provider_process: provider_process.clone(),
            admission_request_json: String::from_utf8(canonical.clone()).expect("UTF-8"),
            admission_request_sha256: sha256_hex(&canonical),
            grant: NativeWorkerProviderProcessGrantV1 {
                grant_digest: "d".repeat(64),
                authority_epoch: test_epoch(),
                fence_generation: 7,
                fence_nonce: "provider-fence-1".to_owned(),
                idempotency_key: "provider-lease-1".to_owned(),
                issued_at_unix_ms: 100,
                expires_at_unix_ms: 200,
            },
        };
        readback
            .validate_for(&provider_process)
            .expect("exact provider request and grant");
        let mut foreign = readback;
        foreign.provider_process.provider_operation_id = "supervisor-op".to_owned();
        assert!(
            foreign.validate_for(&provider_process).is_err(),
            "supervisor process identity must refuse"
        );
    }
}
