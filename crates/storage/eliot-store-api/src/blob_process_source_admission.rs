//! Durable admission and later whole-object commitment for one process stream.
//!
//! This owner is deliberately separate from `WorkScope`'s governing document
//! closure. Its key binds the current WorkScope, process session, generated
//! stream source ID, and exact process binding. A Pending row authorizes the
//! acquisition attempt only; a Ready row attaches a durable whole-object
//! commitment and the original Blob Ready receipt.

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, ReadConsistency, RecoveryRecordKey, ScopeId, StoreError,
};

pub const BLOB_PROCESS_SOURCE_ADMISSION_SCHEMA: &str = "eliot.blob.process-source-admission.v1";
pub const BLOB_PROCESS_SOURCE_ADMISSION_ROW_SCHEMA: &str = "eliot.governor.owner.snapshot.v1";

/// Lifecycle of one admitted process output source.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobProcessSourceAdmissionPhase {
    /// Exact process/source/open intent is persisted before Blob Open.
    Pending,
    /// Exact whole-object content and owner-issued Ready receipt are attached.
    Ready,
}

/// Identity axes used to derive a canonical recovery-owner key.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessSourceAdmissionIdentity {
    pub work_scope_ref: String,
    pub session_id: String,
    pub source_id: String,
    pub process_binding_sha256: String,
}

impl BlobProcessSourceAdmissionIdentity {
    pub fn validate(&self) -> Result<(), StoreError> {
        for (field, value) in [
            (
                "blob_process_source.work_scope_ref",
                self.work_scope_ref.as_str(),
            ),
            ("blob_process_source.session_id", self.session_id.as_str()),
            ("blob_process_source.source_id", self.source_id.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field,
                    reason: "must be non-empty text without control characters",
                });
            }
        }
        validate_sha256(
            &self.process_binding_sha256,
            "blob_process_source.process_binding_sha256",
        )
    }

    pub fn record_key(&self) -> Result<RecoveryRecordKey, StoreError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        RecoveryRecordKey::new(
            "blob_process_source",
            format!("source_{}", sha256_hex(&bytes)),
        )
    }

    pub fn admission_ref(&self) -> Result<String, StoreError> {
        let key = self.record_key()?;
        let bytes = canonical_json_bytes(&key)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Exact terminal payload commitment and the Blob service's Ready receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessSourceReadyCommitment {
    pub ready_operation_id: String,
    pub ready_request_identity_json: String,
    pub ready_request_identity_sha256: String,
    /// Exact revision-1 Pending snapshot whose digest is the Ready CAS base.
    /// The adapter validates that this projection agrees with the Ready
    /// record, and the database CAS requires its digest to equal the current
    /// stored row digest.
    pub pending_admission_json: String,
    pub pending_admission_sha256: String,
    pub whole_source_sha256: String,
    pub whole_source_byte_length: u64,
    pub blob_ready_receipt_json: String,
    pub blob_ready_receipt_sha256: String,
}

/// Store-owned revision of the source acquisition admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessSourceAdmission {
    pub schema: String,
    pub phase: BlobProcessSourceAdmissionPhase,
    pub owner_revision: u64,
    pub state_fence: StateFence,
    pub identity: BlobProcessSourceAdmissionIdentity,
    pub pending_operation_id: String,
    pub pending_request_identity_json: String,
    pub pending_request_identity_sha256: String,
    pub process_binding_json: String,
    pub process_binding_sha256: String,
    pub open_request_json: String,
    pub open_request_sha256: String,
    pub work_scope_owner_revision: u64,
    pub work_scope_owner_digest: String,
    pub owner_facts_json: String,
    pub owner_facts_sha256: String,
    pub ready: Option<BlobProcessSourceReadyCommitment>,
}

impl BlobProcessSourceAdmission {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != BLOB_PROCESS_SOURCE_ADMISSION_SCHEMA {
            return Err(StoreError::InvalidField {
                field: "blob_process_source.schema",
                reason: "unsupported schema",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        self.identity.validate()?;
        if self.owner_revision == 0 || self.work_scope_owner_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "blob_process_source.revision",
                reason: "owner and WorkScope revisions must be non-zero",
            });
        }
        validate_text(
            &self.pending_operation_id,
            "blob_process_source.pending_operation_id",
        )?;
        validate_sha256(
            &self.pending_request_identity_sha256,
            "blob_process_source.pending_request_identity_sha256",
        )?;
        validate_canonical_object(
            &self.pending_request_identity_json,
            "blob_process_source.pending_request_identity_json",
            &self.pending_request_identity_sha256,
        )?;
        validate_sha256(
            &self.process_binding_sha256,
            "blob_process_source.process_binding_sha256",
        )?;
        if self.identity.process_binding_sha256 != self.process_binding_sha256 {
            return Err(StoreError::InvalidField {
                field: "blob_process_source.process_binding_sha256",
                reason: "must equal the source identity binding digest",
            });
        }
        validate_canonical_object(
            &self.process_binding_json,
            "blob_process_source.process_binding_json",
            &self.process_binding_sha256,
        )?;
        validate_sha256(
            &self.open_request_sha256,
            "blob_process_source.open_request_sha256",
        )?;
        validate_canonical_object(
            &self.open_request_json,
            "blob_process_source.open_request_json",
            &self.open_request_sha256,
        )?;
        validate_sha256(
            &self.work_scope_owner_digest,
            "blob_process_source.work_scope_owner_digest",
        )?;
        validate_sha256(
            &self.owner_facts_sha256,
            "blob_process_source.owner_facts_sha256",
        )?;
        validate_canonical_object(
            &self.owner_facts_json,
            "blob_process_source.owner_facts_json",
            &self.owner_facts_sha256,
        )?;

        match (&self.phase, &self.ready, self.owner_revision) {
            (BlobProcessSourceAdmissionPhase::Pending, None, 1) => Ok(()),
            (BlobProcessSourceAdmissionPhase::Ready, Some(ready), 2) => {
                validate_text(
                    &ready.ready_operation_id,
                    "blob_process_source.ready_operation_id",
                )?;
                validate_sha256(
                    &ready.ready_request_identity_sha256,
                    "blob_process_source.ready_request_identity_sha256",
                )?;
                validate_canonical_object(
                    &ready.ready_request_identity_json,
                    "blob_process_source.ready_request_identity_json",
                    &ready.ready_request_identity_sha256,
                )?;
                validate_sha256(
                    &ready.pending_admission_sha256,
                    "blob_process_source.pending_admission_sha256",
                )?;
                validate_canonical_object(
                    &ready.pending_admission_json,
                    "blob_process_source.pending_admission_json",
                    &ready.pending_admission_sha256,
                )?;
                let pending: Self = serde_json::from_str(&ready.pending_admission_json)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                if pending.phase != BlobProcessSourceAdmissionPhase::Pending
                    || pending.owner_revision != 1
                    || pending.ready.is_some()
                    || !same_pending_identity_and_facts(&pending, self)
                {
                    return Err(StoreError::InvalidField {
                        field: "blob_process_source.pending_admission_json",
                        reason: "must be the exact pending predecessor with unchanged admission facts",
                    });
                }
                validate_sha256(
                    &ready.whole_source_sha256,
                    "blob_process_source.whole_source_sha256",
                )?;
                validate_sha256(
                    &ready.blob_ready_receipt_sha256,
                    "blob_process_source.blob_ready_receipt_sha256",
                )?;
                validate_canonical_object(
                    &ready.blob_ready_receipt_json,
                    "blob_process_source.blob_ready_receipt_json",
                    &ready.blob_ready_receipt_sha256,
                )
            }
            _ => Err(StoreError::InvalidField {
                field: "blob_process_source.phase",
                reason: "Pending is revision 1 without Ready data; Ready is revision 2 with a whole-object receipt",
            }),
        }
    }

    pub fn admission_ref(&self) -> Result<String, StoreError> {
        self.identity.admission_ref()
    }
}

/// Exact owner row returned by `GetBlobProcessSourceAdmission`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessSourceAdmissionReadback {
    pub state_fence: StateFence,
    pub owner_revision: u64,
    pub value_digest: String,
    pub admission: BlobProcessSourceAdmission,
}

impl BlobProcessSourceAdmissionReadback {
    pub fn validate_for(
        &self,
        identity: &BlobProcessSourceAdmissionIdentity,
        state_fence: &StateFence,
    ) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.state_fence != *state_fence
            || self.admission.state_fence != *state_fence
            || self.admission.identity != *identity
            || self.owner_revision != self.admission.owner_revision
        {
            return Err(StoreError::FenceMismatch);
        }
        validate_sha256(&self.value_digest, "blob_process_source.owner_digest")?;
        self.admission.validate()?;
        let bytes = canonical_json_bytes(&self.admission)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if sha256_hex(&bytes) != self.value_digest {
            return Err(StoreError::InvalidField {
                field: "blob_process_source.owner_digest",
                reason: "does not match canonical admission bytes",
            });
        }
        Ok(())
    }
}

/// Builds the owner-keyed exact named read for one process source.
pub fn blob_process_source_admission_read_request(
    identity: &BlobProcessSourceAdmissionIdentity,
    state_fence: &StateFence,
) -> Result<NamedReadRequest, StoreError> {
    identity.validate()?;
    state_fence.validate().map_err(StoreError::Foundation)?;
    Ok(NamedReadRequest {
        operation: NamedReadOperation::GetBlobProcessSourceAdmission,
        scope_id: None::<ScopeId>,
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: BTreeMap::from([
            ("work_scope_ref".to_owned(), json!(identity.work_scope_ref)),
            ("session_id".to_owned(), json!(identity.session_id)),
            ("source_id".to_owned(), json!(identity.source_id)),
            (
                "process_binding_sha256".to_owned(),
                json!(identity.process_binding_sha256),
            ),
        ]),
    })
}

/// Decodes the opaque owner row and rechecks every selector and content hash.
pub fn decode_blob_process_source_admission_readback(
    response: &NamedReadResponse,
    identity: &BlobProcessSourceAdmissionIdentity,
    state_fence: &StateFence,
) -> Result<BlobProcessSourceAdmissionReadback, StoreError> {
    if response.operation != NamedReadOperation::GetBlobProcessSourceAdmission
        || response.state_fence != *state_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    let readback: BlobProcessSourceAdmissionReadback =
        serde_json::from_value(response.payload.clone())
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
    readback.validate_for(identity, state_fence)?;
    Ok(readback)
}

/// Encodes one Pending insert or Pending→Ready CAS as a closed canonical
/// named mutation. The prepared transition supplies the original operation
/// identity and fence; this helper does not mint either.
pub fn blob_process_source_admission_mutation(
    admission: &BlobProcessSourceAdmission,
    expected_revision: u64,
    expected_digest: &str,
    expected_admission_ref: &str,
) -> Result<NamedMutationRequest, StoreError> {
    admission.validate()?;
    if expected_revision.checked_add(1) != Some(admission.owner_revision) {
        return Err(StoreError::InvalidField {
            field: "blob_process_source.expected_revision",
            reason: "new owner revision must be exactly the expected revision plus one",
        });
    }
    let admission_ref = admission.admission_ref()?;
    if admission_ref != expected_admission_ref {
        return Err(StoreError::InvalidField {
            field: "blob_process_source.admission_ref",
            reason: "must be the canonical owner-derived identity reference",
        });
    }
    match (expected_revision, expected_digest, admission.phase) {
        (0, "absent", BlobProcessSourceAdmissionPhase::Pending) => {}
        (1, digest, BlobProcessSourceAdmissionPhase::Ready) => {
            validate_sha256(digest, "blob_process_source.expected_digest")?;
            if admission
                .ready
                .as_ref()
                .is_none_or(|ready| ready.pending_admission_sha256 != digest)
            {
                return Err(StoreError::InvalidField {
                    field: "blob_process_source.expected_digest",
                    reason: "must equal the exact retained Pending predecessor digest",
                });
            }
        }
        _ => {
            return Err(StoreError::InvalidField {
                field: "blob_process_source.phase",
                reason: "only absent→Pending and revision-1 Pending→Ready are supported",
            });
        }
    }
    let snapshot = canonical_json_bytes(admission)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let snapshot_json = String::from_utf8(snapshot)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let parameters = BTreeMap::from([
        ("admission_ref".to_owned(), json!(admission_ref)),
        (
            "expected_revision".to_owned(),
            json!(expected_revision.to_string()),
        ),
        ("expected_digest".to_owned(), json!(expected_digest)),
        ("snapshot_json".to_owned(), json!(snapshot_json)),
    ]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::RecordBlobProcessSourceAdmission,
        parameters,
    })
}

fn same_pending_identity_and_facts(
    pending: &BlobProcessSourceAdmission,
    ready: &BlobProcessSourceAdmission,
) -> bool {
    pending.schema == ready.schema
        && pending.state_fence == ready.state_fence
        && pending.identity == ready.identity
        && pending.pending_operation_id == ready.pending_operation_id
        && pending.pending_request_identity_json == ready.pending_request_identity_json
        && pending.pending_request_identity_sha256 == ready.pending_request_identity_sha256
        && pending.process_binding_json == ready.process_binding_json
        && pending.process_binding_sha256 == ready.process_binding_sha256
        && pending.open_request_json == ready.open_request_json
        && pending.open_request_sha256 == ready.open_request_sha256
        && pending.work_scope_owner_revision == ready.work_scope_owner_revision
        && pending.work_scope_owner_digest == ready.work_scope_owner_digest
        && pending.owner_facts_json == ready.owner_facts_json
        && pending.owner_facts_sha256 == ready.owner_facts_sha256
}

fn validate_canonical_object(
    json_text: &str,
    field: &'static str,
    digest: &str,
) -> Result<(), StoreError> {
    if json_text.is_empty() || json_text.len() > crate::MAX_RECOVERY_RECORD_BYTES {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be a bounded canonical JSON object",
        });
    }
    let value: Value = serde_json::from_str(json_text)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if !value.is_object() || bytes != json_text.as_bytes() || sha256_hex(&bytes) != digest {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be an object whose canonical bytes match its SHA-256",
        });
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be non-empty text without control characters",
        });
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}
