//! Canonical capability-evidence wire contract (issue #1773, I3.4).
//!
//! This module owns the serialization-only wire boundary for durable,
//! Governor-owned capability evidence records: the closed mutation/read
//! operation names, the per-record parameter and value rules every backend
//! shares, the deterministic row key, and the request builders. It contains no
//! capability semantics, no admission rule, and no revision authority: the
//! Governor registry in `eliot-governor` is the only admission owner, and the
//! store arbitrates only the fenced revision of the evidence row.
//!
//! Why a dedicated leg exists (I3.4, `CapabilityEvidenceRecord`): the existing
//! `GetCapabilityEvidenceState` read answers committed `ApplyLifecyclePolicy`
//! governance rows, so a lifecycle row carries no capability status, no
//! evidence source, no route-scope fingerprint, and no revision. Nothing can
//! rebuild a capability registry or its invalidation set from it. Reusing
//! `ApplyLifecyclePolicy` to smuggle evidence is closed by design — its
//! parameter contract is exactly six fields and any extra parameter fails
//! closed — and reusing the learning leg would make the learning table a second
//! home for Governor capability state. This leg is therefore the single
//! named store surface for durable capability evidence.
//!
//! Wire identity: [`CAPABILITY_EVIDENCE_STORE_SCHEMA_V1`]
//! (`eliot.capability.evidence.v1`). Mutation operation:
//! `RecordCapabilityEvidenceRecord`. Read operation:
//! `GetCapabilityEvidenceRecordRange`.
//!
//! Revision rule: the mutation carries `expected_canonical_revision`, the CAS
//! predecessor the owner asserts, and the store issues `predecessor + 1` as
//! the row's `revision`. That issued revision is the **owner-issued
//! immutable revision** the Governor registry orders same-key evidence by, and
//! the read projects it back verbatim, so a delayed writer holding a stale
//! predecessor is refused by the store before it can reach the registry.
//!
//! Record documents travel as opaque strings, exactly as the learning leg
//! travels them: the store preserves them verbatim, validates shape/bounds
//! structurally, and never derives status, source, scope fingerprint,
//! limitations, or requalification semantics from the bytes. Those bindings are
//! re-proved by the Governor at the read edge, from the same owner-issued
//! evidence reference the store echoed.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, RecoveryRecordKey, ScopeId, StateFence, StoreError, canonical_json_bytes,
    sha256_hex,
};

/// Versioned wire/schema identity for durable capability evidence.
pub const CAPABILITY_EVIDENCE_STORE_SCHEMA_V1: &str = "eliot.capability.evidence.v1";
/// Closed mutation operation name for capability-evidence commits.
pub const CAPABILITY_EVIDENCE_RECORD_MUTATION_NAME: &str = "RecordCapabilityEvidenceRecord";
/// Closed read operation name for the paged capability-evidence range read.
pub const CAPABILITY_EVIDENCE_RECORD_READ_NAME: &str = "GetCapabilityEvidenceRecordRange";
/// Private record-key namespace for capability-evidence rows.
pub const CAPABILITY_EVIDENCE_RECORD_NAMESPACE: &str = "capability-evidence-v1";

/// Exact skill identity of the evidence key (mutation + optional read filter).
pub const CAPABILITY_EVIDENCE_PARAM_SKILL_ID: &str = "skill_id";
/// Owner-issued digest of the exact route-scope fingerprint (mutation).
pub const CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY: &str = "scope_key";
/// Verbatim canonical evidence-record document (mutation).
pub const CAPABILITY_EVIDENCE_PARAM_RECORD_JSON: &str = "record_json";
/// Presented digest of the committed record bytes (mutation + read projection).
pub const CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST: &str = "record_digest";
/// Decimal CAS predecessor the owner asserts for the evidence key (mutation).
pub const CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION: &str = "expected_canonical_revision";
/// Deterministic commit idempotency key (mutation).
pub const CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY: &str = "idempotency_key";
/// Decimal page-size bound (range read, required).
pub const CAPABILITY_EVIDENCE_PARAM_MAX_RECORDS: &str = "max_records";
/// Opaque fence-bound keyset continuation cursor (range read, optional).
pub const CAPABILITY_EVIDENCE_PARAM_CURSOR: &str = "cursor";

/// Maximum accepted skill-identity length in bytes.
pub const MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES: usize = 256;
/// Maximum accepted idempotency-key length in bytes.
pub const MAX_CAPABILITY_EVIDENCE_IDEMPOTENCY_BYTES: usize = 256;
/// Maximum accepted evidence-record document length in bytes.
///
/// One evidence record is a bounded fact plus references, well under this
/// ceiling; a larger payload belongs in Blob Store behind a handle, never
/// inline in a named operation.
pub const MAX_CAPABILITY_EVIDENCE_RECORD_JSON_BYTES: usize = 65_536;
/// Maximum records one capability-evidence range read may return.
pub const MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS: u16 = 64;

/// Returns the deterministic row key for one `(skill_id, scope_key)` evidence
/// key.
///
/// The key is a digest over the canonical bytes of exactly those two identity
/// parts, so the row address is collision-free by construction and the store
/// never has to parse a composite key. The scope fingerprint itself stays
/// inside the opaque document: the store arbitrates the row, never the route.
#[must_use]
pub fn capability_evidence_row_key(skill_id: &str, scope_key: &str) -> RecoveryRecordKey {
    let identity = canonical_json_bytes(&(skill_id, scope_key))
        .unwrap_or_else(|_| panic!("(skill_id, scope_key) is always canonically encodable"));
    RecoveryRecordKey::new(
        CAPABILITY_EVIDENCE_RECORD_NAMESPACE,
        format!("evidence_{}", sha256_hex(&identity)),
    )
    .unwrap_or_else(|_| panic!("derived capability-evidence key is always well formed"))
}

/// Raw validated mutation decoded from a capability-evidence parameter map.
///
/// Documents stay opaque strings: the backend persists them verbatim and
/// arbitrates the fenced `revision` of the `(skill_id, scope_key)` row. This
/// struct carries no capability semantics beyond shape and bounds.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedCapabilityEvidenceMutation {
    /// Exact skill identity of the evidence key.
    pub skill_id: String,
    /// Owner-issued digest of the exact route-scope fingerprint.
    pub scope_key: String,
    /// Verbatim canonical evidence-record document.
    pub record_json: String,
    /// Presented digest of the committed record bytes; the immutable record
    /// revision identity the store echoes on readback.
    pub record_digest: String,
    /// CAS predecessor the owner asserts for this evidence key.
    pub expected_canonical_revision: u64,
    /// Deterministic commit idempotency key.
    pub idempotency_key: String,
}

/// Decoded paged range read with its closed selectors and page bound.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedCapabilityEvidenceRead {
    /// Optional exact skill filter; `None` selects every skill in scope.
    pub skill_id: Option<String>,
    /// Page-size bound.
    pub max_records: u16,
}

/// Builds a capability-evidence commit parameter map from Governor-produced
/// parts.
pub fn capability_evidence_commit_params(
    skill_id: String,
    scope_key: String,
    record_json: String,
    record_digest: String,
    expected_canonical_revision: u64,
    idempotency_key: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            CAPABILITY_EVIDENCE_PARAM_SKILL_ID.to_owned(),
            Value::String(skill_id),
        ),
        (
            CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY.to_owned(),
            Value::String(scope_key),
        ),
        (
            CAPABILITY_EVIDENCE_PARAM_RECORD_JSON.to_owned(),
            Value::String(record_json),
        ),
        (
            CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST.to_owned(),
            Value::String(record_digest),
        ),
        (
            CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION.to_owned(),
            Value::String(expected_canonical_revision.to_string()),
        ),
        (
            CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY.to_owned(),
            Value::String(idempotency_key),
        ),
    ])
}

/// Builds the closed `RecordCapabilityEvidenceRecord` mutation request.
#[must_use]
pub fn capability_evidence_mutation_request(
    params: BTreeMap<String, Value>,
) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::RecordCapabilityEvidenceRecord,
        parameters: params,
    }
}

/// Builds a closed paged capability-evidence range-read request over one scope.
///
/// `cursor` is the opaque continuation token issued by the previous page; an
/// absent cursor reads from the start of the eligible set. A caller that
/// receives `truncated` MUST present the issued cursor: the store fails closed
/// on a cursor that does not decode against the current fence and revision
/// heads, so a partial page can never be mistaken for complete coverage.
#[must_use]
pub fn capability_evidence_read_request(
    scope_id: ScopeId,
    skill_id: Option<String>,
    max_records: u16,
    cursor: Option<String>,
    state_fence: StateFence,
) -> NamedReadRequest {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        CAPABILITY_EVIDENCE_PARAM_MAX_RECORDS.to_owned(),
        Value::String(max_records.to_string()),
    );
    if let Some(skill_id) = skill_id {
        parameters.insert(
            CAPABILITY_EVIDENCE_PARAM_SKILL_ID.to_owned(),
            Value::String(skill_id),
        );
    }
    if let Some(cursor) = cursor {
        parameters.insert(
            CAPABILITY_EVIDENCE_PARAM_CURSOR.to_owned(),
            Value::String(cursor),
        );
    }
    NamedReadRequest {
        operation: NamedReadOperation::GetCapabilityEvidenceRecordRange,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    }
}

/// Validates closed mutation parameters for the capability-evidence operation.
///
/// Value rules (bounded non-blank text, hex digests, decimal CAS predecessor)
/// run here so every backend shares one acceptance boundary. Digest
/// recomputation stays Governor-owned: the presented digest is shape-checked
/// here, and the store issues the row revision that is the ordering authority.
pub fn validate_capability_evidence_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    if operation != NamedMutationOperation::RecordCapabilityEvidenceRecord {
        return Err(StoreError::UnknownOperation);
    }
    let skill_id = text_param(parameters, CAPABILITY_EVIDENCE_PARAM_SKILL_ID)?;
    if skill_id.len() > MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES {
        return Err(StoreError::InvalidField {
            field: "capability_evidence.skill_id",
            reason: "skill identity exceeds the bounded length",
        });
    }
    crate::validate_sha256_hex(
        text_param(parameters, CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY)?,
        "capability_evidence.scope_key",
    )?;
    let record_json = text_param(parameters, CAPABILITY_EVIDENCE_PARAM_RECORD_JSON)?;
    if record_json.len() > MAX_CAPABILITY_EVIDENCE_RECORD_JSON_BYTES {
        return Err(StoreError::InvalidField {
            field: "capability_evidence.record_json",
            reason: "evidence record document exceeds the bounded length",
        });
    }
    crate::validate_sha256_hex(
        text_param(parameters, CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST)?,
        "capability_evidence.record_digest",
    )?;
    let expected = text_param(parameters, CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION)?;
    expected
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidField {
            field: "capability_evidence.expected_canonical_revision",
            reason: "expected canonical revision must be a decimal revision",
        })?;
    let idempotency_key = text_param(parameters, CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY)?;
    if idempotency_key.len() > MAX_CAPABILITY_EVIDENCE_IDEMPOTENCY_BYTES {
        return Err(StoreError::InvalidField {
            field: "capability_evidence.idempotency_key",
            reason: "idempotency key exceeds the bounded length",
        });
    }
    Ok(())
}

/// Decodes one validated capability-evidence mutation parameter map.
pub fn decode_capability_evidence_mutation(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedCapabilityEvidenceMutation, StoreError> {
    validate_capability_evidence_mutation_params(operation, parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "capability evidence parameter must be present",
            })
    };
    Ok(DecodedCapabilityEvidenceMutation {
        skill_id: text_of(CAPABILITY_EVIDENCE_PARAM_SKILL_ID)?,
        scope_key: text_of(CAPABILITY_EVIDENCE_PARAM_SCOPE_KEY)?,
        record_json: text_of(CAPABILITY_EVIDENCE_PARAM_RECORD_JSON)?,
        record_digest: text_of(CAPABILITY_EVIDENCE_PARAM_RECORD_DIGEST)?,
        expected_canonical_revision: text_of(CAPABILITY_EVIDENCE_PARAM_EXPECTED_REVISION)?
            .parse::<u64>()
            .map_err(|_| StoreError::InvalidField {
                field: "capability_evidence.expected_canonical_revision",
                reason: "expected canonical revision must be a decimal revision",
            })?,
        idempotency_key: text_of(CAPABILITY_EVIDENCE_PARAM_IDEMPOTENCY_KEY)?,
    })
}

/// Validates the closed range-read page bound, skill filter, and cursor, and
/// decodes the query.
pub fn validate_capability_evidence_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedCapabilityEvidenceRead, StoreError> {
    let max_records = parameters
        .get(CAPABILITY_EVIDENCE_PARAM_MAX_RECORDS)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "capability_evidence.max_records",
            reason: "page bound is required",
        })?;
    let max_records: u16 = max_records.parse().map_err(|_| StoreError::InvalidField {
        field: "capability_evidence.max_records",
        reason: "page bound must be a decimal count",
    })?;
    if max_records == 0 || max_records > MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS {
        return Err(StoreError::InvalidField {
            field: "capability_evidence.max_records",
            reason: "page bound is out of range",
        });
    }
    let skill_id = match parameters.get(CAPABILITY_EVIDENCE_PARAM_SKILL_ID) {
        None | Some(Value::Null) => None,
        Some(Value::String(skill)) if valid_skill_id(skill) => Some(skill.clone()),
        Some(_) => {
            return Err(StoreError::InvalidField {
                field: "capability_evidence.skill_id",
                reason: "skill identity must be bounded non-blank text",
            });
        }
    };
    if let Some(cursor) = parameters.get(CAPABILITY_EVIDENCE_PARAM_CURSOR) {
        let cursor = cursor.as_str().ok_or(StoreError::InvalidField {
            field: "capability_evidence.cursor",
            reason: "continuation cursor must be text",
        })?;
        if cursor.is_empty() || cursor.len() > MAX_CAPABILITY_EVIDENCE_IDEMPOTENCY_BYTES {
            return Err(StoreError::InvalidField {
                field: "capability_evidence.cursor",
                reason: "continuation cursor is out of bounds",
            });
        }
    }
    Ok(DecodedCapabilityEvidenceRead {
        skill_id,
        max_records,
    })
}

/// Decodes one validated capability-evidence range-read parameter map.
pub fn decode_capability_evidence_read(
    operation: NamedReadOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedCapabilityEvidenceRead, StoreError> {
    if operation != NamedReadOperation::GetCapabilityEvidenceRecordRange {
        return Err(StoreError::UnknownOperation);
    }
    validate_capability_evidence_read_params(parameters)
}

/// Rejects any direct capability-evidence write that bypasses the named Kernel
/// mutation boundary (issue #1773).
///
/// Only the closed `RecordCapabilityEvidenceRecord` operation is admitted;
/// every other operation fails closed with [`StoreError::UnknownOperation`].
pub fn reject_direct_capability_evidence_write(
    request: &NamedMutationRequest,
) -> Result<(), StoreError> {
    if request.operation == NamedMutationOperation::RecordCapabilityEvidenceRecord {
        Ok(())
    } else {
        Err(StoreError::UnknownOperation)
    }
}

/// Returns true when `skill` is one bounded, non-blank, control-free identity.
#[must_use]
pub fn valid_skill_id(skill: &str) -> bool {
    !skill.trim().is_empty()
        && !skill.chars().any(char::is_control)
        && skill.len() <= MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES
}

fn text_param<'a>(
    parameters: &'a BTreeMap<String, Value>,
    name: &'static str,
) -> Result<&'a str, StoreError> {
    parameters
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        .ok_or(StoreError::InvalidField {
            field: name,
            reason: "capability evidence parameter must be non-blank text",
        })
}
