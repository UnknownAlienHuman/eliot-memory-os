//! Canonical experience-bank/feedback wire contract (issue #223, I5).
//!
//! This module owns the serialization-only wire boundary for durable
//! experience records: versioned identity, closed parameter declarations
//! support, per-leg completeness validation on raw parameter maps, and
//! request builders. It contains no bank/feedback semantics, no revision
//! authority, and no receipt validation: the Governor observation owner
//! (`eliot-observation::bank_admission`) owns admission, sequencing, and
//! digest computation; the canonical backend drives persistence within
//! its fenced transaction and outbox owner. Wire shapes stay
//! serialization-only and never become a second semantic model.
//!
//! Wire identity: [`EXPERIENCE_STORE_SCHEMA_V1`]
//! (`eliot.experience.state.v1`). Mutation operations:
//! `CommitExperienceBank`, `CommitAgentFeedback`. Read operations:
//! `GetExperienceBankRange`, `GetAgentFeedbackRange`. Transition class:
//! `CaptureCandidate` with a `Candidate` ceiling (no support, influence,
//! lifecycle, or assertability change).
//!
//! Record documents travel as opaque JSON strings: the store preserves
//! them verbatim and validates shape/bounds/closed family membership
//! structurally. The presented `record_digest` is shape-checked here; the
//! digest is re-proved at the Governor read edge, where each read-back
//! record re-validates (recomputing its owner digest from fields) before
//! any ref resolves. Lineage (monotonic revisions, predecessor links) is
//! Governor-owned; the store enforces only key existence, verbatim
//! convergence, and row immutability. Read queries project bounded
//! same-fence, same-scope record sets with explicit truncation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId, StateFence, StoreError,
};

/// Versioned wire/schema identity for canonical experience state.
pub const EXPERIENCE_STORE_SCHEMA_V1: &str = "eliot.experience.state.v1";
/// Closed mutation operation name for bank-record writes.
///
/// Must stay byte-identical to the Governor commit producer's
/// `BANK_COMMIT_OPERATION`; the name maps in `operation_parameters` bind
/// this same spelling.
pub const EXPERIENCE_BANK_MUTATION_NAME: &str = "CommitExperienceBank";
/// Closed mutation operation name for feedback-record writes.
pub const EXPERIENCE_FEEDBACK_MUTATION_NAME: &str = "CommitAgentFeedback";
/// Closed read operation name for bank-record range reads.
pub const EXPERIENCE_BANK_READ_NAME: &str = "GetExperienceBankRange";
/// Closed read operation name for feedback-record range reads.
pub const EXPERIENCE_FEEDBACK_READ_NAME: &str = "GetAgentFeedbackRange";
/// Verbatim canonical record document (mutation legs).
pub const EXPERIENCE_PARAM_RECORD_JSON: &str = "record_json";
/// Presented digest of the admitted record bytes (mutation legs).
pub const EXPERIENCE_PARAM_RECORD_DIGEST: &str = "record_digest";
/// Owner revision as its decimal string (mutation legs).
pub const EXPERIENCE_PARAM_RECORD_REVISION: &str = "record_revision";
/// Digest over the canonical admission-scope bytes (mutation legs).
pub const EXPERIENCE_PARAM_SCOPE_DIGEST: &str = "scope_digest";
/// Digest over the canonical admission-fence bytes (mutation legs).
pub const EXPERIENCE_PARAM_FENCE_DIGEST: &str = "fence_digest";
/// Deterministic commit idempotency key (mutation legs).
pub const EXPERIENCE_PARAM_IDEMPOTENCY_KEY: &str = "idempotency_key";
/// Decimal page-size bound (range reads, required).
pub const EXPERIENCE_PARAM_MAX_RECORDS: &str = "max_records";

/// Maximum accepted record-handle length in bytes.
pub const MAX_EXPERIENCE_HANDLE_BYTES: usize = 256;
/// Maximum accepted idempotency-key length in bytes.
pub const MAX_EXPERIENCE_IDEMPOTENCY_BYTES: usize = 256;
/// Maximum accepted record-document length in bytes.
///
/// Admitted records are bounded summaries plus refs (well under this
/// ceiling); larger payloads belong in Blob Store behind handles, never
/// inline in a named operation.
pub const MAX_EXPERIENCE_RECORD_JSON_BYTES: usize = 262_144;
/// Maximum records one experience range read may return.
pub const MAX_EXPERIENCE_PAGE_RECORDS: u16 = 64;

/// Read payload field: record-row array.
pub const EXPERIENCE_PAGE_RECORDS: &str = "records";
/// Read payload field: records actually returned.
pub const EXPERIENCE_PAGE_MATCHED_TOTAL: &str = "matched_total";
/// Read payload field: whether further rows exist past the bound.
pub const EXPERIENCE_PAGE_TRUNCATED: &str = "truncated";
/// Read payload field: projection fence.
pub const EXPERIENCE_PAGE_STATE_FENCE: &str = "state_fence";

/// Fail-closed experience wire errors before [`StoreError`] projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExperienceContractError {
    /// A field failed bounded validation.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// A required parameter is absent.
    #[error("missing experience parameter: {0}")]
    MissingParameter(&'static str),
}

impl ExperienceContractError {
    /// Projects the contract error onto the closed store error set.
    #[must_use]
    pub const fn into_store_error(self) -> StoreError {
        match self {
            Self::InvalidField { field, reason } => StoreError::InvalidField { field, reason },
            Self::MissingParameter(name) => StoreError::InvalidField {
                field: name,
                reason: "missing required experience parameter",
            },
        }
    }
}

/// Raw validated mutation decoded from a mutation parameter map.
///
/// Documents stay opaque strings: the backend persists them verbatim and
/// arbitrates keys. This enum carries no lineage semantics beyond closed
/// family membership.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedExperienceMutation {
    /// Persist one immutable bank-record row.
    Bank {
        /// Exact canonical handle of the record.
        handle: String,
        /// Owner revision of the record.
        revision: u64,
        /// Verbatim canonical record document.
        record_json: String,
        /// Presented digest of the admitted record bytes.
        record_digest: String,
        /// Digest over the canonical admission-scope bytes.
        scope_digest: String,
        /// Digest over the canonical admission-fence bytes.
        fence_digest: String,
        /// Deterministic commit idempotency key.
        idempotency_key: String,
    },
    /// Persist one immutable feedback-record row. Same field rule as bank.
    Feedback {
        /// Exact canonical handle of the record.
        handle: String,
        /// Owner revision of the record.
        revision: u64,
        /// Verbatim canonical record document.
        record_json: String,
        /// Presented digest of the admitted record bytes.
        record_digest: String,
        /// Digest over the canonical admission-scope bytes.
        scope_digest: String,
        /// Digest over the canonical admission-fence bytes.
        fence_digest: String,
        /// Deterministic commit idempotency key.
        idempotency_key: String,
    },
}

/// Decoded range read with its closed page bound.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedExperienceRead {
    /// Page-size bound (range reads only).
    pub max_records: u16,
}

/// Builds a bank commit-leg parameter map from Governor-produced parts.
pub fn experience_bank_commit_params(
    record_json: String,
    record_digest: String,
    record_revision: u64,
    scope_digest: String,
    fence_digest: String,
    idempotency_key: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            EXPERIENCE_PARAM_RECORD_JSON.to_owned(),
            Value::String(record_json),
        ),
        (
            EXPERIENCE_PARAM_RECORD_DIGEST.to_owned(),
            Value::String(record_digest),
        ),
        (
            EXPERIENCE_PARAM_RECORD_REVISION.to_owned(),
            Value::String(record_revision.to_string()),
        ),
        (
            EXPERIENCE_PARAM_SCOPE_DIGEST.to_owned(),
            Value::String(scope_digest),
        ),
        (
            EXPERIENCE_PARAM_FENCE_DIGEST.to_owned(),
            Value::String(fence_digest),
        ),
        (
            EXPERIENCE_PARAM_IDEMPOTENCY_KEY.to_owned(),
            Value::String(idempotency_key),
        ),
    ])
}

/// Builds a feedback commit-leg parameter map. Same field rule as bank.
pub fn experience_feedback_commit_params(
    record_json: String,
    record_digest: String,
    record_revision: u64,
    scope_digest: String,
    fence_digest: String,
    idempotency_key: String,
) -> BTreeMap<String, Value> {
    experience_bank_commit_params(
        record_json,
        record_digest,
        record_revision,
        scope_digest,
        fence_digest,
        idempotency_key,
    )
}

/// Builds the closed `CommitExperienceBank` mutation request.
#[must_use]
pub fn experience_bank_mutation_request(params: BTreeMap<String, Value>) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::CommitExperienceBank,
        parameters: params,
    }
}

/// Builds the closed `CommitAgentFeedback` mutation request.
#[must_use]
pub fn experience_feedback_mutation_request(
    params: BTreeMap<String, Value>,
) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::CommitAgentFeedback,
        parameters: params,
    }
}

/// Builds a closed experience range-read request over one scope.
pub fn experience_bank_read_request(
    scope_id: ScopeId,
    max_records: u16,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        EXPERIENCE_PARAM_MAX_RECORDS.to_owned(),
        Value::String(max_records.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetExperienceBankRange,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Builds a closed feedback range-read request over one scope.
pub fn experience_feedback_read_request(
    scope_id: ScopeId,
    max_records: u16,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        EXPERIENCE_PARAM_MAX_RECORDS.to_owned(),
        Value::String(max_records.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetAgentFeedbackRange,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Validates closed mutation parameters for one experience operation.
///
/// Value rules (bounded text, JSON-object documents, hex digests, decimal
/// revision, cross-field agreement between the `record_revision`
/// parameter and the revision field inside `record_json`) run here so
/// every backend shares one acceptance boundary. Digest recomputation
/// stays Governor-owned: the presented digest is shape-checked here and
/// re-proved at the read edge when each read-back record re-validates.
pub fn validate_experience_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    if operation != NamedMutationOperation::CommitExperienceBank
        && operation != NamedMutationOperation::CommitAgentFeedback
    {
        return Err(StoreError::UnknownOperation);
    }
    let record_json = text_param(parameters, EXPERIENCE_PARAM_RECORD_JSON)?;
    if record_json.len() > MAX_EXPERIENCE_RECORD_JSON_BYTES {
        return Err(StoreError::InvalidField {
            field: "experience.record_json",
            reason: "record document exceeds the bounded length",
        });
    }
    let document: serde_json::Map<String, Value> =
        serde_json::from_str(record_json).map_err(|_| StoreError::InvalidField {
            field: "experience.record_json",
            reason: "record document must be a JSON object",
        })?;
    let revision_field = if operation == NamedMutationOperation::CommitExperienceBank {
        "bank_revision"
    } else {
        "feedback_revision"
    };
    let document_revision =
        document
            .get(revision_field)
            .and_then(Value::as_u64)
            .ok_or(StoreError::InvalidField {
                field: "experience.record_json",
                reason: "record document must carry its family revision as a number",
            })?;
    let revision_param = text_param(parameters, EXPERIENCE_PARAM_RECORD_REVISION)?;
    let revision: u64 = revision_param
        .parse()
        .map_err(|_| StoreError::InvalidField {
            field: "experience.record_revision",
            reason: "record revision must be a decimal count",
        })?;
    if revision != document_revision {
        return Err(StoreError::InvalidField {
            field: "experience.record_revision",
            reason: "record revision must match the document revision",
        });
    }
    let handle =
        document
            .get("handle")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "experience.record_json",
                reason: "record document must carry its handle",
            })?;
    validate_experience_handle(handle)?;
    crate::validate_sha256_hex(
        text_param(parameters, EXPERIENCE_PARAM_RECORD_DIGEST)?,
        "experience.record_digest",
    )?;
    crate::validate_sha256_hex(
        text_param(parameters, EXPERIENCE_PARAM_SCOPE_DIGEST)?,
        "experience.scope_digest",
    )?;
    crate::validate_sha256_hex(
        text_param(parameters, EXPERIENCE_PARAM_FENCE_DIGEST)?,
        "experience.fence_digest",
    )?;
    let idempotency_key = text_param(parameters, EXPERIENCE_PARAM_IDEMPOTENCY_KEY)?;
    if idempotency_key.len() > MAX_EXPERIENCE_IDEMPOTENCY_BYTES {
        return Err(StoreError::InvalidField {
            field: "experience.idempotency_key",
            reason: "idempotency key exceeds the bounded length",
        });
    }
    Ok(())
}

/// Decodes one validated mutation parameter map into its raw leg.
pub fn decode_experience_mutation(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedExperienceMutation, StoreError> {
    validate_experience_mutation_params(operation, parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "experience parameter must be present",
            })
    };
    let document: serde_json::Map<String, Value> = serde_json::from_str(
        parameters
            .get(EXPERIENCE_PARAM_RECORD_JSON)
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .map_err(|_| StoreError::InvalidField {
        field: "experience.record_json",
        reason: "record document must be a JSON object",
    })?;
    let handle = document
        .get("handle")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let revision = text_of(EXPERIENCE_PARAM_RECORD_REVISION)?
        .parse()
        .map_err(|_| StoreError::InvalidField {
            field: "experience.record_revision",
            reason: "record revision must be a decimal count",
        })?;
    let leg = DecodedExperienceMutationFields {
        handle,
        revision,
        record_json: text_of(EXPERIENCE_PARAM_RECORD_JSON)?,
        record_digest: text_of(EXPERIENCE_PARAM_RECORD_DIGEST)?,
        scope_digest: text_of(EXPERIENCE_PARAM_SCOPE_DIGEST)?,
        fence_digest: text_of(EXPERIENCE_PARAM_FENCE_DIGEST)?,
        idempotency_key: text_of(EXPERIENCE_PARAM_IDEMPOTENCY_KEY)?,
    };
    match operation {
        NamedMutationOperation::CommitExperienceBank => Ok(DecodedExperienceMutation::Bank {
            handle: leg.handle,
            revision: leg.revision,
            record_json: leg.record_json,
            record_digest: leg.record_digest,
            scope_digest: leg.scope_digest,
            fence_digest: leg.fence_digest,
            idempotency_key: leg.idempotency_key,
        }),
        NamedMutationOperation::CommitAgentFeedback => Ok(DecodedExperienceMutation::Feedback {
            handle: leg.handle,
            revision: leg.revision,
            record_json: leg.record_json,
            record_digest: leg.record_digest,
            scope_digest: leg.scope_digest,
            fence_digest: leg.fence_digest,
            idempotency_key: leg.idempotency_key,
        }),
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Validates the closed range-read page bound and decodes the query.
pub fn validate_experience_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedExperienceRead, StoreError> {
    let max_records = parameters
        .get(EXPERIENCE_PARAM_MAX_RECORDS)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "experience.max_records",
            reason: "page bound is required",
        })?;
    let max_records: u16 = max_records.parse().map_err(|_| StoreError::InvalidField {
        field: "experience.max_records",
        reason: "page bound must be a decimal count",
    })?;
    if max_records == 0 || max_records > MAX_EXPERIENCE_PAGE_RECORDS {
        return Err(StoreError::InvalidField {
            field: "experience.max_records",
            reason: "page bound is out of range",
        });
    }
    Ok(DecodedExperienceRead { max_records })
}

struct DecodedExperienceMutationFields {
    handle: String,
    revision: u64,
    record_json: String,
    record_digest: String,
    scope_digest: String,
    fence_digest: String,
    idempotency_key: String,
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
            reason: "experience parameter must be non-blank text",
        })
}

fn validate_experience_handle(handle: &str) -> Result<(), StoreError> {
    if handle.trim().is_empty() || handle.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "experience.handle",
            reason: "record handle must be non-blank text",
        });
    }
    if handle.len() > MAX_EXPERIENCE_HANDLE_BYTES {
        return Err(StoreError::InvalidField {
            field: "experience.handle",
            reason: "record handle exceeds the bounded length",
        });
    }
    Ok(())
}

/// Versioned JSON envelope helpers shared by backend read payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceRangePage {
    /// Verbatim record documents in key order.
    pub records: Vec<serde_json::Value>,
    /// Records actually returned.
    pub matched_total: usize,
    /// Whether further rows exist past the bound.
    pub truncated: bool,
}

impl ExperienceRangePage {
    /// Builds the closed page object bound into read payloads.
    pub fn payload(&self, state_fence: &StateFence) -> serde_json::Value {
        serde_json::json!({
            EXPERIENCE_PAGE_RECORDS: self.records,
            EXPERIENCE_PAGE_MATCHED_TOTAL: self.matched_total,
            EXPERIENCE_PAGE_TRUNCATED: self.truncated,
            EXPERIENCE_PAGE_STATE_FENCE: state_fence,
        })
    }
}

/// Extracts one audit-range envelope candidate from a capture subject.
///
/// Syntactic filter only, shared by every backend so contours agree:
/// the subject must parse as JSON, must be an object, and must carry a
/// string `record_id`. Anything else yields `None` and the caller skips
/// it — ordinary non-envelope captures are normal store content, never
/// corruption. This performs NO semantic validation and confers NO
/// admission: full envelope validation happens at the consumer edge
/// (`ObservationRecordEnvelope::validate`), and only records the live
/// Governor journal actually admitted may be carried downstream. A
/// subject that parses but is not an envelope can therefore never become
/// a false journal record.
pub fn audit_envelope_candidate(subject: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(subject).ok()?;
    let object = value.as_object()?;
    object.get("record_id")?.as_str()?;
    Some(value)
}
