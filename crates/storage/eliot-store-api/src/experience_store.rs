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
use std::fmt;

use serde::de::{Deserializer, Visitor};
use serde::ser::Error as _;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId, StateFence, StoreError, canonical_json_bytes, sha256_hex,
    validate_text,
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
/// Opaque audit-range continuation cursor (audit reads, optional).
///
/// Carried as a closed text selector so the frozen `GetAuditRange`
/// shape stays backward compatible: requests without it read from the
/// start with legacy fail-closed overflow. See [`audit_cursor_issue`].
pub const AUDIT_PARAM_CURSOR: &str = "cursor";

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
/// Read payload field: owner-minted continuation cursor, or null at end.
pub const EXPERIENCE_PAGE_NEXT_CURSOR: &str = "next_cursor";
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

/// Parsed owner-page boundary for one bounded experience range response.
///
/// The owner wire has three distinct states. A missing `next_cursor` member is
/// [`PageBoundary::MissingCursor`] and is never a successful end marker; an
/// explicit JSON `null` is [`PageBoundary::ExplicitEnd`]; and a nonblank string
/// is [`PageBoundary::Continuation`]. The custom serde implementation keeps
/// those states distinct while retaining the wire shape (`null` or text).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum PageBoundary {
    /// The owner omitted the required continuation member.
    #[default]
    MissingCursor,
    /// The owner explicitly proved that this page ends the enumeration.
    ExplicitEnd,
    /// The owner issued a cursor for the next page.
    Continuation(String),
}

/// Explicit owner-page spelling for callers that prefer the longer name.
pub type ExperiencePageBoundary = PageBoundary;

impl PageBoundary {
    /// Validates this boundary using the canonical owner field path.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_field(EXPERIENCE_PAGE_NEXT_CURSOR)
    }

    /// Validates this boundary while retaining a family-specific error path.
    pub fn validate_field(&self, field: &'static str) -> Result<(), StoreError> {
        match self {
            Self::MissingCursor => Err(StoreError::InvalidField {
                field,
                reason: "owner page envelope omitted the required continuation cursor member",
            }),
            Self::ExplicitEnd => Ok(()),
            Self::Continuation(cursor) => validate_text(cursor, field),
        }
    }
}

impl Serialize for PageBoundary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::MissingCursor => Err(S::Error::custom(
                "missing owner page continuation cursor cannot be serialized",
            )),
            Self::ExplicitEnd => serializer.serialize_none(),
            Self::Continuation(cursor) => serializer.serialize_str(cursor),
        }
    }
}

impl<'de> Deserialize<'de> for PageBoundary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PageBoundaryVisitor;

        impl<'de> Visitor<'de> for PageBoundaryVisitor {
            type Value = PageBoundary;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null or a nonblank continuation cursor string")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(PageBoundary::ExplicitEnd)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(PageBoundary::ExplicitEnd)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let cursor = String::deserialize(deserializer)?;
                if cursor.trim().is_empty() || cursor.chars().any(char::is_control) {
                    return Err(serde::de::Error::custom(
                        "owner continuation cursor must be nonblank text without control characters",
                    ));
                }
                Ok(PageBoundary::Continuation(cursor))
            }
        }

        deserializer.deserialize_option(PageBoundaryVisitor)
    }
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
    /// Typed owner proof of continuation or explicit end-of-stream.
    #[serde(default)]
    pub next_cursor: PageBoundary,
    /// Exact owner fence carried by the page envelope.
    pub state_fence: StateFence,
}

impl ExperienceRangePage {
    /// Parses and validates one owner page envelope.
    pub fn from_value(value: &Value) -> Result<Self, StoreError> {
        let page: Self =
            serde_json::from_value(value.clone()).map_err(|_| StoreError::InvalidField {
                field: "experience.page",
                reason: "owner page envelope is not the closed range-page shape",
            })?;
        page.validate()?;
        Ok(page)
    }

    /// Validates the page and its typed owner boundary.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.records.len() != self.matched_total {
            return Err(StoreError::InvalidField {
                field: EXPERIENCE_PAGE_MATCHED_TOTAL,
                reason: "must equal the number of returned records",
            });
        }
        if self.records.len() > usize::from(MAX_EXPERIENCE_PAGE_RECORDS) {
            return Err(StoreError::InvalidField {
                field: EXPERIENCE_PAGE_RECORDS,
                reason: "page exceeds the bounded experience range size",
            });
        }
        self.next_cursor.validate()?;
        match (&self.next_cursor, self.truncated) {
            (PageBoundary::ExplicitEnd, true) => Err(StoreError::InvalidField {
                field: EXPERIENCE_PAGE_TRUNCATED,
                reason: "explicit end cannot also be marked truncated",
            }),
            (PageBoundary::Continuation(_), false) => Err(StoreError::InvalidField {
                field: EXPERIENCE_PAGE_TRUNCATED,
                reason: "continuation cursor requires a truncated page",
            }),
            _ => Ok(()),
        }
    }

    /// Builds the closed page object bound into read payloads.
    pub fn payload(&self) -> Result<Value, StoreError> {
        self.validate()?;
        serde_json::to_value(self).map_err(|error| StoreError::Serialization(error.to_string()))
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

/// Mints one opaque audit-range continuation cursor.
///
/// The cursor binds the exact query fence (digest over its canonical
/// bytes), the sorted revision-head set (digest over canonical
/// `(key, revision)` pairs, key order), the next candidate ordinal, and
/// the page bound in force:
/// `audit:{fence_digest}:{heads_digest}:{ordinal:010}:{bound}`.
/// Callers echo cursors; they must never construct them — only the
/// store owner mints, and [`audit_cursor_parse`] re-verifies every
/// binding before resuming. Heads binding makes stale cursors fail
/// closed: any commit advancing any revision head invalidates
/// outstanding cursors, so paged enumeration restarts instead of
/// silently skipping or duplicating rows.
pub fn audit_cursor_issue(
    fence: &StateFence,
    heads: &[(String, u64)],
    ordinal: u64,
) -> Result<String, StoreError> {
    let fence_digest = sha256_hex(
        &canonical_json_bytes(fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    let heads_digest = audit_heads_digest(heads)?;
    Ok(format!(
        "audit:{fence_digest}:{heads_digest}:{ordinal:010}:{}",
        crate::operation_catalogue::MAX_AUDIT_RANGE_RECORDS
    ))
}

/// Digests one revision-head set for cursor binding.
///
/// Sorts by key so the digest is order-independent; identical head sets
/// always yield identical bytes on every contour.
pub fn audit_heads_digest(heads: &[(String, u64)]) -> Result<String, StoreError> {
    let mut ordered: Vec<(&str, u64)> = heads
        .iter()
        .map(|(key, revision)| (key.as_str(), *revision))
        .collect();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    Ok(sha256_hex(&canonical_json_bytes(&ordered).map_err(
        |error| StoreError::Serialization(error.to_string()),
    )?))
}

/// Verifies one continuation cursor against the current read fence and
/// heads, returning the candidate ordinal to resume from.
///
/// Only the canonical five-part owner-minted shape verifies:
/// `audit:{fence_digest}:{heads_digest}:{ordinal:010}:{bound}`.
/// Every binding is re-verified: bound, fence digest, heads digest (any
/// commit since issuance restarts enumeration instead of drifting
/// ordinals). No scaffold or compatibility shape is accepted: cursors
/// the store owner never minted fail closed here.
///
/// A bound that does not match the enforced page bound fails closed
/// (a bound change invalidates old cursors instead of silently
/// repaging); cross-fence continuation is rejected (cursors never carry
/// reads across a fence change).
pub fn audit_cursor_parse(
    cursor: &str,
    fence: &StateFence,
    heads: &[(String, u64)],
) -> Result<u64, StoreError> {
    let invalid = || StoreError::InvalidField {
        field: "experience.cursor",
        reason: "continuation cursor is malformed, foreign, or stale",
    };
    let expected_fence = sha256_hex(&canonical_json_bytes(fence).map_err(|_| invalid())?);
    let bound: u32 = crate::operation_catalogue::MAX_AUDIT_RANGE_RECORDS;
    match cursor.split(':').collect::<Vec<_>>().as_slice() {
        ["audit", fence_digest, heads_digest, ordinal, cursor_bound] => {
            if *fence_digest != expected_fence {
                return Err(invalid());
            }
            if *heads_digest != audit_heads_digest(heads).map_err(|_| invalid())? {
                return Err(invalid());
            }
            let cursor_bound: u32 = cursor_bound.parse().map_err(|_| invalid())?;
            if cursor_bound != bound {
                return Err(invalid());
            }
            ordinal.parse().map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
