//! Canonical learning-record wire contract (issue #1868, I12.24).
//!
//! This module owns the serialization-only wire boundary for durable
//! learning records: the closed record-kind discriminator, per-record
//! completeness validation on raw parameter maps, and request builders.
//! It contains no learning semantics, no revision authority, and no
//! admission validation: Governor admission gating stays Governor-owned
//! (`verify_learning_admission` re-check); durability never implies
//! effectiveness.
//!
//! Integration seam (I12.24, `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`):
//!
//! * "Neither loop creates a second task graph, attempt journal, scheduler,
//!   memory owner or authority path." (L5) — this named mutation/read pair
//!   is the single Kernel-owned learning surface; learning crates are never
//!   autonomous persistence systems and carry no store path of their own.
//! * "The view never accepts writes and never resolves disagreement between
//!   owners… A new owner revision rebuilds the view rather than mutating it
//!   in place." (L143) — rows are keyed `(record_kind, handle,
//!   record_digest)`; a new digest is a new row, never an in-place rewrite;
//!   identical replays converge (`IdentityConflict` on divergent rewrite).
//! * "Actor/Refiner proposes the artifact; Governor admits its local effect;
//!   Context Compiler activates it for a compatible attempt… The artifact
//!   has no independent authority." (L209) — the propose/admit/activate
//!   split: overlays and deltas are durable-but-inert without a live
//!   Governor admission reference; only admission makes a record effective.
//! * "Its disposition records, but never performs, a promotion" (L289) —
//!   the named mutation persists [`TransitionClass::CaptureCandidate`] with
//!   the `Candidate` ceiling: recording a candidate never promotes it.
//!
//! Wire identity: [`LEARNING_STORE_SCHEMA_V1`]
//! (`eliot.learning.state.v1`). Mutation operation: `RecordLearningRecord`.
//! Read operation: `GetLearningRecordRange`. Transition class:
//! `CaptureCandidate` with a `Candidate` ceiling (no support, influence,
//! lifecycle, or assertability change).
//!
//! Record documents travel as opaque strings: the store preserves them
//! verbatim and validates shape/bounds/closed kind membership
//! structurally. The presented `record_digest` is shape-checked here; the
//! digest IS the immutable revision identity at the backend. Owner data
//! travels only as opaque reference digests (`scope_digest`,
//! `fence_digest`); adapters write ONLY the learning tables and never
//! rewrite owner records. The store never derives semantics from the
//! document bytes. Read queries project bounded same-fence, same-scope
//! record sets with explicit truncation.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId, StateFence, StoreError,
};

/// Versioned wire/schema identity for canonical learning state.
pub const LEARNING_STORE_SCHEMA_V1: &str = "eliot.learning.state.v1";
/// Closed mutation operation name for learning-record writes.
pub const LEARNING_RECORD_MUTATION_NAME: &str = "RecordLearningRecord";
/// Closed read operation name for learning-record range reads.
pub const LEARNING_RECORD_READ_NAME: &str = "GetLearningRecordRange";
/// Closed record-kind discriminator (mutation + read selector).
pub const LEARNING_PARAM_RECORD_KIND: &str = "record_kind";
/// Exact canonical handle of the record (mutation).
pub const LEARNING_PARAM_HANDLE: &str = "handle";
/// Verbatim canonical record document (mutation).
pub const LEARNING_PARAM_RECORD_JSON: &str = "record_json";
/// Presented digest of the admitted record bytes (mutation).
pub const LEARNING_PARAM_RECORD_DIGEST: &str = "record_digest";
/// Digest over the canonical admission-scope bytes (mutation).
pub const LEARNING_PARAM_SCOPE_DIGEST: &str = "scope_digest";
/// Digest over the canonical admission-fence bytes (mutation).
pub const LEARNING_PARAM_FENCE_DIGEST: &str = "fence_digest";
/// Deterministic commit idempotency key (mutation).
pub const LEARNING_PARAM_IDEMPOTENCY_KEY: &str = "idempotency_key";
/// Decimal page-size bound (range reads, required).
pub const LEARNING_PARAM_MAX_RECORDS: &str = "max_records";
/// Opaque range continuation cursor (range reads, optional).
pub const LEARNING_PARAM_CURSOR: &str = "cursor";

/// Maximum accepted record-handle length in bytes.
pub const MAX_LEARNING_HANDLE_BYTES: usize = 256;
/// Maximum accepted idempotency-key length in bytes.
pub const MAX_LEARNING_IDEMPOTENCY_BYTES: usize = 256;
/// Maximum accepted record-document length in bytes.
///
/// Admitted records are bounded summaries plus refs (well under this
/// ceiling); larger payloads belong in Blob Store behind handles, never
/// inline in a named operation.
pub const MAX_LEARNING_RECORD_JSON_BYTES: usize = 262_144;
/// Maximum records one learning range read may return.
pub const MAX_LEARNING_PAGE_RECORDS: u16 = 64;

/// Closed learning-record kind discriminator (issue #1868).
///
/// One closed set covers every durable learning record named in Work
/// (view refs, activation receipts, deltas, overlays, closures,
/// candidates) without a per-kind table/authority split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LearningRecordKind {
    /// A proposed behavioral delta record.
    Delta,
    /// A proposed overlay record (durable-but-inert without admission).
    Overlay,
    /// A closure record.
    Closure,
    /// An activation receipt record.
    ActivationReceipt,
    /// A candidate record (recording never performs promotion).
    Candidate,
    /// A reference to a rebuilt view revision (views never accept writes).
    ViewRef,
}

impl LearningRecordKind {
    /// Returns the closed wire spelling of this record kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delta => "delta",
            Self::Overlay => "overlay",
            Self::Closure => "closure",
            Self::ActivationReceipt => "activation_receipt",
            Self::Candidate => "candidate",
            Self::ViewRef => "view_ref",
        }
    }

    /// Parses the closed wire spelling back into its record kind.
    #[must_use]
    pub const fn from_str(name: &str) -> Option<Self> {
        match name.as_bytes() {
            b"delta" => Some(Self::Delta),
            b"overlay" => Some(Self::Overlay),
            b"closure" => Some(Self::Closure),
            b"activation_receipt" => Some(Self::ActivationReceipt),
            b"candidate" => Some(Self::Candidate),
            b"view_ref" => Some(Self::ViewRef),
            _ => None,
        }
    }
}

/// Raw validated mutation decoded from a mutation parameter map.
///
/// Documents stay opaque strings: the backend persists them verbatim and
/// arbitrates `(record_kind, handle, record_digest)` keys. This struct
/// carries no learning semantics beyond closed kind membership.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedLearningMutation {
    /// Closed record-kind discriminator.
    pub record_kind: LearningRecordKind,
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// Presented digest of the admitted record bytes.
    pub record_digest: String,
    /// Digest over the canonical admission-scope bytes.
    pub scope_digest: String,
    /// Digest over the canonical admission-fence bytes.
    pub fence_digest: String,
    /// Deterministic commit idempotency key.
    pub idempotency_key: String,
}

/// Decoded range read with its closed kind filter and page bound.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedLearningRead {
    /// Closed kind filter, or `None` for every kind.
    pub record_kind: Option<LearningRecordKind>,
    /// Page-size bound (range reads only).
    pub max_records: u16,
}

/// Builds a learning-record commit parameter map from Governor-produced parts.
pub fn learning_record_commit_params(
    record_kind: LearningRecordKind,
    handle: String,
    record_json: String,
    record_digest: String,
    scope_digest: String,
    fence_digest: String,
    idempotency_key: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            LEARNING_PARAM_RECORD_KIND.to_owned(),
            Value::String(record_kind.as_str().to_owned()),
        ),
        (LEARNING_PARAM_HANDLE.to_owned(), Value::String(handle)),
        (
            LEARNING_PARAM_RECORD_JSON.to_owned(),
            Value::String(record_json),
        ),
        (
            LEARNING_PARAM_RECORD_DIGEST.to_owned(),
            Value::String(record_digest),
        ),
        (
            LEARNING_PARAM_SCOPE_DIGEST.to_owned(),
            Value::String(scope_digest),
        ),
        (
            LEARNING_PARAM_FENCE_DIGEST.to_owned(),
            Value::String(fence_digest),
        ),
        (
            LEARNING_PARAM_IDEMPOTENCY_KEY.to_owned(),
            Value::String(idempotency_key),
        ),
    ])
}

/// Builds the closed `RecordLearningRecord` mutation request.
#[must_use]
pub fn learning_record_mutation_request(params: BTreeMap<String, Value>) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::RecordLearningRecord,
        parameters: params,
    }
}

/// Builds a closed learning-record range-read request over one scope.
#[must_use]
pub fn learning_record_read_request(
    scope_id: ScopeId,
    record_kind: Option<LearningRecordKind>,
    max_records: u16,
    state_fence: StateFence,
) -> NamedReadRequest {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        LEARNING_PARAM_MAX_RECORDS.to_owned(),
        Value::String(max_records.to_string()),
    );
    if let Some(kind) = record_kind {
        parameters.insert(
            LEARNING_PARAM_RECORD_KIND.to_owned(),
            Value::String(kind.as_str().to_owned()),
        );
    }
    NamedReadRequest {
        operation: NamedReadOperation::GetLearningRecordRange,
        scope_id: Some(scope_id),
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    }
}

/// Validates closed mutation parameters for the learning-record operation.
///
/// Value rules (closed kind membership, bounded non-blank text, hex
/// digests) run here so every backend shares one acceptance boundary.
/// Digest recomputation stays Governor-owned: the presented digest is
/// shape-checked here; the digest IS the immutable revision identity at
/// the backend. Record documents stay opaque strings; the store never
/// derives semantics from them.
pub fn validate_learning_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    if operation != NamedMutationOperation::RecordLearningRecord {
        return Err(StoreError::UnknownOperation);
    }
    let kind = text_param(parameters, LEARNING_PARAM_RECORD_KIND)?;
    if LearningRecordKind::from_str(kind).is_none() {
        return Err(StoreError::InvalidField {
            field: "learning.record_kind",
            reason: "record kind must be a closed learning kind",
        });
    }
    let handle = text_param(parameters, LEARNING_PARAM_HANDLE)?;
    if handle.len() > MAX_LEARNING_HANDLE_BYTES {
        return Err(StoreError::InvalidField {
            field: "learning.handle",
            reason: "record handle exceeds the bounded length",
        });
    }
    let record_json = text_param(parameters, LEARNING_PARAM_RECORD_JSON)?;
    if record_json.len() > MAX_LEARNING_RECORD_JSON_BYTES {
        return Err(StoreError::InvalidField {
            field: "learning.record_json",
            reason: "record document exceeds the bounded length",
        });
    }
    crate::validate_sha256_hex(
        text_param(parameters, LEARNING_PARAM_RECORD_DIGEST)?,
        "learning.record_digest",
    )?;
    crate::validate_sha256_hex(
        text_param(parameters, LEARNING_PARAM_SCOPE_DIGEST)?,
        "learning.scope_digest",
    )?;
    crate::validate_sha256_hex(
        text_param(parameters, LEARNING_PARAM_FENCE_DIGEST)?,
        "learning.fence_digest",
    )?;
    let idempotency_key = text_param(parameters, LEARNING_PARAM_IDEMPOTENCY_KEY)?;
    if idempotency_key.len() > MAX_LEARNING_IDEMPOTENCY_BYTES {
        return Err(StoreError::InvalidField {
            field: "learning.idempotency_key",
            reason: "idempotency key exceeds the bounded length",
        });
    }
    Ok(())
}

/// Decodes one validated mutation parameter map into its raw record.
pub fn decode_learning_mutation(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedLearningMutation, StoreError> {
    validate_learning_mutation_params(operation, parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "learning parameter must be present",
            })
    };
    let kind = text_of(LEARNING_PARAM_RECORD_KIND)?;
    let record_kind =
        LearningRecordKind::from_str(kind.as_str()).ok_or(StoreError::InvalidField {
            field: "learning.record_kind",
            reason: "record kind must be a closed learning kind",
        })?;
    Ok(DecodedLearningMutation {
        record_kind,
        handle: text_of(LEARNING_PARAM_HANDLE)?,
        record_json: text_of(LEARNING_PARAM_RECORD_JSON)?,
        record_digest: text_of(LEARNING_PARAM_RECORD_DIGEST)?,
        scope_digest: text_of(LEARNING_PARAM_SCOPE_DIGEST)?,
        fence_digest: text_of(LEARNING_PARAM_FENCE_DIGEST)?,
        idempotency_key: text_of(LEARNING_PARAM_IDEMPOTENCY_KEY)?,
    })
}

/// Validates the closed range-read page bound and kind filter, and decodes
/// the query.
pub fn validate_learning_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedLearningRead, StoreError> {
    let max_records = parameters
        .get(LEARNING_PARAM_MAX_RECORDS)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "learning.max_records",
            reason: "page bound is required",
        })?;
    let max_records: u16 = max_records.parse().map_err(|_| StoreError::InvalidField {
        field: "learning.max_records",
        reason: "page bound must be a decimal count",
    })?;
    if max_records == 0 || max_records > MAX_LEARNING_PAGE_RECORDS {
        return Err(StoreError::InvalidField {
            field: "learning.max_records",
            reason: "page bound is out of range",
        });
    }
    let record_kind = match parameters.get(LEARNING_PARAM_RECORD_KIND) {
        None | Some(Value::Null) => None,
        Some(Value::String(kind)) => Some(LearningRecordKind::from_str(kind.as_str()).ok_or(
            StoreError::InvalidField {
                field: "learning.record_kind",
                reason: "record kind must be a closed learning kind",
            },
        )?),
        Some(_) => {
            return Err(StoreError::InvalidField {
                field: "learning.record_kind",
                reason: "record kind must be a closed learning kind",
            });
        }
    };
    Ok(DecodedLearningRead {
        record_kind,
        max_records,
    })
}

/// Decodes one validated range-read parameter map into its query.
pub fn decode_learning_read(
    operation: NamedReadOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedLearningRead, StoreError> {
    if operation != NamedReadOperation::GetLearningRecordRange {
        return Err(StoreError::UnknownOperation);
    }
    validate_learning_read_params(parameters)
}

/// Rejects any direct learning write that bypasses the named Kernel
/// mutation boundary (issue #1868).
///
/// Only the closed `RecordLearningRecord` operation is admitted; every
/// other operation fails closed with [`StoreError::UnknownOperation`].
/// Governor and eliotd commit paths call this guard before reaching the
/// neutral Kernel port.
pub fn reject_direct_learning_write(request: &NamedMutationRequest) -> Result<(), StoreError> {
    if request.operation == NamedMutationOperation::RecordLearningRecord {
        Ok(())
    } else {
        Err(StoreError::UnknownOperation)
    }
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
            reason: "learning parameter must be non-blank text",
        })
}
