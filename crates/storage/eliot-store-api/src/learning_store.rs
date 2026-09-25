//! Canonical learning-record wire contract (issue #1868, I12.24).
//!
//! This module owns the canonical wire boundary for durable learning
//! records: the closed record-kind discriminator, typed document decoding,
//! per-record completeness validation on raw parameter maps, and request
//! builders.
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
//!   in place." (L143) — rows are keyed by the complete
//!   kind/handle/record-digest/scope/fence/expiry identity; a new exact
//!   identity is a new row, never an in-place rewrite; identical replays
//!   converge (`IdentityConflict` on divergent rewrite).
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
//! Record documents travel as canonical JSON strings, but the store still
//! decodes and validates the closed first-party document for the declared
//! kind before preserving it. The presented `record_digest` is bound to the
//! exact canonical JSON bytes. The complete
//! kind/handle/record-digest/scope/fence/expiry tuple is the immutable
//! revision identity at the backend. Owner data travels only as
//! opaque reference digests (`scope_digest`, `fence_digest`); adapters write
//! ONLY the learning tables and never rewrite owner records. Read queries
//! project bounded, cursor-paginated, same-fence/same-scope record sets with
//! explicit truncation.

use std::collections::BTreeMap;

use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    ClosureHandoff, HarnessActivationReceiptCandidate,
};
use eliot_learning_delta::StoredLearningDelta;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId, StateFence, StoreError, canonical_json_bytes,
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
/// SHA-256 digest of the exact canonical record document bytes (mutation).
pub const LEARNING_PARAM_RECORD_DIGEST: &str = "record_digest";
/// Digest over the canonical admission-scope bytes (mutation).
pub const LEARNING_PARAM_SCOPE_DIGEST: &str = "scope_digest";
/// Digest over the canonical admission-fence bytes (mutation).
pub const LEARNING_PARAM_FENCE_DIGEST: &str = "fence_digest";
/// Deterministic commit idempotency key (mutation).
pub const LEARNING_PARAM_IDEMPOTENCY_KEY: &str = "idempotency_key";
/// Absolute expiry deadline in Unix milliseconds (mutation).
pub const LEARNING_PARAM_EXPIRES_AT_UNIX_MS: &str = "expires_at_unix_ms";
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
/// Maximum accepted opaque continuation-cursor length in bytes.
pub const MAX_LEARNING_CURSOR_BYTES: usize = 512;
/// Maximum rows a provider may scan for one bounded learning page. A larger
/// requested window is an explicit incomplete read, never a silent truncation.
pub const MAX_LEARNING_SCAN_ROWS: u64 = 4_096;
/// Wire keys for the explicit stream proof returned by learning range reads.
pub const LEARNING_PARAM_END_OF_STREAM: &str = "end_of_stream";
pub const LEARNING_PARAM_TOTAL_MATCHED: &str = "total_matched";

/// The shared foundation kind vocabulary is re-exported by the store seam so
/// every Kernel/store/Governor/context consumer uses the same closed enum.
pub use eliot_contracts::LearningRecordKind;

/// Exact immutable identity of one learning record revision.
///
/// The scope, State Fence, and expiry are part of the identity rather than
/// mutable row annotations. A digest alone is therefore not a cross-scope or
/// cross-fence collision key, and an expired revision cannot be replayed as a
/// current influence under a new deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningRecordIdentity {
    /// Closed record-kind discriminator.
    pub record_kind: LearningRecordKind,
    /// Exact canonical record handle.
    pub handle: String,
    /// SHA-256 digest of the exact canonical `record_json` document bytes.
    pub record_digest: String,
    /// Exact canonical scope identity.
    pub scope_id: String,
    /// Exact admission State Fence.
    pub state_fence: StateFence,
    /// Absolute expiry deadline in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl LearningRecordIdentity {
    /// Validate the complete identity before it reaches a named mutation.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.record_kind.as_str().is_empty() {
            return Err(StoreError::InvalidField {
                field: "learning.record_kind",
                reason: "record kind is required",
            });
        }
        if self.handle.trim().is_empty()
            || self.handle.chars().any(char::is_control)
            || self.handle.len() > MAX_LEARNING_HANDLE_BYTES
        {
            return Err(StoreError::InvalidField {
                field: "learning.handle",
                reason: "record handle is blank, overlong, or contains control characters",
            });
        }
        crate::validate_sha256_hex(&self.record_digest, "learning.record_digest")?;
        if self.scope_id.trim().is_empty() || self.scope_id.chars().any(char::is_control) {
            return Err(StoreError::InvalidField {
                field: "learning.scope_id",
                reason: "scope identity is blank or contains control characters",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| StoreError::InvalidField {
                field: "learning.state_fence",
                reason: "learning identity fence is invalid",
            })?;
        if self.expires_at_unix_ms == 0 {
            return Err(StoreError::InvalidField {
                field: "learning.expires_at_unix_ms",
                reason: "expiry deadline must be non-zero",
            });
        }
        Ok(())
    }

    /// Canonical identity digest used by the Governor operation identity.
    pub fn identity_digest(&self) -> Result<String, StoreError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(crate::sha256_hex(&bytes))
    }
}

/// Raw validated mutation decoded from a mutation parameter map.
///
/// Documents stay opaque strings: the backend persists them verbatim and
/// arbitrates the complete kind/handle/record-digest/scope/fence/expiry
/// identity. This struct carries no learning semantics beyond closed kind
/// membership and structural identity fields.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedLearningMutation {
    /// Closed record-kind discriminator.
    pub record_kind: LearningRecordKind,
    /// Exact canonical handle of the record.
    pub handle: String,
    /// Verbatim canonical record document.
    pub record_json: String,
    /// SHA-256 digest of the exact canonical record document bytes.
    pub record_digest: String,
    /// Digest over the canonical admission-scope bytes.
    pub scope_digest: String,
    /// Digest over the canonical admission-fence bytes.
    pub fence_digest: String,
    /// Deterministic commit idempotency key.
    pub idempotency_key: String,
    /// Absolute expiry deadline in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

/// Decoded range read with its closed kind filter, page bound, and
/// owner-minted continuation cursor.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedLearningRead {
    /// Closed kind filter, or `None` for every kind.
    pub record_kind: Option<LearningRecordKind>,
    /// Page-size bound (range reads only).
    pub max_records: u16,
    /// Opaque continuation cursor returned by the store owner, if any.
    pub cursor: Option<String>,
}

/// Closed typed document accepted by the learning-record store boundary.
///
/// The wire keeps the canonical document bytes, but decoding never falls back
/// to `serde_json::Value`: every kind has one first-party contract and one
/// validating constructor. An owner-defined object is therefore not a valid
/// Candidate/Delta/Overlay/Closure/ActivationReceipt/ViewRef record.
#[derive(Clone, Debug, PartialEq)]
pub enum LearningRecordDocument {
    /// Stored attempt delta.
    Delta(StoredLearningDelta),
    /// Campaign overlay candidate.
    Overlay(CampaignHarnessOverlayCandidate),
    /// Closure handoff.
    Closure(ClosureHandoff),
    /// Activation receipt candidate.
    ActivationReceipt(Box<HarnessActivationReceiptCandidate>),
    /// Reusable candidate.
    Candidate(AttemptLearningDeltaCandidate),
    /// Immutable view reference. The recipe remains an owner-side validation
    /// input; the persisted view still has to decode as the closed view type.
    ViewRef(CampaignLearningStateView),
}

impl LearningRecordDocument {
    /// Decode one exact kind into its typed document contract.
    pub fn decode(kind: LearningRecordKind, record_json: &str) -> Result<Self, StoreError> {
        let invalid = |_error: serde_json::Error| StoreError::InvalidField {
            field: "learning.record_json",
            reason: "record is not the closed typed document for its declared kind",
        };
        match kind {
            LearningRecordKind::Delta => serde_json::from_str::<StoredLearningDelta>(record_json)
                .map(Self::Delta)
                .map_err(invalid),
            LearningRecordKind::Overlay => {
                serde_json::from_str::<CampaignHarnessOverlayCandidate>(record_json)
                    .map(Self::Overlay)
                    .map_err(invalid)
            }
            LearningRecordKind::Closure => serde_json::from_str::<ClosureHandoff>(record_json)
                .map(Self::Closure)
                .map_err(invalid),
            LearningRecordKind::ActivationReceipt => {
                serde_json::from_str::<HarnessActivationReceiptCandidate>(record_json)
                    .map(|record| Self::ActivationReceipt(Box::new(record)))
                    .map_err(invalid)
            }
            LearningRecordKind::Candidate => {
                serde_json::from_str::<AttemptLearningDeltaCandidate>(record_json)
                    .map(Self::Candidate)
                    .map_err(invalid)
            }
            LearningRecordKind::ViewRef => {
                serde_json::from_str::<CampaignLearningStateView>(record_json)
                    .map(Self::ViewRef)
                    .map_err(invalid)
            }
        }
    }

    /// Validate the decoded first-party contract, not just its JSON shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        let contract_error = |_error: String| StoreError::InvalidField {
            field: "learning.record_json",
            reason: "typed learning document failed its owning contract",
        };
        match self {
            Self::Delta(record) => record
                .validate()
                .map_err(|error| contract_error(error.to_string())),
            Self::Overlay(record) => record
                .validate()
                .map_err(|error| contract_error(error.to_string())),
            Self::Closure(record) => record
                .validate()
                .map_err(|error| contract_error(error.to_string())),
            Self::ActivationReceipt(record) => record
                .validate()
                .map_err(|error| contract_error(error.to_string())),
            Self::Candidate(record) => record
                .validate()
                .map_err(|error| contract_error(error.to_string())),
            Self::ViewRef(record) => {
                // A view has no independent recipe authority in the store;
                // its closed type and intrinsic canonical self-digest are
                // still checked here. Governor/Context performs the recipe
                // comparison.
                let mut unsigned = record.clone();
                unsigned.canonical_digest.clear();
                unsigned
                    .seal()
                    .map_err(|error| contract_error(error.to_string()))?;
                if unsigned.canonical_digest != record.canonical_digest {
                    return Err(StoreError::InvalidField {
                        field: "learning.view.canonical_digest",
                        reason: "view intrinsic digest does not match its typed document",
                    });
                }
                Ok(())
            }
        }
    }

    /// Validate that the wire handle is the intrinsic identity of the typed
    /// document. A closed record kind without this correlation would allow a
    /// valid document to be filed under a different immutable revision handle.
    pub fn validate_handle(&self, handle: &str) -> Result<(), StoreError> {
        let matches = match self {
            Self::Delta(record) => record.delta_artifact.as_str() == handle,
            Self::Overlay(record) => record.overlay_id.as_str() == handle,
            Self::Closure(record) => record.assessment_id.as_str() == handle,
            Self::ActivationReceipt(record) => record.activation_id.as_str() == handle,
            Self::Candidate(record) => record.delta_id.as_str() == handle,
            Self::ViewRef(record) => record.view_id.as_str() == handle,
        };
        if matches {
            Ok(())
        } else {
            Err(StoreError::InvalidField {
                field: "learning.handle",
                reason: "record handle does not match the typed document identity",
            })
        }
    }

    /// Validate the typed document's scope/fence binding against the
    /// canonical transition. Stored deltas predate the shared binding object,
    /// so they contribute their intrinsic fence but have no independent scope
    /// field to compare.
    pub fn validate_scope_fence(
        &self,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), StoreError> {
        let matches = match self {
            Self::Delta(record) => record.state_fence == *state_fence,
            Self::Overlay(record) => {
                record.binding.scope.as_str() == scope_id
                    && record.binding.state_fence == *state_fence
            }
            Self::Closure(record) => {
                record.binding.scope.as_str() == scope_id
                    && record.binding.state_fence == *state_fence
            }
            Self::ActivationReceipt(record) => {
                record.binding.scope.as_str() == scope_id
                    && record.binding.state_fence == *state_fence
            }
            Self::Candidate(record) => {
                record.binding.scope.as_str() == scope_id
                    && record.binding.state_fence == *state_fence
            }
            Self::ViewRef(record) => {
                record.binding.scope.as_str() == scope_id
                    && record.binding.state_fence == *state_fence
            }
        };
        if matches {
            Ok(())
        } else {
            Err(StoreError::InvalidField {
                field: "learning.scope_fence_binding",
                reason: "typed document binding differs from the canonical transition",
            })
        }
    }
}

/// Builds a learning-record commit parameter map from Governor-produced parts.
#[allow(
    clippy::too_many_arguments,
    reason = "the closed wire parameter list mirrors the named operation schema"
)]
pub fn learning_record_commit_params(
    record_kind: LearningRecordKind,
    handle: String,
    record_json: String,
    record_digest: String,
    scope_digest: String,
    fence_digest: String,
    idempotency_key: String,
    expires_at_unix_ms: u64,
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
        (
            LEARNING_PARAM_EXPIRES_AT_UNIX_MS.to_owned(),
            Value::String(expires_at_unix_ms.to_string()),
        ),
    ])
}

/// Computes the exact digest of a scope identity used by learning rows.
pub fn learning_scope_digest(scope_id: &str) -> Result<String, StoreError> {
    if scope_id.trim().is_empty() || scope_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "learning.scope_id",
            reason: "scope identity is blank or contains control characters",
        });
    }
    let bytes = canonical_json_bytes(&scope_id)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(crate::sha256_hex(&bytes))
}

/// Computes the exact digest of a State Fence used by learning rows.
pub fn learning_fence_digest(state_fence: &StateFence) -> Result<String, StoreError> {
    state_fence
        .validate()
        .map_err(|_| StoreError::InvalidField {
            field: "learning.state_fence",
            reason: "learning identity fence is invalid",
        })?;
    let bytes = canonical_json_bytes(state_fence)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(crate::sha256_hex(&bytes))
}

/// Computes the authoritative immutable revision digest for a learning
/// record document.
///
/// `record_json` is a wire string, but its bytes are a canonical JSON
/// object. The digest is therefore computed over the exact canonical UTF-8
/// document bytes that the store preserves. A caller cannot pair a valid
/// looking hex digest with different document bytes. Non-object, non-JSON, or
/// non-canonical documents are refused instead of being normalized silently.
pub fn learning_record_document_digest(record_json: &str) -> Result<String, StoreError> {
    let value: Value =
        serde_json::from_str(record_json).map_err(|_error| StoreError::InvalidField {
            field: "learning.record_json",
            reason: "record document must be valid JSON",
        })?;
    if !value.is_object() {
        return Err(StoreError::InvalidField {
            field: "learning.record_json",
            reason: "record document must be a JSON object",
        });
    }
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if canonical != record_json.as_bytes() {
        return Err(StoreError::InvalidField {
            field: "learning.record_json",
            reason: "record document must use canonical JSON bytes",
        });
    }
    Ok(crate::sha256_hex(&canonical))
}

/// Builds the closed mutation parameters from an exact typed identity.
pub fn learning_record_commit_params_from_identity(
    identity: &LearningRecordIdentity,
    record_json: String,
    idempotency_key: String,
) -> Result<BTreeMap<String, Value>, StoreError> {
    identity.validate()?;
    Ok(learning_record_commit_params(
        identity.record_kind,
        identity.handle.clone(),
        record_json,
        identity.record_digest.clone(),
        learning_scope_digest(&identity.scope_id)?,
        learning_fence_digest(&identity.state_fence)?,
        idempotency_key,
        identity.expires_at_unix_ms,
    ))
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
    learning_record_read_request_page(scope_id, record_kind, max_records, state_fence, None)
}

/// Builds one page of the closed learning range read, optionally resuming
/// from an owner-minted continuation cursor.
#[must_use]
pub fn learning_record_read_request_page(
    scope_id: ScopeId,
    record_kind: Option<LearningRecordKind>,
    max_records: u16,
    state_fence: StateFence,
    cursor: Option<String>,
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
    if let Some(cursor) = cursor {
        parameters.insert(LEARNING_PARAM_CURSOR.to_owned(), Value::String(cursor));
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
/// Value rules (closed kind membership, bounded non-blank text, canonical
/// document bytes, and matching hex digests) run here so every backend shares
/// one acceptance boundary. Scope/fence digest recomputation and semantic
/// record validation stay Governor-owned: the store checks the presented
/// values against the canonical transition envelope, while the complete
/// kind/handle/digest/scope/fence/expiry tuple is the immutable revision
/// identity.
pub fn validate_learning_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    if operation != NamedMutationOperation::RecordLearningRecord {
        return Err(StoreError::UnknownOperation);
    }
    let kind = text_param(parameters, LEARNING_PARAM_RECORD_KIND)?;
    let record_kind = LearningRecordKind::from_str(kind).ok_or(StoreError::InvalidField {
        field: "learning.record_kind",
        reason: "record kind must be a closed learning kind",
    })?;
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
    let expected_record_digest = learning_record_document_digest(record_json)?;
    if text_param(parameters, LEARNING_PARAM_RECORD_DIGEST)? != expected_record_digest {
        return Err(StoreError::InvalidField {
            field: "learning.record_digest",
            reason: "record digest does not match canonical record_json bytes",
        });
    }
    let document = LearningRecordDocument::decode(record_kind, record_json)?;
    document.validate()?;
    document.validate_handle(handle)?;
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
    let expires_at_unix_ms = text_param(parameters, LEARNING_PARAM_EXPIRES_AT_UNIX_MS)?
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidField {
            field: "learning.expires_at_unix_ms",
            reason: "expiry deadline must be a decimal Unix millisecond value",
        })?;
    if expires_at_unix_ms == 0 {
        return Err(StoreError::InvalidField {
            field: "learning.expires_at_unix_ms",
            reason: "expiry deadline must be non-zero",
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
        expires_at_unix_ms: text_of(LEARNING_PARAM_EXPIRES_AT_UNIX_MS)?
            .parse::<u64>()
            .map_err(|_| StoreError::InvalidField {
                field: "learning.expires_at_unix_ms",
                reason: "expiry deadline must be a decimal Unix millisecond value",
            })?,
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
    let cursor = match parameters.get(LEARNING_PARAM_CURSOR) {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => {
            if cursor.trim().is_empty()
                || cursor.len() > MAX_LEARNING_CURSOR_BYTES
                || cursor.chars().any(char::is_control)
            {
                return Err(StoreError::InvalidField {
                    field: "learning.cursor",
                    reason: "continuation cursor is malformed or overlong",
                });
            }
            Some(cursor.clone())
        }
        Some(_) => {
            return Err(StoreError::InvalidField {
                field: "learning.cursor",
                reason: "continuation cursor must be text",
            });
        }
    };
    Ok(DecodedLearningRead {
        record_kind,
        max_records,
        cursor,
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
