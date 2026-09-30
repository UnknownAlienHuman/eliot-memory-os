//! Governor seven-role input reconstruction for context composition.
//!
//! T11 section 5, slice T11.3 (part A, Governor): acquire the seven immutable,
//! revision/fence-bound owner projections through the Governor read owner
//! (`eliot_read::ReadApi`) and expose them as input reconstruction. This is
//! never an admitted `ActiveUnderstandingView`: no candidate selection,
//! admission, assembly, or publication runs here (T11.md:163).
//!
//! Role → acquisition mapping (T11.md:65-77):
//!
//! | Candidate provider role | Named read | Facade |
//! |---|---|---|
//! | `TaskFrame` | `GetTaskState` | `ReadApi::state` |
//! | `CriticalAttention`/`Conflict` | `GetAttentionAndProblems` | `ReadApi::state` |
//! | `CurrentEpistemicPosition` | `GetCurrentEpistemicPosition` | `ReadApi::query` with `QueryMode::ContextReconstruction` (reuses the T11.2 readback shape) |
//! | Cue activation | `GetUnderstandingProjectionInputs` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//! | Negative memory | `GetLearningRecordRange` (`ActivationReceipt`) | `ReadApi::query` with the existing negative-memory resolver |
//! | Evidence/source assurance | `GetEvidencePack` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//! | Affordances | `GetCapabilityEvidenceRecordRange` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//!
//! The query facade admits every query role listed above for
//! `QueryMode::ContextReconstruction` (`eliot_read` intent table). Every read uses
//! `ReadConsistency::ExactFence` with caller-supplied dependency revisions.
//!
//! Selector discipline: every role carries the exact closed selector set the
//! store catalogue declares for its read (issue #2563). Task, attention, and
//! cue roles use their versioned owner envelopes; negative-memory and
//! affordance roles retain native record-range rows and original revisions.
//! The request carries no caller-selected scope override, no fabricated `all`
//! selector and no empty default: a missing required selector is refused by
//! [`ContextInputsError::RequestInvalid`] before any read is planned.
//!
//! Closure discipline (T11.md:77): the dependency heads (`ScopeRevisionView`)
//! are captured before acquisition and re-read afterwards; bounded churn
//! fails closed as [`ContextInputsError::SourceHeadsChanged`] rather than
//! exposing a silently mixed snapshot. The whole reconstruction is bounded to
//! one read per role slot (seven physical reads); there is no retry loop and
//! no continuation drain here — #1729 owns broader coherent
//! assembly.
//!
//! Disposition discipline (`eliot_context_candidates::ProjectionState`):
//! `KnownEmpty` requires an authoritative completed lookup (an explicit empty
//! result with an exact truncation/coverage statement). Transport failure,
//! an unactivated (known-but-unsupported) operation, and a bounded partial
//! scan are reported as `Unavailable`/`Unknown`/`Partial` — never as empty.
//! Each role response is bound to the requested operation, scope, selector and
//! payload version before it becomes a disposition, so a response answering a
//! different task/problem/skill is never adopted just because its operation
//! and fence match.
//!
//! Page-provenance discipline (#2857): the shared rule
//! ([`classify_role_page`]) judges the versioned context-envelope pages. The
//! capability range owner has separate keyset semantics: its `matched_total`
//! is the returned count, and a partial page is retained only with its real
//! fence-bound continuation cursor.
//!
//! Downstream limit, kept explicit: a successful source read is not proof of
//! Cue admission, capability qualification or packet readiness. Cue admission
//! and capability qualification remain separate owner decisions.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{ClockReading, RequestMetadata};
use eliot_dreamer_failure::{NegativeMemoryActionPolicy, NegativeMemoryFingerprint};
use eliot_read::{
    BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode, QueryRequest,
    ReadApi, ReadError, ReadIdentity, ReadOrderingBinding, ReadOutcome, RequiredAssurance,
    StateRequest, TimeScope,
};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, LearningRecordKind, MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS,
    MAX_LEARNING_PAGE_RECORDS, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    ReadConsistency, RevisionHead, RevisionKey, ScopeId, ScopeRevisionView, WriteReceiptStatus,
    capability_evidence_read_request, epistemic_revision::EpistemicPositionReadback,
    learning_record_read_request,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Role label for the `TaskFrame` slot.
pub const ROLE_TASK_FRAME: &str = "task_frame";
/// Role label for the `CriticalAttention`/`Conflict` slot.
pub const ROLE_ATTENTION_CONFLICT: &str = "attention_conflict";
/// Role label for the `CurrentEpistemicPosition` slot.
pub const ROLE_EPISTEMIC_POSITION: &str = "epistemic_position";
/// Role label for the cue-activation slot.
pub const ROLE_CUE_ACTIVATION: &str = "cue_activation";
/// Role label for the negative-memory slot.
pub const ROLE_NEGATIVE_MEMORY: &str = "negative_memory";
/// Role label for the evidence/source-assurance slot.
pub const ROLE_EVIDENCE_ASSURANCE: &str = "evidence_assurance";
/// Role label for the affordances slot.
pub const ROLE_AFFORDANCES: &str = "affordances";

/// Fail-closed errors for seven-role input reconstruction.
///
/// A per-role read failure is never raised here: it becomes that role's
/// [`ProjectionState`] disposition inside [`SevenRoleInputs`]. These variants
/// cover only conditions under which no coherent seven-role view can be
/// exposed at all (bad request, missing closure, churn during acquisition).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextInputsError {
    /// The reconstruction request or caller metadata is malformed.
    #[error("context reconstruction request is invalid: {0}")]
    RequestInvalid(String),
    /// Exact-fence reads require at least one dependency revision.
    #[error(
        "context reconstruction requires at least one dependency revision for exact-fence reads"
    )]
    MissingDependencies,
    /// The dependency-head closure could not be established.
    #[error("context reconstruction closure is unavailable: {0}")]
    ClosureUnavailable(String),
    /// Source heads moved between the before/after capture; retry with a
    /// fresh closure instead of serving a mixed snapshot.
    #[error("source heads changed during acquisition; retry with a fresh closure")]
    SourceHeadsChanged,
    /// A role request was rejected for a caller-shape reason (not a provider
    /// outcome); this is a programming error, never a role disposition.
    #[error("context reconstruction role request was rejected: {0}")]
    RequestRejected(String),
}

/// Closed request for one seven-role reconstruction.
///
/// The fence travels only in the caller [`RequestMetadata`]; dependency
/// revisions bind the exact-fence reads. Every field is an owner-resolved exact
/// selector taken from the already admitted scope/task/capability request, and
/// every one maps 1:1 onto the store catalogue's closed parameter set for its
/// read:
///
/// | field | read | catalogue parameters |
/// |---|---|---|
/// | `epistemic_position` | `GetCurrentEpistemicPosition` | `position` |
/// | `evidence_subject`, `evidence_max_records` | `GetEvidencePack` | `subject`, `max_records` |
/// | `task_id`, `task_max_records` | `GetTaskState` | `task_id`, `max_records` |
/// | `attention_problem_id`, `attention_max_records` | `GetAttentionAndProblems` | `problem_id` (omitted when no specific problem is requested), `max_records` |
/// | `projection_selector`, `projection_max_records` | `GetUnderstandingProjectionInputs` (cue activation) | `selector`, `max_records` |
/// | `negative_memory_selector`, `negative_memory_max_records` | `GetLearningRecordRange` | `record_kind` (`activation_receipt`), `max_records` |
/// | `affordance_skill_id`, `affordance_max_records` | `GetCapabilityEvidenceRecordRange` | `skill_id`, `max_records` |
///
/// Each `max_records` is the explicit owner bound
/// `1..=EVIDENCE_PACK_MAX_RECORDS` and travels as its decimal **string**,
/// exactly as every owner handler parses it; a JSON number is not a valid
/// bound.
///
/// There is deliberately no caller-selected scope override, no fabricated `all`
/// selector and no empty default. A required selector the caller cannot resolve
/// is a typed [`ContextInputsError::RequestInvalid`] prerequisite failure
/// raised by [`validate`](Self::validate) before any read is planned, never a
/// permissive fallback.
///
/// Wire compatibility and explicit migration: `epistemic_position`,
/// `evidence_subject` and `evidence_max_records` keep their existing names and
/// meanings unchanged. The task/attention/projection/affordance members are new
/// REQUIRED members, so a request serialized before this shape is REFUSED at
/// this `deny_unknown_fields`/required-member boundary instead of being
/// silently defaulted to a fabricated selector. No permissive compatibility
/// path accepts the old wire shape; `attention_problem_id` is the only
/// member with a default, and its absent value is a declared contract option
/// ("no specific problem is requested"), not a substituted selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextReconstructionRequest {
    /// Scope every role projection must be bound to.
    pub scope_id: ScopeId,
    /// Dependency revisions for the exact-fence reads.
    pub dependency_revisions: BTreeMap<RevisionKey, u64>,
    /// Exact position identity for the epistemic read.
    pub epistemic_position: String,
    /// Exact captured-observation subject for the evidence read.
    pub evidence_subject: String,
    /// Explicit evidence bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub evidence_max_records: u32,
    /// Exact task identity for `GetTaskState` (`task_id`).
    pub task_id: String,
    /// Explicit task-state bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub task_max_records: u32,
    /// Exact problem identity for `GetAttentionAndProblems`, or `None` when no
    /// specific problem is requested (the `problem_id` key is then omitted
    /// rather than sent as null).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention_problem_id: Option<String>,
    /// Explicit attention bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub attention_max_records: u32,
    /// Exact source selector for the cue-activation projection (`selector`).
    pub projection_selector: String,
    /// Explicit cue-projection bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub projection_max_records: u32,
    /// Exact native negative-memory selector (`activation_receipt`).
    ///
    /// Only the fixed activation-receipt source is admitted; this remains a
    /// required member so a caller cannot omit the named native source.
    pub negative_memory_selector: String,
    /// Explicit negative-memory page bound
    /// (`1..=MAX_LEARNING_PAGE_RECORDS`).
    pub negative_memory_max_records: u32,
    /// Exact skill identity for the capability evidence range (`skill_id`).
    pub affordance_skill_id: String,
    /// Explicit capability-evidence page bound
    /// (`1..=MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS`).
    pub affordance_max_records: u32,
}

impl ContextReconstructionRequest {
    /// Validates the closed request shape without performing any read.
    ///
    /// Every owner-resolved selector must be non-blank text without control
    /// characters, every explicit bound must be within
    /// `1..=EVIDENCE_PACK_MAX_RECORDS`, and every dependency revision must be
    /// non-zero. A refusal here is a typed prerequisite/request failure: the
    /// reconstruction stops before any transport rather than planning a read
    /// that could only be rejected downstream.
    pub fn validate(&self) -> Result<(), ContextInputsError> {
        if self
            .dependency_revisions
            .values()
            .any(|revision| *revision == 0)
        {
            return Err(ContextInputsError::RequestInvalid(
                "dependency revisions must be non-zero".to_owned(),
            ));
        }
        self.validate_selectors()?;
        self.validate_page_bounds()
    }

    fn validate_selectors(&self) -> Result<(), ContextInputsError> {
        check_text_selector("epistemic_position", &self.epistemic_position)?;
        check_text_selector("evidence_subject", &self.evidence_subject)?;
        check_text_selector("task_id", &self.task_id)?;
        check_text_selector("projection_selector", &self.projection_selector)?;
        check_text_selector("negative_memory_selector", &self.negative_memory_selector)?;
        if self.negative_memory_selector != LearningRecordKind::ActivationReceipt.as_str() {
            return Err(ContextInputsError::RequestInvalid(
                "negative_memory_selector must name the native activation_receipt source"
                    .to_owned(),
            ));
        }
        check_text_selector("affordance_skill_id", &self.affordance_skill_id)?;
        if let Some(problem_id) = &self.attention_problem_id {
            check_text_selector("attention_problem_id", problem_id)?;
        }
        Ok(())
    }

    fn validate_page_bounds(&self) -> Result<(), ContextInputsError> {
        for (field, bound) in [
            ("evidence_max_records", self.evidence_max_records),
            ("task_max_records", self.task_max_records),
            ("attention_max_records", self.attention_max_records),
            ("projection_max_records", self.projection_max_records),
        ] {
            if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
                return Err(ContextInputsError::RequestInvalid(format!(
                    "{field} must be within 1..=EVIDENCE_PACK_MAX_RECORDS"
                )));
            }
        }
        if self.negative_memory_max_records == 0
            || self.negative_memory_max_records > u32::from(MAX_LEARNING_PAGE_RECORDS)
        {
            return Err(ContextInputsError::RequestInvalid(
                "negative_memory_max_records must fit the native learning page bound".to_owned(),
            ));
        }
        if self.affordance_max_records == 0
            || self.affordance_max_records > u32::from(MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS)
        {
            return Err(ContextInputsError::RequestInvalid(
                "affordance_max_records must fit the native capability evidence page bound"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// One acquired role: its disposition, original payload, and observed heads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAcquisition {
    /// Closed named operation that produced (or refused) this role.
    pub operation: NamedReadOperation,
    /// Completeness state of this role (`inputs.rs:188-282` vocabulary).
    pub state: ProjectionState,
    /// Original owner payload when a response was returned.
    pub payload: Option<Value>,
    /// Revision heads observed with this role's read.
    pub revision_heads: Vec<RevisionHead>,
    /// Exact read identity this role is bound to (`#1144` retained-read
    /// binding): principal, scope, fence, consistency, declared and observed
    /// heads, order heads, source, projection schema, coverage and the exact
    /// invalidation conditions. Partial or malformed returned pages retain
    /// this identity too; absence means no read identity was returned.
    pub identity: Option<ReadIdentity>,
    /// Exact named request sent for native paged owner reads. `ReadIdentity`
    /// retains the operation/source/coverage closure; this request preserves
    /// the original selectors the read identity intentionally does not repeat.
    pub source_request: Option<NamedReadRequest>,
    /// Typed capability records parsed from the original range-read rows.
    /// The raw documents and their owner-issued digest/revision remain in
    /// `payload`; this typed view does not recompute those identities.
    pub retained_capability_records: Option<Vec<RetainedCapabilityEvidenceRecord>>,
    /// Original native negative-memory records accepted by the existing
    /// activation-receipt resolver.
    pub retained_negative_memory_records: Option<Vec<NegativeMemoryFingerprint>>,
    /// Owner-admitted action policies bound to the retained negative-memory
    /// records by that same resolver.
    pub retained_negative_memory_policies: Option<Vec<NegativeMemoryActionPolicy>>,
}

/// Typed view of one row returned by `GetCapabilityEvidenceRecordRange`.
///
/// `scope_key`, record bytes, record digest, and store revision are retained
/// from the exact response. `revision.evidence_ref` is the original digest;
/// this type does not mint or recompute it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCapabilityEvidenceRecord {
    /// Parsed original record document.
    pub record: crate::CapabilityEvidenceRecord,
    /// Original store row key for the route fingerprint.
    pub scope_key: String,
    /// Original store-issued revision and record digest.
    pub revision: crate::OwnerEvidenceRevision,
}

fn failed_role(operation: NamedReadOperation, state: ProjectionState) -> RoleAcquisition {
    RoleAcquisition {
        operation,
        state,
        payload: None,
        revision_heads: Vec::new(),
        identity: None,
        source_request: None,
        retained_capability_records: None,
        retained_negative_memory_records: None,
        retained_negative_memory_policies: None,
    }
}

/// Checks a capability evidence page against its original Store fields and
/// returns typed rows only when every row agrees with its owner-issued key and
/// revision. The exact record digest is carried through without recomputation.
fn classify_capability_evidence_payload(
    payload: &Value,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    skill_id: &str,
    max_records: u16,
) -> (
    ProjectionState,
    Option<Vec<RetainedCapabilityEvidenceRecord>>,
) {
    if let Err(state) = validate_capability_range_payload(payload, scope, fence) {
        return (state, None);
    }
    let (rows, truncated) = match capability_range_rows(payload, max_records) {
        Ok(page) => page,
        Err(state) => return (state, None),
    };
    let retained = match decode_capability_rows(rows, skill_id) {
        Ok(retained) => retained,
        Err(state) => return (state, None),
    };
    if truncated {
        (
            ProjectionState::Partial {
                reason: "capability evidence range has an owner-issued continuation cursor"
                    .to_owned(),
            },
            Some(retained),
        )
    } else if retained.is_empty() {
        (ProjectionState::KnownEmpty, Some(retained))
    } else {
        (ProjectionState::Complete, Some(retained))
    }
}

fn validate_capability_range_payload(
    payload: &Value,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<(), ProjectionState> {
    let unavailable = |detail: &str| ProjectionState::Unavailable {
        reason: bounded_reason("capability evidence page fails its contract", detail),
    };
    if payload.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(unavailable("unsupported range payload version"));
    }
    if payload.get("scope_id").and_then(Value::as_str) != Some(scope.as_str()) {
        return Err(unavailable("range scope mismatch"));
    }
    let Some(observed_fence) = payload.get("state_fence").cloned() else {
        return Err(ProjectionState::Unknown {
            reason: "range payload omits the Store-reported StateFence".to_owned(),
        });
    };
    let Ok(observed_fence) = serde_json::from_value::<eliot_contracts::StateFence>(observed_fence)
    else {
        return Err(ProjectionState::Unknown {
            reason: "range payload carries a malformed StateFence".to_owned(),
        });
    };
    if !eliot_contracts::fences_match_exact(&observed_fence, fence) {
        return Err(ProjectionState::Stale {
            reason: "range payload belongs to a different StateFence".to_owned(),
        });
    }
    Ok(())
}

fn capability_range_rows(
    payload: &Value,
    max_records: u16,
) -> Result<(&[Value], bool), ProjectionState> {
    let Some(rows) = payload.get("records").and_then(Value::as_array) else {
        return Err(ProjectionState::Unavailable {
            reason: bounded_reason(
                "capability evidence page fails its contract",
                "range payload has no records array",
            ),
        });
    };
    let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    let Some(matched_total) = payload.get("matched_total").and_then(Value::as_u64) else {
        return Err(ProjectionState::Unknown {
            reason: "range payload omits its page denominator".to_owned(),
        });
    };
    let Some(truncated) = payload.get("truncated").and_then(Value::as_bool) else {
        return Err(ProjectionState::Unknown {
            reason: "range payload omits its truncation disposition".to_owned(),
        });
    };
    let cursor_matches = match (truncated, payload.get("next_cursor")) {
        (true, Some(Value::String(value))) => !value.is_empty(),
        (false, None | Some(Value::Null)) => true,
        _ => false,
    };
    if !cursor_matches || matched_total != count || rows.len() > usize::from(max_records) {
        return Err(ProjectionState::Unknown {
            reason: "range page denominator, cursor, or bound is incoherent".to_owned(),
        });
    }
    Ok((rows, truncated))
}

fn decode_capability_rows(
    rows: &[Value],
    skill_id: &str,
) -> Result<Vec<RetainedCapabilityEvidenceRecord>, ProjectionState> {
    let unavailable = |detail: &str| ProjectionState::Unavailable {
        reason: bounded_reason("capability evidence page fails its contract", detail),
    };
    let mut seen = BTreeSet::new();
    let mut retained = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(row_skill_id) = row.get("skill_id").and_then(Value::as_str) else {
            return Err(unavailable("record row omits skill identity"));
        };
        let Some(scope_key) = row.get("scope_key").and_then(Value::as_str) else {
            return Err(unavailable("record row omits route-scope key"));
        };
        let Some(record_digest) = row.get("record_digest").and_then(Value::as_str) else {
            return Err(unavailable("record row omits original digest"));
        };
        let Some(record_json) = row.get("record_json").and_then(Value::as_str) else {
            return Err(unavailable("record row omits original document"));
        };
        let Some(owner_revision) = row.get("revision").and_then(Value::as_u64) else {
            return Err(unavailable("record row omits owner revision"));
        };
        if row_skill_id != skill_id
            || !crate::is_evidence_ref(scope_key)
            || !crate::is_evidence_ref(record_digest)
            || owner_revision == 0
        {
            return Err(unavailable(
                "record row identity is malformed or substituted",
            ));
        }
        let record: crate::CapabilityEvidenceRecord = serde_json::from_str(record_json)
            .map_err(|_| unavailable("original record does not decode"))?;
        if record.skill_id != row_skill_id
            || !seen.insert((row_skill_id.to_owned(), scope_key.to_owned()))
        {
            return Err(unavailable(
                "typed record differs from its original row key",
            ));
        }
        let revision = crate::OwnerEvidenceRevision::issued(owner_revision, record_digest)
            .map_err(|_| unavailable("owner revision or original digest is invalid"))?;
        retained.push(RetainedCapabilityEvidenceRecord {
            record,
            scope_key: scope_key.to_owned(),
            revision,
        });
    }
    Ok(retained)
}

/// The reconstructed seven-role input closure.
///
/// All seven roles bind one compatible read closure: the fence plus the
/// before/after dependency heads. `heads_after` equals `heads_before` by
/// construction — any churn fails the whole reconstruction instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SevenRoleInputs {
    /// Scope every role was acquired under.
    pub scope_id: ScopeId,
    /// Fence every role was acquired under.
    pub state_fence: eliot_contracts::StateFence,
    /// Request/assembly time observations carried by the validated request.
    /// These are not source-event time or proof that the reconstructed inputs
    /// remain fresh; `transaction_sequence`, when present, is causal order,
    /// not transaction wall-clock time.
    pub clock: ClockReading,
    /// Dependency heads captured before acquisition.
    pub heads_before: ScopeRevisionView,
    /// Dependency heads re-read after acquisition (equal to `heads_before`).
    pub heads_after: ScopeRevisionView,
    /// `TaskFrame` role (`GetTaskState`).
    pub task_frame: RoleAcquisition,
    /// `CriticalAttention`/`Conflict` role (`GetAttentionAndProblems`).
    pub attention: RoleAcquisition,
    /// `CurrentEpistemicPosition` role (`GetCurrentEpistemicPosition`).
    pub epistemic: RoleAcquisition,
    /// Decoded T11.2 readback when the epistemic role is `Complete`.
    pub epistemic_readback: Option<EpistemicPositionReadback>,
    /// Cue-activation role (`GetUnderstandingProjectionInputs`).
    pub cue: RoleAcquisition,
    /// Negative-memory role (`GetUnderstandingProjectionInputs`,
    /// negative-memory interpretation of the same closed projection).
    pub negative_memory: RoleAcquisition,
    /// Evidence/source-assurance role (`GetEvidencePack`).
    pub evidence: RoleAcquisition,
    /// Affordances role (`GetCapabilityEvidenceRecordRange`).
    pub affordances: RoleAcquisition,
}

impl SevenRoleInputs {
    /// Returns every role label with its disposition, in slot order.
    #[must_use]
    pub fn role_states(&self) -> [(&'static str, &ProjectionState); 7] {
        [
            (ROLE_TASK_FRAME, &self.task_frame.state),
            (ROLE_ATTENTION_CONFLICT, &self.attention.state),
            (ROLE_EPISTEMIC_POSITION, &self.epistemic.state),
            (ROLE_CUE_ACTIVATION, &self.cue.state),
            (ROLE_NEGATIVE_MEMORY, &self.negative_memory.state),
            (ROLE_EVIDENCE_ASSURANCE, &self.evidence.state),
            (ROLE_AFFORDANCES, &self.affordances.state),
        ]
    }

    /// Returns the labels of roles whose source could not be read or
    /// evaluated (`Unavailable`, `Unknown`, `Missing`, `Blocked`).
    ///
    /// These are reported distinctly from authoritative [`ProjectionState::KnownEmpty`]:
    /// an unreadable or unactivated source is never an empty set.
    #[must_use]
    pub fn unsupported_role_names(&self) -> Vec<&'static str> {
        self.role_states()
            .into_iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    ProjectionState::Unavailable { .. }
                        | ProjectionState::Unknown { .. }
                        | ProjectionState::Missing
                        | ProjectionState::Blocked { .. }
                )
            })
            .map(|(name, _)| name)
            .collect()
    }

    /// Returns whether at least one role is unsupported (T11.3 acceptance:
    /// at least one unsupported/missing role reported distinctly from
    /// authoritative `KnownEmpty`).
    #[must_use]
    pub fn has_unsupported_distinct_from_empty(&self) -> bool {
        !self.unsupported_role_names().is_empty()
    }
}

/// Borrow of the read owner; there is no separate context-input state owner.
pub struct GovernorContextInputs<'a, R: ?Sized> {
    reads: &'a R,
}

impl<'a, R: ?Sized> GovernorContextInputs<'a, R> {
    /// Borrows the Governor read owner without touching `composition.rs`.
    #[must_use]
    pub const fn borrow(reads: &'a R) -> Self {
        Self { reads }
    }
}

impl<R: ReadApi + ?Sized> GovernorContextInputs<'_, R> {
    /// Acquires the seven roles over one compatible read closure and exposes
    /// the reconstructed inputs.
    ///
    /// Per-role provider failures become per-role dispositions; only a bad
    /// request, a missing closure, or observed churn fails the whole call.
    ///
    /// The whole request is bounded: one read per role slot, no retry loop and
    /// no continuation field. Seven role slots are served by seven physical
    /// reads so each owner source retains its own operation identity.
    pub async fn reconstruct(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<SevenRoleInputs, ContextInputsError> {
        request.validate()?;
        ctx.validate().map_err(|error| {
            ContextInputsError::RequestInvalid(format!("request metadata: {error}"))
        })?;
        if request.dependency_revisions.is_empty() {
            return Err(ContextInputsError::MissingDependencies);
        }
        let heads_before = self.scope_heads(ctx, request).await?;
        // The declared order-head dependency of every role read is the exact
        // ordering-head set this reconstruction observed in its own closure
        // before acquisition (`#1144`). It is observed, never synthesized, and
        // a head bound to any other fence is refused by the read owner instead
        // of being carried as a live dependency.
        let ordering =
            ReadOrderingBinding::of(heads_before.ordering_heads.clone()).map_err(|error| {
                ContextInputsError::ClosureUnavailable(format!("closure order heads: {error}"))
            })?;
        let task_frame = self
            .acquire_state(
                ctx,
                request,
                &ordering,
                NamedReadOperation::GetTaskState,
                task_state_parameters(request)?,
                SelectorBinding {
                    key: "task_id",
                    expected: Some(&request.task_id),
                },
            )
            .await?;
        let attention = self
            .acquire_state(
                ctx,
                request,
                &ordering,
                NamedReadOperation::GetAttentionAndProblems,
                attention_parameters(request)?,
                SelectorBinding {
                    key: "problem_id",
                    expected: request.attention_problem_id.as_deref(),
                },
            )
            .await?;
        let (epistemic, epistemic_readback) =
            self.acquire_epistemic(ctx, request, &ordering).await?;
        let cue = self
            .acquire_projection_inputs(
                ctx,
                request,
                &ordering,
                ROLE_CUE_ACTIVATION,
                &request.projection_selector,
                request.projection_max_records,
            )
            .await?;
        let negative_memory = self
            .acquire_negative_memory(ctx, request, &ordering)
            .await?;
        let evidence = self.acquire_evidence(ctx, request, &ordering).await?;
        let affordances = self
            .acquire_capability_evidence(ctx, request, &ordering)
            .await?;
        let heads_after = self.scope_heads(ctx, request).await?;
        if heads_after != heads_before {
            return Err(ContextInputsError::SourceHeadsChanged);
        }
        Ok(SevenRoleInputs {
            scope_id: request.scope_id.clone(),
            state_fence: ctx.state_fence.clone(),
            clock: ctx.clock,
            heads_before,
            heads_after,
            task_frame,
            attention,
            epistemic,
            epistemic_readback,
            cue,
            negative_memory,
            evidence,
            affordances,
        })
    }

    async fn scope_heads(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
    ) -> Result<ScopeRevisionView, ContextInputsError> {
        let response = self
            .reads
            .bound_state(
                ctx,
                StateRequest {
                    operation: NamedReadOperation::GetScopeRevisionView,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    // The scope view read is itself the closure: it declares no
                    // order-head dependency because the closure it returns is
                    // what the order heads are.
                    ordering: ReadOrderingBinding::without_order_dependency(),
                    parameters: NamedParameters::new(),
                    provenance_handles: Vec::new(),
                },
            )
            .await
            .map_err(|error| {
                ContextInputsError::ClosureUnavailable(format!("scope heads: {error}"))
            })?;
        let heads: ScopeRevisionView =
            serde_json::from_value(response.view.payload).map_err(|error| {
                ContextInputsError::ClosureUnavailable(format!(
                    "scope heads payload is not a revision view: {error}"
                ))
            })?;
        heads.validate().map_err(|error| {
            ContextInputsError::ClosureUnavailable(format!("scope heads invalid: {error}"))
        })?;
        if heads.scope_id != request.scope_id || heads.state_fence != ctx.state_fence {
            return Err(ContextInputsError::ClosureUnavailable(
                "scope heads changed scope or fence".to_owned(),
            ));
        }
        Ok(heads)
    }

    /// Acquires one `ReadApi::state` role with its exact closed selectors.
    ///
    /// `parameters` is the catalogue's own selector set for `operation`, built
    /// from the owner-resolved request. `binding` names the selector the
    /// handler must echo back, so the response is bound to the requested
    /// operation, scope, selector and payload version before it becomes a
    /// disposition: a response answering a different task, problem or skill is
    /// `Unavailable` even when its operation and fence match.
    async fn acquire_state(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
        operation: NamedReadOperation,
        parameters: NamedParameters,
        binding: SelectorBinding<'_>,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        match self
            .reads
            .bound_state(
                ctx,
                StateRequest {
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => Ok(RoleAcquisition {
                operation,
                state: classify_role_envelope(&response.view.payload, &request.scope_id, binding),
                payload: Some(response.view.payload),
                revision_heads: response.view.revision_heads,
                identity: Some(response.identity),
                source_request: None,
                retained_capability_records: None,
                retained_negative_memory_records: None,
                retained_negative_memory_policies: None,
            }),
            Err(error) => Ok(failed_role(operation, classify_read_error(error)?)),
        }
    }

    /// Acquires the cue-activation role through the admitted
    /// `ContextReconstruction` query intent. Negative memory uses a distinct
    /// native activation-receipt read. The echoed `selector` binds this cue
    /// response to the exact source snapshot requested.
    async fn acquire_projection_inputs(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
        role: &'static str,
        selector: &str,
        max_records: u32,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let operation = NamedReadOperation::GetUnderstandingProjectionInputs;
        let parameters = projection_parameters(role, selector, max_records)?;
        match self
            .reads
            .bound_query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => Ok(RoleAcquisition {
                operation,
                state: classify_role_envelope(
                    &response.view.payload,
                    &request.scope_id,
                    SelectorBinding {
                        key: "selector",
                        expected: Some(selector),
                    },
                ),
                payload: Some(response.view.payload),
                revision_heads: response.view.revision_heads,
                identity: Some(response.identity),
                source_request: None,
                retained_capability_records: None,
                retained_negative_memory_records: None,
                retained_negative_memory_policies: None,
            }),
            Err(error) => Ok(failed_role(operation, classify_read_error(error)?)),
        }
    }

    /// Acquires the original negative-memory activation-receipt source using
    /// its native bounded Store read and the existing authenticated resolver.
    async fn acquire_negative_memory(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let max_records = u16::try_from(request.negative_memory_max_records).map_err(|_| {
            ContextInputsError::RequestRejected(
                "negative-memory page bound does not fit the Store contract".to_owned(),
            )
        })?;
        let named_request = learning_record_read_request(
            request.scope_id.clone(),
            Some(LearningRecordKind::ActivationReceipt),
            max_records,
            ctx.state_fence.clone(),
        );
        named_request.validate().map_err(|error| {
            ContextInputsError::RequestRejected(bounded_reason(
                "invalid negative-memory read",
                error,
            ))
        })?;
        let operation = NamedReadOperation::GetLearningRecordRange;
        let parameters =
            NamedParameters::from_map(named_request.parameters.clone()).map_err(|error| {
                ContextInputsError::RequestRejected(bounded_reason(
                    "invalid negative-memory selectors",
                    error,
                ))
            })?;
        let response = match self
            .reads
            .bound_query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(failed_role(operation, classify_read_error(error)?));
            }
        };
        let named_response = NamedReadResponse {
            operation: response.view.operation,
            state_fence: response.view.state_fence,
            revision_heads: response.view.revision_heads.clone(),
            payload: response.view.payload.clone(),
        };
        Ok(retain_negative_memory_response(
            named_request,
            &named_response,
            response.identity,
            &request.scope_id,
            &ctx.state_fence,
        ))
    }

    /// Acquires the original paged capability-evidence records. The read proves
    /// which records the Store retained; the projection owner still needs the
    /// exact observed route before it can call any record an authorized
    /// affordance.
    async fn acquire_capability_evidence(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let max_records = u16::try_from(request.affordance_max_records).map_err(|_| {
            ContextInputsError::RequestRejected(
                "capability evidence page bound does not fit the Store contract".to_owned(),
            )
        })?;
        let named_request = capability_evidence_read_request(
            request.scope_id.clone(),
            Some(request.affordance_skill_id.clone()),
            max_records,
            None,
            ctx.state_fence.clone(),
        );
        named_request.validate().map_err(|error| {
            ContextInputsError::RequestRejected(bounded_reason(
                "invalid capability evidence read",
                error,
            ))
        })?;
        let operation = NamedReadOperation::GetCapabilityEvidenceRecordRange;
        let parameters =
            NamedParameters::from_map(named_request.parameters.clone()).map_err(|error| {
                ContextInputsError::RequestRejected(bounded_reason(
                    "invalid capability evidence selectors",
                    error,
                ))
            })?;
        let response = match self
            .reads
            .bound_query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(failed_role(operation, classify_read_error(error)?));
            }
        };
        let (state, records) = classify_capability_evidence_payload(
            &response.view.payload,
            &request.scope_id,
            &ctx.state_fence,
            &request.affordance_skill_id,
            max_records,
        );
        Ok(RoleAcquisition {
            operation: response.view.operation,
            state,
            payload: Some(response.view.payload),
            revision_heads: response.view.revision_heads,
            identity: Some(response.identity),
            source_request: Some(named_request),
            retained_capability_records: records,
            retained_negative_memory_records: None,
            retained_negative_memory_policies: None,
        })
    }

    async fn acquire_epistemic(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
    ) -> Result<(RoleAcquisition, Option<EpistemicPositionReadback>), ContextInputsError> {
        let operation = NamedReadOperation::GetCurrentEpistemicPosition;
        let response = match self
            .reads
            .bound_query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters: NamedParameters::from_map(BTreeMap::from([(
                        "position".to_owned(),
                        Value::String(request.epistemic_position.clone()),
                    )]))
                    .map_err(|error| {
                        ContextInputsError::RequestRejected(bounded_reason(
                            "invalid epistemic selectors",
                            error,
                        ))
                    })?,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok((failed_role(operation, classify_read_error(error)?), None));
            }
        };
        let (state, readback) = decode_epistemic_payload(&response.view.payload);
        let payload = Some(response.view.payload);
        Ok((
            RoleAcquisition {
                operation: response.view.operation,
                state,
                payload,
                revision_heads: response.view.revision_heads,
                identity: Some(response.identity),
                source_request: None,
                retained_capability_records: None,
                retained_negative_memory_records: None,
                retained_negative_memory_policies: None,
            },
            readback,
        ))
    }

    async fn acquire_evidence(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        let operation = NamedReadOperation::GetEvidencePack;
        let response = match self
            .reads
            .bound_query(
                ctx,
                QueryRequest {
                    intent: reconstruction_intent(),
                    operation,
                    scope_id: Some(request.scope_id.clone()),
                    consistency: ReadConsistency::ExactFence,
                    dependency_revisions: request.dependency_revisions.clone(),
                    ordering: ordering.clone(),
                    parameters: NamedParameters::from_map(BTreeMap::from([
                        (
                            "subject".to_owned(),
                            Value::String(request.evidence_subject.clone()),
                        ),
                        (
                            "max_records".to_owned(),
                            Value::String(request.evidence_max_records.to_string()),
                        ),
                    ]))
                    .map_err(|error| {
                        ContextInputsError::RequestRejected(bounded_reason(
                            "invalid evidence selectors",
                            error,
                        ))
                    })?,
                    provenance_handles: Vec::new(),
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(failed_role(operation, classify_read_error(error)?));
            }
        };
        let state = classify_evidence_payload(
            &response.view.payload,
            &request.scope_id,
            &request.evidence_subject,
        );
        Ok(RoleAcquisition {
            operation: response.view.operation,
            state,
            payload: Some(response.view.payload),
            revision_heads: response.view.revision_heads,
            identity: Some(response.identity),
            source_request: None,
            retained_capability_records: None,
            retained_negative_memory_records: None,
            retained_negative_memory_policies: None,
        })
    }
}

fn retain_negative_memory_response(
    named_request: NamedReadRequest,
    named_response: &NamedReadResponse,
    identity: ReadIdentity,
    expected_scope: &ScopeId,
    expected_fence: &eliot_contracts::StateFence,
) -> RoleAcquisition {
    let operation = named_response.operation;
    let (state, records, policies) =
        match crate::resolve_negative_memory_rule_read(&named_request, &named_response) {
            Ok(resolved)
                if resolved.scope_id() == expected_scope
                    && eliot_contracts::fences_match_exact(
                        resolved.store_observed_fence(),
                        expected_fence,
                    ) =>
            {
                let records = Some(resolved.records().to_vec());
                let policies = Some(resolved.policies().to_vec());
                let state = if !resolved.enumeration_complete() {
                    ProjectionState::Partial {
                        reason: "native negative-memory page reports more retained records"
                            .to_owned(),
                    }
                } else if resolved.records().is_empty() {
                    ProjectionState::KnownEmpty
                } else {
                    ProjectionState::Complete
                };
                (state, records, policies)
            }
            Ok(_) => (
                ProjectionState::Stale {
                    reason: "negative-memory source changed scope or StateFence".to_owned(),
                },
                None,
                None,
            ),
            Err(error) => (
                ProjectionState::Unknown {
                    reason: bounded_reason("negative-memory owner rejected its source page", error),
                },
                None,
                None,
            ),
        };
    RoleAcquisition {
        operation,
        state,
        payload: Some(named_response.payload.clone()),
        revision_heads: named_response.revision_heads.clone(),
        identity: Some(identity),
        source_request: Some(named_request),
        retained_capability_records: None,
        retained_negative_memory_records: records,
        retained_negative_memory_policies: policies,
    }
}

/// Binds one role's response to the exact selector it was requested with.
///
/// Every task-bound owner handler echoes the selector it matched
/// (`task_id`, `problem_id`, `selector`, `skill_id`), so the echoed value is
/// the response's own proof of which source snapshot it answers. `expected:
/// None` requires the handler's exact null — the declared "no specific problem
/// requested" result of `GetAttentionAndProblems` — and never a substituted
/// identity.
#[derive(Clone, Copy, Debug)]
struct SelectorBinding<'a> {
    /// Payload member the owner handler echoes.
    key: &'static str,
    /// Exact value that member must carry for the requested selector.
    expected: Option<&'a str>,
}

/// Version used by Task, Attention, and Understanding owner envelopes in the
/// memory and Surreal adapters. A different version is `Unavailable`, never
/// coerced.
const ROLE_ENVELOPE_VERSION: u64 = 1;

/// Renders one explicit bound as the decimal string every owner handler parses.
///
/// The store catalogue declares `max_records` as text
/// ([`eliot_store_api::operation_parameters`]); a JSON number is refused
/// downstream, so the producer never emits one.
fn decimal_bound(max_records: u32) -> Value {
    Value::String(max_records.to_string())
}

/// Wraps one exact owner-resolved selector map as closed named selectors.
///
/// The map is the catalogue's own selector set for the read; the wrapper proves
/// the entries are bounded closed scalars and never a nested filter. A refusal
/// is a typed caller-shape rejection ([`ContextInputsError::RequestRejected`]),
/// not a role disposition.
fn closed_parameters(
    role: &'static str,
    parameters: BTreeMap<String, Value>,
) -> Result<NamedParameters, ContextInputsError> {
    NamedParameters::from_map(parameters)
        .map_err(|error| ContextInputsError::RequestRejected(bounded_reason(role, error)))
}

/// Builds the exact `GetTaskState` selector map (`task_id`, `max_records`).
fn task_state_parameters(
    request: &ContextReconstructionRequest,
) -> Result<NamedParameters, ContextInputsError> {
    closed_parameters(
        "invalid task frame selectors",
        BTreeMap::from([
            ("task_id".to_owned(), Value::String(request.task_id.clone())),
            (
                "max_records".to_owned(),
                decimal_bound(request.task_max_records),
            ),
        ]),
    )
}

/// Builds the exact `GetAttentionAndProblems` selector map.
///
/// `max_records` is always present; the optional `problem_id` key is OMITTED
/// entirely when no specific problem is requested, because the catalogue
/// declares it optional and a null value is not a closed selector.
fn attention_parameters(
    request: &ContextReconstructionRequest,
) -> Result<NamedParameters, ContextInputsError> {
    let mut parameters = BTreeMap::from([(
        "max_records".to_owned(),
        decimal_bound(request.attention_max_records),
    )]);
    if let Some(problem_id) = &request.attention_problem_id {
        parameters.insert("problem_id".to_owned(), Value::String(problem_id.clone()));
    }
    closed_parameters("invalid critical attention selectors", parameters)
}

/// Builds the exact `GetUnderstandingProjectionInputs` selector map
/// (`selector`, `max_records`) for one resolved source set.
fn projection_parameters(
    role: &'static str,
    selector: &str,
    max_records: u32,
) -> Result<NamedParameters, ContextInputsError> {
    closed_parameters(
        role,
        BTreeMap::from([
            ("selector".to_owned(), Value::String(selector.to_owned())),
            ("max_records".to_owned(), decimal_bound(max_records)),
        ]),
    )
}

/// Rejects a blank or control-bearing owner-resolved selector.
///
/// Applied before any read is planned so a caller that cannot resolve a
/// required identity gets a typed prerequisite failure instead of a request
/// that would only be refused downstream.
fn check_text_selector(field: &'static str, value: &str) -> Result<(), ContextInputsError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContextInputsError::RequestInvalid(format!(
            "{field} must be non-blank text"
        )));
    }
    Ok(())
}

/// Fixed explicit intent for every `ContextReconstruction` query.
///
/// Free-text dimensions stay data; the closed operation selects the source.
fn reconstruction_intent() -> QueryIntent {
    QueryIntent {
        mode: QueryMode::ContextReconstruction,
        time_scope: TimeScope::DeclaredFence,
        branch_environment_scope: BranchEnvironmentScope::RequestScope,
        freshness_policy: FreshnessPolicy::ExactFence,
        required_assurance: RequiredAssurance::InputReconstructionOnly,
    }
}

/// Builds a bounded, control-character-free reason for a disposition.
fn bounded_reason(prefix: &'static str, detail: impl std::fmt::Display) -> String {
    let mut reason = format!("{prefix}: {detail}");
    reason = reason
        .chars()
        .map(|cell| if cell.is_control() { ' ' } else { cell })
        .collect();
    let trimmed = reason.trim().to_owned();
    let reason = if trimmed.is_empty() {
        prefix.to_owned()
    } else {
        trimmed
    };
    if reason.len() > 240 {
        // Reasons are bounded role metadata; truncation keeps the envelope
        // bounded while the full provider error stays in the read path.
        let mut end = 240;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &reason[..end])
    } else {
        reason
    }
}

/// Maps a read failure to a role disposition.
///
/// Provider failures (`Store`, unsupported operation for this facade,
/// churn/staleness, blocked evaluation) become dispositions — never
/// `KnownEmpty`. Caller-shape rejections are programming errors and abort
/// the whole reconstruction instead of masquerading as a role outcome.
fn classify_read_error(error: ReadError) -> Result<ProjectionState, ContextInputsError> {
    match error {
        ReadError::Store(detail) => Ok(ProjectionState::Unavailable {
            reason: bounded_reason("store read failed", detail),
        }),
        ReadError::Outcome(outcome) => Ok(classify_read_outcome(outcome)),
        ReadError::OperationNotAllowed { operation, context } => Ok(ProjectionState::Unavailable {
            reason: bounded_reason(
                "operation not supported for input reconstruction",
                format!("{operation:?} for {context}"),
            ),
        }),
        ReadError::InvalidIntentOperation { operation, mode } => Ok(ProjectionState::Unavailable {
            reason: bounded_reason(
                "operation does not support this query mode",
                format!("{operation:?} for {mode:?}"),
            ),
        }),
        ReadError::ResponseMismatch => Ok(ProjectionState::Stale {
            reason: "named read response changed operation or fence".to_owned(),
        }),
        ReadError::RevisionChurn => Ok(ProjectionState::Stale {
            reason: "dependency revisions changed during the read".to_owned(),
        }),
        ReadError::StaleRevision => Ok(ProjectionState::Stale {
            reason: "read response is behind the declared minimum revision".to_owned(),
        }),
        ReadError::MissingDependencies => Ok(ProjectionState::Blocked {
            reason: "read consistency requires dependency revisions".to_owned(),
        }),
        ReadError::ScopeRequired => Ok(ProjectionState::Blocked {
            reason: "read operation requires a scope".to_owned(),
        }),
        ReadError::MissingIntent => Ok(ProjectionState::Blocked {
            reason: "broad read omitted its required intent".to_owned(),
        }),
        ReadError::InvalidField { field, reason } => Err(ContextInputsError::RequestRejected(
            bounded_reason("invalid read field", format!("{field}: {reason}")),
        )),
        ReadError::EmptyField(field) => Err(ContextInputsError::RequestRejected(bounded_reason(
            "empty read field",
            field,
        ))),
        ReadError::DuplicateField(field) => Err(ContextInputsError::RequestRejected(
            bounded_reason("duplicate read field", field),
        )),
        ReadError::InvalidResourceUri => Err(ContextInputsError::RequestRejected(
            "invalid exact resource URI".to_owned(),
        )),
        ReadError::InvalidDependencyRevision => Err(ContextInputsError::RequestRejected(
            "invalid dependency revision".to_owned(),
        )),
        ReadError::OrderingIdentityMismatch { declared } => Ok(ProjectionState::Blocked {
            reason: bounded_reason(
                "declared order heads do not carry the read's exact fence",
                format!("{declared} heads"),
            ),
        }),
    }
}

/// Maps the read owner's closed non-current observation onto one role
/// disposition (`#1144`, A5).
///
/// The mapping is total over [`ReadOutcome`], so no state is silently dropped
/// and no two distinct read outcomes collapse into one disposition. Crucially,
/// none of them becomes `KnownEmpty`: a source that is not running, an answer
/// that does not observe the bound identity, and a source-declared truncated
/// coverage are three different facts, and a read that produced none of them
/// did not produce an empty projection.
fn classify_read_outcome(outcome: ReadOutcome) -> ProjectionState {
    match outcome {
        ReadOutcome::Current | ReadOutcome::NotApplicable => ProjectionState::Unknown {
            reason: bounded_reason(
                "current read reported no observation",
                format!("{outcome:?}"),
            ),
        },
        ReadOutcome::NotRunning => ProjectionState::Unavailable {
            reason: "named source has no activated store handler".to_owned(),
        },
        ReadOutcome::Unavailable => ProjectionState::Unavailable {
            reason: "admitted source could not be reached".to_owned(),
        },
        ReadOutcome::Unknown => ProjectionState::Unknown {
            reason: "answer does not observe the bound read identity".to_owned(),
        },
        // A source that authoritatively states the requested subject is absent
        // is `Missing`, which is exactly what this disposition names, and it is
        // reported distinctly from `KnownEmpty` (an empty *result* set) and from
        // `Unavailable` (a source that could not be read at all). It is not
        // `Unknown`: the source did describe its absence, so this is evidence,
        // not an absence of evidence.
        ReadOutcome::Missing => ProjectionState::Missing,
        ReadOutcome::Stale => ProjectionState::Stale {
            reason: "answer belongs to another revision, order or fence identity".to_owned(),
        },
        ReadOutcome::Conflicted => ProjectionState::Stale {
            reason: "bound closure moved during acquisition".to_owned(),
        },
        ReadOutcome::Partial => ProjectionState::Partial {
            reason: "source-declared coverage proves a bounded subset".to_owned(),
        },
    }
}

/// What one role page's own provenance says about the records it returned.
///
/// The three declared counts are the ONLY evidence a page has about the extent
/// of its source, so they are read as one tuple and judged together. `Empty`,
/// `Complete` and `Truncated` each name a page that describes itself
/// coherently; `Undescribed` names a page that does not, whether the counts are
/// absent, mistyped, or contradict the array the page actually carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RolePage {
    /// An authoritative completed lookup that matched no rows and returned none.
    Empty,
    /// An authoritative completed lookup that returned every matched row.
    Complete,
    /// A coherent bounded page: the source matched strictly more rows than the
    /// declared bound returned.
    Truncated,
    /// The declared counts are absent, mistyped, or contradict the records.
    Undescribed,
}

/// The one shared role-page provenance rule for every reconstructed role.
///
/// Every `ProjectionState` a role may take other than `Unavailable`/`Stale`/
/// `Unknown` from the read itself is read off this verdict, so a role page is
/// judged by exactly one function and the task-bound envelopes and the evidence
/// pack cannot drift into two different notions of a bounded partial page.
/// #2857: the previous shape accepted EVERY `(truncated = true, …)` tuple as a
/// bounded partial scan, so a page with one record and `returned = 50`, or a
/// `truncated: true` with neither count present, was trusted. A truncation flag
/// is a claim about the OTHER two counts, so it is only honoured when the whole
/// tuple is coherent:
///
/// 1. all three of `truncated`, `matched_total` and `returned` are present and
///    correctly typed (a JSON number-as-string, a float, a negative or a missing
///    member is `Undescribed`);
/// 2. `returned == records.len()` — the declared count is the array that
///    actually travelled;
/// 3. `matched_total >= returned` — a page cannot return more than it matched;
/// 4. `truncated == (matched_total > returned)` — the flag is exactly the
///    statement that the source holds rows this bound did not return.
///
/// Every failure is `Undescribed`, which the callers report as `Unknown`. A
/// coherent zero-row page is the only `KnownEmpty`; a coherent page that
/// returned every matched row is the only `Complete`; a coherent bounded page is
/// the only `Partial`.
fn classify_role_page(records: &[Value], provenance: Option<&Value>) -> RolePage {
    let read_count = |key: &str| {
        provenance
            .and_then(|provenance| provenance.get(key))
            .and_then(Value::as_u64)
    };
    let (Some(truncated), Some(matched), Some(returned)) = (
        provenance
            .and_then(|provenance| provenance.get("truncated"))
            .and_then(Value::as_bool),
        read_count("matched_total"),
        read_count("returned"),
    ) else {
        return RolePage::Undescribed;
    };
    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    if returned != count || matched < returned || truncated != (matched > returned) {
        return RolePage::Undescribed;
    }
    if matched == 0 {
        return RolePage::Empty;
    }
    if truncated {
        RolePage::Truncated
    } else {
        RolePage::Complete
    }
}

/// Classifies one task-bound role payload against the exact selector it answers.
///
/// The three activated handlers return a versioned source envelope
/// (`{version, <selector>, scope_id, records, provenance}`) over retained
/// authority records — not an admitted Cue array, a qualified capability view or
/// a ready packet. A successful retrieval is therefore bound but not promoted.
///
/// `KnownEmpty` requires an authoritative completed lookup for the REQUESTED
/// selector: zero records with `truncated: false` and matching totals. A bound
/// the store truncated is `Partial`, records whose declared counts are absent or
/// contradict the records are `Unknown`, and a substituted scope, selector or
/// payload version is `Unavailable` — a matching operation and fence are never
/// enough. The extent judgement itself is
/// [`classify_role_page`], shared with the evidence pack.
fn classify_role_envelope(
    payload: &Value,
    scope: &ScopeId,
    binding: SelectorBinding<'_>,
) -> ProjectionState {
    let unavailable = |detail: &str| ProjectionState::Unavailable {
        reason: bounded_reason("role payload fails its contract", detail),
    };
    if payload.get("version").and_then(Value::as_u64) != Some(ROLE_ENVELOPE_VERSION) {
        return unavailable("unsupported role payload version");
    }
    if payload.get("scope_id").and_then(Value::as_str) != Some(scope.as_str()) {
        return unavailable("role scope mismatch");
    }
    match (payload.get(binding.key), binding.expected) {
        (Some(echoed), Some(expected)) if echoed.as_str() == Some(expected) => {}
        (Some(Value::Null), None) => {}
        _ => return unavailable("role selector mismatch"),
    }
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return unavailable("role payload has no records array");
    };
    match classify_role_page(records, payload.get("provenance")) {
        RolePage::Empty => ProjectionState::KnownEmpty,
        RolePage::Complete => ProjectionState::Complete,
        RolePage::Truncated => ProjectionState::Partial {
            reason: "role payload truncated at the declared bound".to_owned(),
        },
        RolePage::Undescribed => ProjectionState::Unknown {
            reason: "role provenance does not authoritatively describe the records".to_owned(),
        },
    }
}

/// Decodes the current-position payload into the T11.2 readback shape.
///
/// `None` from a successful read is an authoritative empty positions view.
/// A non-committed or undecodable payload is `Unavailable`, never empty and
/// never promoted: only an external receipt proves an admitted position.
fn decode_epistemic_payload(
    payload: &Value,
) -> (ProjectionState, Option<EpistemicPositionReadback>) {
    let readback: Option<EpistemicPositionReadback> = match serde_json::from_value(payload.clone())
    {
        Ok(value) => value,
        Err(error) => {
            return (
                ProjectionState::Unavailable {
                    reason: bounded_reason("position payload is not a readback", error),
                },
                None,
            );
        }
    };
    match readback {
        None => (ProjectionState::KnownEmpty, None),
        Some(readback) if readback.receipt.status != WriteReceiptStatus::Committed => (
            ProjectionState::Unavailable {
                reason: "position readback carries no committed receipt".to_owned(),
            },
            None,
        ),
        Some(readback) => (ProjectionState::Complete, Some(readback)),
    }
}

/// Classifies an evidence-pack payload against its authoritative provenance.
///
/// `KnownEmpty` requires the exact empty result: zero records with an
/// explicit `truncated: false` and matching totals. A truncated pack is
/// `Partial`; a payload whose provenance does not describe its records is
/// `Unknown`. Transport and catalogue failures never reach this function. The
/// extent judgement is [`classify_role_page`], the same shared rule the
/// task-bound role envelopes use, so the two payload families cannot disagree
/// about what a bounded partial page is.
fn classify_evidence_payload(payload: &Value, scope: &ScopeId, subject: &str) -> ProjectionState {
    let unavailable = |detail: &str| ProjectionState::Unavailable {
        reason: bounded_reason("evidence payload fails its contract", detail),
    };
    if payload.get("version").and_then(Value::as_u64) != Some(1) {
        return unavailable("unsupported evidence pack version");
    }
    if payload.get("subject").and_then(Value::as_str) != Some(subject) {
        return unavailable("evidence subject mismatch");
    }
    if payload.get("scope_id").and_then(Value::as_str) != Some(scope.as_str()) {
        return unavailable("evidence scope mismatch");
    }
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return unavailable("evidence payload has no records array");
    };
    match classify_role_page(records, payload.get("provenance")) {
        RolePage::Empty => ProjectionState::KnownEmpty,
        RolePage::Complete => ProjectionState::Complete,
        RolePage::Truncated => ProjectionState::Partial {
            reason: "evidence pack truncated at the declared bound".to_owned(),
        },
        RolePage::Undescribed => ProjectionState::Unknown {
            reason: "evidence provenance does not authoritatively describe the records".to_owned(),
        },
    }
}

#[cfg(test)]
mod reconstruction_tests {
    use super::*;
    use eliot_read::StoreReadFailure;

    type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn request_validation_rejects_blank_selectors_and_over_bound() -> ProofResult {
        let request = valid_request()?;
        request.validate()?;
        let mut blank = request.clone();
        blank.epistemic_position = "   ".to_owned();
        assert!(blank.validate().is_err());
        let mut blank_subject = request.clone();
        blank_subject.evidence_subject = "\t".to_owned();
        assert!(blank_subject.validate().is_err());
        let mut over_bound = request.clone();
        over_bound.evidence_max_records = EVIDENCE_PACK_MAX_RECORDS + 1;
        assert!(over_bound.validate().is_err());
        let mut zero_bound = request.clone();
        zero_bound.evidence_max_records = 0;
        assert!(zero_bound.validate().is_err());
        let mut zero_revision = request;
        zero_revision
            .dependency_revisions
            .insert(RevisionKey::new("scope:scope-a")?, 0);
        assert!(zero_revision.validate().is_err());
        Ok(())
    }

    #[test]
    fn store_and_churn_failures_are_never_empty() -> ProofResult {
        let unavailable =
            classify_read_error(ReadError::Store(StoreReadFailure::UnknownOperation))?;
        assert!(matches!(unavailable, ProjectionState::Unavailable { .. }));
        let stale = classify_read_error(ReadError::RevisionChurn)?;
        assert!(matches!(stale, ProjectionState::Stale { .. }));
        let blocked = classify_read_error(ReadError::MissingDependencies)?;
        assert!(matches!(blocked, ProjectionState::Blocked { .. }));
        // Caller-shape rejections abort instead of becoming dispositions.
        assert!(
            classify_read_error(ReadError::EmptyField("parameters.position".to_owned())).is_err()
        );
        Ok(())
    }

    #[test]
    fn evidence_classifier_requires_authoritative_emptiness() -> ProofResult {
        let scope = ScopeId::new("scope-a")?;
        let empty = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        assert_eq!(
            classify_evidence_payload(&empty, &scope, "subject-a"),
            ProjectionState::KnownEmpty
        );
        // Same zero records, but the truncation flag is authoritative: a
        // truncated empty page is partial, not empty.
        let truncated_empty = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 4, "returned": 0, "truncated": true},
        });
        assert!(matches!(
            classify_evidence_payload(&truncated_empty, &scope, "subject-a"),
            ProjectionState::Partial { .. }
        ));
        // Records without a describing provenance are unknown, never empty.
        let undescribed = serde_json::json!({
            "version": 1,
            "subject": "subject-a",
            "scope_id": "scope-a",
            "records": [],
        });
        assert!(matches!(
            classify_evidence_payload(&undescribed, &scope, "subject-a"),
            ProjectionState::Unknown { .. }
        ));
        // A substituted subject fails the contract instead of completing.
        let substituted = serde_json::json!({
            "version": 1,
            "subject": "subject-b",
            "scope_id": "scope-a",
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        assert!(matches!(
            classify_evidence_payload(&substituted, &scope, "subject-a"),
            ProjectionState::Unavailable { .. }
        ));
        Ok(())
    }

    #[test]
    fn unsupported_roles_report_distinctly_from_known_empty() -> ProofResult {
        let inputs = SevenRoleInputs {
            scope_id: ScopeId::new("scope-a")?,
            state_fence: test_fence()?,
            clock: ClockReading::default(),
            heads_before: test_heads("scope-a")?,
            heads_after: test_heads("scope-a")?,
            task_frame: unavailable_role(NamedReadOperation::GetTaskState),
            attention: unavailable_role(NamedReadOperation::GetAttentionAndProblems),
            epistemic: RoleAcquisition {
                operation: NamedReadOperation::GetCurrentEpistemicPosition,
                state: ProjectionState::KnownEmpty,
                payload: Some(Value::Null),
                revision_heads: Vec::new(),
                identity: None,
                source_request: None,
                retained_capability_records: None,
                retained_negative_memory_records: None,
                retained_negative_memory_policies: None,
            },
            epistemic_readback: None,
            cue: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            negative_memory: unavailable_role(NamedReadOperation::GetLearningRecordRange),
            evidence: RoleAcquisition {
                operation: NamedReadOperation::GetEvidencePack,
                state: ProjectionState::Complete,
                payload: Some(serde_json::json!({"records": []})),
                revision_heads: Vec::new(),
                identity: None,
                source_request: None,
                retained_capability_records: None,
                retained_negative_memory_records: None,
                retained_negative_memory_policies: None,
            },
            affordances: unavailable_role(NamedReadOperation::GetCapabilityEvidenceRecordRange),
        };
        let unsupported = inputs.unsupported_role_names();
        assert!(unsupported.contains(&ROLE_TASK_FRAME));
        assert!(unsupported.contains(&ROLE_CUE_ACTIVATION));
        assert!(unsupported.contains(&ROLE_AFFORDANCES));
        assert!(!unsupported.contains(&ROLE_EPISTEMIC_POSITION));
        assert!(!unsupported.contains(&ROLE_EVIDENCE_ASSURANCE));
        assert!(inputs.has_unsupported_distinct_from_empty());
        Ok(())
    }

    fn valid_request() -> ProofResult<ContextReconstructionRequest> {
        let mut dependency_revisions = BTreeMap::new();
        dependency_revisions.insert(RevisionKey::new("scope:scope-a")?, 1);
        Ok(ContextReconstructionRequest {
            scope_id: ScopeId::new("scope-a")?,
            dependency_revisions,
            epistemic_position: "position-a".to_owned(),
            evidence_subject: "subject-a".to_owned(),
            evidence_max_records: 8,
            task_id: "task-a".to_owned(),
            task_max_records: 8,
            attention_problem_id: Some("problem-a".to_owned()),
            attention_max_records: 8,
            projection_selector: "selector-a".to_owned(),
            projection_max_records: 8,
            negative_memory_selector: LearningRecordKind::ActivationReceipt.as_str().to_owned(),
            negative_memory_max_records: 8,
            affordance_skill_id: "skill-a".to_owned(),
            affordance_max_records: 8,
        })
    }

    fn unavailable_role(operation: NamedReadOperation) -> RoleAcquisition {
        RoleAcquisition {
            operation,
            state: ProjectionState::Unavailable {
                reason: "store read failed: unknown operation".to_owned(),
            },
            payload: None,
            revision_heads: Vec::new(),
            identity: None,
            source_request: None,
            retained_capability_records: None,
            retained_negative_memory_records: None,
            retained_negative_memory_policies: None,
        }
    }

    fn test_fence() -> ProofResult<eliot_contracts::StateFence> {
        use std::num::NonZeroU64;
        let lineage = eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
        let epoch = eliot_contracts::EpochId::new(
            lineage,
            NonZeroU64::new(1).ok_or(eliot_store_api::StoreError::InvalidField {
                field: "test.sequence",
                reason: "must be non-zero",
            })?,
        )?;
        Ok(eliot_contracts::StateFence::new(
            epoch,
            eliot_contracts::ResourceGeneration::genesis(),
        ))
    }

    fn test_heads(scope: &str) -> ProofResult<ScopeRevisionView> {
        let fence = test_fence()?;
        let view = ScopeRevisionView {
            scope_id: ScopeId::new(scope)?,
            revision_heads: vec![RevisionHead {
                key: RevisionKey::new(format!("scope:{scope}"))?,
                revision: 1,
                state_fence: fence.clone(),
            }],
            ordering_heads: Vec::new(),
            state_fence: fence,
        };
        view.validate()?;
        Ok(view)
    }
}
