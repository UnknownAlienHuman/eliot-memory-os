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
//! | Negative memory | `GetUnderstandingProjectionInputs` (negative-memory interpretation) | same query |
//! | Evidence/source assurance | `GetEvidencePack` | `ReadApi::query` with `QueryMode::ContextReconstruction` |
//! | Affordances | `GetCapabilityEvidenceState` | `ReadApi::state` |
//!
//! The query facade only admits `GetEvidencePack`,
//! `GetUnderstandingProjectionInputs`, and `GetCurrentEpistemicPosition` for
//! `QueryMode::ContextReconstruction` (`eliot_read` intent table); the three
//! state-only roles go through `ReadApi::state` under the same fence and
//! dependency closure instead of failing the intent gate. Every read uses
//! `ReadConsistency::ExactFence` with caller-supplied dependency revisions.
//!
//! Selector discipline: every role carries the exact closed selector set the
//! store catalogue declares for its read (issue #2563). The four task-bound
//! reads are activated in both owner adapters
//! (`eliot_store_memory::{task_state_payload, attention_problems_payload,
//! understanding_inputs_payload, capability_evidence_payload}` and their
//! Surreal twins), so the three repaired reads and the affordances role now
//! reach real handlers instead of resolving to per-role `Unavailable`. The
//! request carries no caller-selected scope override, no fabricated `all`
//! selector and no empty default: a missing required selector is refused by
//! [`ContextInputsError::RequestInvalid`] before any read is planned.
//!
//! Closure discipline (T11.md:77): the dependency heads (`ScopeRevisionView`)
//! are captured before acquisition and re-read afterwards; bounded churn
//! fails closed as [`ContextInputsError::SourceHeadsChanged`] rather than
//! exposing a silently mixed snapshot. The whole reconstruction is bounded to
//! one read per role slot (six physical reads, seven slots when the cue and
//! negative-memory slots deliberately share one source snapshot); there is no
//! retry loop and no continuation field here — #1729 owns broader coherent
//! assembly.
//!
//! Disposition discipline (`eliot_context_candidates::ProjectionState`):
//! `KnownEmpty` requires an authoritative completed lookup (an explicit empty
//! result with an exact truncation/coverage statement). Transport failure,
//! an unactivated (known-but-unsupported) operation, and a bounded partial
//! scan are reported as `Unavailable`/`Unknown`/`Partial` — never as empty.
//! Each role response is bound to the requested operation, scope, selector and
//! payload version before it becomes a disposition, so a response answering a
//! different task/problem/skill/position is never adopted just because its
//! operation and fence match. The four task-bound envelopes echo their
//! selector as an envelope member ([`classify_role_envelope`]); the evidence
//! pack echoes `subject` and `scope_id` ([`classify_evidence_payload`]); the
//! position read is not a selector envelope, so it is bound against the identity
//! it carries itself — its own `EPISTEMIC_REVISION_SCHEMA`, the scope its
//! candidate and transition carry, and the position its transition and every
//! admitted row name ([`bind_position_payload`]).
//!
//! Content discipline: that binding decides the disposition AND whether the
//! response's records are admissible. Only a response whose version, scope,
//! selector and page provenance were all proved against the request keeps its
//! records ([`admits_source_records`]); a refused or undescribed response keeps
//! no records, no read identity and no observed heads, so no caller and no
//! serialization can adopt a foreign or contract-invalid envelope. The state
//! word is never a label on bytes that are still travelling.
//!
//! Page-provenance discipline (#2857): one shared rule
//! ([`classify_role_page`]) judges every role page's declared extent, so a
//! bounded partial page is only ever `Partial` when its three declared counts
//! are present, correctly typed, and coherent with the records that travelled
//! (`returned == records.len()`, `matched_total >= returned`, and
//! `truncated == (matched_total > returned)`). Absent or contradictory counts
//! are `Unknown` — a truncation flag on its own is a claim about the other two
//! counts and never promotes a page on its own.
//!
//! Downstream limit, kept explicit: a successful retrieval of a versioned
//! source envelope is NOT proof of Cue admission, capability qualification or
//! packet readiness. The four handlers return retained authority-record
//! envelopes (`{version, <selector>, scope_id, records, provenance}`), not
//! admitted Cue arrays or qualified capability; binding those envelopes to the
//! typed cue families and to #1773's capability work is a separate slice.
//!
//! Committed Problem readback (issue #1759 I2 readback, I13.9): when — and only
//! when — the request names an exact `attention_problem_id`, the attention
//! role's page is decoded into the canonical [`ProblemReadback`] carried on
//! [`SevenRoleInputs::problem_readback`]. It adds no read, no store operation and
//! no second Problem model: the record is the `record_json` of committed
//! `ApplyProblemOwnerState` transitions that same page already returns, decoded
//! through the store's own `decode_problem_owner_state_mutation` and validated by
//! the Problem model. It is a read model, not a receipt — it closes nothing,
//! promotes nothing and grants no repair — and a page that does not decode to one
//! Problem's ordered committed history is a typed
//! [`ContextInputsError::AttentionPageUndecodable`], never a partial readback.

use std::collections::BTreeMap;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{ClockReading, RequestMetadata};
use eliot_read::{
    BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode, QueryRequest,
    ReadApi, ReadError, ReadIdentity, ReadOrderingBinding, ReadOutcome, RequiredAssurance,
    StateRequest, TimeScope,
};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency, RevisionHead, RevisionKey,
    ScopeId, ScopeRevisionView, WriteReceiptStatus,
    epistemic_revision::{EPISTEMIC_REVISION_SCHEMA, EpistemicPositionReadback},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::problem_read_site::{ProblemReadback, ProblemReadbackError, read_committed_problem};

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
    /// The read owner's declared surface did not resolve, so this
    /// reconstruction cannot claim which Store dependencies the owner behind
    /// it actually has.
    ///
    /// This is not a per-role disposition and not an empty result: it is the
    /// owner's own completeness check refusing to serve a read whose declared
    /// surface it cannot resolve. The caller resolves
    /// `eliot_read::owner_inventory::read_owner_inventory()` before
    /// acquisition, and a Store dependency this crate imports with no declared
    /// row — or a declared row naming a dependency it no longer imports —
    /// surfaces here by name instead of passing as a complete inventory.
    #[error("read owner declared surface did not resolve: {0}")]
    ReadOwnerSurfaceUnresolved(String),
    /// A role request was rejected for a caller-shape reason (not a provider
    /// outcome); this is a programming error, never a role disposition.
    #[error("context reconstruction role request was rejected: {0}")]
    RequestRejected(String),
    /// A role in the reconstructed closure carries source content its own
    /// disposition does not admit, so the closure cannot be exposed.
    ///
    /// This is the structural content invariant ([`admits_source_records`])
    /// stated once for all seven slots. It is unreachable while every role is
    /// built by [`RoleAcquisition::from_response`]; it exists so a future
    /// classifier change is refused at the read boundary instead of silently
    /// publishing records for a state that does not admit them.
    #[error("context reconstruction role content is not admitted by its state: {0}")]
    ContentNotAdmitted(String),
    /// The `GetAttentionAndProblems` page the attention role returned is not a
    /// decodable, ordered history of canonical Problem revisions, so no committed
    /// Problem can be read back from it.
    ///
    /// This is neither a per-role disposition nor an empty result: a page that
    /// does not decode is a defect in what was read, and serving a spliced or
    /// partial history from it would present a record that was never committed.
    #[error(transparent)]
    AttentionPageUndecodable(#[from] ProblemReadbackError),
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
/// | `negative_memory_selector`, `negative_memory_max_records` | `GetUnderstandingProjectionInputs` (negative memory) | `selector`, `max_records` |
/// | `affordance_skill_id`, `affordance_max_records` | `GetCapabilityEvidenceState` | `skill_id`, `max_records` |
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
    /// Exact source selector for the negative-memory projection (`selector`).
    ///
    /// Resolved separately from the cue selector because the two roles may
    /// address different source sets. It is a required member, never a
    /// default: when it equals the cue selector (and the cue bound) both roles
    /// deliberately address one exact source snapshot and a single response may
    /// serve both slots.
    pub negative_memory_selector: String,
    /// Explicit negative-memory-projection bound
    /// (`1..=EVIDENCE_PACK_MAX_RECORDS`).
    pub negative_memory_max_records: u32,
    /// Exact skill identity for the affordances read (`skill_id`).
    pub affordance_skill_id: String,
    /// Explicit capability-evidence bound (`1..=EVIDENCE_PACK_MAX_RECORDS`).
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
        check_text_selector("epistemic_position", &self.epistemic_position)?;
        check_text_selector("evidence_subject", &self.evidence_subject)?;
        check_text_selector("task_id", &self.task_id)?;
        check_text_selector("projection_selector", &self.projection_selector)?;
        check_text_selector("negative_memory_selector", &self.negative_memory_selector)?;
        check_text_selector("affordance_skill_id", &self.affordance_skill_id)?;
        if let Some(problem_id) = &self.attention_problem_id {
            check_text_selector("attention_problem_id", problem_id)?;
        }
        for (field, bound) in [
            ("evidence_max_records", self.evidence_max_records),
            ("task_max_records", self.task_max_records),
            ("attention_max_records", self.attention_max_records),
            ("projection_max_records", self.projection_max_records),
            (
                "negative_memory_max_records",
                self.negative_memory_max_records,
            ),
            ("affordance_max_records", self.affordance_max_records),
        ] {
            if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
                return Err(ContextInputsError::RequestInvalid(format!(
                    "{field} must be within 1..=EVIDENCE_PACK_MAX_RECORDS"
                )));
            }
        }
        Ok(())
    }
}

/// One acquired role: its disposition, and the source records that disposition
/// admits.
///
/// The fields are never assembled independently of each other: every role is
/// built by [`RoleAcquisition::from_response`], so one classification decides
/// the disposition, the payload, the identity and the observed heads together.
///
/// * `Complete`, `KnownEmpty` and `Partial` admit the validated envelope: an
///   exact version/scope/selector binding with a coherent page-provenance
///   tuple, carried whole (`Partial` is the bounded real prefix its consumers
///   read).
/// * Every other state — a version/scope/selector/shape mismatch, undescribed
///   or contradictory provenance, `Unknown`, `Unavailable`, `Stale`, `Blocked`,
///   `Missing`, or any transport failure — admits nothing. A refused envelope
///   describes another request's source snapshot, so carrying its bytes (or the
///   identity that binds them) would adopt it at the public read boundary
///   (I1.8's exact named-read capability). Its typed reason stays in `state`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAcquisition {
    /// Closed named operation that produced (or refused) this role.
    pub operation: NamedReadOperation,
    /// Completeness state of this role (`inputs.rs:188-282` vocabulary).
    pub state: ProjectionState,
    /// Opaque payload of the validated envelope; present exactly when
    /// [`admits_source_records`] holds for `state`, and `None` otherwise.
    pub payload: Option<Value>,
    /// Revision heads observed with this role's read; empty exactly when
    /// `payload` is `None`.
    pub revision_heads: Vec<RevisionHead>,
    /// Exact read identity this role is bound to (`#1144` retained-read
    /// binding): principal, scope, fence, consistency, declared and observed
    /// heads, order heads, source, projection schema, coverage and the exact
    /// invalidation conditions. Present exactly when the role retains its
    /// validated envelope, so a retained role can always be revalidated from
    /// its own record instead of re-deriving freshness from the payload, and
    /// an identity that binds a refused payload is never presented as the
    /// identity of an accepted role.
    pub identity: Option<ReadIdentity>,
}

impl RoleAcquisition {
    /// Builds one acquired role from a successful transport response whose
    /// content this classification admits.
    ///
    /// This is the single construction site a successful role uses, so the
    /// disposition and the retention of bytes cannot drift apart: a
    /// non-content-bearing state stores no payload, no identity and no heads.
    fn from_response(
        operation: NamedReadOperation,
        state: ProjectionState,
        payload: Value,
        revision_heads: Vec<RevisionHead>,
        identity: ReadIdentity,
    ) -> Self {
        let (payload, revision_heads) = admitted_envelope(&state, payload, revision_heads);
        let identity = admits_source_records(&state).then_some(identity);
        Self {
            operation,
            state,
            payload,
            revision_heads,
            identity,
        }
    }

    /// Builds one acquired role for a failed read, which by definition retains
    /// nothing: the read produced no envelope to bind.
    fn from_failure(operation: NamedReadOperation, state: ProjectionState) -> Self {
        Self {
            operation,
            state,
            payload: None,
            revision_heads: Vec::new(),
            identity: None,
        }
    }
}

/// Retains one successful response's source records only when its
/// classification admits them, and drops them otherwise.
///
/// This is the one retention rule every acquisition site shares, so the
/// disposition and the stored bytes cannot disagree: a response the classifier
/// refused contributes no payload and no observed heads to the role it becomes.
/// Its typed reason stays in the role's [`ProjectionState`].
fn admitted_envelope(
    state: &ProjectionState,
    payload: Value,
    revision_heads: Vec<RevisionHead>,
) -> (Option<Value>, Vec<RevisionHead>) {
    if admits_source_records(state) {
        (Some(payload), revision_heads)
    } else {
        (None, Vec::new())
    }
}

/// Whether one classified role disposition admits the source records that
/// travelled with it.
///
/// The rule is the exact binding this reconstruction asked for, read by
/// [`classify_role_page`]:
///
/// - `Complete` — an authoritative completed lookup whose page describes every
///   matched row;
/// - `KnownEmpty` — the same completed lookup that authoritatively matched no
///   row;
/// - `Partial` — a coherent bounded page: the exact-selector prefix of the rows
///   the source holds. It is real evidence, so it is retained whole and its
///   consumers (`problem_read_site::read_committed_problem`) read it as a
///   labelled prefix rather than dropping it.
///
/// Everything else is non-content-bearing: a version/scope/selector/shape
/// mismatch or undescribed provenance (`Unavailable`, `Unknown`), a read that
/// never observed this fence (`Stale`), a blocked or unsupplied one
/// (`Blocked`, `Missing`), or a transport failure. None of those states may
/// carry raw records, and none may be paired with the identity and observed
/// heads of a rejected envelope.
fn admits_source_records(state: &ProjectionState) -> bool {
    matches!(
        state,
        ProjectionState::Complete | ProjectionState::KnownEmpty | ProjectionState::Partial { .. }
    )
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
    /// The committed canonical Problem read back from the attention role for the
    /// requested `attention_problem_id` (issue #1759 I2 readback, I13.9).
    ///
    /// `None` is an honest outcome, not a missing read: no specific Problem was
    /// requested, the attention source authoritatively reported nothing committed
    /// for the requested identity, or the role was not readable enough to hold
    /// one. A required member rather than a defaulted one, so a reader cannot
    /// mistake an absent readback for a Problem with nothing to report.
    ///
    /// This is a read model over committed history, not authority: it closes
    /// nothing, promotes nothing and grants no repair. A page that does not
    /// decode to one Problem's ordered committed history is
    /// [`ContextInputsError::AttentionPageUndecodable`], never a partial
    /// readback.
    pub problem_readback: Option<ProblemReadback>,
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
    /// Affordances role (`GetCapabilityEvidenceState`).
    pub affordances: RoleAcquisition,
}

impl SevenRoleInputs {
    /// Returns every role label with its disposition, in slot order.
    #[must_use]
    pub fn role_states(&self) -> [(&'static str, &ProjectionState); 7] {
        self.role_acquisitions()
            .map(|(label, role)| (label, &role.state))
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

    /// The structural content invariant of this closure.
    ///
    /// A disposition that does not admit source records must retain none of
    /// them: no payload, no read identity, no observed heads. A content-bearing
    /// disposition may legitimately retain nothing — a read the owner itself
    /// refused reports `Partial` through [`classify_read_outcome`] while holding
    /// no envelope at all, and an unsupported source reports `Missing` — so this
    /// states the direction that admits no leak, rather than requiring content
    /// that a failed read never had.
    ///
    /// This is the one place the rule covers all seven slots at once, so the
    /// public read boundary proves it before serializing instead of trusting each
    /// acquisition site or each future classifier change to remember it.
    pub fn validate_content_admission(&self) -> Result<(), ContextInputsError> {
        for (label, role) in self.role_acquisitions() {
            if admits_source_records(&role.state) {
                continue;
            }
            if role.payload.is_some() || role.identity.is_some() || !role.revision_heads.is_empty()
            {
                return Err(ContextInputsError::ContentNotAdmitted(format!(
                    "{label} retains source content under {:?}",
                    role.state
                )));
            }
        }
        Ok(())
    }

    /// Every role acquisition with its label, in slot order.
    #[must_use]
    pub fn role_acquisitions(&self) -> [(&'static str, &RoleAcquisition); 7] {
        [
            (ROLE_TASK_FRAME, &self.task_frame),
            (ROLE_ATTENTION_CONFLICT, &self.attention),
            (ROLE_EPISTEMIC_POSITION, &self.epistemic),
            (ROLE_CUE_ACTIVATION, &self.cue),
            (ROLE_NEGATIVE_MEMORY, &self.negative_memory),
            (ROLE_EVIDENCE_ASSURANCE, &self.evidence),
            (ROLE_AFFORDANCES, &self.affordances),
        ]
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
    /// no continuation field. Seven role slots are served by six physical reads
    /// only when the cue and negative-memory slots deliberately address one
    /// exact source snapshot; a differing selector gets its own read so one
    /// unrelated result is never relabelled into both roles.
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
            .acquire_negative_memory(ctx, request, &ordering, &cue)
            .await?;
        let evidence = self.acquire_evidence(ctx, request, &ordering).await?;
        let affordances = self
            .acquire_state(
                ctx,
                request,
                &ordering,
                NamedReadOperation::GetCapabilityEvidenceState,
                affordance_parameters(request)?,
                SelectorBinding {
                    key: "skill_id",
                    expected: Some(&request.affordance_skill_id),
                },
            )
            .await?;
        let heads_after = self.scope_heads(ctx, request).await?;
        if heads_after != heads_before {
            return Err(ContextInputsError::SourceHeadsChanged);
        }
        // The committed Problem is read back from the attention role this same
        // reconstruction already read (issue #1759 I2 readback), under the same
        // coherent closure: it adds no read, no store operation and no second
        // Problem model. A Problem-scoped read is the only scope in which a
        // committed record exists; an unscoped attention request names no
        // Problem, so it produces no readback rather than one about an arbitrary
        // record.
        let problem_readback =
            read_committed_problem(&attention, request.attention_problem_id.as_deref())?;
        Ok(SevenRoleInputs {
            scope_id: request.scope_id.clone(),
            state_fence: ctx.state_fence.clone(),
            clock: ctx.clock,
            heads_before,
            heads_after,
            task_frame,
            attention,
            problem_readback,
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
            Ok(response) => Ok(RoleAcquisition::from_response(
                operation,
                classify_role_envelope(&response.view.payload, &request.scope_id, binding),
                response.view.payload,
                response.view.revision_heads,
                response.identity,
            )),
            Err(error) => Ok(RoleAcquisition::from_failure(
                operation,
                classify_read_error(error)?,
            )),
        }
    }

    /// Acquires one `GetUnderstandingProjectionInputs` role through the
    /// admitted `ContextReconstruction` query intent.
    ///
    /// The cue-activation and negative-memory slots call this separately with
    /// their own owner-resolved source selector; only a deliberately identical
    /// selector is served from one physical read. The echoed `selector` binds
    /// the response to the exact source snapshot it was asked for.
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
            Ok(response) => Ok(RoleAcquisition::from_response(
                operation,
                classify_role_envelope(
                    &response.view.payload,
                    &request.scope_id,
                    SelectorBinding {
                        key: "selector",
                        expected: Some(selector),
                    },
                ),
                response.view.payload,
                response.view.revision_heads,
                response.identity,
            )),
            Err(error) => Ok(RoleAcquisition::from_failure(
                operation,
                classify_read_error(error)?,
            )),
        }
    }

    /// Acquires the negative-memory role, reusing the cue acquisition only when
    /// the request deliberately addresses the same exact source snapshot.
    ///
    /// Negative memory reuses the cue read only when it deliberately addresses
    /// the SAME exact source snapshot — identical selector and bound. A
    /// different source set is read separately, so the two slots stay separately
    /// identified (inputs.rs:1-13) without one unrelated result being relabelled
    /// into both roles.
    async fn acquire_negative_memory(
        &self,
        ctx: &RequestMetadata,
        request: &ContextReconstructionRequest,
        ordering: &ReadOrderingBinding,
        cue: &RoleAcquisition,
    ) -> Result<RoleAcquisition, ContextInputsError> {
        if request.negative_memory_selector == request.projection_selector
            && request.negative_memory_max_records == request.projection_max_records
        {
            return Ok(cue.clone());
        }
        self.acquire_projection_inputs(
            ctx,
            request,
            ordering,
            ROLE_NEGATIVE_MEMORY,
            &request.negative_memory_selector,
            request.negative_memory_max_records,
        )
        .await
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
                return Ok((
                    RoleAcquisition::from_failure(operation, classify_read_error(error)?),
                    None,
                ));
            }
        };
        let (state, readback) = decode_epistemic_payload(
            &response.view.payload,
            &request.scope_id,
            &request.epistemic_position,
        );
        Ok((
            RoleAcquisition::from_response(
                response.view.operation,
                state,
                response.view.payload,
                response.view.revision_heads,
                response.identity,
            ),
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
                return Ok(RoleAcquisition::from_failure(
                    operation,
                    classify_read_error(error)?,
                ));
            }
        };
        let state = classify_evidence_payload(
            &response.view.payload,
            &request.scope_id,
            &request.evidence_subject,
        );
        Ok(RoleAcquisition::from_response(
            response.view.operation,
            state,
            response.view.payload,
            response.view.revision_heads,
            response.identity,
        ))
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

/// The single versioned source-envelope version the four task-bound read
/// handlers emit (`TASK_STATE_PAYLOAD_VERSION`,
/// `ATTENTION_PROBLEMS_PAYLOAD_VERSION`,
/// `UNDERSTANDING_INPUTS_PAYLOAD_VERSION` and
/// `CAPABILITY_EVIDENCE_PAYLOAD_VERSION` in both the memory and Surreal owner
/// adapters). A different version is `Unavailable`, never coerced.
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

/// Builds the exact `GetCapabilityEvidenceState` selector map (`skill_id`,
/// `max_records`) that the Kernel capability-evidence check already validates.
fn affordance_parameters(
    request: &ContextReconstructionRequest,
) -> Result<NamedParameters, ContextInputsError> {
    closed_parameters(
        "invalid affordance selectors",
        BTreeMap::from([
            (
                "skill_id".to_owned(),
                Value::String(request.affordance_skill_id.clone()),
            ),
            (
                "max_records".to_owned(),
                decimal_bound(request.affordance_max_records),
            ),
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
        // The bounded page answered, but it does not prove the fence this
        // reconstruction bound: its truncation flag (if any) describes another
        // fence's rows, so this is neither a role outcome nor an empty one. It
        // is `Stale` rather than `Partial` on purpose — `Partial` would claim
        // the source stated a bounded subset of the rows this read asked for,
        // which is exactly what an unproven fence leaves unsaid.
        ReadError::CoverageFenceUnproven => Ok(ProjectionState::Stale {
            reason: "page coverage statement does not prove the read's exact fence".to_owned(),
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
/// The four activated handlers return a versioned source envelope
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

/// Decodes the current-position payload into the T11.2 readback shape, bound to
/// the exact `position` selector and scope this reconstruction asked for.
///
/// A `null` payload is the source's own authoritative empty positions view: the
/// Store keys the lookup by `position_key(scope, position)`, so it already
/// answers THIS selector and there is no echoed identity left to compare.
///
/// Every other payload is bound by [`bind_position_payload`] before it is
/// interpreted, because a readback for another position is as foreign as a
/// readback with another `task_id`. A payload that fails the binding, does not
/// decode, or carries no committed receipt is `Unavailable` with no readback
/// exposed — never empty, never promoted: only an external receipt proves an
/// admitted position.
fn decode_epistemic_payload(
    payload: &Value,
    scope: &ScopeId,
    position: &str,
) -> (ProjectionState, Option<EpistemicPositionReadback>) {
    if payload.is_null() {
        return (ProjectionState::KnownEmpty, None);
    }
    if let Some(reason) = bind_position_payload(payload, scope, position) {
        return (
            ProjectionState::Unavailable {
                reason: bounded_reason("position readback is not this request", reason),
            },
            None,
        );
    }
    let readback: EpistemicPositionReadback = match serde_json::from_value(payload.clone()) {
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
    if readback.receipt.status != WriteReceiptStatus::Committed {
        return (
            ProjectionState::Unavailable {
                reason: "position readback carries no committed receipt".to_owned(),
            },
            None,
        );
    }
    (ProjectionState::Complete, Some(readback))
}

/// Returns why one current-position payload does not answer the requested
/// `position` selector under `scope`, or `None` when it does.
///
/// The position read answers with the T11.2 readback rather than a selector
/// envelope, so the echoed identity is read out of the same bytes the typed
/// decode consumes: the declared readback `schema`, the scope its candidate and
/// transition carry, the position its transition names, and the position every
/// admitted row repeats on its own `AdmittedReceipt`. This is the same
/// comparison [`classify_role_envelope`] makes on `version`/`scope_id`/
/// `<selector>`, and it is a binding check rather than a second decode: every
/// value is compared as recorded, and the typed decode with the contracts' own
/// `validate()` still decides whether the page is usable at all.
fn bind_position_payload(
    payload: &Value,
    scope: &ScopeId,
    position: &str,
) -> Option<&'static str> {
    let echoes = |pointer: &str, expected: &str| {
        payload.pointer(pointer).and_then(Value::as_str) == Some(expected)
    };
    if payload.get("schema").and_then(Value::as_str) != Some(EPISTEMIC_REVISION_SCHEMA) {
        return Some("unsupported position readback schema");
    }
    if !echoes("/candidate/scope", scope.as_str())
        || !echoes("/candidate/work_scope/scope_id", scope.as_str())
        || !echoes("/transition/work_scope/scope_id", scope.as_str())
    {
        return Some("position scope mismatch");
    }
    if !echoes("/transition/position", position) || !echoes("/candidate/proposition", position) {
        return Some("position selector mismatch");
    }
    let Some(admitted) = payload
        .get("positions")
        .and_then(Value::as_array)
        .filter(|positions| !positions.is_empty())
    else {
        return Some("position readback served no admitted position");
    };
    if admitted.iter().any(|view| {
        view.pointer("/admission/position").and_then(Value::as_str) != Some(position)
    }) {
        return Some("an admitted position does not repeat the requested position");
    }
    None
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

    /// One well-formed task-state envelope for the exact requested selector.
    fn bound_task_envelope(scope: &str, task_id: &str) -> Value {
        serde_json::json!({
            "version": ROLE_ENVELOPE_VERSION,
            "scope_id": scope,
            "task_id": task_id,
            "records": [{"revision": 1}],
            "provenance": {"matched_total": 1, "returned": 1, "truncated": false},
        })
    }

    /// The identity a current-position readback echoes for one exact `position`
    /// selector, at the shape the Store's position handler returns.
    fn echoed_position(scope: &str, position: &str) -> Value {
        serde_json::json!({
            "schema": EPISTEMIC_REVISION_SCHEMA,
            "positions": [{"admission": {"scope": scope, "position": position}}],
            "candidate": {
                "scope": scope,
                "proposition": position,
                "work_scope": {"scope_id": scope},
            },
            "transition": {
                "position": position,
                "work_scope": {"scope_id": scope},
            },
        })
    }

    #[test]
    fn a_position_readback_is_bound_to_the_selector_and_scope_it_was_asked_for() -> ProofResult {
        let scope = ScopeId::new("scope-a")?;
        // Positive: the response's own schema, candidate/transition scope and
        // transition position all name what this read asked for, so the binding
        // admits it and the page reaches the typed decode — which is the only
        // stage allowed to refuse it after that. The source's own empty answer
        // for that same `position_key` stays an authoritative `KnownEmpty`.
        let bound = echoed_position("scope-a", "position-a");
        assert_eq!(
            bind_position_payload(&bound, &scope, "position-a"),
            None
        );
        let (state, readback) = decode_epistemic_payload(&bound, &scope, "position-a");
        assert!(matches!(
            state,
            ProjectionState::Unavailable { ref reason } if reason.contains("not a readback")
        ));
        assert!(readback.is_none());
        let (empty, readback) = decode_epistemic_payload(&Value::Null, &scope, "position-a");
        assert_eq!(empty, ProjectionState::KnownEmpty);
        assert!(readback.is_none());

        // Refusal: the same readback answering another position proves nothing
        // about this request, so it is `Unavailable` on the binding itself and
        // exposes no readback.
        let foreign = echoed_position("scope-a", "position-b");
        assert_eq!(
            bind_position_payload(&foreign, &scope, "position-a"),
            Some("position selector mismatch")
        );
        let (state, readback) = decode_epistemic_payload(&foreign, &scope, "position-a");
        assert!(matches!(
            state,
            ProjectionState::Unavailable { ref reason } if reason.contains("not this request")
        ));
        assert!(readback.is_none());
        Ok(())
    }

    /// The binding the `task_frame` slot was requested with.
    fn task_binding<'a>(expected: Option<&'a str>) -> SelectorBinding<'a> {
        SelectorBinding {
            key: "task_id",
            expected,
        }
    }

    #[test]
    fn bound_envelope_reaches_the_consumer_whole() -> ProofResult {
        let scope = ScopeId::new("scope-a")?;
        let heads = test_heads("scope-a")?.revision_heads;
        // Positive: the exact version/scope/selector with coherent provenance is
        // Complete, and every byte of it stays reachable to the consumers that
        // read the role payload.
        let payload = bound_task_envelope("scope-a", "task-a");
        let state = classify_role_envelope(&payload, &scope, task_binding(Some("task-a")));
        assert_eq!(state, ProjectionState::Complete);
        let (retained, retained_heads) = admitted_envelope(&state, payload.clone(), heads.clone());
        assert_eq!(retained.as_ref(), Some(&payload));
        assert_eq!(retained_heads, heads);

        // The bounded real prefix is retained whole too: `Partial` is a real
        // exact-selector page, and `problem_read_site` reads it as a labelled
        // prefix rather than losing it.
        let truncated = serde_json::json!({
            "version": ROLE_ENVELOPE_VERSION,
            "scope_id": "scope-a",
            "task_id": "task-a",
            "records": [{"revision": 1}],
            "provenance": {"matched_total": 4, "returned": 1, "truncated": true},
        });
        let bounded = classify_role_envelope(&truncated, &scope, task_binding(Some("task-a")));
        assert!(matches!(bounded, ProjectionState::Partial { .. }));
        let (retained, _) = admitted_envelope(&bounded, truncated, heads);
        assert!(retained.is_some());

        // An authoritative empty lookup keeps its validated envelope: it is a
        // completed lookup that matched no row, not an absent read.
        let empty = serde_json::json!({
            "version": ROLE_ENVELOPE_VERSION,
            "scope_id": "scope-a",
            "task_id": "task-a",
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        let known_empty = classify_role_envelope(&empty, &scope, task_binding(Some("task-a")));
        assert_eq!(known_empty, ProjectionState::KnownEmpty);
        assert!(
            admitted_envelope(&known_empty, empty, Vec::new())
                .0
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn refused_envelope_stores_no_records_and_never_serializes_them() -> ProofResult {
        let scope = ScopeId::new("scope-a")?;
        let heads = test_heads("scope-a")?.revision_heads;
        // Every refusal below is a response that arrived under the expected
        // operation and fence but does not answer THIS request. None of them may
        // retain the records that travelled with it.
        let refusals: [(&str, Value, ProjectionState); 5] = [
            (
                "foreign selector",
                bound_task_envelope("scope-a", "task-b"),
                ProjectionState::Unavailable {
                    reason: "role payload fails its contract: role selector mismatch".to_owned(),
                },
            ),
            (
                "foreign scope",
                bound_task_envelope("scope-b", "task-a"),
                ProjectionState::Unavailable {
                    reason: "role payload fails its contract: role scope mismatch".to_owned(),
                },
            ),
            (
                "unsupported version",
                serde_json::json!({
                    "version": ROLE_ENVELOPE_VERSION + 1,
                    "scope_id": "scope-a",
                    "task_id": "task-a",
                    "records": [{"revision": 1}],
                    "provenance": {"matched_total": 1, "returned": 1, "truncated": false},
                }),
                ProjectionState::Unavailable {
                    reason: "role payload fails its contract: unsupported role payload version"
                        .to_owned(),
                },
            ),
            (
                "missing records array",
                serde_json::json!({
                    "version": ROLE_ENVELOPE_VERSION,
                    "scope_id": "scope-a",
                    "task_id": "task-a",
                    "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
                }),
                ProjectionState::Unavailable {
                    reason: "role payload fails its contract: role payload has no records array"
                        .to_owned(),
                },
            ),
            (
                "undescribed provenance",
                serde_json::json!({
                    "version": ROLE_ENVELOPE_VERSION,
                    "scope_id": "scope-a",
                    "task_id": "task-a",
                    "records": [{"revision": 1}],
                }),
                ProjectionState::Unknown {
                    reason: "role provenance does not authoritatively describe the records"
                        .to_owned(),
                },
            ),
        ];
        for (label, payload, expected) in refusals {
            let state = classify_role_envelope(&payload, &scope, task_binding(Some("task-a")));
            assert_eq!(state, expected, "{label} must classify as stated");
            let (retained, retained_heads) = admitted_envelope(&state, payload, heads.clone());
            assert!(retained.is_none(), "{label} must retain no payload");
            assert!(
                retained_heads.is_empty(),
                "{label} must retain no observed heads"
            );
            assert!(
                !admits_source_records(&state),
                "{label} must admit no source records"
            );
        }
        Ok(())
    }

    #[test]
    fn content_admission_refuses_a_role_that_still_carries_refused_bytes() -> ProofResult {
        // The structural invariant is checked on the closure, not only at each
        // acquisition site: a role that kept a payload under a state admitting
        // none is refused rather than serialized.
        let mut inputs = role_inputs_with(
            NamedReadOperation::GetTaskState,
            ProjectionState::Unavailable {
                reason: "role payload fails its contract: role selector mismatch".to_owned(),
            },
        )?;
        inputs.task_frame.payload = Some(bound_task_envelope("scope-a", "task-b"));
        assert!(matches!(
            inputs.validate_content_admission(),
            Err(ContextInputsError::ContentNotAdmitted(_))
        ));
        Ok(())
    }

    fn role_inputs_with(
        operation: NamedReadOperation,
        state: ProjectionState,
    ) -> ProofResult<SevenRoleInputs> {
        Ok(SevenRoleInputs {
            scope_id: ScopeId::new("scope-a")?,
            state_fence: test_fence()?,
            clock: ClockReading::default(),
            heads_before: test_heads("scope-a")?,
            heads_after: test_heads("scope-a")?,
            task_frame: RoleAcquisition {
                operation,
                state,
                payload: None,
                revision_heads: Vec::new(),
                identity: None,
            },
            attention: unavailable_role(NamedReadOperation::GetAttentionAndProblems),
            problem_readback: None,
            epistemic: unavailable_role(NamedReadOperation::GetCurrentEpistemicPosition),
            epistemic_readback: None,
            cue: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            negative_memory: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            evidence: unavailable_role(NamedReadOperation::GetEvidencePack),
            affordances: unavailable_role(NamedReadOperation::GetCapabilityEvidenceState),
        })
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
            problem_readback: None,
            epistemic: RoleAcquisition {
                operation: NamedReadOperation::GetCurrentEpistemicPosition,
                state: ProjectionState::KnownEmpty,
                payload: Some(Value::Null),
                revision_heads: Vec::new(),
                identity: None,
            },
            epistemic_readback: None,
            cue: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            negative_memory: unavailable_role(NamedReadOperation::GetUnderstandingProjectionInputs),
            evidence: RoleAcquisition {
                operation: NamedReadOperation::GetEvidencePack,
                state: ProjectionState::Complete,
                payload: Some(serde_json::json!({"records": []})),
                revision_heads: Vec::new(),
                identity: None,
            },
            affordances: unavailable_role(NamedReadOperation::GetCapabilityEvidenceState),
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
            negative_memory_selector: "selector-a".to_owned(),
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
