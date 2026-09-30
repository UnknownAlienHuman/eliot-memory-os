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
//! different task/problem/skill is never adopted just because its operation
//! and fence match.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{ArtifactId, ClockReading, ContractId, RequestMetadata};
use eliot_evaluation_contracts::{
    ComparisonBasis, HumanAttentionClaim, HumanAttentionClaimApplicability,
    HumanAttentionClaimBasis, HumanAttentionClaimCaveat, HumanAttentionClaimKind,
    HumanAttentionEvidenceKind, HumanAttentionEvidenceRead, HumanAttentionMethod,
    HumanAttentionMetric, HumanAttentionSourceBinding,
};
use eliot_read::{
    BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode, QueryRequest,
    ReadApi, ReadError, ReadIdentity, ReadOrderingBinding, ReadOutcome, RequiredAssurance,
    StateRequest, TimeScope,
};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, ReadConsistency, RevisionHead, RevisionKey,
    ScopeId, ScopeRevisionView, WriteReceiptStatus, epistemic_revision::EpistemicPositionReadback,
};
use schemars::JsonSchema;
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
    /// A role request was rejected for a caller-shape reason (not a provider
    /// outcome); this is a programming error, never a role disposition.
    #[error("context reconstruction role request was rejected: {0}")]
    RequestRejected(String),
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

/// One acquired role: its disposition, raw payload, and observed heads.
///
/// Payloads stay opaque here; the candidate stage (T11.4) binds them to the
/// seven typed input families. A `None` payload always pairs with a
/// non-`Complete` disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleAcquisition {
    /// Closed named operation that produced (or refused) this role.
    pub operation: NamedReadOperation,
    /// Completeness state of this role (`inputs.rs:188-282` vocabulary).
    pub state: ProjectionState,
    /// Opaque payload for a completed role; `None` otherwise.
    pub payload: Option<Value>,
    /// Revision heads observed with this role's read.
    pub revision_heads: Vec<RevisionHead>,
    /// Exact read identity this role is bound to (`#1144` retained-read
    /// binding): principal, scope, fence, consistency, declared and observed
    /// heads, order heads, source, projection schema, coverage and the exact
    /// invalidation conditions. `None` exactly when the role is not `Complete`
    /// or `KnownEmpty`, so a retained role can always be revalidated from its
    /// own record instead of re-deriving freshness from the payload.
    pub identity: Option<ReadIdentity>,
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
            Ok(response) => Ok(RoleAcquisition {
                operation,
                state: classify_role_envelope(&response.view.payload, &request.scope_id, binding),
                payload: Some(response.view.payload),
                revision_heads: response.view.revision_heads,
                identity: Some(response.identity),
            }),
            Err(error) => Ok(RoleAcquisition {
                operation,
                state: classify_read_error(error)?,
                payload: None,
                revision_heads: Vec::new(),
                identity: None,
            }),
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
            }),
            Err(error) => Ok(RoleAcquisition {
                operation,
                state: classify_read_error(error)?,
                payload: None,
                revision_heads: Vec::new(),
                identity: None,
            }),
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
                    RoleAcquisition {
                        operation,
                        state: classify_read_error(error)?,
                        payload: None,
                        revision_heads: Vec::new(),
                        identity: None,
                    },
                    None,
                ));
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
                return Ok(RoleAcquisition {
                    operation,
                    state: classify_read_error(error)?,
                    payload: None,
                    revision_heads: Vec::new(),
                    identity: None,
                });
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
        })
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

// ---------------------------------------------------------------------------
// Human attention evaluation evidence assembly (issue #1784, I11.10).
//
// This section is the W3 narrow producer and the W4 conditional-claim gate
// under the existing Governor evidence-admission integration. It prepares the
// semantic admission of a `HumanAttentionEvaluation`: it binds bounded owner
// evidence into one consistently windowed package and derives conditional
// conclusions from observed metrics only. It authorizes nothing, persists
// nothing, completes nothing, and performs no owner read, clock read, I/O,
// or live query: every input is a value the caller already nominated.
//
// W3, bounded owner evidence: [`assemble_human_attention_evidence`] takes the
// caller-nominated named reads of notification delivery/disposition, exact
// expiring approvals, task/verifier/outcome, and privacy records, binds the
// exact per-read source revisions the shared evaluation owner consumes for
// each slot (delivery and disposition stay distinct reads with distinct
// revisions, and so do approval/telemetry, task/verifier, and
// privacy/telemetry) alongside the evaluation window consistently, and returns
// either a complete package or a partial package carrying the exact
// gaps. A missing read is an explicit [`HumanAttentionReadPresentation::Unavailable`]
// entry with its reason, so unavailable evidence yields a partial/inconclusive
// assembly with exact gaps, never synthetic zeros: this section invents no
// counts, no denominators, and no observations. An observed zero still names
// the read that observed it, so an empty nomination is refused and the caller
// presents a gap instead. The caller nominates evidence but neither authorizes
// access to it nor establishes its completeness: authorization stays with the
// evaluator identity and the owner admission path, and completeness is decided
// by the record validator downstream, not here. Analysis that needs bounded
// jobs uses separately admitted jobs on the caller side; nothing here starts
// a telemetry collector or makes a model call on a synchronous control gate.
// The record carries no evaluator-supplied score and no qualification flag,
// so there is no independently-established-evidence shortcut to honor.
//
// W4, conditional comparison: [`assemble_human_attention_claims`] derives
// record claims from observed metrics only. A descriptive record stays useful
// without a control; every difference, prevention, and false-negative
// conclusion requires the declared matched control profile plus applicable
// task-risk/exposure context, and preserves selection bias, censoring,
// intervention effects, and alternative explanations. The closed claim
// vocabulary carries no superiority or overall-ranking kind and this section
// emits no aggregate score, so a quieter or stricter profile is never ranked
// automatically better.
//
// The persistence, authorization, and projection legs (record creation and
// correction, canonical transition and receipt, role-filtered `ControlBoard`
// view) are separate work owned by their own seams; the assembled
// [`BoundHumanAttentionEvidence`] and the derived claims are the exact inputs
// those legs consume.

/// Named owner-read slot feeding one Human attention evaluation.
///
/// The four slots are different counts from different owners: deduplicated
/// inbox items, delivery attempts, and distinct risk events must never be
/// conflated, and none may stand in for an expiring approval boundary, a
/// task/verifier outcome, or a privacy assessment.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HumanAttentionReadSlot {
    /// Named read of notification delivery and disposition (I11.7: delivery,
    /// acknowledgement, and authorized disposition stay distinct).
    NotificationDeliveryDisposition,
    /// Named read of exact expiring approvals (scope and expiry intact).
    ExpiringApprovals,
    /// Named read of task, verifier, and outcome records.
    TaskVerifierOutcome,
    /// Named read of privacy records (purpose, retention, disclosure cost).
    PrivacyRecords,
}

impl HumanAttentionReadSlot {
    /// Stable read name used in errors, gaps, and bound receipts.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotificationDeliveryDisposition => "notification_delivery_disposition",
            Self::ExpiringApprovals => "expiring_approvals",
            Self::TaskVerifierOutcome => "task_verifier_outcome",
            Self::PrivacyRecords => "privacy_records",
        }
    }

    /// Exact owner reads this slot binds, in binding order.
    ///
    /// Mirrors the shared evaluation owner's read split one-for-one: delivery
    /// and disposition carry distinct revisions, the approval boundary joins
    /// its approval revision with its telemetry revision, task outcomes join
    /// the task read with the verifier read, and privacy joins its record
    /// revision with its telemetry revision. The assembly requires exactly
    /// this set with exact revisions, so the bound package lines up with the
    /// record's source bindings instead of conflating independent owner
    /// revisions into one.
    #[must_use]
    pub fn owner_reads(self) -> &'static [HumanAttentionEvidenceRead] {
        use HumanAttentionEvidenceRead as OwnerRead;
        match self {
            Self::NotificationDeliveryDisposition => &[
                OwnerRead::NotificationDelivery,
                OwnerRead::NotificationDisposition,
            ],
            Self::ExpiringApprovals => &[
                OwnerRead::ExpiringApproval,
                OwnerRead::TelemetryCollection,
            ],
            Self::TaskVerifierOutcome => &[OwnerRead::TaskOutcome, OwnerRead::TaskVerifier],
            Self::PrivacyRecords => &[OwnerRead::PrivacyRecord, OwnerRead::TelemetryCollection],
        }
    }
}

impl fmt::Display for HumanAttentionReadSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One caller-nominated named owner read.
///
/// The caller presents the exact per-read source revisions it read — one
/// [`HumanAttentionSourceBinding`] for each owner read in
/// [`HumanAttentionReadSlot::owner_reads`] — and the evaluation window the
/// reads were taken for. The Governor binds them; it never re-reads the
/// owner, never authorizes the access, and never declares the read complete.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NominatedHumanAttentionRead {
    /// Which of the four named slots this nomination fills.
    pub read: HumanAttentionReadSlot,
    /// Exact owner-issued source revisions the caller read, exactly the
    /// slot's owner reads each with an exact revision.
    pub source_bindings: Vec<HumanAttentionSourceBinding>,
    /// Evaluation window the read was taken for; must equal the request window.
    pub window_ref: ContractId,
    /// Evidence artifacts the caller nominates from that read. A present read
    /// always names at least one artifact: an observed zero still names the
    /// read that observed it, so an empty nomination is refused and the caller
    /// presents a gap instead.
    pub evidence_refs: Vec<ArtifactId>,
    /// Contract evidence kinds this read feeds. Admissibility of a kind for a
    /// given metric is enforced by the record validator downstream.
    pub evidence_kinds: Vec<HumanAttentionEvidenceKind>,
}

/// Presentation of one read slot: either the caller nominated a read, or the
/// read is unavailable with its exact reason.
///
/// There is no third state. A missing read never becomes an empty nomination
/// or a zero; it becomes a gap the partial assembly carries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum HumanAttentionReadPresentation {
    /// The caller nominated the owner read for this slot.
    Nominated(NominatedHumanAttentionRead),
    /// The read is unavailable. The reason names the exact gap, for example
    /// which owner could not serve the read inside the evaluation window.
    Unavailable {
        /// Exact reason the read could not be nominated.
        reason: String,
    },
}

/// Caller request to assemble bounded owner evidence for one evaluation window.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceRequest {
    /// Evaluation window every nominated read must bind.
    pub evaluation_window_ref: ContractId,
    /// Named read of notification delivery and disposition.
    pub notification_delivery_disposition: HumanAttentionReadPresentation,
    /// Named read of exact expiring approvals.
    pub expiring_approvals: HumanAttentionReadPresentation,
    /// Named read of task, verifier, and outcome records.
    pub task_verifier_outcome: HumanAttentionReadPresentation,
    /// Named read of privacy records.
    pub privacy_records: HumanAttentionReadPresentation,
}

/// One bound read: the nominated evidence the assembly accepted unchanged.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHumanAttentionRead {
    /// Which named slot this read fills.
    pub read: HumanAttentionReadSlot,
    /// Exact owner-issued source revisions the caller read, exactly the
    /// slot's owner reads each with an exact revision.
    pub source_bindings: Vec<HumanAttentionSourceBinding>,
    /// Evidence artifacts the caller nominated, in nomination order.
    pub evidence_refs: Vec<ArtifactId>,
    /// Contract evidence kinds this read feeds.
    pub evidence_kinds: Vec<HumanAttentionEvidenceKind>,
}

/// Exact gap left by one unavailable read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionEvidenceGap {
    /// Which named slot has no nominated read.
    pub read: HumanAttentionReadSlot,
    /// Exact reason the caller gave for the missing read.
    pub reason: String,
}

/// Assembled bounded owner evidence for one evaluation window.
///
/// A complete assembly carries all four bound reads and no gaps. A partial
/// assembly carries the reads that were available alongside the exact gaps, so
/// the persistence leg records the affected metrics as explicit unknowns with
/// their reasons rather than as zeros. Use
/// [`BoundHumanAttentionEvidence::require_complete`] where a caller needs the
/// complete package only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHumanAttentionEvidence {
    /// Evaluation window every bound read was taken for.
    pub evaluation_window_ref: ContractId,
    /// Accepted reads in slot order.
    pub bound_reads: Vec<BoundHumanAttentionRead>,
    /// Exact gaps for the slots with no nominated read.
    pub gaps: Vec<HumanAttentionEvidenceGap>,
}

impl BoundHumanAttentionEvidence {
    /// Whether every named slot carries a bound read.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// Refuses a partial assembly for callers that need the complete package
    /// only. The refusal carries the missing slots; it deletes nothing and
    /// invents nothing.
    pub fn require_complete(&self) -> Result<(), HumanAttentionEvaluationError> {
        if self.is_complete() {
            return Ok(());
        }
        Err(HumanAttentionEvaluationError::PartialEvidence {
            gaps: self.gaps.iter().map(|gap| gap.read).collect(),
        })
    }
}

/// Fail-closed errors of the Human attention evaluation assembly.
///
/// A missing read is never an error: it becomes a gap on the partial
/// assembly. These errors refuse malformed nominations and unsupported
/// conclusions only.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HumanAttentionEvaluationError {
    /// A required text field is blank or contains control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed text validation.
        field: &'static str,
    },
    /// A nomination was presented in the wrong read slot.
    #[error("nominated read belongs to slot {presented}, not to slot {expected}")]
    ReadSlotMismatch {
        /// Slot the request field requires.
        expected: HumanAttentionReadSlot,
        /// Slot the nomination actually names.
        presented: HumanAttentionReadSlot,
    },
    /// A present read nominates no evidence. An observed zero still names the
    /// read that observed it, so the caller must present a gap instead.
    #[error("nominated {read} carries no evidence references; present a gap instead")]
    EmptyEvidenceRefs {
        /// Slot whose nomination is empty.
        read: HumanAttentionReadSlot,
    },
    /// The same artifact was nominated twice in one read.
    #[error("nominated {read} names the same evidence artifact twice")]
    DuplicateEvidenceRef {
        /// Slot whose nomination repeats an artifact.
        read: HumanAttentionReadSlot,
    },
    /// A present read declares no contract evidence kind.
    #[error("nominated {read} declares no contract evidence kind")]
    NoEvidenceKinds {
        /// Slot whose nomination declares no kind.
        read: HumanAttentionReadSlot,
    },
    /// A nominated read was taken for a different evaluation window.
    #[error("nominated {read} binds a different evaluation window")]
    WindowMismatch {
        /// Slot whose window disagrees with the request window.
        read: HumanAttentionReadSlot,
    },
    /// A nominated read does not bind exactly its slot's owner reads, each
    /// with an exact revision.
    #[error("nominated {read} must bind exactly its owner reads: {expected:?}")]
    WrongSourceBindings {
        /// Slot whose source bindings are not exactly its owner reads.
        read: HumanAttentionReadSlot,
        /// Owner reads the slot requires, in binding order.
        expected: Vec<HumanAttentionEvidenceRead>,
    },
    /// The assembly is partial; the missing slots travel with the refusal.
    #[error("evidence assembly is partial; no complete package was produced")]
    PartialEvidence {
        /// Slots with no nominated read.
        gaps: Vec<HumanAttentionReadSlot>,
    },
    /// A comparative conclusion has no declared comparison basis at all.
    #[error("a comparative conclusion requires a declared comparison basis")]
    NoDeclaredComparisonBasis,
    /// A comparative conclusion rests on a declared basis that is not the
    /// matched control profile. Pre-change, memory-free, and historical
    /// references remain admissible as descriptive context, never as the basis
    /// of a comparative conclusion.
    #[error("a comparative conclusion requires the declared matched control profile")]
    UnmatchedComparisonBasis,
    /// A comparative claim names a profile the record method never declared.
    #[error("comparative claim names an undeclared comparator profile")]
    UnknownMatchedProfile {
        /// Profile the claim names.
        profile: String,
    },
    /// A comparative conclusion drops a required caveat statement.
    #[error("comparative conclusion requires a non-blank {caveat} statement")]
    BlankCaveat {
        /// Caveat whose statement is blank: `selection_bias`, `censoring`,
        /// `intervention_effect`, or `alternative_explanation`.
        caveat: &'static str,
    },
    /// A claim rests on a metric the assembled record did not observe. An
    /// unknown or not-applicable measurement supports no conclusion.
    #[error("claim rests on a metric the record did not observe: {metric:?}")]
    UnknownMetricSupport {
        /// Metric without an observed value.
        metric: HumanAttentionMetric,
    },
    /// A claim names no supporting metric.
    #[error("claim names no supporting metric")]
    EmptySupportingMetrics,
    /// A claim names the same supporting metric twice.
    #[error("claim names the same supporting metric twice: {metric:?}")]
    DuplicateSupportingMetric {
        /// Repeated metric.
        metric: HumanAttentionMetric,
    },
    /// A prevention credit names no observed pre-exposure prevention count. A
    /// prevented action is credited only from an observed prevention count,
    /// never from a lower blocking or harm figure.
    #[error("attributed prevention requires an observed pre-exposure prevention count")]
    PreventionWithoutObservedPrevention,
    /// A suppression false-negative rate names no observed missed-critical
    /// count. It is never inferred from fewer emitted alerts.
    #[error("suppression false-negative rate requires an observed missed-critical count")]
    SuppressionWithoutMissedCritical,
    /// Volume and profile-shape metrics alone support no conclusion. They
    /// describe how much attention a policy asked for, not what it achieved.
    #[error("volume and profile shape alone support no conclusion")]
    VolumeOnlyConclusion,
    /// A comparator profile does not make a description a difference.
    #[error("only a descriptive observation may stand without a comparator profile")]
    BasisKindMismatch,
    /// Two requested claims share one reference.
    #[error("duplicate claim reference")]
    DuplicateClaimRef {
        /// Repeated claim reference.
        claim_ref: String,
    },
}

/// Declared matched comparison context for one comparative conclusion.
///
/// The matched profile reference must be one the record method declared, and
/// the conclusion applies only to the task-risk and exposure context named
/// here. All four caveats are always present: selection bias, censoring,
/// intervention effects, and alternative explanations are preserved on every
/// comparative conclusion by construction.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanAttentionMatchedComparison {
    /// Comparator profile declared by the record method.
    pub matched_profile_ref: String,
    /// Task-risk context the conclusion applies to.
    pub task_risk_context: String,
    /// Exposure context the conclusion applies to.
    pub exposure_context: String,
    /// Preserved selection-bias statement.
    pub selection_bias: String,
    /// Preserved censoring statement.
    pub censoring: String,
    /// Preserved intervention-effect statement.
    pub intervention_effect: String,
    /// Preserved alternative-explanation statement.
    pub alternative_explanation: String,
}

/// One conclusion the production evaluator is asked to derive.
///
/// The closed claim kind carries no superiority or overall-ranking kind, so no
/// request can ask this section to rank a profile simply better, and no
/// aggregate score is emitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedHumanAttentionClaim {
    /// Stable claim reference, unique within the request.
    pub claim_ref: String,
    /// Closed claim kind.
    pub kind: HumanAttentionClaimKind,
    /// Claim statement.
    pub statement: String,
    /// Metrics the claim rests on. Each must be observed by the assembled
    /// record; an unknown cannot support a conclusion.
    pub supporting_metrics: Vec<HumanAttentionMetric>,
    /// Matched comparison context, or `None` for a descriptive observation
    /// that asserts no difference.
    pub comparison: Option<HumanAttentionMatchedComparison>,
}

/// Inputs to the production comparative evaluator.
///
/// This is a transient borrow bundle, not a persisted record: it joins the
/// record method, the descriptive-claim window binding, the observed metrics,
/// and the requested conclusions for one evaluation call.
pub struct HumanAttentionComparisonInput<'a> {
    /// Record method carrying the declared comparison basis and comparator
    /// profiles.
    pub method: &'a HumanAttentionMethod,
    /// Evaluation window descriptive claims must bind.
    pub observation_window_ref: &'a ContractId,
    /// Metrics the assembled record measured with an observed value.
    pub observed_metrics: &'a [HumanAttentionMetric],
    /// Requested conclusions in output order.
    pub requested: &'a [RequestedHumanAttentionClaim],
}

/// Assemble bounded owner evidence for one evaluation window.
///
/// This is the W3 producer: a pure function of the caller-nominated reads. It
/// binds the exact per-read source revisions and the evaluation window
/// consistently, keeps every nominated artifact unchanged, and turns each
/// unavailable read into an exact gap. Missing evidence never becomes a zero, a denominator, or an
/// observation; it becomes a [`HumanAttentionEvidenceGap`] the persistence leg
/// records as an explicit unknown with its reason.
///
/// The call fails closed only on malformed nominations: a blank or
/// control-character revision or gap reason, a nomination in the wrong slot, an
/// empty or duplicate-bearing nomination, a nomination without a contract
/// evidence kind, or a read bound to a different window.
pub fn assemble_human_attention_evidence(
    request: &HumanAttentionEvidenceRequest,
) -> Result<BoundHumanAttentionEvidence, HumanAttentionEvaluationError> {
    let mut bound_reads = Vec::with_capacity(4);
    let mut gaps = Vec::new();
    bind_human_attention_slot(
        &request.notification_delivery_disposition,
        HumanAttentionReadSlot::NotificationDeliveryDisposition,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_human_attention_slot(
        &request.expiring_approvals,
        HumanAttentionReadSlot::ExpiringApprovals,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_human_attention_slot(
        &request.task_verifier_outcome,
        HumanAttentionReadSlot::TaskVerifierOutcome,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    bind_human_attention_slot(
        &request.privacy_records,
        HumanAttentionReadSlot::PrivacyRecords,
        &request.evaluation_window_ref,
        &mut bound_reads,
        &mut gaps,
    )?;
    Ok(BoundHumanAttentionEvidence {
        evaluation_window_ref: request.evaluation_window_ref.clone(),
        bound_reads,
        gaps,
    })
}

/// Derive conditional record claims from the observed metrics.
///
/// This is the W4 production evaluator: a descriptive request always yields a
/// window-bound descriptive claim, while every difference, prevention, and
/// false-negative conclusion is admitted only on the declared matched control
/// profile with applicable task-risk/exposure context and all four preserved
/// caveats. Prevention is credited only from an observed pre-exposure
/// prevention count, a suppression false-negative rate only from an observed
/// missed-critical count, and volume or profile shape alone supports no
/// conclusion. The call fails closed on any unsupported request; it never
/// weakens a request into a descriptive claim and never emits a ranking.
pub fn assemble_human_attention_claims(
    input: &HumanAttentionComparisonInput<'_>,
) -> Result<Vec<HumanAttentionClaim>, HumanAttentionEvaluationError> {
    let mut seen_refs = BTreeSet::new();
    let mut claims = Vec::with_capacity(input.requested.len());
    for requested in input.requested {
        require_attention_text(&requested.claim_ref, "human_attention_claim.claim_ref")?;
        require_attention_text(&requested.statement, "human_attention_claim.statement")?;
        if !seen_refs.insert(requested.claim_ref.as_str()) {
            return Err(HumanAttentionEvaluationError::DuplicateClaimRef {
                claim_ref: requested.claim_ref.clone(),
            });
        }
        validate_claim_support(requested, input.observed_metrics)?;
        let basis = assemble_claim_basis(requested, input)?;
        claims.push(HumanAttentionClaim {
            claim_ref: requested.claim_ref.clone(),
            kind: requested.kind,
            statement: requested.statement.clone(),
            supporting_metrics: requested.supporting_metrics.clone(),
            basis,
        });
    }
    Ok(claims)
}

/// Volume, delivery, and profile-shape metrics.
///
/// Mirrors the closed contract set: these metrics describe how much attention
/// a policy asked for, not what it achieved, so they can never be the sole
/// support of a comparative conclusion.
const fn is_volume_or_profile_shape(metric: HumanAttentionMetric) -> bool {
    use HumanAttentionMetric as M;
    matches!(
        metric,
        M::DeduplicatedInboxItems
            | M::DeliveryAttempts
            | M::NotificationApprovalAndTelemetryProfile
            | M::PolicyAndTaskRiskProfile
    )
}

fn require_attention_text(
    value: &str,
    field: &'static str,
) -> Result<(), HumanAttentionEvaluationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(HumanAttentionEvaluationError::InvalidText { field });
    }
    Ok(())
}

fn bind_human_attention_slot(
    presentation: &HumanAttentionReadPresentation,
    expected: HumanAttentionReadSlot,
    window_ref: &ContractId,
    bound_reads: &mut Vec<BoundHumanAttentionRead>,
    gaps: &mut Vec<HumanAttentionEvidenceGap>,
) -> Result<(), HumanAttentionEvaluationError> {
    match presentation {
        HumanAttentionReadPresentation::Nominated(nominated) => {
            if nominated.read != expected {
                return Err(HumanAttentionEvaluationError::ReadSlotMismatch {
                    expected,
                    presented: nominated.read,
                });
            }
            check_source_bindings(nominated.read, &nominated.source_bindings)?;
            if nominated.window_ref != *window_ref {
                return Err(HumanAttentionEvaluationError::WindowMismatch {
                    read: nominated.read,
                });
            }
            if nominated.evidence_refs.is_empty() {
                return Err(HumanAttentionEvaluationError::EmptyEvidenceRefs {
                    read: nominated.read,
                });
            }
            let mut seen = BTreeSet::new();
            for evidence_ref in &nominated.evidence_refs {
                if !seen.insert(evidence_ref) {
                    return Err(HumanAttentionEvaluationError::DuplicateEvidenceRef {
                        read: nominated.read,
                    });
                }
            }
            if nominated.evidence_kinds.is_empty() {
                return Err(HumanAttentionEvaluationError::NoEvidenceKinds {
                    read: nominated.read,
                });
            }
            bound_reads.push(BoundHumanAttentionRead {
                read: nominated.read,
                source_bindings: nominated.source_bindings.clone(),
                evidence_refs: nominated.evidence_refs.clone(),
                evidence_kinds: nominated.evidence_kinds.clone(),
            });
            Ok(())
        }
        HumanAttentionReadPresentation::Unavailable { reason } => {
            require_attention_text(reason, "human_attention_evidence.unavailable.reason")?;
            gaps.push(HumanAttentionEvidenceGap {
                read: expected,
                reason: reason.clone(),
            });
            Ok(())
        }
    }
}

/// Checks that a nomination binds exactly its slot's owner reads.
///
/// Each binding must name one of the slot's
/// [`HumanAttentionReadSlot::owner_reads`] with an exact non-blank revision,
/// with no missing, foreign, or repeated owner read. The check keeps the
/// Governor package aligned with the source bindings the shared evaluation
/// owner assembles into the record: delivery and disposition, approval and
/// telemetry, task and verifier, and privacy and telemetry revisions are
/// never conflated into one.
fn check_source_bindings(
    read: HumanAttentionReadSlot,
    bindings: &[HumanAttentionSourceBinding],
) -> Result<(), HumanAttentionEvaluationError> {
    let expected = read.owner_reads();
    let exact = bindings.len() == expected.len()
        && expected
            .iter()
            .all(|expected_read| bindings.iter().filter(|b| b.read == *expected_read).count() == 1);
    if !exact {
        return Err(HumanAttentionEvaluationError::WrongSourceBindings {
            read,
            expected: expected.to_vec(),
        });
    }
    for binding in bindings {
        require_attention_text(
            &binding.source_revision,
            "human_attention_evidence.read.source_revision",
        )?;
    }
    Ok(())
}

fn validate_claim_support(
    requested: &RequestedHumanAttentionClaim,
    observed_metrics: &[HumanAttentionMetric],
) -> Result<(), HumanAttentionEvaluationError> {
    if requested.supporting_metrics.is_empty() {
        return Err(HumanAttentionEvaluationError::EmptySupportingMetrics);
    }
    let mut seen = BTreeSet::new();
    for metric in &requested.supporting_metrics {
        if !seen.insert(*metric) {
            return Err(HumanAttentionEvaluationError::DuplicateSupportingMetric {
                metric: *metric,
            });
        }
        if !observed_metrics.contains(metric) {
            return Err(HumanAttentionEvaluationError::UnknownMetricSupport {
                metric: *metric,
            });
        }
    }
    Ok(())
}

fn assemble_claim_basis(
    requested: &RequestedHumanAttentionClaim,
    input: &HumanAttentionComparisonInput<'_>,
) -> Result<HumanAttentionClaimBasis, HumanAttentionEvaluationError> {
    match (&requested.comparison, requested.kind) {
        (None, HumanAttentionClaimKind::DescriptiveObservation) => {
            Ok(HumanAttentionClaimBasis::Descriptive {
                observation_window_ref: input.observation_window_ref.clone(),
            })
        }
        (Some(_), HumanAttentionClaimKind::DescriptiveObservation) => {
            Err(HumanAttentionEvaluationError::BasisKindMismatch)
        }
        (None, _) => Err(HumanAttentionEvaluationError::NoDeclaredComparisonBasis),
        (Some(comparison), kind) => {
            require_matched_basis(input.method)?;
            validate_matched_profile(comparison, input.method)?;
            validate_kind_evidence(requested, kind)?;
            Ok(HumanAttentionClaimBasis::Comparative {
                matched_profile_ref: comparison.matched_profile_ref.clone(),
                applicability: HumanAttentionClaimApplicability {
                    task_risk_context: comparison.task_risk_context.clone(),
                    exposure_context: comparison.exposure_context.clone(),
                },
                caveats: vec![
                    HumanAttentionClaimCaveat::SelectionBias {
                        statement: comparison.selection_bias.clone(),
                    },
                    HumanAttentionClaimCaveat::Censoring {
                        statement: comparison.censoring.clone(),
                    },
                    HumanAttentionClaimCaveat::InterventionEffect {
                        statement: comparison.intervention_effect.clone(),
                    },
                    HumanAttentionClaimCaveat::AlternativeExplanation {
                        statement: comparison.alternative_explanation.clone(),
                    },
                ],
            })
        }
    }
}

/// A comparative conclusion requires the declared matched control profile:
/// the `MatchedControl` basis is the matched-or-paired profile I11.10
/// requires. Any other declared basis stays admissible as descriptive context
/// but cannot carry a comparative conclusion.
fn require_matched_basis(
    method: &HumanAttentionMethod,
) -> Result<(), HumanAttentionEvaluationError> {
    if matches!(
        &method.comparison_basis,
        ComparisonBasis::None | ComparisonBasis::NotApplicableWithReason
    ) {
        return Err(HumanAttentionEvaluationError::NoDeclaredComparisonBasis);
    }
    if method.comparison_basis != ComparisonBasis::MatchedControl {
        return Err(HumanAttentionEvaluationError::UnmatchedComparisonBasis);
    }
    Ok(())
}

fn validate_matched_profile(
    comparison: &HumanAttentionMatchedComparison,
    method: &HumanAttentionMethod,
) -> Result<(), HumanAttentionEvaluationError> {
    require_attention_text(
        &comparison.matched_profile_ref,
        "human_attention_claim.basis.matched_profile_ref",
    )?;
    if !method
        .comparator_profile_refs
        .iter()
        .any(|profile| profile == &comparison.matched_profile_ref)
    {
        return Err(HumanAttentionEvaluationError::UnknownMatchedProfile {
            profile: comparison.matched_profile_ref.clone(),
        });
    }
    require_attention_text(
        &comparison.task_risk_context,
        "human_attention_claim.basis.applicability.task_risk_context",
    )?;
    require_attention_text(
        &comparison.exposure_context,
        "human_attention_claim.basis.applicability.exposure_context",
    )?;
    validate_caveat(&comparison.selection_bias, "selection_bias")?;
    validate_caveat(&comparison.censoring, "censoring")?;
    validate_caveat(&comparison.intervention_effect, "intervention_effect")?;
    validate_caveat(
        &comparison.alternative_explanation,
        "alternative_explanation",
    )?;
    Ok(())
}

fn validate_caveat(
    statement: &str,
    caveat: &'static str,
) -> Result<(), HumanAttentionEvaluationError> {
    if statement.trim().is_empty() || statement.chars().any(char::is_control) {
        return Err(HumanAttentionEvaluationError::BlankCaveat { caveat });
    }
    Ok(())
}

/// A prevented action is credited only from an observed pre-exposure
/// prevention count, a suppression false-negative rate only from an observed
/// missed-critical count, and volume or profile shape alone supports no
/// conclusion: neither prevention nor a false-negative rate is inferred from
/// a lower blocking, harm, or alert figure.
fn validate_kind_evidence(
    requested: &RequestedHumanAttentionClaim,
    kind: HumanAttentionClaimKind,
) -> Result<(), HumanAttentionEvaluationError> {
    match kind {
        HumanAttentionClaimKind::DescriptiveObservation => {
            Err(HumanAttentionEvaluationError::BasisKindMismatch)
        }
        HumanAttentionClaimKind::AttributedPrevention
            if !requested
                .supporting_metrics
                .contains(&HumanAttentionMetric::PreExposurePreventionEvents) =>
        {
            Err(HumanAttentionEvaluationError::PreventionWithoutObservedPrevention)
        }
        HumanAttentionClaimKind::SuppressionFalseNegative
            if !requested
                .supporting_metrics
                .contains(&HumanAttentionMetric::MissedCriticalRiskEvents) =>
        {
            Err(HumanAttentionEvaluationError::SuppressionWithoutMissedCritical)
        }
        _ if requested
            .supporting_metrics
            .iter()
            .all(|metric| is_volume_or_profile_shape(*metric)) =>
        {
            Err(HumanAttentionEvaluationError::VolumeOnlyConclusion)
        }
        _ => Ok(()),
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
