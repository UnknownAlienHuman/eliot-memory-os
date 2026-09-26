//! Receipt-bound `WorkScope` transitions (issue #2380, I4.7).
//!
//! Implements the I4.7 scope-transition procedure exactly: expand, contract,
//! merge, split, or move runs propose (1) → identify affected records/authority
//! (2) → preserve old scope and provenance (3) → copy/reference data only as
//! candidates unless validity transfers deterministically (4) → issue new scope
//! generation (5) → invalidate incompatible sessions/leases (6) → verify new
//! truth and access boundaries (7) → commit receipt (8). Cross-scope atomicity
//! is not promised: the procedure is a saga with visible partial outcomes.
//!
//! Grounding in the linked fragments:
//!
//! - I4.7 owns this procedure and its committed receipt. This module consumes
//!   the #1787 [`ScopeBindingGuard`] receipts (MATCHED pre-check on the old
//!   generation, MATCHED revalidation on the new generation post-commit) and
//!   the #1789 readiness hook (`assess_material_readiness` must be re-run once
//!   the generation advances), and never redefines them.
//! - I4.2.1 provisional/quarantine rule: moved records land as
//!   [`StagedCandidateRecord`] candidates with preserved provenance until a
//!   deterministic validity transfer; [`StagedCandidateRecord::admits_material_effects`]
//!   withholds project writes/effects while a record is still a candidate.
//! - Receipt durability travels the canonical Governor semantic admission →
//!   Kernel fence → store commit path: the proposal and the receipt bind the
//!   caller's [`StateFence`](eliot_contracts::StateFence) and create no writer,
//!   no second ledger, no parallel commit path.
//! - Observability rides the existing Governor observation path: every type
//!   here is `Serialize` + `JsonSchema`, and [`TransitionObservation`] is the
//!   validated queryable view of proposal, per-step outcomes, and final
//!   receipt. No new observation surface is created.
//!
//! This crate evaluates caller-supplied observations only. Mechanical truth
//! (which records exist, which sessions are live, what the new boundaries are)
//! enters through the caller's [`TransitionStepEvidence`]; this module records
//! each step's outcome in the receipt and fails closed on the first mismatch.

use super::{
    IdentityLegOutcome, ScopeBinding, ScopeBindingDisposition, ScopeBindingGuardReceipt,
    WorkScopeError, counter, identity_legs, text, unique,
};
use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Total steps of the I4.7 procedure; a committed receipt names exactly these.
pub const TRANSITION_STEP_COUNT: u8 = 8;

/// Which I4.7 transition the proposal performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTransitionKind {
    Expand,
    Contract,
    Merge,
    Split,
    Move,
}

/// One step of the 8-step I4.7 procedure, in procedure order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTransitionStep {
    Propose,
    IdentifyAffected,
    PreserveOldScope,
    StageCandidates,
    IssueNewGeneration,
    InvalidateSessions,
    VerifyBoundaries,
    CommitReceipt,
}

impl ScopeTransitionStep {
    /// Returns the 1-based procedure number of this step.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Propose => 1,
            Self::IdentifyAffected => 2,
            Self::PreserveOldScope => 3,
            Self::StageCandidates => 4,
            Self::IssueNewGeneration => 5,
            Self::InvalidateSessions => 6,
            Self::VerifyBoundaries => 7,
            Self::CommitReceipt => 8,
        }
    }

    /// Returns the procedure text of this step, verbatim from I4.7.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Propose => "create proposed ScopeTransition",
            Self::IdentifyAffected => "identify records/authority affected",
            Self::PreserveOldScope => "preserve old scope and provenance",
            Self::StageCandidates => {
                "copy/reference data only as candidates unless validity transfers deterministically"
            }
            Self::IssueNewGeneration => "issue new scope generation",
            Self::InvalidateSessions => "invalidate incompatible sessions/leases",
            Self::VerifyBoundaries => "verify new truth and access boundaries",
            Self::CommitReceipt => "commit receipt",
        }
    }

    /// Returns the step for a 1-based procedure number.
    fn from_number(number: usize) -> Option<Self> {
        match number {
            1 => Some(Self::Propose),
            2 => Some(Self::IdentifyAffected),
            3 => Some(Self::PreserveOldScope),
            4 => Some(Self::StageCandidates),
            5 => Some(Self::IssueNewGeneration),
            6 => Some(Self::InvalidateSessions),
            7 => Some(Self::VerifyBoundaries),
            8 => Some(Self::CommitReceipt),
            _ => None,
        }
    }
}

/// Whether a staged record may yet admit project writes/effects.
///
/// A moved record stays [`Self::Candidate`] with preserved provenance until a
/// deterministic validity transfer names `transfer_ref`; only
/// [`Self::ValidityTransferred`] admits material effects (I4.2.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "standing", content = "detail")]
pub enum CandidateRecordStanding {
    Candidate,
    ValidityTransferred { transfer_ref: String },
}

/// One record copied/referenced by step 4, always as a candidate first.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StagedCandidateRecord {
    pub record_ref: String,
    pub provenance_ref: String,
    pub standing: CandidateRecordStanding,
}

impl StagedCandidateRecord {
    /// Validates record identity, preserved provenance, and transfer evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank or the transfer reference of
    /// a validity transfer is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.record_ref, "staged.record_ref")?;
        text(&self.provenance_ref, "staged.provenance_ref")?;
        if let CandidateRecordStanding::ValidityTransferred { transfer_ref } = &self.standing {
            text(transfer_ref, "staged.transfer_ref")?;
        }
        Ok(())
    }

    /// Returns whether this record admits project writes/effects.
    ///
    /// Candidates never do: project writes/effects stay withheld per I4.2.1
    /// until a deterministic validity transfer completes.
    #[must_use]
    pub const fn admits_material_effects(&self) -> bool {
        matches!(
            self.standing,
            CandidateRecordStanding::ValidityTransferred { .. }
        )
    }
}

/// Step-1 proposal of one I4.7 transition.
///
/// The proposal names the operation, the primary scope, every affected record
/// and authority reference, the old and new generations, and the MATCHED
/// pre-check guard receipt on the old generation. Merge, split, and move name
/// the counterpart scopes in `related_scope_refs`; expand and contract carry
/// none.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeTransition {
    pub transition_ref: String,
    pub kind: ScopeTransitionKind,
    pub scope_ref: String,
    pub related_scope_refs: Vec<String>,
    pub old_generation: u64,
    pub new_generation: u64,
    pub affected_record_refs: Vec<String>,
    pub authority_refs: Vec<String>,
    pub pre_commit_guard: ScopeBindingGuardReceipt,
    pub state_fence: StateFence,
}

impl ScopeTransition {
    /// Validates the proposal without running any transition step.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank, counters are zero, a
    /// collection is empty or duplicated, the new generation does not advance
    /// past the old one, the kind's counterpart-scope shape is violated, the
    /// fence is invalid, or the pre-check guard is not MATCHED on the old
    /// generation.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.transition_ref, "transition_ref")?;
        text(&self.scope_ref, "scope_ref")?;
        counter(self.old_generation, "old_generation")?;
        counter(self.new_generation, "new_generation")?;
        if self.new_generation <= self.old_generation {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        match self.kind {
            ScopeTransitionKind::Expand | ScopeTransitionKind::Contract => {
                if !self.related_scope_refs.is_empty() {
                    return Err(WorkScopeError::BindingReceiptMismatch);
                }
            }
            ScopeTransitionKind::Merge | ScopeTransitionKind::Split | ScopeTransitionKind::Move => {
                if self.related_scope_refs.is_empty() {
                    return Err(WorkScopeError::EmptyCollection {
                        field: "related_scope_refs",
                    });
                }
                for related in &self.related_scope_refs {
                    text(related, "related_scope_refs")?;
                    if *related == self.scope_ref {
                        return Err(WorkScopeError::BindingReceiptMismatch);
                    }
                }
                unique(self.related_scope_refs.iter(), "related_scope_refs")?;
            }
        }
        collection(&self.affected_record_refs, "affected_record_refs", 256)?;
        collection(&self.authority_refs, "authority_refs", 16)?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        if self.state_fence.resource_generation.value() != self.old_generation {
            return Err(WorkScopeError::StateFenceMismatch);
        }
        check_guard_matches_generation(&self.pre_commit_guard, &self.scope_ref, self.old_generation)
    }
}

/// Recorded outcome of one procedure step: evidence when completed, the exact
/// withholding/failure reason otherwise. A saga interrupted mid-procedure
/// keeps every prior step's outcome visible in the partial receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionStepOutcome {
    pub step: ScopeTransitionStep,
    pub completed: bool,
    pub evidence_refs: Vec<String>,
    pub note: String,
}

impl TransitionStepOutcome {
    /// Validates one recorded step outcome.
    ///
    /// # Errors
    ///
    /// Returns an error when the note is blank or an evidence reference is
    /// blank or duplicated.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.note, "outcome.note")?;
        for evidence in &self.evidence_refs {
            text(evidence, "outcome.evidence_refs")?;
        }
        unique(self.evidence_refs.iter(), "outcome.evidence_refs")
    }
}

/// Committed or partial receipt of one I4.7 transition.
///
/// A committed receipt names exactly the eight step outcomes (all completed),
/// the old and new generations, the invalidated sessions/leases, and the
/// boundary-verification evidence. A partial receipt carries the contiguous
/// completed prefix plus the failed step's outcome with `committed` false; it
/// is resumed by [`resume_transition`] under a new revision, never mutated.
/// The post-commit guard endorsement attaches after commit via
/// [`attach_post_commit_guard`], which consumes the receipt and returns a new
/// value so the committed step outcomes are never rewritten.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeTransitionReceipt {
    pub receipt_ref: String,
    pub transition_ref: String,
    pub kind: ScopeTransitionKind,
    pub revision: u64,
    pub scope_ref: String,
    pub old_generation: u64,
    pub new_generation: u64,
    pub step_outcomes: Vec<TransitionStepOutcome>,
    pub committed: bool,
    pub invalidated_session_refs: Vec<String>,
    pub staged_candidates: Vec<StagedCandidateRecord>,
    pub boundary_evidence_refs: Vec<String>,
    pub post_commit_guard: Option<ScopeBindingGuardReceipt>,
    pub readiness_reevaluation_required: bool,
    pub state_fence: StateFence,
}

impl ScopeTransitionReceipt {
    /// Validates a committed or partial receipt without re-running any step.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank, counters are zero, the
    /// generation does not advance, step outcomes are not the contiguous
    /// `1..=k` prefix (exactly eight, all completed, when committed), a
    /// committed receipt lacks invalidated sessions, staged candidates,
    /// boundary evidence, or the readiness re-evaluation flag, the fence is
    /// invalid or not bound to the receipt's final generation, or a present
    /// post-commit guard is not MATCHED on the new generation.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "receipt_ref")?;
        text(&self.transition_ref, "transition_ref")?;
        text(&self.scope_ref, "scope_ref")?;
        counter(self.revision, "revision")?;
        counter(self.old_generation, "old_generation")?;
        counter(self.new_generation, "new_generation")?;
        if self.new_generation <= self.old_generation {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if self.step_outcomes.is_empty()
            || self.step_outcomes.len() > TRANSITION_STEP_COUNT as usize
        {
            return Err(WorkScopeError::EmptyCollection {
                field: "step_outcomes",
            });
        }
        for (index, outcome) in self.step_outcomes.iter().enumerate() {
            outcome.validate()?;
            let expected = ScopeTransitionStep::from_number(index + 1)
                .ok_or(WorkScopeError::BindingReceiptMismatch)?;
            if outcome.step != expected || usize::from(outcome.step.number()) != index + 1 {
                return Err(WorkScopeError::BindingReceiptMismatch);
            }
        }
        if self.committed {
            if self.step_outcomes.len() != TRANSITION_STEP_COUNT as usize
                || self.step_outcomes.iter().any(|outcome| !outcome.completed)
            {
                return Err(WorkScopeError::BindingReceiptMismatch);
            }
            if self.invalidated_session_refs.is_empty() {
                return Err(WorkScopeError::EmptyCollection {
                    field: "invalidated_session_refs",
                });
            }
            if self.staged_candidates.is_empty() {
                return Err(WorkScopeError::EmptyCollection {
                    field: "staged_candidates",
                });
            }
            if self.boundary_evidence_refs.is_empty() {
                return Err(WorkScopeError::EmptyCollection {
                    field: "boundary_evidence_refs",
                });
            }
            if !self.readiness_reevaluation_required {
                return Err(WorkScopeError::BindingReceiptMismatch);
            }
        }
        // A partial interrupted before step 6 carries no invalidated sessions
        // yet; the completed step outcomes stay visible below. Committed
        // receipts must name them (checked above).
        if self.committed || !self.invalidated_session_refs.is_empty() {
            collection(
                &self.invalidated_session_refs,
                "invalidated_session_refs",
                128,
            )?;
        }
        for candidate in &self.staged_candidates {
            candidate.validate()?;
        }
        unique(
            self.staged_candidates
                .iter()
                .map(|candidate| &candidate.record_ref),
            "staged.record_ref",
        )?;
        references(&self.boundary_evidence_refs, "boundary_evidence_refs", 32)?;
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)?;
        let final_generation = if self.committed {
            self.new_generation
        } else {
            self.old_generation
        };
        if self.state_fence.resource_generation.value() != final_generation {
            return Err(WorkScopeError::StateFenceMismatch);
        }
        if let Some(guard) = &self.post_commit_guard {
            if !self.committed {
                return Err(WorkScopeError::BindingReceiptMismatch);
            }
            check_guard_matches_generation(guard, &self.scope_ref, self.new_generation)?;
        }
        Ok(())
    }
}

/// Caller-supplied mechanical evidence for steps 2–8.
///
/// This is a transient execution argument, not a persisted binding: every
/// field carries caller-observed authority (affected records, preserved
/// provenance, staged candidates, the new-generation binding, invalidated
/// sessions with their bindings observed at invalidation time, boundary
/// verification, and the commit fence). The executor checks each step against
/// the proposal and records the outcome.
#[derive(Clone, Debug)]
pub struct TransitionStepEvidence {
    pub affected_record_refs: Vec<String>,
    pub authority_refs: Vec<String>,
    pub old_scope_provenance_refs: Vec<String>,
    pub staged_candidates: Vec<StagedCandidateRecord>,
    pub new_binding: ScopeBinding,
    pub invalidated_session_refs: Vec<String>,
    /// Caller-observed bindings of the invalidated sessions/leases, counted
    /// against `invalidated_session_refs` (one binding per recorded ref).
    ///
    /// Step 6 runs the existing guard legs ([`identity_legs`]) of each
    /// binding against `new_binding`: an invalidated session must *not* be
    /// identity-clear under the new generation (a still-clear session is not
    /// incompatible and must not be recorded as invalidated).
    pub invalidated_session_bindings: Vec<ScopeBinding>,
    pub boundary_evidence_refs: Vec<String>,
    pub commit_fence: StateFence,
}

impl TransitionStepEvidence {
    /// Validates evidence shape without checking it against a proposal.
    ///
    /// # Errors
    ///
    /// Returns an error when a collection is empty or oversized, a reference
    /// is blank or duplicated, a staged candidate is malformed, the new
    /// binding is malformed, or the commit fence is invalid.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        collection(&self.affected_record_refs, "affected_record_refs", 256)?;
        collection(&self.authority_refs, "authority_refs", 16)?;
        collection(
            &self.old_scope_provenance_refs,
            "old_scope_provenance_refs",
            32,
        )?;
        if self.staged_candidates.is_empty() || self.staged_candidates.len() > 256 {
            return Err(WorkScopeError::EmptyCollection {
                field: "staged_candidates",
            });
        }
        for candidate in &self.staged_candidates {
            candidate.validate()?;
        }
        unique(
            self.staged_candidates
                .iter()
                .map(|candidate| &candidate.record_ref),
            "staged.record_ref",
        )?;
        self.new_binding.validate()?;
        collection(
            &self.invalidated_session_refs,
            "invalidated_session_refs",
            128,
        )?;
        if self.invalidated_session_bindings.len() != self.invalidated_session_refs.len() {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        for binding in &self.invalidated_session_bindings {
            binding.validate()?;
        }
        collection(&self.boundary_evidence_refs, "boundary_evidence_refs", 32)?;
        self.commit_fence
            .validate()
            .map_err(|_| WorkScopeError::InvalidStateFence)
    }
}

fn collection(values: &[String], field: &'static str, max: usize) -> Result<(), WorkScopeError> {
    if values.is_empty() || values.len() > max {
        return Err(WorkScopeError::EmptyCollection { field });
    }
    references(values, field, max)
}

fn references(values: &[String], field: &'static str, max: usize) -> Result<(), WorkScopeError> {
    if values.len() > max {
        return Err(WorkScopeError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    unique(values.iter(), field)
}

/// Visible interruption of the saga: the partial receipt with every completed
/// step's outcome intact, the failed step, and the exact failure reason.
/// Nothing is rolled back silently and no step claims atomicity across scopes.
/// Post-commit driver failures carry the committed receipt instead of an
/// uncommitted partial so endorsement can be retried; such receipts are never
/// resumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionFailure {
    pub partial: Box<ScopeTransitionReceipt>,
    pub failed_step: ScopeTransitionStep,
    pub reason: WorkScopeError,
}

/// Queryable view of a proposal plus its receipt for the existing Governor
/// observation path.
///
/// This is a validated projection carried as JSON by the existing path, not a
/// new observation surface: proposal, per-step outcomes, and final receipt
/// stay queryable through the step outcomes and receipt the Governor already
/// retains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransitionObservation {
    pub transition_ref: String,
    pub receipt_ref: String,
    pub kind: ScopeTransitionKind,
    pub scope_ref: String,
    pub old_generation: u64,
    pub new_generation: u64,
    pub completed_steps: u8,
    pub total_steps: u8,
    pub committed: bool,
    pub readiness_reevaluation_required: bool,
}

impl TransitionObservation {
    /// Validates the projected observation.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank, counters are zero, the
    /// generation does not advance, or the completed-step count is
    /// inconsistent with the committed flag.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.transition_ref, "transition_ref")?;
        text(&self.receipt_ref, "receipt_ref")?;
        text(&self.scope_ref, "scope_ref")?;
        counter(self.old_generation, "old_generation")?;
        counter(self.new_generation, "new_generation")?;
        if self.new_generation <= self.old_generation {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if self.total_steps != TRANSITION_STEP_COUNT {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if self.completed_steps > self.total_steps {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        if self.committed && self.completed_steps != self.total_steps {
            return Err(WorkScopeError::BindingReceiptMismatch);
        }
        Ok(())
    }
}

fn check_guard_matches_generation(
    guard: &ScopeBindingGuardReceipt,
    scope_ref: &str,
    generation: u64,
) -> Result<(), WorkScopeError> {
    if guard.disposition != ScopeBindingDisposition::Matched {
        return Err(WorkScopeError::BindingReceiptNotMatched);
    }
    text(&guard.expected_scope_ref, "guard.expected_scope_ref")?;
    text(&guard.observed_scope_ref, "guard.observed_scope_ref")?;
    if guard.observed_scope_ref != scope_ref
        || guard.expected_scope_ref != scope_ref
        || guard.source_generation != generation
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    Ok(())
}

fn completed(
    step: ScopeTransitionStep,
    evidence_refs: Vec<String>,
    note: &str,
) -> TransitionStepOutcome {
    TransitionStepOutcome {
        step,
        completed: true,
        evidence_refs,
        note: format!("{}: {note}", step.label()),
    }
}

fn failed_outcome(step: ScopeTransitionStep, reason: &WorkScopeError) -> TransitionStepOutcome {
    TransitionStepOutcome {
        step,
        completed: false,
        evidence_refs: Vec::new(),
        note: format!("{} failed: {reason}", step.label()),
    }
}

/// Creates the step-1 proposal of one I4.7 transition.
///
/// Requires a MATCHED pre-check guard receipt bound to the old generation: a
/// transition extends a healthy binding, it never repairs a withheld one. The
/// returned outcome records step 1 for the receipt under construction.
///
/// # Errors
///
/// Returns an error when references, generations, collections, the kind's
/// counterpart-scope shape, or the fence are malformed, or when the pre-check
/// guard is not MATCHED on the old generation.
#[allow(clippy::too_many_arguments)]
pub fn propose_transition(
    transition_ref: impl Into<String>,
    kind: ScopeTransitionKind,
    scope_ref: impl Into<String>,
    related_scope_refs: Vec<String>,
    old_generation: u64,
    new_generation: u64,
    affected_record_refs: Vec<String>,
    authority_refs: Vec<String>,
    pre_commit_guard: &ScopeBindingGuardReceipt,
    state_fence: &StateFence,
) -> Result<(ScopeTransition, TransitionStepOutcome), WorkScopeError> {
    let proposal = ScopeTransition {
        transition_ref: transition_ref.into(),
        kind,
        scope_ref: scope_ref.into(),
        related_scope_refs,
        old_generation,
        new_generation,
        affected_record_refs,
        authority_refs,
        pre_commit_guard: pre_commit_guard.clone(),
        state_fence: state_fence.clone(),
    };
    proposal.validate()?;
    let outcome = completed(
        ScopeTransitionStep::Propose,
        vec![proposal.transition_ref.clone()],
        "proposal admitted on MATCHED pre-check guard",
    );
    outcome.validate()?;
    Ok((proposal, outcome))
}

/// Accumulates step outcomes and builds the visible partial receipt on failure.
struct StepRunner {
    transition_ref: String,
    kind: ScopeTransitionKind,
    scope_ref: String,
    old_generation: u64,
    new_generation: u64,
    proposal_fence: StateFence,
    receipt_ref: String,
    outcomes: Vec<TransitionStepOutcome>,
}

impl StepRunner {
    fn for_proposal(proposal: &ScopeTransition, receipt_ref: String) -> Self {
        Self {
            transition_ref: proposal.transition_ref.clone(),
            kind: proposal.kind,
            scope_ref: proposal.scope_ref.clone(),
            old_generation: proposal.old_generation,
            new_generation: proposal.new_generation,
            proposal_fence: proposal.state_fence.clone(),
            receipt_ref,
            outcomes: Vec::new(),
        }
    }

    fn fail(self, step: ScopeTransitionStep, reason: WorkScopeError) -> TransitionFailure {
        let mut outcomes = self.outcomes;
        outcomes.push(failed_outcome(step, &reason));
        TransitionFailure {
            partial: Box::new(ScopeTransitionReceipt {
                receipt_ref: self.receipt_ref,
                transition_ref: self.transition_ref,
                kind: self.kind,
                revision: 1,
                scope_ref: self.scope_ref,
                old_generation: self.old_generation,
                new_generation: self.new_generation,
                step_outcomes: outcomes,
                committed: false,
                invalidated_session_refs: Vec::new(),
                staged_candidates: Vec::new(),
                boundary_evidence_refs: Vec::new(),
                post_commit_guard: None,
                readiness_reevaluation_required: false,
                state_fence: self.proposal_fence,
            }),
            failed_step: step,
            reason,
        }
    }
}

fn same_refs(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left_sorted = left.to_vec();
    let mut right_sorted = right.to_vec();
    left_sorted.sort();
    right_sorted.sort();
    left_sorted == right_sorted
}

/// Checks step 3 against the proposal: the preserved provenance must cover
/// everything later staged, or the candidate carries no old-scope lineage.
fn check_preserve_old_scope(evidence: &TransitionStepEvidence) -> Result<(), WorkScopeError> {
    let uncovered = evidence.staged_candidates.iter().any(|candidate| {
        !evidence
            .old_scope_provenance_refs
            .contains(&candidate.provenance_ref)
    });
    if uncovered {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    Ok(())
}

/// Checks step 4 against the proposal: staged records stay inside the
/// affected set, validate, and admit material effects only under a
/// non-self-referential deterministic validity transfer (I4.2.1).
fn check_stage_candidates(
    proposal: &ScopeTransition,
    evidence: &TransitionStepEvidence,
) -> Result<(), WorkScopeError> {
    let staged_outside_scope = evidence.staged_candidates.iter().any(|candidate| {
        !proposal
            .affected_record_refs
            .contains(&candidate.record_ref)
    });
    if staged_outside_scope {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    for candidate in &evidence.staged_candidates {
        candidate.validate()?;
        if candidate.admits_material_effects() {
            match &candidate.standing {
                CandidateRecordStanding::ValidityTransferred { transfer_ref }
                    if transfer_ref != &candidate.record_ref
                        && transfer_ref != &candidate.provenance_ref => {}
                _ => return Err(WorkScopeError::BindingReceiptMismatch),
            }
        }
    }
    Ok(())
}

/// Checks step 6 against the proposal through the existing guard legs: every
/// recorded session binding is evaluated against the new binding, and a
/// session that is still identity-clear under the new generation is not
/// incompatible — recording it as invalidated fails instead of silently
/// carrying it over or killing a live session.
fn check_invalidate_sessions(evidence: &TransitionStepEvidence) -> Result<(), WorkScopeError> {
    if evidence.invalidated_session_bindings.len() != evidence.invalidated_session_refs.len() {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let live_recorded = evidence.invalidated_session_bindings.iter().any(|session| {
        identity_legs(&evidence.new_binding, session) == IdentityLegOutcome::IdentityClear
    });
    if live_recorded {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    Ok(())
}

/// Checks step 7 against the proposal: boundary attestation for the new scope
/// is neither a killed session token nor moved data.
fn check_verify_boundaries(
    proposal: &ScopeTransition,
    evidence: &TransitionStepEvidence,
) -> Result<(), WorkScopeError> {
    let recycled = evidence.boundary_evidence_refs.iter().any(|boundary| {
        evidence.invalidated_session_refs.contains(boundary)
            || proposal.affected_record_refs.contains(boundary)
    });
    if recycled {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    Ok(())
}

/// Runs one procedure step against the proposal, recording its outcome.
///
/// Returns the failing step and reason on mismatch; completed outcomes are
/// appended to `outcomes` in procedure order.
fn run_step(
    proposal: &ScopeTransition,
    evidence: &TransitionStepEvidence,
    step: ScopeTransitionStep,
    outcomes: &mut Vec<TransitionStepOutcome>,
) -> Result<(), (ScopeTransitionStep, WorkScopeError)> {
    let failed = |reason| Err((step, reason));
    match step {
        ScopeTransitionStep::Propose => {
            return failed(WorkScopeError::BindingReceiptMismatch);
        }
        ScopeTransitionStep::IdentifyAffected => {
            if !same_refs(
                &evidence.affected_record_refs,
                &proposal.affected_record_refs,
            ) || !same_refs(&evidence.authority_refs, &proposal.authority_refs)
            {
                return failed(WorkScopeError::BindingReceiptMismatch);
            }
            outcomes.push(completed(
                step,
                evidence.affected_record_refs.clone(),
                "affected records and authority identified",
            ));
        }
        ScopeTransitionStep::PreserveOldScope => {
            check_preserve_old_scope(evidence).map_err(|reason| (step, reason))?;
            outcomes.push(completed(
                step,
                evidence.old_scope_provenance_refs.clone(),
                "old scope and provenance preserved",
            ));
        }
        ScopeTransitionStep::StageCandidates => {
            check_stage_candidates(proposal, evidence).map_err(|reason| (step, reason))?;
            outcomes.push(completed(
                step,
                evidence
                    .staged_candidates
                    .iter()
                    .map(|candidate| candidate.record_ref.clone())
                    .collect(),
                "records staged as candidates with preserved provenance",
            ));
        }
        ScopeTransitionStep::IssueNewGeneration => {
            if evidence.new_binding.scope.scope_ref != proposal.scope_ref
                || evidence.new_binding.scope.generation != proposal.new_generation
            {
                return failed(WorkScopeError::BindingReceiptMismatch);
            }
            outcomes.push(completed(
                step,
                vec![format!(
                    "{}:{}",
                    evidence.new_binding.scope.scope_ref, evidence.new_binding.scope.generation
                )],
                "new scope generation issued",
            ));
        }
        ScopeTransitionStep::InvalidateSessions => {
            check_invalidate_sessions(evidence).map_err(|reason| (step, reason))?;
            outcomes.push(completed(
                step,
                evidence.invalidated_session_refs.clone(),
                "incompatible sessions/leases invalidated via the guard",
            ));
        }
        ScopeTransitionStep::VerifyBoundaries => {
            check_verify_boundaries(proposal, evidence).map_err(|reason| (step, reason))?;
            outcomes.push(completed(
                step,
                evidence.boundary_evidence_refs.clone(),
                "new truth and access boundaries verified",
            ));
        }
        ScopeTransitionStep::CommitReceipt => {
            if evidence.commit_fence.resource_generation.value() != proposal.new_generation {
                return failed(WorkScopeError::StateFenceMismatch);
            }
            outcomes.push(completed(
                step,
                vec![format!(
                    "fence:{}",
                    evidence.commit_fence.resource_generation.value()
                )],
                "receipt committed on the canonical transition path",
            ));
        }
    }
    Ok(())
}

fn remaining_steps(completed_prefix: usize) -> Vec<ScopeTransitionStep> {
    (completed_prefix + 1..=usize::from(TRANSITION_STEP_COUNT))
        .filter_map(ScopeTransitionStep::from_number)
        .collect()
}

/// Assembles the final receipt after all eight steps complete.
fn assemble_committed(
    runner: &StepRunner,
    evidence: &TransitionStepEvidence,
    revision: u64,
) -> Result<ScopeTransitionReceipt, WorkScopeError> {
    let receipt = ScopeTransitionReceipt {
        receipt_ref: runner.receipt_ref.clone(),
        transition_ref: runner.transition_ref.clone(),
        kind: runner.kind,
        revision,
        scope_ref: runner.scope_ref.clone(),
        old_generation: runner.old_generation,
        new_generation: runner.new_generation,
        step_outcomes: runner.outcomes.clone(),
        committed: true,
        invalidated_session_refs: evidence.invalidated_session_refs.clone(),
        staged_candidates: evidence.staged_candidates.clone(),
        boundary_evidence_refs: evidence.boundary_evidence_refs.clone(),
        post_commit_guard: None,
        readiness_reevaluation_required: true,
        state_fence: evidence.commit_fence.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Runs steps 2–8 of the I4.7 procedure over caller-supplied evidence.
///
/// Step 1 must already be recorded by [`propose_transition`]; its outcome is
/// the required `propose_outcome`. Each step is checked against the proposal
/// in procedure order and its outcome is recorded; the first mismatch returns
/// [`TransitionFailure`] with the visible partial receipt. Step 8 binds the
/// commit fence at the new generation and marks the receipt committed with
/// readiness re-evaluation required (the post-transition state re-enters #1789
/// `assess_material_readiness`; the old receipt's fence/generation no longer
/// binds, so `evaluate_material_request` denies with re-evaluation until
/// recompilation).
///
/// # Errors
///
/// Returns [`TransitionFailure`] when the proposal or step-1 outcome is
/// malformed, any step's evidence disagrees with the proposal, the new binding
/// is not issued at the new generation, or the commit fence is not bound to
/// the new generation.
pub fn execute_transition(
    proposal: &ScopeTransition,
    propose_outcome: &TransitionStepOutcome,
    receipt_ref: impl Into<String>,
    evidence: &TransitionStepEvidence,
) -> Result<ScopeTransitionReceipt, TransitionFailure> {
    let receipt_ref: String = receipt_ref.into();
    if let Err(reason) = proposal.validate() {
        return Err(StepRunner::for_proposal(proposal, receipt_ref)
            .fail(ScopeTransitionStep::Propose, reason));
    }
    let mut runner = StepRunner::for_proposal(proposal, receipt_ref);
    if propose_outcome.step != ScopeTransitionStep::Propose || !propose_outcome.completed {
        return Err(runner.fail(
            ScopeTransitionStep::Propose,
            WorkScopeError::BindingReceiptMismatch,
        ));
    }
    runner.outcomes.push(propose_outcome.clone());
    if let Err(reason) = evidence.validate() {
        return Err(runner.fail(ScopeTransitionStep::IdentifyAffected, reason));
    }
    for step in remaining_steps(1) {
        if let Err((failed_step, reason)) = run_step(proposal, evidence, step, &mut runner.outcomes)
        {
            return Err(runner.fail(failed_step, reason));
        }
    }
    match assemble_committed(&runner, evidence, 1) {
        Ok(receipt) => Ok(receipt),
        Err(reason) => Err(runner.fail(ScopeTransitionStep::CommitReceipt, reason)),
    }
}

/// Resumes an interrupted saga under a new revision.
///
/// The caller retains the original `proposal`; the partial receipt must name
/// it, and fresh caller evidence is checked against the proposal exactly as in
/// [`execute_transition`]. Outcomes already recorded are preserved verbatim
/// and the revision advances by one. A committed receipt is never resumed: it
/// is returned intact inside the failure.
///
/// # Errors
///
/// Returns [`TransitionFailure`] when the proposal or partial receipt is
/// malformed, the partial receipt does not belong to the proposal or is
/// already committed, or any remaining step's evidence fails.
pub fn resume_transition(
    proposal: &ScopeTransition,
    partial: &ScopeTransitionReceipt,
    evidence: &TransitionStepEvidence,
) -> Result<ScopeTransitionReceipt, TransitionFailure> {
    let receipt_ref = partial.receipt_ref.clone();
    if let Err(reason) = proposal.validate() {
        return Err(StepRunner::for_proposal(proposal, receipt_ref)
            .fail(ScopeTransitionStep::Propose, reason));
    }
    let mut runner = StepRunner::for_proposal(proposal, receipt_ref);
    let belongs = partial.transition_ref == proposal.transition_ref
        && partial.kind == proposal.kind
        && partial.scope_ref == proposal.scope_ref
        && partial.old_generation == proposal.old_generation
        && partial.new_generation == proposal.new_generation;
    if !belongs || partial.committed || partial.validate().is_err() {
        return Err(runner.fail(
            ScopeTransitionStep::CommitReceipt,
            WorkScopeError::BindingReceiptMismatch,
        ));
    }
    let completed_prefix = partial
        .step_outcomes
        .iter()
        .take_while(|outcome| outcome.completed)
        .count();
    if completed_prefix == 0 || completed_prefix >= TRANSITION_STEP_COUNT as usize {
        return Err(runner.fail(
            ScopeTransitionStep::CommitReceipt,
            WorkScopeError::BindingReceiptMismatch,
        ));
    }
    runner.outcomes = partial.step_outcomes[..completed_prefix].to_vec();
    if let Err(reason) = evidence.validate() {
        let next = ScopeTransitionStep::from_number(completed_prefix + 1)
            .unwrap_or(ScopeTransitionStep::CommitReceipt);
        return Err(runner.fail(next, reason));
    }
    for step in remaining_steps(completed_prefix) {
        if let Err((failed_step, reason)) = run_step(proposal, evidence, step, &mut runner.outcomes)
        {
            return Err(runner.fail(failed_step, reason));
        }
    }
    match assemble_committed(&runner, evidence, partial.revision + 1) {
        Ok(receipt) => Ok(receipt),
        Err(reason) => Err(runner.fail(ScopeTransitionStep::CommitReceipt, reason)),
    }
}

/// Attaches the post-commit guard revalidation to a committed receipt.
///
/// Requires a MATCHED guard receipt bound to the new generation: a task bound
/// to the old generation cannot act under the new scope until revalidation
/// returns MATCHED, and its pre-commit session token is rejected here (a
/// stale observed generation never matches). The receipt is consumed and a
/// new value is returned; the committed step outcomes are never mutated.
///
/// # Errors
///
/// Returns an error when the receipt is not committed or malformed, or when
/// the guard is not MATCHED on the new generation.
pub fn attach_post_commit_guard(
    receipt: ScopeTransitionReceipt,
    guard: &ScopeBindingGuardReceipt,
) -> Result<ScopeTransitionReceipt, WorkScopeError> {
    if !receipt.committed {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    receipt.validate()?;
    check_guard_matches_generation(guard, &receipt.scope_ref, receipt.new_generation)?;
    let endorsed = ScopeTransitionReceipt {
        post_commit_guard: Some(guard.clone()),
        ..receipt
    };
    endorsed.validate()?;
    Ok(endorsed)
}

/// Projects the queryable observation of a proposal plus its receipt.
///
/// Requires the receipt to name the proposal (transition, kind, scope, and
/// both generations must agree); the completed-step count is derived from the
/// recorded outcomes, so an interrupted saga observes its visible partial.
///
/// # Errors
///
/// Returns an error when the proposal or receipt is malformed or the receipt
/// does not belong to the proposal.
pub fn observe_transition(
    proposal: &ScopeTransition,
    receipt: &ScopeTransitionReceipt,
) -> Result<TransitionObservation, WorkScopeError> {
    proposal.validate()?;
    receipt.validate()?;
    if receipt.transition_ref != proposal.transition_ref
        || receipt.kind != proposal.kind
        || receipt.scope_ref != proposal.scope_ref
        || receipt.old_generation != proposal.old_generation
        || receipt.new_generation != proposal.new_generation
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let completed_steps = u8::try_from(
        receipt
            .step_outcomes
            .iter()
            .take_while(|outcome| outcome.completed)
            .count(),
    )
    .map_err(|_| WorkScopeError::BindingReceiptMismatch)?;
    let observation = TransitionObservation {
        transition_ref: proposal.transition_ref.clone(),
        receipt_ref: receipt.receipt_ref.clone(),
        kind: proposal.kind,
        scope_ref: proposal.scope_ref.clone(),
        old_generation: proposal.old_generation,
        new_generation: proposal.new_generation,
        completed_steps,
        total_steps: TRANSITION_STEP_COUNT,
        committed: receipt.committed,
        readiness_reevaluation_required: receipt.readiness_reevaluation_required,
    };
    observation.validate()?;
    Ok(observation)
}

/// Endorses a committed receipt with the post-commit guard and projects its
/// observation.
///
/// This is the production endorse-and-observe composition of the transition
/// surface: [`ScopeTransition::drive`] and [`ScopeTransition::resume_interrupted`]
/// run it after commit, so the MATCHED revalidation on the new generation
/// ([`attach_post_commit_guard`]) and the queryable projection
/// ([`observe_transition`]) execute in product code, not only in fixtures.
///
/// A failure carries the committed receipt inside [`TransitionFailure`]
/// (failed step [`ScopeTransitionStep::CommitReceipt`]): the commit stands,
/// endorsement or observation is retried, the receipt is never resumed.
///
/// # Errors
///
/// Returns [`TransitionFailure`] when the post-commit guard is not MATCHED
/// on the new generation or the observation projection is malformed.
pub fn endorse_and_observe(
    proposal: &ScopeTransition,
    receipt: ScopeTransitionReceipt,
    post_commit_guard: &ScopeBindingGuardReceipt,
) -> Result<(ScopeTransitionReceipt, TransitionObservation), TransitionFailure> {
    let retained = receipt.clone();
    let endorsed = attach_post_commit_guard(receipt, post_commit_guard).map_err(|reason| {
        TransitionFailure {
            partial: Box::new(retained),
            failed_step: ScopeTransitionStep::CommitReceipt,
            reason,
        }
    })?;
    let committed = endorsed.clone();
    let observation =
        observe_transition(proposal, &endorsed).map_err(|reason| TransitionFailure {
            partial: Box::new(committed),
            failed_step: ScopeTransitionStep::CommitReceipt,
            reason,
        })?;
    Ok((endorsed, observation))
}

impl ScopeTransition {
    /// Drives this proposal from admission to endorsed, observed receipt.
    ///
    /// This is the intra-crate production caller of the transition surface:
    /// it re-admits the proposal through [`propose_transition`] (step 1),
    /// runs [`execute_transition`] (steps 2–8),
    /// [`attach_post_commit_guard`] (MATCHED revalidation on the new
    /// generation), and [`observe_transition`] in product code, outside test
    /// fixtures. The Governor transition driver is the intended external
    /// caller: it builds the proposal, supplies the caller-observed step
    /// evidence and the MATCHED post-commit guard on the new generation, and
    /// retains the returned receipt.
    ///
    /// On interruption the [`TransitionFailure`] carries the visible partial:
    /// resume it with [`ScopeTransition::resume_interrupted`] and fresh
    /// evidence under a new revision. A post-commit failure carries the
    /// committed receipt (failed step [`ScopeTransitionStep::CommitReceipt`]):
    /// the commit stands and endorsement is retried, never resumed.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionFailure`] when the proposal is malformed, any
    /// step's evidence disagrees with the proposal, the commit fence is not
    /// bound to the new generation, or post-commit endorsement/observation
    /// fails.
    pub fn drive(
        &self,
        receipt_ref: impl Into<String>,
        evidence: &TransitionStepEvidence,
        post_commit_guard: &ScopeBindingGuardReceipt,
    ) -> Result<(ScopeTransitionReceipt, TransitionObservation), TransitionFailure> {
        let receipt_ref: String = receipt_ref.into();
        let (proposal, propose_outcome) = propose_transition(
            self.transition_ref.clone(),
            self.kind,
            self.scope_ref.clone(),
            self.related_scope_refs.clone(),
            self.old_generation,
            self.new_generation,
            self.affected_record_refs.clone(),
            self.authority_refs.clone(),
            &self.pre_commit_guard,
            &self.state_fence,
        )
        .map_err(|reason| {
            StepRunner::for_proposal(self, receipt_ref.clone())
                .fail(ScopeTransitionStep::Propose, reason)
        })?;
        let receipt = execute_transition(&proposal, &propose_outcome, receipt_ref, evidence)?;
        endorse_and_observe(&proposal, receipt, post_commit_guard)
    }

    /// Resumes an interrupted saga in product code and drives it to an
    /// endorsed, observed receipt.
    ///
    /// This is the intra-crate production caller of [`resume_transition`]:
    /// the visible partial from a [`TransitionFailure`] continues after its
    /// last completed step under a new revision, then endorses and observes
    /// exactly like [`ScopeTransition::drive`]. The caller retains the
    /// original proposal and supplies fresh evidence for the remaining steps;
    /// a committed receipt is never resumed.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionFailure`] when the proposal or partial receipt is
    /// malformed, the partial does not belong to the proposal or is already
    /// committed, any remaining step's evidence fails, or post-commit
    /// endorsement/observation fails (carrying the committed receipt for
    /// endorsement retry).
    pub fn resume_interrupted(
        &self,
        partial: &ScopeTransitionReceipt,
        evidence: &TransitionStepEvidence,
        post_commit_guard: &ScopeBindingGuardReceipt,
    ) -> Result<(ScopeTransitionReceipt, TransitionObservation), TransitionFailure> {
        let receipt = resume_transition(self, partial, evidence)?;
        endorse_and_observe(self, receipt, post_commit_guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrivacyClass, ScopeIdentity, ScopeKind};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch() -> EpochId {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(value) => value,
            Err(error) => panic!("lineage fixture is invalid: {error}"),
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("epoch sequence fixture is invalid");
        };
        match EpochId::new(lineage, sequence) {
            Ok(value) => value,
            Err(error) => panic!("epoch fixture is invalid: {error}"),
        }
    }

    fn fence_at(generation: u64) -> StateFence {
        let resource = match ResourceGeneration::new(generation) {
            Ok(value) => value,
            Err(error) => panic!("generation fixture is invalid: {error}"),
        };
        StateFence::new(test_epoch(), resource)
    }

    fn matched_guard(generation: u64) -> ScopeBindingGuardReceipt {
        ScopeBindingGuardReceipt {
            expected_scope_ref: "scope:one".into(),
            observed_scope_ref: "scope:one".into(),
            expected_lineage_ref: Some("lineage:one".into()),
            observed_lineage_ref: Some("lineage:one".into()),
            expected_instance_ref: "instance:a".into(),
            observed_instance_ref: "instance:a".into(),
            disposition: ScopeBindingDisposition::Matched,
            source_generation: generation,
        }
    }

    fn staged(record: &str) -> StagedCandidateRecord {
        StagedCandidateRecord {
            record_ref: record.into(),
            provenance_ref: "provenance:old".into(),
            standing: CandidateRecordStanding::Candidate,
        }
    }

    fn new_scope_binding(generation: u64) -> ScopeBinding {
        ScopeBinding {
            scope: ScopeIdentity {
                scope_ref: "scope:one".into(),
                kind: ScopeKind::GitRepo,
                lineage_ref: Some("lineage:one".into()),
                instance_ref: "instance:a".into(),
                root_identity: "root:a".into(),
                generation,
            },
            privacy_class: PrivacyClass::Internal,
            governing_source_generation: generation,
        }
    }

    fn propose_move() -> (ScopeTransition, TransitionStepOutcome) {
        match propose_transition(
            "transition:one",
            ScopeTransitionKind::Move,
            "scope:one",
            vec!["scope:two".into()],
            1,
            2,
            vec!["record:one".into()],
            vec!["authority:one".into()],
            &matched_guard(1),
            &fence_at(1),
        ) {
            Ok(value) => value,
            Err(error) => panic!("proposal fixture is invalid: {error}"),
        }
    }

    fn evidence() -> TransitionStepEvidence {
        TransitionStepEvidence {
            affected_record_refs: vec!["record:one".into()],
            authority_refs: vec!["authority:one".into()],
            old_scope_provenance_refs: vec!["provenance:old".into()],
            staged_candidates: vec![staged("record:one")],
            new_binding: new_scope_binding(2),
            invalidated_session_refs: vec!["session:old".into()],
            invalidated_session_bindings: vec![new_scope_binding(1)],
            boundary_evidence_refs: vec!["boundary:one".into()],
            commit_fence: fence_at(2),
        }
    }

    fn execute_receipt(receipt_ref: &str) -> ScopeTransitionReceipt {
        let (proposal, outcome) = propose_move();
        match execute_transition(&proposal, &outcome, receipt_ref, &evidence()) {
            Ok(receipt) => receipt,
            Err(failure) => panic!("transition execution failed: {:?}", failure.reason),
        }
    }

    #[test]
    fn eight_steps_cover_the_procedure_in_order() {
        assert_eq!(TRANSITION_STEP_COUNT, 8);
        let steps = [
            ScopeTransitionStep::Propose,
            ScopeTransitionStep::IdentifyAffected,
            ScopeTransitionStep::PreserveOldScope,
            ScopeTransitionStep::StageCandidates,
            ScopeTransitionStep::IssueNewGeneration,
            ScopeTransitionStep::InvalidateSessions,
            ScopeTransitionStep::VerifyBoundaries,
            ScopeTransitionStep::CommitReceipt,
        ];
        for (index, step) in steps.iter().enumerate() {
            let number = index + 1;
            assert_eq!(usize::from(step.number()), number);
            assert!(!step.label().is_empty());
            assert_eq!(ScopeTransitionStep::from_number(number), Some(*step));
        }
        assert_eq!(ScopeTransitionStep::from_number(0), None);
        assert_eq!(ScopeTransitionStep::from_number(9), None);
    }

    #[test]
    fn move_proposal_rejects_counterpart_and_guard_mismatch() {
        assert!(matches!(
            propose_transition(
                "transition:bad",
                ScopeTransitionKind::Expand,
                "scope:one",
                vec!["scope:two".into()],
                1,
                2,
                vec!["record:one".into()],
                vec!["authority:one".into()],
                &matched_guard(1),
                &fence_at(1),
            ),
            Err(WorkScopeError::BindingReceiptMismatch)
        ));
        assert!(matches!(
            propose_transition(
                "transition:bad",
                ScopeTransitionKind::Move,
                "scope:one",
                Vec::new(),
                1,
                2,
                vec!["record:one".into()],
                vec!["authority:one".into()],
                &matched_guard(1),
                &fence_at(1),
            ),
            Err(WorkScopeError::EmptyCollection { .. })
        ));
        let mut stale_guard = matched_guard(1);
        stale_guard.disposition = ScopeBindingDisposition::DifferentInstance;
        assert!(matches!(
            propose_transition(
                "transition:bad",
                ScopeTransitionKind::Move,
                "scope:one",
                vec!["scope:two".into()],
                1,
                2,
                vec!["record:one".into()],
                vec!["authority:one".into()],
                &stale_guard,
                &fence_at(1),
            ),
            Err(WorkScopeError::BindingReceiptNotMatched)
        ));
        assert!(matches!(
            propose_transition(
                "transition:bad",
                ScopeTransitionKind::Move,
                "scope:one",
                vec!["scope:two".into()],
                1,
                2,
                vec!["record:one".into()],
                vec!["authority:one".into()],
                &matched_guard(2),
                &fence_at(1),
            ),
            Err(WorkScopeError::BindingReceiptMismatch)
        ));
    }

    #[test]
    fn execute_transition_commits_all_eight_steps() {
        let (proposal, outcome) = propose_move();
        let receipt = match execute_transition(&proposal, &outcome, "receipt:one", &evidence()) {
            Ok(receipt) => receipt,
            Err(failure) => panic!("transition execution failed: {:?}", failure.reason),
        };
        assert!(receipt.committed);
        assert_eq!(receipt.revision, 1);
        assert_eq!(receipt.step_outcomes.len(), 8);
        for (index, step_outcome) in receipt.step_outcomes.iter().enumerate() {
            assert!(step_outcome.completed);
            assert_eq!(usize::from(step_outcome.step.number()), index + 1);
        }
        assert!(receipt.readiness_reevaluation_required);
        assert_eq!(receipt.invalidated_session_refs, vec!["session:old"]);
        assert!(!receipt.boundary_evidence_refs.is_empty());
        match receipt.validate() {
            Ok(()) => (),
            Err(error) => panic!("committed receipt is invalid: {error}"),
        }
        let observation = match observe_transition(&proposal, &receipt) {
            Ok(observation) => observation,
            Err(error) => panic!("transition observation failed: {error}"),
        };
        assert_eq!(observation.completed_steps, 8);
        assert!(observation.committed);
    }

    #[test]
    fn mismatched_records_fail_closed_with_visible_partial() {
        let (proposal, outcome) = propose_move();
        let mut bad = evidence();
        bad.affected_record_refs = vec!["record:other".into()];
        let Err(failure) = execute_transition(&proposal, &outcome, "receipt:one", &bad) else {
            panic!("mismatched records must fail the transition");
        };
        assert_eq!(failure.failed_step, ScopeTransitionStep::IdentifyAffected);
        assert!(!failure.partial.committed);
        assert_eq!(failure.partial.step_outcomes.len(), 2);
        assert!(failure.partial.step_outcomes[0].completed);
        assert_eq!(
            failure.partial.step_outcomes[0].step,
            ScopeTransitionStep::Propose
        );
        assert!(!failure.partial.step_outcomes[1].completed);
        assert_eq!(
            failure.partial.step_outcomes[1].step,
            ScopeTransitionStep::IdentifyAffected
        );
        match failure.partial.validate() {
            Ok(()) => (),
            Err(error) => panic!("partial receipt is invalid: {error}"),
        }
        let observation = match observe_transition(&proposal, &failure.partial) {
            Ok(observation) => observation,
            Err(error) => panic!("partial observation failed: {error}"),
        };
        assert_eq!(observation.completed_steps, 1);
        assert!(!observation.committed);
    }

    #[test]
    fn stale_commit_fence_fails_at_commit_with_seven_visible_steps() {
        let (proposal, outcome) = propose_move();
        let mut bad = evidence();
        bad.commit_fence = fence_at(1);
        let Err(failure) = execute_transition(&proposal, &outcome, "receipt:one", &bad) else {
            panic!("stale commit fence must fail the transition");
        };
        assert_eq!(failure.failed_step, ScopeTransitionStep::CommitReceipt);
        assert_eq!(failure.reason, WorkScopeError::StateFenceMismatch);
        let completed = failure
            .partial
            .step_outcomes
            .iter()
            .filter(|step_outcome| step_outcome.completed)
            .count();
        assert_eq!(completed, 7);
        match failure.partial.validate() {
            Ok(()) => (),
            Err(error) => panic!("partial receipt is invalid: {error}"),
        }
    }

    #[test]
    fn resume_completes_interrupted_saga_as_new_revision() {
        let (proposal, outcome) = propose_move();
        let mut bad = evidence();
        bad.commit_fence = fence_at(1);
        let Err(failure) = execute_transition(&proposal, &outcome, "receipt:one", &bad) else {
            panic!("stale commit fence must fail the transition");
        };
        let resumed = match resume_transition(&proposal, &failure.partial, &evidence()) {
            Ok(receipt) => receipt,
            Err(failure) => panic!("transition resume failed: {:?}", failure.reason),
        };
        assert!(resumed.committed);
        assert_eq!(resumed.revision, failure.partial.revision + 1);
        assert_eq!(resumed.receipt_ref, failure.partial.receipt_ref);
        assert_eq!(resumed.step_outcomes.len(), 8);
        assert!(
            resumed
                .step_outcomes
                .iter()
                .all(|step_outcome| step_outcome.completed)
        );
        match resumed.validate() {
            Ok(()) => (),
            Err(error) => panic!("resumed receipt is invalid: {error}"),
        }
        assert!(resume_transition(&proposal, &resumed, &evidence()).is_err());
    }

    #[test]
    fn staged_candidates_withhold_effects_until_validity_transfer() {
        assert!(!staged("record:one").admits_material_effects());
        let transferred = StagedCandidateRecord {
            record_ref: "record:one".into(),
            provenance_ref: "provenance:old".into(),
            standing: CandidateRecordStanding::ValidityTransferred {
                transfer_ref: "transfer:one".into(),
            },
        };
        assert!(transferred.admits_material_effects());
        match transferred.validate() {
            Ok(()) => (),
            Err(error) => panic!("transferred candidate is invalid: {error}"),
        }
        let receipt = execute_receipt("receipt:one");
        assert!(!receipt.staged_candidates.is_empty());
        assert!(
            receipt
                .staged_candidates
                .iter()
                .all(|candidate| !candidate.admits_material_effects())
        );
    }

    #[test]
    fn post_commit_guard_requires_matched_new_generation() {
        let receipt = execute_receipt("receipt:one");
        let endorsed = match attach_post_commit_guard(receipt, &matched_guard(2)) {
            Ok(endorsed) => endorsed,
            Err(error) => panic!("post-commit endorsement failed: {error}"),
        };
        assert!(endorsed.post_commit_guard.is_some());
        match endorsed.validate() {
            Ok(()) => (),
            Err(error) => panic!("endorsed receipt is invalid: {error}"),
        }
        let fresh = execute_receipt("receipt:two");
        assert!(matches!(
            attach_post_commit_guard(fresh, &matched_guard(1)),
            Err(WorkScopeError::BindingReceiptMismatch)
        ));
    }
}
