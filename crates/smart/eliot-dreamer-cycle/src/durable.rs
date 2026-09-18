//! Pure durable job state machine over one Dreamer job.
//!
//! The one-step cycle controller (`step_dreamer_cycle`) owns a single adjacent
//! phase transition. This module owns the orthogonal durable concern: the
//! job-level lifecycle from admission to acknowledgement (or to an explicit
//! cancelled/failed/blocked boundary), the at-most-once operation ledger, the
//! monotone progress measure, and restart/reconciliation semantics.
//!
//! The machine never re-validates owner receipts. Stage completion enters only
//! as an adapter-supplied cycle-receipt digest that the cycle controller has
//! already accepted; the digest is opaque here and is never inferred from
//! liveness, time, logs, model output, or adapter prose. All time is injected
//! inside events. There is no clock, randomness, I/O, Store, provider, model,
//! authority, canonical write, external effect, or task Finish anywhere in
//! this module.

#![allow(clippy::unnecessary_wraps)]

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{DreamJobInput, JobClass};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::{is_digest, validate_text};
use crate::error::CycleError;

/// Version of the durable job wire shape.
pub const DURABLE_SCHEMA_VERSION: u32 = 1;
/// Maximum settled operations retained in the at-most-once ledger.
pub const MAX_SETTLED_OPERATIONS: usize = 64;
/// Consecutive no-progress events tolerated before the job parks in
/// [`DurablePhase::Blocked`].
pub const MAX_NO_PROGRESS: u32 = 8;
/// Maximum commands emitted by one durable transition.
pub const MAX_DURABLE_COMMANDS: usize = 1;

/// One durable stage of a Dreamer job.
///
/// Stages are coarser than [`crate::contract::CyclePhase`]: they name the
/// job-level lifecycle owned here, while the cycle controller owns the
/// adjacent phase mechanics underneath each stage. Delivery has no requested
/// operation; it is observed, never dispatched.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableStage {
    /// Frozen input bundle compilation.
    Bundle,
    /// Curation screening (skipped with evidence for other classes).
    Screen,
    /// Provider/model invocation; may leave a possible effect.
    Model,
    /// Grounding validation after model output.
    Grounding,
    /// Common validation before any handler dispatch.
    Validation,
    /// Exactly-one semantic handler dispatch.
    Dispatch,
    /// Result submission; may leave a possible effect before commit.
    Submission,
    /// Output delivery after the durable result commit.
    Delivery,
}

impl DurableStage {
    /// Phase that must be current before this stage may be requested.
    #[must_use]
    pub const fn predecessor_phase(self) -> DurablePhase {
        match self {
            Self::Bundle => DurablePhase::Admitted,
            Self::Screen => DurablePhase::BundleReady,
            Self::Model => DurablePhase::ScreenReady,
            Self::Grounding => DurablePhase::ModelReady,
            Self::Validation => DurablePhase::GroundingReady,
            Self::Dispatch => DurablePhase::ValidationReady,
            Self::Submission => DurablePhase::DispatchReady,
            Self::Delivery => DurablePhase::SubmissionCommitted,
        }
    }

    /// Requested phase entered when this stage starts.
    #[must_use]
    pub const fn requested_phase(self) -> Option<DurablePhase> {
        match self {
            Self::Bundle => Some(DurablePhase::BundleRequested),
            Self::Screen => Some(DurablePhase::ScreenRequested),
            Self::Model => Some(DurablePhase::ModelRequested),
            Self::Grounding => Some(DurablePhase::GroundingRequested),
            Self::Validation => Some(DurablePhase::ValidationRequested),
            Self::Dispatch => Some(DurablePhase::DispatchRequested),
            Self::Submission => Some(DurablePhase::SubmissionRequested),
            Self::Delivery => None,
        }
    }

    /// Settled phase entered when this stage completes cleanly.
    #[must_use]
    pub const fn ready_phase(self) -> Option<DurablePhase> {
        match self {
            Self::Bundle => Some(DurablePhase::BundleReady),
            Self::Screen => Some(DurablePhase::ScreenReady),
            Self::Model => Some(DurablePhase::ModelReady),
            Self::Grounding => Some(DurablePhase::GroundingReady),
            Self::Validation => Some(DurablePhase::ValidationReady),
            Self::Dispatch => Some(DurablePhase::DispatchReady),
            Self::Submission => Some(DurablePhase::SubmissionCommitted),
            Self::Delivery => Some(DurablePhase::Delivery),
        }
    }

    /// Lateral phase holding an unresolved possible effect, if representable.
    ///
    /// Only provider invocation and result submission may leave a possible
    /// effect; every other stage must settle or fail outright.
    #[must_use]
    pub const fn possible_phase(self) -> Option<DurablePhase> {
        match self {
            Self::Model => Some(DurablePhase::ModelPossible),
            Self::Submission => Some(DurablePhase::SubmissionPossible),
            Self::Bundle
            | Self::Screen
            | Self::Grounding
            | Self::Validation
            | Self::Dispatch
            | Self::Delivery => None,
        }
    }

    /// Whether the model-applicability screen runs for this job class.
    ///
    /// Screening is a Curation-class obligation. Every other class skips the
    /// screen with an explicit [`OperationOutcome::NotApplicable`] ledger
    /// entry instead of an owner operation.
    #[must_use]
    pub const fn screen_applies(job_class: JobClass) -> bool {
        matches!(job_class, JobClass::Curation)
    }
}

/// Closed durable job phases.
///
/// Requested phases hold exactly one in-flight operation. Possible phases hold
/// one operation with an unresolved possible effect. Ready phases settle their
/// stage in the ledger. Terminal phases never transition except by exact
/// replay.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurablePhase {
    /// Job admitted; no stage started.
    Admitted,
    /// Bundle compilation requested.
    BundleRequested,
    /// Bundle compilation settled.
    BundleReady,
    /// Curation screening requested.
    ScreenRequested,
    /// Curation screening settled.
    ScreenReady,
    /// Screening skipped by job class, with ledger evidence.
    ScreenNotApplicable,
    /// Provider/model invocation requested.
    ModelRequested,
    /// Provider/model outcome unknown; possible effect parked.
    ModelPossible,
    /// Provider/model invocation settled.
    ModelReady,
    /// Grounding validation requested.
    GroundingRequested,
    /// Grounding validation settled.
    GroundingReady,
    /// Common validation requested.
    ValidationRequested,
    /// Common validation settled.
    ValidationReady,
    /// Semantic handler dispatch requested.
    DispatchRequested,
    /// Semantic handler dispatch settled.
    DispatchReady,
    /// Result submission requested.
    SubmissionRequested,
    /// Result submission outcome unknown; possible effect parked.
    SubmissionPossible,
    /// Durable result commit settled.
    SubmissionCommitted,
    /// Output delivery observed.
    Delivery,
    /// External acknowledgement observed; terminal.
    Acknowledged,
    /// Cancelled with no unresolved effect; terminal.
    Cancelled,
    /// Failed with terminal evidence; terminal.
    Failed,
    /// Parked by no-progress, stale fence, or disruption; terminal.
    Blocked,
    /// Rehydrated or interrupted; the in-flight operation must be read back
    /// under the same identity before any progress.
    Reconciling,
}

impl DurablePhase {
    /// Monotone progress rank. Rankless phases preserve the stored measure.
    #[must_use]
    pub const fn rank(self) -> Option<u32> {
        match self {
            Self::Admitted => Some(0),
            Self::BundleRequested => Some(1),
            Self::BundleReady => Some(2),
            Self::ScreenRequested => Some(3),
            Self::ScreenReady | Self::ScreenNotApplicable => Some(4),
            Self::ModelRequested | Self::ModelPossible => Some(5),
            Self::ModelReady => Some(6),
            Self::GroundingRequested => Some(7),
            Self::GroundingReady => Some(8),
            Self::ValidationRequested => Some(9),
            Self::ValidationReady => Some(10),
            Self::DispatchRequested => Some(11),
            Self::DispatchReady => Some(12),
            Self::SubmissionRequested | Self::SubmissionPossible => Some(13),
            Self::SubmissionCommitted => Some(14),
            Self::Delivery => Some(15),
            Self::Acknowledged => Some(16),
            Self::Cancelled | Self::Failed | Self::Blocked | Self::Reconciling => None,
        }
    }

    /// Whether this phase ends the job; only exact replay may follow.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Acknowledged | Self::Cancelled | Self::Failed | Self::Blocked
        )
    }

    /// Whether this phase may hold an unresolved possible effect.
    #[must_use]
    pub const fn is_possible(self) -> bool {
        matches!(self, Self::ModelPossible | Self::SubmissionPossible)
    }
}

/// Terminal per-operation outcome recorded in the at-most-once ledger.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationOutcome {
    /// Stage settled cleanly.
    Ready,
    /// Durable result commit settled.
    Committed,
    /// Stage skipped by job class; no owner operation occurred.
    NotApplicable,
    /// Stage failed with terminal evidence.
    Failed,
    /// Operation cancelled before any effect.
    Cancelled,
}

/// Resolution supplied by same-operation reconciliation readback.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageResolution {
    /// The model operation completed; valid only for the model stage.
    Ready,
    /// The submission committed; valid only for the submission stage.
    Committed,
    /// The operation definitively failed.
    Failed,
    /// The operation never took effect; valid only after cancellation.
    Cancelled,
}

/// Disposition of one durable transition.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableDisposition {
    /// Progress rank advanced or a new stage operation started.
    Advanced,
    /// The exact event was already applied; state is unchanged.
    Replayed,
    /// The same operation must be read back before any progress.
    ReconciliationRequired,
    /// A typed condition parks the job; terminal.
    Blocked,
    /// A terminal phase was reached with full accounting.
    Terminal,
}

/// One in-flight stage operation. At most one exists at any time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InFlightOperation {
    /// Stable operation identity.
    pub operation_id: eliot_contracts::OperationId,
    /// Idempotency identity supplied with the request.
    pub idempotency_key: String,
    /// Stage owned by this operation.
    pub stage: DurableStage,
}

/// One settled ledger entry proving at-most-once execution per stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SettledOperation {
    /// Stable operation identity.
    pub operation_id: eliot_contracts::OperationId,
    /// Idempotency identity supplied with the request.
    pub idempotency_key: String,
    /// Stage owned by this operation.
    pub stage: DurableStage,
    /// Terminal outcome.
    pub outcome: OperationOutcome,
    /// Cycle-controller receipt digest evidencing the outcome, or `None` only
    /// when the stage was skipped as not applicable.
    pub evidence_digest: Option<String>,
}

/// Immutable durable job state consumed and returned by one step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableJobState {
    /// Exact durable schema revision.
    pub schema_version: u32,
    /// Controller-local durable job handle bound to the frozen job.
    pub job_id: String,
    /// Digest of the complete frozen [`DreamJobInput`].
    pub job_digest: String,
    /// Digest of the frozen input bundle.
    pub bundle_digest: String,
    /// Closed job class selecting stage applicability.
    pub job_class: JobClass,
    /// Optional task binding copied from the frozen job.
    pub task_id: Option<String>,
    /// Scope binding copied from the frozen job.
    pub scope_id: String,
    /// Requester identity copied from the frozen job.
    pub requester: String,
    /// Budget in abstract units copied from the frozen job.
    pub budget_units: u64,
    /// Proof ceiling; this candidate-only controller admits no stronger proof.
    pub proof_ceiling: ProofCeiling,
    /// Exact state fence.
    pub fence: StateFence,
    /// Optional injected deadline in Unix milliseconds.
    pub deadline_ms: Option<i64>,
    /// Current durable phase.
    pub phase: DurablePhase,
    /// Monotonic durable revision, bumped by every non-replay transition.
    pub revision: u32,
    /// Monotone progress measure; never decreases.
    pub progress_rank: u32,
    /// Consecutive no-progress events; capped by [`MAX_NO_PROGRESS`].
    pub no_progress_streak: u32,
    /// The single in-flight operation, if any.
    pub current_operation: Option<InFlightOperation>,
    /// Settled per-stage ledger proving at-most-once execution.
    pub settled: Vec<SettledOperation>,
    /// Whether cancellation was requested.
    pub cancel_requested: bool,
    /// Phase at which cancellation was first recorded, if any.
    pub cancel_phase: Option<DurablePhase>,
    /// Digest of the last applied event, for exact-replay detection.
    pub last_event_digest: Option<String>,
    /// Digest of the state supplied as predecessor.
    pub predecessor_digest: Option<String>,
    /// Frozen state digest.
    pub canonical_digest: String,
}

/// Request one stage operation under a fresh identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageRequest {
    /// Stage to start.
    pub stage: DurableStage,
    /// Fresh stable operation identity.
    pub operation_id: eliot_contracts::OperationId,
    /// Idempotency identity for this operation.
    pub idempotency_key: String,
}

/// Stage evidence bound to an already-accepted cycle-controller receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageEvidence {
    /// Stage the evidence settles.
    pub stage: DurableStage,
    /// Operation identity the evidence belongs to.
    pub operation_id: eliot_contracts::OperationId,
    /// Opaque digest of the accepted cycle-controller receipt.
    pub cycle_receipt_digest: String,
}

/// Same-operation reconciliation readback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StageReconciled {
    /// Operation identity read back; never a replacement identity.
    pub operation_id: eliot_contracts::OperationId,
    /// Readback resolution.
    pub resolution: StageResolution,
    /// Opaque digest of the readback evidence.
    pub readback_digest: String,
}

/// Restart rehydration proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestartEvidence {
    /// Fence of the persisted snapshot; must equal the bound fence.
    pub fence: StateFence,
    /// Revision of the persisted snapshot; must equal the live revision.
    pub revision: u32,
}

/// Observed fence that may or may not be stale.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FenceEvidence {
    /// Observed fence to compare against the bound fence.
    pub fence: StateFence,
}

/// Injected deadline observation carrying adapter-supplied time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeadlineEvidence {
    /// Adapter-observed Unix time in milliseconds; compared purely, never read.
    pub observed_time_ms: i64,
}

/// Delivery observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvidence {
    /// Opaque digest of the delivery handoff evidence.
    pub delivery_digest: String,
}

/// Acknowledgement observation, distinct from delivery and from task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AckEvidence {
    /// Opaque digest of the external acknowledgement evidence.
    pub ack_digest: String,
}

/// Closed durable event vocabulary. Every variant carries already-observed,
/// immutable evidence only; nothing is inferred inside the transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableEvent {
    /// Start one stage under a fresh operation identity.
    RequestStage(StageRequest),
    /// Settle the in-flight operation with accepted cycle evidence.
    StageReady(StageEvidence),
    /// Park a model/submission operation as a possible effect.
    StageUnknown(StageEvidence),
    /// Fail the in-flight operation with terminal evidence.
    StageFailed(StageEvidence),
    /// Resolve a parked operation under the same identity.
    Reconciled(StageReconciled),
    /// Record an owner cancellation signal.
    CancelRequested,
    /// Record an adapter-observed deadline comparison.
    DeadlineExceeded(DeadlineEvidence),
    /// Observe output delivery after the durable result commit.
    Delivered(DeliveryEvidence),
    /// Observe external acknowledgement; terminal.
    Acknowledged(AckEvidence),
    /// Prove restart from the exact persisted snapshot.
    RestartObserved(RestartEvidence),
    /// Observe a fence that must differ from the bound fence.
    StaleFenceObserved(FenceEvidence),
}

/// Request the adapter to advance one stage through the cycle controller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdvanceStageCommand {
    /// Stage to advance.
    pub stage: DurableStage,
    /// Fresh operation identity minted for this attempt.
    pub operation_id: eliot_contracts::OperationId,
    /// Idempotency identity for this attempt.
    pub idempotency_key: String,
    /// Digest of the frozen job this attempt belongs to.
    pub job_digest: String,
}

/// Request the adapter to read back one parked operation under the same
/// identity. A replacement retry is never permitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconcileCommand {
    /// Operation identity to read back.
    pub operation_id: eliot_contracts::OperationId,
    /// Stage the parked operation belongs to.
    pub stage: DurableStage,
}

/// Escalate a parked job with a bounded, non-executable reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EscalateCommand {
    /// Bounded human-readable reason; never an executable instruction.
    pub reason: String,
}

/// Closed owner-directed command vocabulary. Commands name immutable inputs
/// only; the controller executes nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableCommand {
    /// Advance one stage through the owning cycle controller.
    AdvanceStage(AdvanceStageCommand),
    /// Reconcile one parked operation under the same identity.
    ReconcileOperation(ReconcileCommand),
    /// Escalate a blocked job for owner review.
    EscalateBlocked(EscalateCommand),
}

/// Result of one deterministic durable transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableTransition {
    /// Digest of the consumed state.
    pub predecessor_digest: String,
    /// One canonical next-state candidate.
    pub next_state: DurableJobState,
    /// Finite inert commands for the owning adapter.
    pub commands: Vec<DurableCommand>,
    /// Explicit disposition of this call.
    pub disposition: DurableDisposition,
    /// Digest of the complete candidate transition.
    pub transition_digest: String,
}

/// How one transition treats the no-progress streak.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreakEffect {
    /// Progress rank advanced; the streak resets.
    Reset,
    /// Genuine lateral information; the streak is preserved.
    Keep,
    /// No material change; the streak grows toward [`MAX_NO_PROGRESS`].
    NoChange,
}

impl DurableJobState {
    /// Admits one frozen job into the durable lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the job, bundle digest, fence, or deadline
    /// binding is malformed.
    pub fn admit(
        job: &DreamJobInput,
        bundle_digest: &str,
        deadline_ms: Option<i64>,
    ) -> Result<Self, CycleError> {
        job.validate()?;
        if !is_digest(bundle_digest) {
            return Err(CycleError::IncompleteOutcome("durable.bundle_digest"));
        }
        let job_deadline = Some(job.deadline_ms);
        if deadline_ms.is_some() && job_deadline != deadline_ms {
            return Err(CycleError::BindingMismatch {
                field: "durable.deadline_ms",
                reason: "admission deadline differs from the frozen job",
            });
        }
        job.state_fence.validate()?;
        let job_id = job.job_id.clone();
        validate_text(&job_id, "durable.job_id")?;
        validate_text(&job.scope_id, "durable.scope_id")?;
        validate_text(&job.requester, "durable.requester")?;
        if let Some(task_id) = &job.task_id {
            validate_text(task_id, "durable.task_id")?;
        }
        if job.budget_units == 0 {
            return Err(CycleError::BindingMismatch {
                field: "durable.budget_units",
                reason: "budget binding copied from the frozen job is zero",
            });
        }
        let job_digest = job_digest(job)?;
        let mut state = Self {
            schema_version: DURABLE_SCHEMA_VERSION,
            job_id,
            job_digest,
            bundle_digest: bundle_digest.to_owned(),
            job_class: job.job_class,
            task_id: job.task_id.clone(),
            scope_id: job.scope_id.clone(),
            requester: job.requester.clone(),
            budget_units: job.budget_units,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            fence: job.state_fence.clone(),
            deadline_ms,
            phase: DurablePhase::Admitted,
            revision: 0,
            progress_rank: 0,
            no_progress_streak: 0,
            current_operation: None,
            settled: Vec::new(),
            cancel_requested: false,
            cancel_phase: None,
            last_event_digest: None,
            predecessor_digest: None,
            canonical_digest: String::new(),
        };
        state.seal()?;
        state.validate()?;
        Ok(state)
    }

    /// Seals the immutable state with a deterministic digest.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the state exceeds its canonical bounds.
    pub fn seal(&mut self) -> Result<(), CycleError> {
        preflight_state(self)?;
        self.canonical_digest.clear();
        let bytes =
            canonical_json_bytes(self).map_err(|error| CycleError::Encoding(error.to_string()))?;
        if bytes.len() > crate::contract::MAX_CANONICAL_BYTES {
            return Err(CycleError::Bound {
                field: "durable.canonical_bytes",
                maximum: crate::contract::MAX_CANONICAL_BYTES,
            });
        }
        self.canonical_digest = sha256_hex(&bytes);
        Ok(())
    }

    /// Validates immutable state shape, ledger coherence, and its digest.
    ///
    /// # Errors
    ///
    /// Returns a typed error describing the first violated invariant.
    pub fn validate(&self) -> Result<(), CycleError> {
        preflight_state(self)?;
        if self.schema_version != DURABLE_SCHEMA_VERSION {
            return Err(CycleError::BindingMismatch {
                field: "durable.schema_version",
                reason: "unsupported durable schema version",
            });
        }
        validate_text(&self.job_id, "durable.job_id")?;
        if let Some(task_id) = &self.task_id {
            validate_text(task_id, "durable.task_id")?;
        }
        validate_text(&self.scope_id, "durable.scope_id")?;
        validate_text(&self.requester, "durable.requester")?;
        if self.budget_units == 0 {
            return Err(CycleError::BindingMismatch {
                field: "durable.budget_units",
                reason: "budget binding copied from the frozen job is zero",
            });
        }
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(CycleError::BindingMismatch {
                field: "durable.proof_ceiling",
                reason: "candidate-only controller carries no stronger proof ceiling",
            });
        }
        if !is_digest(&self.job_digest) {
            return Err(CycleError::IncompleteOutcome("durable.job_digest"));
        }
        if !is_digest(&self.bundle_digest) {
            return Err(CycleError::IncompleteOutcome("durable.bundle_digest"));
        }
        self.fence.validate()?;
        if self.settled.len() > MAX_SETTLED_OPERATIONS {
            return Err(CycleError::Bound {
                field: "durable.settled",
                maximum: MAX_SETTLED_OPERATIONS,
            });
        }
        if self.no_progress_streak > MAX_NO_PROGRESS {
            return Err(CycleError::Bound {
                field: "durable.no_progress_streak",
                maximum: MAX_NO_PROGRESS as usize,
            });
        }
        if let Some(rank) = self.phase.rank()
            && self.progress_rank < rank
        {
            return Err(CycleError::BindingMismatch {
                field: "durable.progress_rank",
                reason: "progress measure regressed below the current phase",
            });
        }
        validate_ledger(self)?;
        validate_current(self)?;
        if self.cancel_phase.is_some() && !self.cancel_requested {
            return Err(CycleError::BindingMismatch {
                field: "durable.cancel_phase",
                reason: "cancel phase recorded without a cancel request",
            });
        }
        if let Some(digest) = &self.last_event_digest
            && !is_digest(digest)
        {
            return Err(CycleError::IncompleteOutcome("durable.last_event_digest"));
        }
        if let Some(digest) = &self.predecessor_digest
            && !is_digest(digest)
        {
            return Err(CycleError::IncompleteOutcome("durable.predecessor_digest"));
        }
        let expected = state_digest(self)?;
        if expected != self.canonical_digest {
            return Err(CycleError::IdentityConflict {
                identity: "durable.canonical_digest".to_owned(),
            });
        }
        Ok(())
    }
}

/// Performs one finite durable transition and emits only inert commands.
///
/// The two-argument form is total over the closed vocabulary: every
/// state/event pair yields exactly one canonical next state and command set,
/// or one typed error. Terminal phases answer every event with an exact
/// replay; nothing mutates.
///
/// # Errors
///
/// Returns a typed [`CycleError`] for illegal transitions, identity
/// conflicts, binding mismatches, exhausted bounds, or blocked budgets.
pub fn step_durable_job(
    current: &DurableJobState,
    event: &DurableEvent,
) -> Result<DurableTransition, CycleError> {
    preflight_event(event)?;
    current.validate()?;
    let event_digest = event_digest(event)?;
    if current.last_event_digest.as_deref() == Some(event_digest.as_str()) {
        return finish_replay(current);
    }
    if current.phase.is_terminal() {
        return Err(CycleError::PhaseViolation(
            "terminal job cannot accept divergent events",
        ));
    }
    let mut next = current.clone();
    let (mut commands, mut disposition, streak) = match event {
        DurableEvent::RequestStage(request) => apply_request_stage(current, &mut next, request),
        DurableEvent::StageReady(evidence) => apply_stage_ready(current, &mut next, evidence),
        DurableEvent::StageUnknown(evidence) => apply_stage_unknown(current, &mut next, evidence),
        DurableEvent::StageFailed(evidence) => apply_stage_failed(current, &mut next, evidence),
        DurableEvent::Reconciled(reconciled) => apply_reconciled(current, &mut next, reconciled),
        DurableEvent::CancelRequested => apply_cancel(current, &mut next),
        DurableEvent::DeadlineExceeded(evidence) => {
            apply_deadline(current, &mut next, evidence.observed_time_ms)
        }
        DurableEvent::Delivered(evidence) => apply_delivered(current, &mut next, evidence),
        DurableEvent::Acknowledged(evidence) => apply_acknowledged(current, &mut next, evidence),
        DurableEvent::RestartObserved(evidence) => apply_restart(current, &mut next, evidence),
        DurableEvent::StaleFenceObserved(evidence) => {
            apply_stale_fence(current, &mut next, evidence)
        }
    }?;
    apply_streak(&mut next, streak)?;
    if streak == StreakEffect::NoChange && next.phase == DurablePhase::Blocked {
        commands = vec![DurableCommand::EscalateBlocked(EscalateCommand {
            reason: "maximum no-progress streak exceeded".to_owned(),
        })];
        disposition = DurableDisposition::Blocked;
    }
    next.last_event_digest = Some(event_digest);
    next.revision = next
        .revision
        .checked_add(1)
        .ok_or(CycleError::BudgetBlocked)?;
    next.predecessor_digest = Some(current.canonical_digest.clone());
    next.seal()?;
    next.validate()?;
    finish_step(current, next, commands, disposition)
}

fn apply_request_stage(
    current: &DurableJobState,
    next: &mut DurableJobState,
    request: &StageRequest,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if current.cancel_requested {
        return Err(CycleError::BudgetBlocked);
    }
    if current.phase == DurablePhase::Reconciling {
        return Err(CycleError::PhaseViolation(
            "controller is reconciling; resolve the parked operation first",
        ));
    }
    if current.current_operation.is_some() {
        return Err(CycleError::PhaseViolation(
            "one stage operation is already in flight",
        ));
    }
    if request.stage == DurableStage::Delivery {
        return Err(CycleError::PhaseViolation(
            "delivery is observed, never requested",
        ));
    }
    if current
        .settled
        .iter()
        .any(|settled| settled.stage == request.stage)
    {
        return Err(CycleError::PhaseViolation(
            "stage already settled; at-most-once per stage",
        ));
    }
    if current
        .settled
        .iter()
        .any(|settled| settled.operation_id == request.operation_id)
    {
        return Err(CycleError::IdentityConflict {
            identity: request.operation_id.as_str().to_owned(),
        });
    }
    validate_text(&request.idempotency_key, "durable.idempotency_key")?;
    if request.stage == DurableStage::Model {
        match current.phase {
            DurablePhase::ScreenReady | DurablePhase::ScreenNotApplicable => {}
            _ => {
                return Err(CycleError::PhaseViolation(
                    "model requires an applicable or not-applicable screen first",
                ));
            }
        }
    } else if current.phase != request.stage.predecessor_phase() {
        return Err(CycleError::PhaseViolation(
            "stage predecessor phase is not current",
        ));
    }
    if request.stage == DurableStage::Screen && !DurableStage::screen_applies(current.job_class) {
        settle(
            next,
            request,
            OperationOutcome::NotApplicable,
            None,
            DurablePhase::ScreenNotApplicable,
        )?;
        return Ok((
            Vec::new(),
            DurableDisposition::Advanced,
            StreakEffect::Reset,
        ));
    }
    let Some(requested) = request.stage.requested_phase() else {
        return Err(CycleError::PhaseViolation("stage has no requested phase"));
    };
    next.current_operation = Some(InFlightOperation {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        stage: request.stage,
    });
    next.phase = requested;
    if let Some(rank) = requested.rank() {
        next.progress_rank = next.progress_rank.max(rank);
    }
    let command = DurableCommand::AdvanceStage(AdvanceStageCommand {
        stage: request.stage,
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        job_digest: current.job_digest.clone(),
    });
    Ok((
        vec![command],
        DurableDisposition::Advanced,
        StreakEffect::Reset,
    ))
}

fn apply_stage_ready(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &StageEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    let in_flight = require_current(current, evidence)?;
    if Some(current.phase) != evidence.stage.requested_phase() {
        return Err(CycleError::PhaseViolation(
            "ready evidence does not match the requested phase",
        ));
    }
    require_digest(
        &evidence.cycle_receipt_digest,
        "durable.cycle_receipt_digest",
    )?;
    let (outcome, ready) = if evidence.stage == DurableStage::Submission {
        (
            OperationOutcome::Committed,
            DurablePhase::SubmissionCommitted,
        )
    } else if let Some(ready) = evidence.stage.ready_phase() {
        (OperationOutcome::Ready, ready)
    } else {
        return Err(CycleError::PhaseViolation(
            "delivery readiness is observed, never evidenced here",
        ));
    };
    settle(
        next,
        &StageRequest {
            stage: in_flight.stage,
            operation_id: in_flight.operation_id.clone(),
            idempotency_key: in_flight.idempotency_key.clone(),
        },
        outcome,
        Some(evidence.cycle_receipt_digest.clone()),
        ready,
    )?;
    next.current_operation = None;
    Ok((
        Vec::new(),
        DurableDisposition::Advanced,
        StreakEffect::Reset,
    ))
}

fn apply_stage_unknown(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &StageEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    let in_flight = require_current(current, evidence)?;
    let Some(possible) = evidence.stage.possible_phase() else {
        return Err(CycleError::PhaseViolation(
            "unknown outcome is representable only for provider and submission stages",
        ));
    };
    if Some(current.phase) != evidence.stage.requested_phase() {
        return Err(CycleError::PhaseViolation(
            "unknown evidence does not match the requested phase",
        ));
    }
    require_digest(
        &evidence.cycle_receipt_digest,
        "durable.cycle_receipt_digest",
    )?;
    next.phase = possible;
    next.progress_rank = next.progress_rank.max(possible.rank().unwrap_or(0));
    let command = DurableCommand::ReconcileOperation(ReconcileCommand {
        operation_id: in_flight.operation_id.clone(),
        stage: in_flight.stage,
    });
    Ok((
        vec![command],
        DurableDisposition::ReconciliationRequired,
        StreakEffect::Keep,
    ))
}

fn apply_stage_failed(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &StageEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    let in_flight = require_current(current, evidence)?;
    let requested_matches = evidence.stage.requested_phase() == Some(current.phase);
    let possible_matches = evidence.stage.possible_phase() == Some(current.phase);
    if !requested_matches && !possible_matches {
        return Err(CycleError::PhaseViolation(
            "failure evidence does not match the in-flight phase",
        ));
    }
    require_digest(
        &evidence.cycle_receipt_digest,
        "durable.cycle_receipt_digest",
    )?;
    settle(
        next,
        &StageRequest {
            stage: in_flight.stage,
            operation_id: in_flight.operation_id.clone(),
            idempotency_key: in_flight.idempotency_key.clone(),
        },
        OperationOutcome::Failed,
        Some(evidence.cycle_receipt_digest.clone()),
        DurablePhase::Failed,
    )?;
    next.current_operation = None;
    Ok((Vec::new(), DurableDisposition::Terminal, StreakEffect::Keep))
}

fn apply_reconciled(
    current: &DurableJobState,
    next: &mut DurableJobState,
    reconciled: &StageReconciled,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    let Some(in_flight) = current.current_operation.as_ref() else {
        return Err(CycleError::PhaseViolation(
            "no operation is parked for reconciliation",
        ));
    };
    if in_flight.operation_id != reconciled.operation_id {
        return Err(CycleError::BindingMismatch {
            field: "durable.reconciled.operation_id",
            reason: "readback identity differs from the parked operation",
        });
    }
    let parked = current.phase == DurablePhase::Reconciling
        || Some(current.phase) == in_flight.stage.possible_phase();
    if !parked {
        return Err(CycleError::PhaseViolation(
            "reconciliation requires a parked or possible phase",
        ));
    }
    require_digest(&reconciled.readback_digest, "durable.readback_digest")?;
    match reconciled.resolution {
        StageResolution::Ready if in_flight.stage == DurableStage::Model => {
            let request = current_request(in_flight);
            settle(
                next,
                &request,
                OperationOutcome::Ready,
                Some(reconciled.readback_digest.clone()),
                DurablePhase::ModelReady,
            )?;
            next.current_operation = None;
            Ok((
                Vec::new(),
                DurableDisposition::Advanced,
                StreakEffect::Reset,
            ))
        }
        StageResolution::Committed if in_flight.stage == DurableStage::Submission => {
            let request = current_request(in_flight);
            settle(
                next,
                &request,
                OperationOutcome::Committed,
                Some(reconciled.readback_digest.clone()),
                DurablePhase::SubmissionCommitted,
            )?;
            next.current_operation = None;
            Ok((
                Vec::new(),
                DurableDisposition::Advanced,
                StreakEffect::Reset,
            ))
        }
        StageResolution::Failed => {
            let request = current_request(in_flight);
            settle(
                next,
                &request,
                OperationOutcome::Failed,
                Some(reconciled.readback_digest.clone()),
                DurablePhase::Failed,
            )?;
            next.current_operation = None;
            Ok((Vec::new(), DurableDisposition::Terminal, StreakEffect::Keep))
        }
        StageResolution::Cancelled if current.cancel_requested => {
            let request = current_request(in_flight);
            settle(
                next,
                &request,
                OperationOutcome::Cancelled,
                Some(reconciled.readback_digest.clone()),
                DurablePhase::Cancelled,
            )?;
            next.current_operation = None;
            if next.cancel_phase.is_none() {
                next.cancel_phase = Some(current.phase);
            }
            Ok((Vec::new(), DurableDisposition::Terminal, StreakEffect::Keep))
        }
        _ => Err(CycleError::BindingMismatch {
            field: "durable.reconciled.resolution",
            reason: "resolution is inadmissible for this stage and cancel state",
        }),
    }
}

fn apply_cancel(
    current: &DurableJobState,
    next: &mut DurableJobState,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if current.cancel_requested {
        return Ok((
            Vec::new(),
            DurableDisposition::Blocked,
            StreakEffect::NoChange,
        ));
    }
    next.cancel_requested = true;
    next.cancel_phase = Some(current.phase);
    if let Some(in_flight) = current.current_operation.clone() {
        next.phase = DurablePhase::Reconciling;
        let command = DurableCommand::ReconcileOperation(ReconcileCommand {
            operation_id: in_flight.operation_id,
            stage: in_flight.stage,
        });
        Ok((
            vec![command],
            DurableDisposition::ReconciliationRequired,
            StreakEffect::Keep,
        ))
    } else {
        next.phase = DurablePhase::Cancelled;
        Ok((Vec::new(), DurableDisposition::Terminal, StreakEffect::Keep))
    }
}

fn apply_deadline(
    current: &DurableJobState,
    next: &mut DurableJobState,
    observed_time_ms: i64,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    let Some(deadline) = current.deadline_ms else {
        return Err(CycleError::BindingMismatch {
            field: "durable.deadline_ms",
            reason: "no deadline is bound to this job",
        });
    };
    if observed_time_ms <= deadline {
        return Err(CycleError::BindingMismatch {
            field: "durable.observed_time_ms",
            reason: "observed time does not exceed the bound deadline",
        });
    }
    apply_cancel(current, next)
}

fn apply_delivered(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &DeliveryEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if current.phase != DurablePhase::SubmissionCommitted {
        return Err(CycleError::PhaseViolation(
            "delivery requires the committed submission phase",
        ));
    }
    if current.current_operation.is_some() {
        return Err(CycleError::PhaseViolation(
            "delivery requires no in-flight operation",
        ));
    }
    require_digest(&evidence.delivery_digest, "durable.delivery_digest")?;
    next.phase = DurablePhase::Delivery;
    if let Some(rank) = DurablePhase::Delivery.rank() {
        next.progress_rank = next.progress_rank.max(rank);
    }
    Ok((
        Vec::new(),
        DurableDisposition::Advanced,
        StreakEffect::Reset,
    ))
}

fn apply_acknowledged(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &AckEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if current.phase != DurablePhase::Delivery {
        return Err(CycleError::PhaseViolation(
            "acknowledgement requires the delivery phase",
        ));
    }
    require_digest(&evidence.ack_digest, "durable.ack_digest")?;
    next.phase = DurablePhase::Acknowledged;
    if let Some(rank) = DurablePhase::Acknowledged.rank() {
        next.progress_rank = next.progress_rank.max(rank);
    }
    Ok((
        Vec::new(),
        DurableDisposition::Terminal,
        StreakEffect::Reset,
    ))
}

fn apply_restart(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &RestartEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if evidence.fence != current.fence {
        return park_blocked(
            current,
            next,
            "restart under a stale fence; persisted snapshot is foreign",
        );
    }
    if evidence.revision != current.revision {
        return Err(CycleError::IdentityConflict {
            identity: "durable.restart.revision".to_owned(),
        });
    }
    if current.phase == DurablePhase::Reconciling {
        return Ok((
            Vec::new(),
            DurableDisposition::Blocked,
            StreakEffect::NoChange,
        ));
    }
    if let Some(in_flight) = current.current_operation.clone() {
        next.phase = DurablePhase::Reconciling;
        let command = DurableCommand::ReconcileOperation(ReconcileCommand {
            operation_id: in_flight.operation_id,
            stage: in_flight.stage,
        });
        Ok((
            vec![command],
            DurableDisposition::ReconciliationRequired,
            StreakEffect::Keep,
        ))
    } else {
        Ok((
            Vec::new(),
            DurableDisposition::Advanced,
            StreakEffect::NoChange,
        ))
    }
}

fn apply_stale_fence(
    current: &DurableJobState,
    next: &mut DurableJobState,
    evidence: &FenceEvidence,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    evidence.fence.validate()?;
    if evidence.fence == current.fence {
        return Err(CycleError::BindingMismatch {
            field: "durable.observed_fence",
            reason: "observed fence equals the bound fence; nothing is stale",
        });
    }
    park_blocked(current, next, "stale fence observed; job cannot continue")
}

fn park_blocked(
    current: &DurableJobState,
    next: &mut DurableJobState,
    reason: &'static str,
) -> Result<(Vec<DurableCommand>, DurableDisposition, StreakEffect), CycleError> {
    if let Some(in_flight) = current.current_operation.clone() {
        next.phase = DurablePhase::Reconciling;
        let command = DurableCommand::ReconcileOperation(ReconcileCommand {
            operation_id: in_flight.operation_id,
            stage: in_flight.stage,
        });
        return Ok((
            vec![command],
            DurableDisposition::ReconciliationRequired,
            StreakEffect::Keep,
        ));
    }
    next.phase = DurablePhase::Blocked;
    let command = DurableCommand::EscalateBlocked(EscalateCommand {
        reason: reason.to_owned(),
    });
    Ok((
        vec![command],
        DurableDisposition::Blocked,
        StreakEffect::Keep,
    ))
}

fn apply_streak(next: &mut DurableJobState, effect: StreakEffect) -> Result<(), CycleError> {
    match effect {
        StreakEffect::Reset => {
            next.no_progress_streak = 0;
            Ok(())
        }
        StreakEffect::Keep => Ok(()),
        StreakEffect::NoChange => {
            if next.no_progress_streak >= MAX_NO_PROGRESS {
                next.phase = DurablePhase::Blocked;
                return Ok(());
            }
            next.no_progress_streak = next.no_progress_streak.saturating_add(1);
            Ok(())
        }
    }
}

fn require_current<'a>(
    current: &'a DurableJobState,
    evidence: &StageEvidence,
) -> Result<&'a InFlightOperation, CycleError> {
    let Some(in_flight) = current.current_operation.as_ref() else {
        return Err(CycleError::PhaseViolation(
            "no stage operation is in flight",
        ));
    };
    if in_flight.operation_id != evidence.operation_id || in_flight.stage != evidence.stage {
        return Err(CycleError::BindingMismatch {
            field: "durable.evidence.operation",
            reason: "evidence identity differs from the in-flight operation",
        });
    }
    Ok(in_flight)
}

fn current_request(in_flight: &InFlightOperation) -> StageRequest {
    StageRequest {
        stage: in_flight.stage,
        operation_id: in_flight.operation_id.clone(),
        idempotency_key: in_flight.idempotency_key.clone(),
    }
}

fn settle(
    next: &mut DurableJobState,
    request: &StageRequest,
    outcome: OperationOutcome,
    evidence_digest: Option<String>,
    phase: DurablePhase,
) -> Result<(), CycleError> {
    if next.settled.len() >= MAX_SETTLED_OPERATIONS {
        return Err(CycleError::Bound {
            field: "durable.settled",
            maximum: MAX_SETTLED_OPERATIONS,
        });
    }
    if outcome == OperationOutcome::NotApplicable && evidence_digest.is_some() {
        return Err(CycleError::BindingMismatch {
            field: "durable.settled.evidence",
            reason: "a skipped stage carries no owner evidence",
        });
    }
    if outcome != OperationOutcome::NotApplicable && evidence_digest.is_none() {
        return Err(CycleError::IncompleteOutcome("durable.settled.evidence"));
    }
    next.settled.push(SettledOperation {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        stage: request.stage,
        outcome,
        evidence_digest,
    });
    next.phase = phase;
    if let Some(rank) = phase.rank() {
        next.progress_rank = next.progress_rank.max(rank);
    }
    Ok(())
}

fn require_digest(value: &str, field: &'static str) -> Result<(), CycleError> {
    if !is_digest(value) {
        return Err(CycleError::BindingMismatch {
            field,
            reason: "evidence digest must be lowercase sha256",
        });
    }
    Ok(())
}

fn validate_ledger(state: &DurableJobState) -> Result<(), CycleError> {
    let mut operations = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut stages = BTreeSet::new();
    for settled in &state.settled {
        let id = settled.operation_id.as_str().to_owned();
        if !operations.insert(id.clone()) {
            return Err(CycleError::IdentityConflict { identity: id });
        }
        validate_text(&settled.idempotency_key, "durable.idempotency_key")?;
        if !keys.insert(settled.idempotency_key.clone()) {
            return Err(CycleError::IdentityConflict {
                identity: settled.idempotency_key.clone(),
            });
        }
        if !stages.insert(settled.stage) {
            return Err(CycleError::PhaseViolation(
                "ledger settles one stage twice; at-most-once violated",
            ));
        }
        match &settled.evidence_digest {
            Some(digest) => require_digest(digest, "durable.settled.evidence")?,
            None if settled.outcome == OperationOutcome::NotApplicable => {}
            None => {
                return Err(CycleError::IncompleteOutcome("durable.settled.evidence"));
            }
        }
        if let Some(rank) = settled.stage.ready_phase().and_then(DurablePhase::rank)
            && state.progress_rank < rank
        {
            return Err(CycleError::BindingMismatch {
                field: "durable.progress_rank",
                reason: "progress measure regressed below a settled stage",
            });
        }
    }
    if let Some(current) = &state.current_operation {
        let id = current.operation_id.as_str().to_owned();
        if !operations.insert(id.clone()) {
            return Err(CycleError::IdentityConflict { identity: id });
        }
        validate_text(&current.idempotency_key, "durable.idempotency_key")?;
        if !keys.insert(current.idempotency_key.clone()) {
            return Err(CycleError::IdentityConflict {
                identity: current.idempotency_key.clone(),
            });
        }
        if !stages.insert(current.stage) {
            return Err(CycleError::PhaseViolation(
                "in-flight stage is already settled; at-most-once violated",
            ));
        }
    }
    validate_stage_closure(state)
}

fn validate_stage_closure(state: &DurableJobState) -> Result<(), CycleError> {
    let settled_stages: BTreeSet<DurableStage> =
        state.settled.iter().map(|settled| settled.stage).collect();
    for settled in &state.settled {
        match settled.stage {
            DurableStage::Bundle | DurableStage::Delivery => {}
            DurableStage::Screen
            | DurableStage::Grounding
            | DurableStage::Validation
            | DurableStage::Dispatch
            | DurableStage::Submission => {
                let predecessor = match settled.stage {
                    DurableStage::Screen => DurableStage::Bundle,
                    DurableStage::Grounding => DurableStage::Model,
                    DurableStage::Validation => DurableStage::Grounding,
                    DurableStage::Dispatch => DurableStage::Validation,
                    DurableStage::Submission => DurableStage::Dispatch,
                    DurableStage::Bundle | DurableStage::Delivery | DurableStage::Model => {
                        unreachable!()
                    }
                };
                if !settled_stages.contains(&predecessor) {
                    return Err(CycleError::PhaseViolation(
                        "ledger skips a predecessor stage",
                    ));
                }
            }
            DurableStage::Model => {
                if !settled_stages.contains(&DurableStage::Screen) {
                    return Err(CycleError::PhaseViolation(
                        "ledger skips a predecessor stage",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_current(state: &DurableJobState) -> Result<(), CycleError> {
    if let Some(current) = &state.current_operation {
        let coherent = match state.phase {
            DurablePhase::Reconciling | DurablePhase::Blocked => true,
            phase => {
                Some(phase) == current.stage.requested_phase()
                    || Some(phase) == current.stage.possible_phase()
            }
        };
        if !coherent {
            return Err(CycleError::PhaseViolation(
                "in-flight operation disagrees with the current phase",
            ));
        }
    } else {
        if matches!(
            state.phase,
            DurablePhase::BundleRequested
                | DurablePhase::ScreenRequested
                | DurablePhase::ModelRequested
                | DurablePhase::ModelPossible
                | DurablePhase::GroundingRequested
                | DurablePhase::ValidationRequested
                | DurablePhase::DispatchRequested
                | DurablePhase::SubmissionRequested
                | DurablePhase::SubmissionPossible
        ) {
            return Err(CycleError::IncompleteOutcome("durable.current_operation"));
        }
        if matches!(
            state.phase,
            DurablePhase::Failed | DurablePhase::Acknowledged
        ) && state.settled.is_empty()
        {
            return Err(CycleError::IncompleteOutcome("durable.settled"));
        }
    }
    if matches!(
        state.phase,
        DurablePhase::Cancelled | DurablePhase::Failed | DurablePhase::Acknowledged
    ) && state.current_operation.is_some()
    {
        return Err(CycleError::PhaseViolation(
            "terminal phase retains an in-flight operation",
        ));
    }
    Ok(())
}

fn finish_replay(current: &DurableJobState) -> Result<DurableTransition, CycleError> {
    finish_step(
        current,
        current.clone(),
        Vec::new(),
        DurableDisposition::Replayed,
    )
}

fn finish_step(
    current: &DurableJobState,
    next: DurableJobState,
    commands: Vec<DurableCommand>,
    disposition: DurableDisposition,
) -> Result<DurableTransition, CycleError> {
    if commands.len() > MAX_DURABLE_COMMANDS {
        return Err(CycleError::Bound {
            field: "durable.commands",
            maximum: MAX_DURABLE_COMMANDS,
        });
    }
    for command in &commands {
        match command {
            DurableCommand::AdvanceStage(payload) => {
                validate_text(&payload.idempotency_key, "durable.idempotency_key")?;
            }
            DurableCommand::ReconcileOperation(_) => {}
            DurableCommand::EscalateBlocked(payload) => {
                validate_text(&payload.reason, "durable.escalate.reason")?;
            }
        }
    }
    let candidate = DurableTransition {
        predecessor_digest: current.canonical_digest.clone(),
        next_state: next,
        commands,
        disposition,
        transition_digest: String::new(),
    };
    let bytes = canonical_json_bytes(&candidate)
        .map_err(|error| CycleError::Encoding(error.to_string()))?;
    if bytes.len() > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "durable.canonical_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    let mut sealed = candidate;
    sealed.transition_digest = sha256_hex(&bytes);
    Ok(sealed)
}

fn preflight_state(state: &DurableJobState) -> Result<(), CycleError> {
    if state.settled.len() > MAX_SETTLED_OPERATIONS {
        return Err(CycleError::Bound {
            field: "durable.settled",
            maximum: MAX_SETTLED_OPERATIONS,
        });
    }
    let mut total = 0usize;
    bounded_text(&state.job_id, &mut total, "durable.job_id")?;
    if let Some(task_id) = &state.task_id {
        bounded_text(task_id, &mut total, "durable.task_id")?;
    }
    bounded_text(&state.scope_id, &mut total, "durable.scope_id")?;
    bounded_text(&state.requester, &mut total, "durable.requester")?;
    bounded_text(&state.job_digest, &mut total, "durable.job_digest")?;
    bounded_text(&state.bundle_digest, &mut total, "durable.bundle_digest")?;
    bounded_text(
        &state.canonical_digest,
        &mut total,
        "durable.canonical_digest",
    )?;
    if let Some(digest) = &state.last_event_digest {
        bounded_text(digest, &mut total, "durable.last_event_digest")?;
    }
    if let Some(digest) = &state.predecessor_digest {
        bounded_text(digest, &mut total, "durable.predecessor_digest")?;
    }
    if let Some(current) = &state.current_operation {
        bounded_text(
            current.operation_id.as_str(),
            &mut total,
            "durable.operation_id",
        )?;
        bounded_text(
            &current.idempotency_key,
            &mut total,
            "durable.idempotency_key",
        )?;
    }
    for settled in &state.settled {
        bounded_text(
            settled.operation_id.as_str(),
            &mut total,
            "durable.operation_id",
        )?;
        bounded_text(
            &settled.idempotency_key,
            &mut total,
            "durable.idempotency_key",
        )?;
        if let Some(digest) = &settled.evidence_digest {
            bounded_text(digest, &mut total, "durable.settled.evidence")?;
        }
    }
    if total > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "durable.scalar_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    Ok(())
}

fn preflight_event(event: &DurableEvent) -> Result<(), CycleError> {
    let mut total = 0usize;
    match event {
        DurableEvent::RequestStage(request) => {
            bounded_text(
                request.operation_id.as_str(),
                &mut total,
                "durable.operation_id",
            )?;
            bounded_text(
                &request.idempotency_key,
                &mut total,
                "durable.idempotency_key",
            )?;
        }
        DurableEvent::StageReady(evidence)
        | DurableEvent::StageUnknown(evidence)
        | DurableEvent::StageFailed(evidence) => {
            bounded_text(
                evidence.operation_id.as_str(),
                &mut total,
                "durable.operation_id",
            )?;
            bounded_text(
                &evidence.cycle_receipt_digest,
                &mut total,
                "durable.cycle_receipt_digest",
            )?;
        }
        DurableEvent::Reconciled(reconciled) => {
            bounded_text(
                reconciled.operation_id.as_str(),
                &mut total,
                "durable.operation_id",
            )?;
            bounded_text(
                &reconciled.readback_digest,
                &mut total,
                "durable.readback_digest",
            )?;
        }
        DurableEvent::Delivered(evidence) => {
            bounded_text(
                &evidence.delivery_digest,
                &mut total,
                "durable.delivery_digest",
            )?;
        }
        DurableEvent::Acknowledged(evidence) => {
            bounded_text(&evidence.ack_digest, &mut total, "durable.ack_digest")?;
        }
        DurableEvent::CancelRequested
        | DurableEvent::DeadlineExceeded(_)
        | DurableEvent::RestartObserved(_)
        | DurableEvent::StaleFenceObserved(_) => {}
    }
    if total > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "durable.scalar_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    Ok(())
}

fn bounded_text(value: &str, total: &mut usize, field: &'static str) -> Result<(), CycleError> {
    if value.len() > crate::contract::MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(CycleError::Bound {
            field,
            maximum: crate::contract::MAX_TEXT_BYTES,
        });
    }
    *total = total.checked_add(value.len()).ok_or(CycleError::Bound {
        field: "durable.scalar_bytes",
        maximum: crate::contract::MAX_CANONICAL_BYTES,
    })?;
    if *total > crate::contract::MAX_CANONICAL_BYTES {
        return Err(CycleError::Bound {
            field: "durable.scalar_bytes",
            maximum: crate::contract::MAX_CANONICAL_BYTES,
        });
    }
    Ok(())
}

fn event_digest(event: &DurableEvent) -> Result<String, CycleError> {
    let bytes =
        canonical_json_bytes(event).map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn job_digest(job: &DreamJobInput) -> Result<String, CycleError> {
    let bytes =
        canonical_json_bytes(job).map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn state_digest(state: &DurableJobState) -> Result<String, CycleError> {
    let mut value = state.clone();
    value.canonical_digest.clear();
    let bytes =
        canonical_json_bytes(&value).map_err(|error| CycleError::Encoding(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
