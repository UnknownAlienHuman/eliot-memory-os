//! Governor-owned bounded memory projection (CC-008, store-deferred).
//!
//! [`project_batch`] maps admitted memory observations supplied by the
//! Governor read side into one bounded [`MemoryProjectionBatch`] under a
//! shared [`MemoryScopeBinding`]. The provider retrieves and projects; the
//! Smart evaluator decides applicability over the supplied set.
//!
//! Store read-through is deliberately absent: the observations arrive as
//! function arguments (fixtures now, the Governor read path after the MGR04
//! handoff), so this crate imports no storage, journal, credential, or
//! vendor type. There is no second graph here either: records are projected
//! field-for-field in deterministic intake order, never re-linked.
//!
//! Every observed item is accounted: projected, named in `omissions` with
//! its exact rule (scope mismatch, fence mismatch, admitted continuity the
//! projection record contract cannot carry), or named in the resume
//! `frontier` when volume truncation cuts the batch. The request
//! `denominator_total` must equal the supplied observation count plus the
//! supplied continuity observation count: this is the single-read contract,
//! and multi-page reads stay MGR04 scope.
//!
//! Continuity is enforced here, not merely offered: [`project_batch`] refuses
//! the whole read when a continuity observation breaks the I12.35 ingestion
//! rules, or when an attached workflow view does not belong to the batch
//! binding, before a single record is built. Admitted continuity then reaches
//! the denominator exactly once, so a continuity-gated read can never report a
//! denominator that quietly dropped the continuity material it was gated on.

#![forbid(unsafe_code)]

mod continuity;
pub use continuity::{admit_continuity_for_projection, admit_workflow_view_for_projection};

use eliot_contracts::{ArtifactId, SessionId, SourceId, StateFence, TaskId};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    CONTRACT_VERSION, CoverageOmission, CueTrigger, DenominatorState,
    MEMORY_PROJECTION_MAX_RECORDS, MemoryFreshness, MemoryKind, MemoryProjectionBatch,
    MemoryProjectionError, MemoryProjectionRecord, MemoryRole, MemoryScopeBinding, NegativeTrigger,
    Precondition, ProjectionCoverage, WorkflowStateView,
};
use eliot_observation_contracts::{ContinuityError, ContinuityObservation};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard ceiling on observations accepted by one projection request.
///
/// Intake beyond this ceiling fails closed so one call can never do
/// unbounded work; the read side pages across requests instead.
pub const MAX_INTAKE_OBSERVATIONS: usize = 4_096;

/// Hard ceiling on continuity observations accepted by one projection request.
///
/// Continuity intake is bounded separately from memory intake: the two are
/// different record families with different bounds. Every admitted continuity
/// observation becomes one named coverage omission, so this bound also sits
/// inside the contracts' `MAX_BATCH_OMISSIONS` bound; a combined omission
/// volume above that contract bound fails the batch closed.
pub const MAX_INTAKE_CONTINUITY_OBSERVATIONS: usize = 256;

/// Stable omission reason for a scope-triple mismatch.
pub const OMISSION_SCOPE_MISMATCH: &str = "scope-mismatch";
/// Stable omission reason for a fence incompatibility.
pub const OMISSION_FENCE_MISMATCH: &str = "fence-mismatch";
/// Stable omission reason for admitted continuity outside the record contract.
///
/// [`MemoryProjectionRecord`] carries no continuity fields, so an admitted
/// continuity observation is accounted by name and loss reason instead of
/// being projected with invented fields or dropped without a trace.
pub const OMISSION_CONTINUITY_NOT_PROJECTED: &str = "continuity-admitted-not-projected";

/// Projection failure for a memory read set.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProjectionError {
    /// The request or the projected batch is invalid.
    #[error("memory projection: {0}")]
    Contract(#[from] MemoryProjectionError),
    /// The continuity ingestion rules refused the supplied material.
    #[error("continuity ingestion: {0}")]
    Continuity(#[from] ContinuityError),
    /// The declared denominator does not equal the supplied volume.
    #[error("denominator {total} contradicts supplied volume {supplied}")]
    DenominatorContradiction {
        /// Declared canonical total.
        total: usize,
        /// Observations actually supplied.
        supplied: usize,
    },
    /// Intake exceeds the bounded-work ceiling.
    #[error("intake {supplied} exceeds bound {bound}")]
    IntakeOverBound {
        /// Observations supplied.
        supplied: usize,
        /// Intake ceiling.
        bound: usize,
    },
}

/// One Governor-admitted memory observation: the provider port.
///
/// This is the typed dependency port the Governor read side will supply
/// after the MGR04 store read-through handoff. Every field maps
/// field-for-field onto [`MemoryProjectionRecord`]; the provider adds only
/// the shared binding, the projection revision, and coverage accounting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedMemoryObservation {
    /// Exact canonical handle of the record.
    pub handle: ArtifactId,
    /// Canonical kind of the record.
    pub kind: MemoryKind,
    /// Task the record was admitted under.
    pub task_id: TaskId,
    /// Scope the record was admitted under.
    pub scope_id: WorkScopeId,
    /// Session the record was admitted under, when session-bound.
    pub session_id: Option<SessionId>,
    /// Fence the record was admitted under.
    pub state_fence: StateFence,
    /// Epistemic status at admission.
    pub epistemic: EpistemicStatus,
    /// Assertability ceiling at admission.
    pub assertability: Assertability,
    /// Lifecycle state at admission.
    pub lifecycle: LifecycleState,
    /// Freshness statement at admission.
    pub freshness: MemoryFreshness,
    /// Exact source and route lineage.
    pub provenance: Provenance,
    /// Prior record in the immutable lineage, when retained.
    pub predecessor: Option<ArtifactId>,
    /// Influence roles at admission.
    pub roles: Vec<MemoryRole>,
    /// Whether the record is eligible for downstream influence at all.
    pub influence_eligible: bool,
    /// Declared procedure preconditions with owner assessment.
    pub preconditions: Vec<Precondition>,
    /// Declared applicability limits, where relevant.
    pub applicability_limits: Vec<String>,
    /// Exact cue trigger metadata.
    pub cue_triggers: Vec<CueTrigger>,
    /// Negative-memory trigger metadata, for failure records.
    pub negative_trigger: Option<NegativeTrigger>,
    /// Canonical source identity of the record.
    pub source_id: SourceId,
}

/// Bounded projection request over admitted observations.
///
/// The request is the provider intake port: continuity evidence travels with
/// the memory records it was captured beside, so gating one and dropping the
/// other at the boundary is not expressible. The material is owned, not
/// borrowed, so the request stays one serializable, deserializable, and
/// schema-described value the Governor read side can carry on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequest {
    /// Shared binding every projected record must satisfy.
    pub binding: MemoryScopeBinding,
    /// Projection revision assigned to every projected record.
    pub projection_revision: u64,
    /// Canonical records observed by the read side; must equal the supplied
    /// observation count plus the supplied continuity observation count
    /// (single-read contract).
    pub denominator_total: usize,
    /// Admitted observations in deterministic read order.
    pub observations: Vec<AdmittedMemoryObservation>,
    /// Admitted continuity observations in deterministic capture order.
    ///
    /// Every entry is gated by
    /// [`admit_continuity_for_projection`](crate::admit_continuity_for_projection)
    /// and accounted in the batch denominator exactly once.
    pub continuity: Vec<ContinuityObservation>,
    /// Workflow state view travelling with this read, when one is attested.
    ///
    /// `None` means no view was supplied; it never means a view was checked
    /// and found consistent, because a supplied view that does not belong to
    /// the batch binding fails the whole read.
    pub workflow_view: Option<WorkflowStateView>,
}

impl ProjectionRequest {
    /// Validate binding shape, intake bound, and denominator equality.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        self.binding.validate()?;
        if self.observations.len() > MAX_INTAKE_OBSERVATIONS {
            return Err(ProjectionError::IntakeOverBound {
                supplied: self.observations.len(),
                bound: MAX_INTAKE_OBSERVATIONS,
            });
        }
        if self.continuity.len() > MAX_INTAKE_CONTINUITY_OBSERVATIONS {
            return Err(ProjectionError::IntakeOverBound {
                supplied: self.continuity.len(),
                bound: MAX_INTAKE_CONTINUITY_OBSERVATIONS,
            });
        }
        // Both families are canonical records the read side observed, and the
        // batch validator rejects a denominator below the projected plus
        // omitted volume, so continuity counts here rather than being free.
        let observed = self.observations.len() + self.continuity.len();
        if self.denominator_total != observed {
            return Err(ProjectionError::DenominatorContradiction {
                total: self.denominator_total,
                supplied: observed,
            });
        }
        Ok(())
    }
}

/// Project admitted observations into one bounded batch.
///
/// Scope-mismatched and fence-incompatible observations become named
/// omissions; volume beyond [`MEMORY_PROJECTION_MAX_RECORDS`] truncates
/// with a resume frontier. Continuity material is gated first: a refused
/// continuity observation, or a workflow view outside the batch binding,
/// fails the read before any record exists, so a refused input can never
/// contribute to a batch. Admitted continuity is then accounted as one named
/// omission per observation, which keeps `records.len() + omissions.len()` at
/// or below the declared denominator. The returned batch is fully validated.
pub fn project_batch(
    request: &ProjectionRequest,
) -> Result<MemoryProjectionBatch, ProjectionError> {
    request.validate()?;
    // Ordering is load-bearing: the continuity gates run before the first
    // record is built, so nothing from a refused read reaches the batch.
    admit_continuity_for_projection(&request.continuity)?;
    if let Some(view) = &request.workflow_view {
        admit_workflow_view_for_projection(view, &request.binding)?;
    }
    let mut records = Vec::new();
    let mut omissions = Vec::new();
    let mut frontier: Vec<String> = Vec::new();
    let mut truncated = false;
    for observation in &request.observations {
        if truncated {
            frontier.push(observation.handle.as_str().to_owned());
            continue;
        }
        if observation.task_id != request.binding.task_id
            || observation.scope_id != request.binding.scope_id
            || observation.session_id != request.binding.session_id
        {
            omissions.push(CoverageOmission {
                handle: observation.handle.clone(),
                reason: OMISSION_SCOPE_MISMATCH.to_owned(),
            });
            continue;
        }
        if !observation
            .state_fence
            .is_compatible_with(&request.binding.state_fence)
        {
            omissions.push(CoverageOmission {
                handle: observation.handle.clone(),
                reason: OMISSION_FENCE_MISMATCH.to_owned(),
            });
            continue;
        }
        if records.len() >= MEMORY_PROJECTION_MAX_RECORDS {
            truncated = true;
            frontier.push(observation.handle.as_str().to_owned());
            continue;
        }
        records.push(project_one(observation, request));
    }
    // Admitted continuity is accounted exactly once, in the same coverage
    // vocabulary as every other observed item. `MemoryProjectionRecord` has
    // no continuity fields, and inventing an epistemic status, kind, or
    // handle for a continuity observation would fabricate the very evidence
    // the gate just refused to fabricate, so the loss is named instead. The
    // handle is the observation's own canonical identity, which the gate
    // already proved is non-blank and control-character free, so this
    // construction cannot invent or reject an identity.
    for observation in &request.continuity {
        let handle = ArtifactId::new(observation.observation_id.as_str())
            .map_err(MemoryProjectionError::from)
            .map_err(ProjectionError::from)?;
        omissions.push(CoverageOmission {
            handle,
            reason: OMISSION_CONTINUITY_NOT_PROJECTED.to_owned(),
        });
    }
    let batch = MemoryProjectionBatch {
        contract_version: CONTRACT_VERSION,
        binding: request.binding.clone(),
        records,
        coverage: ProjectionCoverage {
            denominator: DenominatorState::Known {
                total: request.denominator_total,
            },
            truncated,
            frontier,
            omissions,
            revalidation_required: false,
        },
    };
    // Revalidation is required exactly when the batch is lossy; the batch
    // validator enforces the implication, so set the flag first.
    let mut batch = batch;
    batch.coverage.revalidation_required =
        batch.coverage.truncated || !batch.coverage.omissions.is_empty();
    batch.validate()?;
    Ok(batch)
}

/// Map one admitted observation field-for-field onto a record.
fn project_one(
    observation: &AdmittedMemoryObservation,
    request: &ProjectionRequest,
) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        contract_version: CONTRACT_VERSION,
        handle: observation.handle.clone(),
        kind: observation.kind,
        binding: request.binding.clone(),
        state_fence: observation.state_fence.clone(),
        projection_revision: request.projection_revision,
        epistemic: observation.epistemic,
        assertability: observation.assertability,
        lifecycle: observation.lifecycle,
        freshness: observation.freshness.clone(),
        provenance: observation.provenance.clone(),
        predecessor: observation.predecessor.clone(),
        roles: observation.roles.clone(),
        influence_eligible: observation.influence_eligible,
        preconditions: observation.preconditions.clone(),
        applicability_limits: observation.applicability_limits.clone(),
        cue_triggers: observation.cue_triggers.clone(),
        negative_trigger: observation.negative_trigger.clone(),
        source_id: observation.source_id.clone(),
    }
}
