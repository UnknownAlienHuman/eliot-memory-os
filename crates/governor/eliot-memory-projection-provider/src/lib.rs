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
//! its exact rule (scope mismatch, fence mismatch), or named in the resume
//! `frontier` when volume truncation cuts the batch. The request
//! `denominator_total` must equal the supplied observation count: this is
//! the single-read contract, and multi-page reads stay MGR04 scope.

#![forbid(unsafe_code)]

use eliot_contracts::{ArtifactId, SessionId, SourceId, StateFence, TaskId};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState, Provenance};
use eliot_memory_projection_contracts::{
    CONTRACT_VERSION, CoverageOmission, CueTrigger, DenominatorState,
    MEMORY_PROJECTION_MAX_RECORDS, MemoryFreshness, MemoryKind, MemoryProjectionBatch,
    MemoryProjectionError, MemoryProjectionRecord, MemoryRole, MemoryScopeBinding, NegativeTrigger,
    Precondition, ProjectionCoverage,
};
use eliot_receipts::WorkScopeId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard ceiling on observations accepted by one projection request.
///
/// Intake beyond this ceiling fails closed so one call can never do
/// unbounded work; the read side pages across requests instead.
pub const MAX_INTAKE_OBSERVATIONS: usize = 4_096;

/// Stable omission reason for a scope-triple mismatch.
pub const OMISSION_SCOPE_MISMATCH: &str = "scope-mismatch";
/// Stable omission reason for a fence incompatibility.
pub const OMISSION_FENCE_MISMATCH: &str = "fence-mismatch";

/// Projection failure for a memory read set.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProjectionError {
    /// The request or the projected batch is invalid.
    #[error("memory projection: {0}")]
    Contract(#[from] MemoryProjectionError),
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRequest {
    /// Shared binding every projected record must satisfy.
    pub binding: MemoryScopeBinding,
    /// Projection revision assigned to every projected record.
    pub projection_revision: u64,
    /// Canonical records observed by the read side; must equal the
    /// supplied observation count (single-read contract).
    pub denominator_total: usize,
    /// Admitted observations in deterministic read order.
    pub observations: Vec<AdmittedMemoryObservation>,
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
        if self.denominator_total != self.observations.len() {
            return Err(ProjectionError::DenominatorContradiction {
                total: self.denominator_total,
                supplied: self.observations.len(),
            });
        }
        Ok(())
    }
}

/// Project admitted observations into one bounded batch.
///
/// Scope-mismatched and fence-incompatible observations become named
/// omissions; volume beyond [`MEMORY_PROJECTION_MAX_RECORDS`] truncates
/// with a resume frontier. The returned batch is fully validated.
pub fn project_batch(
    request: &ProjectionRequest,
) -> Result<MemoryProjectionBatch, ProjectionError> {
    request.validate()?;
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
