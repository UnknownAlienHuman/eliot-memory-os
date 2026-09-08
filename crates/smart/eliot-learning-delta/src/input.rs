//! Provider-neutral inputs accepted by the derivation boundary.

use eliot_contracts::{
    ArtifactId, ContractId, RequestId, SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_instrument_api::{RawEvidence, VerificationRun};
use eliot_learning_contracts::{
    AgentAttemptId, ChangeOperation, ChangeSurface, ContractBinding, InverseChange, MemberId,
    NoChangeReason, OwnerId, TargetId, ValueState, WorkScopeId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EvidenceReceipt, LearningDeltaError, SemanticOutcome, policy::RetryReason, retry::RetryContext,
};

/// Exact member selector used to resolve a before value from the supplied view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "before", content = "value", deny_unknown_fields)]
pub enum BeforeSelector {
    /// A current member whose owner/source/value identity is exact.
    CurrentMember {
        /// Recipe slot containing the member.
        slot_id: crate::SlotId,
        /// Declared member identity.
        member_id: MemberId,
        /// Owner that issued the member projection.
        owner: OwnerId,
        /// Source owner that issued the member projection.
        source_owner: SourceId,
        /// Source projection revision.
        source_revision: TaskRevision,
        /// Source snapshot identity.
        source_snapshot: ArtifactId,
        /// Source snapshot digest.
        source_digest: String,
        /// Projection revision of the selected member.
        projection_revision: TaskRevision,
    },
    /// A canonical owner-issued empty slot, suitable only for an Add.
    KnownEmpty {
        /// Empty recipe slot identity.
        slot_id: crate::SlotId,
        /// Declared owner of the empty slot.
        owner: OwnerId,
        /// Source owner that issued the empty declaration.
        source_owner: SourceId,
        /// Source snapshot of the owner's empty declaration.
        source_snapshot: ArtifactId,
        /// Source revision of the owner's empty declaration.
        source_revision: TaskRevision,
        /// Source digest of the owner's empty declaration.
        source_digest: String,
        /// Evidence proving the owner declared the slot empty.
        evidence: ArtifactId,
    },
}

fn validate_attempt_identity(input: &AttemptEvidence) -> Result<(), LearningDeltaError> {
    if input.attempt_id.as_str().trim().is_empty()
        || input.delta_id.as_str().trim().is_empty()
        || input.target.as_str().trim().is_empty()
        || input
            .pre_observation_discriminator
            .as_str()
            .trim()
            .is_empty()
        || input.intended_strategy.as_str().trim().is_empty()
        || input.attempted_strategy.as_str().trim().is_empty()
        || input.intended_strategy_evidence.as_str().trim().is_empty()
        || input.attempted_strategy_evidence.as_str().trim().is_empty()
        || input.mechanism_evidence.as_str().trim().is_empty()
        || input.probe_evidence.as_str().trim().is_empty()
        || input.action_plan_evidence.as_str().trim().is_empty()
        || input
            .pre_observation_invocation_id
            .as_str()
            .trim()
            .is_empty()
        || input.discriminator_evidence.as_str().trim().is_empty()
        || input.pre_observation_discriminator != input.discriminator_evidence
        || input.intended_strategy != input.intended_strategy_evidence
        || input.attempted_strategy != input.attempted_strategy_evidence
        || input.action_plan_fingerprint.len() != 64
        || !input
            .action_plan_fingerprint
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "attempt.identity",
        });
    }
    Ok(())
}

fn validate_secondary_bounds(
    input: &AttemptEvidence,
    policy: &crate::DerivationPolicy,
) -> Result<(), LearningDeltaError> {
    for (ids, field) in [
        (&input.baseline, "baseline"),
        (&input.control, "control"),
        (&input.confounders, "confounders"),
    ] {
        validate_unique_ids(ids, field)?;
        if u32::try_from(ids.len()).map_err(|_| LearningDeltaError::Bound { field })?
            > policy.max_references
        {
            return Err(LearningDeltaError::Bound { field });
        }
    }
    if input.retry.environment_fingerprint.trim().is_empty()
        || input.retry.environment_fingerprint == "environment:unspecified"
    {
        return Err(LearningDeltaError::InvalidInput {
            field: "environment",
        });
    }
    let stu = input
        .stu
        .ok_or(LearningDeltaError::InsufficientEvidence { field: "stu" })?;
    if stu > policy.max_stu
        || input.cost_units > policy.max_cost_units
        || input.output_units > policy.max_output_units
        || input.work_units > policy.max_work_units
    {
        return Err(LearningDeltaError::Bound {
            field: "measured_limits",
        });
    }
    for (value, field) in [
        (&input.intended_strategy_digest, "intended_strategy_digest"),
        (
            &input.attempted_strategy_digest,
            "attempted_strategy_digest",
        ),
        (&input.mechanism_fingerprint, "mechanism_fingerprint"),
        (&input.probe_fingerprint, "probe_fingerprint"),
        (&input.discriminator_digest, "discriminator_digest"),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(LearningDeltaError::InvalidInput { field });
        }
    }
    Ok(())
}

/// A typed proposed operation plus its required rollback and invalidation proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    /// Exact target selected by the immutable view recipe.
    pub target: TargetId,
    /// Recipe slot that owns the target surface.
    pub slot_id: crate::SlotId,
    /// Member changed when the slot has a member.
    pub member_id: Option<MemberId>,
    /// Exact owner selected by the recipe.
    pub owner: OwnerId,
    /// Recipe-declared accepted value type.
    pub accepted_type: String,
    /// Recipe-declared value schema digest.
    pub schema_digest: String,
    /// Closed candidate surface.
    pub surface: ChangeSurface,
    /// Exact before value selector.
    pub before: BeforeSelector,
    /// Proposed typed after value.
    pub after: ValueState,
    /// Exact inverse supplied by the local owner for rollback.
    pub rollback: InverseChange,
    /// Receipt proving invalidation is defined for this candidate.
    pub invalidation: ArtifactId,
    /// Typed dependencies required by the next compatible attempt.
    pub dependencies: Vec<ArtifactId>,
}

/// Status of one exact dependency join required by a candidate operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyStatus {
    /// Dependency is current under the supplied binding.
    Current,
    /// Dependency is absent from the declared source.
    Missing,
    /// Dependency has crossed its freshness boundary.
    Stale,
    /// Dependency has incompatible competing projections.
    Conflicted,
}

/// Typed role of a dependency reference retained by a candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "role", content = "binding", deny_unknown_fields)]
pub enum DependencyRole {
    /// Supporting input used by the operation.
    Supporting,
    /// Invalidation receipt tied to the exact mutable surface.
    Invalidation {
        /// Candidate target invalidated by the receipt.
        target: TargetId,
        /// Candidate surface invalidated by the receipt.
        surface: ChangeSurface,
        /// Owner responsible for the mutable surface.
        owner: OwnerId,
        /// Member selected by the receipt, if any.
        member_id: Option<MemberId>,
    },
}

/// Exact dependency/source join retained for preflight validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DependencyEvidence {
    /// Dependency identity referenced by a change.
    pub id: ArtifactId,
    /// Exact binding under which it was observed.
    pub binding: ContractBinding,
    /// Current source digest for the dependency.
    pub source_digest: String,
    /// Semantic role of this reference.
    pub role: DependencyRole,
    /// Explicit dependency disposition.
    pub status: DependencyStatus,
    /// Direct dependency edges used to reject cyclic closure.
    pub depends_on: Vec<ArtifactId>,
}

/// Affirmative predicates that map one-to-one to A32's closed no-change reasons.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "predicate", content = "evidence", deny_unknown_fields)]
pub enum NoChangeProof {
    /// Evaluator measured the exact frozen prediction unchanged.
    ConfirmedFixedPrediction { evaluator: ArtifactId },
    /// A compatible equivalent retry has an explicit allowed reason.
    ControlledReplicationNeeded {
        prior_evidence: ArtifactId,
        reason: RetryReason,
    },
    /// A typed protected constraint rejects the exact operation.
    ProtectedConstraint { constraint: ArtifactId },
    /// Owner evidence proves typed non-applicability or no-op.
    ProvenNonApplicability { applicability: ArtifactId },
    /// Counterevidence defeats every considered candidate mechanism.
    Contradicted { counterevidence: ArtifactId },
    /// Current policy evidence rejects the exact operation as unsafe.
    UnsafeCandidate { policy_evidence: ArtifactId },
    /// The declared owner rejected the exact operation.
    OwnerBlocked { owner_receipt: ArtifactId },
    /// An independent review requirement is current and explicit.
    ExternalReviewRequired { review_requirement: ArtifactId },
}

impl NoChangeProof {
    /// Return the corresponding closed A32 reason.
    pub const fn reason(&self) -> NoChangeReason {
        match self {
            Self::ConfirmedFixedPrediction { .. } => NoChangeReason::ConfirmedFixedPrediction,
            Self::ControlledReplicationNeeded { .. } => NoChangeReason::ControlledReplicationNeeded,
            Self::ProtectedConstraint { .. } => NoChangeReason::ProtectedConstraint,
            Self::ProvenNonApplicability { .. } => NoChangeReason::ProvenNonApplicability,
            Self::Contradicted { .. } => NoChangeReason::Contradicted,
            Self::UnsafeCandidate { .. } => NoChangeReason::UnsafeCandidate,
            Self::OwnerBlocked { .. } => NoChangeReason::OwnerBlocked,
            Self::ExternalReviewRequired { .. } => NoChangeReason::ExternalReviewRequired,
        }
    }

    /// Return the one predicate receipt that must be present in the denominator.
    pub fn evidence_id(&self) -> &ArtifactId {
        match self {
            Self::ConfirmedFixedPrediction { evaluator }
            | Self::ControlledReplicationNeeded {
                prior_evidence: evaluator,
                ..
            }
            | Self::ProtectedConstraint {
                constraint: evaluator,
            }
            | Self::ProvenNonApplicability {
                applicability: evaluator,
            }
            | Self::Contradicted {
                counterevidence: evaluator,
            }
            | Self::UnsafeCandidate {
                policy_evidence: evaluator,
            }
            | Self::OwnerBlocked {
                owner_receipt: evaluator,
            }
            | Self::ExternalReviewRequired {
                review_requirement: evaluator,
            } => evaluator,
        }
    }
}

/// A complete affirmative no-change request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoChangeRequest {
    /// Checked reason/predicate pair.
    pub proof: NoChangeProof,
    /// All considered affirmative receipts, in any input order.
    pub affirmative_evidence: Vec<ArtifactId>,
    /// Exact declared/observed evidence denominator.
    pub denominator: eliot_learning_contracts::SourceDenominator,
}

/// Immutable owner-issued declaration proving that a recipe slot is empty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerEmptyDeclaration {
    /// Receipt identity for the declaration.
    pub receipt_id: ArtifactId,
    /// Exact recipe slot declared empty.
    pub slot_id: crate::SlotId,
    /// Exact target covered by the declaration.
    pub target: TargetId,
    /// Exact semantic owner of the slot.
    pub owner: OwnerId,
    /// Full source lineage of the empty declaration.
    pub source: eliot_learning_contracts::identity::SourceLineage,
    /// Request/task/scope/fence binding of the declaration.
    pub binding: ContractBinding,
}

/// Immutable optional Refiner output; it contributes references only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefinerDraft {
    /// Draft artifact identity.
    pub artifact: ArtifactId,
    /// Route identity that produced the draft.
    pub route: String,
    /// Source receipt anchoring the draft.
    pub receipt: ArtifactId,
}

/// Lifecycle of the attempt before semantic derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptStatus {
    /// A consequential attempt reached evidence derivation.
    Consequential,
    /// The attempt was outside the learning boundary.
    NonConsequential,
    /// The attempt stopped before a semantic result.
    Cancelled,
    /// The derivation's explicit work bound was reached.
    BoundedOut,
}

/// All immutable observations needed to derive one successful A32 outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptEvidence {
    /// Shared request/task/scope/fence binding.
    pub binding: ContractBinding,
    /// Consequential attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Stable candidate identity.
    pub delta_id: ArtifactId,
    /// Target under evaluation.
    pub target: TargetId,
    /// Exact recipe used to validate the immutable view.
    pub recipe: eliot_learning_contracts::LearningStateViewRecipe,
    /// Attempt lifecycle status.
    pub status: AttemptStatus,
    /// Prediction and discriminator frozen before observation.
    pub pre_observation_discriminator: ArtifactId,
    /// Exact member selector for the fixed before state.
    pub before: BeforeSelector,
    /// Owner-issued empty declarations used by `KnownEmpty` selectors.
    pub owner_empty_declarations: Vec<OwnerEmptyDeclaration>,
    /// Expected semantic result fixed before the attempt.
    pub predicted_outcome: SemanticOutcome,
    /// Intended strategy identity.
    pub intended_strategy: ArtifactId,
    /// Attempted strategy identity.
    pub attempted_strategy: ArtifactId,
    /// Exact candidate operations, if changes are justified.
    pub changes: Vec<ChangeRequest>,
    /// Exact dependency records for every declared change dependency.
    pub dependency_evidence: Vec<DependencyEvidence>,
    /// Raw and semantic observation receipts.
    pub observations: Vec<EvidenceReceipt>,
    /// Independent evaluator receipt, if available.
    pub evaluator: Option<EvidenceReceipt>,
    /// Exact evaluator contract/run/revision predeclared by the caller.
    pub evaluator_binding: Option<EvaluatorBinding>,
    /// Positive proof for the `NoChange` arm, if selected.
    pub no_change: Option<NoChangeRequest>,
    /// Compatible prior-attempt retry context.
    pub retry: RetryContext,
    /// Optional bounded interpretation from an already-run Refiner.
    pub refiner: Option<RefinerDraft>,
    /// Baseline receipts retained independently from evaluator receipts.
    pub baseline: Vec<ArtifactId>,
    /// Control receipts retained independently from baseline.
    pub control: Vec<ArtifactId>,
    /// Confounder receipts retained independently from controls.
    pub confounders: Vec<ArtifactId>,
    /// Measured source-token units; absent values are refused by derivation.
    pub stu: Option<u32>,
    /// Measured cost units.
    pub cost_units: u32,
    /// Measured output units.
    pub output_units: u32,
    /// Measured derivation work units.
    pub work_units: u32,
    /// Canonical content identity of the intended strategy.
    pub intended_strategy_digest: String,
    /// Canonical content identity of the attempted strategy.
    pub attempted_strategy_digest: String,
    /// Canonical mechanism identity used by retry comparison.
    pub mechanism_fingerprint: String,
    /// Canonical probe identity used by retry comparison.
    pub probe_fingerprint: String,
    /// Canonical pre-observation action-plan identity used by retry comparison.
    pub action_plan_fingerprint: String,
    /// Invocation that captured the frozen pre-observation materials.
    pub pre_observation_invocation_id: RequestId,
    /// Raw artifact containing the frozen prediction discriminator.
    pub discriminator_evidence: ArtifactId,
    /// Digest of the frozen prediction discriminator material.
    pub discriminator_digest: String,
    /// Raw artifact containing intended strategy material.
    pub intended_strategy_evidence: ArtifactId,
    /// Raw artifact containing attempted strategy material.
    pub attempted_strategy_evidence: ArtifactId,
    /// Raw artifact containing mechanism material.
    pub mechanism_evidence: ArtifactId,
    /// Raw artifact containing probe material.
    pub probe_evidence: ArtifactId,
    /// Raw artifact containing the pre-observation action plan.
    pub action_plan_evidence: ArtifactId,
}

/// Exact relation between one attempt and its instrument invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptInvocationBinding {
    /// Attempt identity in the learning domain.
    pub attempt_id: AgentAttemptId,
    /// Target measured by the invocation.
    pub target: TargetId,
    /// Task identity in the contract domain.
    pub task_id: TaskId,
    /// Scope identity in the contract domain.
    pub scope: WorkScopeId,
    /// State fence captured for the invocation.
    pub state_fence: StateFence,
    /// Exact environment identity captured before execution.
    pub environment_fingerprint: String,
    /// Instrument invocation identity in the request domain.
    pub invocation_id: RequestId,
    /// Receipt which records the attempt-to-invocation relation.
    pub relation_receipt: ArtifactId,
    /// Invocation that captured pre-observation materials.
    pub pre_observation_invocation_id: RequestId,
}

/// Frozen verifier property and semantic mapping supplied by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenPropertyBinding {
    /// Exact run identity.
    pub run_id: RequestId,
    /// Invocation identity tied to the attempt.
    pub invocation_id: RequestId,
    /// Registered verifier identity.
    pub verifier: ContractId,
    /// Exact evaluated property.
    pub property: String,
    /// Exact evaluated scope.
    pub scope: String,
    /// Source revision evaluated by the run.
    pub revision: String,
    /// Semantic mapping for PASS.
    pub pass_outcome: SemanticOutcome,
    /// Semantic mapping for FAIL.
    pub fail_outcome: SemanticOutcome,
}

/// Borrowed canonical evaluation records used only during this derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationContext<'a> {
    /// Instrument-owned semantic verification run.
    pub run: &'a VerificationRun,
    /// Raw payloads referenced by the run.
    pub raw_evidence: &'a [RawEvidence],
    /// Frozen property/run binding expected by the caller.
    pub binding: &'a FrozenPropertyBinding,
    /// Exact attempt-to-invocation relation for these records.
    pub invocation: &'a AttemptInvocationBinding,
}

/// Current and optional prior borrowed evidence sidecars.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivationContext<'a> {
    /// Evidence for the current attempt.
    pub current: EvaluationContext<'a>,
    /// Evidence for the compatible prior attempt, when retrying.
    pub prior: Option<EvaluationContext<'a>>,
}

/// Exact verification identity expected from evaluator evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorBinding {
    /// Evaluation contract identity.
    pub contract_id: ContractId,
    /// Current verification run identity.
    pub run_id: RequestId,
    /// Invocation identity expected to represent this attempt.
    pub invocation_id: RequestId,
    /// Exact verifier property evaluated by the run.
    pub property: String,
    /// Exact scope evaluated by the run.
    pub scope: String,
    /// Verifier identity expected by the run.
    pub verifier: ContractId,
    /// Exact evaluated source revision.
    pub revision: String,
    /// Semantic mapping for a PASS run, frozen by policy.
    pub pass_outcome: SemanticOutcome,
    /// Semantic mapping for a FAIL run, frozen by policy.
    pub fail_outcome: SemanticOutcome,
}

impl AttemptEvidence {
    /// Validate cheap identity and collection bounds before expensive joins.
    pub fn validate_shape(
        &self,
        policy: &crate::DerivationPolicy,
    ) -> Result<(), LearningDeltaError> {
        self.binding.validate()?;
        self.recipe.validate()?;
        if self.binding.policy_revision != policy.revision {
            return Err(LearningDeltaError::EvidenceBinding {
                field: "policy_revision",
            });
        }
        validate_attempt_identity(self)?;
        if u32::try_from(self.observations.len()).map_err(|_| LearningDeltaError::Bound {
            field: "observations",
        })? > policy.max_evidence
        {
            return Err(LearningDeltaError::Bound {
                field: "observations",
            });
        }
        if u32::try_from(self.owner_empty_declarations.len()).map_err(|_| {
            LearningDeltaError::Bound {
                field: "owner_empty_declarations",
            }
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "owner_empty_declarations",
            });
        }
        let refs = self
            .observations
            .len()
            .checked_add(
                self.changes
                    .iter()
                    .try_fold(0usize, |total, change| {
                        total.checked_add(change.dependencies.len())
                    })
                    .ok_or(LearningDeltaError::Bound {
                        field: "references",
                    })?,
            )
            .ok_or(LearningDeltaError::Bound {
                field: "references",
            })?;
        if u32::try_from(refs).map_err(|_| LearningDeltaError::Bound {
            field: "references",
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "references",
            });
        }
        if u32::try_from(self.retry.prior_evidence.len()).map_err(|_| {
            LearningDeltaError::Bound {
                field: "retry.references",
            }
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "retry.references",
            });
        }
        if u32::try_from(self.retry.prior_material_evidence.len()).map_err(|_| {
            LearningDeltaError::Bound {
                field: "retry.material_references",
            }
        })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "retry.material_references",
            });
        }
        if let Some(no_change) = &self.no_change
            && u32::try_from(no_change.affirmative_evidence.len()).map_err(|_| {
                LearningDeltaError::Bound {
                    field: "no_change.evidence",
                }
            })? > policy.max_references
        {
            return Err(LearningDeltaError::Bound {
                field: "no_change.evidence",
            });
        }
        validate_secondary_bounds(self, policy)?;
        Ok(())
    }
}

/// Compute the typed operation that a resolved before value implies.
pub(crate) fn operation_from_values(
    request: &ChangeRequest,
    before: ValueState,
) -> Result<ChangeOperation, LearningDeltaError> {
    let target = request.target.clone();
    let operation = match (before.present, request.after.present) {
        (true, true) if before == request.after => {
            return Err(LearningDeltaError::InvalidInput {
                field: "change.noop",
            });
        }
        (true, true) => ChangeOperation::Replace {
            target,
            surface: request.surface,
            before,
            after: request.after.clone(),
        },
        (false, true) => ChangeOperation::Add {
            target,
            surface: request.surface,
            after: request.after.clone(),
        },
        (true, false) => ChangeOperation::Remove {
            target,
            surface: request.surface,
            before,
        },
        (false, false) => {
            return Err(LearningDeltaError::InvalidInput {
                field: "change.empty",
            });
        }
    };
    operation.validate()?;
    if !request.rollback.is_exact_inverse_of(&operation) {
        return Err(LearningDeltaError::InvalidInput {
            field: "change.rollback",
        });
    }
    Ok(operation)
}

/// Check a bounded identity list without exposing values in errors.
pub(crate) fn validate_unique_ids(
    ids: &[ArtifactId],
    field: &'static str,
) -> Result<(), LearningDeltaError> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if id.as_str().trim().is_empty() || !seen.insert(id.as_str()) {
            return Err(LearningDeltaError::InvalidInput { field });
        }
    }
    Ok(())
}
