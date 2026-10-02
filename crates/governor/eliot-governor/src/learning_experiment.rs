//! Governor-owned improvement-experiment producers and their eight owner seams
//! (CC-007, issue #45).
//!
//! [`eliot_learning_contracts::ImprovementExperimentCandidate`] is the
//! candidate-only third link of the #45 chain: the family owns its validation,
//! but twenty-one of its twenty-two fields had no production owner, and the
//! outer loop that produces them was never executed. This module gives every
//! field an owner at the home the canonical documentation assigns it, and
//! derives the candidate only from those owner records. It never fills a field
//! in itself.
//!
//! # Owner seams
//!
//! | Owner seam | Owner record | Experiment fields it owns |
//! |---|---|---|
//! | attribution-lineage owner (Governor use-attribution owner) | [`AttributionLineageOwnerRecord`] | `binding`, `target`, `attribution_id`, `attribution_digest` |
//! | mechanism owner (pre-registered causal mechanism) | [`MechanismOwnerRecord`] | `hypothesis`, `pre_observation_discriminator` |
//! | bounded-plan owner (`TestD`-owned bounded experiment plan + Governor proposal) | [`BoundedPlanOwnerRecord`] | `eligibility`, `intervention_id`, `control_id`, `safeguards`, `stop_conditions` |
//! | assignment owner (assignment/sampling mechanism) | [`AssignmentOwnerRecord`] | `assignment`, `assignment_seed_digest` |
//! | rollback owner (external rollback contract) | [`RollbackOwnerRecord`] | `rollback_refs` |
//! | contamination owner (prior-exposure account) | [`ContaminationOwnerRecord`] | `contamination_policy`, `prior_exposure_refs` |
//! | evidence-freeze owner (versioned proposal commitment + activation record) | [`EvidenceFreezeOwnerRecord`] | `evidence_freeze_digest`, `evidence_freeze_refs` |
//! | outcome/verifier owner (dimensioned assessment + independent activation evidence) | [`OutcomeOwnerRecord`] | `outcome_dimensions`, `claim_ceiling` |
//!
//! Each seam is an independent optional slot in [`ExperimentOwnerInput`], so an
//! owner that published nothing is named by its own typed
//! [`ExperimentRefusal::OwnerAbsent`] rather than being silently defaulted, and
//! every *content* failure travels as one of the two existing typed vocabularies
//! this seam composes: [`LearningContractError`] for the learning-contracts
//! content rules and [`PipelineError`] for the maintenance owner's own record
//! rules. No refusal is ever a string verdict or a boolean.
//!
//! # Nothing is asserted by presence
//!
//! Three bindings keep the experiment from being satisfied by shape alone:
//!
//! 1. [`ImprovementExperimentCandidate::validate_against_attribution`] re-checks
//!    the whole lineage in one fence, so an experiment separated from the
//!    attribution it consumed is
//!    [`LearningContractError::ScopeMismatch`];
//! 2. `intervention_id` and `control_id` are content-addressed over the bounded
//!    plan's intervention and control surfaces, so two different surfaces never
//!    share one identity and a self-named control is
//!    [`LearningContractError::ScopeMismatch`];
//! 3. the outcome owner requires the `SOURCE_EVALUATOR_INDEPENDENCE` dimension to
//!    carry *the independent activation record's own identity* as its owner
//!    receipt, and requires that record to carry an executed, independent,
//!    executor-distinct status — the A5.5 analogue for the outer loop. A5.5 is
//!    the governing sentence: "A Critical result requires an observation or
//!    evaluation route outside the actor's failure domain when practical;
//!    otherwise, finish remains honestly degraded."
//!
//! `NOT_OBSERVED` is never turned into a negative finding (I12.24 line 256):
//! this module reads no activation status and derives no disposition from
//! absence. Where an owner publishes nothing, the seam records typed
//! `OwnerAbsent` instead of inventing a value.
//!
//! # Boundary
//!
//! Nothing here runs an experiment, promotes, admits or delivers anything. The
//! producer is a pure function of owner records: no clock, no I/O, no live
//! query, no authority beyond the verdict it returns. A14.5 ARCH-META-01 holds:
//! "Self-improvement is advisory, isolated, and falsifiable."

use eliot_contracts::{ArtifactId, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::identity::validate_digest;
use eliot_learning_contracts::{
    AssessmentDimension, AssignmentKind, CausalCeiling, ContractBinding, DimensionAssessment,
    ImprovementExperimentCandidate, LearningAssessmentCandidate, LearningContractError, TargetId,
    UseAttributionCandidate,
};
use eliot_maintenance::{
    ActivationEvidence, ExperimentPlan, IMPROVEMENT_EFFECT_CEILING,
    IMPROVEMENT_RISK_CEILING_BOUNDED, IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
    ImprovementEvidenceExecution, ImprovementProposal, KERNEL_CANARY_OWNER, MechanismDeclaration,
    PipelineError, RollbackContract, TESTD_OWNER, VERIFIER_OWNER_FAMILY, proposal_digest,
};
use thiserror::Error;

/// Owner seam 1 — the Governor use-attribution owner.
///
/// I12.24 line 251 makes the attribution the decision owner's own downstream
/// handle, and
/// [`ImprovementExperimentCandidate::validate_against_attribution`] refuses an
/// experiment whose binding, target, attribution identity or attribution digest
/// diverges from it. So all four lineage fields are read out of the sealed
/// attribution record rather than restated here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionLineageOwnerRecord<'a> {
    /// The sealed attribution candidate this experiment consumes.
    pub attribution: &'a UseAttributionCandidate,
}

impl AttributionLineageOwnerRecord<'_> {
    /// Revalidate the attribution this experiment is bound to.
    pub fn validate(&self) -> Result<(), ExperimentRefusal> {
        Ok(self.attribution.validate()?)
    }

    /// The shared task-local scope/fence/source binding.
    #[must_use]
    pub fn binding(&self) -> ContractBinding {
        self.attribution.binding.clone()
    }

    /// The target whose decision opportunity is under experiment.
    #[must_use]
    pub fn target(&self) -> TargetId {
        self.attribution.target.clone()
    }

    /// The exact attributed-use lineage this experiment consumes.
    #[must_use]
    pub fn attribution_id(&self) -> ArtifactId {
        self.attribution.attribution_id.clone()
    }

    /// The canonical attribution digest consumed here.
    #[must_use]
    pub fn attribution_digest(&self) -> String {
        self.attribution.canonical_digest.clone()
    }
}

/// Owner seam 2 — the mechanism owner that declared the causal hypothesis.
///
/// I12.24:26 names `root_cause_hypotheses` on the outer-loop candidate, and the
/// maintenance owner's [`MechanismDeclaration`] is the pre-registered form of it:
/// `declared_before_results` must be true, because a post-hoc mechanism can
/// explain any result and therefore proves nothing. The pre-observation
/// discriminator is content-addressed over that declaration and the frozen
/// proposal commitment, so a rewritten mechanism or a rewritten proposal yields
/// a different discriminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MechanismOwnerRecord<'a> {
    /// Pre-registered causal mechanism declaration.
    pub declaration: &'a MechanismDeclaration,
    /// Governor-side proposal the mechanism was declared against.
    pub proposal: &'a ImprovementProposal,
}

impl MechanismOwnerRecord<'_> {
    /// The falsifiable hypothesis, refused unless it was pre-registered.
    pub fn hypothesis(&self) -> Result<&str, ExperimentRefusal> {
        if !self.declaration.declared_before_results {
            return Err(PipelineError::MechanismNotPredeclared.into());
        }
        if self.declaration.declared_ref.trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.pre_observation_discriminator",
            }
            .into());
        }
        Ok(self.declaration.hypothesis.as_str())
    }

    /// The discriminator frozen before any observation, by content.
    pub fn pre_observation_discriminator(&self) -> Result<ArtifactId, ExperimentRefusal> {
        self.hypothesis()?;
        content_identity(
            "experiment-discriminator",
            &[
                self.declaration.mechanism_id.as_str(),
                self.declaration.declared_ref.as_str(),
                self.declaration.causal_link.as_str(),
                proposal_commitment_digest(self.proposal)?.as_str(),
            ],
        )
    }
}

/// Owner seam 3 — the bounded-plan owner.
///
/// The [`ExperimentPlan`] is the `TestD`-owned bounded run
/// (`ImprovementOperation::ExecuteExperiment` routes to [`TESTD_OWNER`]) and the
/// [`ImprovementProposal`] is the Governor owner's own declaration of the
/// expected delta, ceilings and closure binding. A14.5's outer loop is exactly
/// this pair: "isolated candidate, fixed replay, shadow, or canary". The
/// intervention identity is the intervention surface and the control identity is
/// the control surface; they are content-addressed separately and compared, so a
/// plan whose "control" names the executor can never satisfy the contract's
/// distinct-identity rule by spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedPlanOwnerRecord<'a> {
    /// `TestD`-owned bounded experiment plan.
    pub plan: &'a ExperimentPlan,
    /// Governor-side proposal declaring the change under test.
    pub proposal: &'a ImprovementProposal,
}

impl BoundedPlanOwnerRecord<'_> {
    /// The eligibility rule, read out of the plan's own scope, budget and
    /// deadline rather than summarized in prose.
    pub fn eligibility(&self) -> Result<String, ExperimentRefusal> {
        bounded_text(
            format!(
                "scope={};budget={};deadline={}",
                self.plan.scope_ref, self.plan.budget_ref, self.plan.deadline_ref
            ),
            "experiment.eligibility",
            1024,
        )
    }

    /// The immutable intervention identity, content-addressed over the exact
    /// intervention surface the plan bounds.
    pub fn intervention_id(&self) -> Result<ArtifactId, ExperimentRefusal> {
        content_identity(
            "experiment-intervention",
            &[
                self.plan.experiment_id.as_str(),
                self.plan.operation_ref.as_str(),
                self.plan.scope_ref.as_str(),
                self.plan.budget_ref.as_str(),
                self.plan.deadline_ref.as_str(),
                self.plan.testd_owner_id.as_str(),
                // `ImprovementProposal` carries `target_capability` and
                // `target_generation`; there is no `delivery_target` member,
                // and the intervention surface is content-addressed over the
                // real ones rather than over an invented third.
                self.proposal.target_capability.as_str(),
                self.proposal.target_generation.as_str(),
            ],
        )
    }

    /// The immutable control identity, content-addressed over the control
    /// surface.
    ///
    /// I12.24's "Explicitly reject" list names "Missing control identity", and
    /// A14.5 keeps the control arm of a comparison independent of the arm that
    /// executed the intervention. A plan whose evaluator is the executor is
    /// refused here rather than being given a control identity over itself.
    pub fn control_id(&self) -> Result<ArtifactId, ExperimentRefusal> {
        if self.plan.evaluator_id.trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.control_identity",
            }
            .into());
        }
        if self.plan.evaluator_id == self.plan.testd_owner_id
            || self.plan.evaluator_id == TESTD_OWNER
        {
            return Err(LearningContractError::NonIndependentAssessment.into());
        }
        content_identity(
            "experiment-control",
            &[
                self.plan.experiment_id.as_str(),
                self.plan.operation_ref.as_str(),
                self.plan.scope_ref.as_str(),
                self.plan.budget_ref.as_str(),
                self.plan.deadline_ref.as_str(),
                self.plan.evaluator_id.as_str(),
                VERIFIER_OWNER_FAMILY,
                self.proposal.closure_id.as_str(),
                self.proposal.closure_digest.as_str(),
            ],
        )
    }

    /// The safeguard handles that bound the experiment.
    ///
    /// I12.24's pre-authorized reversible tuning class says the change "never
    /// changes authority, privacy, finish semantics, Decision Safety Floor,
    /// `ContextAtomPolicy`, verifier definition, canonical durability,
    /// Kernel/Watchdog reserve or last-resort recovery capacity", and the
    /// rollout crosses
    /// [`KERNEL_CANARY_OWNER`]. Those are the owner-published handles the plan
    /// and proposal carry, and a proposal that widened the effect ceiling or
    /// declared an unsupported risk ceiling never reaches the candidate list.
    pub fn safeguards(&self) -> Result<Vec<ArtifactId>, ExperimentRefusal> {
        if self.proposal.effect_ceiling != IMPROVEMENT_EFFECT_CEILING {
            return Err(LearningContractError::CandidateCeiling.into());
        }
        if self.proposal.risk_ceiling != IMPROVEMENT_RISK_CEILING_BOUNDED {
            return Err(PipelineError::UnsupportedRiskCeiling {
                encoding_version: IMPROVEMENT_RISK_CEILING_ENCODING_VERSION,
            }
            .into());
        }
        let mut handles = Vec::new();
        for value in [
            self.plan.scope_ref.as_str(),
            self.plan.budget_ref.as_str(),
            self.plan.deadline_ref.as_str(),
            self.proposal.risk_ceiling.as_str(),
            self.proposal.effect_ceiling.as_str(),
            self.proposal.privacy_class.as_str(),
            KERNEL_CANARY_OWNER,
        ] {
            handles.push(artifact(value)?);
        }
        let handles = sorted_unique_refs(handles);
        if handles.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.safeguards",
            }
            .into());
        }
        Ok(handles)
    }

    /// The stop conditions that end the experiment.
    ///
    /// They are the plan's own two terminal bounds — its deadline and its budget
    /// — each named with the dimension it bounds, so the two conditions are
    /// distinct values and neither is prose.
    pub fn stop_conditions(&self) -> Result<Vec<String>, ExperimentRefusal> {
        let mut conditions = Vec::new();
        for condition in [
            format!("deadline={}", self.plan.deadline_ref),
            format!("budget={}", self.plan.budget_ref),
        ] {
            conditions.push(bounded_text(condition, "experiment.stop_conditions", 256)?);
        }
        Ok(conditions)
    }
}

/// Owner seam 4 — the assignment/sampling owner.
///
/// I12.24's improvement-experiment family names "assignment/sampling" as
/// governed content. The closed [`AssignmentKind`] vocabulary is the
/// mechanism and the seed digest is the sampling proof, so the pair travels
/// together and neither is reconstructed here. A seed that is not a lowercase
/// SHA-256 value is refused rather than being formatted into one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignmentOwnerRecord<'a> {
    /// Closed assignment mechanism the owner selected.
    pub kind: AssignmentKind,
    /// Digest of the assignment seed or matching rule.
    pub seed_digest: &'a str,
    /// Owner receipt registering this assignment for this experiment.
    pub owner_receipt: &'a ArtifactId,
}

impl AssignmentOwnerRecord<'_> {
    /// The closed assignment mechanism.
    #[must_use]
    pub const fn assignment(&self) -> AssignmentKind {
        self.kind
    }

    /// The assignment seed digest, shape-checked.
    pub fn assignment_seed_digest(&self) -> Result<&str, ExperimentRefusal> {
        validate_digest(self.seed_digest, "experiment.assignment_seed_digest")?;
        Ok(self.seed_digest)
    }

    /// Revalidate the whole assignment owner record.
    pub fn validate(&self) -> Result<(), ExperimentRefusal> {
        self.assignment_seed_digest()?;
        if self.owner_receipt.as_str().trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.assignment_owner_receipt",
            }
            .into());
        }
        Ok(())
    }
}

/// Owner seam 5 — the external rollback owner.
///
/// I12.24:89 requires "reversible rollout, canary, and invalidation conditions"
/// and the maintenance owner's [`RollbackContract`] is the named owner record
/// for all of them. Naming a rollback, disable, reopen, expiry or forward-repair
/// contract proves a repair path exists; it never proves a rollback was
/// requested or applied, so nothing here reads a rollback outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackOwnerRecord<'a> {
    /// Rollback contract named before the experiment.
    pub contract: &'a RollbackContract,
}

impl RollbackOwnerRecord<'_> {
    /// The rollback handles retained for this experiment.
    pub fn rollback_refs(&self) -> Result<Vec<ArtifactId>, ExperimentRefusal> {
        let mut refs = Vec::new();
        for value in [
            self.contract.rollback_ref.as_str(),
            self.contract.disable_ref.as_str(),
            self.contract.reopen_ref.as_str(),
            self.contract.expiry_ref.as_str(),
            self.contract.forward_repair_ref.as_str(),
        ] {
            refs.push(artifact(value)?);
        }
        for value in &self.contract.invalidation_set {
            refs.push(artifact(value)?);
        }
        let refs = sorted_unique_refs(refs);
        if refs.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.rollback_refs",
            }
            .into());
        }
        Ok(refs)
    }
}

/// Owner seam 6 — the contamination / prior-exposure owner.
///
/// The contract's own comment is the governing sentence: "Contamination handling
/// policy; silence is not permitted." So an empty accounted-exposure set is
/// [`LearningContractError::MissingOwnerEvidence`] rather than an empty list that
/// reads as "nothing was exposed".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContaminationOwnerRecord<'a> {
    /// Contamination handling policy this owner published.
    pub policy: &'a str,
    /// Prior-exposure handles the policy accounts for.
    pub accounted_refs: &'a [ArtifactId],
    /// Owner receipt registering the account.
    pub owner_receipt: &'a ArtifactId,
}

impl ContaminationOwnerRecord<'_> {
    /// The contamination handling policy.
    pub fn contamination_policy(&self) -> Result<&str, ExperimentRefusal> {
        bounded_text(
            self.policy.to_owned(),
            "experiment.contamination_policy",
            1024,
        )?;
        Ok(self.policy)
    }

    /// The prior-exposure handles accounted by that policy.
    pub fn prior_exposure_refs(&self) -> Result<Vec<ArtifactId>, ExperimentRefusal> {
        if self.owner_receipt.as_str().trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.contamination_owner_receipt",
            }
            .into());
        }
        if self.accounted_refs.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.prior_exposure_refs",
            }
            .into());
        }
        Ok(sorted_unique_refs(self.accounted_refs.to_vec()))
    }
}

/// Owner seam 7 — the evidence-freeze owner.
///
/// Issue #45's acceptance names "exact evidence freeze and reproducible
/// evaluation", and I12.24:209 freezes the load-bearing revision fields "before
/// evaluation". The freeze digest is therefore the maintenance owner's own
/// domain-separated, versioned [`proposal_digest`] commitment — not a digest
/// recomputed here — and the frozen set is the proposal's own evidence lineage
/// plus the independent activation record that observed the exact run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceFreezeOwnerRecord<'a> {
    /// Governor-side proposal whose commitment is frozen.
    pub proposal: &'a ImprovementProposal,
    /// Independent activation record over the executed run.
    pub activation: &'a ActivationEvidence,
    /// Owner receipt registering the freeze for this experiment.
    pub freeze_receipt: &'a ArtifactId,
}

impl EvidenceFreezeOwnerRecord<'_> {
    /// The identity of the independent activation record over the executed run.
    pub fn activation_receipt(&self) -> Result<ArtifactId, ExperimentRefusal> {
        artifact(self.activation.evidence_id.as_str())
    }

    /// The owner's own versioned commitment digest over the frozen proposal.
    pub fn evidence_freeze_digest(&self) -> Result<String, ExperimentRefusal> {
        let digest = proposal_commitment_digest(self.proposal)?;
        validate_digest(&digest, "experiment.evidence_freeze_digest")?;
        Ok(digest)
    }

    /// The exact frozen inputs a reproducible evaluation reads.
    pub fn evidence_freeze_refs(&self) -> Result<Vec<ArtifactId>, ExperimentRefusal> {
        if self.freeze_receipt.as_str().trim().is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.evidence_freeze_receipt",
            }
            .into());
        }
        let mut refs = Vec::new();
        for value in &self.proposal.evidence_refs {
            refs.push(artifact(value)?);
        }
        refs.push(self.activation_receipt()?);
        refs.push(self.freeze_receipt.clone());
        let refs = sorted_unique_refs(refs);
        if refs.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "experiment.evidence_freeze_refs",
            }
            .into());
        }
        Ok(refs)
    }
}

/// Owner seam 8 — the outcome/verifier owner.
///
/// The dimensioned assessment is the outcome owner's own record; there is
/// deliberately no scalar score and the contract refuses one. The independent
/// activation record is the A5.5 route check: it must be independent of the
/// candidate source, must not be the executor, and must carry an executed
/// status, because I0.5 forbids substituting `NOT_EXECUTED` or `SIMULATED` for
/// real execution evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeOwnerRecord<'a> {
    /// Dimensioned assessment the outcome owner published.
    pub assessment: &'a LearningAssessmentCandidate,
    /// Bounded plan the assessment is bound to.
    pub plan: &'a ExperimentPlan,
    /// Independent activation evidence over the executed run.
    pub activation: &'a ActivationEvidence,
}

impl OutcomeOwnerRecord<'_> {
    /// Revalidate the independent activation record and return its identity.
    ///
    /// `NOT_OBSERVED`/absent observability is never converted into a negative
    /// finding here (I12.24 line 256): an unexecuted or non-independent
    /// evaluation is refused as exactly that, and never becomes "no effect".
    pub fn validate_activation(&self) -> Result<ArtifactId, ExperimentRefusal> {
        if self.activation.bound_experiment_id != self.plan.experiment_id {
            return Err(PipelineError::UnboundRelation {
                relation: "experiment: activation evidence is bound to another bounded plan",
            }
            .into());
        }
        if self.activation.verifier_id != self.plan.evaluator_id {
            return Err(PipelineError::UnboundRelation {
                relation: "experiment: activation evidence names another evaluator than the plan",
            }
            .into());
        }
        if self.activation.verifier_id == self.plan.testd_owner_id
            || self.activation.verifier_id == TESTD_OWNER
        {
            return Err(PipelineError::EvidenceNotIndependent.into());
        }
        if !self.activation.independent || !self.activation.verifier_passed {
            return Err(PipelineError::EvidenceNotIndependent.into());
        }
        if self.activation.execution != ImprovementEvidenceExecution::Executed {
            return Err(PipelineError::EvidenceNotExecuted {
                status: self.activation.execution.label(),
            }
            .into());
        }
        artifact(self.activation.evidence_id.as_str())
    }

    /// The dimensioned outcome; there is deliberately no scalar score.
    pub fn outcome_dimensions(&self) -> Result<Vec<DimensionAssessment>, ExperimentRefusal> {
        // `validate` returns `Result<(), _>`: it is a check, not an accessor,
        // so the value is read from the assessment after the check succeeds.
        self.assessment.validate()?;
        Ok(self.assessment.dimensions.clone())
    }

    /// The weakest causal interpretation the outcome owner supports.
    pub fn claim_ceiling(&self) -> Result<CausalCeiling, ExperimentRefusal> {
        self.assessment.validate()?;
        Ok(self.assessment.causal_ceiling)
    }

    /// Require the independence dimension to carry the independent record's own
    /// identity.
    ///
    /// The attributor's own dimensioned self-assessment can therefore never
    /// certify its own independence, which is the A5.5 constraint applied to the
    /// outer loop: the verifying route outside the executor's domain must be the
    /// named owner of that dimension.
    pub fn require_independent_dimension(
        &self,
        activation_receipt: &ArtifactId,
    ) -> Result<(), ExperimentRefusal> {
        let dimension = self
            .assessment
            .dimensions
            .iter()
            .find(|dimension| {
                dimension.dimension == AssessmentDimension::SourceEvaluatorIndependence
            })
            .ok_or(LearningContractError::IncompleteCoverage)?;
        if dimension.owner_receipt.as_ref() != Some(activation_receipt) {
            return Err(LearningContractError::NonIndependentAssessment.into());
        }
        Ok(())
    }
}

/// Exact owner evidence presented to one improvement-experiment derivation.
///
/// Every value is published by its owner and passed through unchanged. The
/// Governor composes them; it never fills one in, and an owner that published
/// nothing leaves its slot `None` so the refusal names that seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentOwnerInput<'a> {
    /// Attribution-lineage owner record.
    pub attribution: Option<&'a AttributionLineageOwnerRecord<'a>>,
    /// Mechanism owner record.
    pub mechanism: Option<&'a MechanismOwnerRecord<'a>>,
    /// Bounded-plan owner record.
    pub plan: Option<&'a BoundedPlanOwnerRecord<'a>>,
    /// Assignment owner record.
    pub assignment: Option<&'a AssignmentOwnerRecord<'a>>,
    /// Rollback owner record.
    pub rollback: Option<&'a RollbackOwnerRecord<'a>>,
    /// Contamination/prior-exposure owner record.
    pub contamination: Option<&'a ContaminationOwnerRecord<'a>>,
    /// Evidence-freeze owner record.
    pub freeze: Option<&'a EvidenceFreezeOwnerRecord<'a>>,
    /// Outcome/verifier owner record.
    pub outcome: Option<&'a OutcomeOwnerRecord<'a>>,
}

impl ExperimentOwnerInput<'_> {
    /// The presentation for a seam where no owner publishes any record.
    ///
    /// This is the honest production state of the improvement-intake seam: no
    /// owner publishes an attribution, a bounded plan, a mechanism declaration,
    /// an assignment seed, a rollback contract, a contamination account, an
    /// evidence freeze or a dimensioned outcome there, so every slot is absent
    /// and the first failing seam is the recorded refusal.
    #[must_use]
    pub const fn no_owner_records() -> ExperimentOwnerInput<'static> {
        ExperimentOwnerInput {
            attribution: None,
            mechanism: None,
            plan: None,
            assignment: None,
            rollback: None,
            contamination: None,
            freeze: None,
            outcome: None,
        }
    }
}

/// Typed refusals of one improvement-experiment derivation; every variant names
/// one cause.
///
/// An absent owner and a failed owner record stay distinct, exactly as
/// [`crate::learning_attribution::AttributionRefusal`] keeps an absent owner
/// distinct from an invalid one, and the two composed vocabularies stay
/// distinct too: a learning-contract content failure and a maintenance-owner
/// record failure are not the same fact.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ExperimentRefusal {
    /// No owner published a record for this experiment owner seam, so nothing
    /// was derived. Absence is recorded as absence and never as a pass.
    #[error("no owner record was published for {field}")]
    OwnerAbsent {
        /// The owner seam that published nothing.
        field: &'static str,
    },
    /// A content rule of the learning contracts refused a derived value. The
    /// typed contract error travels as the source.
    #[error("improvement experiment refused: {0}")]
    Owner(#[source] LearningContractError),
    /// The maintenance owner refused one of its own records. That typed error
    /// travels whole, so a pre-hoc mechanism and an unsupported risk ceiling
    /// never collapse into one reason.
    #[error("improvement experiment owner record refused: {0}")]
    OwnerRecord(#[source] PipelineError),
}

impl From<LearningContractError> for ExperimentRefusal {
    fn from(error: LearningContractError) -> Self {
        Self::Owner(error)
    }
}

impl From<PipelineError> for ExperimentRefusal {
    fn from(error: PipelineError) -> Self {
        Self::OwnerRecord(error)
    }
}

/// Typed outcome of the outer improvement-experiment loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExperimentLoopOutcome {
    /// Every owner seam published and the candidate validated in one fence. The
    /// record stays candidate-only: nothing is admitted, run or promoted here.
    Experimental(Box<ImprovementExperimentCandidate>),
    /// An owner seam was absent or refused, so no experiment exists. The typed
    /// cause is retained so an honest absence and an invalid record never
    /// collapse into one answer.
    NotExperimental {
        /// The exact reason no governed experiment was produced.
        reason: ExperimentRefusal,
    },
}

/// Produce the candidate-only improvement experiment from the owner records.
///
/// This is the strict entry point: it returns the candidate or the exact typed
/// refusal, so a caller that must treat a refusal as a hard failure can.
/// Evaluation order is fixed and fail-closed: the attribution lineage first,
/// then the seven remaining owner seams in the order the documentation names
/// them, then the cross-owner content bindings and the one-fence contract
/// validation. The first failing seam is the recorded refusal, so a consumer
/// always learns which owner is missing rather than only that something is.
#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed owner-seam block per seam, kept in the documented evaluation order"
)]
pub fn derive_experiment_candidate(
    input: &ExperimentOwnerInput<'_>,
) -> Result<ImprovementExperimentCandidate, ExperimentRefusal> {
    let Some(attribution_seam) = input.attribution else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.attribution_owner",
        });
    };
    let Some(mechanism_seam) = input.mechanism else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.mechanism_owner",
        });
    };
    let Some(plan_seam) = input.plan else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.bounded_plan_owner",
        });
    };
    let Some(assignment_seam) = input.assignment else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.assignment_owner",
        });
    };
    let Some(rollback_seam) = input.rollback else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.rollback_owner",
        });
    };
    let Some(contamination_seam) = input.contamination else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.contamination_owner",
        });
    };
    let Some(freeze_seam) = input.freeze else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.evidence_freeze_owner",
        });
    };
    let Some(outcome_seam) = input.outcome else {
        return Err(ExperimentRefusal::OwnerAbsent {
            field: "experiment.outcome_owner",
        });
    };

    // Seam 1 — attribution lineage.
    attribution_seam.validate()?;
    let binding = attribution_seam.binding();
    let target = attribution_seam.target();
    let attribution_id = attribution_seam.attribution_id();
    let attribution_digest = attribution_seam.attribution_digest();

    // Seam 2 — pre-registered mechanism.
    let hypothesis = mechanism_seam.hypothesis()?.to_owned();
    let pre_observation_discriminator = mechanism_seam.pre_observation_discriminator()?;

    // Seam 3 — bounded plan: eligibility, immutable arm identities, safeguards
    // and stop conditions.
    let eligibility = plan_seam.eligibility()?;
    let intervention_id = plan_seam.intervention_id()?;
    let control_id = plan_seam.control_id()?;
    if intervention_id == control_id {
        return Err(LearningContractError::ScopeMismatch {
            field: "experiment.control",
        }
        .into());
    }
    let safeguards = plan_seam.safeguards()?;
    let stop_conditions = plan_seam.stop_conditions()?;

    // Seam 4 — assignment mechanism.
    assignment_seam.validate()?;
    let assignment = assignment_seam.assignment();
    let assignment_seed_digest = assignment_seam.assignment_seed_digest()?.to_owned();

    // Seam 5 — external rollback owner.
    let rollback_refs = rollback_seam.rollback_refs()?;

    // Seam 6 — contamination and prior exposure.
    let contamination_policy = contamination_seam.contamination_policy()?.to_owned();
    let prior_exposure_refs = contamination_seam.prior_exposure_refs()?;

    // Seam 7 — exact evidence freeze.
    let evidence_freeze_digest = freeze_seam.evidence_freeze_digest()?;
    let evidence_freeze_refs = freeze_seam.evidence_freeze_refs()?;

    // Seam 8 — independent route check, then the dimensioned outcome. The
    // independence receipt must be the owner receipt of the
    // `SOURCE_EVALUATOR_INDEPENDENCE` dimension.
    let activation_receipt = outcome_seam.validate_activation()?;
    let outcome_dimensions = outcome_seam.outcome_dimensions()?;
    outcome_seam.require_independent_dimension(&activation_receipt)?;
    let claim_ceiling = outcome_seam.claim_ceiling()?;

    let experiment_id = content_identity(
        "improvement-experiment",
        &[
            attribution_id.as_str(),
            attribution_digest.as_str(),
            plan_seam.plan.experiment_id.as_str(),
            plan_seam.plan.operation_ref.as_str(),
            mechanism_seam.declaration.declared_ref.as_str(),
            evidence_freeze_digest.as_str(),
        ],
    )?;

    let mut candidate = ImprovementExperimentCandidate {
        binding,
        experiment_id,
        target,
        attribution_id,
        attribution_digest,
        hypothesis,
        eligibility,
        assignment,
        assignment_seed_digest,
        intervention_id,
        control_id,
        pre_observation_discriminator,
        safeguards,
        stop_conditions,
        rollback_refs,
        contamination_policy,
        prior_exposure_refs,
        evidence_freeze_digest,
        evidence_freeze_refs,
        outcome_dimensions,
        claim_ceiling,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    // One fence: the candidate's own rules AND its exact lineage against the
    // attribution it consumed.
    candidate.validate_against_attribution(attribution_seam.attribution)?;
    Ok(candidate)
}

/// Run the outer improvement-experiment loop over the published owner records.
///
/// This is the production producer of the governed experiment candidate. It is
/// the entry the improvement lifecycle's `accepted_for_experiment` edge asks, and
/// it is a pure function of the owner records: no clock, no I/O, no live query,
/// and no authority beyond the verdict it returns. It returns an outcome for
/// every input, so an owner seam that published nothing is recorded as a typed
/// [`ExperimentRefusal::OwnerAbsent`] rather than being defaulted, and a
/// candidate that does exist stays candidate-only: this loop neither runs an
/// experiment nor promotes, admits or delivers anything.
#[must_use = "the governed experiment verdict must be recorded, not discarded"]
pub fn run_improvement_experiment_loop(input: &ExperimentOwnerInput<'_>) -> ExperimentLoopOutcome {
    match derive_experiment_candidate(input) {
        Ok(candidate) => ExperimentLoopOutcome::Experimental(Box::new(candidate)),
        Err(reason) => ExperimentLoopOutcome::NotExperimental { reason },
    }
}

/// Build one foundation artifact identity or fail closed with the foundation
/// contract error.
fn artifact(value: &str) -> Result<ArtifactId, ExperimentRefusal> {
    ArtifactId::new(value).map_err(|_| ExperimentRefusal::Owner(LearningContractError::Foundation))
}

/// Reject blank, control-bearing and over-long bounded text.
fn bounded_text(
    value: String,
    field: &'static str,
    max_chars: usize,
) -> Result<String, ExperimentRefusal> {
    if value.trim().is_empty() {
        return Err(LearningContractError::Missing { field }.into());
    }
    if value.chars().any(char::is_control) {
        return Err(LearningContractError::ScopeMismatch { field }.into());
    }
    if value.chars().count() > max_chars {
        return Err(LearningContractError::Bound { field }.into());
    }
    Ok(value)
}

/// Content-address one identity over the exact owner parts that decide it.
///
/// Two different parts never share one identity, and an empty or blank part is a
/// typed refusal rather than a digest over nothing.
fn content_identity(domain: &str, parts: &[&str]) -> Result<ArtifactId, ExperimentRefusal> {
    if parts.is_empty() || parts.iter().any(|part| part.trim().is_empty()) {
        return Err(LearningContractError::Missing {
            field: "experiment.identity_part",
        }
        .into());
    }
    let bytes = canonical_json_bytes(&parts)
        .map_err(|_| ExperimentRefusal::Owner(LearningContractError::Canonicalization))?;
    artifact(&format!("{domain}:{}", sha256_hex(&bytes)))
}

/// The maintenance owner's own versioned commitment digest over one proposal.
fn proposal_commitment_digest(proposal: &ImprovementProposal) -> Result<String, ExperimentRefusal> {
    Ok(proposal_digest(proposal)?.digest)
}

/// Sort and deduplicate artifact references so a derived set binds stably.
fn sorted_unique_refs(refs: Vec<ArtifactId>) -> Vec<ArtifactId> {
    let mut refs = refs;
    refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    refs.dedup();
    refs
}
