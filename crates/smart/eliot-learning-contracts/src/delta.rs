//! Consequential-attempt learning results and candidate changes.

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::LearningContractError,
    identity::{
        AgentAttemptId, ContractBinding, ProofCeiling, TargetId, digest_without_field,
        validate_digest,
    },
    state_view::SourceDenominator,
};

/// Whether a value existed before/after a candidate change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValueState {
    /// Presence is explicit; absence is not an empty value.
    pub present: bool,
    /// Digest of the typed value when present.
    pub digest: Option<String>,
}

/// Closed set of candidate surfaces that learning may propose to change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeSurface {
    /// Task-local context shaping.
    TaskLocalContext,
    /// Memory or retrieval representation.
    Memory,
    /// Skill or procedure representation.
    Skill,
    /// Tool selection or use representation.
    Tool,
    /// Route or capability selection representation.
    Route,
    /// Hypothesis representation.
    Hypothesis,
    /// Strategy representation.
    Strategy,
    /// Abstraction representation.
    Abstraction,
    /// Candidate parent lineage metadata.
    CandidateParent,
    /// Verification ordering representation.
    VerificationOrder,
    /// Search or probe stopping representation.
    SearchProbeStopping,
}

impl ValueState {
    /// Validate presence/digest agreement.
    pub fn validate(&self, field: &'static str) -> Result<(), LearningContractError> {
        match (self.present, &self.digest) {
            (true, Some(digest)) => validate_digest(digest, field),
            (true, None) => Err(LearningContractError::Missing { field }),
            (false, None) => Ok(()),
            (false, Some(_)) => Err(LearningContractError::ScopeMismatch { field }),
        }
    }
}

/// Closed, typed change operations with exact before/after values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", content = "change", deny_unknown_fields)]
pub enum ChangeOperation {
    /// Replace one value while retaining both snapshots.
    Replace {
        target: TargetId,
        surface: ChangeSurface,
        before: ValueState,
        after: ValueState,
    },
    /// Add a previously absent value.
    Add {
        target: TargetId,
        surface: ChangeSurface,
        after: ValueState,
    },
    /// Remove a previously present value.
    Remove {
        target: TargetId,
        surface: ChangeSurface,
        before: ValueState,
    },
}

impl ChangeOperation {
    /// Return the surface identity touched by the operation.
    pub const fn target(&self) -> &TargetId {
        match self {
            Self::Replace { target, .. }
            | Self::Add { target, .. }
            | Self::Remove { target, .. } => target,
        }
    }

    /// Validate exact operation semantics.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        crate::identity::validate_external_id(self.target().as_str(), "change.target")?;
        match self {
            Self::Replace { before, after, .. } => {
                before.validate("change.before")?;
                after.validate("change.after")?;
                if !before.present || !after.present || before == after {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "change.replace",
                    });
                }
            }
            Self::Add { after, .. } => {
                after.validate("change.after")?;
                if !after.present {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "change.add",
                    });
                }
            }
            Self::Remove { before, .. } => {
                before.validate("change.before")?;
                if !before.present {
                    return Err(LearningContractError::ScopeMismatch {
                        field: "change.remove",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Explicit inverse operation retained for every proposed change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InverseChange {
    /// Forward operation being inverted.
    pub forward_target: TargetId,
    /// Exact inverse operation.
    pub inverse: ChangeOperation,
}

impl InverseChange {
    /// Validate target identity and matching inverse surface.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        crate::identity::validate_external_id(self.forward_target.as_str(), "inverse.target")?;
        self.inverse.validate()?;
        if self.forward_target != *self.inverse.target() {
            return Err(LearningContractError::ScopeMismatch {
                field: "inverse.target",
            });
        }
        Ok(())
    }

    /// Check that the inverse is the exact opposite operation.
    #[allow(clippy::match_same_arms)]
    pub fn is_exact_inverse_of(&self, forward: &ChangeOperation) -> bool {
        match (forward, &self.inverse) {
            (
                ChangeOperation::Replace {
                    target,
                    surface,
                    before,
                    after,
                },
                ChangeOperation::Replace {
                    target: inverse_target,
                    surface: inverse_surface,
                    before: inverse_before,
                    after: inverse_after,
                },
            ) => {
                target == inverse_target
                    && surface == inverse_surface
                    && before == inverse_after
                    && after == inverse_before
            }
            (
                ChangeOperation::Add {
                    target,
                    surface,
                    after,
                },
                ChangeOperation::Remove {
                    target: inverse_target,
                    surface: inverse_surface,
                    before,
                },
            ) => target == inverse_target && surface == inverse_surface && after == before,
            (
                ChangeOperation::Remove {
                    target,
                    surface,
                    before,
                },
                ChangeOperation::Add {
                    target: inverse_target,
                    surface: inverse_surface,
                    after,
                },
            ) => target == inverse_target && surface == inverse_surface && before == after,
            _ => false,
        }
    }
}

/// A materially different controlled retry retained as evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EquivalentRetry {
    /// Prior attempt identity.
    pub prior_attempt: AgentAttemptId,
    /// Strategy fingerprint that was actually repeated.
    pub strategy_fingerprint: String,
    /// Why controlled repetition was required.
    pub reason: String,
    /// Evidence/source dependency for comparison.
    pub evidence: Vec<ArtifactId>,
}

impl EquivalentRetry {
    /// Validate retry identity and bounded explanatory fields.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        crate::identity::validate_external_id(
            self.prior_attempt.as_str(),
            "equivalent_retry.prior_attempt",
        )?;
        if self.strategy_fingerprint.trim().is_empty() || self.reason.trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "equivalent_retry",
            });
        }
        if self.strategy_fingerprint.chars().count() > 256 {
            return Err(LearningContractError::Bound {
                field: "equivalent_retry.strategy_fingerprint",
            });
        }
        if self.evidence.is_empty() {
            return Err(LearningContractError::Missing {
                field: "equivalent_retry.evidence",
            });
        }
        Ok(())
    }
}

/// A finite change candidate for one consequential attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptLearningDeltaCandidate {
    /// Shared request/task/scope/fence/source binding.
    pub binding: ContractBinding,
    /// Consequential attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Stable candidate artifact identity.
    pub delta_id: ArtifactId,
    /// Target whose compatible next attempt may inspect this candidate.
    pub target: TargetId,
    /// Immutable state view observed before the attempt.
    pub base_view_digest: String,
    /// Discriminator fixed before observation.
    pub pre_observation_discriminator: ArtifactId,
    /// Intended strategy identity, separate from observed outcome.
    pub intended_strategy: ArtifactId,
    /// Attempted strategy identity.
    pub attempted_strategy: ArtifactId,
    /// Typed changes proposed by the candidate.
    pub changes: Vec<ChangeOperation>,
    /// Exact inverse for each change.
    pub inverses: Vec<InverseChange>,
    /// Evidence supporting the observed result.
    pub evidence: Vec<ArtifactId>,
    /// Independent evaluator receipts, if available.
    pub evaluator_receipts: Vec<ArtifactId>,
    /// Baseline/control and confounder references retained separately.
    pub baseline: Vec<ArtifactId>,
    /// Controlled comparison references.
    pub control: Vec<ArtifactId>,
    /// Known confounders.
    pub confounders: Vec<ArtifactId>,
    /// Applicability/dependency references for a next compatible attempt.
    pub dependencies: Vec<ArtifactId>,
    /// Equivalent retry relation, if one was needed.
    pub equivalent_retry: Option<EquivalentRetry>,
    /// Candidate is always bounded by this closed ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Canonical candidate shape digest, excluding this field.
    pub canonical_digest: String,
}

impl AttemptLearningDeltaCandidate {
    /// Validate a finite, evidence-backed candidate without applying it.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        crate::identity::validate_external_id(self.attempt_id.as_str(), "delta.attempt_id")?;
        if self.delta_id.as_str().trim().is_empty() {
            return Err(LearningContractError::Missing {
                field: "delta.delta_id",
            });
        }
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(LearningContractError::CandidateCeiling);
        }
        crate::identity::validate_external_id(self.target.as_str(), "delta.target")?;
        validate_digest(&self.base_view_digest, "delta.base_view_digest")?;
        for id in [
            &self.pre_observation_discriminator,
            &self.intended_strategy,
            &self.attempted_strategy,
        ] {
            if id.as_str().trim().is_empty() {
                return Err(LearningContractError::Missing {
                    field: "delta.lineage",
                });
            }
        }
        if self.changes.is_empty() || self.changes.len() > 128 {
            return Err(LearningContractError::Bound {
                field: "delta.changes",
            });
        }
        for change in &self.changes {
            change.validate()?;
        }
        for inverse in &self.inverses {
            inverse.validate()?;
        }
        if self.inverses.len() != self.changes.len() {
            return Err(LearningContractError::MissingInverse);
        }
        if self
            .changes
            .iter()
            .zip(&self.inverses)
            .any(|(change, inverse)| !inverse.is_exact_inverse_of(change))
        {
            return Err(LearningContractError::MissingInverse);
        }
        if self.evidence.is_empty() {
            return Err(LearningContractError::Missing {
                field: "delta.evidence",
            });
        }
        if self.evaluator_receipts.is_empty() {
            return Err(LearningContractError::MissingOwnerEvidence {
                field: "delta.evaluator_receipts",
            });
        }
        for ids in [
            &self.evidence,
            &self.evaluator_receipts,
            &self.baseline,
            &self.control,
            &self.confounders,
            &self.dependencies,
        ] {
            ensure_unique(ids.iter().map(ArtifactId::as_str), "delta.references")?;
        }
        if let Some(retry) = &self.equivalent_retry {
            retry.validate()?;
        }
        validate_digest(&self.canonical_digest, "delta.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "delta.canonical_digest",
            });
        }
        Ok(())
    }

    /// Validate that this candidate is tied to the exact immutable pre-attempt view.
    pub fn validate_against_view(
        &self,
        view: &crate::state_view::CampaignLearningStateView,
    ) -> Result<(), LearningContractError> {
        self.validate()?;
        view.binding.validate()?;
        if digest_without_field(view, "canonical_digest")? != view.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "view.canonical_digest",
            });
        }
        if self.binding != view.binding
            || self.target != view.target
            || self.base_view_digest != view.canonical_digest
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "delta.view_lineage",
            });
        }
        Ok(())
    }

    /// Populate the canonical candidate digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

/// Evidence-backed reasons why a consequential attempt justified no change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NoChangeReason {
    /// The fixed prediction survived the declared evaluation.
    ConfirmedFixedPrediction,
    /// Controlled replication is required before changing the candidate.
    ControlledReplicationNeeded,
    /// A protected constraint rules out the candidate.
    ProtectedConstraint,
    /// The target is proven nonapplicable or a typed no-op.
    ProvenNonApplicability,
    /// Candidate evidence contradicts the proposed mechanism.
    Contradicted,
    /// Candidate would be unsafe under the declared evidence.
    UnsafeCandidate,
    /// The canonical owner blocked the candidate.
    OwnerBlocked,
    /// Independent external review is required before proposing a change.
    ExternalReviewRequired,
}

/// A successful, evidence-backed no-change outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoChangeDisposition {
    /// Shared task/scope/fence/source binding.
    pub binding: ContractBinding,
    /// Consequential attempt identity.
    pub attempt_id: AgentAttemptId,
    /// Target considered.
    pub target: TargetId,
    /// Exact reason from the closed vocabulary.
    pub reason: NoChangeReason,
    /// Affirmative evidence proving the reason.
    pub affirmative_evidence: Vec<ArtifactId>,
    /// Declared versus observed evidence denominator.
    pub denominator: SourceDenominator,
    /// Canonical disposition shape digest, excluding this field.
    pub canonical_digest: String,
}

impl NoChangeDisposition {
    /// Validate that no-change is affirmative and cannot hide missing evidence.
    pub fn validate(&self) -> Result<(), LearningContractError> {
        self.binding.validate()?;
        crate::identity::validate_external_id(self.attempt_id.as_str(), "no_change.attempt_id")?;
        crate::identity::validate_external_id(self.target.as_str(), "no_change.target")?;
        if self.affirmative_evidence.is_empty() {
            return Err(LearningContractError::InvalidNoChange);
        }
        ensure_unique(
            self.affirmative_evidence.iter().map(ArtifactId::as_str),
            "no_change.evidence",
        )?;
        self.denominator.validate()?;
        let evidence_count = u32::try_from(self.affirmative_evidence.len()).map_err(|_| {
            LearningContractError::Bound {
                field: "no_change.evidence",
            }
        })?;
        if self.denominator.observed != evidence_count
            || self.denominator.observed != self.denominator.declared
        {
            return Err(LearningContractError::InvalidNoChange);
        }
        validate_digest(&self.canonical_digest, "no_change.canonical_digest")?;
        if digest_without_field(self, "canonical_digest")? != self.canonical_digest {
            return Err(LearningContractError::DigestMismatch {
                field: "no_change.canonical_digest",
            });
        }
        Ok(())
    }

    /// Populate the canonical disposition digest.
    pub fn seal(&mut self) -> Result<(), LearningContractError> {
        self.canonical_digest = digest_without_field(self, "canonical_digest")?;
        Ok(())
    }
}

/// The only two successful semantic arms for a consequential attempt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "outcome",
    content = "value",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum AttemptLearningOutcome {
    /// A bounded candidate change with exact inverse and evidence.
    Delta(AttemptLearningDeltaCandidate),
    /// An affirmative evidence-backed decision to change nothing.
    NoChange(NoChangeDisposition),
}

/// Non-successful attempt dispositions remain outside `AttemptLearningOutcome`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptFailure {
    /// The attempt returned an error.
    Error,
    /// The attempt was cancelled before a semantic result.
    Cancelled,
    /// The attempt exhausted its allowed work.
    Exhausted,
    /// The attempt was not consequential.
    NonConsequential,
    /// Evidence could not establish a result.
    Unknown,
}

/// Enclosing result that keeps failure/unknown outside the two success arms.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", content = "value", deny_unknown_fields)]
pub enum AttemptLearningResult {
    /// Successful consequential result.
    Success(AttemptLearningOutcome),
    /// Error/cancellation/exhaustion/nonconsequential/unknown outcome.
    Failure(AttemptFailure),
}

fn ensure_unique<'a, I>(values: I, field: &'static str) -> Result<(), LearningContractError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(LearningContractError::Duplicate { field });
        }
    }
    Ok(())
}
