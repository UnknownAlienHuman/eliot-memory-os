//! Provider-neutral, phase-aware references for material decision lineage.
//!
//! This contract records links and their lifecycle. It does not grant authority,
//! assert that a referenced policy is applicable, or prove that a decision caused
//! an outcome. Those claims require the owning policy and live receipt gates.

use eliot_agent_contracts::{AnchorReference, AnchorResolutionStatus, PublicReference};
use eliot_contracts::{EpochId, StateFence};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, OperationBinding, ReceiptEnvelope, ReceiptKind, TaskBinding,
    VerifierBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, validate_digest, validate_text};

const MAX_DECISION_LINEAGE_ITEMS: usize = 256;

/// Decision lifecycle point against which required lineage is evaluated.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionLineagePhase {
    /// Before dispatching a newly proposed effect.
    BeforeEffect,
    /// A retained decision is resumed or continued.
    Resume,
    /// Expected observables and artifacts are being verified.
    Verification,
    /// A typed finish outcome is being recorded.
    Finish,
}

/// Derived phase-relative state of a lineage contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionLineageCompleteness {
    /// Every link due at this phase is present or policy-accounted as inapplicable.
    Complete,
    /// A link already due at this phase is not yet produced.
    Partial,
    /// The lineage is superseded or its fence no longer matches.
    Stale,
    /// A required fact is explicitly unknown.
    Unknown,
}

impl DecisionLineageCompleteness {
    fn combine(self, other: Self) -> Self {
        use DecisionLineageCompleteness::{Complete, Partial, Stale, Unknown};
        match (self, other) {
            (Stale, _) | (_, Stale) => Stale,
            (Unknown, _) | (_, Unknown) => Unknown,
            (Partial, _) | (_, Partial) => Partial,
            _ => Complete,
        }
    }
}

/// Immutable typed pointer to a public artifact, evidence item, or receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageRef {
    /// Closed semantic category for the target.
    pub kind: DecisionLineageReferenceKind,
    /// Existing public reference with identity and observed revision.
    pub reference: PublicReference,
}

impl DecisionLineageRef {
    /// Validates the referenced identity without asserting its semantic truth.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.reference
            .validate()
            .map_err(|_| ContextError::InvalidField("lineage.reference"))?;
        if self.reference.kind != self.kind.wire_kind() {
            return Err(ContextError::InvalidField("lineage.reference.kind"));
        }
        Ok(())
    }

    fn validate_as(&self, expected: DecisionLineageReferenceKind) -> Result<(), ContextError> {
        self.validate()?;
        if self.kind != expected {
            return Err(ContextError::InvalidField("lineage.reference.role"));
        }
        Ok(())
    }
}

/// Closed semantic categories for references in the shared lineage shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionLineageReferenceKind {
    /// Governing goal.
    Goal,
    /// Goal acceptance criterion.
    Acceptance,
    /// Decision-time observation.
    Observation,
    /// Source evidence.
    Evidence,
    /// Current epistemic position.
    EpistemicPosition,
    /// Material unknown or conflict.
    MaterialUnknown,
    /// Rival theory or alternative.
    Rival,
    /// Rejection reason for a rival.
    RejectionReason,
    /// Selected option.
    SelectedOption,
    /// Public decision rationale.
    Rationale,
    /// Why the decision is timely.
    WhyNow,
    /// Condition requiring reconsideration.
    RevisitCondition,
    /// Existing `ActionContract`.
    ActionContract,
    /// Authority source for an effect.
    AuthoritySource,
    /// Required future observable.
    ExpectedObservable,
    /// Applicable verifier contract.
    VerifierContract,
    /// Diff or change set.
    Diff,
    /// Observation of a change.
    ChangeObservation,
    /// Anchored review item.
    ReviewItem,
    /// Review disposition.
    ReviewDisposition,
    /// Artifact provenance source.
    ArtifactSource,
    /// Decision outcome evidence.
    Outcome,
    /// Memory revision linked to an outcome.
    MemoryRevision,
    /// Omission or compaction manifest.
    OmissionManifest,
    /// Handoff artifact.
    HandoffArtifact,
    /// Policy governing an explicit status.
    Policy,
    /// Evidence supporting an explicit unknown.
    UnknownEvidence,
    /// Successor lineage.
    Successor,
}

impl DecisionLineageReferenceKind {
    const fn wire_kind(self) -> &'static str {
        match self {
            Self::Goal => "goal",
            Self::Acceptance => "acceptance",
            Self::Observation => "observation",
            Self::Evidence | Self::UnknownEvidence => "evidence",
            Self::EpistemicPosition => "epistemic_position",
            Self::MaterialUnknown => "material_unknown",
            Self::Rival => "rival",
            Self::RejectionReason => "rejection_reason",
            Self::SelectedOption => "selected_option",
            Self::Rationale => "rationale",
            Self::WhyNow => "why_now",
            Self::RevisitCondition => "revisit_condition",
            Self::ActionContract => "action_contract",
            Self::AuthoritySource => "authority",
            Self::ExpectedObservable => "expected_observable",
            Self::VerifierContract => "verifier",
            Self::Diff => "diff",
            Self::ChangeObservation => "change_observation",
            Self::ReviewItem => "review_item",
            Self::ReviewDisposition => "review_disposition",
            Self::ArtifactSource => "artifact_source",
            Self::Outcome => "outcome",
            Self::MemoryRevision => "memory_revision",
            Self::OmissionManifest => "omission_manifest",
            Self::HandoffArtifact => "handoff_artifact",
            Self::Policy => "policy",
            Self::Successor => "successor",
        }
    }
}

/// Semantically explicit reference to the C4-owned `ActionContract`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageActionContractRef {
    /// Public reference whose category is exactly `action_contract`.
    pub reference: DecisionLineageRef,
}

impl DecisionLineageActionContractRef {
    fn validate(&self) -> Result<(), ContextError> {
        self.reference
            .validate_as(DecisionLineageReferenceKind::ActionContract)
    }
}

/// Explicit disposition for one required lineage relation.
///
/// There is no default variant: the producer must identify an existing record,
/// cite policy for a non-applicable/not-yet-produced relation, or state why it is
/// unknown with a supporting evidence reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DecisionLineageSlot<T> {
    /// The referenced typed record exists.
    Present {
        /// Existing record or typed binding.
        value: T,
    },
    /// An identified policy explicitly makes this relation inapplicable.
    NotApplicable {
        /// Policy identity and revision that permits omission of this relation.
        policy: DecisionLineageRef,
        /// Public reason tied to that policy decision.
        reason: String,
    },
    /// An identified policy permits production after the stated phase.
    NotYetProduced {
        /// Policy identity and revision governing the production boundary.
        policy: DecisionLineageRef,
        /// Earliest phase by which the relation is required to exist.
        due_by: DecisionLineagePhase,
        /// Public explanation of why production is deferred.
        reason: String,
    },
    /// The relation is already due or relevant but cannot be established.
    Unknown {
        /// Public explanation of the unresolved state.
        reason: String,
        /// Evidence reference supporting the explicit unknown classification.
        evidence: DecisionLineageRef,
    },
}

impl<T> DecisionLineageSlot<T> {
    fn validate_at(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError>
    where
        T: LineagePayload,
    {
        match self {
            Self::Present { value } => {
                value.validate_payload()?;
                Ok(DecisionLineageCompleteness::Complete)
            }
            Self::NotApplicable { policy, reason } => {
                policy.validate_as(DecisionLineageReferenceKind::Policy)?;
                validate_text(reason, "lineage.not_applicable.reason")?;
                Ok(DecisionLineageCompleteness::Complete)
            }
            Self::NotYetProduced {
                policy,
                due_by,
                reason,
            } => {
                policy.validate_as(DecisionLineageReferenceKind::Policy)?;
                validate_text(reason, "lineage.not_yet_produced.reason")?;
                Ok(if *due_by > phase {
                    DecisionLineageCompleteness::Complete
                } else {
                    DecisionLineageCompleteness::Partial
                })
            }
            Self::Unknown { reason, evidence } => {
                validate_text(reason, "lineage.unknown.reason")?;
                evidence.validate_as(DecisionLineageReferenceKind::UnknownEvidence)?;
                Ok(DecisionLineageCompleteness::Unknown)
            }
        }
    }

    fn present(&self) -> Option<&T> {
        match self {
            Self::Present { value } => Some(value),
            Self::NotApplicable { .. } | Self::NotYetProduced { .. } | Self::Unknown { .. } => None,
        }
    }

    fn required_at(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError>
    where
        T: LineagePayload,
    {
        let state = self.validate_at(phase)?;
        Ok(if self.present().is_some() {
            DecisionLineageCompleteness::Complete
        } else if state == DecisionLineageCompleteness::Unknown {
            DecisionLineageCompleteness::Unknown
        } else {
            DecisionLineageCompleteness::Partial
        })
    }
}

/// A selected public option and the public reason a rival was rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageRival {
    /// Reference to one actual rival hypothesis or alternative.
    pub rival: DecisionLineageRef,
    /// Reference to its explicit rejection rationale.
    pub rejection_reason: DecisionLineageRef,
}

/// The expected observable and the verifier that can observe it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageExpectedObservable {
    /// Reference to the required future observable definition.
    pub observable: DecisionLineageRef,
    /// Reference to the verifier required to evaluate that observable.
    pub verifier: DecisionLineageRef,
}

/// Existing authority binding plus the public source that authorizes its use.
///
/// `AuthorityBinding` is a binding value, not proof that the named authority was
/// issued or remains live. The referenced authority source must be checked by the
/// owning authorization gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageAuthorization {
    /// Existing grant, policy decision, or authority receipt reference.
    pub source: DecisionLineageRef,
    /// Typed epoch, fence, effect and proof-ceiling binding.
    pub binding: AuthorityBinding,
}

/// One effect and its pre-effect, execution, and outcome records.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageEffect {
    /// Proposal identity, request, idempotency key, effect class and fence.
    pub proposal: DecisionLineageSlot<OperationBinding>,
    /// Existing authority source and its typed binding.
    pub authorization: DecisionLineageSlot<DecisionLineageAuthorization>,
    /// Required future observable and its verifier.
    pub expected_observable: DecisionLineageSlot<DecisionLineageExpectedObservable>,
    /// Canonical receipt, or explicit policy-backed lifecycle state.
    pub execution: DecisionLineageSlot<ReceiptEnvelope>,
    /// Canonical outcome receipt, or explicit policy-backed lifecycle state.
    pub outcome: DecisionLineageSlot<ReceiptEnvelope>,
}

/// Exact historical anchor, current resolution and resolution classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageAnchorLink {
    /// Immutable anchor as it was originally observed.
    pub historical: AnchorReference,
    /// Current anchor, or policy-backed absence when the historical target moved
    /// or was removed.
    pub current: DecisionLineageSlot<AnchorReference>,
    /// Existing typed resolution classification.
    pub resolution: DecisionLineageSlot<AnchorResolutionStatus>,
}

/// Public review target and its disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageReview {
    /// Anchored review item identity.
    pub item: DecisionLineageRef,
    /// Exact public anchor within the reviewed target.
    pub anchor: AnchorReference,
    /// Public disposition reference for the item.
    pub disposition: DecisionLineageRef,
}

/// Artifact binding plus the reference to its immutable source revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageArtifact {
    /// Existing typed artifact identity and digest.
    pub binding: ArtifactBinding,
    /// Public source/provenance reference.
    pub source: DecisionLineageRef,
}

/// Verifier binding plus the public verifier contract reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageVerifier {
    /// Existing typed verifier identity, artifact set, proof ceiling and fence.
    pub binding: VerifierBinding,
    /// Public verifier contract reference.
    pub source: DecisionLineageRef,
}

/// Explicit current-or-superseded relation for the lineage's authority epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DecisionLineageSupersession {
    /// This lineage is current under the cited no-supersession policy.
    Current {
        /// Policy reference governing current-epoch selection.
        policy: DecisionLineageRef,
    },
    /// This lineage was superseded by the identified successor.
    Superseded {
        /// Successor lineage reference; the old lineage is stale for decisions.
        successor: DecisionLineageRef,
    },
}

/// Authority epoch, state fence, and supersession relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionLineageEpochRefs {
    /// Typed current authority epoch.
    pub authority_epoch: EpochId,
    /// Exact typed state fence for the decision snapshot.
    pub state_fence: StateFence,
    /// Current or superseded status; superseded lineages fail closed.
    pub supersession: DecisionLineageSupersession,
}

/// Required typed lineage references for one material decision or continuation.
///
/// Every field is required on the wire. Collections are slots so an empty set
/// cannot silently stand in for missing evidence; an empty present set fails
/// validation. No completeness field is accepted from the producer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionExecutionLineageRefs {
    /// Governing goal.
    pub goal: DecisionLineageSlot<DecisionLineageRef>,
    /// Goal acceptance criteria.
    pub acceptance: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Canonical task ID, task revision and captured fence.
    pub task: DecisionLineageSlot<TaskBinding>,
    /// Observations used at the decision boundary.
    pub observations: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Source evidence and provenance.
    pub evidence: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Current epistemic position, referenced without importing its owner crate.
    pub epistemic_position: DecisionLineageSlot<DecisionLineageRef>,
    /// Material unknowns and unresolved conflicts.
    pub material_unknowns: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Rival hypotheses and their rejection reasons.
    pub rivals: DecisionLineageSlot<Vec<DecisionLineageRival>>,
    /// Chosen public option.
    pub selected_option: DecisionLineageSlot<DecisionLineageRef>,
    /// Public rationale, including why this decision is timely.
    pub rationale: DecisionLineageSlot<DecisionLineageRef>,
    /// Explicit `why now` rationale link.
    pub why_now: DecisionLineageSlot<DecisionLineageRef>,
    /// Conditions that require the decision to be revisited.
    pub revisit_conditions: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Existing typed task, decision, scope, attempt and fence binding.
    pub context: ContextBinding,
    /// Reference to the existing `ActionContract`; the C4 contract is not copied.
    pub action_contract: DecisionLineageSlot<DecisionLineageActionContractRef>,
    /// Each proposed effect and its authorization, observable, execution and outcome.
    pub effects: Vec<DecisionLineageEffect>,
    /// Exact operation bindings associated with the effect records.
    pub operations: DecisionLineageSlot<Vec<OperationBinding>>,
    /// Current and historical diff references.
    pub diffs: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Change observations linked to the operations and diffs.
    pub change_observations: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Historical/current anchor pairs and their resolution status.
    pub anchors: DecisionLineageSlot<Vec<DecisionLineageAnchorLink>>,
    /// Anchored review items and their dispositions.
    pub reviews: DecisionLineageSlot<Vec<DecisionLineageReview>>,
    /// Artifact identities and provenance.
    pub artifacts: DecisionLineageSlot<Vec<DecisionLineageArtifact>>,
    /// Exact verifier bindings and contract references.
    pub verifiers: DecisionLineageSlot<Vec<DecisionLineageVerifier>>,
    /// Decision outcomes and their public evidence.
    pub outcomes: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Memory revisions linked to the recorded outcome.
    pub memory_revisions: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Compaction or omission manifest references.
    pub omissions: DecisionLineageSlot<Vec<DecisionLineageRef>>,
    /// Handoff artifact reference for continuation.
    pub handoff: DecisionLineageSlot<DecisionLineageRef>,
    /// Fence and epoch history for the exact decision snapshot.
    pub epoch: DecisionLineageEpochRefs,
}

impl DecisionExecutionLineageRefs {
    /// Validates this shape for a lifecycle phase and derives its completeness.
    ///
    /// `NotYetProduced` is complete only before its declared due phase. At and
    /// after that phase it is `PARTIAL`; the caller must provide the observed
    /// receipt or an evidence-backed `UNKNOWN` slot. A superseded epoch or fence
    /// mismatch is `STALE`. `UNKNOWN` never means success or causal proof.
    pub fn validate_for_phase(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        let mut result = self
            .validate_required_links(phase)?
            .combine(self.validate_optional_links(phase)?);
        result = result.combine(self.validate_epoch()?);

        let proposed = self.validate_effects(phase, &mut result)?;
        result = result.combine(self.validate_cross_links(phase, &proposed)?);
        Ok(result)
    }

    fn validate_required_links(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        Ok(
            validate_ref_slot(&self.goal, phase, DecisionLineageReferenceKind::Goal, true)?
                .combine(validate_ref_vec_slot(
                    &self.acceptance,
                    phase,
                    DecisionLineageReferenceKind::Acceptance,
                    true,
                )?)
                .combine(self.task.required_at(phase)?)
                .combine(validate_ref_vec_slot(
                    &self.observations,
                    phase,
                    DecisionLineageReferenceKind::Observation,
                    true,
                )?)
                .combine(validate_ref_vec_slot(
                    &self.evidence,
                    phase,
                    DecisionLineageReferenceKind::Evidence,
                    true,
                )?)
                .combine(validate_ref_slot(
                    &self.epistemic_position,
                    phase,
                    DecisionLineageReferenceKind::EpistemicPosition,
                    true,
                )?)
                .combine(validate_ref_slot(
                    &self.selected_option,
                    phase,
                    DecisionLineageReferenceKind::SelectedOption,
                    true,
                )?)
                .combine(validate_ref_slot(
                    &self.rationale,
                    phase,
                    DecisionLineageReferenceKind::Rationale,
                    true,
                )?)
                .combine(validate_ref_slot(
                    &self.why_now,
                    phase,
                    DecisionLineageReferenceKind::WhyNow,
                    true,
                )?)
                .combine(self.action_contract.required_at(phase)?)
                .combine(validate_operation_vec_slot(&self.operations, phase)?),
        )
    }

    fn validate_optional_links(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        let mut result = validate_ref_vec_slot(
            &self.material_unknowns,
            phase,
            DecisionLineageReferenceKind::MaterialUnknown,
            false,
        )?
        .combine(self.rivals.validate_at(phase)?)
        .combine(validate_ref_vec_slot(
            &self.revisit_conditions,
            phase,
            DecisionLineageReferenceKind::RevisitCondition,
            false,
        )?)
        .combine(validate_ref_vec_slot(
            &self.diffs,
            phase,
            DecisionLineageReferenceKind::Diff,
            false,
        )?)
        .combine(validate_ref_vec_slot(
            &self.change_observations,
            phase,
            DecisionLineageReferenceKind::ChangeObservation,
            false,
        )?)
        .combine(self.anchors.validate_at(phase)?)
        .combine(self.reviews.validate_at(phase)?)
        .combine(self.artifacts.validate_at(phase)?)
        .combine(validate_ref_vec_slot(
            &self.outcomes,
            phase,
            DecisionLineageReferenceKind::Outcome,
            false,
        )?)
        .combine(validate_ref_vec_slot(
            &self.memory_revisions,
            phase,
            DecisionLineageReferenceKind::MemoryRevision,
            false,
        )?)
        .combine(validate_ref_vec_slot(
            &self.omissions,
            phase,
            DecisionLineageReferenceKind::OmissionManifest,
            false,
        )?)
        .combine(validate_ref_slot(
            &self.handoff,
            phase,
            DecisionLineageReferenceKind::HandoffArtifact,
            false,
        )?);
        result = result.combine(match &self.verifiers {
            DecisionLineageSlot::NotApplicable { .. } => {
                self.verifiers.validate_at(phase)?;
                DecisionLineageCompleteness::Partial
            }
            _ if phase >= DecisionLineagePhase::Verification => {
                self.verifiers.required_at(phase)?
            }
            _ => self.verifiers.validate_at(phase)?,
        });
        Ok(result)
    }

    fn validate_epoch(&self) -> Result<DecisionLineageCompleteness, ContextError> {
        self.epoch
            .state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        let mut result = DecisionLineageCompleteness::Complete;
        match &self.epoch.supersession {
            DecisionLineageSupersession::Current { policy } => {
                policy.validate_as(DecisionLineageReferenceKind::Policy)?;
            }
            DecisionLineageSupersession::Superseded { successor } => {
                successor.validate_as(DecisionLineageReferenceKind::Successor)?;
                result = result.combine(DecisionLineageCompleteness::Stale);
            }
        }
        if !self
            .epoch
            .state_fence
            .authority_epoch
            .is_same_authority(&self.epoch.authority_epoch)
        {
            result = result.combine(DecisionLineageCompleteness::Stale);
        }
        Ok(result)
    }

    fn validate_effects(
        &self,
        phase: DecisionLineagePhase,
        result: &mut DecisionLineageCompleteness,
    ) -> Result<Vec<OperationBinding>, ContextError> {
        if self.effects.len() > MAX_DECISION_LINEAGE_ITEMS {
            return Err(ContextError::Bounds {
                field: "lineage.effects",
            });
        }
        if self.effects.is_empty() {
            *result = result.combine(DecisionLineageCompleteness::Partial);
        }
        let mut proposed = Vec::with_capacity(self.effects.len());
        for effect in &self.effects {
            *result = result.combine(effect.validate_for_phase(phase, &self.epoch.state_fence)?);
            if let Some(operation) = effect.proposal.present() {
                proposed.push(operation.clone());
            }
        }
        if let Some(operations) = self.operations.present()
            && !operations.eq(&proposed)
        {
            *result = result.combine(DecisionLineageCompleteness::Stale);
        }
        Ok(proposed)
    }

    fn validate_cross_links(
        &self,
        phase: DecisionLineagePhase,
        proposed: &[OperationBinding],
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        self.context.validate()?;
        let mut result = DecisionLineageCompleteness::Complete;
        if let Some(task) = self.task.present()
            && (task.state_fence != self.epoch.state_fence || task.task_id != self.context.task_id)
        {
            result = result.combine(DecisionLineageCompleteness::Stale);
        }
        if self.context.state_fence != self.epoch.state_fence {
            result = result.combine(DecisionLineageCompleteness::Stale);
        }
        if let Some(verifiers) = self.verifiers.present() {
            for expected in self
                .effects
                .iter()
                .filter_map(|effect| effect.expected_observable.present())
                .map(|expected| &expected.verifier)
            {
                if !verifiers
                    .iter()
                    .any(|verifier| verifier.source.eq(expected))
                {
                    result = result.combine(DecisionLineageCompleteness::Partial);
                }
            }
            if verifiers
                .iter()
                .any(|verifier| verifier.binding.state_fence != self.epoch.state_fence)
            {
                result = result.combine(DecisionLineageCompleteness::Stale);
            }
        }
        if let Some(operation_id) = &self.context.operation_id
            && !proposed
                .iter()
                .any(|operation| &operation.operation_id == operation_id)
        {
            result = result.combine(DecisionLineageCompleteness::Stale);
        }
        if let Some(anchors) = self.anchors.present() {
            for anchor in anchors {
                result = result.combine(anchor.validate_for_phase(phase)?);
            }
        }
        Ok(result)
    }
}

impl DecisionLineageEffect {
    fn validate_for_phase(
        &self,
        phase: DecisionLineagePhase,
        current_fence: &StateFence,
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        let mut result = self
            .proposal
            .required_at(phase)?
            .combine(self.authorization.required_at(phase)?)
            .combine(self.expected_observable.required_at(phase)?);
        for slot in [&self.execution, &self.outcome] {
            result = result.combine(if phase == DecisionLineagePhase::BeforeEffect {
                match slot {
                    DecisionLineageSlot::NotApplicable { .. } => {
                        slot.validate_at(phase)?;
                        DecisionLineageCompleteness::Partial
                    }
                    _ => slot.validate_at(phase)?,
                }
            } else {
                match slot {
                    DecisionLineageSlot::Present { value } => {
                        value.validate_payload()?;
                        DecisionLineageCompleteness::Complete
                    }
                    DecisionLineageSlot::Unknown { .. } => slot.validate_at(phase)?,
                    DecisionLineageSlot::NotApplicable { .. }
                    | DecisionLineageSlot::NotYetProduced { .. } => {
                        slot.validate_at(phase)?;
                        DecisionLineageCompleteness::Partial
                    }
                }
            });
        }

        let (Some(proposal), Some(authorization), Some(expected)) = (
            self.proposal.present(),
            self.authorization.present(),
            self.expected_observable.present(),
        ) else {
            return Ok(result.combine(DecisionLineageCompleteness::Partial));
        };
        if proposal.state_fence != *current_fence
            || authorization.binding.state_fence != proposal.state_fence
            || !authorization
                .binding
                .state_fence
                .authority_epoch
                .is_same_authority(&authorization.binding.authority_epoch)
            || authorization.binding.allowed_effect != proposal.effect
        {
            result = result.combine(DecisionLineageCompleteness::Stale);
        }
        authorization.validate_payload()?;
        expected.validate_payload()?;

        for (slot, required_kind) in [
            (&self.execution, Some(ReceiptKind::Operation)),
            (&self.outcome, None),
        ] {
            if let Some(receipt) = slot.present() {
                receipt
                    .validate()
                    .map_err(|_| ContextError::InvalidField("lineage.receipt"))?;
                if &receipt.core.operation != proposal
                    || receipt.core.authority != authorization.binding
                    || required_kind.is_some_and(|kind| receipt.core.kind != kind)
                    || (required_kind.is_none()
                        && !matches!(
                            receipt.core.kind,
                            ReceiptKind::Operation
                                | ReceiptKind::Verification
                                | ReceiptKind::Problem
                        ))
                {
                    result = result.combine(DecisionLineageCompleteness::Stale);
                }
            }
        }
        Ok(result)
    }
}

fn validate_ref_slot(
    slot: &DecisionLineageSlot<DecisionLineageRef>,
    phase: DecisionLineagePhase,
    expected: DecisionLineageReferenceKind,
    required: bool,
) -> Result<DecisionLineageCompleteness, ContextError> {
    let state = if required {
        slot.required_at(phase)?
    } else {
        slot.validate_at(phase)?
    };
    if let Some(reference) = slot.present() {
        reference.validate_as(expected)?;
    }
    Ok(state)
}

fn validate_ref_vec_slot(
    slot: &DecisionLineageSlot<Vec<DecisionLineageRef>>,
    phase: DecisionLineagePhase,
    expected: DecisionLineageReferenceKind,
    required: bool,
) -> Result<DecisionLineageCompleteness, ContextError> {
    let state = if required {
        slot.required_at(phase)?
    } else {
        slot.validate_at(phase)?
    };
    if let Some(references) = slot.present() {
        for reference in references {
            reference.validate_as(expected)?;
        }
    }
    Ok(state)
}

fn validate_operation_vec_slot(
    slot: &DecisionLineageSlot<Vec<OperationBinding>>,
    phase: DecisionLineagePhase,
) -> Result<DecisionLineageCompleteness, ContextError> {
    slot.required_at(phase)
}

trait LineagePayload: Eq {
    fn validate_payload(&self) -> Result<(), ContextError>;
}

impl LineagePayload for DecisionLineageRef {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.validate()
    }
}

impl<T: LineagePayload> LineagePayload for Vec<T> {
    fn validate_payload(&self) -> Result<(), ContextError> {
        if self.is_empty() {
            return Err(ContextError::MissingField("lineage.present_collection"));
        }
        if self.len() > MAX_DECISION_LINEAGE_ITEMS {
            return Err(ContextError::Bounds {
                field: "lineage.collection",
            });
        }
        for (index, value) in self.iter().enumerate() {
            value.validate_payload()?;
            if self[..index].contains(value) {
                return Err(ContextError::Duplicate("lineage.collection"));
            }
        }
        Ok(())
    }
}

impl LineagePayload for DecisionLineageActionContractRef {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.validate()
    }
}

impl LineagePayload for TaskBinding {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)
    }
}

impl LineagePayload for OperationBinding {
    fn validate_payload(&self) -> Result<(), ContextError> {
        validate_text(&self.idempotency_key, "lineage.operation.idempotency_key")?;
        validate_text(&self.operation_kind, "lineage.operation.operation_kind")?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)
    }
}

impl LineagePayload for DecisionLineageRival {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.rival
            .validate_as(DecisionLineageReferenceKind::Rival)?;
        self.rejection_reason
            .validate_as(DecisionLineageReferenceKind::RejectionReason)
    }
}

impl LineagePayload for AuthorityBinding {
    fn validate_payload(&self) -> Result<(), ContextError> {
        validate_text(&self.authority_owner, "lineage.authority.owner")?;
        self.state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)
    }
}

impl LineagePayload for DecisionLineageAuthorization {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.source
            .validate_as(DecisionLineageReferenceKind::AuthoritySource)?;
        self.binding.validate_payload()
    }
}

impl LineagePayload for DecisionLineageExpectedObservable {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.observable
            .validate_as(DecisionLineageReferenceKind::ExpectedObservable)?;
        self.verifier
            .validate_as(DecisionLineageReferenceKind::VerifierContract)
    }
}

impl LineagePayload for ReceiptEnvelope {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.validate()
            .map_err(|_| ContextError::InvalidField("lineage.receipt"))
    }
}

impl LineagePayload for AnchorResolutionStatus {
    fn validate_payload(&self) -> Result<(), ContextError> {
        Ok(())
    }
}

impl LineagePayload for AnchorReference {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.validate()
            .map_err(|_| ContextError::InvalidField("lineage.anchor"))
    }
}

impl LineagePayload for DecisionLineageAnchorLink {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.historical
            .validate()
            .map_err(|_| ContextError::InvalidField("lineage.anchor.historical"))?;
        self.current
            .present()
            .map_or(Ok(()), LineagePayload::validate_payload)?;
        self.resolution
            .present()
            .map_or(Ok(()), LineagePayload::validate_payload)
    }
}

impl DecisionLineageAnchorLink {
    fn validate_for_phase(
        &self,
        phase: DecisionLineagePhase,
    ) -> Result<DecisionLineageCompleteness, ContextError> {
        self.historical
            .validate()
            .map_err(|_| ContextError::InvalidField("lineage.anchor.historical"))?;
        let mut state = self
            .current
            .validate_at(phase)?
            .combine(self.resolution.validate_at(phase)?);
        if matches!(&self.current, DecisionLineageSlot::NotApplicable { .. })
            || matches!(&self.resolution, DecisionLineageSlot::NotApplicable { .. })
        {
            state = state.combine(DecisionLineageCompleteness::Partial);
        }
        if phase >= DecisionLineagePhase::Resume {
            state = state.combine(self.current.required_at(phase)?);
            state = state.combine(self.resolution.required_at(phase)?);
        }
        if let Some(resolution) = self.resolution.present() {
            state = state.combine(match resolution {
                AnchorResolutionStatus::Exact
                | AnchorResolutionStatus::Moved
                | AnchorResolutionStatus::Modified => DecisionLineageCompleteness::Complete,
                AnchorResolutionStatus::Stale => DecisionLineageCompleteness::Stale,
                AnchorResolutionStatus::Ambiguous | AnchorResolutionStatus::Unavailable => {
                    DecisionLineageCompleteness::Unknown
                }
                AnchorResolutionStatus::Deleted => DecisionLineageCompleteness::Partial,
            });
        }
        Ok(state)
    }
}

impl LineagePayload for DecisionLineageReview {
    fn validate_payload(&self) -> Result<(), ContextError> {
        self.item
            .validate_as(DecisionLineageReferenceKind::ReviewItem)?;
        self.anchor
            .validate()
            .map_err(|_| ContextError::InvalidField("lineage.review.anchor"))?;
        self.disposition
            .validate_as(DecisionLineageReferenceKind::ReviewDisposition)
    }
}

impl LineagePayload for DecisionLineageArtifact {
    fn validate_payload(&self) -> Result<(), ContextError> {
        validate_digest(&self.binding.sha256, "lineage.artifact.sha256")?;
        if let Some(revision) = &self.binding.source_revision {
            validate_text(revision, "lineage.artifact.source_revision")?;
        }
        self.source
            .validate_as(DecisionLineageReferenceKind::ArtifactSource)
    }
}

impl LineagePayload for DecisionLineageVerifier {
    fn validate_payload(&self) -> Result<(), ContextError> {
        if self.binding.artifact_ids.is_empty() {
            return Err(ContextError::MissingField("lineage.verifier.artifacts"));
        }
        if self.binding.artifact_ids.len() > MAX_DECISION_LINEAGE_ITEMS {
            return Err(ContextError::Bounds {
                field: "lineage.verifier.artifacts",
            });
        }
        for (index, artifact_id) in self.binding.artifact_ids.iter().enumerate() {
            if self.binding.artifact_ids[..index].contains(artifact_id) {
                return Err(ContextError::Duplicate("lineage.verifier.artifacts"));
            }
        }
        self.binding
            .state_fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        self.source
            .validate_as(DecisionLineageReferenceKind::VerifierContract)
    }
}
