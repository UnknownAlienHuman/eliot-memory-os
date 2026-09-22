//! Bounded Common Ground and scoped understanding assessment (#223).
//!
//! [`assess_common_ground`] checks Common Ground as public causal-inheritance
//! survival across model/harness change, and [`assess_scoped`] emits one
//! [`ScopedUnderstandingAssessment`] per question/task family at one State
//! Fence. Both consume immutable owner projections **by handle only**:
//!
//! * the already-compiled [`ActiveUnderstandingView`] (frozen 9/9,
//!   `eliot-context-contracts`), never a second `ContextCompiler`
//!   invocation and never a second admission pass;
//! * the unit-#3 [`AcceptedSourceProjection`] (frozen owner contract,
//!   `eliot-dreamer-contracts`), cited by exact handle/revision/digest
//!   triple with no similarity fallback;
//! * the owner [`ProviderContribution`] (frozen 11/11,
//!   `eliot-epistemic-contracts`), validated and fence-gated, echoed by
//!   digest and claim;
//! * owner experience envelopes ([`JournalProjection`], [`BankProjection`],
//!   [`FeedbackProjection`], `eliot-observation-contracts`) for
//!   outcome/verifier-side evidence, validated as wholes with carried
//!   (never inferred) fences.
//!
//! Outputs are reversible candidates with the exact independently recheckable
//! denominator (`declared_question_task_family_times_state_fence_with_
//! onboarding_slice_plus_discriminator_plus_outcome_verifier_closure`):
//! [`CommonGroundAssessment`] and [`ScopedUnderstandingAssessment`] reuse the
//! frozen `UnderstandingAssessment` field contract verbatim — no new public
//! assessment type is invented here. There is no global `understands` flag,
//! no single understanding score, no model/judgment score, and no reactive
//! path D. [`DenominatorRecheck`] re-resolves every cited triple so any
//! `LOCALLY_ADEQUATE` stays independently recheckable; product claims
//! additionally require held-out evidence.
//!
//! `MemoryContextProjectionRequest` stays `NOT_FROZEN` in the freeze: this
//! consumer never issues projection requests — every input arrives by handle
//! — so the shape is not implemented here. It belongs to whichever consumer
//! owner needs to request memory-context projections, not to assessment.
//!
//! This module performs no model, storage, network, canonical-write,
//! admission, delivery, lease, or effect behavior. It is a static candidate
//! record, not edge, product, or pulse proof.

#![forbid(unsafe_code)]

use eliot_contracts::{ArtifactId, ContractVersion, StateFence, canonical_json_bytes, sha256_hex};
use eliot_context_contracts::{ActiveUnderstandingView, ContextError};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, AcceptedSourceRef, SelfQueryContractError,
};
use eliot_epistemic_contracts::{ContractError as EpistemicError, ProviderContribution};
use eliot_observation_contracts::{
    BankProjection, ExperienceRecordRef, FeedbackProjection, JournalProjection, ObservationError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";
/// Exact contract version every assessment candidate in this crate is written
/// against (`VR-EXACT-CONTRACT-VERSION` applied to the own wire shape).
pub const UA_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Maximum evidence cites carried by one assessment slot list.
pub const MAX_EVIDENCE_CITES: usize = 256;
/// Maximum Unicode scalar values accepted for one scope/identity text field.
pub const MAX_SCOPE_TEXT: usize = 256;
/// Maximum missing-input names carried by one scope.
pub const MAX_MISSING_INPUTS: usize = 32;

/// Assessment failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AssessmentError {
    /// A compiled-view shape is invalid.
    #[error("understanding assessment: {0}")]
    UpstreamContext(#[from] ContextError),
    /// An accepted-source shape is invalid.
    #[error("understanding assessment: {0}")]
    UpstreamDreamer(#[from] SelfQueryContractError),
    /// An epistemic contribution shape is invalid.
    #[error("understanding assessment: {0}")]
    UpstreamEpistemic(#[from] EpistemicError),
    /// An experience envelope shape is invalid.
    #[error("understanding assessment: {0}")]
    UpstreamObservation(#[from] ObservationError),
    /// A shared foundation identity or digest shape is invalid.
    #[error("understanding assessment: invalid foundation identity")]
    UpstreamContracts(#[from] eliot_contracts::ContractError),
    /// This crate's own contract version drifted from [`UA_CONTRACT_VERSION`].
    #[error("understanding assessment: version drift")]
    VersionMismatch,
    /// A carried fence is incompatible with the assessment fence.
    #[error("understanding assessment: fence mismatch at {field}")]
    FenceMismatch {
        /// Field at fault.
        field: &'static str,
    },
    /// A cited accepted-source triple is stale or uncited.
    #[error("understanding assessment: stale citation at {field}")]
    StaleCitation {
        /// Field at fault.
        field: &'static str,
    },
    /// A required assessment input is absent.
    #[error("understanding assessment: missing input {field}")]
    MissingInput {
        /// Field at fault.
        field: &'static str,
    },
    /// A scope, identity, or slot text is invalid.
    #[error("understanding assessment: invalid field {field}: {reason}")]
    InvalidField {
        /// Field at fault.
        field: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// A frozen digest does not match its canonical preimage.
    #[error("understanding assessment: digest mismatch at {field}")]
    DigestMismatch {
        /// Field at fault.
        field: &'static str,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), AssessmentError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(AssessmentError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    if value.chars().count() > MAX_SCOPE_TEXT {
        return Err(AssessmentError::InvalidField {
            field,
            reason: "exceeds bounded length",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), AssessmentError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(AssessmentError::InvalidField {
            field,
            reason: "must be 64 lowercase hex characters",
        });
    }
    Ok(())
}

fn fence_shape(value: &StateFence, field: &'static str) -> Result<(), AssessmentError> {
    value.validate().map_err(|_| AssessmentError::FenceMismatch { field })?;
    Ok(())
}

fn gate_compatible(
    carried: &StateFence,
    governing: &StateFence,
    field: &'static str,
) -> Result<(), AssessmentError> {
    fence_shape(carried, field)?;
    if !carried.is_compatible_with(governing) {
        return Err(AssessmentError::FenceMismatch { field });
    }
    Ok(())
}

/// Assessment status vocabulary (I06-16; `NOT_ONBOARDED` forbids adequacy).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AssessmentStatus {
    /// No current Product/State-Fence-bound situation model or sufficient
    /// onboarding slice exists; adequacy is forbidden.
    NotOnboarded,
    /// Onboarded but never probed: no discriminator run yet.
    Untested,
    /// The exact independently recheckable denominator closure holds.
    LocallyAdequate,
    /// A governing verdict owner refuted the claim (set by the review path,
    /// never constructed here).
    Refuted,
    /// Probed but the closure is partial or unresolved.
    Inconclusive,
    /// A recheck found drifted inputs; the candidate no longer binds.
    Stale,
}

/// One question/task family at one product/State Fence with its onboarding
/// slice: the denominator anchor every assessment in this crate carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentScope {
    /// Declared question family under assessment.
    pub question_family: String,
    /// Declared task family under assessment.
    pub task_family: String,
    /// Product the assessment is bound to.
    pub product_id: String,
    /// Work scope the compiled view must be bound to.
    pub scope_id: String,
    /// Governing fence every carried fence gates against.
    pub state_fence: StateFence,
    /// Onboarding slice handle or note; blank means not onboarded.
    pub onboarding_slice: String,
    /// Names of still-missing inputs; non-empty means not onboarded.
    pub missing_inputs: Vec<String>,
}

impl AssessmentScope {
    /// Validate identity texts, fence shape, and missing-input bounds.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        text(&self.question_family, "scope.question_family")?;
        text(&self.task_family, "scope.task_family")?;
        text(&self.product_id, "scope.product_id")?;
        text(&self.scope_id, "scope.scope_id")?;
        fence_shape(&self.state_fence, "scope.state_fence")?;
        if !self.onboarding_slice.trim().is_empty() {
            text(&self.onboarding_slice, "scope.onboarding_slice")?;
        }
        if self.missing_inputs.len() > MAX_MISSING_INPUTS {
            return Err(AssessmentError::InvalidField {
                field: "scope.missing_inputs",
                reason: "exceeds bounded length",
            });
        }
        for missing in &self.missing_inputs {
            text(missing, "scope.missing_inputs")?;
        }
        Ok(())
    }

    /// Onboarded means a sufficient slice exists and nothing is missing.
    #[must_use]
    pub fn is_onboarded(&self) -> bool {
        !self.onboarding_slice.trim().is_empty() && self.missing_inputs.is_empty()
    }
}

/// Source-family label for one evidence cite: labels only, never bodies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CitedFamily {
    /// Accepted Architecture/Implementation source triple.
    AcceptedSource,
    /// Admitted epistemic contribution digest.
    EpistemicContribution,
    /// Governor observation journal record.
    JournalRecord,
    /// Experience bank record ref.
    BankRecord,
    /// Agent feedback receipt ref.
    FeedbackRecord,
    /// Task outcome record.
    OutcomeRecord,
    /// Verifier receipt.
    VerifierReceipt,
}

/// One handle-bound evidence cite: identity plus revision cursor and digest.
///
/// Accepted-source cites revalidate by exact triple match against the
/// supplied [`AcceptedSourceProjection`]; all other families are
/// shape-checked here and bound to their owner envelopes by the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCite {
    /// Exact canonical handle cited.
    pub handle: ArtifactId,
    /// Which owner family this cite belongs to.
    pub family: CitedFamily,
    /// Revision cursor observed for this handle.
    pub revision: String,
    /// Content digest at the revision cursor.
    pub digest: String,
}

impl EvidenceCite {
    /// Validate handle, revision, and digest shape.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        text(&self.revision, "cite.revision")?;
        digest(&self.digest, "cite.digest")?;
        Ok(())
    }

    /// Cite one projected accepted-source ref exactly.
    pub fn accepted(source: &AcceptedSourceRef) -> Result<Self, AssessmentError> {
        source.validate()?;
        Ok(Self {
            handle: source.source_handle.clone(),
            family: CitedFamily::AcceptedSource,
            revision: source.revision.clone(),
            digest: source.digest.clone(),
        })
    }

    /// Cite one validated owner epistemic contribution by digest and claim.
    pub fn contribution(contribution: &ProviderContribution) -> Result<Self, AssessmentError> {
        contribution.validate()?;
        Ok(Self {
            handle: ArtifactId::new(contribution.claim.as_str())?,
            family: CitedFamily::EpistemicContribution,
            revision: contribution.source_revision.clone(),
            digest: contribution.position_digest.clone(),
        })
    }

    /// Cite one validated experience record ref under an explicit family.
    pub fn experience(
        reference: &ExperienceRecordRef,
        family: CitedFamily,
    ) -> Result<Self, AssessmentError> {
        match family {
            CitedFamily::JournalRecord
            | CitedFamily::BankRecord
            | CitedFamily::FeedbackRecord => {}
            _ => {
                return Err(AssessmentError::InvalidField {
                    field: "cite.family",
                    reason: "experience refs require a journal, bank, or feedback family",
                });
            }
        }
        reference.validate()?;
        Ok(Self {
            handle: reference.handle.clone(),
            family,
            revision: reference.revision.revision.clone(),
            digest: reference.revision.content_sha256.clone(),
        })
    }
}

/// Rival-aware closure backing every adequacy verdict: a public rival-aware
/// model, a prediction fixed before observation, a discriminative
/// probe/action, applicable outcome/verifier evidence, revision on failure,
/// and held-out evidence where product claims apply.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssessmentClosure {
    /// Public rival-aware model refs.
    pub rival_model: Vec<EvidenceCite>,
    /// Predictions fixed before observation.
    pub pre_probe_prediction: Vec<EvidenceCite>,
    /// Selected discriminative probe/action refs.
    pub discriminator: Vec<EvidenceCite>,
    /// Applicable outcome/verifier evidence refs.
    pub outcome_verifier: Vec<EvidenceCite>,
    /// Model revision after outcome refs.
    pub revision: Vec<EvidenceCite>,
    /// Held-out/compositional transfer evidence refs.
    pub held_out: Vec<EvidenceCite>,
}

impl AssessmentClosure {
    fn cites(cites: &[EvidenceCite], field: &'static str) -> Result<(), AssessmentError> {
        if cites.len() > MAX_EVIDENCE_CITES {
            return Err(AssessmentError::InvalidField {
                field,
                reason: "exceeds bounded length",
            });
        }
        for cite in cites {
            cite.validate()?;
        }
        Ok(())
    }

    /// Validate every cite list bound.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        Self::cites(&self.rival_model, "closure.rival_model")?;
        Self::cites(&self.pre_probe_prediction, "closure.pre_probe_prediction")?;
        Self::cites(&self.discriminator, "closure.discriminator")?;
        Self::cites(&self.outcome_verifier, "closure.outcome_verifier")?;
        Self::cites(&self.revision, "closure.revision")?;
        Self::cites(&self.held_out, "closure.held_out")?;
        Ok(())
    }

    /// Names of closure legs still empty; held-out required only when
    /// `product_claims` is set.
    #[must_use]
    pub fn missing(&self, product_claims: bool) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.rival_model.is_empty() {
            missing.push("closure.rival_model");
        }
        if self.pre_probe_prediction.is_empty() {
            missing.push("closure.pre_probe_prediction");
        }
        if self.discriminator.is_empty() {
            missing.push("closure.discriminator");
        }
        if self.outcome_verifier.is_empty() {
            missing.push("closure.outcome_verifier");
        }
        if self.revision.is_empty() {
            missing.push("closure.revision");
        }
        if product_claims && self.held_out.is_empty() {
            missing.push("closure.held_out");
        }
        missing
    }

    /// The full structural closure holds (held-out included for product claims).
    #[must_use]
    pub fn is_complete_for(&self, product_claims: bool) -> bool {
        self.missing(product_claims).is_empty()
    }
}

/// Experience evidence supplied to an assessment: owner envelopes by
/// reference, validated as wholes with carried (never inferred) fences.
#[derive(Clone, Copy, Debug)]
pub enum ExperienceEvidence<'a> {
    /// Governor journal envelope with full owner records.
    Journal(&'a JournalProjection),
    /// Experience bank envelope with opaque refs.
    Bank(&'a BankProjection),
    /// Agent feedback envelope with opaque refs.
    Feedback(&'a FeedbackProjection),
}

impl ExperienceEvidence<'_> {
    /// Run the owner envelope validation.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        match self {
            ExperienceEvidence::Journal(projection) => projection.validate().map_err(Into::into),
            ExperienceEvidence::Bank(projection) => projection.validate().map_err(Into::into),
            ExperienceEvidence::Feedback(projection) => projection.validate().map_err(Into::into),
        }
    }

    /// Fence this envelope was read under, carried for edge gating.
    #[must_use]
    pub fn fence(&self) -> &StateFence {
        match self {
            ExperienceEvidence::Journal(projection) => &projection.fence,
            ExperienceEvidence::Bank(projection) => &projection.fence,
            ExperienceEvidence::Feedback(projection) => &projection.fence,
        }
    }
}

/// Verdict of an independent denominator recheck: the declared triple is
/// re-resolved, fences re-gated, and the frozen digest recomputed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenominatorRecheck {
    /// True only with no missing slots, no drifted cites, and a matching digest.
    pub complete: bool,
    /// Required slots or closure legs still empty.
    pub missing: Vec<String>,
    /// Cites whose triple no longer matches the supplied projection.
    pub drifted: Vec<String>,
}

/// Check every accepted-source cite in `slots` against the projection by
/// exact triple match; other families are shape-checked only.
fn check_slot_cites(
    slots: &[&[EvidenceCite]],
    sources: &AcceptedSourceProjection,
    drifted: &mut Vec<String>,
    slot_names: &[&str],
) -> Result<(), AssessmentError> {
    for (slot, name) in slots.iter().zip(slot_names.iter()) {
        for cite in slot.iter() {
            cite.validate()?;
            if cite.family == CitedFamily::AcceptedSource
                && sources
                    .check_cited(&cite.handle, &cite.revision, &cite.digest)
                    .is_err()
            {
                drifted.push((*name).to_string());
            }
        }
    }
    Ok(())
}

/// Gate every carried fence against the assessment fence.
fn gate_inputs(
    view: &ActiveUnderstandingView,
    sources: &AcceptedSourceProjection,
    contribution: Option<&ProviderContribution>,
    experience: &[ExperienceEvidence<'_>],
    scope: &AssessmentScope,
) -> Result<(), AssessmentError> {
    view.validate()?;
    sources.validate()?;
    if view.binding.scope_id.as_str() != scope.scope_id {
        return Err(AssessmentError::InvalidField {
            field: "assessment.scope_id",
            reason: "compiled view is bound to a different work scope",
        });
    }
    gate_compatible(
        &view.binding.state_fence,
        &scope.state_fence,
        "assessment.view_fence",
    )?;
    gate_compatible(
        &sources.fence,
        &scope.state_fence,
        "assessment.sources_fence",
    )?;
    if let Some(contribution) = contribution {
        contribution.validate()?;
        gate_compatible(
            &contribution.fence,
            &scope.state_fence,
            "assessment.contribution_fence",
        )?;
    }
    for (index, evidence) in experience.iter().enumerate() {
        evidence.validate()?;
        if index >= MAX_EVIDENCE_CITES {
            return Err(AssessmentError::InvalidField {
                field: "assessment.experience",
                reason: "exceeds bounded length",
            });
        }
        gate_compatible(
            evidence.fence(),
            &scope.state_fence,
            "assessment.experience_fence",
        )?;
    }
    Ok(())
}

fn decide_status(
    onboarded: bool,
    slots_filled: bool,
    closure: &AssessmentClosure,
    product_claims: bool,
) -> AssessmentStatus {
    if !onboarded {
        return AssessmentStatus::NotOnboarded;
    }
    if !closure.is_complete_for(product_claims) {
        if closure.discriminator.is_empty() {
            return AssessmentStatus::Untested;
        }
        return AssessmentStatus::Inconclusive;
    }
    if !slots_filled {
        return AssessmentStatus::Inconclusive;
    }
    AssessmentStatus::LocallyAdequate
}

/// Common Ground assessment candidate: the 7 frozen `common_ground_*` fields
/// plus requalification scope, status, and frozen digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommonGroundAssessment {
    /// Exact contract version this candidate was written against.
    pub contract_version: ContractVersion,
    /// Denominator anchor: one question/task family at one fence.
    pub scope: AssessmentScope,
    /// Terminology compatibility evidence cites.
    pub common_ground_terminology_compatibility: Vec<EvidenceCite>,
    /// Reference compatibility evidence cites.
    pub common_ground_reference_compatibility: Vec<EvidenceCite>,
    /// Commitment compatibility evidence cites.
    pub common_ground_commitment_compatibility: Vec<EvidenceCite>,
    /// Action-consequence compatibility evidence cites.
    pub common_ground_action_consequence_compatibility: Vec<EvidenceCite>,
    /// Goals/decisions/invariants/rivals/unknowns survival evidence cites.
    pub common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change:
        Vec<EvidenceCite>,
    /// Public inheritance transfer refs.
    pub common_ground_public_inheritance_transfer_refs: Vec<EvidenceCite>,
    /// Requalification scope for tacit competence.
    pub common_ground_requalification_scope_for_tacit_competence: String,
    /// Assessment status; never adequate without the full closure.
    pub status: AssessmentStatus,
    /// Frozen digest over this shape, excluding this field.
    pub digest: String,
}

impl CommonGroundAssessment {
    fn slot_lists(&self) -> [&[EvidenceCite]; 6] {
        [
            &self.common_ground_terminology_compatibility,
            &self.common_ground_reference_compatibility,
            &self.common_ground_commitment_compatibility,
            &self.common_ground_action_consequence_compatibility,
            &self
                .common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change,
            &self.common_ground_public_inheritance_transfer_refs,
        ]
    }

    /// Compute the frozen digest over this shape.
    pub fn compute_digest(&self) -> Result<String, AssessmentError> {
        #[derive(Serialize)]
        struct CommonGroundDigest<'a> {
            contract_version: &'a ContractVersion,
            scope: &'a AssessmentScope,
            terminology: &'a [EvidenceCite],
            reference: &'a [EvidenceCite],
            commitment: &'a [EvidenceCite],
            action_consequence: &'a [EvidenceCite],
            survival: &'a [EvidenceCite],
            transfer_refs: &'a [EvidenceCite],
            requalification_scope: &'a str,
            status: AssessmentStatus,
        }
        canonical_json_bytes(&CommonGroundDigest {
            contract_version: &self.contract_version,
            scope: &self.scope,
            terminology: &self.common_ground_terminology_compatibility,
            reference: &self.common_ground_reference_compatibility,
            commitment: &self.common_ground_commitment_compatibility,
            action_consequence: &self.common_ground_action_consequence_compatibility,
            survival: &self
                .common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change,
            transfer_refs: &self.common_ground_public_inheritance_transfer_refs,
            requalification_scope: &self
                .common_ground_requalification_scope_for_tacit_competence,
            status: self.status,
        })
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AssessmentError::DigestMismatch {
            field: "assessment.digest",
        })
    }

    /// Validate version, scope, slots, requalification text, and digest.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.contract_version != UA_CONTRACT_VERSION {
            return Err(AssessmentError::VersionMismatch);
        }
        self.scope.validate()?;
        for slot in self.slot_lists() {
            AssessmentClosure::cites(slot, "assessment.slot")?;
        }
        text(
            &self.common_ground_requalification_scope_for_tacit_competence,
            "assessment.common_ground_requalification_scope_for_tacit_competence",
        )?;
        digest(&self.digest, "assessment.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(AssessmentError::DigestMismatch {
                field: "assessment.digest",
            });
        }
        Ok(())
    }

    /// Independently recheck the denominator: fences, cited triples, digest.
    pub fn recheck(
        &self,
        view: &ActiveUnderstandingView,
        sources: &AcceptedSourceProjection,
    ) -> Result<DenominatorRecheck, AssessmentError> {
        view.validate()?;
        sources.validate()?;
        gate_compatible(
            &view.binding.state_fence,
            &self.scope.state_fence,
            "assessment.view_fence",
        )?;
        gate_compatible(
            &sources.fence,
            &self.scope.state_fence,
            "assessment.sources_fence",
        )?;
        let mut drifted = Vec::new();
        check_slot_cites(
            &self.slot_lists(),
            sources,
            &mut drifted,
            &[
                "common_ground_terminology_compatibility",
                "common_ground_reference_compatibility",
                "common_ground_commitment_compatibility",
                "common_ground_action_consequence_compatibility",
                "common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change",
                "common_ground_public_inheritance_transfer_refs",
            ],
        )?;
        let mut missing = Vec::new();
        for (slot, name) in self.slot_lists().iter().zip(
            [
                "common_ground_terminology_compatibility",
                "common_ground_reference_compatibility",
                "common_ground_commitment_compatibility",
                "common_ground_action_consequence_compatibility",
                "common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change",
                "common_ground_public_inheritance_transfer_refs",
            ],
        ) {
            if slot.is_empty() {
                missing.push(name.to_string());
            }
        }
        if self.digest != self.compute_digest()? {
            drifted.push("assessment.digest".to_string());
        }
        Ok(DenominatorRecheck {
            complete: missing.is_empty() && drifted.is_empty(),
            missing,
            drifted,
        })
    }
}

/// Inputs to [`assess_common_ground`]: by-handle owner evidence plus the
/// declared scope, compatibility slots, closure, and product-claim flag.
#[derive(Clone, Debug)]
pub struct CommonGroundInput<'a> {
    /// Already-compiled understanding view, by handle.
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks.
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Optional experience envelopes for outcome-side context.
    pub experience: Vec<ExperienceEvidence<'a>>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Terminology compatibility cites.
    pub terminology: Vec<EvidenceCite>,
    /// Reference compatibility cites.
    pub reference: Vec<EvidenceCite>,
    /// Commitment compatibility cites.
    pub commitment: Vec<EvidenceCite>,
    /// Action-consequence compatibility cites.
    pub action_consequence: Vec<EvidenceCite>,
    /// Survival-across-change cites.
    pub survival: Vec<EvidenceCite>,
    /// Public inheritance transfer refs.
    pub transfer_refs: Vec<EvidenceCite>,
    /// Requalification scope for tacit competence.
    pub requalification_scope: String,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// Assess Common Ground over frozen by-handle inputs.
///
/// Validates every owner shape, gates every carried fence against the
/// assessment fence, revalidates accepted-source triples by exact match, and
/// emits a typed candidate. Status follows the closure rule: not onboarded
/// without a slice, untested without a discriminator run, inconclusive on a
/// partial closure, adequate only with the full closure (plus held-out for
/// product claims). Never assigns scores and never promotes.
pub fn assess_common_ground(input: CommonGroundInput<'_>) -> Result<CommonGroundAssessment, AssessmentError> {
    input.scope.validate()?;
    input.closure.validate()?;
    gate_inputs(
        input.view,
        input.sources,
        input.contribution,
        &input.experience,
        &input.scope,
    )?;
    let slots = [
        input.terminology.clone(),
        input.reference.clone(),
        input.commitment.clone(),
        input.action_consequence.clone(),
        input.survival.clone(),
        input.transfer_refs.clone(),
    ];
    let mut drifted = Vec::new();
    check_slot_cites(
        &[
            &slots[0], &slots[1], &slots[2], &slots[3], &slots[4], &slots[5],
        ],
        input.sources,
        &mut drifted,
        &[
            "assessment.terminology",
            "assessment.reference",
            "assessment.commitment",
            "assessment.action_consequence",
            "assessment.survival",
            "assessment.transfer_refs",
        ],
    )?;
    if !drifted.is_empty() {
        return Err(AssessmentError::StaleCitation { field: "assessment.slot" });
    }
    text(
        &input.requalification_scope,
        "assessment.common_ground_requalification_scope_for_tacit_competence",
    )?;
    let slots_filled = slots.iter().all(|slot| !slot.is_empty());
    let status = decide_status(
        input.scope.is_onboarded(),
        slots_filled,
        &input.closure,
        input.product_claims,
    );
    let mut assessment = CommonGroundAssessment {
        contract_version: UA_CONTRACT_VERSION,
        scope: input.scope,
        common_ground_terminology_compatibility: slots[0].clone(),
        common_ground_reference_compatibility: slots[1].clone(),
        common_ground_commitment_compatibility: slots[2].clone(),
        common_ground_action_consequence_compatibility: slots[3].clone(),
        common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change:
            slots[4].clone(),
        common_ground_public_inheritance_transfer_refs: slots[5].clone(),
        common_ground_requalification_scope_for_tacit_competence: input.requalification_scope,
        status,
        digest: String::new(),
    };
    assessment.digest = assessment.compute_digest()?;
    assessment.validate()?;
    Ok(assessment)
}

/// Scoped understanding assessment candidate: the 17 frozen `scoped_*`
/// fields plus status and frozen digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedUnderstandingAssessment {
    /// Exact contract version this candidate was written against.
    pub contract_version: ContractVersion,
    /// Denominator anchor: one question/task family at one fence.
    pub scope: AssessmentScope,
    /// Subject route or coupled system under assessment.
    pub scoped_subject_route_or_coupled_system: String,
    /// Declared question and task family.
    pub scoped_question_and_task_family: String,
    /// Declared product and State Fence binding.
    pub scoped_product_and_state_fence: String,
    /// Current model and rivals cites.
    pub scoped_current_model_and_rivals: Vec<EvidenceCite>,
    /// Material unknowns cites.
    pub scoped_material_unknowns: Vec<EvidenceCite>,
    /// Pre-probe predictions fixed before observation.
    pub scoped_pre_probe_predictions_fixed_before_observation: Vec<EvidenceCite>,
    /// Selected discriminator or action cites.
    pub scoped_selected_discriminator_or_action: Vec<EvidenceCite>,
    /// Observed outcome and verifier cites.
    pub scoped_observed_outcome_and_verifier: Vec<EvidenceCite>,
    /// Model revision after outcome cites.
    pub scoped_model_revision_after_outcome: Vec<EvidenceCite>,
    /// Counterfactual or held-out evidence cites.
    pub scoped_counterfactual_or_held_out_evidence: Vec<EvidenceCite>,
    /// Transfer boundary and requalification text.
    pub scoped_transfer_boundary_and_requalification: String,
    /// Onboarding slice and missing inputs text.
    pub scoped_onboarding_slice_and_missing_inputs: String,
    /// Assessment status.
    pub scoped_status_not_onboarded_or_untested_or_locally_adequate_or_refuted_or_inconclusive_or_stale:
        AssessmentStatus,
    /// Unanswerable/stale case cites, where applicable.
    pub scoped_unanswerable_stale_case_where_applicable: Vec<EvidenceCite>,
    /// Counterfactual intervention or state-update case cites, where applicable.
    pub scoped_counterfactual_intervention_or_state_update_case_where_applicable:
        Vec<EvidenceCite>,
    /// Held-out compositional transfer cites, where applicable.
    pub scoped_held_out_compositional_transfer_where_applicable: Vec<EvidenceCite>,
    /// Abstention precision/coverage cites, where applicable.
    pub scoped_abstention_precision_coverage_where_applicable: Vec<EvidenceCite>,
    /// Frozen digest over this shape, excluding this field.
    pub digest: String,
}

impl ScopedUnderstandingAssessment {
    fn slot_lists(&self) -> [&[EvidenceCite]; 10] {
        [
            &self.scoped_current_model_and_rivals,
            &self.scoped_material_unknowns,
            &self.scoped_pre_probe_predictions_fixed_before_observation,
            &self.scoped_selected_discriminator_or_action,
            &self.scoped_observed_outcome_and_verifier,
            &self.scoped_model_revision_after_outcome,
            &self.scoped_counterfactual_or_held_out_evidence,
            &self.scoped_unanswerable_stale_case_where_applicable,
            &self
                .scoped_counterfactual_intervention_or_state_update_case_where_applicable,
            &self.scoped_held_out_compositional_transfer_where_applicable,
        ]
    }

    /// Compute the frozen digest over this shape.
    pub fn compute_digest(&self) -> Result<String, AssessmentError> {
        #[derive(Serialize)]
        struct ScopedDigest<'a> {
            contract_version: &'a ContractVersion,
            scope: &'a AssessmentScope,
            subject: &'a str,
            question_and_task_family: &'a str,
            product_and_state_fence: &'a str,
            current_model_and_rivals: &'a [EvidenceCite],
            material_unknowns: &'a [EvidenceCite],
            pre_probe_predictions: &'a [EvidenceCite],
            discriminator: &'a [EvidenceCite],
            outcome_verifier: &'a [EvidenceCite],
            model_revision: &'a [EvidenceCite],
            counterfactual_or_held_out: &'a [EvidenceCite],
            transfer_boundary: &'a str,
            onboarding: &'a str,
            status: AssessmentStatus,
            unanswerable: &'a [EvidenceCite],
            counterfactual_case: &'a [EvidenceCite],
            held_out_transfer: &'a [EvidenceCite],
            abstention: &'a [EvidenceCite],
        }
        canonical_json_bytes(&ScopedDigest {
            contract_version: &self.contract_version,
            scope: &self.scope,
            subject: &self.scoped_subject_route_or_coupled_system,
            question_and_task_family: &self.scoped_question_and_task_family,
            product_and_state_fence: &self.scoped_product_and_state_fence,
            current_model_and_rivals: &self.scoped_current_model_and_rivals,
            material_unknowns: &self.scoped_material_unknowns,
            pre_probe_predictions: &self.scoped_pre_probe_predictions_fixed_before_observation,
            discriminator: &self.scoped_selected_discriminator_or_action,
            outcome_verifier: &self.scoped_observed_outcome_and_verifier,
            model_revision: &self.scoped_model_revision_after_outcome,
            counterfactual_or_held_out: &self.scoped_counterfactual_or_held_out_evidence,
            transfer_boundary: &self.scoped_transfer_boundary_and_requalification,
            onboarding: &self.scoped_onboarding_slice_and_missing_inputs,
            status: self
                .scoped_status_not_onboarded_or_untested_or_locally_adequate_or_refuted_or_inconclusive_or_stale,
            unanswerable: &self.scoped_unanswerable_stale_case_where_applicable,
            counterfactual_case: &self
                .scoped_counterfactual_intervention_or_state_update_case_where_applicable,
            held_out_transfer: &self.scoped_held_out_compositional_transfer_where_applicable,
            abstention: &self.scoped_abstention_precision_coverage_where_applicable,
        })
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AssessmentError::DigestMismatch {
            field: "assessment.digest",
        })
    }

    /// Validate version, scope, texts, slots, and digest.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.contract_version != UA_CONTRACT_VERSION {
            return Err(AssessmentError::VersionMismatch);
        }
        self.scope.validate()?;
        text(
            &self.scoped_subject_route_or_coupled_system,
            "assessment.scoped_subject_route_or_coupled_system",
        )?;
        text(
            &self.scoped_question_and_task_family,
            "assessment.scoped_question_and_task_family",
        )?;
        text(
            &self.scoped_product_and_state_fence,
            "assessment.scoped_product_and_state_fence",
        )?;
        text(
            &self.scoped_transfer_boundary_and_requalification,
            "assessment.scoped_transfer_boundary_and_requalification",
        )?;
        text(
            &self.scoped_onboarding_slice_and_missing_inputs,
            "assessment.scoped_onboarding_slice_and_missing_inputs",
        )?;
        for slot in self.slot_lists() {
            AssessmentClosure::cites(slot, "assessment.slot")?;
        }
        digest(&self.digest, "assessment.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(AssessmentError::DigestMismatch {
                field: "assessment.digest",
            });
        }
        Ok(())
    }

    /// Independently recheck the denominator: fences, cited triples, digest.
    ///
    /// `product_claims` must match the flag the candidate was assessed under:
    /// held-out slots join the missing set only for product claims.
    /// `*_where_applicable` slots are checked for drift but never required.
    pub fn recheck(
        &self,
        view: &ActiveUnderstandingView,
        sources: &AcceptedSourceProjection,
        product_claims: bool,
    ) -> Result<DenominatorRecheck, AssessmentError> {
        view.validate()?;
        sources.validate()?;
        gate_compatible(
            &view.binding.state_fence,
            &self.scope.state_fence,
            "assessment.view_fence",
        )?;
        gate_compatible(
            &sources.fence,
            &self.scope.state_fence,
            "assessment.sources_fence",
        )?;
        let mut drifted = Vec::new();
        check_slot_cites(
            &self.slot_lists(),
            sources,
            &mut drifted,
            &[
                "scoped_current_model_and_rivals",
                "scoped_material_unknowns",
                "scoped_pre_probe_predictions_fixed_before_observation",
                "scoped_selected_discriminator_or_action",
                "scoped_observed_outcome_and_verifier",
                "scoped_model_revision_after_outcome",
                "scoped_counterfactual_or_held_out_evidence",
                "scoped_unanswerable_stale_case_where_applicable",
                "scoped_counterfactual_intervention_or_state_update_case_where_applicable",
                "scoped_held_out_compositional_transfer_where_applicable",
            ],
        )?;
        let mut missing = Vec::new();
        for (slot, name) in self.slot_lists()[..6].iter().zip(
            [
                "scoped_current_model_and_rivals",
                "scoped_material_unknowns",
                "scoped_pre_probe_predictions_fixed_before_observation",
                "scoped_selected_discriminator_or_action",
                "scoped_observed_outcome_and_verifier",
                "scoped_model_revision_after_outcome",
            ],
        ) {
            if slot.is_empty() {
                missing.push(name.to_string());
            }
        }
        if product_claims {
            if self.scoped_counterfactual_or_held_out_evidence.is_empty()
                && self.scoped_held_out_compositional_transfer_where_applicable.is_empty()
            {
                missing.push("scoped_held_out_evidence".to_string());
            }
        }
        if self.digest != self.compute_digest()? {
            drifted.push("assessment.digest".to_string());
        }
        Ok(DenominatorRecheck {
            complete: missing.is_empty() && drifted.is_empty(),
            missing,
            drifted,
        })
    }
}

/// Inputs to [`assess_scoped`]: by-handle owner evidence plus the declared
/// scope, identity texts, closure evidence, and product-claim flag.
#[derive(Clone, Debug)]
pub struct ScopedInput<'a> {
    /// Already-compiled understanding view, by handle.
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks.
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Optional experience envelopes for outcome/verifier-side evidence.
    pub experience: Vec<ExperienceEvidence<'a>>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Subject route or coupled system.
    pub subject: String,
    /// Transfer boundary and requalification text.
    pub transfer_boundary: String,
    /// Material unknowns cites.
    pub material_unknowns: Vec<EvidenceCite>,
    /// Abstention precision/coverage cites, where applicable.
    pub abstention: Vec<EvidenceCite>,
    /// Unanswerable/stale case cites, where applicable.
    pub unanswerable: Vec<EvidenceCite>,
    /// Counterfactual intervention cites, where applicable.
    pub counterfactual: Vec<EvidenceCite>,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// Emit one scoped understanding assessment per question/task family at one
/// State Fence.
///
/// Runs the same owner validation, fence gating, and exact-triple citation
/// checks as [`assess_common_ground`], then binds the closure legs into the
/// frozen `scoped_*` fields. Status follows the closure rule; held-out
/// evidence is required for product claims. Candidates only: no scores, no
/// promotion, no second compilation or admission.
pub fn assess_scoped(input: ScopedInput<'_>) -> Result<ScopedUnderstandingAssessment, AssessmentError> {
    input.scope.validate()?;
    input.closure.validate()?;
    gate_inputs(
        input.view,
        input.sources,
        input.contribution,
        &input.experience,
        &input.scope,
    )?;
    let closure_slots: [&[EvidenceCite]; 6] = [
        &input.closure.rival_model,
        &input.closure.pre_probe_prediction,
        &input.closure.discriminator,
        &input.closure.outcome_verifier,
        &input.closure.revision,
        &input.closure.held_out,
    ];
    let mut drifted = Vec::new();
    check_slot_cites(
        &closure_slots,
        input.sources,
        &mut drifted,
        &[
            "closure.rival_model",
            "closure.pre_probe_prediction",
            "closure.discriminator",
            "closure.outcome_verifier",
            "closure.revision",
            "closure.held_out",
        ],
    )?;
    if !drifted.is_empty() {
        return Err(AssessmentError::StaleCitation {
            field: "assessment.closure",
        });
    }
    AssessmentClosure::cites(&input.material_unknowns, "assessment.material_unknowns")?;
    AssessmentClosure::cites(&input.abstention, "assessment.abstention")?;
    AssessmentClosure::cites(&input.unanswerable, "assessment.unanswerable")?;
    AssessmentClosure::cites(&input.counterfactual, "assessment.counterfactual")?;
    text(&input.subject, "assessment.subject")?;
    text(&input.transfer_boundary, "assessment.transfer_boundary")?;
    let question_and_task_family =
        format!("{}/{}", input.scope.question_family, input.scope.task_family);
    let onboarding = if input.scope.onboarding_slice.trim().is_empty() {
        format!("missing:{}", input.scope.missing_inputs.join(","))
    } else {
        input.scope.onboarding_slice.clone()
    };
    let slots_filled = !input.closure.rival_model.is_empty()
        && !input.closure.pre_probe_prediction.is_empty()
        && !input.closure.discriminator.is_empty()
        && !input.closure.outcome_verifier.is_empty()
        && !input.closure.revision.is_empty();
    let status = decide_status(
        input.scope.is_onboarded(),
        slots_filled,
        &input.closure,
        input.product_claims,
    );
    let mut assessment = ScopedUnderstandingAssessment {
        contract_version: UA_CONTRACT_VERSION,
        scoped_question_and_task_family: question_and_task_family,
        scoped_product_and_state_fence: input.scope.product_id.clone(),
        scoped_subject_route_or_coupled_system: input.subject,
        scoped_current_model_and_rivals: input.closure.rival_model.clone(),
        scoped_material_unknowns: input.material_unknowns,
        scoped_pre_probe_predictions_fixed_before_observation: input
            .closure
            .pre_probe_prediction
            .clone(),
        scoped_selected_discriminator_or_action: input.closure.discriminator.clone(),
        scoped_observed_outcome_and_verifier: input.closure.outcome_verifier.clone(),
        scoped_model_revision_after_outcome: input.closure.revision.clone(),
        scoped_counterfactual_or_held_out_evidence: input.closure.held_out.clone(),
        scoped_transfer_boundary_and_requalification: input.transfer_boundary,
        scoped_onboarding_slice_and_missing_inputs: onboarding,
        scoped_status_not_onboarded_or_untested_or_locally_adequate_or_refuted_or_inconclusive_or_stale:
            status,
        scoped_unanswerable_stale_case_where_applicable: input.unanswerable,
        scoped_counterfactual_intervention_or_state_update_case_where_applicable: input
            .counterfactual,
        scoped_held_out_compositional_transfer_where_applicable: if input.product_claims {
            input.closure.held_out.clone()
        } else {
            Vec::new()
        },
        scoped_abstention_precision_coverage_where_applicable: input.abstention,
        scope: input.scope,
        digest: String::new(),
    };
    assessment.digest = assessment.compute_digest()?;
    assessment.validate()?;
    Ok(assessment)
}
