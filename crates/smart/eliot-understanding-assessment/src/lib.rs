//! Bounded Common Ground and scoped understanding assessment (#223).
//!
//! [`assess_common_ground`] checks Common Ground as public causal-inheritance
//! survival across model/harness change, and [`assess_scoped`] emits one
//! [`ScopedUnderstandingAssessment`] per question/task family at one State
//! Fence. Both consume immutable owner projections **by handle only**,
//! bundled as one [`OwnerContext`]:
//!
//! * the already-compiled [`ActiveUnderstandingView`] (frozen 9/9,
//!   `eliot-context-contracts`), never a second `ContextCompiler`
//!   invocation and never a second admission pass;
//! * the unit-#3 [`AcceptedSourceProjection`] (frozen owner contract,
//!   `eliot-dreamer-contracts`), cited by exact handle/revision/digest
//!   triple with no similarity fallback;
//! * the owner [`ProviderContribution`] (`eliot-epistemic-contracts`),
//!   validated and fence-gated, echoed by digest and claim;
//! * owner experience envelopes ([`JournalProjection`], [`BankProjection`],
//!   [`FeedbackProjection`], `eliot-observation-contracts`) for
//!   outcome/verifier-side evidence, validated as wholes with carried
//!   (never inferred) fences.
//!
//! Every carried cite must resolve into one of those passed owner objects
//! before any adequacy verdict: accepted-source triples by exact match,
//! contribution cites by position digest plus claim plus source revision,
//! bank/feedback cites by handle plus revision cursor plus content digest,
//! and journal/outcome/verifier cites by record handle inside a passed
//! journal envelope (record identity plus envelope digest plus source
//! revision). Outcome and discriminator legs additionally require
//! owner-verified semantics: an outcome-kind journal event
//! (`ProductOutcome`, `TaskProgress`, `FailureOrRepair`, `UserCorrection`,
//! `LoopOrNoProgress`) or a view atom with an outcome role (`Evidence`,
//! `Acceptance`) — and the `Verifier` role for verifier receipts — and an
//! action-kind journal event (`ToolOrRoute`, `TaskProgress`) or an
//! `Instruction`-role view atom for discriminative probes. Cite-family
//! labels record the caller's claimed role; binding proves owner-record
//! existence with the required role, never role correctness beyond that —
//! which is why verdicts stay candidates. Rival, prediction, revision, and
//! material-unknown cites carry exact existence binding only: no
//! role-typed owner records exist for them in intake (`ObservationKind`
//! and `SemanticRole` name no model, prediction, or revision kinds), so
//! their roles stay caller-claimed and they cannot establish adequacy
//! alone — the role-gated legs must also bind.
//!
//! Authority boundary: `validate()` is a shape and tamper check only, never
//! authority — a shape hash is not provenance. The consumer authority path
//! is [`CommonGroundAssessment::recheck`] /
//! [`ScopedUnderstandingAssessment::recheck`], which re-resolve every cite
//! against caller-supplied owner objects. Integration must source the view,
//! projection, contribution, and envelopes ONLY from their owners. `Stale`
//! is never assigned in-crate: on a non-complete [`DenominatorRecheck`],
//! the owning review path (model/harness-change review for Common Ground,
//! product acceptance for scoped assessments) transitions the candidate.
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
use eliot_context_contracts::{ActiveUnderstandingView, ContextError, SemanticRole};
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, AcceptedSourceRef, SelfQueryContractError,
};
use eliot_epistemic_contracts::{ContractError as EpistemicError, ProviderContribution};
use eliot_observation_contracts::{
    BankProjection, ExperienceRecordRef, FeedbackProjection, JournalProjection, ObservationError,
    ObservationKind,
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
///
/// Amendment history: 1.0.0 wrote CommonGround candidates without the
/// closure annex; 1.1.0 persists the role-labeled closure annex plus the
/// product-claim flag, both digest-bound, so recheck re-applies identical
/// role gating. The frozen `UnderstandingAssessment` 24-field contract is
/// preserved verbatim — annex and flag are crate envelope, like
/// version/scope/status/digest — so the freeze file needs no edit.
/// `validate()` accepts exactly the current version: 1.0.0 artifacts exist
/// only in branch history (crate unreleased, zero consumers) and are
/// rejected with `VersionMismatch`.
pub const UA_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);
/// Maximum evidence cites carried by one assessment slot list.
pub const MAX_EVIDENCE_CITES: usize = 256;
/// Maximum Unicode scalar values accepted for one scope/identity text field.
pub const MAX_SCOPE_TEXT: usize = 256;
/// Maximum missing-input names carried by one scope.
pub const MAX_MISSING_INPUTS: usize = 32;
/// Journal event kinds carrying outcome semantics (`ObservationKind`, owner
/// vocabulary): only these qualify a journal record as outcome evidence.
const OUTCOME_KINDS: [ObservationKind; 5] = [
    ObservationKind::ProductOutcome,
    ObservationKind::TaskProgress,
    ObservationKind::FailureOrRepair,
    ObservationKind::UserCorrection,
    ObservationKind::LoopOrNoProgress,
];
/// Journal event kinds carrying executed probe/action semantics: only these
/// qualify a journal record as a discriminative probe or action.
const ACTION_KINDS: [ObservationKind; 2] = [
    ObservationKind::ToolOrRoute,
    ObservationKind::TaskProgress,
];
/// View semantic roles carrying outcome semantics (`SemanticRole`, owner
/// vocabulary): only these qualify a compiled atom as outcome evidence.
const OUTCOME_ROLES: [SemanticRole; 2] = [SemanticRole::Evidence, SemanticRole::Acceptance];

/// Closure leg label: which adequacy leg a persisted cite list fills.
/// Labels are stored, never inferred — recheck gates each list by its label.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ClosureLeg {
    /// Public rival-aware model refs.
    RivalModel,
    /// Predictions fixed before observation.
    PreProbePrediction,
    /// Selected discriminative probe/action refs.
    Discriminator,
    /// Applicable outcome/verifier evidence refs.
    OutcomeVerifier,
    /// Model revision after outcome refs.
    Revision,
    /// Held-out/compositional transfer evidence refs.
    HeldOut,
}

/// Canonical persistence order for the closure annex.
const CLOSURE_LEG_ORDER: [ClosureLeg; 6] = [
    ClosureLeg::RivalModel,
    ClosureLeg::PreProbePrediction,
    ClosureLeg::Discriminator,
    ClosureLeg::OutcomeVerifier,
    ClosureLeg::Revision,
    ClosureLeg::HeldOut,
];

/// One role-labeled closure leg persisted in the artifact so recheck
/// re-applies the identical role gate the constructor ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegEvidence {
    /// Which adequacy leg these cites fill.
    pub leg: ClosureLeg,
    /// The cites, in deterministic supply order.
    pub cites: Vec<EvidenceCite>,
}

impl LegEvidence {
    /// Build the annex in canonical leg order from a closure.
    #[must_use]
    pub fn annex(closure: &AssessmentClosure) -> Vec<LegEvidence> {
        vec![
            LegEvidence { leg: ClosureLeg::RivalModel, cites: closure.rival_model.clone() },
            LegEvidence { leg: ClosureLeg::PreProbePrediction, cites: closure.pre_probe_prediction.clone() },
            LegEvidence { leg: ClosureLeg::Discriminator, cites: closure.discriminator.clone() },
            LegEvidence { leg: ClosureLeg::OutcomeVerifier, cites: closure.outcome_verifier.clone() },
            LegEvidence { leg: ClosureLeg::Revision, cites: closure.revision.clone() },
            LegEvidence { leg: ClosureLeg::HeldOut, cites: closure.held_out.clone() },
        ]
    }

    /// Stable slot name for diagnostics.
    #[must_use]
    pub fn name(leg: ClosureLeg) -> &'static str {
        match leg {
            ClosureLeg::RivalModel => "closure.rival_model",
            ClosureLeg::PreProbePrediction => "closure.pre_probe_prediction",
            ClosureLeg::Discriminator => "closure.discriminator",
            ClosureLeg::OutcomeVerifier => "closure.outcome_verifier",
            ClosureLeg::Revision => "closure.revision",
            ClosureLeg::HeldOut => "closure.held_out",
        }
    }

    /// Role gate for one persisted leg.
    #[must_use]
    fn gate(leg: ClosureLeg) -> CiteLeg {
        match leg {
            ClosureLeg::Discriminator => CiteLeg::Discriminator,
            ClosureLeg::OutcomeVerifier => CiteLeg::Outcome,
            _ => CiteLeg::Neutral,
        }
    }

    /// Validate one annex entry bound.
    pub fn validate_cites(cites: &[EvidenceCite], field: &'static str) -> Result<(), AssessmentError> {
        AssessmentClosure::cites(cites, field)
    }
}

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
    /// Never assigned in-crate: on a non-complete [`DenominatorRecheck`],
    /// the owning review path transitions the candidate.
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

/// Shared owner-envelope intake for assessment and recheck: the compiled
/// view, the accepted-source projection, the optional admitted
/// contribution, and the optional experience envelopes — all by handle,
/// all sourced ONLY from their owners.
#[derive(Clone, Copy, Debug)]
pub struct OwnerContext<'a> {
    /// Already-compiled understanding view, by handle.
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks.
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Optional experience envelopes for outcome-side evidence.
    pub experience: &'a [ExperienceEvidence<'a>],
}

/// Outcome of binding one cite into the passed owner objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CiteBinding {
    /// The cite matches an owner record exactly.
    Bound,
    /// The cite contradicts its owner projection (accepted-source triple
    /// drift only).
    Stale,
    /// The cite is well-formed but matches no passed owner object.
    Unbound,
}

/// Match a contribution cite by position digest plus claim plus revision.
fn match_contribution(
    cite: &EvidenceCite,
    contribution: &ProviderContribution,
) -> bool {
    cite.digest == contribution.position_digest
        && cite.revision == contribution.source_revision
        && cite.handle.as_str() == contribution.claim.as_str()
}

/// Match a cite pin against a journal envelope: digest plus source revision.
fn match_journal_record(cite: &EvidenceCite, envelope_digest: &str, source_revision: &str) -> bool {
    cite.digest == envelope_digest && cite.revision == source_revision
}

/// Match a journal/outcome/verifier cite to a journal record: exact record
/// handle inside a passed envelope pinned by envelope digest plus source
/// revision. Returns the owner event kind when the record carries an event.
fn journal_record_kind(
    cite: &EvidenceCite,
    owner: &OwnerContext<'_>,
) -> Option<ObservationKind> {
    for evidence in owner.experience {
        if let ExperienceEvidence::Journal(projection) = evidence {
            if let Some(record) = projection
                .records
                .iter()
                .find(|record| record.record_id == cite.handle.as_str())
            {
                if match_journal_record(cite, &projection.digest, &projection.source_revision) {
                    return record.event.as_ref().map(|event| event.kind);
                }
                return None;
            }
        }
    }
    None
}

/// Match an outcome/verifier cite to a compiled view atom: exact atom
/// handle plus source revision plus source digest. Returns the owner
/// semantic role assigned at admission.
fn view_atom_role(cite: &EvidenceCite, view: &ActiveUnderstandingView) -> Option<SemanticRole> {
    view.rendered
        .iter()
        .find(|atom| {
            atom.atom_id == cite.handle
                && atom.source_revision == cite.revision
                && atom.source_digest == cite.digest
        })
        .map(|atom| atom.role)
}

/// Which adequacy leg a cite fills: only outcome and discriminator legs
/// carry owner-role requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CiteLeg {
    /// No role requirement beyond owner-record existence.
    Neutral,
    /// Applicable outcome evidence: owner outcome kind or outcome role.
    Outcome,
    /// Discriminative probe/action: owner action kind or instruction role.
    Discriminator,
}

/// Enforce the owner-role requirement for outcome and discriminator legs.
///
/// Accepted-source, contribution, bank, and feedback cites resolve into
/// typed owner envelopes whose membership already constrains semantics, so
/// existence binding suffices there. Journal/outcome/verifier cites must
/// additionally carry owner-verified semantics: an outcome-kind journal
/// event, or a view atom with an outcome role (`Evidence`/`Acceptance`) for
/// outcome evidence and the `Verifier` role for verifier receipts;
/// discriminator cites require an action-kind journal event or an
/// `Instruction`-role view atom. No role-typed owner records exist in
/// intake for rival, prediction, revision, or material-unknown cites, so
/// those legs stay on exact existence binding (documented residual: their
/// roles stay caller-claimed, and they cannot establish adequacy alone
/// because the role-gated legs must also bind).
fn leg_role_ok(cite: &EvidenceCite, owner: &OwnerContext<'_>, leg: CiteLeg) -> bool {
    match leg {
        CiteLeg::Neutral => true,
        CiteLeg::Outcome => match cite.family {
            CitedFamily::AcceptedSource
            | CitedFamily::EpistemicContribution
            | CitedFamily::BankRecord
            | CitedFamily::FeedbackRecord => true,
            CitedFamily::JournalRecord => journal_record_kind(cite, owner)
                .map(|kind| OUTCOME_KINDS.contains(&kind))
                .unwrap_or(false),
            CitedFamily::OutcomeRecord => {
                journal_record_kind(cite, owner)
                    .map(|kind| OUTCOME_KINDS.contains(&kind))
                    .unwrap_or(false)
                    || view_atom_role(cite, owner.view)
                        .map(|role| OUTCOME_ROLES.contains(&role))
                        .unwrap_or(false)
            }
            CitedFamily::VerifierReceipt => {
                journal_record_kind(cite, owner)
                    .map(|kind| OUTCOME_KINDS.contains(&kind))
                    .unwrap_or(false)
                    || view_atom_role(cite, owner.view)
                        .map(|role| role == SemanticRole::Verifier)
                        .unwrap_or(false)
            }
        },
        CiteLeg::Discriminator => match cite.family {
            CitedFamily::AcceptedSource
            | CitedFamily::EpistemicContribution
            | CitedFamily::BankRecord
            | CitedFamily::FeedbackRecord => true,
            CitedFamily::JournalRecord | CitedFamily::OutcomeRecord | CitedFamily::VerifierReceipt => {
                journal_record_kind(cite, owner)
                    .map(|kind| ACTION_KINDS.contains(&kind))
                    .unwrap_or(false)
                    || view_atom_role(cite, owner.view)
                        .map(|role| role == SemanticRole::Instruction)
                        .unwrap_or(false)
            }
        },
    }
}

/// Match a bank/feedback cite by handle plus revision cursor plus content
/// digest against one owner ref.
fn match_record_ref(cite: &EvidenceCite, reference: &ExperienceRecordRef) -> bool {
    cite.handle == reference.handle
        && cite.revision == reference.revision.revision
        && cite.digest == reference.revision.content_sha256
}

/// Classify one cite against the passed owner objects.
///
/// Accepted-source triples re-resolve by exact match (`Stale` on drift);
/// contribution cites match the passed contribution by digest, claim, and
/// revision; journal/outcome/verifier cites match a passed journal
/// envelope's record set pinned by envelope digest and source revision;
/// bank/feedback cites match passed envelope refs by handle, cursor, and
/// content digest. Anything well-formed but unmatched is `Unbound`.
/// Errors are reserved for malformed shapes.
fn classify_cite(
    cite: &EvidenceCite,
    owner: &OwnerContext<'_>,
) -> Result<CiteBinding, AssessmentError> {
    cite.validate()?;
    match cite.family {
        CitedFamily::AcceptedSource => {
            if owner
                .sources
                .check_cited(&cite.handle, &cite.revision, &cite.digest)
                .is_err()
            {
                Ok(CiteBinding::Stale)
            } else {
                Ok(CiteBinding::Bound)
            }
        }
        CitedFamily::EpistemicContribution => Ok(match owner.contribution {
            Some(contribution) if match_contribution(cite, contribution) => CiteBinding::Bound,
            _ => CiteBinding::Unbound,
        }),
        CitedFamily::JournalRecord => Ok(if journal_record_kind(cite, owner).is_some() {
            CiteBinding::Bound
        } else {
            CiteBinding::Unbound
        }),
        CitedFamily::OutcomeRecord | CitedFamily::VerifierReceipt => {
            let bound = journal_record_kind(cite, owner).is_some()
                || view_atom_role(cite, owner.view).is_some();
            Ok(if bound { CiteBinding::Bound } else { CiteBinding::Unbound })
        }
        CitedFamily::BankRecord | CitedFamily::FeedbackRecord => {
            let mut bound = false;
            for evidence in owner.experience {
                let refs = match (evidence, cite.family) {
                    (ExperienceEvidence::Bank(projection), CitedFamily::BankRecord) => {
                        Some(projection.refs.as_slice())
                    }
                    (ExperienceEvidence::Feedback(projection), CitedFamily::FeedbackRecord) => {
                        Some(projection.refs.as_slice())
                    }
                    _ => None,
                };
                if refs
                    .map(|refs| refs.iter().any(|reference| match_record_ref(cite, reference)))
                    .unwrap_or(false)
                {
                    bound = true;
                    break;
                }
            }
            Ok(if bound { CiteBinding::Bound } else { CiteBinding::Unbound })
        }
    }
}

/// Binding rollup over every carried cite list: stale accepted-source
/// triples fail closed; unbound cites and owner-role mismatches cap adequacy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BindingRollup {
    /// Accepted-source cites contradicting their projection.
    stale: Vec<String>,
    /// Well-formed cites matching no passed owner object.
    unbound: Vec<String>,
    /// Bound cites whose owner record carries the wrong role for the leg.
    role_mismatch: Vec<String>,
}

impl BindingRollup {
    fn classify_slots(
        &mut self,
        slots: &[(&[EvidenceCite], &str, CiteLeg)],
        owner: &OwnerContext<'_>,
    ) -> Result<(), AssessmentError> {
        for (slot, name, leg) in slots {
            for cite in slot.iter() {
                match classify_cite(cite, owner)? {
                    CiteBinding::Bound if leg_role_ok(cite, owner, *leg) => {}
                    CiteBinding::Bound => self.role_mismatch.push((*name).to_string()),
                    CiteBinding::Stale => self.stale.push((*name).to_string()),
                    CiteBinding::Unbound => self.unbound.push((*name).to_string()),
                }
            }
        }
        Ok(())
    }

    /// True only when every carried cite resolved into an owner object with
    /// the role its leg requires.
    #[must_use]
    fn fully_bound(&self) -> bool {
        self.stale.is_empty() && self.unbound.is_empty() && self.role_mismatch.is_empty()
    }
}

/// Gate every carried fence against the assessment fence.
fn gate_owner(owner: &OwnerContext<'_>, scope: &AssessmentScope) -> Result<(), AssessmentError> {
    owner.view.validate()?;
    owner.sources.validate()?;
    if owner.view.binding.scope_id.as_str() != scope.scope_id {
        return Err(AssessmentError::InvalidField {
            field: "assessment.scope_id",
            reason: "compiled view is bound to a different work scope",
        });
    }
    gate_compatible(
        &owner.view.binding.state_fence,
        &scope.state_fence,
        "assessment.view_fence",
    )?;
    gate_compatible(
        &owner.sources.fence,
        &scope.state_fence,
        "assessment.sources_fence",
    )?;
    if let Some(contribution) = owner.contribution {
        contribution.validate()?;
        gate_compatible(
            &contribution.fence,
            &scope.state_fence,
            "assessment.contribution_fence",
        )?;
    }
    for (index, evidence) in owner.experience.iter().enumerate() {
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
    closure_complete: bool,
    discriminator_present: bool,
    fully_bound: bool,
) -> AssessmentStatus {
    if !onboarded {
        return AssessmentStatus::NotOnboarded;
    }
    if !closure_complete || !fully_bound {
        if !discriminator_present {
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
    /// Persisted role-labeled closure annex in canonical leg order: the
    /// exact evidence the verdict was assessed under, so recheck re-applies
    /// identical role gating. Crate envelope, not part of the frozen field
    /// contract.
    pub closure_evidence: Vec<LegEvidence>,
    /// Product-claim flag the verdict was assessed under (held-out required
    /// iff true). Crate envelope.
    pub product_claims: bool,
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
            closure_evidence: &'a [LegEvidence],
            product_claims: bool,
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
            closure_evidence: &self.closure_evidence,
            product_claims: self.product_claims,
            status: self.status,
        })
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AssessmentError::DigestMismatch {
            field: "assessment.digest",
        })
    }

    /// Validate version, scope, slots, annex order, flag, text, and digest.
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.contract_version != UA_CONTRACT_VERSION {
            return Err(AssessmentError::VersionMismatch);
        }
        self.scope.validate()?;
        for slot in self.slot_lists() {
            AssessmentClosure::cites(slot, "assessment.slot")?;
        }
        if self.closure_evidence.len() != CLOSURE_LEG_ORDER.len() {
            return Err(AssessmentError::InvalidField {
                field: "assessment.closure_evidence",
                reason: "annex must carry exactly one entry per closure leg",
            });
        }
        for (entry, expected) in self.closure_evidence.iter().zip(CLOSURE_LEG_ORDER.iter()) {
            if entry.leg != *expected {
                return Err(AssessmentError::InvalidField {
                    field: "assessment.closure_evidence",
                    reason: "annex legs must follow canonical order",
                });
            }
            LegEvidence::validate_cites(&entry.cites, "assessment.closure_evidence")?;
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

    /// Independently recheck the denominator against current owner objects:
    /// fences re-gated, every cite re-resolved, digest recomputed.
    ///
    /// This is the consumer authority path: `validate()` first proves the
    /// persisted candidate's version, six-leg canonical shape, and digest;
    /// owner re-resolution then proves that its current evidence still binds.
    /// A non-complete verdict means the candidate no longer binds; the
    /// owning review path transitions it to `Stale`.
    pub fn recheck(&self, owner: &OwnerContext<'_>) -> Result<DenominatorRecheck, AssessmentError> {
        self.validate()?;
        gate_owner(owner, &self.scope)?;
        let mut rollup = BindingRollup::default();
        rollup.classify_slots(
            &[
                (&self.common_ground_terminology_compatibility[..], "common_ground_terminology_compatibility", CiteLeg::Neutral),
                (&self.common_ground_reference_compatibility[..], "common_ground_reference_compatibility", CiteLeg::Neutral),
                (&self.common_ground_commitment_compatibility[..], "common_ground_commitment_compatibility", CiteLeg::Neutral),
                (&self.common_ground_action_consequence_compatibility[..], "common_ground_action_consequence_compatibility", CiteLeg::Neutral),
                (&self.common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change[..], "common_ground_goals_decisions_invariants_rivals_unknowns_survival_after_model_harness_change", CiteLeg::Neutral),
                (&self.common_ground_public_inheritance_transfer_refs[..], "common_ground_public_inheritance_transfer_refs", CiteLeg::Neutral),
            ],
            owner,
        )?;
        let mut annexed: Vec<(&[EvidenceCite], &str, CiteLeg)> = Vec::new();
        for entry in &self.closure_evidence {
            annexed.push((entry.cites.as_slice(), LegEvidence::name(entry.leg), LegEvidence::gate(entry.leg)));
        }
        rollup.classify_slots(&annexed, owner)?;
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
        for entry in &self.closure_evidence {
            let required = !matches!(entry.leg, ClosureLeg::HeldOut) || self.product_claims;
            if required && entry.cites.is_empty() {
                missing.push(LegEvidence::name(entry.leg).to_string());
            }
        }
        let mut drifted = rollup.stale;
        drifted.extend(rollup.unbound);
        drifted.extend(rollup.role_mismatch);
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

/// Inputs to [`assess_common_ground`]: shared owner intake plus the
/// declared scope, compatibility slots, closure, and product-claim flag.
#[derive(Clone, Debug)]
pub struct CommonGroundInput<'a> {
    /// Owner envelopes, sourced ONLY from their owners.
    pub owner: OwnerContext<'a>,
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
/// assessment fence, binds every cite into a passed owner object, and emits
/// a typed candidate. Accepted-source drift fails closed; any other unbound
/// cite caps the verdict below adequate. Status follows the closure rule:
/// not onboarded without a slice, untested without a discriminator run,
/// inconclusive on a partial closure or unbound evidence, adequate only with
/// the full bound closure (plus held-out for product claims). The closure is
/// persisted as a leg-labeled annex plus the product-claim flag, both
/// digest-bound, so recheck re-applies identical role gating. Never assigns
/// scores and never promotes.
pub fn assess_common_ground(input: CommonGroundInput<'_>) -> Result<CommonGroundAssessment, AssessmentError> {
    input.scope.validate()?;
    input.closure.validate()?;
    gate_owner(&input.owner, &input.scope)?;
    let slots = [
        input.terminology.clone(),
        input.reference.clone(),
        input.commitment.clone(),
        input.action_consequence.clone(),
        input.survival.clone(),
        input.transfer_refs.clone(),
    ];
    let mut rollup = BindingRollup::default();
    rollup.classify_slots(
        &[
            (&slots[0][..], "assessment.terminology", CiteLeg::Neutral),
            (&slots[1][..], "assessment.reference", CiteLeg::Neutral),
            (&slots[2][..], "assessment.commitment", CiteLeg::Neutral),
            (&slots[3][..], "assessment.action_consequence", CiteLeg::Neutral),
            (&slots[4][..], "assessment.survival", CiteLeg::Neutral),
            (&slots[5][..], "assessment.transfer_refs", CiteLeg::Neutral),
            (&input.closure.rival_model[..], "closure.rival_model", CiteLeg::Neutral),
            (&input.closure.pre_probe_prediction[..], "closure.pre_probe_prediction", CiteLeg::Neutral),
            (&input.closure.discriminator[..], "closure.discriminator", CiteLeg::Discriminator),
            (&input.closure.outcome_verifier[..], "closure.outcome_verifier", CiteLeg::Outcome),
            (&input.closure.revision[..], "closure.revision", CiteLeg::Neutral),
            (&input.closure.held_out[..], "closure.held_out", CiteLeg::Neutral),
        ],
        &input.owner,
    )?;
    if !rollup.stale.is_empty() {
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
        input.closure.is_complete_for(input.product_claims),
        !input.closure.discriminator.is_empty(),
        rollup.fully_bound(),
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
        closure_evidence: LegEvidence::annex(&input.closure),
        product_claims: input.product_claims,
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

    /// Independently recheck the denominator against current owner objects:
    /// fences re-gated, every cite re-resolved, digest recomputed.
    ///
    /// `product_claims` must match the flag the candidate was assessed under:
    /// held-out slots join the missing set only for product claims.
    /// `*_where_applicable` slots are re-resolved for drift but never
    /// required. This is the consumer authority path: `validate()` first
    /// proves the persisted candidate's version, slot/text shape, and digest;
    /// owner re-resolution then proves that its current evidence still binds.
    /// A non-complete verdict means the candidate no longer binds; the product
    /// acceptance path transitions it to `Stale`.
    pub fn recheck(
        &self,
        owner: &OwnerContext<'_>,
        product_claims: bool,
    ) -> Result<DenominatorRecheck, AssessmentError> {
        self.validate()?;
        gate_owner(owner, &self.scope)?;
        let mut rollup = BindingRollup::default();
        rollup.classify_slots(
            &[
                (&self.scoped_current_model_and_rivals[..], "scoped_current_model_and_rivals", CiteLeg::Neutral),
                (&self.scoped_material_unknowns[..], "scoped_material_unknowns", CiteLeg::Neutral),
                (&self.scoped_pre_probe_predictions_fixed_before_observation[..], "scoped_pre_probe_predictions_fixed_before_observation", CiteLeg::Neutral),
                (&self.scoped_selected_discriminator_or_action[..], "scoped_selected_discriminator_or_action", CiteLeg::Discriminator),
                (&self.scoped_observed_outcome_and_verifier[..], "scoped_observed_outcome_and_verifier", CiteLeg::Outcome),
                (&self.scoped_model_revision_after_outcome[..], "scoped_model_revision_after_outcome", CiteLeg::Neutral),
                (&self.scoped_counterfactual_or_held_out_evidence[..], "scoped_counterfactual_or_held_out_evidence", CiteLeg::Neutral),
                (&self.scoped_unanswerable_stale_case_where_applicable[..], "scoped_unanswerable_stale_case_where_applicable", CiteLeg::Neutral),
                (&self.scoped_counterfactual_intervention_or_state_update_case_where_applicable[..], "scoped_counterfactual_intervention_or_state_update_case_where_applicable", CiteLeg::Neutral),
                (&self.scoped_held_out_compositional_transfer_where_applicable[..], "scoped_held_out_compositional_transfer_where_applicable", CiteLeg::Neutral),
                (&self.scoped_abstention_precision_coverage_where_applicable[..], "scoped_abstention_precision_coverage_where_applicable", CiteLeg::Neutral),
            ],
            owner,
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
        let mut drifted = rollup.stale;
        drifted.extend(rollup.unbound);
        drifted.extend(rollup.role_mismatch);
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

/// Inputs to [`assess_scoped`]: shared owner intake plus the declared
/// scope, identity texts, closure evidence, and product-claim flag.
#[derive(Clone, Debug)]
pub struct ScopedInput<'a> {
    /// Owner envelopes, sourced ONLY from their owners.
    pub owner: OwnerContext<'a>,
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
/// Runs the same owner validation, fence gating, and cite binding as
/// [`assess_common_ground`], then binds the closure legs into the
/// frozen `scoped_*` fields. Every carried cite must resolve into a passed
/// owner object; accepted-source drift fails closed and any other unbound
/// cite caps the verdict below adequate. Status follows the closure rule;
/// held-out evidence is required for product claims. Candidates only: no
/// scores, no promotion, no second compilation or admission.
pub fn assess_scoped(input: ScopedInput<'_>) -> Result<ScopedUnderstandingAssessment, AssessmentError> {
    input.scope.validate()?;
    input.closure.validate()?;
    gate_owner(&input.owner, &input.scope)?;
    AssessmentClosure::cites(&input.material_unknowns, "assessment.material_unknowns")?;
    AssessmentClosure::cites(&input.abstention, "assessment.abstention")?;
    AssessmentClosure::cites(&input.unanswerable, "assessment.unanswerable")?;
    AssessmentClosure::cites(&input.counterfactual, "assessment.counterfactual")?;
    let mut rollup = BindingRollup::default();
    rollup.classify_slots(
        &[
            (&input.closure.rival_model[..], "closure.rival_model", CiteLeg::Neutral),
            (&input.closure.pre_probe_prediction[..], "closure.pre_probe_prediction", CiteLeg::Neutral),
            (&input.closure.discriminator[..], "closure.discriminator", CiteLeg::Discriminator),
            (&input.closure.outcome_verifier[..], "closure.outcome_verifier", CiteLeg::Outcome),
            (&input.closure.revision[..], "closure.revision", CiteLeg::Neutral),
            (&input.closure.held_out[..], "closure.held_out", CiteLeg::Neutral),
            (&input.material_unknowns[..], "assessment.material_unknowns", CiteLeg::Neutral),
            (&input.abstention[..], "assessment.abstention", CiteLeg::Neutral),
            (&input.unanswerable[..], "assessment.unanswerable", CiteLeg::Neutral),
            (&input.counterfactual[..], "assessment.counterfactual", CiteLeg::Neutral),
        ],
        &input.owner,
    )?;
    if !rollup.stale.is_empty() {
        return Err(AssessmentError::StaleCitation {
            field: "assessment.closure",
        });
    }
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
        && !input.material_unknowns.is_empty()
        && !input.closure.pre_probe_prediction.is_empty()
        && !input.closure.discriminator.is_empty()
        && !input.closure.outcome_verifier.is_empty()
        && !input.closure.revision.is_empty();
    let status = decide_status(
        input.scope.is_onboarded(),
        slots_filled,
        input.closure.is_complete_for(input.product_claims),
        !input.closure.discriminator.is_empty(),
        rollup.fully_bound(),
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
