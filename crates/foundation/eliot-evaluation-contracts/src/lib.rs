//! Store-neutral contracts for bounded product and recovery evaluation (C0-13).
//!
//! This crate describes claims, scopes, observations and budget evidence.  It
//! does not execute an evaluator, issue proof, decide task finish, or own a
//! product/release status.  Every validator is structural and claim-scoped;
//! no missing observation is inferred as success.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, ProductId, ReceiptId, RequestId,
    StateFence, TaskId, TaskRevision,
};
use eliot_instrument_api::{EvidenceFreshness, ExecutionStatus, VerificationOutcome};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable wire name for the C0-13 surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.evaluation-contracts";
/// Current wire revision for the C0-13 surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(2, 0, 0);
/// Stable identity of the attributed-use contract family.
pub const ATTRIBUTED_MEMORY_USE_CONTRACT_NAME: &str = "eliot.evaluation.attributed-memory-use";
/// Stable identity of the outcome/economics contract family.
pub const MEMORY_OUTCOME_ECONOMICS_CONTRACT_NAME: &str =
    "eliot.evaluation.memory-outcome-economics";

/// Structural validation failures.  These errors never imply a product or
/// release verdict.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EvaluationContractError {
    /// A required text field is blank or contains control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A required collection has no members.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A collection contains the same identity more than once.
    #[error("{field} contains a duplicate identity")]
    DuplicateIdentity { field: &'static str },
    /// A numeric or temporal interval is inverted or zero where positive is required.
    #[error("{field} has an invalid interval or zero value")]
    InvalidInterval { field: &'static str },
    /// A claim is broader than its declared evidence ceiling.
    #[error("claim exceeds the available proof ceiling")]
    ProofOverclaim,
    /// A status does not carry the evidence needed to interpret it.
    #[error("{field} has incompatible evidence: {reason}")]
    EvidenceState {
        field: &'static str,
        reason: &'static str,
    },
    /// A canonical C0-01 clock or graph revision rejected its value.
    #[error("{field} is invalid: {reason}")]
    InvalidDependency {
        field: &'static str,
        reason: &'static str,
    },
    /// A human-readable reason exceeds the bounded wire representation.
    #[error("{field} exceeds the bounded reason length")]
    ReasonTooLong { field: &'static str },
}

const MAX_REASON_LENGTH: usize = 512;
const MAX_DIGEST_LENGTH: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), EvaluationContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(EvaluationContractError::InvalidText { field });
    }
    Ok(())
}

fn bounded_reason(value: &str, field: &'static str) -> Result<(), EvaluationContractError> {
    text(value, field)?;
    if value.chars().count() > MAX_REASON_LENGTH {
        return Err(EvaluationContractError::ReasonTooLong { field });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), EvaluationContractError> {
    text(value, field)?;
    if value.chars().count() > MAX_DIGEST_LENGTH {
        return Err(EvaluationContractError::ReasonTooLong { field });
    }
    Ok(())
}

fn texts(values: &[String], field: &'static str) -> Result<(), EvaluationContractError> {
    if values.is_empty() {
        return Err(EvaluationContractError::EmptyCollection { field });
    }
    for value in values {
        text(value, field)?;
    }
    Ok(())
}

fn unique_texts(values: &[String], field: &'static str) -> Result<(), EvaluationContractError> {
    texts(values, field)?;
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(EvaluationContractError::DuplicateIdentity { field });
    }
    Ok(())
}

/// The comparison basis for an outcome claim.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComparisonBasis {
    /// Compare against exact pre-change behavior on the same scope.
    ExactPrechangeBehavior,
    /// Compare against an authorized matched control.
    MatchedControl,
    /// Compare against a memory-free control.
    MemoryFreeControl,
    /// Compare against a declared historical reference.
    HistoricalReference,
    /// No separate control can change a deterministic conclusion.
    NotApplicableWithReason,
    /// No comparison is available; the claim must carry an explicit ceiling.
    #[serde(rename = "NONE")]
    None,
}

/// Lifecycle of a user outcome objective.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectiveStatus {
    Active,
    Achieved,
    Refuted,
    Superseded,
    Cancelled,
}

/// Lifecycle of a recovery acceptance profile.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryProfileStatus {
    Active,
    Satisfied,
    Superseded,
}

/// The intended claim depth of a product evaluation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimKind {
    Deterministic,
    Stochastic,
    Comparative,
    PopulationLevel,
    NonInferiority,
    Generalization,
}

/// Product-evidence disposition.  It is not task finish or release authority.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductEvidenceStatus {
    CurrentlyVerified,
    ResidualWindowOpen,
    Matured,
    Regressed,
    CensoredOrInconclusive,
}

/// Trial execution and observation state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrialStatus {
    Planned,
    Running,
    Succeeded,
    Failed,
    Partial,
    Excluded,
    Censored,
    Contaminated,
    Unknown,
}

/// Explicit trial outcome.  Unknown is first-class and never a success alias.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum TrialOutcome {
    Improved { summary: String },
    NoChange { summary: String },
    Regressed { summary: String },
    Inconclusive { reason: String },
    Unknown { reason: String },
}

impl TrialOutcome {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        match self {
            Self::Improved { summary }
            | Self::NoChange { summary }
            | Self::Regressed { summary }
            | Self::Inconclusive { reason: summary }
            | Self::Unknown { reason: summary } => text(summary, "trial.outcome")?,
        }
        Ok(())
    }

    /// Whether this outcome is explicitly uncertain.
    pub const fn is_uncertain(&self) -> bool {
        matches!(self, Self::Inconclusive { .. } | Self::Unknown { .. })
    }
}

/// Coverage state for the complete decision-opportunity denominator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Complete,
    Partial,
    Unavailable,
    NotApplicable,
    Unknown,
}

/// A subject excluded from a decision opportunity for an explicit reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IneligibleSubjectRef {
    pub subject_ref: String,
    pub reason: String,
}

impl IneligibleSubjectRef {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.subject_ref, "denominator.ineligible_subject_ref")?;
        bounded_reason(&self.reason, "denominator.ineligible_reason")
    }
}

/// The denominator against which a no-use claim is made.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOpportunityDenominator {
    pub eligible_subject_refs: Vec<String>,
    pub ineligible_subject_refs_with_reason: Vec<IneligibleSubjectRef>,
    pub opportunity_start: ClockReading,
    pub opportunity_end: Option<ClockReading>,
    pub observable_boundaries: Vec<String>,
    pub unobservable_boundaries_and_blind_intervals: Vec<String>,
    pub coverage_state: CoverageState,
    pub denominator_source_and_revision: String,
}

impl DecisionOpportunityDenominator {
    /// Validates denominator identity, coverage, and its closed interval.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        unique_texts(
            &self.eligible_subject_refs,
            "denominator.eligible_subject_refs",
        )?;
        for subject in &self.ineligible_subject_refs_with_reason {
            subject.validate()?;
        }
        let ineligible: Vec<String> = self
            .ineligible_subject_refs_with_reason
            .iter()
            .map(|subject| subject.subject_ref.clone())
            .collect();
        if !ineligible.is_empty() {
            unique_texts(&ineligible, "denominator.ineligible_subject_refs")?;
        }
        if self
            .eligible_subject_refs
            .iter()
            .any(|subject| ineligible.iter().any(|excluded| excluded == subject))
        {
            return Err(EvaluationContractError::DuplicateIdentity {
                field: "denominator.subject_refs",
            });
        }
        self.opportunity_start.validate().map_err(|_| {
            EvaluationContractError::InvalidDependency {
                field: "denominator.opportunity_start",
                reason: "invalid clock reading",
            }
        })?;
        if let Some(end) = self.opportunity_end {
            end.validate()
                .map_err(|_| EvaluationContractError::InvalidDependency {
                    field: "denominator.opportunity_end",
                    reason: "invalid clock reading",
                })?;
            if let (Some(start), Some(end)) =
                (self.opportunity_start.known_time_ms, end.known_time_ms)
                && end < start
            {
                return Err(EvaluationContractError::InvalidInterval {
                    field: "denominator.opportunity_start/opportunity_end",
                });
            }
        }
        texts(
            &self.observable_boundaries,
            "denominator.observable_boundaries",
        )?;
        for boundary in &self.unobservable_boundaries_and_blind_intervals {
            bounded_reason(boundary, "denominator.blind_interval")?;
        }
        text(
            &self.denominator_source_and_revision,
            "denominator.source_and_revision",
        )?;
        if self.coverage_state == CoverageState::Complete {
            if self.opportunity_end.is_none() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "denominator.opportunity_end",
                    reason: "complete coverage requires a closed opportunity window",
                });
            }
            if !self.unobservable_boundaries_and_blind_intervals.is_empty() {
                return Err(EvaluationContractError::EvidenceState {
                    field: "denominator.unobservable_boundaries_and_blind_intervals",
                    reason: "complete coverage cannot contain blind intervals",
                });
            }
        }
        Ok(())
    }

    fn contains(&self, subject_ref: &str) -> bool {
        self.eligible_subject_refs
            .iter()
            .any(|subject| subject == subject_ref)
    }
}

/// Inclusion state before delivery or observable use.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InclusionDisposition {
    NotConsidered,
    Considered,
    AdmittedHandle,
    AdmittedFull,
    Suppressed,
    Quarantined,
    RevalidationRequired,
    Unknown,
}

/// Delivery and exposure are evidence dimensions, not use or benefit.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryExposureDisposition {
    NotApplicable,
    NotDelivered,
    DeliveredPartial,
    DeliveredFull,
    DeliveryUnknown,
}

/// Evidence that a subject reached the declared exposure boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryExposureEvidence {
    pub disposition: DeliveryExposureDisposition,
    pub exposure_revision: String,
    pub exposure_digest: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub reason: Option<String>,
}

impl DeliveryExposureEvidence {
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.disposition != DeliveryExposureDisposition::NotApplicable
            && self.evidence_refs.is_empty()
        {
            return Err(EvaluationContractError::EmptyCollection {
                field: "delivery.evidence_refs",
            });
        }
        if matches!(
            self.disposition,
            DeliveryExposureDisposition::DeliveredFull
                | DeliveryExposureDisposition::DeliveredPartial
        ) {
            text(&self.exposure_revision, "delivery.exposure_revision")?;
            digest(&self.exposure_digest, "delivery.exposure_digest")?;
        }
        if matches!(
            self.disposition,
            DeliveryExposureDisposition::NotDelivered
                | DeliveryExposureDisposition::DeliveryUnknown
        ) {
            match &self.reason {
                Some(reason) => bounded_reason(reason, "delivery.reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "delivery.reason",
                        reason: "missing or unknown delivery requires a bounded reason",
                    });
                }
            }
        }
        Ok(())
    }
}

/// The strongest observable relation between a subject and a public action.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservableInfluence {
    NotAssessed,
    NotObserved,
    AcknowledgedOnly,
    CitedOrUsed,
    ChangedDecisionOrAction,
    UsedForVerification,
    PreventedExactFailure,
    ContradictedOrRejected,
    Unknown,
}

/// Disposition of use after the opportunity has been observed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UseDisposition {
    QualifyingUse,
    QualifyingNonUse,
    Censored,
    OutOfWindow,
    Ineligible,
    NotObservable,
    Unknown,
}

/// Protected roles remain reviewable regardless of observed use.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedRole {
    None,
    DecisionSafetyFloor,
    MinorityEvidence,
    Counterexample,
    AuditEvidence,
    FailureFingerprint,
    NegativeMemory,
    Invariant,
    HumanProtected,
}

impl ProtectedRole {
    #[must_use]
    pub const fn requires_accessibility_review(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Attribution ceiling for evidence, never a scalar usefulness score.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttributionCeiling {
    DeliveryOnly,
    ObservedAssociation,
    SupportedContribution,
    ObservedUnderIntervention,
    CompositeBenefit,
    Contradicted,
    Unknown,
}

/// Exact identity of one attributed-use record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributedUseIdentity {
    pub evaluation_id: ContractId,
    pub evaluation_revision: ContractVersion,
    pub record_digest: String,
}

impl AttributedUseIdentity {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        digest(&self.record_digest, "attributed_use.record_digest")
    }
}

/// Owner-neutral evidence for one memory/candidate use opportunity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributedMemoryUseRecord {
    pub identity: AttributedUseIdentity,
    pub subject_memory_or_candidate_ref: String,
    pub subject_record_revision: TaskRevision,
    pub subject_record_digest: String,
    pub workscope_ref: String,
    pub task_ref: TaskId,
    pub task_revision: TaskRevision,
    pub decision_opportunity_ref: String,
    pub state_fence: StateFence,
    pub observation_window: ObservationWindowSpec,
    pub denominator: DecisionOpportunityDenominator,
    pub inclusion: InclusionDisposition,
    pub delivery: DeliveryExposureEvidence,
    pub observable_influence: ObservableInfluence,
    pub use_disposition: UseDisposition,
    pub protected_role: ProtectedRole,
    pub attribution_ceiling: AttributionCeiling,
    pub qualifying_use_ref: Option<String>,
    pub disposition_reason: Option<String>,
    pub evidence_refs: Vec<ArtifactId>,
}

impl AttributedMemoryUseRecord {
    /// Validates identity and prevents delivery, silence, or acknowledgement
    /// from being promoted to use or qualifying non-use.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.identity.validate()?;
        for (value, field) in [
            (
                &self.subject_memory_or_candidate_ref,
                "attributed_use.subject_ref",
            ),
            (&self.workscope_ref, "attributed_use.workscope_ref"),
            (
                &self.decision_opportunity_ref,
                "attributed_use.decision_opportunity_ref",
            ),
        ] {
            text(value, field)?;
        }
        digest(
            &self.subject_record_digest,
            "attributed_use.subject_record_digest",
        )?;
        self.state_fence
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "attributed_use.state_fence",
                reason: "invalid state fence",
            })?;
        if self.state_fence.task_revision != Some(self.task_revision) {
            return Err(EvaluationContractError::InvalidDependency {
                field: "attributed_use.state_fence.task_revision",
                reason: "state fence must bind the attributed task revision",
            });
        }
        self.observation_window.validate()?;
        self.denominator.validate()?;
        if !self
            .denominator
            .contains(&self.subject_memory_or_candidate_ref)
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "attributed_use.denominator",
                reason: "subject must be eligible in the decision opportunity",
            });
        }
        self.delivery.validate()?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "attributed_use.evidence_refs",
            });
        }
        if let Some(reason) = &self.disposition_reason {
            bounded_reason(reason, "attributed_use.disposition_reason")?;
        }
        match self.use_disposition {
            UseDisposition::QualifyingNonUse => {
                if self.denominator.coverage_state != CoverageState::Complete
                    || self.denominator.opportunity_end.is_none()
                    || self.observation_window.status != ObservationWindowStatus::Matured
                    || !self
                        .denominator
                        .unobservable_boundaries_and_blind_intervals
                        .is_empty()
                    || self.delivery.disposition != DeliveryExposureDisposition::DeliveredFull
                    || self.qualifying_use_ref.is_some()
                    || self.observable_influence != ObservableInfluence::NotObserved
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "attributed_use.use_disposition",
                        reason: "qualifying non-use requires closed complete coverage and full delivery evidence",
                    });
                }
            }
            UseDisposition::QualifyingUse => {
                if self.delivery.disposition != DeliveryExposureDisposition::DeliveredFull
                    || self.qualifying_use_ref.is_none()
                    || matches!(
                        self.observable_influence,
                        ObservableInfluence::NotAssessed
                            | ObservableInfluence::NotObserved
                            | ObservableInfluence::AcknowledgedOnly
                            | ObservableInfluence::Unknown
                    )
                {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "attributed_use.qualifying_use_ref",
                        reason: "qualifying use requires full exposure and an observable downstream reference",
                    });
                }
            }
            UseDisposition::Censored
            | UseDisposition::OutOfWindow
            | UseDisposition::Ineligible
            | UseDisposition::NotObservable
            | UseDisposition::Unknown => {
                if self.disposition_reason.is_none() {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "attributed_use.disposition_reason",
                        reason: "non-qualifying disposition requires a bounded reason",
                    });
                }
            }
        }
        Ok(())
    }

    /// Returns a deterministic projection with set-like evidence ordered.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut canonical = self.clone();
        canonical.denominator.eligible_subject_refs.sort();
        canonical
            .denominator
            .ineligible_subject_refs_with_reason
            .sort_by(|left, right| left.subject_ref.cmp(&right.subject_ref));
        canonical.denominator.observable_boundaries.sort();
        canonical
            .denominator
            .unobservable_boundaries_and_blind_intervals
            .sort();
        canonical.evidence_refs.sort();
        canonical.delivery.evidence_refs.sort();
        canonical
    }
}

/// Missingness state for one measured cost component.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CostValueStatus {
    Known,
    Estimated,
    Unknown,
    NotExposed,
    NotApplicable,
}

/// One cost component; absent values are not silently encoded as zero.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostEvidence {
    pub component: String,
    pub status: CostValueStatus,
    pub value: Option<u64>,
    pub units: String,
    pub source: String,
}

impl CostEvidence {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.component, "outcome.cost.component")?;
        text(&self.units, "outcome.cost.units")?;
        text(&self.source, "outcome.cost.source")?;
        if matches!(
            self.status,
            CostValueStatus::Known | CostValueStatus::Estimated
        ) && self.value.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome.cost.value",
                reason: "known or estimated cost requires a value",
            });
        }
        if matches!(
            self.status,
            CostValueStatus::Unknown | CostValueStatus::NotExposed | CostValueStatus::NotApplicable
        ) && self.value.is_some()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome.cost.value",
                reason: "missing cost status cannot carry a measured value",
            });
        }
        Ok(())
    }
}

/// Outcome dimension for one attributed-use opportunity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryOutcome {
    Improved,
    NoChange,
    Regressed,
    Inconclusive,
    Unknown,
    Censored,
    NotApplicable,
}

/// Explicit harm dimension, independent from outcome and attribution.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarmDisposition {
    NoneObserved,
    WrongDecisionOrAction,
    MissedOrWeakenedVerifier,
    StaleOrWrongScopeInfluence,
    FalseWarningOrBlock,
    ArtifactOrEffectRegression,
    PrivacySecurityOrAuthorityHarm,
    Rework,
    OpportunityCost,
    DelayedOrResidualHarm,
    Inconclusive,
    Unknown,
}

/// Explicit regret dimension, independent from harm and outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegretDisposition {
    NoRegretObserved,
    AvoidableActionRegret,
    AvoidableInactionRegret,
    PolicyOrRouteRegret,
    RollbackRegret,
    CounterfactualRegretEstimate,
    Inconclusive,
    Unknown,
}

/// Outcome/economics evidence bound to one exact attributed-use revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryOutcomeEconomicsRecord {
    pub attributed_use: AttributedUseIdentity,
    pub outcome: MemoryOutcome,
    pub outcome_measure: String,
    pub outcome_reason: Option<String>,
    pub comparison_basis: ComparisonBasis,
    pub comparison_reason: Option<String>,
    pub claim_ceiling: Option<ProofCeiling>,
    pub attribution_ceiling: AttributionCeiling,
    pub rival_causes: Vec<String>,
    pub confounders: Vec<String>,
    pub contamination: bool,
    pub crossover: bool,
    pub cost_evidence: Vec<CostEvidence>,
    pub harm: HarmDisposition,
    pub regret: RegretDisposition,
    pub evidence_refs: Vec<ArtifactId>,
}

impl MemoryOutcomeEconomicsRecord {
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.attributed_use.validate()?;
        text(&self.outcome_measure, "outcome.measure")?;
        if let Some(reason) = &self.outcome_reason {
            bounded_reason(reason, "outcome.reason")?;
        }
        if matches!(
            self.outcome,
            MemoryOutcome::Improved | MemoryOutcome::NoChange | MemoryOutcome::Regressed
        ) && self.evidence_refs.is_empty()
        {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome.evidence_refs",
            });
        }
        if matches!(
            self.outcome,
            MemoryOutcome::Inconclusive | MemoryOutcome::Unknown | MemoryOutcome::Censored
        ) && self.outcome_reason.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome.reason",
                reason: "uncertain outcome requires a bounded reason",
            });
        }
        if comparison_requires_reason(self.comparison_basis) {
            match &self.comparison_reason {
                Some(reason) => bounded_reason(reason, "outcome.comparison_reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "outcome.comparison_reason",
                        reason: "absent comparison requires a bounded reason",
                    });
                }
            }
            if comparison_requires_claim_ceiling(self.comparison_basis)
                && self.claim_ceiling.is_none()
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "outcome.claim_ceiling",
                    reason: "absent comparison requires an explicit claim ceiling",
                });
            }
        }
        texts(&self.rival_causes, "outcome.rival_causes")?;
        texts(&self.confounders, "outcome.confounders")?;
        if self.cost_evidence.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome.cost_evidence",
            });
        }
        for cost in &self.cost_evidence {
            cost.validate()?;
        }
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome.evidence_refs",
            });
        }
        Ok(())
    }

    /// Validates the cross-record identity binding before an outcome is used.
    pub fn validate_against(
        &self,
        attributed_use: &AttributedMemoryUseRecord,
    ) -> Result<(), EvaluationContractError> {
        attributed_use.validate()?;
        self.validate()?;
        if self.attributed_use != attributed_use.identity {
            return Err(EvaluationContractError::InvalidDependency {
                field: "outcome.attributed_use",
                reason: "outcome must bind the exact attributed-use revision and digest",
            });
        }
        Ok(())
    }

    /// Returns a deterministic projection with set-like evidence ordered.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut canonical = self.clone();
        canonical.rival_causes.sort();
        canonical.confounders.sort();
        canonical
            .cost_evidence
            .sort_by(|left, right| left.component.cmp(&right.component));
        canonical.evidence_refs.sort();
        canonical
    }
}

/// The bounded candidate result joining use and outcome evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributedMemoryEvaluation {
    pub attributed_use: AttributedMemoryUseRecord,
    pub outcome: MemoryOutcomeEconomicsRecord,
}

impl AttributedMemoryEvaluation {
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.outcome.validate_against(&self.attributed_use)
    }

    /// Returns a deterministic projection of both set-like record families.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        Self {
            attributed_use: self.attributed_use.canonicalized(),
            outcome: self.outcome.canonicalized(),
        }
    }
}

fn comparison_requires_reason(basis: ComparisonBasis) -> bool {
    matches!(
        basis,
        ComparisonBasis::NotApplicableWithReason | ComparisonBasis::None
    )
}

fn comparison_requires_claim_ceiling(basis: ComparisonBasis) -> bool {
    basis == ComparisonBasis::None
}

/// The evidence scope attached to a claim or report input.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceScope {
    Shape,
    Contract,
    OperationalSpine,
    ProductOutcome,
}

/// A source identity and the contract revisions it was evaluated against.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductIdentityRef {
    /// Product/source identity.
    pub product_id: ProductId,
    /// Exact source or artifact revision.
    pub source_revision: String,
    /// Contract revisions used by the proof surface.
    pub contract_revisions: Vec<ContractVersion>,
}

impl ProductIdentityRef {
    /// Validates exact identity binding.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.source_revision, "product_identity.source_revision")?;
        if self.contract_revisions.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "product_identity.contract_revisions",
            });
        }
        Ok(())
    }
}

/// One named recovery gap and its discriminator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGap {
    /// Stable gap identity.
    pub gap_id: ContractId,
    /// Human-readable bounded description.
    pub description: String,
    /// Observable discriminator that can resolve the gap.
    pub discriminator: String,
}

impl RecoveryGap {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.description, "recovery_gap.description")?;
        text(&self.discriminator, "recovery_gap.discriminator")
    }
}

/// Human-owned user/task outcome objective state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserOutcomeObjectiveState {
    pub objective_id: ContractId,
    pub owner: String,
    pub task_family_and_population: String,
    pub intended_user_outcome: String,
    pub primary_outcome_measure: String,
    pub comparison_basis: ComparisonBasis,
    pub comparison_reason: Option<String>,
    /// Required when `comparison_basis` is `NONE`.
    #[serde(default)]
    pub claim_ceiling: Option<ProofCeiling>,
    pub counter_metrics: Vec<String>,
    pub disproof_and_stop_conditions: Vec<String>,
    pub evaluation_plan_ref: Option<ContractId>,
    pub product_identity_ref: ProductIdentityRef,
    pub outcome_evidence_refs: Vec<ArtifactId>,
    pub status: ObjectiveStatus,
    pub revision: TaskRevision,
}

impl UserOutcomeObjectiveState {
    /// Validates scope, comparison rationale and objective evidence shape.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.owner, "objective.owner")?;
        text(
            &self.task_family_and_population,
            "objective.task_family_and_population",
        )?;
        text(
            &self.intended_user_outcome,
            "objective.intended_user_outcome",
        )?;
        text(
            &self.primary_outcome_measure,
            "objective.primary_outcome_measure",
        )?;
        self.product_identity_ref.validate()?;
        texts(&self.counter_metrics, "objective.counter_metrics")?;
        texts(
            &self.disproof_and_stop_conditions,
            "objective.disproof_and_stop_conditions",
        )?;
        if comparison_requires_reason(self.comparison_basis) {
            match &self.comparison_reason {
                Some(reason) => bounded_reason(reason, "objective.comparison_reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "objective.comparison_reason",
                        reason: "not-applicable comparison requires a reason",
                    });
                }
            }
            if comparison_requires_claim_ceiling(self.comparison_basis)
                && self.claim_ceiling.is_none()
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "objective.claim_ceiling",
                    reason: "absent comparison requires an explicit claim ceiling",
                });
            }
        }
        if self.status == ObjectiveStatus::Achieved && self.outcome_evidence_refs.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "objective.outcome_evidence_refs",
                reason: "achieved objective requires outcome evidence",
            });
        }
        Ok(())
    }
}

/// Bounded set of currently blocking invariant gaps.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAcceptanceProfile {
    pub profile_id: ContractId,
    pub objective_ref: ContractId,
    pub invariant_gaps: Vec<RecoveryGap>,
    pub affected_owners: Vec<String>,
    pub discriminators: Vec<String>,
    pub enablement_condition: String,
    pub status: RecoveryProfileStatus,
    pub revision: TaskRevision,
}

impl RecoveryAcceptanceProfile {
    /// Validates recovery scope without declaring the profile satisfied.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        texts(&self.affected_owners, "recovery.affected_owners")?;
        texts(&self.discriminators, "recovery.discriminators")?;
        text(&self.enablement_condition, "recovery.enablement_condition")?;
        for gap in &self.invariant_gaps {
            gap.validate()?;
        }
        if self.status == RecoveryProfileStatus::Satisfied && !self.invariant_gaps.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "recovery.invariant_gaps",
                reason: "satisfied profile cannot retain unresolved gaps",
            });
        }
        Ok(())
    }
}

/// Observable that a planned verifier is expected to establish.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedObservableSpec {
    pub property: String,
    pub matcher: String,
    pub artifact_selector: String,
}

impl ExpectedObservableSpec {
    /// Validates that the property, matcher, and artifact selector are all
    /// explicit before execution begins.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.property, "expected_observable.property")?;
        text(&self.matcher, "expected_observable.matcher")?;
        text(
            &self.artifact_selector,
            "expected_observable.artifact_selector",
        )?;
        Ok(())
    }
}

/// Planned verifier configuration used by a proof brief.
///
/// This is intentionally not executable evidence: admission of the declared
/// configuration and revision to a run remains the consumer's responsibility.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedVerifierRef {
    pub verifier_id: ContractId,
    pub scope: String,
    pub verifier_config_hash: String,
    pub expected_observable: ExpectedObservableSpec,
    pub environment_binding: String,
    pub verifier_authority_ref: String,
    pub contract_revision: ContractVersion,
    pub proof_ceiling: ProofCeiling,
}

impl PlannedVerifierRef {
    /// Validates the non-empty, non-executable verifier plan fields.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.scope, "planned_verifier.scope")?;
        text(
            &self.verifier_config_hash,
            "planned_verifier.verifier_config_hash",
        )?;
        self.expected_observable.validate()?;
        text(
            &self.environment_binding,
            "planned_verifier.environment_binding",
        )?;
        text(
            &self.verifier_authority_ref,
            "planned_verifier.verifier_authority_ref",
        )?;
        Ok(())
    }
}

/// Exact terminal verifier evidence reference used by a proof brief.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierEvidenceRef {
    pub run_id: RequestId,
    pub verifier_id: ContractId,
    pub scope: String,
    pub execution: ExecutionStatus,
    pub outcome: VerificationOutcome,
    pub proof_ceiling: ProofCeiling,
    pub evidence_refs: Vec<ArtifactId>,
}

impl VerifierEvidenceRef {
    /// Validates that the reference is scoped and not an execution shortcut.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.scope, "verifier.scope")?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "verifier.evidence_refs",
            });
        }
        if !self.execution.is_terminal() {
            return Err(EvaluationContractError::EvidenceState {
                field: "verifier.execution",
                reason: "proof reference requires a terminal execution status",
            });
        }
        if self.outcome.is_pass() && self.execution != ExecutionStatus::Succeeded {
            return Err(EvaluationContractError::EvidenceState {
                field: "verifier.outcome",
                reason: "PASS requires a succeeded verifier execution",
            });
        }
        Ok(())
    }
}

/// Binding between a planned verifier and its terminal evidence.
///
/// This binds the verifier identity, scope, and proof ceiling. Admission of
/// the planned configuration hash and contract revision to the executed run
/// remains the consumer's responsibility because terminal evidence does not
/// carry those planned-only fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalVerifierBinding {
    pub planned: PlannedVerifierRef,
    pub evidence: VerifierEvidenceRef,
}

impl TerminalVerifierBinding {
    /// Validates exact verifier identity/scope binding without admitting a run.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.planned.validate()?;
        self.evidence.validate()?;
        if self.planned.verifier_id != self.evidence.verifier_id {
            return Err(EvaluationContractError::InvalidDependency {
                field: "terminal_verifier_binding.evidence.verifier_id",
                reason: "terminal evidence verifier must match the planned verifier",
            });
        }
        if self.planned.scope != self.evidence.scope {
            return Err(EvaluationContractError::InvalidDependency {
                field: "terminal_verifier_binding.evidence.scope",
                reason: "terminal evidence scope must match the planned verifier scope",
            });
        }
        if !self
            .evidence
            .proof_ceiling
            .is_at_most(self.planned.proof_ceiling)
        {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        Ok(())
    }
}

/// Budget and time envelope for a deterministic spine proof.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetTimeEnvelope {
    pub max_wall_time_ms: u64,
    pub max_model_calls: u64,
    pub max_tool_calls: u64,
    pub max_human_attention_ms: u64,
}

impl BudgetTimeEnvelope {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.max_wall_time_ms == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "budget.max_wall_time_ms",
            });
        }
        Ok(())
    }
}

/// Bounded proof brief for deterministic operational-spine properties.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSpineProofBrief {
    pub exact_product_identity_and_contract_revisions: ProductIdentityRef,
    pub user_outcome_and_one_causal_property: String,
    pub task_and_environment: String,
    pub comparison_basis: ComparisonBasis,
    pub comparison_reason: Option<String>,
    /// Required when no comparison exists; keeps the claim bounded.
    #[serde(default)]
    pub claim_ceiling: Option<ProofCeiling>,
    pub expected_observable_and_exact_verifier: PlannedVerifierRef,
    pub counter_metrics_and_known_confounders: Vec<String>,
    pub budget_and_time_envelope: BudgetTimeEnvelope,
    pub stop_kill_rollback_and_claim_boundary: String,
    pub delayed_observation_or_recurrence_window: Option<ObservationWindowSpec>,
    pub proof_ceiling: ProofCeiling,
}

impl OperationalSpineProofBrief {
    /// Validates exact identity, verifier scope, uncertainty and budget bounds.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.exact_product_identity_and_contract_revisions
            .validate()?;
        text(
            &self.user_outcome_and_one_causal_property,
            "brief.user_outcome_and_one_causal_property",
        )?;
        text(&self.task_and_environment, "brief.task_and_environment")?;
        text(
            &self.stop_kill_rollback_and_claim_boundary,
            "brief.stop_kill_rollback_and_claim_boundary",
        )?;
        texts(
            &self.counter_metrics_and_known_confounders,
            "brief.counter_metrics_and_known_confounders",
        )?;
        self.expected_observable_and_exact_verifier.validate()?;
        if !self
            .exact_product_identity_and_contract_revisions
            .contract_revisions
            .contains(
                &self
                    .expected_observable_and_exact_verifier
                    .contract_revision,
            )
        {
            return Err(EvaluationContractError::InvalidDependency {
                field: "brief.expected_observable_and_exact_verifier.contract_revision",
                reason: "planned verifier revision must be listed in product identity contract revisions",
            });
        }
        self.budget_and_time_envelope.validate()?;
        if comparison_requires_reason(self.comparison_basis) {
            match &self.comparison_reason {
                Some(reason) => bounded_reason(reason, "brief.comparison_reason")?,
                None => {
                    return Err(EvaluationContractError::EvidenceState {
                        field: "brief.comparison_reason",
                        reason: "not-applicable comparison requires a reason",
                    });
                }
            }
            if comparison_requires_claim_ceiling(self.comparison_basis)
                && self.claim_ceiling.is_none()
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "brief.claim_ceiling",
                    reason: "absent comparison requires an explicit claim ceiling",
                });
            }
        }
        if let Some(window) = &self.delayed_observation_or_recurrence_window {
            window.validate()?;
        }
        if self.proof_ceiling > self.expected_observable_and_exact_verifier.proof_ceiling {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        Ok(())
    }
}

/// Equivalence class for a comparative budget ledger.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetEquivalence {
    Exact,
    TokenMatched,
    ComputeMatched,
    CostMatched,
    NonEquivalent,
    Unknown,
}

/// One arm's measured resource/cost evidence.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEvidence {
    pub arm_id: String,
    pub inference_tokens: u64,
    pub cache_tokens: u64,
    pub reasoning_tokens: u64,
    pub model_cost_micros: u64,
    pub model_calls: u64,
    pub retries: u64,
    pub tool_calls: u64,
    pub process_calls: u64,
    pub verifier_calls: u64,
    pub cpu_ms: u64,
    pub ram_mb_peak: u64,
    pub disk_bytes: u64,
    pub network_bytes: u64,
    pub queue_wait_ms: u64,
    pub wall_time_ms: u64,
    pub human_attention_ms: u64,
    pub hidden_background_cost_micros: u64,
}

impl BudgetEvidence {
    /// Validates arm identity; zero measurements remain valid observations.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.arm_id, "budget.arm_id")
    }
}

/// Immutable comparison budget ledger.  It records equivalence; it does not
/// infer equivalence from matching-looking fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEquivalenceLedger {
    pub ledger_id: ContractId,
    pub arm_ids_and_exact_product_route_profiles: Vec<String>,
    pub arm_evidence: Vec<BudgetEvidence>,
    pub equivalence: BudgetEquivalence,
    pub mismatch_and_claim_limit: Option<String>,
}

impl BudgetEquivalenceLedger {
    /// Validates arm uniqueness and explicit mismatch handling.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        unique_texts(
            &self.arm_ids_and_exact_product_route_profiles,
            "budget.arm_ids_and_exact_product_route_profiles",
        )?;
        if self.arm_evidence.len() < 2 {
            return Err(EvaluationContractError::EvidenceState {
                field: "budget.arm_evidence",
                reason: "comparative ledger requires at least two arms",
            });
        }
        let ids: Vec<String> = self
            .arm_evidence
            .iter()
            .map(|evidence| evidence.arm_id.clone())
            .collect();
        unique_texts(&ids, "budget.arm_evidence.arm_id")?;
        for evidence in &self.arm_evidence {
            evidence.validate()?;
            if !self
                .arm_ids_and_exact_product_route_profiles
                .iter()
                .any(|arm| arm == &evidence.arm_id)
            {
                return Err(EvaluationContractError::EvidenceState {
                    field: "budget.arm_evidence.arm_id",
                    reason: "evidence arm is absent from declared profiles",
                });
            }
        }
        if matches!(
            self.equivalence,
            BudgetEquivalence::NonEquivalent | BudgetEquivalence::Unknown
        ) && self.mismatch_and_claim_limit.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "budget.mismatch_and_claim_limit",
                reason: "non-equivalent or unknown budget requires an explicit claim limit",
            });
        }
        if let Some(limit) = &self.mismatch_and_claim_limit {
            text(limit, "budget.mismatch_and_claim_limit")?;
        }
        Ok(())
    }
}

/// A full plan required for stochastic/comparative/population/generalization claims.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductEvaluationPlan {
    pub plan_id: ContractId,
    pub claim_kinds: Vec<ClaimKind>,
    pub brief: OperationalSpineProofBrief,
    pub target_user_task_population_and_strata: String,
    pub immutable_sample_and_cluster_unit: String,
    pub pilot_holdout_and_contamination_boundaries: String,
    pub comparison_arms_and_budget_equivalence: BudgetEquivalenceLedger,
    pub randomization_pairing_blocking_seed_and_order: String,
    pub route_model_tool_environment_freeze: String,
    pub primary_outcome_quality_floor_and_countermetrics: String,
    pub pilot_variance_and_dependence: String,
    pub minimum_detectable_effect_or_noninferiority_margin: String,
    pub precision_power_or_declared_estimation_policy: String,
    pub evaluator_oracle_and_independence_profile: String,
    pub leakage_and_prior_run_visibility_controls: String,
    pub failed_excluded_censored_trial_policy: String,
    pub delayed_outcome_and_recurrence_policy: String,
    pub preregistered_analysis_and_final_disposition: String,
}

impl ProductEvaluationPlan {
    /// Validates plan completeness and prevents budget/uncertainty erasure.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.claim_kinds.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "plan.claim_kinds",
            });
        }
        self.brief.validate()?;
        self.comparison_arms_and_budget_equivalence.validate()?;
        for (field, value) in [
            (
                "plan.target_user_task_population_and_strata",
                &self.target_user_task_population_and_strata,
            ),
            (
                "plan.immutable_sample_and_cluster_unit",
                &self.immutable_sample_and_cluster_unit,
            ),
            (
                "plan.pilot_holdout_and_contamination_boundaries",
                &self.pilot_holdout_and_contamination_boundaries,
            ),
            (
                "plan.randomization_pairing_blocking_seed_and_order",
                &self.randomization_pairing_blocking_seed_and_order,
            ),
            (
                "plan.route_model_tool_environment_freeze",
                &self.route_model_tool_environment_freeze,
            ),
            (
                "plan.primary_outcome_quality_floor_and_countermetrics",
                &self.primary_outcome_quality_floor_and_countermetrics,
            ),
            (
                "plan.pilot_variance_and_dependence",
                &self.pilot_variance_and_dependence,
            ),
            (
                "plan.minimum_detectable_effect_or_noninferiority_margin",
                &self.minimum_detectable_effect_or_noninferiority_margin,
            ),
            (
                "plan.precision_power_or_declared_estimation_policy",
                &self.precision_power_or_declared_estimation_policy,
            ),
            (
                "plan.evaluator_oracle_and_independence_profile",
                &self.evaluator_oracle_and_independence_profile,
            ),
            (
                "plan.leakage_and_prior_run_visibility_controls",
                &self.leakage_and_prior_run_visibility_controls,
            ),
            (
                "plan.failed_excluded_censored_trial_policy",
                &self.failed_excluded_censored_trial_policy,
            ),
            (
                "plan.delayed_outcome_and_recurrence_policy",
                &self.delayed_outcome_and_recurrence_policy,
            ),
            (
                "plan.preregistered_analysis_and_final_disposition",
                &self.preregistered_analysis_and_final_disposition,
            ),
        ] {
            text(value, field)?;
        }
        Ok(())
    }
}

/// Censoring or exposure record for a trial/window.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CensoringRecord {
    pub reason: String,
    pub observed_until: Option<ClockReading>,
    pub exposure: String,
}

impl CensoringRecord {
    fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.reason, "censoring.reason")?;
        text(&self.exposure, "censoring.exposure")?;
        if let Some(clock) = self.observed_until {
            clock
                .validate()
                .map_err(|_| EvaluationContractError::InvalidDependency {
                    field: "censoring.observed_until",
                    reason: "invalid clock reading",
                })?;
        }
        Ok(())
    }
}

/// One immutable trial/result record retained by a report or evaluator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRecord {
    pub trial_id: ContractId,
    pub plan_ref: ContractId,
    pub arm_id: String,
    pub request_id: Option<RequestId>,
    pub status: TrialStatus,
    pub outcome: TrialOutcome,
    pub receipt_ref: Option<ReceiptId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub budget_evidence: Option<BudgetEvidence>,
    pub censoring: Option<CensoringRecord>,
    pub contamination_reason: Option<String>,
}

impl TrialRecord {
    /// Validates outcome/status agreement and preserves unknown/censored reasons.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.arm_id, "trial.arm_id")?;
        self.outcome.validate()?;
        if matches!(
            self.status,
            TrialStatus::Succeeded | TrialStatus::Failed | TrialStatus::Partial
        ) && self.evidence_refs.is_empty()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.evidence_refs",
                reason: "terminal observed trial requires evidence references",
            });
        }
        if self.status == TrialStatus::Unknown && !self.outcome.is_uncertain() {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.outcome",
                reason: "unknown trial status requires unknown or inconclusive outcome",
            });
        }
        if matches!(self.status, TrialStatus::Censored | TrialStatus::Excluded)
            && self.censoring.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.censoring",
                reason: "censored or excluded trial requires a censoring record",
            });
        }
        if let Some(censoring) = &self.censoring {
            censoring.validate()?;
        }
        if matches!(self.status, TrialStatus::Contaminated) && self.contamination_reason.is_none() {
            return Err(EvaluationContractError::EvidenceState {
                field: "trial.contamination_reason",
                reason: "contaminated trial requires a reason",
            });
        }
        if let Some(reason) = &self.contamination_reason {
            text(reason, "trial.contamination_reason")?;
        }
        if let Some(budget) = &self.budget_evidence {
            budget.validate()?;
        }
        Ok(())
    }
}

/// Delayed outcome observation state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationWindowStatus {
    Open,
    Matured,
    Regressed,
    CensoredOrInconclusive,
}

/// Declared observation interval and recurrence policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindowSpec {
    pub window_id: ContractId,
    pub duration_ms: u64,
    pub recurrence_measure: String,
    pub status: ObservationWindowStatus,
}

impl ObservationWindowSpec {
    /// Validates positive duration and explicit recurrence measure.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.duration_ms == 0 {
            return Err(EvaluationContractError::InvalidInterval {
                field: "observation_window.duration_ms",
            });
        }
        text(
            &self.recurrence_measure,
            "observation_window.recurrence_measure",
        )
    }
}

/// One delayed product outcome observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeObservation {
    pub observation_id: ContractId,
    pub observed_at: ClockReading,
    pub outcome: TrialOutcome,
    pub downstream_rework: String,
    pub maintenance_or_rollback: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub censored: Option<CensoringRecord>,
}

impl OutcomeObservation {
    /// Validates delayed observation without rewriting the original trial.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.observed_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "outcome_observation.observed_at",
                reason: "invalid clock reading",
            })?;
        self.outcome.validate()?;
        text(
            &self.downstream_rework,
            "outcome_observation.downstream_rework",
        )?;
        text(
            &self.maintenance_or_rollback,
            "outcome_observation.maintenance_or_rollback",
        )?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome_observation.evidence_refs",
            });
        }
        if let Some(censored) = &self.censored {
            censored.validate()?;
        }
        Ok(())
    }
}

/// Durable delayed-outcome window linked to an accepted task/artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductOutcomeObservationWindow {
    pub window_id: ContractId,
    pub accepted_task_ref: TaskId,
    pub artifact_refs: Vec<ArtifactId>,
    pub release_ref: Option<ArtifactId>,
    pub opened_at: ClockReading,
    pub closes_at: Option<ClockReading>,
    pub status: ObservationWindowStatus,
    pub observations: Vec<OutcomeObservation>,
    pub evaluator_revision: ContractVersion,
    pub rollback_reconciliation: Option<String>,
}

impl ProductOutcomeObservationWindow {
    /// Validates delayed evidence and makes open/censored states explicit.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        if self.artifact_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "outcome_window.artifact_refs",
            });
        }
        self.opened_at
            .validate()
            .map_err(|_| EvaluationContractError::InvalidDependency {
                field: "outcome_window.opened_at",
                reason: "invalid clock reading",
            })?;
        if let Some(closes_at) = self.closes_at {
            closes_at
                .validate()
                .map_err(|_| EvaluationContractError::InvalidDependency {
                    field: "outcome_window.closes_at",
                    reason: "invalid clock reading",
                })?;
            if let (Some(opened), Some(closed)) =
                (self.opened_at.known_time_ms, closes_at.known_time_ms)
                && closed < opened
            {
                return Err(EvaluationContractError::InvalidInterval {
                    field: "outcome_window.opened_at/closes_at",
                });
            }
        }
        if self.status != ObservationWindowStatus::Open && self.observations.is_empty() {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome_window.observations",
                reason: "closed window requires at least one observation",
            });
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        if matches!(
            self.status,
            ObservationWindowStatus::Regressed | ObservationWindowStatus::CensoredOrInconclusive
        ) && self.rollback_reconciliation.is_none()
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "outcome_window.rollback_reconciliation",
                reason: "regressed or censored window requires reconciliation text",
            });
        }
        if let Some(reconciliation) = &self.rollback_reconciliation {
            text(reconciliation, "outcome_window.rollback_reconciliation")?;
        }
        Ok(())
    }
}

/// Evidence-bound input accepted by a report renderer.  It cannot alter any
/// objective, trial, verifier, finish or release state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReportInput {
    pub input_id: ContractId,
    pub objective_ref: ContractId,
    pub plan_ref: Option<ContractId>,
    pub product_identity: ProductIdentityRef,
    pub claim_scope: EvidenceScope,
    pub claimed_proof_ceiling: ProofCeiling,
    pub available_proof_ceiling: ProofCeiling,
    pub trial_refs: Vec<ContractId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub uncertainty: String,
    pub status: ProductEvidenceStatus,
    pub outcome_window_ref: Option<ContractId>,
}

impl EvaluationReportInput {
    /// Validates evidence binding and refuses proof overclaims.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        self.product_identity.validate()?;
        if self.trial_refs.is_empty() && self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "report_input.evidence_refs_or_trial_refs",
            });
        }
        text(&self.uncertainty, "report_input.uncertainty")?;
        if self.claimed_proof_ceiling > self.available_proof_ceiling {
            return Err(EvaluationContractError::ProofOverclaim);
        }
        if matches!(
            self.status,
            ProductEvidenceStatus::CurrentlyVerified | ProductEvidenceStatus::Matured
        ) && self.uncertainty.eq_ignore_ascii_case("unknown")
        {
            return Err(EvaluationContractError::EvidenceState {
                field: "report_input.uncertainty",
                reason: "verified or matured input cannot declare unknown uncertainty",
            });
        }
        Ok(())
    }
}

/// Compatibility alias used by report consumers.
pub type ReportInput = EvaluationReportInput;
/// Compatibility alias for a delayed product outcome record.
pub type DelayedOutcomeWindow = ProductOutcomeObservationWindow;
/// Compatibility alias for a trial/outcome record.
pub type Trial = TrialRecord;

/// Public projection for the C0-13 surface-types slice.
pub mod surface_types {
    pub use super::{
        AttributedMemoryEvaluation, AttributedMemoryUseRecord, AttributedUseIdentity,
        AttributionCeiling, BudgetEquivalence, BudgetEquivalenceLedger, BudgetEvidence,
        BudgetTimeEnvelope, CensoringRecord, ClaimKind, ComparisonBasis, CostEvidence,
        CostValueStatus, CoverageState, DecisionOpportunityDenominator, DelayedOutcomeWindow,
        DeliveryExposureDisposition, DeliveryExposureEvidence, EvaluationReportInput,
        EvidenceScope, ExpectedObservableSpec, GraphEvidenceRef, HarmDisposition,
        InclusionDisposition, IneligibleSubjectRef, MemoryOutcome, MemoryOutcomeEconomicsRecord,
        ObjectiveStatus, ObservableInfluence, ObservationWindowSpec, ObservationWindowStatus,
        OperationalSpineProofBrief, OutcomeObservation, PlannedVerifierRef, ProductEvaluationPlan,
        ProductEvidenceStatus, ProductIdentityRef, ProtectedRole, RecoveryAcceptanceProfile,
        RecoveryGap, RecoveryProfileStatus, RegretDisposition, ReportInput,
        TerminalVerifierBinding, Trial, TrialOutcome, TrialRecord, TrialStatus, UseDisposition,
        UserOutcomeObjectiveState, VerifierEvidenceRef,
    };
}

/// Public projection for the validation-compatibility slice.
pub mod validation_compatibility {
    pub use super::EvaluationContractError;
}

/// Small, deterministic malformed-consumer fixtures.  They are data only;
/// no fixture can be mistaken for an evaluator result or authority decision.
pub mod negative_consumer_fixtures {
    use serde_json::{Value, json};

    /// JSON with an unknown field, rejected by every deny-unknown-fields surface.
    pub fn unknown_field() -> Value {
        json!({"objective_id": "objective-1", "unknown": true})
    }

    /// JSON with a blank required text value.
    pub fn blank_required_text() -> Value {
        json!({"owner": " ", "intended_user_outcome": ""})
    }

    /// JSON preserving an explicit unknown outcome rather than a false success.
    pub fn explicit_unknown_outcome() -> Value {
        json!({"kind": "UNKNOWN", "reason": "provider did not reconcile"})
    }

    /// JSON for a censoring record without its required reason.
    pub fn censored_without_reason() -> Value {
        json!({"reason": "", "exposure": "partial"})
    }

    /// Planned verifier JSON with terminal-only fields; rejected fail-closed.
    pub fn planned_as_terminal() -> Value {
        json!({
            "verifier_id": "verifier-1",
            "scope": "one task",
            "verifier_config_hash": "config-1",
            "expected_observable": {
                "property": "one property",
                "matcher": "equals expected",
                "artifact_selector": "artifact.json"
            },
            "environment_binding": "local fixture",
            "verifier_authority_ref": "authority:test",
            "contract_revision": {"major": 2, "minor": 0, "patch": 0},
            "proof_ceiling": "SCOPED_VERIFICATION",
            "run_id": "run-1",
            "execution": "SUCCEEDED",
            "outcome": {"kind": "PASS"},
            "evidence_refs": ["artifact-1"]
        })
    }

    /// Planned verifier JSON with empty required text fields.
    pub fn empty_planned_fields() -> Value {
        json!({
            "verifier_id": "verifier-1",
            "scope": " ",
            "verifier_config_hash": "",
            "expected_observable": {
                "property": "",
                "matcher": " ",
                "artifact_selector": ""
            },
            "environment_binding": "",
            "verifier_authority_ref": "",
            "contract_revision": {"major": 2, "minor": 0, "patch": 0},
            "proof_ceiling": "OBSERVATION"
        })
    }
}

/// Graph evidence can be attached without making the graph an evaluation oracle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEvidenceRef {
    pub revision: ArtifactId,
    pub freshness: EvidenceFreshness,
    pub scope: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl GraphEvidenceRef {
    /// Validates a graph evidence attachment's scope and artifact binding.
    pub fn validate(&self) -> Result<(), EvaluationContractError> {
        text(&self.scope, "graph_evidence.scope")?;
        if self.evidence_refs.is_empty() {
            return Err(EvaluationContractError::EmptyCollection {
                field: "graph_evidence.evidence_refs",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! valid {
        ($type:ty, $value:expr) => {{
            match <$type>::new($value) {
                Ok(value) => value,
                Err(error) => panic!("invalid test value: {error}"),
            }
        }};
    }

    fn product_identity() -> ProductIdentityRef {
        ProductIdentityRef {
            product_id: valid!(ProductId, "product-1"),
            source_revision: "source-1".to_owned(),
            contract_revisions: vec![CONTRACT_VERSION],
        }
    }

    fn planned_verifier() -> PlannedVerifierRef {
        PlannedVerifierRef {
            verifier_id: valid!(ContractId, "verifier-1"),
            scope: "one task".to_owned(),
            verifier_config_hash: "config-1".to_owned(),
            expected_observable: ExpectedObservableSpec {
                property: "one property".to_owned(),
                matcher: "equals expected".to_owned(),
                artifact_selector: "artifact.json".to_owned(),
            },
            environment_binding: "local fixture".to_owned(),
            verifier_authority_ref: "authority:test".to_owned(),
            contract_revision: CONTRACT_VERSION,
            proof_ceiling: ProofCeiling::ScopedVerification,
        }
    }

    fn verifier_evidence() -> VerifierEvidenceRef {
        VerifierEvidenceRef {
            run_id: valid!(RequestId, "run-1"),
            verifier_id: valid!(ContractId, "verifier-1"),
            scope: "one task".to_owned(),
            execution: ExecutionStatus::Succeeded,
            outcome: VerificationOutcome::Pass,
            proof_ceiling: ProofCeiling::ScopedVerification,
            evidence_refs: vec![valid!(ArtifactId, "artifact-1")],
        }
    }

    fn budget() -> BudgetEquivalenceLedger {
        BudgetEquivalenceLedger {
            ledger_id: valid!(ContractId, "ledger-1"),
            arm_ids_and_exact_product_route_profiles: vec![
                "control".to_owned(),
                "treatment".to_owned(),
            ],
            arm_evidence: vec![
                BudgetEvidence {
                    arm_id: "control".to_owned(),
                    wall_time_ms: 1,
                    ..Default::default()
                },
                BudgetEvidence {
                    arm_id: "treatment".to_owned(),
                    wall_time_ms: 1,
                    ..Default::default()
                },
            ],
            equivalence: BudgetEquivalence::Exact,
            mismatch_and_claim_limit: None,
        }
    }

    fn attributed_use() -> AttributedMemoryUseRecord {
        let task_revision = TaskRevision::genesis();
        AttributedMemoryUseRecord {
            identity: AttributedUseIdentity {
                evaluation_id: valid!(ContractId, "evaluation-1"),
                evaluation_revision: CONTRACT_VERSION,
                record_digest: "use-digest-1".to_owned(),
            },
            subject_memory_or_candidate_ref: "memory-1".to_owned(),
            subject_record_revision: task_revision,
            subject_record_digest: "subject-digest-1".to_owned(),
            workscope_ref: "scope-1".to_owned(),
            task_ref: valid!(TaskId, "task-1"),
            task_revision,
            decision_opportunity_ref: "opportunity-1".to_owned(),
            state_fence: {
                let mut fence = StateFence::new(
                    eliot_contracts::AuthorityEpoch::genesis(),
                    eliot_contracts::ResourceGeneration::genesis(),
                );
                fence.task_revision = Some(task_revision);
                fence
            },
            observation_window: ObservationWindowSpec {
                window_id: valid!(ContractId, "window-1"),
                duration_ms: 1,
                recurrence_measure: "one decision".to_owned(),
                status: ObservationWindowStatus::Matured,
            },
            denominator: DecisionOpportunityDenominator {
                eligible_subject_refs: vec!["memory-1".to_owned()],
                ineligible_subject_refs_with_reason: vec![],
                opportunity_start: ClockReading {
                    known_time_ms: Some(1),
                    ..Default::default()
                },
                opportunity_end: Some(ClockReading {
                    known_time_ms: Some(2),
                    ..Default::default()
                }),
                observable_boundaries: vec!["decision".to_owned()],
                unobservable_boundaries_and_blind_intervals: vec![],
                coverage_state: CoverageState::Complete,
                denominator_source_and_revision: "denominator-1".to_owned(),
            },
            inclusion: InclusionDisposition::AdmittedFull,
            delivery: DeliveryExposureEvidence {
                disposition: DeliveryExposureDisposition::DeliveredFull,
                exposure_revision: "exposure-1".to_owned(),
                exposure_digest: "exposure-digest-1".to_owned(),
                evidence_refs: vec![valid!(ArtifactId, "delivery-1")],
                reason: None,
            },
            observable_influence: ObservableInfluence::NotObserved,
            use_disposition: UseDisposition::QualifyingNonUse,
            protected_role: ProtectedRole::None,
            attribution_ceiling: AttributionCeiling::DeliveryOnly,
            qualifying_use_ref: None,
            disposition_reason: None,
            evidence_refs: vec![valid!(ArtifactId, "use-evidence-1")],
        }
    }

    fn outcome(attributed_use: &AttributedMemoryUseRecord) -> MemoryOutcomeEconomicsRecord {
        MemoryOutcomeEconomicsRecord {
            attributed_use: attributed_use.identity.clone(),
            outcome: MemoryOutcome::NotApplicable,
            outcome_measure: "decision outcome".to_owned(),
            outcome_reason: None,
            comparison_basis: ComparisonBasis::ExactPrechangeBehavior,
            comparison_reason: None,
            claim_ceiling: None,
            attribution_ceiling: AttributionCeiling::DeliveryOnly,
            rival_causes: vec!["none identified".to_owned()],
            confounders: vec!["none identified".to_owned()],
            contamination: false,
            crossover: false,
            cost_evidence: vec![CostEvidence {
                component: "provider".to_owned(),
                status: CostValueStatus::Known,
                value: Some(0),
                units: "micros".to_owned(),
                source: "fixture".to_owned(),
            }],
            harm: HarmDisposition::NoneObserved,
            regret: RegretDisposition::Unknown,
            evidence_refs: vec![valid!(ArtifactId, "outcome-evidence-1")],
        }
    }

    #[test]
    fn unknown_trial_is_not_a_success_alias() {
        let trial = TrialRecord {
            trial_id: valid!(ContractId, "trial-1"),
            plan_ref: valid!(ContractId, "plan-1"),
            arm_id: "control".to_owned(),
            request_id: None,
            status: TrialStatus::Unknown,
            outcome: TrialOutcome::Unknown {
                reason: "provider stopped".to_owned(),
            },
            receipt_ref: None,
            evidence_refs: vec![],
            budget_evidence: None,
            censoring: None,
            contamination_reason: None,
        };
        assert!(trial.validate().is_ok());
        assert!(trial.outcome.is_uncertain());
    }

    #[test]
    fn none_comparison_requires_bounded_reason_and_claim_ceiling() {
        let mut brief = OperationalSpineProofBrief {
            exact_product_identity_and_contract_revisions: product_identity(),
            user_outcome_and_one_causal_property: "memory use".to_owned(),
            task_and_environment: "fixture".to_owned(),
            comparison_basis: ComparisonBasis::None,
            comparison_reason: None,
            claim_ceiling: None,
            expected_observable_and_exact_verifier: planned_verifier(),
            counter_metrics_and_known_confounders: vec!["latency".to_owned()],
            budget_and_time_envelope: BudgetTimeEnvelope {
                max_wall_time_ms: 1,
                max_model_calls: 0,
                max_tool_calls: 0,
                max_human_attention_ms: 0,
            },
            stop_kill_rollback_and_claim_boundary: "observational only".to_owned(),
            delayed_observation_or_recurrence_window: None,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        };
        assert!(brief.validate().is_err());
        brief.comparison_reason = Some("no eligible comparator".to_owned());
        assert!(brief.validate().is_err());
        brief.claim_ceiling = Some(ProofCeiling::CandidateArtifact);
        assert!(brief.validate().is_ok());
        brief.comparison_reason = Some("x".repeat(MAX_REASON_LENGTH + 1));
        assert!(brief.validate().is_err());
    }

    #[test]
    fn qualifying_non_use_requires_complete_denominator_and_full_exposure() {
        let mut record = attributed_use();
        assert!(record.validate().is_ok());

        record.delivery.disposition = DeliveryExposureDisposition::DeliveredPartial;
        assert!(record.validate().is_err());

        record = attributed_use();
        record
            .denominator
            .unobservable_boundaries_and_blind_intervals
            .push("host action".to_owned());
        assert!(record.validate().is_err());
    }

    #[test]
    fn outcome_requires_exact_attributed_use_revision_and_digest() {
        let record = attributed_use();
        let mut evaluation = AttributedMemoryEvaluation {
            outcome: outcome(&record),
            attributed_use: record,
        };
        assert!(evaluation.validate().is_ok());

        evaluation.outcome.attributed_use.record_digest = "other-digest".to_owned();
        assert!(evaluation.validate().is_err());
        evaluation.outcome.attributed_use = evaluation.attributed_use.identity.clone();
        evaluation.outcome.attributed_use.evaluation_revision = ContractVersion::new(9, 0, 0);
        assert!(evaluation.validate().is_err());
    }

    #[test]
    fn observable_downstream_reference_can_establish_use() {
        let mut record = attributed_use();
        record.observable_influence = ObservableInfluence::ChangedDecisionOrAction;
        record.use_disposition = UseDisposition::QualifyingUse;
        record.qualifying_use_ref = Some("decision-1".to_owned());
        assert!(record.validate().is_ok());
    }

    #[test]
    fn canonicalized_use_is_order_independent_and_protected_roles_need_review() {
        let record = attributed_use();
        let mut permuted = record.clone();
        permuted.denominator.eligible_subject_refs.reverse();
        permuted.evidence_refs.reverse();
        assert_eq!(record.canonicalized(), permuted.canonicalized());
        let mut protected = record;
        protected.protected_role = ProtectedRole::FailureFingerprint;
        assert!(protected.validate().is_ok());
        assert!(protected.protected_role.requires_accessibility_review());
    }

    #[test]
    fn missing_cost_is_not_zero_cost() {
        let record = attributed_use();
        let mut economics = outcome(&record);
        economics.cost_evidence[0].status = CostValueStatus::NotExposed;
        economics.cost_evidence[0].value = Some(0);
        assert!(economics.validate().is_err());
        economics.cost_evidence[0].value = None;
        assert!(economics.validate().is_ok());
    }

    #[test]
    fn unknown_budget_requires_claim_limit() {
        let mut ledger = budget();
        ledger.equivalence = BudgetEquivalence::Unknown;
        assert!(ledger.validate().is_err());
        ledger.mismatch_and_claim_limit = Some("operating-point only".to_owned());
        assert!(ledger.validate().is_ok());
    }

    #[test]
    fn proof_ceiling_cannot_be_overclaimed() {
        let brief = OperationalSpineProofBrief {
            exact_product_identity_and_contract_revisions: product_identity(),
            user_outcome_and_one_causal_property: "recovery".to_owned(),
            task_and_environment: "fixture".to_owned(),
            comparison_basis: ComparisonBasis::ExactPrechangeBehavior,
            comparison_reason: None,
            claim_ceiling: None,
            expected_observable_and_exact_verifier: planned_verifier(),
            counter_metrics_and_known_confounders: vec!["latency".to_owned()],
            budget_and_time_envelope: BudgetTimeEnvelope {
                max_wall_time_ms: 1,
                max_model_calls: 0,
                max_tool_calls: 0,
                max_human_attention_ms: 0,
            },
            stop_kill_rollback_and_claim_boundary: "no release claim".to_owned(),
            delayed_observation_or_recurrence_window: None,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        assert_eq!(
            brief.validate(),
            Err(EvaluationContractError::ProofOverclaim)
        );
    }

    #[test]
    fn planned_verifier_rejects_terminal_fields_during_serde() {
        assert!(
            serde_json::from_value::<PlannedVerifierRef>(
                negative_consumer_fixtures::planned_as_terminal()
            )
            .is_err()
        );
    }

    #[test]
    fn planned_verifier_rejects_empty_required_fields() {
        let planned = match serde_json::from_value::<PlannedVerifierRef>(
            negative_consumer_fixtures::empty_planned_fields(),
        ) {
            Ok(planned) => planned,
            Err(error) => panic!("fixture must retain the planned verifier shape: {error}"),
        };
        assert!(planned.validate().is_err());
    }

    #[test]
    fn brief_rejects_unlisted_planned_contract_revision() {
        let mut brief = OperationalSpineProofBrief {
            exact_product_identity_and_contract_revisions: product_identity(),
            user_outcome_and_one_causal_property: "recovery".to_owned(),
            task_and_environment: "fixture".to_owned(),
            comparison_basis: ComparisonBasis::ExactPrechangeBehavior,
            comparison_reason: None,
            claim_ceiling: None,
            expected_observable_and_exact_verifier: planned_verifier(),
            counter_metrics_and_known_confounders: vec!["latency".to_owned()],
            budget_and_time_envelope: BudgetTimeEnvelope {
                max_wall_time_ms: 1,
                max_model_calls: 0,
                max_tool_calls: 0,
                max_human_attention_ms: 0,
            },
            stop_kill_rollback_and_claim_boundary: "no release claim".to_owned(),
            delayed_observation_or_recurrence_window: None,
            proof_ceiling: ProofCeiling::ScopedVerification,
        };
        brief
            .expected_observable_and_exact_verifier
            .contract_revision = ContractVersion::new(1, 0, 0);
        assert!(matches!(
            brief.validate(),
            Err(EvaluationContractError::InvalidDependency { .. })
        ));
    }

    #[test]
    fn terminal_binding_rejects_scope_and_verifier_substitution() {
        let mut binding = TerminalVerifierBinding {
            planned: planned_verifier(),
            evidence: verifier_evidence(),
        };
        binding.evidence.scope = "other task".to_owned();
        assert!(binding.validate().is_err());

        binding.evidence.scope = binding.planned.scope.clone();
        binding.evidence.verifier_id = valid!(ContractId, "other-verifier");
        assert!(binding.validate().is_err());
    }

    #[test]
    fn terminal_binding_rejects_evidence_above_planned_ceiling() {
        let mut binding = TerminalVerifierBinding {
            planned: planned_verifier(),
            evidence: verifier_evidence(),
        };
        binding.planned.proof_ceiling = ProofCeiling::Observation;
        assert_eq!(
            binding.validate(),
            Err(EvaluationContractError::ProofOverclaim)
        );
    }

    #[test]
    fn terminal_evidence_requires_terminal_status_and_artifacts() {
        let mut evidence = verifier_evidence();
        evidence.execution = ExecutionStatus::Running;
        assert!(evidence.validate().is_err());

        evidence.execution = ExecutionStatus::Succeeded;
        evidence.evidence_refs.clear();
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn terminal_pass_requires_succeeded_execution() {
        for execution in [
            ExecutionStatus::Failed,
            ExecutionStatus::Partial,
            ExecutionStatus::Unknown,
            ExecutionStatus::Blocked,
            ExecutionStatus::Cancelled,
        ] {
            let mut evidence = verifier_evidence();
            evidence.execution = execution;
            assert!(matches!(
                evidence.validate(),
                Err(EvaluationContractError::EvidenceState {
                    field: "verifier.outcome",
                    ..
                })
            ));
        }
    }

    #[test]
    fn censoring_requires_reason() {
        let record = CensoringRecord {
            reason: " ".to_owned(),
            observed_until: None,
            exposure: "partial".to_owned(),
        };
        assert!(record.validate().is_err());
    }

    #[test]
    fn graph_evidence_requires_artifacts() {
        let evidence = GraphEvidenceRef {
            revision: valid!(ArtifactId, "graph-revision-1"),
            freshness: EvidenceFreshness::ExactCandidate,
            scope: "crate".to_owned(),
            evidence_refs: vec![],
        };
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn negative_fixtures_are_non_authoritative_data() {
        assert_eq!(
            negative_consumer_fixtures::explicit_unknown_outcome()["kind"],
            "UNKNOWN"
        );
        assert_eq!(
            negative_consumer_fixtures::censored_without_reason()["reason"],
            ""
        );
    }
}
