//! Deterministic G-08 governance state machines.
//!
//! This crate owns typed transitions only. It does not persist records, issue
//! authority, execute recovery, deliver notifications, or decide task finish.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{ArtifactId, ClockReading, StateFence};
use eliot_evidence::ObservationRecord;
use eliot_observation_contracts::ObservationError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable package identity.
pub const CONTRACT_NAME: &str = "eliot.governor.problem";
/// Current package contract revision.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a non-blank, non-control-character identity.
            pub fn new(value: impl Into<String>) -> Result<Self, ProblemError> {
                let value = value.into();
                text(&value, $field)?;
                Ok(Self(value))
            }

            /// Returns stable identity text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

id_type!(/// Signal identity.
    SignalId, "signal_id");
id_type!(/// Problem identity.
    ProblemId, "problem_id");
id_type!(/// Incident identity.
    IncidentId, "incident_id");
id_type!(/// Conflict identity.
    ConflictId, "conflict_id");
id_type!(/// Concilium run identity.
    ConciliumRunId, "concilium_run_id");
id_type!(/// Critical attention identity.
    AttentionId, "attention_id");
id_type!(/// Recovery profile identity.
    RecoveryProfileId, "profile_id");
id_type!(/// Governed challenge identity.
    ChallengeId, "challenge_id");
id_type!(/// Implementation deviation identity.
    DeviationId, "deviation_id");

/// Typed failures for all G-08 transitions.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProblemError {
    /// A required text field is malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// A required collection has no values.
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    /// A collection contains duplicate identities.
    #[error("{field} contains duplicate value {value}")]
    Duplicate { field: &'static str, value: String },
    /// A provider evidence contract rejected a record.
    #[error("evidence contract: {0}")]
    Evidence(eliot_evidence::EvidenceError),
    /// A provider observation contract rejected a record.
    #[error("observation contract: {0}")]
    Observation(ObservationError),
    /// A state fence does not match the current owner/state.
    #[error("state fence mismatch")]
    FenceMismatch,
    /// The requested transition is not legal from the current state.
    #[error("illegal transition from {from} to {to}")]
    IllegalTransition { from: String, to: String },
    /// A stale owner cannot advance the record.
    #[error("owner mismatch")]
    OwnerMismatch,
    /// A terminal record needs explicit new evidence before reopening.
    #[error("reopen requires new evidence")]
    ReopenRequiresEvidence,
    /// Acknowledgement was already recorded by another principal.
    #[error("acknowledgement conflict")]
    AcknowledgementConflict,
    /// A resolution transition lacks verifier/evidence support.
    #[error("resolution requires evidence")]
    ResolutionRequiresEvidence,
    /// Hard Boundaries cannot be challenged or deviated.
    #[error("hard boundary cannot be challenged")]
    HardBoundaryImmutable,
    /// A challenge/deviation has expired or is no longer mutable.
    #[error("record is no longer mutable")]
    ImmutableState,
}

fn text(value: &str, field: &'static str) -> Result<(), ProblemError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProblemError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn nonempty<T>(values: &[T], field: &'static str) -> Result<(), ProblemError> {
    if values.is_empty() {
        Err(ProblemError::Empty { field })
    } else {
        Ok(())
    }
}

fn unique_text(values: &[String], field: &'static str) -> Result<(), ProblemError> {
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(ProblemError::Duplicate {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn fence(fence: &StateFence) -> Result<(), ProblemError> {
    fence.validate().map_err(|_| ProblemError::InvalidField {
        field: "state_fence",
        reason: "authority and resource generations are required",
    })
}

fn same_fence(expected: &StateFence, actual: &StateFence) -> Result<(), ProblemError> {
    fence(expected)?;
    fence(actual)?;
    if expected == actual {
        Ok(())
    } else {
        Err(ProblemError::FenceMismatch)
    }
}

fn owner_name(value: &str) -> Result<(), ProblemError> {
    text(value, "owner")
}

/// Signal severity from deterministic supervision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSeverity {
    Info,
    Warning,
    Blocking,
    IncidentCandidate,
}

/// Attribution confidence, independent from severity.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalAttribution {
    Known,
    Suspected,
    Unknown,
}

/// Signal processing axis.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalProcessingState {
    Observed,
    Triaged,
    Investigating,
    Escalated,
    Closed,
}

/// Signal delivery axis.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryState {
    Pending,
    Delivered,
    Acknowledged,
}

/// Signal semantic disposition; it does not itself resolve a problem.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalDisposition {
    Informational,
    ProblemCandidate,
    IncidentCandidate,
    Superseded,
}

/// Observed deviation with preserved evidence and independent state axes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub signal_id: SignalId,
    pub rule_id: String,
    pub severity: SignalSeverity,
    pub subject: String,
    pub scope_id: String,
    pub observed_at: ClockReading,
    pub evidence_handles: Vec<ArtifactId>,
    pub observation: Option<ObservationRecord>,
    pub attribution: SignalAttribution,
    pub processing_state: SignalProcessingState,
    pub delivery_state: DeliveryState,
    pub disposition: SignalDisposition,
    pub dedup_key: String,
    pub reopen_condition: String,
    pub state_fence: StateFence,
}

impl Signal {
    /// Validates signal shape and provider evidence without assigning authority.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.rule_id, "rule_id")?;
        text(&self.subject, "subject")?;
        text(&self.scope_id, "scope_id")?;
        text(&self.dedup_key, "dedup_key")?;
        text(&self.reopen_condition, "reopen_condition")?;
        nonempty(&self.evidence_handles, "evidence_handles")?;
        fence(&self.state_fence)?;
        self.observed_at
            .validate()
            .map_err(|_| ProblemError::InvalidField {
                field: "observed_at",
                reason: "invalid clock interval",
            })?;
        let refs = self
            .evidence_handles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&refs, "evidence_handles")?;
        if let Some(observation) = &self.observation {
            observation.validate().map_err(ProblemError::Evidence)?;
            same_fence(&self.state_fence, &observation.evidence.state_fence)?;
        }
        Ok(())
    }

    /// Records delivery acknowledgement without changing semantic disposition.
    pub fn acknowledge(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.delivery_state == DeliveryState::Acknowledged {
            return Ok(());
        }
        self.delivery_state = DeliveryState::Acknowledged;
        Ok(())
    }

    /// Reopens processing after new evidence while retaining the signal identity.
    pub fn reopen(
        &mut self,
        expected_fence: &StateFence,
        new_evidence: Vec<ArtifactId>,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        nonempty(&new_evidence, "new_evidence")?;
        self.evidence_handles.extend(new_evidence);
        self.processing_state = SignalProcessingState::Investigating;
        self.disposition = SignalDisposition::ProblemCandidate;
        self.validate()
    }
}

/// Stable principal/generation used for owner and reassignment checks.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRef {
    pub principal: String,
    pub generation: String,
}

impl OwnerRef {
    /// Validates principal and owner generation.
    pub fn validate(&self) -> Result<(), ProblemError> {
        owner_name(&self.principal)?;
        text(&self.generation, "owner.generation")
    }
}

/// Problem lifecycle from opening through evidence-backed resolution.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProblemState {
    Open,
    Triaged,
    Diagnosing,
    Contained,
    Repairing,
    Verifying,
    Resolved,
    AcceptedRisk,
    Superseded,
    Quarantined,
}

impl ProblemState {
    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::Triaged)
                | (
                    Self::Triaged,
                    Self::Diagnosing | Self::Contained | Self::Repairing
                )
                | (
                    Self::Diagnosing,
                    Self::Contained | Self::Repairing | Self::Verifying
                )
                | (
                    Self::Contained,
                    Self::Repairing | Self::Verifying | Self::Quarantined
                )
                | (Self::Repairing, Self::Verifying | Self::Quarantined)
                | (
                    Self::Verifying,
                    Self::Resolved | Self::AcceptedRisk | Self::Quarantined
                )
                | (
                    Self::Resolved | Self::AcceptedRisk | Self::Superseded | Self::Quarantined,
                    Self::Superseded
                )
        )
    }
}

/// Durable operational/cognitive/integration/data-quality problem.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub problem_id: ProblemId,
    pub signal_refs: Vec<SignalId>,
    pub title: String,
    pub scope_id: String,
    pub owner: OwnerRef,
    pub state: ProblemState,
    pub evidence_refs: Vec<ArtifactId>,
    pub resolution_condition: String,
    pub acknowledged_by: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

impl Problem {
    /// Validates problem invariants and evidence identity.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.title, "title")?;
        text(&self.scope_id, "scope_id")?;
        text(&self.resolution_condition, "resolution_condition")?;
        self.owner.validate()?;
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        nonempty(&self.signal_refs, "signal_refs")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        let signals = self
            .signal_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&signals, "signal_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "evidence_refs")?;
        if let Some(principal) = &self.acknowledged_by {
            owner_name(principal)?;
        }
        Ok(())
    }

    /// Advances only along the declared Problem lifecycle.
    pub fn transition(
        &mut self,
        expected_fence: &StateFence,
        next: ProblemState,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !self.state.can_transition_to(next) {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        self.state = next;
        self.revision = self.revision.saturating_add(1);
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "revision overflow",
            });
        }
        Ok(())
    }

    /// Records receipt by the current owner; acknowledgement is not resolution.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        principal: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner_name(principal)?;
        if principal != self.owner.principal {
            return Err(ProblemError::OwnerMismatch);
        }
        match &self.acknowledged_by {
            Some(existing) if existing != principal => Err(ProblemError::AcknowledgementConflict),
            Some(_) => Ok(()),
            None => {
                self.acknowledged_by = Some(principal.to_owned());
                Ok(())
            }
        }
    }

    /// Changes owner only after comparing the current owner fence.
    pub fn reassign_owner(
        &mut self,
        expected_fence: &StateFence,
        owner: OwnerRef,
        new_fence: StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner.validate()?;
        same_fence(&new_fence, &new_fence)?;
        self.owner = owner;
        self.state_fence = new_fence;
        self.acknowledged_by = None;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Reopens a terminal problem only with new evidence and the current fence.
    pub fn reopen(
        &mut self,
        expected_fence: &StateFence,
        new_evidence: Vec<ArtifactId>,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !matches!(
            self.state,
            ProblemState::Resolved
                | ProblemState::AcceptedRisk
                | ProblemState::Superseded
                | ProblemState::Quarantined
        ) {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "OPEN".to_owned(),
            });
        }
        if new_evidence.is_empty() {
            return Err(ProblemError::ReopenRequiresEvidence);
        }
        self.evidence_refs.extend(new_evidence);
        self.state = ProblemState::Open;
        self.acknowledged_by = None;
        self.reopen_count = self.reopen_count.saturating_add(1);
        self.revision = self.revision.saturating_add(1);
        self.validate()
    }

    /// Returns whether evidence-backed terminal resolution was reached.
    pub const fn is_resolved(&self) -> bool {
        matches!(
            self.state,
            ProblemState::Resolved | ProblemState::AcceptedRisk | ProblemState::Superseded
        )
    }
}

/// Incident lifecycle for integrity, authority, security or dangerous effects.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentState {
    Candidate,
    Open,
    Contained,
    Investigating,
    Recovering,
    Verifying,
    Resolved,
    AcceptedRisk,
    Superseded,
}

/// Heavy Problem State with an independent incident lifecycle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub incident_id: IncidentId,
    pub title: String,
    pub scope_id: String,
    pub owner: OwnerRef,
    pub state: IncidentState,
    pub evidence_refs: Vec<ArtifactId>,
    pub acknowledged_by: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

impl Incident {
    /// Validates incident identity, ownership and evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.title, "title")?;
        text(&self.scope_id, "scope_id")?;
        self.owner.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Records acknowledgement without resolving the incident.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        principal: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner_name(principal)?;
        if principal != self.owner.principal {
            return Err(ProblemError::OwnerMismatch);
        }
        self.acknowledged_by = Some(principal.to_owned());
        Ok(())
    }

    /// Reopens a terminal incident with new evidence.
    pub fn reopen(
        &mut self,
        expected_fence: &StateFence,
        evidence: Vec<ArtifactId>,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !matches!(
            self.state,
            IncidentState::Resolved | IncidentState::AcceptedRisk | IncidentState::Superseded
        ) {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "OPEN".to_owned(),
            });
        }
        nonempty(&evidence, "new_evidence")?;
        self.evidence_refs.extend(evidence);
        self.state = IncidentState::Open;
        self.acknowledged_by = None;
        self.reopen_count = self.reopen_count.saturating_add(1);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// Conflict lifecycle; unresolved disagreement remains visible.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictState {
    Open,
    Triaged,
    Probing,
    Adjudicating,
    Resolved,
    AcceptedResidual,
    Superseded,
}

/// One rival interpretation retained for a Conflict.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalClaim {
    pub claim_ref: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub lineage_ref: String,
}

impl RivalClaim {
    /// Validates claim identity and evidence lineage.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.claim_ref, "claim_ref")?;
        text(&self.lineage_ref, "lineage_ref")?;
        nonempty(&self.evidence_refs, "rival.evidence_refs")
    }
}

/// Evidence-linked conflict set; agreement is not truth.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub conflict_id: ConflictId,
    pub subject: String,
    pub owner: OwnerRef,
    pub rival_claims: Vec<RivalClaim>,
    pub state: ConflictState,
    pub dissent: Vec<String>,
    pub decision_ref: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl Conflict {
    /// Validates rival evidence, dissent and state.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.subject, "subject")?;
        self.owner.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.rival_claims, "rival_claims")?;
        for claim in &self.rival_claims {
            claim.validate()?;
        }
        let claims = self
            .rival_claims
            .iter()
            .map(|claim| claim.claim_ref.clone())
            .collect::<Vec<_>>();
        unique_text(&claims, "rival_claims")?;
        unique_text(&self.dissent, "dissent")?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Adds a rival model while preserving current conflict state.
    pub fn add_rival(
        &mut self,
        expected_fence: &StateFence,
        rival: RivalClaim,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if matches!(
            self.state,
            ConflictState::Resolved | ConflictState::Superseded
        ) {
            return Err(ProblemError::ImmutableState);
        }
        rival.validate()?;
        if self
            .rival_claims
            .iter()
            .any(|claim| claim.claim_ref == rival.claim_ref)
        {
            return Err(ProblemError::Duplicate {
                field: "rival_claims",
                value: rival.claim_ref,
            });
        }
        self.rival_claims.push(rival);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Records a decision by the named owner; no vote tally is consulted.
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        decision_ref: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        text(decision_ref, "decision_ref")?;
        if self.state != ConflictState::Adjudicating {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "RESOLVED".to_owned(),
            });
        }
        self.decision_ref = Some(decision_ref.to_owned());
        self.state = ConflictState::Resolved;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Reopens a resolved conflict with a newly supplied rival/evidence line.
    pub fn reopen(
        &mut self,
        expected_fence: &StateFence,
        rival: RivalClaim,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !matches!(
            self.state,
            ConflictState::Resolved | ConflictState::AcceptedResidual | ConflictState::Superseded
        ) {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "OPEN".to_owned(),
            });
        }
        rival.validate()?;
        self.rival_claims.push(rival);
        self.state = ConflictState::Open;
        self.decision_ref = None;
        self.revision = self.revision.saturating_add(1);
        self.validate()
    }
}

/// Staged Concilium process from framing to owner decision and dissent.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConciliumStage {
    Framed,
    ObservationsSeparated,
    LineageMapped,
    ObjectionsGathered,
    RivalPredictions,
    ProbesSelected,
    TheoryUpdated,
    DecisionPending,
    Recorded,
}

/// Bounded comparison run; it is not a truth/authority oracle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConciliumRun {
    pub run_id: ConciliumRunId,
    pub conflict_id: ConflictId,
    pub stage: ConciliumStage,
    pub decision_owner: OwnerRef,
    pub participants: Vec<String>,
    pub evidence_refs: Vec<ArtifactId>,
    pub selected_probes: Vec<String>,
    pub dissent: Vec<String>,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl ConciliumRun {
    /// Validates bounded panel identity and dissent preservation.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.decision_owner.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.participants, "participants")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        unique_text(&self.participants, "participants")?;
        unique_text(&self.selected_probes, "selected_probes")?;
        unique_text(&self.dissent, "dissent")?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Advances exactly one Concilium stage.
    pub fn advance(
        &mut self,
        expected_fence: &StateFence,
        next: ConciliumStage,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        let legal = matches!(
            (self.stage, next),
            (
                ConciliumStage::Framed,
                ConciliumStage::ObservationsSeparated
            ) | (
                ConciliumStage::ObservationsSeparated,
                ConciliumStage::LineageMapped
            ) | (
                ConciliumStage::LineageMapped,
                ConciliumStage::ObjectionsGathered
            ) | (
                ConciliumStage::ObjectionsGathered,
                ConciliumStage::RivalPredictions
            ) | (
                ConciliumStage::RivalPredictions,
                ConciliumStage::ProbesSelected
            ) | (
                ConciliumStage::ProbesSelected,
                ConciliumStage::TheoryUpdated
            ) | (
                ConciliumStage::TheoryUpdated,
                ConciliumStage::DecisionPending
            ) | (ConciliumStage::DecisionPending, ConciliumStage::Recorded)
        );
        if !legal {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.stage),
                to: format!("{next:?}"),
            });
        }
        self.stage = next;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// Critical obligation state; delivery and resolution remain separate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionState {
    Active,
    Acknowledged,
    Escalated,
    Resolved,
    Waived,
    Superseded,
}

/// Persistent attention obligation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticalAttention {
    pub attention_id: AttentionId,
    pub obligation: String,
    pub affected_scope_actions: Vec<String>,
    pub evidence_refs: Vec<ArtifactId>,
    pub owner: OwnerRef,
    pub delivery_state: DeliveryState,
    pub state: AttentionState,
    pub review_condition: String,
    pub escalation_route: String,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl CriticalAttention {
    /// Validates that an attention is durable obligation state, not a toast.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.obligation, "obligation")?;
        text(&self.review_condition, "review_condition")?;
        text(&self.escalation_route, "escalation_route")?;
        self.owner.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.affected_scope_actions, "affected_scope_actions")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        unique_text(&self.affected_scope_actions, "affected_scope_actions")?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Acknowledges receipt while retaining an active obligation.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        principal: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner_name(principal)?;
        if principal != self.owner.principal {
            return Err(ProblemError::OwnerMismatch);
        }
        if self.state == AttentionState::Resolved {
            return Err(ProblemError::ImmutableState);
        }
        self.delivery_state = DeliveryState::Acknowledged;
        self.state = AttentionState::Acknowledged;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Resolves only with explicit evidence and a matching fence.
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        evidence_refs: Vec<ArtifactId>,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        nonempty(&evidence_refs, "resolution_evidence")?;
        self.evidence_refs.extend(evidence_refs);
        self.state = AttentionState::Resolved;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Reassigns delivery ownership without deleting the obligation.
    pub fn reassign_owner(
        &mut self,
        expected_fence: &StateFence,
        owner: OwnerRef,
        new_fence: StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner.validate()?;
        fence(&new_fence)?;
        self.owner = owner;
        self.state_fence = new_fence;
        self.delivery_state = DeliveryState::Pending;
        self.state = AttentionState::Active;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// A bounded recovery gap and its observable discriminator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGap {
    pub gap_id: String,
    pub description: String,
    pub discriminator: String,
}

impl RecoveryGap {
    /// Validates gap identity and discriminator.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.gap_id, "gap_id")?;
        text(&self.description, "description")?;
        text(&self.discriminator, "discriminator")
    }
}

/// Recovery acceptance profile owned by G-08.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryProfileState {
    Active,
    Satisfied,
    Superseded,
}

/// Deterministic current recovery invariant profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAcceptanceProfile {
    pub profile_id: RecoveryProfileId,
    pub objective_ref: String,
    pub invariant_gaps: Vec<RecoveryGap>,
    pub affected_owners: Vec<String>,
    pub discriminators: Vec<String>,
    pub enablement_condition: String,
    pub state: RecoveryProfileState,
    pub revision: u64,
    pub state_fence: StateFence,
}

impl RecoveryAcceptanceProfile {
    /// Validates profile completeness without declaring product success.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.objective_ref, "objective_ref")?;
        text(&self.enablement_condition, "enablement_condition")?;
        unique_text(&self.affected_owners, "affected_owners")?;
        unique_text(&self.discriminators, "discriminators")?;
        for gap in &self.invariant_gaps {
            gap.validate()?;
        }
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        if self.state == RecoveryProfileState::Satisfied && !self.invariant_gaps.is_empty() {
            return Err(ProblemError::InvalidField {
                field: "invariant_gaps",
                reason: "satisfied profile cannot retain unresolved gaps",
            });
        }
        Ok(())
    }

    /// Satisfies only an already gap-free profile.
    pub fn satisfy(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !self.invariant_gaps.is_empty() {
            return Err(ProblemError::InvalidField {
                field: "invariant_gaps",
                reason: "all gaps require evidence-backed closure",
            });
        }
        self.state = RecoveryProfileState::Satisfied;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// Normative class that determines whether a challenge is possible.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleClass {
    HardBoundary,
    Contract,
    Guardrail,
    Default,
    Experiment,
    Policy,
}

/// Challenge lifecycle; acceptance is not authority or finish.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeState {
    Proposed,
    UnderReview,
    Accepted,
    Rejected,
    Expired,
}

/// Evidence-backed challenge of an existing rule/default.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedChallenge {
    pub challenge_id: ChallengeId,
    pub from_rule: String,
    pub rule_class: RuleClass,
    pub scope: String,
    pub owner: OwnerRef,
    pub reason_and_evidence: Vec<ArtifactId>,
    pub expected_benefit: String,
    pub risk: String,
    pub rollback: String,
    pub review_condition: String,
    pub state: ChallengeState,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl GovernedChallenge {
    /// Validates challengeability and bounded rollback/review data.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.from_rule, "from_rule")?;
        text(&self.scope, "scope")?;
        text(&self.expected_benefit, "expected_benefit")?;
        text(&self.risk, "risk")?;
        text(&self.rollback, "rollback")?;
        text(&self.review_condition, "review_condition")?;
        self.owner.validate()?;
        nonempty(&self.reason_and_evidence, "reason_and_evidence")?;
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        if self.rule_class == RuleClass::HardBoundary {
            return Err(ProblemError::HardBoundaryImmutable);
        }
        Ok(())
    }

    /// Moves a challenge into bounded review.
    pub fn submit(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        self.validate()?;
        if self.state != ChallengeState::Proposed {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "UNDER_REVIEW".to_owned(),
            });
        }
        self.state = ChallengeState::UnderReview;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Accepts a reversible challenge; it does not grant implementation authority.
    pub fn accept(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state != ChallengeState::UnderReview {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "ACCEPTED".to_owned(),
            });
        }
        self.state = ChallengeState::Accepted;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Rejects an unaccepted challenge while retaining its evidence.
    pub fn reject(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if !matches!(
            self.state,
            ChallengeState::Proposed | ChallengeState::UnderReview
        ) {
            return Err(ProblemError::ImmutableState);
        }
        self.state = ChallengeState::Rejected;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// Implementation deviation lifecycle.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeviationState {
    Active,
    Promoted,
    Rejected,
    Expired,
}

/// Concrete recoverable implementation deviation; never a Hard Boundary bypass.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationDeviation {
    pub deviation_id: DeviationId,
    pub from_contract_or_default: String,
    pub rule_class: RuleClass,
    pub scope: String,
    pub owner: OwnerRef,
    pub reason_and_evidence: Vec<ArtifactId>,
    pub hard_boundaries_checked: Vec<String>,
    pub expected_benefit: String,
    pub risk: String,
    pub rollback: String,
    pub review_condition: String,
    pub outcome_ref: Option<String>,
    pub state: DeviationState,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl ImplementationDeviation {
    /// Validates bounded reversible deviation semantics.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.from_contract_or_default, "from_contract_or_default")?;
        text(&self.scope, "scope")?;
        self.owner.validate()?;
        nonempty(&self.reason_and_evidence, "reason_and_evidence")?;
        nonempty(&self.hard_boundaries_checked, "hard_boundaries_checked")?;
        unique_text(&self.hard_boundaries_checked, "hard_boundaries_checked")?;
        text(&self.expected_benefit, "expected_benefit")?;
        text(&self.risk, "risk")?;
        text(&self.rollback, "rollback")?;
        text(&self.review_condition, "review_condition")?;
        if let Some(outcome) = &self.outcome_ref {
            text(outcome, "outcome_ref")?;
        }
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        if self.rule_class == RuleClass::HardBoundary {
            return Err(ProblemError::HardBoundaryImmutable);
        }
        Ok(())
    }

    /// Promotes only an active deviation with explicit outcome evidence.
    pub fn promote(
        &mut self,
        expected_fence: &StateFence,
        outcome_ref: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        text(outcome_ref, "outcome_ref")?;
        if self.state != DeviationState::Active {
            return Err(ProblemError::ImmutableState);
        }
        self.outcome_ref = Some(outcome_ref.to_owned());
        self.state = DeviationState::Promoted;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Rejects an active deviation without deleting its evidence.
    pub fn reject(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state != DeviationState::Active {
            return Err(ProblemError::ImmutableState);
        }
        self.state = DeviationState::Rejected;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }
}

/// Returns a deterministic schema/provenance identity for the public surface.
pub fn contract_identity() -> Result<eliot_contracts::ContractIdentity, ProblemError> {
    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "signal": schemars::schema_for!(Signal),
            "problem": schemars::schema_for!(Problem),
            "incident": schemars::schema_for!(Incident),
            "conflict": schemars::schema_for!(Conflict),
            "concilium": schemars::schema_for!(ConciliumRun),
            "attention": schemars::schema_for!(CriticalAttention),
            "recovery": schemars::schema_for!(RecoveryAcceptanceProfile),
            "challenge": schemars::schema_for!(GovernedChallenge),
            "deviation": schemars::schema_for!(ImplementationDeviation),
        }),
    )
    .map_err(|_error| ProblemError::InvalidField {
        field: "contract_identity",
        reason: "serialization failed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn state_fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn owner() -> OwnerRef {
        OwnerRef {
            principal: "owner-1".to_owned(),
            generation: "generation-1".to_owned(),
        }
    }

    fn artifact(value: &str) -> Result<ArtifactId, ProblemError> {
        ArtifactId::new(value).map_err(|_| ProblemError::InvalidField {
            field: "artifact_id",
            reason: "invalid artifact id",
        })
    }

    fn problem() -> Result<Problem, ProblemError> {
        Ok(Problem {
            problem_id: ProblemId::new("problem-1")?,
            signal_refs: vec![SignalId::new("signal-1")?],
            title: "repeated failure".to_owned(),
            scope_id: "scope-1".to_owned(),
            owner: owner(),
            state: ProblemState::Open,
            evidence_refs: vec![artifact("evidence-1")?],
            resolution_condition: "verifier evidence".to_owned(),
            acknowledged_by: None,
            state_fence: state_fence(),
            revision: 1,
            reopen_count: 0,
        })
    }

    #[test]
    fn acknowledgement_is_not_resolution() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = problem()?;
        value.acknowledge(&fence, "owner-1")?;
        assert_eq!(value.acknowledged_by.as_deref(), Some("owner-1"));
        assert_eq!(value.state, ProblemState::Open);
        assert!(!value.is_resolved());
        Ok(())
    }

    #[test]
    fn resolved_problem_reopens_only_with_new_evidence() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = problem()?;
        value.transition(&fence, ProblemState::Triaged)?;
        value.transition(&fence, ProblemState::Diagnosing)?;
        value.transition(&fence, ProblemState::Verifying)?;
        value.transition(&fence, ProblemState::Resolved)?;
        assert!(matches!(
            value.reopen(&fence, Vec::new()),
            Err(ProblemError::ReopenRequiresEvidence)
        ));
        value.reopen(&fence, vec![artifact("evidence-2")?])?;
        assert_eq!(value.state, ProblemState::Open);
        assert_eq!(value.reopen_count, 1);
        assert_eq!(value.acknowledged_by, None);
        Ok(())
    }

    #[test]
    fn owner_reassignment_fences_old_owner() -> Result<(), ProblemError> {
        let old_fence = state_fence();
        let new_fence = StateFence::new(
            AuthorityEpoch::new(2).map_err(|_| ProblemError::InvalidField {
                field: "authority_epoch",
                reason: "invalid epoch",
            })?,
            ResourceGeneration::genesis(),
        );
        let mut value = problem()?;
        value.reassign_owner(&old_fence, owner(), new_fence.clone())?;
        assert!(matches!(
            value.acknowledge(&old_fence, "owner-1"),
            Err(ProblemError::FenceMismatch)
        ));
        value.acknowledge(&new_fence, "owner-1")?;
        Ok(())
    }

    #[test]
    fn hard_boundary_challenge_is_rejected() -> Result<(), ProblemError> {
        let challenge = GovernedChallenge {
            challenge_id: ChallengeId::new("challenge-1")?,
            from_rule: "ARCH-SEC-01".to_owned(),
            rule_class: RuleClass::HardBoundary,
            scope: "scope-1".to_owned(),
            owner: owner(),
            reason_and_evidence: vec![artifact("evidence-1")?],
            expected_benefit: "none".to_owned(),
            risk: "authority bypass".to_owned(),
            rollback: "discard".to_owned(),
            review_condition: "human review".to_owned(),
            state: ChallengeState::Proposed,
            state_fence: state_fence(),
            revision: 1,
        };
        assert!(matches!(
            challenge.validate(),
            Err(ProblemError::HardBoundaryImmutable)
        ));
        Ok(())
    }
}
