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
    /// Closure evidence was presented by the record's own owner.
    #[error("closure requires an independent verifier")]
    VerifierNotIndependent,
    /// A waiver was presented without the recorded waiver authority.
    #[error("waiver requires the recorded waiver authority")]
    WaiverNotAuthorized,
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

/// Advances a record revision, refusing overflow instead of reusing one.
///
/// A saturating bump pins a live record to the revision that already names its
/// current committed state, so the transition is refused and the caller must
/// re-read the record rather than write a reused identity.
fn next_revision(current: u64) -> Result<u64, ProblemError> {
    current.checked_add(1).ok_or(ProblemError::InvalidField {
        field: "revision",
        reason: "revision overflow",
    })
}

/// Advances the reopen counter under the same no-reuse rule as the revision.
fn next_reopen_count(current: u32) -> Result<u32, ProblemError> {
    current.checked_add(1).ok_or(ProblemError::InvalidField {
        field: "reopen_count",
        reason: "reopen_count overflow",
    })
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
    NextBoundaryPending,
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

/// Bounded revocation-driven quarantine request for incomplete lineage (I12.20 S4).
///
/// Carries exactly the bounded impacted scope plus the revocation evidence.
/// The scope set is consumed verbatim: it is never expanded by similarity,
/// and an empty scope is rejected so a caller cannot launder a whole-memory
/// purge through this entry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationQuarantine {
    pub impacted_scopes: Vec<String>,
    pub revocation_evidence: Vec<ArtifactId>,
    pub revoked_source_ref: String,
    pub rebuild_condition: String,
}

impl RevocationQuarantine {
    /// Validates the bounded scope, revocation evidence and rebuild requirement.
    pub fn validate(&self) -> Result<(), ProblemError> {
        nonempty(&self.impacted_scopes, "impacted_scopes")?;
        unique_text(&self.impacted_scopes, "impacted_scopes")?;
        nonempty(&self.revocation_evidence, "revocation_evidence")?;
        let evidence = self
            .revocation_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "revocation_evidence")?;
        text(&self.revoked_source_ref, "revoked_source_ref")?;
        text(&self.rebuild_condition, "rebuild_condition")
    }
}

/// Typed rebuild-from-clean-inputs requirement emitted by the revocation
/// quarantine entry (I12.20 S1).
///
/// This crate owns typed transitions only and never persists records: the
/// caller persists this order alongside the quarantined `Problem`, whose
/// `evidence_refs` retain the revocation evidence. The quarantined record is
/// rebuilt from clean inputs satisfying `rebuild_condition`, never from the
/// revoked source. `validate` re-checks a reloaded order at the caller
/// boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRebuildOrder {
    pub problem_id: ProblemId,
    pub impacted_scopes: Vec<String>,
    pub revoked_source_ref: String,
    pub rebuild_condition: String,
    pub revocation_evidence: Vec<ArtifactId>,
}

impl RevocationRebuildOrder {
    /// Validates the recorded rebuild requirement.
    pub fn validate(&self) -> Result<(), ProblemError> {
        nonempty(&self.impacted_scopes, "impacted_scopes")?;
        unique_text(&self.impacted_scopes, "impacted_scopes")?;
        nonempty(&self.revocation_evidence, "revocation_evidence")?;
        let evidence = self
            .revocation_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "revocation_evidence")?;
        text(&self.revoked_source_ref, "revoked_source_ref")?;
        text(&self.rebuild_condition, "rebuild_condition")
    }
}

/// I13.9 problem class, from the closed registry vocabulary.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemClass {
    Operational,
    Integration,
    Cognitive,
    DataQuality,
    Security,
    Cost,
}

/// One evidence-backed repair attempt retained in `repair_history`.
///
/// A repair outcome is only ever recorded together with the evidence handles
/// that support it, so "repair succeeded" is never a bare claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairRecord {
    pub attempt: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl RepairRecord {
    /// Validates the attempt text and its supporting evidence handles.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.attempt, "repair_history.attempt")?;
        nonempty(&self.evidence_refs, "repair_history.evidence_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "repair_history.evidence_refs")
    }
}

/// One evidenced reopen retained in `reopen_history`.
///
/// The reopen counter alone is not reopen evidence: each retained entry names
/// the revision it reopened and the evidence that justified it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenRecord {
    pub revision: u64,
    pub evidence_refs: Vec<ArtifactId>,
}

impl ReopenRecord {
    /// Validates the reopened revision and its justifying evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "reopen_history.revision",
                reason: "must be non-zero",
            });
        }
        nonempty(&self.evidence_refs, "reopen_history.evidence_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "reopen_history.evidence_refs")
    }
}

/// The single outstanding obligation produced when a `Problem` loses its owner.
///
/// Produced by [`Problem::owner_loss`] so the caller persists exactly one
/// reassignment/escalation obligation instead of rebuilding one from the
/// cleared record. An unassigned `Problem` is not resolved, accepted risk or
/// discardable while this obligation is outstanding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReassignmentObligation {
    pub problem_id: ProblemId,
    pub lost_owner: OwnerRef,
    pub loss_evidence: Vec<ArtifactId>,
}

impl ReassignmentObligation {
    /// Validates the obligation identity, former owner and loss evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.lost_owner.validate()?;
        nonempty(&self.loss_evidence, "loss_evidence")?;
        let evidence = self
            .loss_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "loss_evidence")
    }
}

/// Durable operational/cognitive/integration/data-quality problem.
///
/// `owner` is `None` for the explicit I13.9 `unassigned` state reached through
/// [`Problem::owner_loss`]; it is never a placeholder principal. The live
/// lease/epoch binding of an assigned owner is the record's `state_fence`, so
/// `owner` plus `state_fence` carry the I13.9 `owner_and_epoch` field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub problem_id: ProblemId,
    pub signal_refs: Vec<SignalId>,
    pub title: String,
    pub class: ProblemClass,
    pub severity: SignalSeverity,
    pub scope_id: String,
    pub affected_dependencies: Vec<String>,
    pub symptom: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub hypotheses: Vec<String>,
    pub owner: Option<OwnerRef>,
    pub containment: Option<String>,
    pub repair_history: Vec<RepairRecord>,
    pub next_probe: Option<String>,
    pub resolution_condition: String,
    pub state: ProblemState,
    pub acknowledged_by: Option<String>,
    pub reopen_history: Vec<ReopenRecord>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

impl Problem {
    /// Validates problem invariants, evidence identity and retained history.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.title, "title")?;
        text(&self.scope_id, "scope_id")?;
        text(&self.symptom, "symptom")?;
        text(&self.resolution_condition, "resolution_condition")?;
        if let Some(owner) = &self.owner {
            owner.validate()?;
        }
        if let Some(containment) = &self.containment {
            text(containment, "containment")?;
        }
        if let Some(probe) = &self.next_probe {
            text(probe, "next_probe")?;
        }
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        nonempty(&self.signal_refs, "signal_refs")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        nonempty(&self.affected_dependencies, "affected_dependencies")?;
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
        unique_text(&self.affected_dependencies, "affected_dependencies")?;
        unique_text(&self.hypotheses, "hypotheses")?;
        for record in &self.repair_history {
            record.validate()?;
        }
        for record in &self.reopen_history {
            record.validate()?;
        }
        let reopened = self
            .reopen_history
            .iter()
            .map(|record| record.revision.to_string())
            .collect::<Vec<_>>();
        unique_text(&reopened, "reopen_history.revision")?;
        if u64::try_from(self.reopen_history.len()).unwrap_or(u64::MAX)
            != u64::from(self.reopen_count)
        {
            return Err(ProblemError::InvalidField {
                field: "reopen_history",
                reason: "retained reopen history must match reopen_count",
            });
        }
        if let Some(principal) = &self.acknowledged_by {
            owner_name(principal)?;
        }
        Ok(())
    }

    /// Returns whether the record currently has a live assigned owner.
    pub const fn is_assigned(&self) -> bool {
        self.owner.is_some()
    }

    /// Advances only along the declared Problem lifecycle.
    ///
    /// The candidate state is validated on a copy, so a rejected edge or a
    /// refused revision leaves the live record exactly as it was.
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
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.state = next;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records receipt by the current owner; acknowledgement is not resolution.
    ///
    /// An unassigned record has no principal that may acknowledge it, so owner
    /// loss leaves the obligation visible instead of silently acknowledged.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        principal: &str,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner_name(principal)?;
        if self.owner.as_ref().map(OwnerRef::principal.as_str()) != Some(principal) {
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

    /// Changes owner only after comparing the caller's fence against the live one.
    ///
    /// `expected_fence` is the fence the caller believes is current; it is
    /// compared against the record's live fence and a mismatch is refused, so a
    /// renewed or already-reassigned record cannot be fenced by a stale caller.
    /// `new_fence` is the successor authority fence and must be structurally
    /// valid. Its authority epoch must be a newly issued direct child of the
    /// record's current authority epoch: a successor is installed under a
    /// fresh ownership epoch, so equality of caller-provided principal and
    /// generation strings cannot stand in for that issuance. The successor is
    /// built and validated as a candidate, so a refused reassignment leaves the
    /// live record untouched.
    pub fn reassign_owner(
        &mut self,
        expected_fence: &StateFence,
        owner: OwnerRef,
        new_fence: StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner.validate()?;
        fence(&new_fence)?;
        if !new_fence
            .authority_epoch
            .is_direct_child_of(&self.state_fence.authority_epoch)
        {
            return Err(ProblemError::InvalidField {
                field: "state_fence.authority_epoch",
                reason: "successor requires a newly issued ownership epoch",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.owner = Some(owner);
        candidate.state_fence = new_fence;
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Clears the expired assignment under a fenced owner-loss event.
    ///
    /// The caller presents the fence it believes is current; it is compared
    /// against the record's live fence, so a delayed expiry carrying a
    /// superseded fence cannot unassign a lease that has already been renewed
    /// to a successor. The unresolved phase, evidence, hypotheses, containment,
    /// repair history and reopen history are all retained, and the single
    /// outstanding [`ReassignmentObligation`] is returned for the caller to
    /// persist. A terminal record is left byte-identical: a former owner
    /// disappearing never reopens an already terminal Problem.
    pub fn owner_loss(
        &mut self,
        expected_fence: &StateFence,
        loss_evidence: Vec<ArtifactId>,
    ) -> Result<Option<ReassignmentObligation>, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        nonempty(&loss_evidence, "loss_evidence")?;
        let evidence = loss_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "loss_evidence")?;
        let Some(lost_owner) = self.owner.clone() else {
            return Ok(None);
        };
        if self.is_resolved() || matches!(self.state, ProblemState::Quarantined) {
            return Ok(None);
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.owner = None;
        candidate.acknowledged_by = None;
        for reference in &loss_evidence {
            if !candidate.evidence_refs.contains(reference) {
                candidate.evidence_refs.push(reference.clone());
            }
        }
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(Some(ReassignmentObligation {
            problem_id: self.problem_id.clone(),
            lost_owner,
            loss_evidence,
        }))
    }

    /// Reopens a terminal problem only with new evidence and the current fence.
    ///
    /// The reopened record is built as a candidate and validated before it is
    /// committed, so a refused reopen leaves the terminal record unchanged.
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
        let revision = next_revision(self.revision)?;
        let reopen_count = next_reopen_count(self.reopen_count)?;
        let mut candidate = self.clone();
        candidate.evidence_refs.extend(new_evidence.iter().cloned());
        candidate.reopen_history.push(ReopenRecord {
            revision,
            evidence_refs: new_evidence,
        });
        candidate.state = ProblemState::Open;
        candidate.acknowledged_by = None;
        candidate.reopen_count = reopen_count;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Returns whether evidence-backed terminal resolution was reached.
    pub const fn is_resolved(&self) -> bool {
        matches!(
            self.state,
            ProblemState::Resolved | ProblemState::AcceptedRisk | ProblemState::Superseded
        )
    }

    /// Revocation-driven quarantine entry for incomplete lineage (I12.20 S4).
    ///
    /// Given a bounded impacted scope plus revocation evidence, quarantines
    /// exactly that bounded scope: the record's own `scope_id` must already
    /// lie inside `request.impacted_scopes`, and the passed set is consumed
    /// verbatim — never expanded by similarity and never replaced by a
    /// whole-memory purge. A terminal record is opened through the existing
    /// `reopen` entry (which still requires not-yet-attached revocation
    /// evidence); an active record is reused with deduplicated revocation
    /// evidence attached and its acknowledgement cleared. The record moves to
    /// `Quarantined` and the typed rebuild-from-clean-inputs requirement
    /// (I12.20 S1) is returned for the caller to persist alongside it.
    /// `transition` and `reopen` are unchanged for non-revocation paths.
    /// The quarantined record is assembled and validated as a candidate, so a
    /// refused entry leaves the live record unchanged.
    pub fn open_for_revocation(
        &mut self,
        expected_fence: &StateFence,
        request: &RevocationQuarantine,
    ) -> Result<RevocationRebuildOrder, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        request.validate()?;
        if !request.impacted_scopes.contains(&self.scope_id) {
            return Err(ProblemError::InvalidField {
                field: "impacted_scopes",
                reason: "problem scope lies outside the bounded revocation scope",
            });
        }
        let mut candidate = self.clone();
        if matches!(
            self.state,
            ProblemState::Resolved
                | ProblemState::AcceptedRisk
                | ProblemState::Superseded
                | ProblemState::Quarantined
        ) {
            let fresh = request
                .revocation_evidence
                .iter()
                .filter(|evidence| !self.evidence_refs.contains(evidence))
                .cloned()
                .collect::<Vec<_>>();
            if fresh.is_empty() {
                return Err(ProblemError::ReopenRequiresEvidence);
            }
            candidate.reopen(expected_fence, fresh)?;
        } else {
            for evidence in &request.revocation_evidence {
                if !candidate.evidence_refs.contains(evidence) {
                    candidate.evidence_refs.push(evidence.clone());
                }
            }
            candidate.acknowledged_by = None;
        }
        candidate.revision = next_revision(candidate.revision)?;
        candidate.state = ProblemState::Quarantined;
        candidate.validate()?;
        *self = candidate;
        Ok(RevocationRebuildOrder {
            problem_id: self.problem_id.clone(),
            impacted_scopes: request.impacted_scopes.clone(),
            revoked_source_ref: request.revoked_source_ref.clone(),
            rebuild_condition: request.rebuild_condition.clone(),
            revocation_evidence: request.revocation_evidence.clone(),
        })
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

/// The closed I13.10 promotion reasons, in the document's own order.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentReason {
    CanonicalIntegrityOrAuthorityCompromised,
    SecretPrivacyOrSecurityBreach,
    CriticalTelemetryOrControlPathLost,
    UnknownMaterialOrCriticalExternalEffect,
    PersistentBlockingWithUnsafeContinuation,
    StructuralCorruption,
    ControlReserveOrLastResortPathExhausted,
}

/// The admitted authority for an Incident promotion.
///
/// There is no variant for a model opinion, a `Signal` labelled
/// `IncidentCandidate`, or a repair/notification/score claim: a promotion can
/// only carry current deterministic policy evidence or an authorized Human
/// decision, so a model-only recommendation cannot open an Incident.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentPromotion {
    pub reason: IncidentReason,
    pub policy_ref: String,
    pub evidence_refs: Vec<ArtifactId>,
    pub source_problem: ProblemId,
    pub source_problem_revision: u64,
    pub human_authority: Option<String>,
}

impl IncidentPromotion {
    /// Validates that the promotion names one closed reason, its exact receipt
    /// and the source Problem revision it was decided against.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.policy_ref, "policy_ref")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "evidence_refs")?;
        if self.source_problem_revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "source_problem_revision",
                reason: "must be non-zero",
            });
        }
        if let Some(authority) = &self.human_authority {
            owner_name(authority)?;
        }
        Ok(())
    }
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
    pub reason: Option<IncidentReason>,
    pub source_problem: Option<ProblemId>,
    pub promotion_evidence: Vec<ArtifactId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub acknowledged_by: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

impl Incident {
    /// Validates incident identity, ownership and evidence.
    ///
    /// A committed promotion must retain the closed reason, the source Problem
    /// link and the exact evidence handles the decision was made on; a record
    /// in `Candidate` carries none of them, so a model recommendation can be
    /// reviewed without ever looking like a committed Incident.
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
        let promoted = self.state != IncidentState::Candidate;
        if promoted {
            if self.reason.is_none() {
                return Err(ProblemError::InvalidField {
                    field: "reason",
                    reason: "a promoted incident must retain its closed reason",
                });
            }
            if self.source_problem.is_none() {
                return Err(ProblemError::InvalidField {
                    field: "source_problem",
                    reason: "a promoted incident must retain its source Problem link",
                });
            }
            nonempty(&self.promotion_evidence, "promotion_evidence")?;
            let promotion = self
                .promotion_evidence
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            unique_text(&promotion, "promotion_evidence")?;
        } else if self.reason.is_some() || self.source_problem.is_some() {
            return Err(ProblemError::InvalidField {
                field: "reason",
                reason: "a candidate must not carry a committed promotion reason",
            });
        }
        Ok(())
    }

    /// Commits an Incident promotion against the current source Problem.
    ///
    /// The promotion is refused unless the caller presents a closed
    /// [`IncidentReason`] with its own receipt, and the named source Problem is
    /// the record being promoted at exactly the revision the decision was made
    /// against. A `Signal` alone is not an input here, so a model-only
    /// recommendation cannot reach `Open` through this path. Semantic
    /// contamination is not a structural reason, so a wrong interpretation
    /// cannot justify the restore or global shutdown that
    /// `StructuralCorruption` authorises.
    pub fn promote(
        &mut self,
        expected_fence: &StateFence,
        source: &Problem,
        promotion: &IncidentPromotion,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        promotion.validate()?;
        source.validate()?;
        if &promotion.source_problem != &source.problem_id {
            return Err(ProblemError::InvalidField {
                field: "source_problem",
                reason: "promotion names a different source Problem",
            });
        }
        if promotion.source_problem_revision != source.revision {
            return Err(ProblemError::InvalidField {
                field: "source_problem_revision",
                reason: "promotion was decided against a different source revision",
            });
        }
        if self.state != IncidentState::Candidate {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "OPEN".to_owned(),
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.state = IncidentState::Open;
        candidate.reason = Some(promotion.reason);
        candidate.source_problem = Some(source.problem_id.clone());
        candidate.promotion_evidence = promotion.evidence_refs.clone();
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
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
        let revision = next_revision(self.revision)?;
        let reopen_count = next_reopen_count(self.reopen_count)?;
        let mut candidate = self.clone();
        for reference in &evidence {
            if !candidate.evidence_refs.contains(reference) {
                candidate.evidence_refs.push(reference.clone());
            }
        }
        candidate.state = IncidentState::Open;
        candidate.acknowledged_by = None;
        candidate.reopen_count = reopen_count;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
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

/// The closed I13.8 attention kinds that select a default owner role.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionKind {
    TaskIssue,
    SecurityIntegrity,
    ArchitectureGap,
    VerifierEvidenceGap,
    ModuleHealth,
    Budget,
}

/// The closed I13.8 owner roles an attention kind can route to.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRole {
    TaskController,
    SystemOwner,
    RecoveryPrincipal,
    ArchitectureOwner,
    WorkScopeOwner,
    ModuleOwner,
    Doctor,
    Requester,
}

impl AttentionKind {
    /// Returns the default owner roles for this kind, in the I13.8 order.
    ///
    /// Roles are resolved against actual eligible actors by
    /// [`AttentionKind::route_to`]; no principal name is hardcoded here.
    pub const fn default_owner_roles(self) -> &'static [OwnerRole] {
        match self {
            Self::TaskIssue => &[OwnerRole::TaskController],
            Self::SecurityIntegrity => &[OwnerRole::SystemOwner, OwnerRole::RecoveryPrincipal],
            Self::ArchitectureGap => &[OwnerRole::ArchitectureOwner],
            Self::VerifierEvidenceGap => &[OwnerRole::WorkScopeOwner, OwnerRole::TaskController],
            Self::ModuleHealth => &[OwnerRole::ModuleOwner, OwnerRole::Doctor],
            Self::Budget => &[OwnerRole::Requester, OwnerRole::SystemOwner],
        }
    }

    /// Resolves the first eligible actor holding a default role for this kind.
    ///
    /// Eligibility is decided by the caller-supplied lease roster, so a retired
    /// or unleased actor is never selected. Returns `None` when no eligible
    /// actor holds a default role, which leaves the record unassigned for
    /// escalation through the admitted critical-attention route.
    pub fn route_to(&self, roster: &[EligibleOwner]) -> Option<OwnerRef> {
        if roster.iter().any(|candidate| candidate.validate().is_err()) {
            return None;
        }
        self.default_owner_roles().iter().find_map(|role| {
            roster
                .iter()
                .find(|candidate| candidate.role == *role && candidate.eligible)
                .map(|candidate| candidate.owner.clone())
        })
    }
}

/// One leased actor the routing table may select.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleOwner {
    pub owner: OwnerRef,
    pub role: OwnerRole,
    pub eligible: bool,
}

impl EligibleOwner {
    /// Validates the owner reference of a roster entry.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.owner.validate()
    }
}

/// The independent closure evidence a `CriticalAttention` resolution needs.
///
/// The verifier must be a principal distinct from the obligation's current
/// owner, so the owner cannot verify its own closure, and the expected
/// observable must match the obligation's recorded resolution condition
/// exactly: unrelated evidence for a different condition does not close it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureEvidence {
    pub expected_observable: String,
    pub subject_version: String,
    pub verifier: String,
    pub evidence_refs: Vec<ArtifactId>,
}

impl ClosureEvidence {
    /// Validates the observable, subject version, verifier and readback handles.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.expected_observable, "expected_observable")?;
        text(&self.subject_version, "subject_version")?;
        owner_name(&self.verifier)?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "evidence_refs")
    }
}

/// A scoped, authorized waiver with its expiry and residual risk.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverRecord {
    pub authority: String,
    pub limits: Vec<String>,
    pub expires_at_ms: i64,
    pub residual_risk: String,
}

impl WaiverRecord {
    /// Validates the waiver authority, its explicit limits, expiry and the
    /// residual risk the waiver leaves behind.
    pub fn validate(&self) -> Result<(), ProblemError> {
        owner_name(&self.authority)?;
        nonempty(&self.limits, "limits")?;
        unique_text(&self.limits, "limits")?;
        text(&self.residual_risk, "residual_risk")?;
        if self.expires_at_ms <= 0 {
            return Err(ProblemError::InvalidField {
                field: "expires_at_ms",
                reason: "waiver expiry must be a positive timestamp",
            });
        }
        Ok(())
    }
}

/// A supersession pointing at the accepted replacement obligation.
///
/// The replacement must exist, must not be this obligation, and must not be
/// terminal, so blocking cannot disappear into a cycle or a nonexistent id.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersessionRecord {
    pub replacement: AttentionId,
    pub accepted: bool,
    pub evidence_refs: Vec<ArtifactId>,
}

impl SupersessionRecord {
    /// Validates that a replacement obligation is named with acceptance evidence.
    pub fn validate(&self, self_id: &AttentionId) -> Result<(), ProblemError> {
        if &self.replacement == self_id {
            return Err(ProblemError::InvalidField {
                field: "replacement",
                reason: "an obligation cannot supersede itself",
            });
        }
        if !self.accepted {
            return Err(ProblemError::InvalidField {
                field: "accepted",
                reason: "supersession requires an accepted replacement obligation",
            });
        }
        nonempty(&self.evidence_refs, "evidence_refs")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "evidence_refs")
    }
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
    pub resolution_condition: String,
    pub waiver_authority: String,
    pub escalation_route: String,
    pub waiver: Option<WaiverRecord>,
    pub supersession: Option<SupersessionRecord>,
    pub state_fence: StateFence,
    pub revision: u64,
}

impl CriticalAttention {
    /// Validates that an attention is durable obligation state, not a toast.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.obligation, "obligation")?;
        text(&self.review_condition, "review_condition")?;
        text(&self.resolution_condition, "resolution_condition")?;
        text(&self.escalation_route, "escalation_route")?;
        owner_name(&self.waiver_authority)?;
        self.owner.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.affected_scope_actions, "affected_scope_actions")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        unique_text(&self.affected_scope_actions, "affected_scope_actions")?;
        if let Some(waiver) = &self.waiver {
            waiver.validate()?;
            if waiver.authority != self.waiver_authority {
                return Err(ProblemError::WaiverNotAuthorized);
            }
        }
        if let Some(supersession) = &self.supersession {
            supersession.validate(&self.attention_id)?;
        }
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }

    /// Creates a durable obligation in `Active` state with pending delivery.
    ///
    /// Creation is the first append-only transition: the record starts at
    /// revision 1 carrying the caller's owner, scope, evidence, review
    /// condition, escalation route and State Fence. No later transition
    /// erases the obligation or its evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attention_id: AttentionId,
        obligation: String,
        affected_scope_actions: Vec<String>,
        evidence_refs: Vec<ArtifactId>,
        owner: OwnerRef,
        review_condition: String,
        resolution_condition: String,
        waiver_authority: String,
        escalation_route: String,
        state_fence: StateFence,
    ) -> Result<Self, ProblemError> {
        let value = Self {
            attention_id,
            obligation,
            affected_scope_actions,
            evidence_refs,
            owner,
            delivery_state: DeliveryState::Pending,
            state: AttentionState::Active,
            review_condition,
            resolution_condition,
            waiver_authority,
            escalation_route,
            waiver: None,
            supersession: None,
            state_fence,
            revision: 1,
        };
        value.validate()?;
        Ok(value)
    }

    /// Acknowledges receipt while retaining an active obligation.
    ///
    /// Acknowledgement records delivery only: the blocking action set, the
    /// resolution condition and the evidence all stay in place, and a terminal
    /// obligation is never reactivated by a late acknowledgement.
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
        match self.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        if self.delivery_state == DeliveryState::Acknowledged {
            return Ok(());
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.delivery_state = DeliveryState::Acknowledged;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records that host-event push is unavailable and delivery must wait for
    /// the next available boundary, without changing the obligation state.
    pub fn defer_until_next_boundary(
        &mut self,
        expected_fence: &StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        match self.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        if self.delivery_state == DeliveryState::NextBoundaryPending {
            return Ok(());
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.delivery_state = DeliveryState::NextBoundaryPending;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Resolves only against the exact expected observable and an independent
    /// verifier, under a matching fence.
    ///
    /// Delivery and acknowledgement never reach this path: the caller must
    /// present closure evidence naming the obligation's own
    /// `resolution_condition` and a verifier that is not the current owner, so
    /// unrelated evidence and owner self-certification both reject. The blocking
    /// action set is retained on the terminal record rather than cleared.
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        closure: &ClosureEvidence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        closure.validate()?;
        if closure.expected_observable != self.resolution_condition {
            return Err(ProblemError::ResolutionRequiresEvidence);
        }
        if closure.verifier == self.owner.principal {
            return Err(ProblemError::VerifierNotIndependent);
        }
        match self.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        for reference in &closure.evidence_refs {
            if !candidate.evidence_refs.contains(reference) {
                candidate.evidence_refs.push(reference.clone());
            }
        }
        candidate.state = AttentionState::Resolved;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Reassigns delivery ownership without deleting the obligation.
    ///
    /// The successor is installed under a newly issued ownership epoch: the
    /// new fence's authority epoch must be a direct child of the current one, so
    /// a caller cannot re-present the current lease. A terminal obligation is
    /// never reassigned, so owner movement cannot reactivate it.
    pub fn reassign_owner(
        &mut self,
        expected_fence: &StateFence,
        owner: OwnerRef,
        new_fence: StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner.validate()?;
        fence(&new_fence)?;
        if !new_fence
            .authority_epoch
            .is_direct_child_of(&self.state_fence.authority_epoch)
        {
            return Err(ProblemError::InvalidField {
                field: "state_fence.authority_epoch",
                reason: "successor requires a newly issued ownership epoch",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        match candidate.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Escalated => {}
            AttentionState::Active | AttentionState::Acknowledged => {
                candidate.state = AttentionState::Active;
            }
        }
        candidate.owner = owner;
        candidate.state_fence = new_fence;
        candidate.delivery_state = DeliveryState::Pending;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records an authorized waiver: only the recorded `waiver_authority` may
    /// waive, not merely the delivery owner, and the obligation with its
    /// evidence and blocking action set is retained as terminal.
    ///
    /// A waiver without the record's own recorded authority is refused, so an
    /// owner cannot waive its own blocking obligation. The recorded limits,
    /// expiry and residual risk travel with the terminal state.
    pub fn waive(
        &mut self,
        expected_fence: &StateFence,
        waiver: &WaiverRecord,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        waiver.validate()?;
        if waiver.authority != self.waiver_authority {
            return Err(ProblemError::WaiverNotAuthorized);
        }
        match self.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.waiver = Some(waiver.clone());
        candidate.state = AttentionState::Waived;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records supersession against the accepted replacement obligation.
    ///
    /// The replacement is checked against the caller-supplied live obligation
    /// set: it must exist, must not be this obligation (no self-cycle) and must
    /// not itself be a terminal obligation, so blocking cannot disappear into a
    /// cycle or a nonexistent id. The superseded obligation is retained with
    /// its evidence and blocking action set.
    pub fn supersede(
        &mut self,
        expected_fence: &StateFence,
        principal: &str,
        supersession: &SupersessionRecord,
        live: &[CriticalAttention],
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner_name(principal)?;
        if principal != self.owner.principal {
            return Err(ProblemError::OwnerMismatch);
        }
        supersession.validate(&self.attention_id)?;
        let replacement = live
            .iter()
            .find(|candidate| candidate.attention_id == supersession.replacement)
            .ok_or(ProblemError::InvalidField {
                field: "replacement",
                reason: "replacement obligation does not exist",
            })?;
        if matches!(
            replacement.state,
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded
        ) {
            return Err(ProblemError::InvalidField {
                field: "replacement",
                reason: "replacement obligation is not an open accepted obligation",
            });
        }
        match self.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        for reference in &supersession.evidence_refs {
            if !candidate.evidence_refs.contains(reference) {
                candidate.evidence_refs.push(reference.clone());
            }
        }
        candidate.supersession = Some(supersession.clone());
        candidate.state = AttentionState::Superseded;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Applies review-condition expiry: the obligation escalates via the
    /// recorded route to a new owner and fence, retaining the prior obligation
    /// and evidence. The record remains inspectable; expiry never deletes it.
    pub fn expire(
        &mut self,
        expected_fence: &StateFence,
        owner: OwnerRef,
        new_fence: StateFence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        owner.validate()?;
        fence(&new_fence)?;
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        match candidate.state {
            AttentionState::Resolved | AttentionState::Waived | AttentionState::Superseded => {
                return Err(ProblemError::ImmutableState);
            }
            AttentionState::Active | AttentionState::Acknowledged | AttentionState::Escalated => {}
        }
        candidate.owner = owner;
        candidate.state_fence = new_fence;
        candidate.delivery_state = DeliveryState::Pending;
        candidate.state = AttentionState::Escalated;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

/// The I13.11 Diagnostic Brief compiled from one canonical `Problem`.
///
/// Every section is a retained field or an exact handle of the record, and the
/// unknowns are named explicitly, so a reader receives a problem model with
/// exact evidence handles rather than a title with raw logs attached. The
/// brief carries no log content and no model summary: `hypotheses` are the
/// record's own unverified explanations and `unknowns` is the derived list of
/// what the record does not yet establish.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBrief {
    pub problem_id: ProblemId,
    pub title: String,
    pub class: ProblemClass,
    pub severity: SignalSeverity,
    pub state: ProblemState,
    pub revision: u64,
    pub scope_id: String,
    pub symptom: String,
    pub affected_dependencies: Vec<String>,
    pub owner: Option<OwnerRef>,
    pub containment: Option<String>,
    pub evidence_handles: Vec<ArtifactId>,
    pub hypotheses: Vec<String>,
    pub repair_history: Vec<RepairRecord>,
    pub reopen_history: Vec<ReopenRecord>,
    pub next_probe: Option<String>,
    pub resolution_condition: String,
    pub unknowns: Vec<String>,
}

impl DiagnosticBrief {
    /// Compiles the brief from the canonical `Problem` it was read from.
    ///
    /// The result resolves to the same record that produced it: the problem
    /// identity, revision and fence-scoped content come from the record itself,
    /// so a read after restart rebuilds an identical brief.
    pub fn compile(problem: &Problem) -> Result<Self, ProblemError> {
        problem.validate()?;
        let mut unknowns = problem.hypotheses.clone();
        if problem.affected_dependencies.is_empty() {
            unknowns.push("affected dependencies are not yet established".to_owned());
        }
        if problem.next_probe.is_none() {
            unknowns.push("no next discriminative probe is recorded".to_owned());
        }
        if problem.owner.is_none() {
            unknowns.push("ownership is unassigned and awaiting reassignment".to_owned());
        }
        if !problem.is_resolved() {
            unknowns.push(format!(
                "resolution condition is unmet: {}",
                problem.resolution_condition
            ));
        }
        Ok(Self {
            problem_id: problem.problem_id.clone(),
            title: problem.title.clone(),
            class: problem.class,
            severity: problem.severity,
            state: problem.state,
            revision: problem.revision,
            scope_id: problem.scope_id.clone(),
            symptom: problem.symptom.clone(),
            affected_dependencies: problem.affected_dependencies.clone(),
            owner: problem.owner.clone(),
            containment: problem.containment.clone(),
            evidence_handles: problem.evidence_refs.clone(),
            hypotheses: problem.hypotheses.clone(),
            repair_history: problem.repair_history.clone(),
            reopen_history: problem.reopen_history.clone(),
            next_probe: problem.next_probe.clone(),
            resolution_condition: problem.resolution_condition.clone(),
            unknowns,
        })
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

    /// Expires an active deviation when its review condition triggers.
    ///
    /// The departure reason is recorded in `outcome_ref`; the reason,
    /// evidence, hard-boundary checks, risk, rollback and review condition are
    /// retained so a later reviewer can still read why the assumption lapsed.
    pub fn expire(
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
        self.state = DeviationState::Expired;
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
            "incident_promotion": schemars::schema_for!(IncidentPromotion),
            "reassignment_obligation": schemars::schema_for!(ReassignmentObligation),
            "diagnostic_brief": schemars::schema_for!(DiagnosticBrief),
            "closure_evidence": schemars::schema_for!(ClosureEvidence),
            "waiver": schemars::schema_for!(WaiverRecord),
            "supersession": schemars::schema_for!(SupersessionRecord),
            "eligible_owner": schemars::schema_for!(EligibleOwner),
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
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn state_fence() -> StateFence {
        StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
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
            class: ProblemClass::Operational,
            severity: SignalSeverity::Blocking,
            scope_id: "scope-1".to_owned(),
            affected_dependencies: vec!["module-1".to_owned()],
            symptom: "attempt fails at the effect boundary".to_owned(),
            evidence_refs: vec![artifact("evidence-1")?],
            hypotheses: vec!["retained effect is stale".to_owned()],
            owner: Some(owner()),
            containment: None,
            repair_history: Vec::new(),
            next_probe: Some("re-read the effect handle".to_owned()),
            resolution_condition: "verifier evidence".to_owned(),
            state: ProblemState::Open,
            acknowledged_by: None,
            reopen_history: Vec::new(),
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
        let new_fence =
            StateFence::new(test_epoch(TEST_LINEAGE_A, 2), ResourceGeneration::genesis());
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
    fn owner_loss_unassigns_without_resolving() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = problem()?;
        value.acknowledge(&fence, "owner-1")?;
        let obligation = value
            .owner_loss(&fence, vec![artifact("lease-expiry-1")?])?
            .ok_or(ProblemError::ImmutableState)?;
        assert!(!value.is_assigned());
        assert_eq!(value.state, ProblemState::Open);
        assert!(!value.is_resolved());
        assert_eq!(value.acknowledged_by, None);
        assert!(value
            .evidence_refs
            .contains(&artifact("lease-expiry-1")?));
        assert!(matches!(
            value.acknowledge(&fence, "owner-1"),
            Err(ProblemError::OwnerMismatch)
        ));
        obligation.validate()?;
        Ok(())
    }

    #[test]
    fn stale_expiry_cannot_unassign_a_renewed_successor() -> Result<(), ProblemError> {
        let old_fence = state_fence();
        let new_fence =
            StateFence::new(test_epoch(TEST_LINEAGE_A, 2), ResourceGeneration::genesis());
        let mut value = problem()?;
        value.reassign_owner(&old_fence, owner(), new_fence.clone())?;
        assert!(matches!(
            value.owner_loss(&old_fence, vec![artifact("lease-expiry-1")?]),
            Err(ProblemError::FenceMismatch)
        ));
        assert!(value.is_assigned());
        Ok(())
    }

    #[test]
    fn owner_loss_leaves_a_terminal_record_untouched() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = problem()?;
        value.transition(&fence, ProblemState::Triaged)?;
        value.transition(&fence, ProblemState::Diagnosing)?;
        value.transition(&fence, ProblemState::Verifying)?;
        value.transition(&fence, ProblemState::Resolved)?;
        let before = value.clone();
        assert!(value
            .owner_loss(&fence, vec![artifact("lease-expiry-1")?])?
            .is_none());
        assert_eq!(value, before);
        Ok(())
    }

    #[test]
    fn successor_requires_a_newly_issued_ownership_epoch() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = problem()?;
        assert!(matches!(
            value.reassign_owner(&fence, owner(), fence.clone()),
            Err(ProblemError::InvalidField { .. })
        ));
        assert!(value.is_assigned());
        Ok(())
    }

    fn attention() -> Result<CriticalAttention, ProblemError> {
        CriticalAttention::new(
            AttentionId::new("attention-1")?,
            "block the affected actions".to_owned(),
            vec!["task.commit".to_owned()],
            vec![artifact("evidence-1")?],
            owner(),
            "review after the next boundary".to_owned(),
            "effect handle reads back as expected".to_owned(),
            "human-authority-1".to_owned(),
            "critical-attention".to_owned(),
            state_fence(),
        )
    }

    #[test]
    fn acknowledgement_does_not_close_blocking_attention() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = attention()?;
        value.acknowledge(&fence, "owner-1")?;
        assert_eq!(value.state, AttentionState::Active);
        assert_eq!(value.affected_scope_actions, vec!["task.commit".to_owned()]);
        Ok(())
    }

    #[test]
    fn owner_cannot_verify_or_waive_its_own_obligation() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = attention()?;
        let own = ClosureEvidence {
            expected_observable: value.resolution_condition.clone(),
            subject_version: "revision-1".to_owned(),
            verifier: "owner-1".to_owned(),
            evidence_refs: vec![artifact("evidence-2")?],
        };
        assert!(matches!(
            value.resolve(&fence, &own),
            Err(ProblemError::VerifierNotIndependent)
        ));
        let waiver = WaiverRecord {
            authority: "owner-1".to_owned(),
            limits: vec!["one boundary".to_owned()],
            expires_at_ms: 1_900_000_000_000,
            residual_risk: "task.commit may still fail".to_owned(),
        };
        assert!(matches!(
            value.waive(&fence, &waiver),
            Err(ProblemError::WaiverNotAuthorized)
        ));
        assert_eq!(value.state, AttentionState::Active);
        Ok(())
    }

    #[test]
    fn unrelated_evidence_does_not_resolve_attention() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = attention()?;
        let unrelated = ClosureEvidence {
            expected_observable: "a different observable".to_owned(),
            subject_version: "revision-1".to_owned(),
            verifier: "verifier-1".to_owned(),
            evidence_refs: vec![artifact("evidence-2")?],
        };
        assert!(matches!(
            value.resolve(&fence, &unrelated),
            Err(ProblemError::ResolutionRequiresEvidence)
        ));
        assert_eq!(value.state, AttentionState::Active);
        Ok(())
    }

    #[test]
    fn supersession_rejects_a_nonexistent_replacement() -> Result<(), ProblemError> {
        let fence = state_fence();
        let mut value = attention()?;
        let missing = SupersessionRecord {
            replacement: AttentionId::new("attention-2")?,
            accepted: true,
            evidence_refs: vec![artifact("evidence-2")?],
        };
        assert!(matches!(
            value.supersede(&fence, "owner-1", &missing, &[]),
            Err(ProblemError::InvalidField { .. })
        ));
        let live = attention()?;
        value.supersede(&fence, "owner-1", &missing, &[live])?;
        assert_eq!(value.state, AttentionState::Superseded);
        assert_eq!(value.affected_scope_actions, vec!["task.commit".to_owned()]);
        assert!(matches!(
            value.acknowledge(&fence, "owner-1"),
            Err(ProblemError::ImmutableState)
        ));
        Ok(())
    }

    #[test]
    fn routing_resolves_an_eligible_lease_not_a_hardcoded_name() -> Result<(), ProblemError> {
        let roster = vec![
            EligibleOwner {
                owner: owner(),
                role: OwnerRole::ArchitectureOwner,
                eligible: false,
            },
            EligibleOwner {
                owner: OwnerRef {
                    principal: "task-controller-1".to_owned(),
                    generation: "generation-2".to_owned(),
                },
                role: OwnerRole::TaskController,
                eligible: true,
            },
        ];
        assert_eq!(
            AttentionKind::ArchitectureGap.route_to(&roster),
            None,
            "an ineligible architecture owner must not be selected"
        );
        assert_eq!(
            AttentionKind::TaskIssue
                .route_to(&roster)
                .map(|owner| owner.principal),
            Some("task-controller-1".to_owned())
        );
        assert_eq!(AttentionKind::Budget.route_to(&[]), None);
        Ok(())
    }

    fn candidate_incident() -> Result<Incident, ProblemError> {
        Ok(Incident {
            incident_id: IncidentId::new("incident-1")?,
            title: "authority compromise".to_owned(),
            scope_id: "scope-1".to_owned(),
            owner: owner(),
            state: IncidentState::Candidate,
            reason: None,
            source_problem: None,
            promotion_evidence: Vec::new(),
            evidence_refs: vec![artifact("evidence-1")?],
            acknowledged_by: None,
            state_fence: state_fence(),
            revision: 1,
            reopen_count: 0,
        })
    }

    #[test]
    fn admitted_trigger_promotes_with_its_receipt_and_source_problem() -> Result<(), ProblemError> {
        let fence = state_fence();
        let source = problem()?;
        let mut value = candidate_incident()?;
        let promotion = IncidentPromotion {
            reason: IncidentReason::CanonicalIntegrityOrAuthorityCompromised,
            policy_ref: "policy:authority-compromise".to_owned(),
            evidence_refs: vec![artifact("evidence-9")?],
            source_problem: source.problem_id.clone(),
            source_problem_revision: source.revision,
            human_authority: None,
        };
        value.promote(&fence, &source, &promotion)?;
        assert_eq!(value.state, IncidentState::Open);
        assert_eq!(
            value.reason,
            Some(IncidentReason::CanonicalIntegrityOrAuthorityCompromised)
        );
        assert_eq!(value.source_problem.as_ref(), Some(&source.problem_id));
        assert_eq!(value.promotion_evidence, promotion.evidence_refs);
        Ok(())
    }

    #[test]
    fn promotion_rejects_a_stale_source_revision() -> Result<(), ProblemError> {
        let fence = state_fence();
        let source = problem()?;
        let mut value = candidate_incident()?;
        let promotion = IncidentPromotion {
            reason: IncidentReason::StructuralCorruption,
            policy_ref: "policy:structural-corruption".to_owned(),
            evidence_refs: vec![artifact("evidence-9")?],
            source_problem: source.problem_id.clone(),
            source_problem_revision: source.revision + 1,
            human_authority: None,
        };
        assert!(matches!(
            value.promote(&fence, &source, &promotion),
            Err(ProblemError::InvalidField { .. })
        ));
        assert_eq!(value.state, IncidentState::Candidate);
        Ok(())
    }

    #[test]
    fn brief_exposes_exact_evidence_and_explicit_unknowns() -> Result<(), ProblemError> {
        let mut source = problem()?;
        source.owner = None;
        let brief = DiagnosticBrief::compile(&source)?;
        assert_eq!(brief.evidence_handles, source.evidence_refs);
        assert!(brief
            .unknowns
            .iter()
            .any(|unknown| unknown.contains("unassigned")));
        assert!(brief
            .unknowns
            .iter()
            .any(|unknown| unknown.contains(&source.resolution_condition)));
        assert!(brief.hypotheses.contains(&"retained effect is stale".to_owned()));
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
