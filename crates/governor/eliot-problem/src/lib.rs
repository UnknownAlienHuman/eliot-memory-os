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

mod ownership;

pub use ownership::{
    AssignedOwnership, AuthenticatedOwnerLease, AuthorizedWaiver, ClosureEvidence, LeaseIdentity,
    OwnerLeaseGrant, OwnerLeaseIssuer, OwnerLeaseLoss, OwnerLossReason, OwnerRoute, Ownership,
    OwnershipObligation, Supersession, SupersessionRecord, UnassignedOwnership, WaiverRecord,
    obligation_id,
};

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
    /// A record revision or counter cannot advance without reusing an identity.
    #[error("{field} overflow: refusing to reuse revision {current}")]
    CounterOverflow { field: &'static str, current: u64 },
    /// The record is unassigned and therefore carries a visible obligation
    /// instead of an owner. It is not resolved, accepted risk, or discardable.
    #[error("record is unassigned: a reassignment or escalation obligation is outstanding")]
    OwnerUnassigned,
    /// The presented ownership lease is no longer inside its validity window.
    #[error("ownership lease is outside its validity window")]
    OwnerLeaseNotCurrent,
    /// The presented owner claim does not match the retained lease identity.
    #[error("owner claim does not match the retained ownership lease")]
    OwnerLeaseMismatch,
    /// An owner-loss event names a lease or ownership epoch this record no
    /// longer holds, so it is a delayed event for an already-superseded lease
    /// and must not unassign the current successor.
    #[error("owner-loss event is stale for the lease and ownership epoch this record holds")]
    StaleOwnerLoss,
    /// Closure evidence must come from a verifier independent of the owner.
    #[error("resolution evidence must come from a verifier independent of the owner")]
    IndependentVerifierRequired,
    /// The submitted evidence does not cover every independently expected
    /// observable, so the resolution condition is not satisfied yet.
    #[error("resolution evidence does not cover expected observable {value}")]
    UnresolvedExpectation { value: String },
    /// A waiver was attempted by a principal that is not the recorded waiver
    /// authority, or by the current owner, who cannot waive its own obligation.
    #[error("waiver is not the recorded waiver authority")]
    WaiverAuthorityRequired,
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

/// Appends newly observed evidence without disturbing what is already retained.
///
/// Append-only: an existing reference is kept once and its position is not
/// rewritten, so a closure readback augments the observation history rather
/// than replacing it.
fn merge_evidence(retained: &[ArtifactId], observed: &[ArtifactId]) -> Vec<ArtifactId> {
    let mut merged = retained.to_vec();
    for reference in observed {
        if !merged.contains(reference) {
            merged.push(reference.clone());
        }
    }
    merged
}

/// The ownership epoch a legacy record without a lease is migrated under.
///
/// The legacy record never held an ownership epoch, so this derives the
/// migration's epoch from the record's own committed revision rather than
/// inventing a plausible one: the value is deterministic, non-zero, and it
/// carries no claim that a lease was ever issued.
fn unassigned_legacy_epoch(revision: u64) -> Result<u64, ProblemError> {
    if revision == 0 {
        return Err(ProblemError::InvalidField {
            field: "revision",
            reason: "must be non-zero",
        });
    }
    Ok(revision)
}

/// Advances a record revision, refusing overflow instead of reusing one.
///
/// A saturating bump pins a live record to the revision that already names its
/// current committed state, so the transition is refused and the caller must
/// re-read the record rather than write a reused identity. Refusal is the only
/// correct outcome: two distinct states sharing one revision is a
/// compare-and-set that has stopped comparing, so the caller sees a conflict
/// and re-reads instead of committing under an identity it already used.
fn next_revision(current: u64) -> Result<u64, ProblemError> {
    current.checked_add(1).ok_or(ProblemError::CounterOverflow {
        field: "revision",
        current,
    })
}

/// Advances the reopen counter under the same no-reuse rule as the revision.
fn next_reopen_count(current: u32) -> Result<u32, ProblemError> {
    current.checked_add(1).ok_or(ProblemError::CounterOverflow {
        field: "reopen_count",
        current: u64::from(current),
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

/// The closed I13.9 Problem classification.
///
/// The set is closed: I13.9 enumerates exactly these six classes, so an
/// unlisted class cannot be spelled and a listed class cannot be renamed. The
/// class is the record's own routing input for the I13.8 default-owner table,
/// so an owner-loss obligation names a role derived from the record rather than
/// a role the caller raising the loss chose.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemClass {
    /// Runtime/operational failure.
    Operational,
    /// Boundary or interface failure between components.
    Integration,
    /// Wrong interpretation, belief or reasoning.
    Cognitive,
    /// Wrong, missing or contradictory data.
    DataQuality,
    /// Security or integrity failure.
    Security,
    /// Budget or resource-consumption failure.
    Cost,
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

/// Durable operational/cognitive/integration/data-quality problem.
///
/// Every I13.9 field is present and separately named. In particular
/// `class`/`severity` drive the I13.8 routing, `observed_evidence` is kept
/// distinct from `hypotheses` so a guess is never counted as an observation,
/// `ownership` replaces a bare principal pair with a lease/epoch-bound owner
/// that has an explicit unassigned state, and `expected_resolution` is the
/// independently expected closure set that a resolution is checked against
/// rather than the set the closer supplies.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub problem_id: ProblemId,
    pub signal_refs: Vec<SignalId>,
    /// I13.9 `class`.
    pub class: ProblemClass,
    /// I13.9 `severity`, taken from the admitting Signal's own severity.
    pub severity: SignalSeverity,
    pub title: String,
    /// I13.9 `symptom`.
    pub symptom: String,
    pub scope_id: String,
    /// I13.9 `scope/affected_dependencies`, the exact dependencies hit.
    pub affected_dependencies: Vec<String>,
    /// I13.9 `evidence`: what was actually observed.
    pub observed_evidence: Vec<ArtifactId>,
    /// I13.9 `hypotheses`: candidate explanations, never evidence.
    pub hypotheses: Vec<ProblemHypothesis>,
    /// I13.9 `owner_and_epoch`, lease-bound with an explicit unassigned state.
    pub ownership: Ownership,
    /// I13.9 `containment`.
    pub containment: Vec<ArtifactId>,
    /// I13.9 `repair_history`, one retained entry per committed repair.
    pub repair_history: Vec<RepairRecord>,
    /// I13.9 `next_probe_or_action`: the next discriminative action.
    pub next_probe: String,
    pub state: ProblemState,
    /// I13.9 `resolution_condition`, stated by the record rather than the closer.
    pub resolution_condition: String,
    /// The independently expected observables a resolution must cover.
    ///
    /// Fixed when the Problem is raised, so the principal that closes it cannot
    /// choose the set it will be measured against.
    pub expected_resolution: Vec<ArtifactId>,
    /// I13.9 `reopen_history`, retained per reopen revision.
    pub reopen_history: Vec<ReopenRecord>,
    /// The outstanding reassignment/escalation obligation while unassigned.
    pub obligation: Option<OwnershipObligation>,
    pub acknowledged_by: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

/// One retained I13.9 hypothesis: a candidate explanation plus what supports it.
///
/// Hypotheses are kept separate from `observed_evidence` on purpose: I13.9 lists
/// them as different fields, and collapsing them would let a guess be counted
/// as an observation when closure is checked.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemHypothesis {
    /// The candidate explanation under test.
    pub statement: String,
    /// Artifacts that bear on the hypothesis without establishing it.
    pub supporting_evidence: Vec<ArtifactId>,
    /// The observation that would discriminate this hypothesis from the others.
    pub discriminating_probe: String,
}

impl ProblemHypothesis {
    /// Validates the statement, bearing evidence and its discriminating probe.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.statement, "hypothesis.statement")?;
        text(
            &self.discriminating_probe,
            "hypothesis.discriminating_probe",
        )?;
        nonempty(&self.supporting_evidence, "hypothesis.supporting_evidence")?;
        let evidence = self
            .supporting_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "hypothesis.supporting_evidence")
    }
}

/// One retained I13.9 repair history entry, bound to the revision that made it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairRecord {
    /// The record revision this repair was committed at.
    pub revision: u64,
    /// The repair action that was attempted.
    pub action: String,
    /// The evidence the attempt actually produced.
    pub evidence: Vec<ArtifactId>,
}

impl RepairRecord {
    /// Validates the bound revision, action and evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "repair.revision",
                reason: "must be non-zero",
            });
        }
        text(&self.action, "repair.action")?;
        nonempty(&self.evidence, "repair.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "repair.evidence")
    }
}

/// One retained I13.9 reopen-history entry.
///
/// A reopen count alone is not retained reopen evidence: each reopen appends
/// this record carrying the evidence that actually recurred, bound to the
/// revision it produced, and `validate` requires the history length to equal
/// the count so the two can never drift apart.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReopenRecord {
    /// The revision this reopen produced.
    pub revision: u64,
    /// The state the record held before this reopen.
    pub previous_state: ProblemState,
    /// The evidence that the problem actually recurred.
    pub evidence: Vec<ArtifactId>,
}

impl ReopenRecord {
    /// Validates the bound revision, prior state and recurrence evidence.
    pub fn validate(&self) -> Result<(), ProblemError> {
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "reopen.revision",
                reason: "must be non-zero",
            });
        }
        if !matches!(
            self.previous_state,
            ProblemState::Resolved
                | ProblemState::AcceptedRisk
                | ProblemState::Superseded
                | ProblemState::Quarantined
        ) {
            return Err(ProblemError::InvalidField {
                field: "reopen.previous_state",
                reason: "a reopen may only follow a terminal state",
            });
        }
        nonempty(&self.evidence, "reopen.evidence")?;
        let evidence = self
            .evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "reopen.evidence")
    }
}

impl Problem {
    /// Opens a Problem at revision 1 with a lease-backed owner.
    ///
    /// The owner is an [`AuthenticatedOwnerLease`], so opening a Problem under a
    /// principal the caller merely named is not expressible: the lease owner
    /// named the holder and this crate re-derived the commitment. `severity` and
    /// `observed_evidence` are checked against the admitting `Signal`, so the
    /// record cannot restate a severity or an observation the Signal never
    /// carried, and `expected_resolution` is fixed here — before anyone can
    /// close it — which is what makes later resolution evidence-backed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        problem_id: ProblemId,
        source: &Signal,
        class: ProblemClass,
        title: String,
        symptom: String,
        scope_id: String,
        affected_dependencies: Vec<String>,
        hypotheses: Vec<ProblemHypothesis>,
        ownership: &AuthenticatedOwnerLease,
        containment: Vec<ArtifactId>,
        next_probe: String,
        resolution_condition: String,
        expected_resolution: Vec<ArtifactId>,
        state_fence: StateFence,
    ) -> Result<Self, ProblemError> {
        source.validate()?;
        let value = Self {
            problem_id,
            signal_refs: vec![source.signal_id.clone()],
            class,
            severity: source.severity,
            title,
            symptom,
            scope_id,
            affected_dependencies,
            observed_evidence: source.evidence_handles.clone(),
            hypotheses,
            ownership: Ownership::Assigned(AssignedOwnership {
                holder: ownership.holder().clone(),
                lease: ownership.identity().clone(),
                ownership_epoch: ownership.ownership_epoch(),
            }),
            containment,
            repair_history: Vec::new(),
            next_probe,
            state: ProblemState::Open,
            resolution_condition,
            expected_resolution,
            reopen_history: Vec::new(),
            obligation: None,
            acknowledged_by: None,
            state_fence,
            revision: 1,
            reopen_count: 0,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates problem invariants, lease-bound ownership and evidence identity.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.title, "title")?;
        text(&self.symptom, "symptom")?;
        text(&self.scope_id, "scope_id")?;
        text(&self.resolution_condition, "resolution_condition")?;
        text(&self.next_probe, "next_probe")?;
        self.ownership.validate()?;
        fence(&self.state_fence)?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        nonempty(&self.signal_refs, "signal_refs")?;
        nonempty(&self.observed_evidence, "observed_evidence")?;
        nonempty(&self.affected_dependencies, "affected_dependencies")?;
        nonempty(&self.expected_resolution, "expected_resolution")?;
        let signals = self
            .signal_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&signals, "signal_refs")?;
        unique_text(&self.affected_dependencies, "affected_dependencies")?;
        let evidence = self
            .observed_evidence
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "observed_evidence")?;
        let expected = self
            .expected_resolution
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&expected, "expected_resolution")?;
        for hypothesis in &self.hypotheses {
            hypothesis.validate()?;
        }
        for repair in &self.repair_history {
            repair.validate()?;
        }
        for reopen in &self.reopen_history {
            reopen.validate()?;
        }
        // A reopen count is not reopen evidence: the two must agree, so a count
        // can never stand in for evidence that was never retained.
        if self.reopen_history.len() != usize::try_from(self.reopen_count).unwrap_or(usize::MAX) {
            return Err(ProblemError::InvalidField {
                field: "reopen_count",
                reason: "must equal the retained reopen history length",
            });
        }
        // An unassigned Problem is not resolved, accepted risk, or discardable:
        // its obligation must be visible on the record, and an assigned Problem
        // must not carry a stale one.
        match (&self.ownership, &self.obligation) {
            (Ownership::Unassigned(_), None) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an unassigned problem must retain its outstanding obligation",
            }),
            (Ownership::Unassigned(unassigned), Some(obligation)) => {
                if *obligation != unassigned.obligation {
                    return Err(ProblemError::InvalidField {
                        field: "obligation",
                        reason: "must be the obligation raised by the retained owner loss",
                    });
                }
                Ok(())
            }
            (Ownership::Assigned(_), Some(_)) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an assigned problem retains no outstanding obligation",
            }),
            (Ownership::Assigned(_), None) => Ok(()),
        }
    }

    /// The exact observables a resolution is checked against.
    ///
    /// These were fixed when the Problem was raised, which is what makes
    /// resolution evidence-backed: the closing principal does not get to pick
    /// the set that closes it.
    pub fn expected_observables(&self) -> &[ArtifactId] {
        &self.expected_resolution
    }

    /// The I13.8 default-owner route for this Problem's class.
    pub const fn default_owner_route(&self) -> OwnerRoute {
        OwnerRoute::for_class(self.class)
    }

    /// Advances only along the declared Problem lifecycle.
    ///
    /// The candidate state is validated on a copy, so a rejected edge or a
    /// refused revision leaves the live record exactly as it was. A terminal
    /// edge is refused: closure goes through [`Self::resolve`] or
    /// [`Self::accept_risk`], which require independent evidence or an
    /// authorized waiver, so a bare transition can never declare resolution.
    pub fn transition(
        &mut self,
        expected_fence: &StateFence,
        next: ProblemState,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if matches!(
            next,
            ProblemState::Resolved | ProblemState::AcceptedRisk | ProblemState::Superseded
        ) {
            return Err(ProblemError::ResolutionRequiresEvidence);
        }
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

    /// Resolves only against the independently expected observable set.
    ///
    /// The evidence is checked against `expected_resolution`, which the record
    /// fixed when it was raised, and the verifier must be independent of the
    /// current owner and bound to the record's current fence. A non-empty
    /// evidence list is not enough: unrelated evidence does not satisfy the
    /// condition, and neither delivery, restart nor model opinion can appear
    /// here at all because the only input is an independent readback.
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        closure: &ClosureEvidence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        self.check_closure_preconditions(closure)?;
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.observed_evidence =
            merge_evidence(&candidate.observed_evidence, &closure.verified_observables);
        candidate.state = ProblemState::Resolved;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Accepts risk only under an authorized, scoped, expiring waiver.
    ///
    /// The waiver authority is a separate principal from the owner, so the
    /// owner cannot waive its own obligation. The authority, limits, expiry and
    /// residual risk are retained on the record as [`WaiverRecord`].
    pub fn accept_risk(
        &mut self,
        expected_fence: &StateFence,
        waiver: &AuthorizedWaiver,
    ) -> Result<WaiverRecord, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        waiver.validate()?;
        let owner = self.ownership.assigned()?;
        if waiver.authority.principal == owner.holder.principal {
            return Err(ProblemError::WaiverAuthorityRequired);
        }
        if self.state != ProblemState::Verifying {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "ACCEPTED_RISK".to_owned(),
            });
        }
        let revision = next_revision(self.revision)?;
        let record = WaiverRecord {
            authority: waiver.authority.clone(),
            decision_ref: waiver.decision_ref.clone(),
            limits: waiver.limits.clone(),
            expires_at_ms: waiver.expires_at_ms,
            residual_risk: waiver.residual_risk.clone(),
            evidence: waiver.evidence.clone(),
        };
        let mut candidate = self.clone();
        candidate.observed_evidence =
            merge_evidence(&candidate.observed_evidence, &waiver.evidence);
        candidate.state = ProblemState::AcceptedRisk;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(record)
    }

    /// Refuses a resolution whose evidence the owner alone chose.
    ///
    /// This is the one place the independent-closure rule is enforced, so both
    /// [`Self::resolve`] and the read-only checks share it.
    fn check_closure_preconditions(&self, closure: &ClosureEvidence) -> Result<(), ProblemError> {
        closure.validate()?;
        let owner = self.ownership.assigned()?;
        if closure.verifier.principal == owner.holder.principal {
            return Err(ProblemError::IndependentVerifierRequired);
        }
        if closure.verifier_fence != self.state_fence {
            return Err(ProblemError::FenceMismatch);
        }
        // The expected set was fixed when the record was raised. Every one of
        // them must be covered, so a list of unrelated artifacts cannot close
        // the Problem even when the list is non-empty.
        for expected in &self.expected_resolution {
            if !closure.verified_observables.contains(expected) {
                return Err(ProblemError::UnresolvedExpectation {
                    value: expected.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Records receipt by the current lease-backed owner.
    ///
    /// Acknowledgement is not resolution: it records that the owner saw the
    /// record and leaves the state, evidence and obligation untouched.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        // A record whose owner was lost has no principal any caller can present,
        // so the lost owner is fenced from every later update.
        let owner = self.ownership.assigned()?;
        if !lease.is_exactly(&owner.lease) || lease.holder().principal != owner.holder.principal {
            return Err(ProblemError::OwnerLeaseMismatch);
        }
        match &self.acknowledged_by {
            Some(existing) if *existing != owner.holder.principal => {
                Err(ProblemError::AcknowledgementConflict)
            }
            Some(_) => Ok(()),
            None => {
                self.acknowledged_by = Some(owner.holder.principal.clone());
                Ok(())
            }
        }
    }

    /// Assigns an eligible successor under a newly issued ownership lease.
    ///
    /// `lease` must be an [`AuthenticatedOwnerLease`], so the successor is
    /// named by the lease owner rather than by the caller: a caller that only
    /// has a principal string cannot reach this entry at all. The lease must
    /// still be inside its own validity window at `now_ms`, the grant's
    /// ownership epoch must be greater than the epoch currently held so I13.8's
    /// "new Authority Epoch" cannot be a reuse, and the grant must be bound to
    /// the record's live fence.
    ///
    /// This is also the reassignment half of the fenced owner-loss workflow, so
    /// it is admitted on an already-unassigned record: that is the state
    /// [`Self::record_owner_loss`] leaves behind, and admitting a successor is
    /// how the outstanding obligation is discharged. Clearing that obligation
    /// here is what makes the loss a reassignment rather than a delete — the
    /// phase, evidence, hypotheses and repair history all survive, and only the
    /// expired assignment is replaced. The epoch floor is read from whichever
    /// ownership variant the record holds, so the successor still has to clear
    /// the fenced epoch rather than restart from nothing.
    pub fn assign_owner(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
        now_ms: u64,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        let grant = lease.grant();
        if !lease.is_current_at(now_ms) {
            return Err(ProblemError::OwnerLeaseNotCurrent);
        }
        if !lease.is_bound_to(&self.state_fence) {
            return Err(ProblemError::FenceMismatch);
        }
        // The epoch is read from whichever variant this record holds, not from
        // the live assignment: a record that lost its owner retains the fenced
        // epoch, and refusing to read it here would make every recorded owner
        // loss permanent, because no successor could ever clear the epoch
        // floor and the outstanding obligation could never be discharged.
        let current_epoch = self.ownership.retained_epoch();
        if grant.ownership_epoch <= current_epoch {
            return Err(ProblemError::InvalidField {
                field: "lease.ownership_epoch",
                reason: "must be a new epoch greater than the epoch this record holds",
            });
        }
        if self.is_resolved() {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Assigned(AssignedOwnership {
            holder: grant.holder.clone(),
            lease: lease.identity().clone(),
            ownership_epoch: grant.ownership_epoch,
        });
        candidate.obligation = None;
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records a fenced owner loss and leaves the obligation visible.
    ///
    /// This is the seam that makes loss non-silent. The lease owner reports the
    /// exact [`LeaseIdentity`] it observed dead; a loss naming a different
    /// identity is a delayed event for an already-superseded lease and is
    /// refused with [`ProblemError::StaleOwnerLoss`], so it cannot unassign the
    /// current successor. When the loss is current, only the assignment is
    /// cleared: the unresolved phase, evidence, hypotheses, repair history and
    /// reopen history are all retained, and one obligation derived from the
    /// record's own class and the fenced epoch is raised. The unresolved
    /// Problem is still unresolved afterwards.
    ///
    /// An already-terminal record is preserved rather than reopened: losing a
    /// former owner does not resurrect a resolved Problem.
    pub fn record_owner_loss(
        &mut self,
        expected_fence: &StateFence,
        loss: &OwnerLeaseLoss,
    ) -> Result<OwnershipObligation, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        loss.validate()?;
        let owner = self.ownership.assigned()?;
        if !loss.observed_lease.is_exactly(&owner.lease) {
            return Err(ProblemError::StaleOwnerLoss);
        }
        if matches!(
            self.state,
            ProblemState::Resolved
                | ProblemState::AcceptedRisk
                | ProblemState::Superseded
                | ProblemState::Quarantined
        ) {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        let obligation = OwnershipObligation {
            obligation_id: obligation_id(
                self.problem_id.as_str(),
                self.default_owner_route(),
                owner.ownership_epoch,
            )?,
            route: self.default_owner_route(),
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            raised_at_revision: revision,
        };
        // The one exact line where owner loss becomes a visible obligation and
        // the former owner is fenced: the assignment is replaced by an
        // unassigned state that names the fenced holder, the retained loss
        // evidence and this obligation.
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Unassigned(UnassignedOwnership {
            last_holder: owner.holder.clone(),
            reason: loss.reason,
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            loss_evidence: loss.evidence.clone(),
            obligation: obligation.clone(),
        });
        candidate.obligation = Some(obligation.clone());
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(obligation)
    }

    /// Migrates a legacy record that carried no ownership lease.
    ///
    /// The absence is the finding: the record becomes explicitly unassigned
    /// under [`OwnerLossReason::LegacyRecordWithoutLease`] with a visible
    /// escalation obligation, and never a synthesized live lease. A legacy
    /// record that already looks assigned is refused, because that would mean
    /// inventing a lease for a record whose lease was never issued.
    pub fn migrate_legacy_without_lease(
        &mut self,
        expected_fence: &StateFence,
        legacy_holder: &OwnerRef,
    ) -> Result<OwnershipObligation, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        legacy_holder.validate()?;
        if self.ownership.is_assigned() {
            return Err(ProblemError::OwnerLeaseMismatch);
        }
        if let Ownership::Unassigned(unassigned) = &self.ownership
            && unassigned.reason == OwnerLossReason::LegacyRecordWithoutLease
        {
            return Ok(unassigned.obligation.clone());
        }
        let revision = next_revision(self.revision)?;
        let route = self.default_owner_route();
        let obligation = OwnershipObligation {
            obligation_id: obligation_id(
                self.problem_id.as_str(),
                route,
                unassigned_legacy_epoch(self.revision)?,
            )?,
            route,
            lost_lease: None,
            ownership_epoch: unassigned_legacy_epoch(self.revision)?,
            raised_at_revision: revision,
        };
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Unassigned(UnassignedOwnership {
            last_holder: legacy_holder.clone(),
            reason: OwnerLossReason::LegacyRecordWithoutLease,
            lost_lease: None,
            ownership_epoch: obligation.ownership_epoch,
            loss_evidence: Vec::new(),
            obligation: obligation.clone(),
        });
        candidate.obligation = Some(obligation.clone());
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(obligation)
    }

    /// Reopens a terminal problem only with new evidence and the current fence.
    ///
    /// Actual recurrence is what reopens: the supplied evidence is retained as a
    /// [`ReopenRecord`] bound to the revision this reopen produces, and
    /// `validate` requires the retained history length to equal the count, so a
    /// bare count can never stand in for evidence that was not kept. The
    /// reopened record is built as a candidate and validated before it is
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
        candidate.observed_evidence = merge_evidence(&candidate.observed_evidence, &new_evidence);
        candidate.reopen_history.push(ReopenRecord {
            revision,
            previous_state: self.state,
            evidence: new_evidence,
        });
        candidate.state = ProblemState::Open;
        candidate.acknowledged_by = None;
        candidate.reopen_count = reopen_count;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Reaches `I13.9` `superseded` under an accepted replacement obligation.
    ///
    /// I13.7 closes blocking on "verified resolution, authorized waiver or
    /// supersession", and I13.9 names `superseded` as its own terminal state
    /// beside `resolved` and `accepted_risk`. A bare
    /// [`Self::transition`] refuses every terminal target, so this is the only
    /// path to that state and it cannot be spelled as an ordinary update: the
    /// replacement obligation is validated against this record first, so a
    /// cycle or a nonexistent reference is refused rather than committed. The
    /// retained [`SupersessionRecord`] is returned for the caller to persist
    /// with the state change, exactly as [`Self::accept_risk`] returns its
    /// [`WaiverRecord`]. The candidate is validated before it replaces the live
    /// record, so a refused supersession leaves the record unchanged.
    pub fn supersede(
        &mut self,
        expected_fence: &StateFence,
        supersession: &Supersession,
    ) -> Result<SupersessionRecord, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        supersession.validate(self.problem_id.as_str())?;
        if !self.state.can_transition_to(ProblemState::Superseded) {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "SUPERSEDED".to_owned(),
            });
        }
        let revision = next_revision(self.revision)?;
        let record = SupersessionRecord {
            replacement_obligation_ref: supersession.replacement_obligation_ref.clone(),
            replacement_holder: supersession.replacement_holder.clone(),
            evidence: supersession.evidence.clone(),
        };
        // The retained record is checked against the same contract the input
        // faced before it leaves this crate, so a reloaded supersession is held
        // to the admission it was admitted under.
        record.validate()?;
        let mut candidate = self.clone();
        candidate.observed_evidence =
            merge_evidence(&candidate.observed_evidence, &supersession.evidence);
        candidate.state = ProblemState::Superseded;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(record)
    }

    /// Escalates the outstanding reassignment/escalation obligation.
    ///
    /// I13.9 says an owner loss leaves ownership `unassigned` "until reassigned
    /// to an eligible successor **or escalated through Critical Attention**", so
    /// losing the owner and escalating the consequence are two distinct steps:
    /// [`Self::record_owner_loss`] performs the first and this the second. It is
    /// therefore admitted only on an already-unassigned record — an assigned
    /// record has no outstanding obligation to escalate, and clearing its
    /// assignment is a loss, not an escalation — and an already-terminal record
    /// is preserved rather than escalated back into work.
    ///
    /// The obligation identity is re-derived from the record's own class route
    /// and the fenced ownership epoch rather than minted here, so a replayed or
    /// repeated escalation converges on the identical obligation instead of
    /// producing an escalation storm of new identities. The escalation evidence
    /// is merged into the observed evidence and the record advances to a new
    /// revision, which is what makes each attempt durable and readable back
    /// while the obligation itself stays one.
    pub fn escalate_obligation(
        &mut self,
        expected_fence: &StateFence,
        evidence: &[ArtifactId],
    ) -> Result<OwnershipObligation, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        nonempty(evidence, "escalation.evidence")?;
        let evidence_text = evidence.iter().map(ToString::to_string).collect::<Vec<_>>();
        unique_text(&evidence_text, "escalation.evidence")?;
        let Ownership::Unassigned(unassigned) = &self.ownership else {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.ownership),
                to: "ESCALATE".to_owned(),
            });
        };
        if matches!(
            self.state,
            ProblemState::Resolved
                | ProblemState::AcceptedRisk
                | ProblemState::Superseded
                | ProblemState::Quarantined
        ) {
            return Err(ProblemError::ImmutableState);
        }
        let route = self.default_owner_route();
        let obligation = OwnershipObligation {
            obligation_id: obligation_id(
                self.problem_id.as_str(),
                route,
                unassigned.ownership_epoch,
            )?,
            route,
            lost_lease: unassigned.lost_lease.clone(),
            ownership_epoch: unassigned.ownership_epoch,
            raised_at_revision: self.revision,
        };
        if obligation != unassigned.obligation {
            return Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an escalation may only restate the obligation the owner loss raised",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.observed_evidence = merge_evidence(&candidate.observed_evidence, evidence);
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(obligation)
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
                .filter(|evidence| !self.observed_evidence.contains(evidence))
                .cloned()
                .collect::<Vec<_>>();
            if fresh.is_empty() {
                return Err(ProblemError::ReopenRequiresEvidence);
            }
            candidate.reopen(expected_fence, fresh)?;
        } else {
            candidate.observed_evidence =
                merge_evidence(&candidate.observed_evidence, &request.revocation_evidence);
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

/// The seven closed I13.10 reasons a Problem becomes an Incident.
///
/// The set is closed: the document enumerates exactly these findings, so an
/// unlisted reason cannot be spelled and a listed reason cannot be renamed.
/// `StructuralCorruption` names canonical ordering, receipts, provenance,
/// schema/storage integrity or authority state being untrusted; a wrong
/// interpretation is a different reason, never a corruption claim.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentReason {
    /// Canonical integrity or authority is compromised.
    IntegrityOrAuthorityCompromised,
    /// A secret, privacy or security boundary was breached.
    SecurityPrivacyBreach,
    /// A critical telemetry or control path is lost.
    CriticalTelemetryOrControlPathLost,
    /// An external effect of unknown Material or Critical materiality occurred.
    UnknownMaterialOrCriticalExternalEffect,
    /// A blocking condition persists while continuation stays unsafe.
    PersistentUnsafeBlocking,
    /// Canonical ordering, receipts, provenance or schema integrity is untrusted.
    StructuralCorruption,
    /// The Control Reserve or last-resort path is exhausted.
    ControlReserveExhausted,
}

/// The authority under which an Incident Open is committed (I13.10 S1).
///
/// The document admits exactly two: "Problem becomes Incident when
/// deterministic policy or authorized Human finds" the reason. A
/// `ModelRecommendation` is deliberately NOT a variant, so a Signal labelled
/// `IncidentCandidate` or a model confidence score has no way to name itself
/// as the opening authority at all.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PromotionAuthority {
    /// A deterministic policy evaluation, bound to its exact rule identity.
    DeterministicPolicy {
        /// The policy rule that decided this promotion.
        rule_id: String,
    },
    /// An authorized Human decision, bound to its exact decision reference.
    AuthorizedHuman {
        /// The admitted Human decision record that authorized this promotion.
        decision_ref: String,
    },
}

impl PromotionAuthority {
    /// Validates that the authority names a real admitting record.
    pub fn validate(&self) -> Result<(), ProblemError> {
        match self {
            Self::DeterministicPolicy { rule_id } => text(rule_id, "promotion.rule_id"),
            Self::AuthorizedHuman { decision_ref } => text(decision_ref, "promotion.decision_ref"),
        }
    }
}

/// A closed request to review a candidate as an Incident.
///
/// A request is not a decision. It records the reason, the source Problem and
/// the requesting Signal so a review can consider them, and it never changes
/// `Incident::state`: only [`Incident::promote`] moves `Candidate` to `Open`,
/// and only on a [`PromotionAuthority`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentReviewRequest {
    /// The closed I13.10 reason the requester observed.
    pub reason: IncidentReason,
    /// The Problem this Incident was promoted from; the link is never dropped.
    pub source_problem: ProblemId,
    /// The Signal whose severity/attribution asked for the review.
    pub signal_id: SignalId,
    /// The evidence the requesting Signal actually carried.
    pub evidence_refs: Vec<ArtifactId>,
    /// The requesting Signal's severity, read from the Signal itself.
    pub signal_severity: SignalSeverity,
}

impl IncidentReviewRequest {
    /// Validates the request's identity and its bound evidence.
    ///
    /// `source` is the Signal the request claims to come from. The evidence
    /// list is compared with `source.evidence_handles` and the severity with
    /// `source.severity`, so a request cannot restate another Signal's severity
    /// or borrow unrelated evidence.
    pub fn validate(&self, source: &Signal) -> Result<(), ProblemError> {
        if self.signal_id != source.signal_id {
            return Err(ProblemError::InvalidField {
                field: "review_request.signal_id",
                reason: "must name the signal the request was derived from",
            });
        }
        if self.signal_severity != source.severity {
            return Err(ProblemError::InvalidField {
                field: "review_request.signal_severity",
                reason: "must restate the source signal's own severity",
            });
        }
        nonempty(&self.evidence_refs, "review_request.evidence_refs")?;
        if self.evidence_refs != source.evidence_handles {
            return Err(ProblemError::InvalidField {
                field: "review_request.evidence_refs",
                reason: "must be the source signal's own evidence handles",
            });
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
    /// Lease-bound owner with an explicit unassigned state, so losing an
    /// Incident owner leaves a visible obligation rather than a silent gap.
    pub ownership: Ownership,
    pub state: IncidentState,
    pub evidence_refs: Vec<ArtifactId>,
    /// The Problem this Incident was promoted from, once promotion is decided.
    pub source_problem: Option<ProblemId>,
    /// The reason and admitting authority of the committed promotion, once one
    /// exists. A `None` value is an unpromoted `Candidate`, never an Incident
    /// that merely forgot its reason.
    pub promotion: Option<IncidentPromotion>,
    /// Retained review requests; a request is evidence that review was asked
    /// for, and it is never a decision.
    pub review_requests: Vec<IncidentReviewRequest>,
    /// The independently expected observables a resolution must cover.
    pub expected_resolution: Vec<ArtifactId>,
    /// The outstanding reassignment/escalation obligation while unassigned.
    pub obligation: Option<OwnershipObligation>,
    pub acknowledged_by: Option<String>,
    pub state_fence: StateFence,
    pub revision: u64,
    pub reopen_count: u32,
}

/// The committed promotion decision: reason plus the admitting authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentPromotion {
    /// The closed I13.10 reason that was found.
    pub reason: IncidentReason,
    /// The authority that admitted the promotion.
    pub authority: PromotionAuthority,
    /// The Signal the promotion was requested from, when it came from one.
    pub request_signal: Option<SignalId>,
}

impl IncidentPromotion {
    /// Validates the reason/authority pair.
    pub fn validate(&self) -> Result<(), ProblemError> {
        self.authority.validate()
    }
}

impl Incident {
    /// Validates incident identity, ownership and evidence.
    ///
    /// A committed promotion must name the Problem it came from and carry a
    /// validated reason/authority pair, so an `Open` Incident can never be
    /// reconstructed from a state alone.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.title, "title")?;
        text(&self.scope_id, "scope_id")?;
        self.ownership.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        if self.revision == 0 {
            return Err(ProblemError::InvalidField {
                field: "revision",
                reason: "must be non-zero",
            });
        }
        if let Some(promotion) = &self.promotion {
            if self.expected_resolution.is_empty() {
                return Err(ProblemError::InvalidField {
                    field: "expected_resolution",
                    reason: "a promoted incident must retain its expected closure set",
                });
            }
            // I13.9 separates semantic contamination from structural corruption.
            // A review request that observed a wrong interpretation is not a
            // corruption finding, so an `UnknownMaterialOrCriticalExternalEffect`
            // or `CriticalTelemetryOrControlPathLost` request can never be the
            // retained request a structural-corruption promotion decides on:
            // wrong interpretations do not automatically justify restore or a
            // global shutdown.
            if promotion.reason == IncidentReason::StructuralCorruption
                && self
                    .review_requests
                    .iter()
                    .all(|request| request.reason != IncidentReason::StructuralCorruption)
            {
                return Err(ProblemError::InvalidField {
                    field: "promotion.reason",
                    reason: "structural corruption requires a retained review request that found it",
                });
            }
        }
        let expected = self
            .expected_resolution
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&expected, "expected_resolution")?;
        match (&self.promotion, &self.source_problem) {
            (None, None) => {}
            (Some(promotion), Some(problem_id)) => {
                promotion.validate()?;
                text(problem_id.as_str(), "source_problem")?;
                if matches!(self.state, IncidentState::Candidate) {
                    return Err(ProblemError::InvalidField {
                        field: "promotion",
                        reason: "a candidate incident carries no committed promotion",
                    });
                }
            }
            (Some(_), None) => {
                return Err(ProblemError::InvalidField {
                    field: "source_problem",
                    reason: "a promoted incident must retain its source problem",
                });
            }
            (None, Some(_)) => {
                return Err(ProblemError::InvalidField {
                    field: "promotion",
                    reason: "a source problem requires a committed promotion",
                });
            }
        }
        let reviews = self
            .review_requests
            .iter()
            .map(|request| request.signal_id.to_string())
            .collect::<Vec<_>>();
        unique_text(&reviews, "review_requests")?;
        for request in &self.review_requests {
            nonempty(&request.evidence_refs, "review_requests.evidence_refs")?;
        }
        // An unassigned Incident keeps a visible obligation, exactly as an
        // unassigned Problem or attention does; loss is never silent.
        match (&self.ownership, &self.obligation) {
            (Ownership::Unassigned(unassigned), Some(obligation)) => {
                if *obligation != unassigned.obligation {
                    return Err(ProblemError::InvalidField {
                        field: "obligation",
                        reason: "must be the obligation raised by the retained owner loss",
                    });
                }
                Ok(())
            }
            (Ownership::Unassigned(_), None) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an unassigned incident must retain its outstanding obligation",
            }),
            (Ownership::Assigned(_), Some(_)) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an assigned incident retains no outstanding obligation",
            }),
            (Ownership::Assigned(_), None) => Ok(()),
        }
    }

    /// Records that review was requested, without deciding anything.
    ///
    /// The requesting Signal is the evidence: the request is refused unless it
    /// restates that Signal's own severity and evidence handles exactly, so a
    /// caller cannot request review under a severity the Signal never carried.
    /// `state` is untouched — a request is not a decision, and a model-only
    /// request never reaches `Open`.
    pub fn request_review(
        &mut self,
        expected_fence: &StateFence,
        source: &Signal,
        request: IncidentReviewRequest,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        request.validate(source)?;
        if self
            .review_requests
            .iter()
            .any(|existing| existing.signal_id == request.signal_id)
        {
            return Err(ProblemError::Duplicate {
                field: "review_requests",
                value: request.signal_id.to_string(),
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.review_requests.push(request);
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Commits `Candidate -> Open` on a real I13.10 authority.
    ///
    /// Promotion is a separate governed decision: it requires one of the seven
    /// closed reasons, a named deterministic policy rule or authorized Human
    /// decision, and the source Problem link. A model-only request cannot reach
    /// this entry at all, because [`PromotionAuthority`] has no model variant.
    ///
    /// The request must already be retained by [`Self::request_review`], so
    /// promotion decides on a request that a Signal actually made rather than
    /// one a caller assembles at the moment of opening. The candidate is built
    /// and validated before it is committed, so a refused promotion leaves the
    /// record exactly as it was.
    pub fn promote(
        &mut self,
        expected_fence: &StateFence,
        request: &IncidentReviewRequest,
        authority: PromotionAuthority,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        authority.validate()?;
        if self.state != IncidentState::Candidate {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "OPEN".to_owned(),
            });
        }
        if !self
            .review_requests
            .iter()
            .any(|retained| retained == request)
        {
            return Err(ProblemError::InvalidField {
                field: "promotion",
                reason: "promotion must decide on a retained review request",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        for evidence in &request.evidence_refs {
            if !candidate.evidence_refs.contains(evidence) {
                candidate.evidence_refs.push(evidence.clone());
            }
        }
        candidate.source_problem = Some(request.source_problem.clone());
        candidate.promotion = Some(IncidentPromotion {
            reason: request.reason,
            authority,
            request_signal: Some(request.signal_id.clone()),
        });
        candidate.state = IncidentState::Open;
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records acknowledgement without resolving the incident.
    ///
    /// The caller must present the live [`AuthenticatedOwnerLease`], so a lost
    /// owner cannot come back and write: the record is unassigned, so there is
    /// no principal to satisfy. Acknowledgement is receipt only and never
    /// changes `state` or the promotion.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        let owner = self.ownership.assigned()?;
        if !lease.is_exactly(&owner.lease) || lease.holder().principal != owner.holder.principal {
            return Err(ProblemError::OwnerLeaseMismatch);
        }
        self.acknowledged_by = Some(owner.holder.principal.clone());
        Ok(())
    }

    /// Assigns an eligible successor under a newly issued ownership lease.
    ///
    /// Same lease-epoch rule as the Problem and attention records: the successor
    /// is named by the lease owner, the lease must be current at `now_ms`, and
    /// the grant's ownership epoch must exceed the epoch currently held, so a
    /// renewal is a new epoch rather than a reuse.
    ///
    /// As on the Problem, this is also how the owner-loss obligation is
    /// discharged on an already-unassigned Incident: the promotion, its reason,
    /// its admitting authority and its retained review requests all survive and
    /// only the expired assignment is replaced.
    pub fn assign_owner(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
        now_ms: u64,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        let grant = lease.grant();
        if !lease.is_current_at(now_ms) {
            return Err(ProblemError::OwnerLeaseNotCurrent);
        }
        if !lease.is_bound_to(&self.state_fence) {
            return Err(ProblemError::FenceMismatch);
        }
        let current_epoch = self.ownership.retained_epoch();
        if grant.ownership_epoch <= current_epoch {
            return Err(ProblemError::InvalidField {
                field: "lease.ownership_epoch",
                reason: "must be a new epoch greater than the epoch this record holds",
            });
        }
        if matches!(
            self.state,
            IncidentState::Resolved | IncidentState::AcceptedRisk | IncidentState::Superseded
        ) {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Assigned(AssignedOwnership {
            holder: grant.holder.clone(),
            lease: lease.identity().clone(),
            ownership_epoch: grant.ownership_epoch,
        });
        candidate.obligation = None;
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records a fenced owner loss and leaves the obligation visible.
    ///
    /// The promotion, its reason, its admitting authority, the source Problem
    /// link and the retained review requests all survive: losing the owner of
    /// an Incident does not soften what the Incident is. Only the assignment is
    /// cleared, and one obligation is raised. A loss naming a lease identity
    /// this record no longer holds is stale and cannot unassign the current
    /// successor.
    pub fn record_owner_loss(
        &mut self,
        expected_fence: &StateFence,
        loss: &OwnerLeaseLoss,
    ) -> Result<OwnershipObligation, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        loss.validate()?;
        let owner = self.ownership.assigned()?;
        if !loss.observed_lease.is_exactly(&owner.lease) {
            return Err(ProblemError::StaleOwnerLoss);
        }
        if matches!(
            self.state,
            IncidentState::Resolved | IncidentState::AcceptedRisk | IncidentState::Superseded
        ) {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        // An open Incident is a security/integrity-class obligation, so the
        // I13.8 default route is the System Owner/Recovery Principal rather
        // than a role the caller raising the loss picked.
        let route = OwnerRoute::SystemOwnerRecoveryPrincipal;
        let obligation = OwnershipObligation {
            obligation_id: obligation_id(self.incident_id.as_str(), route, owner.ownership_epoch)?,
            route,
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            raised_at_revision: revision,
        };
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Unassigned(UnassignedOwnership {
            last_holder: owner.holder.clone(),
            reason: loss.reason,
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            loss_evidence: loss.evidence.clone(),
            obligation: obligation.clone(),
        });
        candidate.obligation = Some(obligation.clone());
        candidate.acknowledged_by = None;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(obligation)
    }

    /// Resolves the Incident only against the independently expected set.
    ///
    /// The expected observables were fixed when the Incident was promoted, and
    /// the verifier must be independent of the current owner under the
    /// record's current fence. Repair success, a notification, or a score are
    /// not observables this can be given, so none of them closes an Incident.
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        closure: &ClosureEvidence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state != IncidentState::Verifying {
            return Err(ProblemError::IllegalTransition {
                from: format!("{:?}", self.state),
                to: "RESOLVED".to_owned(),
            });
        }
        closure.validate()?;
        let owner = self.ownership.assigned()?;
        if closure.verifier.principal == owner.holder.principal {
            return Err(ProblemError::IndependentVerifierRequired);
        }
        if closure.verifier_fence != self.state_fence {
            return Err(ProblemError::FenceMismatch);
        }
        for expected in &self.expected_resolution {
            if !closure.verified_observables.contains(expected) {
                return Err(ProblemError::UnresolvedExpectation {
                    value: expected.to_string(),
                });
            }
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.evidence_refs =
            merge_evidence(&candidate.evidence_refs, &closure.verified_observables);
        candidate.state = IncidentState::Resolved;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
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
        // The reopened record is built and validated as a candidate, so a
        // refused reopen leaves the terminal Incident exactly as it was.
        let mut candidate = self.clone();
        candidate.evidence_refs.extend(evidence);
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
        let revision = next_revision(self.revision)?;
        self.rival_claims.push(rival);
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.decision_ref = Some(decision_ref.to_owned());
        self.state = ConflictState::Resolved;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.rival_claims.push(rival);
        self.state = ConflictState::Open;
        self.decision_ref = None;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.stage = next;
        self.revision = revision;
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
///
/// Every I13.7 field is present and separately named. Delivery,
/// acknowledgement and influence are independent axes from resolution, so a
/// delivered or acknowledged record still blocks; `expected_resolution` is the
/// independently expected closure set fixed when the obligation was raised, and
/// `waiver_authority` is a principal distinct from the owner, so the owner
/// cannot waive its own obligation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticalAttention {
    pub attention_id: AttentionId,
    /// I13.7 `scope/task` the obligation applies to.
    pub scope: String,
    /// I13.7 `affected_action_classes`, the actions this blocks.
    pub affected_scope_actions: Vec<String>,
    /// I13.7 `source/evidence`.
    pub evidence_refs: Vec<ArtifactId>,
    /// I13.7 `owner`, lease-bound with an explicit unassigned state.
    pub ownership: Ownership,
    /// I13.7 `delivery_state`.
    pub delivery_state: DeliveryState,
    /// I13.7 `acknowledgement_state`.
    pub acknowledged_by: Option<String>,
    /// I13.7 `influence_state`: what the obligation is currently allowed to
    /// influence, tracked separately from whether it is resolved.
    pub influence_state: AttentionInfluence,
    /// I13.7 `resolution_state`.
    pub state: AttentionState,
    /// I13.7 `deadline_or_review`.
    pub review_condition: String,
    /// I13.7 `escalation_target`, as the closed I13.8 route.
    pub escalation_target: OwnerRoute,
    /// I13.7 `resolution_condition`, stated by the record.
    pub resolution_condition: String,
    /// The independently expected observables a resolution must cover.
    pub expected_resolution: Vec<ArtifactId>,
    /// I13.7 `waiver_authority`, a principal distinct from the owner.
    pub waiver_authority: OwnerRef,
    /// The applied waiver, retained when one exists.
    pub waiver: Option<WaiverRecord>,
    /// The accepted replacement obligation a supersession points at.
    ///
    /// Supersession must name a real accepted replacement, so blocking cannot
    /// disappear into a cycle or a nonexistent identity.
    pub superseded_by: Option<AttentionId>,
    /// The outstanding reassignment/escalation obligation while unassigned.
    pub obligation: Option<OwnershipObligation>,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// I13.7 `influence_state`: what an attention is currently allowed to affect.
///
/// It is a separate axis from resolution on purpose. An unresolved obligation
/// keeps its influence (and therefore its blocking) even after delivery and
/// acknowledgement; only a committed terminal transition removes it.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionInfluence {
    /// The obligation still blocks its affected action classes.
    Blocking,
    /// The obligation no longer influences anything, because it reached a
    /// committed terminal state.
    Released,
}

impl AttentionState {
    /// Whether this is a committed terminal state.
    ///
    /// A terminal obligation is closed; nothing reopens it, including a late
    /// acknowledgement or a reassignment.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved | Self::Waived | Self::Superseded)
    }
}

impl CriticalAttention {
    /// Validates that an attention is durable obligation state, not a toast.
    pub fn validate(&self) -> Result<(), ProblemError> {
        text(&self.scope, "scope")?;
        text(&self.review_condition, "review_condition")?;
        text(&self.resolution_condition, "resolution_condition")?;
        self.ownership.validate()?;
        self.waiver_authority.validate()?;
        fence(&self.state_fence)?;
        nonempty(&self.affected_scope_actions, "affected_scope_actions")?;
        nonempty(&self.evidence_refs, "evidence_refs")?;
        nonempty(&self.expected_resolution, "expected_resolution")?;
        unique_text(&self.affected_scope_actions, "affected_scope_actions")?;
        let evidence = self
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&evidence, "evidence_refs")?;
        let expected = self
            .expected_resolution
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        unique_text(&expected, "expected_resolution")?;
        if let Some(principal) = &self.acknowledged_by {
            owner_name(principal)?;
        }
        // The waiver authority must be a principal distinct from the owner. An
        // unassigned record has no owner to be distinct from, so the check
        // applies exactly when an owner exists.
        if let Ok(owner) = self.ownership.assigned()
            && self.waiver_authority.principal == owner.holder.principal
        {
            return Err(ProblemError::WaiverAuthorityRequired);
        }
        if let Some(waiver) = &self.waiver {
            if self.state != AttentionState::Waived {
                return Err(ProblemError::InvalidField {
                    field: "waiver",
                    reason: "a waiver is retained only on a waived obligation",
                });
            }
            waiver.validate()?;
        }
        if let Some(replacement) = &self.superseded_by {
            if self.state != AttentionState::Superseded {
                return Err(ProblemError::InvalidField {
                    field: "superseded_by",
                    reason: "a replacement is retained only on a superseded obligation",
                });
            }
            if *replacement == self.attention_id {
                return Err(ProblemError::InvalidField {
                    field: "superseded_by",
                    reason: "a supersession must name a different accepted obligation",
                });
            }
        }
        // Influence follows resolution, not delivery: an unresolved obligation
        // keeps blocking, and only a committed terminal state releases it.
        let expected_influence = if self.state.is_terminal() {
            AttentionInfluence::Released
        } else {
            AttentionInfluence::Blocking
        };
        if self.influence_state != expected_influence {
            return Err(ProblemError::InvalidField {
                field: "influence_state",
                reason: "must be Released exactly when the obligation is terminal",
            });
        }
        if self.state == AttentionState::Waived && self.waiver.is_none() {
            return Err(ProblemError::WaiverAuthorityRequired);
        }
        if self.state == AttentionState::Superseded && self.superseded_by.is_none() {
            return Err(ProblemError::InvalidField {
                field: "superseded_by",
                reason: "supersession must name the accepted replacement obligation",
            });
        }
        match (&self.ownership, &self.obligation) {
            (Ownership::Unassigned(unassigned), Some(obligation)) => {
                if *obligation != unassigned.obligation {
                    return Err(ProblemError::InvalidField {
                        field: "obligation",
                        reason: "must be the obligation raised by the retained owner loss",
                    });
                }
                Ok(())
            }
            (Ownership::Unassigned(_), None) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an unassigned attention must retain its outstanding obligation",
            }),
            (Ownership::Assigned(_), Some(_)) => Err(ProblemError::InvalidField {
                field: "obligation",
                reason: "an assigned attention retains no outstanding obligation",
            }),
            (Ownership::Assigned(_), None) => Ok(()),
        }
    }

    /// Creates a durable obligation in `Active` state with pending delivery.
    ///
    /// Creation is the first append-only transition: the record starts at
    /// revision 1 carrying the lease-backed owner, scope, evidence, review
    /// condition, escalation route, waiver authority, the independently
    /// expected closure set and the State Fence. No later transition erases the
    /// obligation or its evidence.
    ///
    /// A newly created attention has a live owner, so it retains no outstanding
    /// owner-loss obligation; `obligation` is set only by owner loss.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attention_id: AttentionId,
        scope: String,
        affected_scope_actions: Vec<String>,
        evidence_refs: Vec<ArtifactId>,
        ownership: Ownership,
        review_condition: String,
        escalation_target: OwnerRoute,
        resolution_condition: String,
        expected_resolution: Vec<ArtifactId>,
        waiver_authority: OwnerRef,
        state_fence: StateFence,
    ) -> Result<Self, ProblemError> {
        let value = Self {
            attention_id,
            scope,
            affected_scope_actions,
            evidence_refs,
            ownership,
            delivery_state: DeliveryState::Pending,
            acknowledged_by: None,
            influence_state: AttentionInfluence::Blocking,
            state: AttentionState::Active,
            review_condition,
            escalation_target,
            resolution_condition,
            expected_resolution,
            waiver_authority,
            waiver: None,
            superseded_by: None,
            obligation: None,
            state_fence,
            revision: 1,
        };
        value.validate()?;
        Ok(value)
    }

    /// Acknowledges receipt while retaining an active obligation.
    ///
    /// The caller must present the live [`AuthenticatedOwnerLease`], so
    /// acknowledgement is receipt by the lease-backed owner and nothing more.
    /// Acknowledgement never changes `state` or `influence_state`: a delivered
    /// or acknowledged notification does not close a blocking obligation.
    pub fn acknowledge(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        // A record whose owner was lost refuses every owner-scoped update, which
        // is how the lost owner stays fenced.
        let owner = self.ownership.assigned()?;
        if !lease.is_exactly(&owner.lease) || lease.holder().principal != owner.holder.principal {
            return Err(ProblemError::OwnerLeaseMismatch);
        }
        if self.state.is_terminal() {
            // A late acknowledgement cannot revive a terminal obligation.
            return Err(ProblemError::ImmutableState);
        }
        if self.delivery_state == DeliveryState::Acknowledged {
            return Ok(());
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.delivery_state = DeliveryState::Acknowledged;
        candidate.acknowledged_by = Some(owner.holder.principal.clone());
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
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
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

    /// Resolves only against the independently expected observable set.
    ///
    /// I13.7: "Blocking ends only on verified resolution, authorized waiver or
    /// supersession. Delivery/acknowledgement alone do not close." The evidence
    /// is checked against `expected_resolution`, which was fixed when the
    /// obligation was raised, and the verifier must be independent of the
    /// current owner under the record's current fence. This is the one exact
    /// line where a resolution requires evidence the closer did not choose
    /// alone: a non-empty but unrelated evidence list is refused with
    /// [`ProblemError::UnresolvedExpectation`], and the owner's own readback is
    /// refused with [`ProblemError::IndependentVerifierRequired`].
    pub fn resolve(
        &mut self,
        expected_fence: &StateFence,
        closure: &ClosureEvidence,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
        }
        closure.validate()?;
        let owner = self.ownership.assigned()?;
        if closure.verifier.principal == owner.holder.principal {
            return Err(ProblemError::IndependentVerifierRequired);
        }
        if closure.verifier_fence != self.state_fence {
            return Err(ProblemError::FenceMismatch);
        }
        for expected in &self.expected_resolution {
            if !closure.verified_observables.contains(expected) {
                return Err(ProblemError::UnresolvedExpectation {
                    value: expected.to_string(),
                });
            }
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.evidence_refs =
            merge_evidence(&candidate.evidence_refs, &closure.verified_observables);
        candidate.state = AttentionState::Resolved;
        candidate.influence_state = AttentionInfluence::Released;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Waives the obligation under a named authority distinct from the owner.
    ///
    /// The waiver records its authority, limits, expiry and residual risk, and
    /// all four are retained as a [`WaiverRecord`]. The owner cannot waive its
    /// own obligation: only the record's `waiver_authority` may, which is why
    /// `validate` refuses a record whose waiver authority is the owner.
    pub fn waive(
        &mut self,
        expected_fence: &StateFence,
        waiver: &AuthorizedWaiver,
    ) -> Result<WaiverRecord, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
        }
        waiver.validate()?;
        if waiver.authority.principal != self.waiver_authority.principal {
            return Err(ProblemError::WaiverAuthorityRequired);
        }
        let owner = self.ownership.assigned()?;
        if waiver.authority.principal == owner.holder.principal {
            return Err(ProblemError::WaiverAuthorityRequired);
        }
        let revision = next_revision(self.revision)?;
        let record = WaiverRecord {
            authority: waiver.authority.clone(),
            decision_ref: waiver.decision_ref.clone(),
            limits: waiver.limits.clone(),
            expires_at_ms: waiver.expires_at_ms,
            residual_risk: waiver.residual_risk.clone(),
            evidence: waiver.evidence.clone(),
        };
        let mut candidate = self.clone();
        candidate.evidence_refs = merge_evidence(&candidate.evidence_refs, &waiver.evidence);
        candidate.waiver = Some(record.clone());
        candidate.state = AttentionState::Waived;
        candidate.influence_state = AttentionInfluence::Released;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(record)
    }

    /// Supersedes the obligation onto an accepted replacement.
    ///
    /// The replacement must be a different attention that is itself still live,
    /// so blocking cannot disappear into a cycle or a nonexistent identity: the
    /// blocking action set moves to a real, inspectable record rather than
    /// evaporating. A terminal record is never reopened by supersession.
    pub fn supersede(
        &mut self,
        expected_fence: &StateFence,
        replacement: &CriticalAttention,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
        }
        replacement.validate()?;
        if replacement.attention_id == self.attention_id {
            return Err(ProblemError::InvalidField {
                field: "superseded_by",
                reason: "a supersession must name a different accepted obligation",
            });
        }
        if replacement.state.is_terminal() {
            return Err(ProblemError::InvalidField {
                field: "superseded_by",
                reason: "the replacement obligation must still be live",
            });
        }
        if replacement.superseded_by.as_ref() == Some(&self.attention_id) {
            return Err(ProblemError::InvalidField {
                field: "superseded_by",
                reason: "the replacement already supersedes this obligation",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.state = AttentionState::Superseded;
        candidate.influence_state = AttentionInfluence::Released;
        candidate.superseded_by = Some(replacement.attention_id.clone());
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Assigns an eligible successor under a newly issued ownership lease.
    ///
    /// The successor is named by the lease owner, not by the caller: a caller
    /// holding only a principal string cannot reach this entry. The lease must
    /// still be current at `now_ms`, the grant's ownership epoch must exceed the
    /// epoch currently held, and the grant must be bound to the record's live
    /// fence, so a renewal is a new epoch rather than a reuse. The blocking
    /// action set is retained in full.
    ///
    /// This is also the reassignment half of the fenced owner-loss workflow, so
    /// it is admitted on an already-unassigned record: the blocking actions, the
    /// evidence, the review condition and the expected closure set all survive
    /// and only the expired assignment is replaced.
    pub fn assign_owner(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
        now_ms: u64,
    ) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
        }
        let grant = lease.grant();
        if !lease.is_current_at(now_ms) {
            return Err(ProblemError::OwnerLeaseNotCurrent);
        }
        if !lease.is_bound_to(&self.state_fence) {
            return Err(ProblemError::FenceMismatch);
        }
        let current_epoch = self.ownership.retained_epoch();
        if grant.ownership_epoch <= current_epoch {
            return Err(ProblemError::InvalidField {
                field: "lease.ownership_epoch",
                reason: "must be a new epoch greater than the epoch this record holds",
            });
        }
        let revision = next_revision(self.revision)?;
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Assigned(AssignedOwnership {
            holder: grant.holder.clone(),
            lease: lease.identity().clone(),
            ownership_epoch: grant.ownership_epoch,
        });
        candidate.obligation = None;
        candidate.acknowledged_by = None;
        candidate.delivery_state = DeliveryState::Pending;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Records a fenced owner loss and leaves the obligation visible.
    ///
    /// Only the assignment is cleared: the blocking action set, the obligation
    /// text, the evidence, the review condition and the expected closure set all
    /// survive, and the obligation escalates through the record's own recorded
    /// [`OwnerRoute`]. A loss naming a lease identity this record no longer
    /// holds is stale and cannot unassign the current successor. A terminal
    /// record is preserved rather than reopened.
    pub fn record_owner_loss(
        &mut self,
        expected_fence: &StateFence,
        loss: &OwnerLeaseLoss,
    ) -> Result<OwnershipObligation, ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        loss.validate()?;
        let owner = self.ownership.assigned()?;
        if !loss.observed_lease.is_exactly(&owner.lease) {
            return Err(ProblemError::StaleOwnerLoss);
        }
        if self.state.is_terminal() {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        let obligation = OwnershipObligation {
            obligation_id: obligation_id(
                self.attention_id.as_str(),
                self.escalation_target,
                owner.ownership_epoch,
            )?,
            route: self.escalation_target,
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            raised_at_revision: revision,
        };
        // The one exact line where owner loss produces a visible obligation and
        // fences that owner: the assignment is replaced by an unassigned state
        // naming the fenced holder, the retained loss evidence and this
        // obligation, while the blocking action set is kept intact.
        let mut candidate = self.clone();
        candidate.ownership = Ownership::Unassigned(UnassignedOwnership {
            last_holder: owner.holder.clone(),
            reason: loss.reason,
            lost_lease: Some(owner.lease.clone()),
            ownership_epoch: owner.ownership_epoch,
            loss_evidence: loss.evidence.clone(),
            obligation: obligation.clone(),
        });
        candidate.obligation = Some(obligation.clone());
        candidate.acknowledged_by = None;
        candidate.state = AttentionState::Escalated;
        candidate.revision = revision;
        candidate.validate()?;
        *self = candidate;
        Ok(obligation)
    }

    /// Applies review-condition expiry: the obligation escalates via the
    /// recorded route to a new owner and fence, retaining the prior obligation
    /// and evidence. The record remains inspectable; expiry never deletes it.
    ///
    /// The new owner is still an [`AuthenticatedOwnerLease`], so escalation
    /// cannot hand the obligation to a name the caller supplied.
    pub fn expire(
        &mut self,
        expected_fence: &StateFence,
        lease: &AuthenticatedOwnerLease,
        now_ms: u64,
    ) -> Result<(), ProblemError> {
        self.assign_owner(expected_fence, lease, now_ms)?;
        if self.state != AttentionState::Escalated {
            let revision = next_revision(self.revision)?;
            let mut candidate = self.clone();
            candidate.state = AttentionState::Escalated;
            candidate.revision = revision;
            candidate.validate()?;
            *self = candidate;
        }
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
        let revision = next_revision(self.revision)?;
        self.state = RecoveryProfileState::Satisfied;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.state = ChallengeState::UnderReview;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.state = ChallengeState::Accepted;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.state = ChallengeState::Rejected;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.outcome_ref = Some(outcome_ref.to_owned());
        self.state = DeviationState::Promoted;
        self.revision = revision;
        Ok(())
    }

    /// Rejects an active deviation without deleting its evidence.
    pub fn reject(&mut self, expected_fence: &StateFence) -> Result<(), ProblemError> {
        same_fence(expected_fence, &self.state_fence)?;
        if self.state != DeviationState::Active {
            return Err(ProblemError::ImmutableState);
        }
        let revision = next_revision(self.revision)?;
        self.state = DeviationState::Rejected;
        self.revision = revision;
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
        let revision = next_revision(self.revision)?;
        self.outcome_ref = Some(outcome_ref.to_owned());
        self.state = DeviationState::Expired;
        self.revision = revision;
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
            "problem_class": schemars::schema_for!(ProblemClass),
            "problem_hypothesis": schemars::schema_for!(ProblemHypothesis),
            "repair_record": schemars::schema_for!(RepairRecord),
            "reopen_record": schemars::schema_for!(ReopenRecord),
            "ownership": schemars::schema_for!(Ownership),
            "assigned_ownership": schemars::schema_for!(AssignedOwnership),
            "unassigned_ownership": schemars::schema_for!(UnassignedOwnership),
            "owner_lease_grant": schemars::schema_for!(OwnerLeaseGrant),
            "lease_identity": schemars::schema_for!(LeaseIdentity),
            "owner_lease_loss": schemars::schema_for!(OwnerLeaseLoss),
            "owner_loss_reason": schemars::schema_for!(OwnerLossReason),
            "owner_route": schemars::schema_for!(OwnerRoute),
            "ownership_obligation": schemars::schema_for!(OwnershipObligation),
            "closure_evidence": schemars::schema_for!(ClosureEvidence),
            "authorized_waiver": schemars::schema_for!(AuthorizedWaiver),
            "waiver_record": schemars::schema_for!(WaiverRecord),
            "incident": schemars::schema_for!(Incident),
            "incident_reason": schemars::schema_for!(IncidentReason),
            "incident_promotion": schemars::schema_for!(IncidentPromotion),
            "incident_promotion_authority": schemars::schema_for!(PromotionAuthority),
            "incident_review_request": schemars::schema_for!(IncidentReviewRequest),
            "attention_influence": schemars::schema_for!(AttentionInfluence),
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

    /// The lease owner's own commitment store, standing in for the real issuer.
    struct TestIssuer {
        grants: Vec<OwnerLeaseGrant>,
    }

    impl OwnerLeaseIssuer for TestIssuer {
        fn commitment_for(&self, grant: &OwnerLeaseGrant) -> Option<String> {
            if self.grants.contains(grant) {
                grant.expected_commitment().ok()
            } else {
                None
            }
        }
    }

    fn lease_for(
        principal: &str,
        fence: &StateFence,
        epoch: u64,
    ) -> Result<AuthenticatedOwnerLease, ProblemError> {
        let grant = OwnerLeaseGrant {
            lease_id: format!("lease-{principal}-{epoch}"),
            holder: OwnerRef {
                principal: principal.to_owned(),
                generation: format!("generation-{epoch}"),
            },
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            ownership_epoch: epoch,
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
        };
        let issuer = TestIssuer {
            grants: vec![grant.clone()],
        };
        AuthenticatedOwnerLease::authenticate(&grant, &issuer)
    }

    fn signal() -> Result<Signal, ProblemError> {
        Ok(Signal {
            signal_id: SignalId::new("signal-1")?,
            rule_id: "rule-1".to_owned(),
            severity: SignalSeverity::Blocking,
            subject: "subject-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            observed_at: ClockReading::default(),
            evidence_handles: vec![artifact("evidence-1")?],
            observation: None,
            attribution: SignalAttribution::Known,
            processing_state: SignalProcessingState::Observed,
            delivery_state: DeliveryState::Pending,
            disposition: SignalDisposition::ProblemCandidate,
            dedup_key: "dedup-1".to_owned(),
            reopen_condition: "recurrence".to_owned(),
            state_fence: state_fence(),
        })
    }

    fn problem() -> Result<Problem, ProblemError> {
        let fence = state_fence();
        let lease = lease_for("owner-1", &fence, 1)?;
        Problem::new(
            ProblemId::new("problem-1")?,
            &signal()?,
            ProblemClass::Operational,
            "repeated failure".to_owned(),
            "the route fails repeatedly".to_owned(),
            "scope-1".to_owned(),
            vec!["dependency-1".to_owned()],
            Vec::new(),
            &lease,
            Vec::new(),
            "next probe".to_owned(),
            "verifier evidence".to_owned(),
            vec![artifact("evidence-2")?],
            fence,
        )
    }

    fn closure(fence: &StateFence, verifier: &str, refs: Vec<ArtifactId>) -> ClosureEvidence {
        ClosureEvidence {
            verifier: OwnerRef {
                principal: verifier.to_owned(),
                generation: "verifier-generation".to_owned(),
            },
            verifier_fence: fence.clone(),
            verified_subject: "subject-1".to_owned(),
            verified_observables: refs,
        }
    }

    #[test]
    fn acknowledgement_is_not_resolution() -> Result<(), ProblemError> {
        let fence = state_fence();
        let lease = lease_for("owner-1", &fence, 1)?;
        let mut value = problem()?;
        value.acknowledge(&fence, &lease)?;
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
        value.resolve(
            &fence,
            &closure(&fence, "verifier-1", vec![artifact("evidence-2")?]),
        )?;
        assert!(matches!(
            value.reopen(&fence, Vec::new()),
            Err(ProblemError::ReopenRequiresEvidence)
        ));
        value.reopen(&fence, vec![artifact("evidence-3")?])?;
        assert_eq!(value.state, ProblemState::Open);
        assert_eq!(value.reopen_count, 1);
        assert_eq!(value.reopen_history.len(), 1);
        assert_eq!(value.acknowledged_by, None);
        Ok(())
    }

    #[test]
    fn owner_reassignment_fences_old_owner() -> Result<(), ProblemError> {
        let old_fence = state_fence();
        let new_fence =
            StateFence::new(test_epoch(TEST_LINEAGE_A, 2), ResourceGeneration::genesis());
        let old_lease = lease_for("owner-1", &old_fence, 1)?;
        let new_lease = lease_for("owner-2", &new_fence, 2)?;
        let mut value = problem()?;
        value.assign_owner(&old_fence, &new_lease, 1_500)?;
        assert!(matches!(
            value.acknowledge(&old_fence, &old_lease),
            Err(ProblemError::FenceMismatch)
        ));
        value.acknowledge(&new_fence, &new_lease)?;
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
