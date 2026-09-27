//! The evidence-to-disposition boundary between `InstrumentRunner` and
//! `FinishService`.
//!
//! The two sides are kept apart by construction:
//!
//! ```text
//! InstrumentRunner side
//!   EvidenceOutcome / EvidenceProof / EvidenceReceipt
//!     what was measured, in which scope, and with which outcome; nothing
//!     else.  The receipt type has no completion, acceptance, or task-verdict
//!     field, so it cannot carry one.
//!
//! FinishService side
//!   AcceptanceOracle / DeclaredAcceptance / TaskOutcome / FinishDisposition
//!     the declared acceptance contract, its authority, and the task outcome
//!     derived from evidence under that contract.  Only this side produces a
//!     task outcome.
//! ```
//!
//! Rules this module makes structural instead of advisory (`I18.24`,
//! `I10.8.4`, `I18.27`, `I18.23`, `I2.17`):
//!
//! ```text
//! a declared required proof the receipt never observed is a missing required
//!   stage (`I18.24`), so silence is neither a pass nor an absence;
//! `UNKNOWN`, `PARTIAL` and `BLOCKED` never become PASS through aggregation:
//!   `TaskOutcome::Pass` holds a `RequiredProofCompletion`, whose field is
//!   private and obtainable only from `RequiredProofCompletion::prove`, which
//!   refuses any declared required proof that is not PASS and names it;
//! every acceptance oracle carries an owner and an origin, and a declared
//!   acceptance without a required oracle is rejected, so there is no vacuous
//!   pass;
//! the required set comes from the acceptance declaration and is never
//!   derived from what a verifier happened to check;
//! a disputed discriminator is returned as a typed `ContractChallenge` before
//!   any disposition is derived, preserving the conflicting observation.  This
//!   module holds no mutable state and exposes no setter, so it cannot
//!   rewrite a discriminator, oracle, expectation, or tolerance to accept a
//!   candidate.
//! ```
//!
//! This module owns no task state, no scheduler, and no process.  It is the
//! boundary contract `FinishService` consumes; task completion itself remains
//! with `FinishService` (`I18.1`, `I10.8.4`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PlanError, plan_text};

/// One evidence outcome, with exactly the meanings `I18.24` gives it.
///
/// These are distinct observations.  None of them is a task outcome, and a
/// passing crate-local observation is a fact about the crate contract, not
/// about task completion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EvidenceOutcome {
    /// The property is proven in the declared scope.
    Pass,
    /// A contradictory observation, or a required stage that is missing.
    Fail,
    /// Some required scope was measured and some is explicitly uncovered.
    Partial,
    /// Tool, parser, freshness, or coverage cannot answer.
    Unknown,
    /// Policy, environment, or capability prevents the required proof.
    Blocked,
    /// No further effect; prior evidence is retained.
    Cancelled,
}

impl EvidenceOutcome {
    /// Whether this outcome proves its declared scope.  `PARTIAL`, `UNKNOWN`,
    /// `BLOCKED`, `CANCELLED`, and `FAIL` never do, and no aggregation may
    /// turn one of them into a pass.
    #[must_use]
    pub const fn is_proven_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// The source of authority behind one acceptance oracle (`I18.27`).
///
/// A test author may encode an oracle but cannot create its authority by
/// assertion, so the origin is part of the declared type rather than prose.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum OracleOrigin {
    /// Architecture or implementation contract.
    ArchitectureContract,
    /// External standard or exact source.
    ExternalStandardOrSource,
    /// Accepted Human or domain decision.
    AcceptedDecision,
    /// Registered deterministic evaluator.
    DeterministicEvaluator,
    /// Previously accepted artifact baseline.
    AcceptedArtifactBaseline,
}

/// Declared acceptance criticality of one oracle.
///
/// The criticality is a declaration made by the acceptance contract, and the
/// boundary applies it: a `Required` oracle gates the task outcome, and an
/// `Advisory` oracle is recorded without ever gating it or being promoted
/// into required evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AcceptanceCriticality {
    /// The task outcome cannot pass while this oracle is not proven.
    Required,
    /// The oracle is reported; it neither gates nor widens acceptance.
    Advisory,
}

/// Typed failures of the boundary.
///
/// Each rejection keeps its typed cause.  A contract challenge is not one of
/// these: it is a returned value ([`ContractChallenge`]) handed back instead
/// of a disposition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DispositionError {
    /// The acceptance declaration named no oracle at all.
    #[error("declared acceptance must name at least one oracle")]
    EmptyAcceptance,
    /// The acceptance declaration named no required oracle, which would make
    /// every task outcome vacuously passing.
    #[error("declared acceptance must name at least one required oracle")]
    NoRequiredOracle,
    /// One proof identity was declared twice with different owners, origins,
    /// or criticalities.
    #[error("duplicate declared acceptance oracle: {proof_id}")]
    DuplicateOracle { proof_id: String },
    /// One proof identity occurs more than once in a receipt; one measurement
    /// speaks once.
    #[error("duplicate proof identity in evidence receipt: {proof_id}")]
    DuplicateProof { proof_id: String },
    /// A declared required proof is not proven, so no completion exists.  The
    /// proof is named with the outcome that was actually observed for it.
    #[error("required proof {proof_id} is not PASS: {outcome:?}")]
    RequiredProofNotPassed {
        /// Declared proof identity that is not proven.
        proof_id: String,
        /// Outcome observed for it; a proof the receipt never observed is
        /// reported as [`EvidenceOutcome::Fail`], a missing required stage.
        outcome: EvidenceOutcome,
    },
    /// A challenge was raised against a discriminator the acceptance
    /// declaration never declared, so there is no oracle to challenge.
    #[error("no declared acceptance oracle for proof: {proof_id}")]
    UndeclaredProof { proof_id: String },
    /// An identifier was rejected by this crate's shared text validation.
    #[error(transparent)]
    Plan(#[from] PlanError),
}

/// One acceptance oracle bound to its owner, its origin, and its declared
/// criticality (`I18.27`).
///
/// Owner and origin are required at construction: there is no oracle without
/// an accountable owner and a named source of authority, and no defaulted
/// value that could mint either by assertion.
// `Deserialize` is absent so that an owner and an origin cannot be minted by
// deserializing an untrusted acceptance document; both are required at
// construction by the checked constructor.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AcceptanceOracle {
    proof_id: String,
    owner: String,
    origin: OracleOrigin,
    criticality: AcceptanceCriticality,
}

impl AcceptanceOracle {
    /// Declares one acceptance oracle.  Blank identities are rejected rather
    /// than defaulted.
    pub fn new(
        proof_id: &str,
        owner: &str,
        origin: OracleOrigin,
        criticality: AcceptanceCriticality,
    ) -> Result<Self, DispositionError> {
        let oracle = Self {
            proof_id: proof_id.to_owned(),
            owner: owner.to_owned(),
            origin,
            criticality,
        };
        oracle.validate()?;
        Ok(oracle)
    }

    /// Declares an acceptance oracle that gates the task outcome.
    pub fn required(
        proof_id: &str,
        owner: &str,
        origin: OracleOrigin,
    ) -> Result<Self, DispositionError> {
        Self::new(proof_id, owner, origin, AcceptanceCriticality::Required)
    }

    fn validate(&self) -> Result<(), DispositionError> {
        plan_text(&self.proof_id, "oracle.proof_id")?;
        plan_text(&self.owner, "oracle.owner")?;
        Ok(())
    }

    /// Exact discriminator or proof identity this oracle governs.
    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    /// Owner accountable for this oracle.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Source of authority for this oracle.
    #[must_use]
    pub fn origin(&self) -> OracleOrigin {
        self.origin
    }

    /// Declared criticality the boundary applies to this oracle.
    #[must_use]
    pub fn criticality(&self) -> AcceptanceCriticality {
        self.criticality
    }
}

/// One observed proof outcome emitted by `InstrumentRunner`.
///
/// The observation names what was measured and the outcome it produced.  It
/// carries no verdict about the task, the candidate, or acceptance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EvidenceProof {
    proof_id: String,
    outcome: EvidenceOutcome,
}

impl EvidenceProof {
    /// Records one observed proof outcome.
    pub fn new(proof_id: &str, outcome: EvidenceOutcome) -> Result<Self, DispositionError> {
        let proof = Self {
            proof_id: proof_id.to_owned(),
            outcome,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(&self) -> Result<(), DispositionError> {
        plan_text(&self.proof_id, "proof.proof_id")?;
        Ok(())
    }

    /// Identity of the proof that was measured.
    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    /// Outcome actually observed for that proof.
    #[must_use]
    pub fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }
}

/// The only value `InstrumentRunner` hands to the acceptance boundary.
///
/// This receipt exists to report evidence and its provenance.  By
/// construction it has no completion, acceptance, or task-verdict field: a
/// passing crate-local receipt is a fact about the crate contract, and the
/// task outcome is produced by [`apply_finish_boundary`] on the `FinishService`
/// side of the boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    receipt_id: String,
    proofs: Vec<EvidenceProof>,
}

impl EvidenceReceipt {
    /// Binds observed proof outcomes into one evidence receipt.
    pub fn new(receipt_id: &str, proofs: Vec<EvidenceProof>) -> Result<Self, DispositionError> {
        let receipt = Self {
            receipt_id: receipt_id.to_owned(),
            proofs,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), DispositionError> {
        plan_text(&self.receipt_id, "receipt.receipt_id")?;
        let mut seen = BTreeSet::new();
        for proof in &self.proofs {
            proof.validate()?;
            if !seen.insert(proof.proof_id.as_str()) {
                return Err(DispositionError::DuplicateProof {
                    proof_id: proof.proof_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Identity of the run that produced this receipt.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Every observation the run recorded, in reported order.
    #[must_use]
    pub fn proofs(&self) -> &[EvidenceProof] {
        &self.proofs
    }

    /// Outcome observed for one proof identity, or `None` when the run never
    /// observed that proof.  `None` is an unknown measurement, never an
    /// absent requirement.
    #[must_use]
    pub fn outcome_of(&self, proof_id: &str) -> Option<EvidenceOutcome> {
        self.proofs
            .iter()
            .find(|proof| proof.proof_id == proof_id)
            .map(EvidenceProof::outcome)
    }
}

/// One declared oracle with the outcome observed for it.
///
/// The record is authored by the boundary alone: a caller cannot construct an
/// observation that the declared acceptance never produced.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OracleObservation {
    proof_id: String,
    outcome: EvidenceOutcome,
    owner: String,
    origin: OracleOrigin,
    criticality: AcceptanceCriticality,
}

impl OracleObservation {
    fn of(oracle: &AcceptanceOracle, outcome: EvidenceOutcome) -> Self {
        Self {
            proof_id: oracle.proof_id.clone(),
            outcome,
            owner: oracle.owner.clone(),
            origin: oracle.origin,
            criticality: oracle.criticality,
        }
    }

    /// Identity of the declared oracle.
    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    /// Outcome observed for that oracle.
    #[must_use]
    pub fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }

    /// Owner of the oracle that produced the observation.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Origin of the oracle that produced the observation.
    #[must_use]
    pub fn origin(&self) -> OracleOrigin {
        self.origin
    }

    /// Criticality under which the boundary considered the oracle.
    #[must_use]
    pub fn criticality(&self) -> AcceptanceCriticality {
        self.criticality
    }
}

/// One required oracle proven in its declared scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProvenRequiredProof {
    proof_id: String,
    owner: String,
    origin: OracleOrigin,
}

impl ProvenRequiredProof {
    /// Identity of the proven required oracle.
    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    /// Owner accountable for the proven oracle.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Origin of the proven oracle.
    #[must_use]
    pub fn origin(&self) -> OracleOrigin {
        self.origin
    }
}

/// Proof that every declared required oracle is proven.
///
/// This is the payload of [`TaskOutcome::Pass`] and its field is private, so
/// the only way to obtain one is [`RequiredProofCompletion::prove`].  That
/// function refuses any declared required proof that is not `PASS` and names
/// it, which makes an aggregate `PASS` unrepresentable whenever a required
/// proof is `UNKNOWN`, `PARTIAL`, or `BLOCKED` (`I18.24`) — including a
/// passing crate-local receipt alongside a required live proof that is
/// `BLOCKED`.
// `Deserialize` is deliberately absent: a derived impl would rebuild this
// value straight from untrusted bytes and hand every caller a `Pass` for a
// required proof that was never proven, which is the promotion this boundary
// exists to refuse.  A value read back from storage is re-proved instead.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RequiredProofCompletion {
    required: Vec<ProvenRequiredProof>,
}

impl RequiredProofCompletion {
    /// Proves that every declared required oracle is `PASS` under the given
    /// acceptance declaration and evidence receipt.
    ///
    /// A required proof the receipt never observed is a missing required
    /// stage, which `I18.24` classes as [`EvidenceOutcome::Fail`].  The first
    /// required proof that is not proven is returned as
    /// [`DispositionError::RequiredProofNotPassed`] with its identity and the
    /// outcome actually observed for it.
    pub fn prove(
        acceptance: &DeclaredAcceptance,
        receipt: &EvidenceReceipt,
    ) -> Result<Self, DispositionError> {
        acceptance.validate()?;
        receipt.validate()?;
        let mut required = Vec::new();
        for oracle in acceptance.oracles() {
            if oracle.criticality() != AcceptanceCriticality::Required {
                continue;
            }
            let outcome = observed_outcome(oracle, receipt);
            if !outcome.is_proven_pass() {
                return Err(DispositionError::RequiredProofNotPassed {
                    proof_id: oracle.proof_id().to_owned(),
                    outcome,
                });
            }
            required.push(ProvenRequiredProof {
                proof_id: oracle.proof_id().to_owned(),
                owner: oracle.owner().to_owned(),
                origin: oracle.origin(),
            });
        }
        Ok(Self { required })
    }

    /// Every required oracle that is proven, in declaration order.
    #[must_use]
    pub fn required_proofs(&self) -> &[ProvenRequiredProof] {
        &self.required
    }
}

/// The declared acceptance contract of one task: the authority entitled to
/// accept it and the oracles that authority requires.
///
/// The oracle set is declared here.  It is never derived from what a verifier
/// happened to check, and it is never widened by a run that observed more
/// proofs than acceptance required.
// `Deserialize` is absent for the same reason as on `AcceptanceOracle`: the
// declared oracle set is authority, and only the checked constructor may
// establish it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DeclaredAcceptance {
    authority: String,
    oracles: Vec<AcceptanceOracle>,
}

impl DeclaredAcceptance {
    /// Declares the acceptance authority and its oracles.
    ///
    /// A declaration with no oracle, with a repeated proof identity, or with
    /// no required oracle is rejected: an empty acceptance would turn every
    /// task outcome into a vacuous pass.
    pub fn new(authority: &str, oracles: Vec<AcceptanceOracle>) -> Result<Self, DispositionError> {
        let acceptance = Self {
            authority: authority.to_owned(),
            oracles,
        };
        acceptance.validate()?;
        Ok(acceptance)
    }

    /// Rejects a declaration that cannot authorize an honest outcome.
    pub fn validate(&self) -> Result<(), DispositionError> {
        plan_text(&self.authority, "acceptance.authority")?;
        if self.oracles.is_empty() {
            return Err(DispositionError::EmptyAcceptance);
        }
        let mut seen = BTreeSet::new();
        let mut required = 0_usize;
        for oracle in &self.oracles {
            oracle.validate()?;
            if !seen.insert(oracle.proof_id.as_str()) {
                return Err(DispositionError::DuplicateOracle {
                    proof_id: oracle.proof_id.clone(),
                });
            }
            if oracle.criticality == AcceptanceCriticality::Required {
                required = required.saturating_add(1);
            }
        }
        if required == 0 {
            return Err(DispositionError::NoRequiredOracle);
        }
        Ok(())
    }

    /// Authority entitled to accept the claimed outcome (`I18.23`: the
    /// Requester or domain owner; the Task Controller may only propose
    /// within its delegated acceptance contract).
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Every declared oracle, in declaration order.
    #[must_use]
    pub fn oracles(&self) -> &[AcceptanceOracle] {
        &self.oracles
    }

    /// Exact declared oracle for one proof identity, if declared.
    #[must_use]
    pub fn oracle(&self, proof_id: &str) -> Option<&AcceptanceOracle> {
        self.oracles
            .iter()
            .find(|oracle| oracle.proof_id == proof_id)
    }
}

/// The task outcome resolved from evidence under a declared acceptance.
///
/// [`TaskOutcome::Pass`] is reachable only by holding a
/// [`RequiredProofCompletion`], which exists only when every declared required
/// oracle is proven.  A non-passing or unobserved required proof therefore
/// yields [`TaskOutcome::NotPassed`] with that proof named.
// As with `RequiredProofCompletion`, `Deserialize` is deliberately absent so
// no byte stream can mint a `Pass`.  A disposition read back from storage is
// re-derived through `apply_finish_boundary`, never trusted as-is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum TaskOutcome {
    /// Every declared required oracle is proven in its declared scope.
    Pass {
        /// The required oracles that are proven, with their owners and
        /// origins.
        completion: RequiredProofCompletion,
    },
    /// At least one declared required proof is not proven.  Every such proof
    /// is named with its outcome, owner, and origin, so a `BLOCKED` required
    /// live proof appears here even when a crate-local receipt passed.
    NotPassed {
        /// Required proofs that are not proven, in declaration order.
        non_passing: Vec<OracleObservation>,
    },
}

/// Why the boundary returns a challenge instead of proceeding.
///
/// These are the documented triggers for challenging a brief or
/// discriminator (`I2.17`, `I10.4`, `I17.14`, `I18.23`, `I18.27`).  An
/// unclassified cause is a typed error, never free prose.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ContractChallengeReason {
    /// The owner named by the brief is wrong for the property.
    WrongOwner,
    /// The discriminator does not fail on the old production path, so it
    /// cannot distinguish the candidate.
    DiscriminatorDoesNotFailOnOldPath,
    /// The declared contract is contradictory for this candidate.
    ContradictoryContract,
    /// The oracle would need a hidden change to accept the candidate.
    HiddenOracleChangeRequired,
    /// The oracle is controlled by the same patch as the candidate, so it
    /// cannot be independent evidence.
    OracleControlledByCandidate,
}

/// A typed refusal to optimize to a malformed or disputed discriminator.
///
/// Returning a challenge is how this boundary declines a discriminator
/// (`I18.23`).  The challenge preserves the conflicting observation and the
/// declared owner and origin so an independent route can decide (`I18.27`,
/// `I18.31`), and it is a value rather than a rewrite: nothing in this module
/// alters a discriminator, oracle, expectation, or tolerance to accept a
/// candidate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ContractChallenge {
    proof_id: String,
    reason: ContractChallengeReason,
    observation: EvidenceOutcome,
    owner: String,
    origin: OracleOrigin,
}

impl ContractChallenge {
    /// Raises a challenge against a declared discriminator.
    ///
    /// The challenge is bound to the declared oracle, so it cannot name an
    /// oracle that acceptance never declared and cannot carry an owner or
    /// origin of its own.
    pub fn against(
        acceptance: &DeclaredAcceptance,
        proof_id: &str,
        reason: ContractChallengeReason,
        observation: EvidenceOutcome,
    ) -> Result<Self, DispositionError> {
        acceptance.validate()?;
        let oracle =
            acceptance
                .oracle(proof_id)
                .ok_or_else(|| DispositionError::UndeclaredProof {
                    proof_id: proof_id.to_owned(),
                })?;
        let challenge = Self {
            proof_id: oracle.proof_id.clone(),
            reason,
            observation,
            owner: oracle.owner.clone(),
            origin: oracle.origin,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    fn validate(&self) -> Result<(), DispositionError> {
        plan_text(&self.proof_id, "challenge.proof_id")?;
        plan_text(&self.owner, "challenge.owner")?;
        Ok(())
    }

    /// Declared discriminator this challenge disputes.
    #[must_use]
    pub fn proof_id(&self) -> &str {
        &self.proof_id
    }

    /// Documented trigger for the challenge.
    #[must_use]
    pub fn reason(&self) -> ContractChallengeReason {
        self.reason
    }

    /// The conflicting observation, preserved rather than discarded.
    #[must_use]
    pub fn observation(&self) -> EvidenceOutcome {
        self.observation
    }

    /// Owner of the disputed oracle.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Origin of the disputed oracle.
    #[must_use]
    pub fn origin(&self) -> OracleOrigin {
        self.origin
    }
}

/// The disposition `FinishService` reaches for one task.
///
/// It names the acceptance authority it acted under, the origin of every
/// declared oracle it applied, the receipt it read, and the task outcome.  A
/// disposition is a `FinishService` value; no receipt can carry one.
// `Deserialize` is absent for the same reason as on `TaskOutcome`: this type
// embeds the outcome, so a derived impl would restore a `Pass` for evidence
// that was never proven.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FinishDisposition {
    receipt_id: String,
    authority: String,
    outcome: TaskOutcome,
    oracle_origins: BTreeMap<String, OracleOrigin>,
    advisory: Vec<OracleObservation>,
}

impl FinishDisposition {
    /// Identity of the evidence receipt this disposition was derived from.
    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Acceptance authority the disposition acted under.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The task outcome.
    #[must_use]
    pub fn outcome(&self) -> &TaskOutcome {
        &self.outcome
    }

    /// Origin of every declared oracle, by proof identity.
    #[must_use]
    pub fn oracle_origins(&self) -> &BTreeMap<String, OracleOrigin> {
        &self.oracle_origins
    }

    /// Declared advisory oracles with the outcome observed for each.  They
    /// are reported and never gate the outcome.
    #[must_use]
    pub fn advisory(&self) -> &[OracleObservation] {
        &self.advisory
    }
}

/// What the boundary returns: either a disposition, or the challenge that
/// replaced it.
// `Deserialize` is absent because this response carries the disposition, and
// the disposition must be re-derived through the boundary rather than read
// back as a trusted verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FinishBoundaryResponse {
    /// A disposition was derived from the evidence.
    Disposition(FinishDisposition),
    /// The brief or discriminator was disputed, so no disposition was
    /// derived and no test was rewritten.
    ContractChallenge(ContractChallenge),
}

/// Applies the evidence-to-disposition boundary for one task.
///
/// The order is deliberate.  A declared dispute of the discriminator is
/// returned as a [`ContractChallenge`] before any disposition is derived, so
/// a disputed oracle can never produce a disposition.  Otherwise the
/// disposition follows the declared acceptance contract:
///
/// ```text
/// a required proof the receipt never observed is a missing required stage;
/// any declared required proof that is not PASS keeps the task outcome
///   non-passing and names that proof, with the outcome actually observed;
/// a passing crate-local receipt therefore never promotes a task whose
///   required live proof is BLOCKED, PARTIAL, or UNKNOWN;
/// the required set is the declared one, not the set a verifier happened to
///   check;
/// every disposition names its acceptance authority and the origin of every
///   oracle it applied.
/// ```
pub fn apply_finish_boundary(
    acceptance: &DeclaredAcceptance,
    receipt: &EvidenceReceipt,
    challenge: Option<ContractChallenge>,
) -> Result<FinishBoundaryResponse, DispositionError> {
    acceptance.validate()?;
    receipt.validate()?;
    if let Some(challenge) = challenge {
        return Ok(FinishBoundaryResponse::ContractChallenge(challenge));
    }
    Ok(FinishBoundaryResponse::Disposition(finish_disposition(
        acceptance, receipt,
    )?))
}

/// The outcome observed for one declared oracle.
///
/// A required proof the receipt never observed is a missing required stage,
/// which `I18.24` classes as [`EvidenceOutcome::Fail`]: silence is neither a
/// pass nor an absent requirement.
fn observed_outcome(oracle: &AcceptanceOracle, receipt: &EvidenceReceipt) -> EvidenceOutcome {
    receipt
        .outcome_of(oracle.proof_id())
        .unwrap_or(EvidenceOutcome::Fail)
}

/// Derives the disposition for evidence that is not disputed.
fn finish_disposition(
    acceptance: &DeclaredAcceptance,
    receipt: &EvidenceReceipt,
) -> Result<FinishDisposition, DispositionError> {
    let mut oracle_origins = BTreeMap::new();
    let mut non_passing = Vec::new();
    let mut advisory = Vec::new();
    for oracle in acceptance.oracles() {
        oracle_origins.insert(oracle.proof_id().to_owned(), oracle.origin());
        let observation = OracleObservation::of(oracle, observed_outcome(oracle, receipt));
        match oracle.criticality() {
            AcceptanceCriticality::Required => {
                if !observation.outcome.is_proven_pass() {
                    non_passing.push(observation);
                }
            }
            AcceptanceCriticality::Advisory => advisory.push(observation),
        }
    }
    let outcome = if non_passing.is_empty() {
        TaskOutcome::Pass {
            completion: RequiredProofCompletion::prove(acceptance, receipt)?,
        }
    } else {
        TaskOutcome::NotPassed { non_passing }
    };
    Ok(FinishDisposition {
        receipt_id: receipt.receipt_id().to_owned(),
        authority: acceptance.authority().to_owned(),
        outcome,
        oracle_origins,
        advisory,
    })
}
