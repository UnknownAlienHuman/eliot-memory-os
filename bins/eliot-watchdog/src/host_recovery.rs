//! Private Watchdog Host-recovery cell: bounded identity recheck, fenced
//! recovery intent, stop/start reconciliation, and the correlated dual audit
//! record (issue #1757).
//!
//! Architecture: A8.1 (`docs/architecture/A08-01-purpose.md`), A13.2
//! (`docs/architecture/A13-02-kernel-and-failure-domains.md`), ARCH-WDG-01,
//! ARCH-WDG-02.
//! Implementation: I8.3 (`docs/architecture/I08-03-deterministic-supervision-loop.md`),
//! I1.4 (`docs/architecture/I01-04-supervision-tree.md`), I13.5
//! (`docs/architecture/I13-05-staterevision-conflicts.md`).
//!
//! This cell never performs an SCM effect. It observes, journals its own
//! attempts, and revalidates at every irreversible boundary whether one attempt
//! may be requested at all. Where the existing SCM adapter cannot exclude a
//! generation substitution across its own effect boundary, the fence **refuses**
//! the attempt rather than claiming an atomic generation fence that does not
//! exist.
//!
//! Journal ownership: the durable rows live in the same `watchdog.redb` file,
//! under the same single writer, as every other Watchdog record, and are reached
//! through the owner-held [`redb::Database`]. There is no second journal and no
//! second writer, and no Host journal is opened here: the Watchdog reads the
//! Host epoch through its owner contour and never manufactures the next epoch
//! (I8.1).
//!
//! Exclusion: no lock is ever held across an attempt. The competing-attempt
//! exclusion is a durable row in the Watchdog's own journal, so a hung Host can
//! neither hold it nor make the Watchdog wait on it.
//!
//! Redaction: only validated coordination identities and content digests enter
//! a durable row or a diagnostic. Credentials, nonces, raw process values (process
//! ID, start time, image path), and user data are never carried: a process
//! identity is recorded as the digest of its own stable key, so a boundary
//! revalidates against the originally recorded value rather than a raw value.

use eliot_contracts::sha256_hex;
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{AdmittedEventLogEvent, ProcessIdentity};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::SpoolError;
use crate::host_identity_observation::{
    ApprovedRecoveryPolicy, BoundedChallengeWait, ChallengeAttemptOutcome, ChallengeUncertainty,
    HostObservation, HostObservationState, HostResponsiveness, RecoveryBudgetDecision,
};

/// Single-key row of the open recovery operation.
///
/// The key is a constant because exactly one recovery operation may be open per
/// installation. That is the competing-attempt exclusion, and it is a row in the
/// Watchdog's own journal rather than a lock the hung Host could hold.
pub const SPOOL_RECOVERY_KEY: u64 = 0;

/// Open recovery-operation row inside the same `watchdog.redb` file.
pub const SPOOL_RECOVERY_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_recovery_v1");

/// Single-key row of the durable recovery budget and failure accounting.
///
/// This row is deliberately separate from the per-operation row: opening a new
/// operation must never reset the budget, so exhaustion and the consecutive
/// failure count survive both a new operation and a Watchdog restart.
pub const SPOOL_RECOVERY_BUDGET_KEY: u64 = 0;

/// Durable recovery budget row inside the same `watchdog.redb` file.
pub const SPOOL_RECOVERY_BUDGET_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_recovery_budget_v1");

/// Per-event correlated audit rows inside the same `watchdog.redb` file.
///
/// Every challenge, timeout, denied or budget-exhausted decision, SCM request,
/// and readback lands here under its operation/policy/target correlation
/// identity. Retention is bounded exactly like the retained spool: the oldest
/// rows are evicted when the bound is reached, never silently skipped.
pub const SPOOL_RECOVERY_AUDIT_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_recovery_audit_v1");

/// Storage revision of every durable row this cell writes.
const RECOVERY_SCHEMA_VERSION: u16 = 1;

/// Retention bound for the correlated audit rows of one installation.
const MAX_RETAINED_RECOVERY_AUDIT_ROWS: u64 = 256;

/// Retention bound for the attempt timestamps one budget row carries.
const MAX_RETAINED_ATTEMPT_TIMESTAMPS: usize = 64;

/// Sibling branches a Host recovery must account for, named exactly as the
/// I1.4 supervision tree names them.
///
/// This is the independent expected set a completeness check compares against,
/// so a scope can never omit a supervised lineage.
pub const RECOVERY_SIBLING_BRANCHES: [SiblingBranch; 3] = [
    SiblingBranch::HostKernelLineage,
    SiblingBranch::CanonicalStoreBranch,
    SiblingBranch::WatchdogService,
];

/// Fail-closed errors of the recovery cell.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryError {
    /// The Watchdog journal could not be read or written.
    #[error("watchdog recovery journal is unavailable: {0}")]
    Journal(String),
    /// A record or step is not canonical.
    #[error("watchdog recovery record is invalid: {0}")]
    Invalid(String),
    /// A stale expected revision or content: a conflict, never a silent
    /// overwrite (I13.5).
    #[error("watchdog recovery revision conflict")]
    Conflict,
    /// A recovery step does not follow the operation's current phase.
    #[error("watchdog recovery step is not legal in this phase")]
    IllegalPhase,
    /// A recovery operation is already open and unreconciled.
    #[error("watchdog recovery operation is already open")]
    OperationOpen,
    /// A scope does not account for exactly the supervised sibling branches.
    #[error("watchdog recovery scope does not account for every sibling branch")]
    IncompleteScope,
    /// The boundary refused this step for the named reason.
    #[error("watchdog recovery boundary refused this step: {0:?}")]
    Boundary(BoundaryRefusal),
}

impl From<RecoveryError> for SpoolError {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::Journal(detail) => Self::Database(detail),
            other => Self::Corrupt(other.to_string()),
        }
    }
}

/// Digest of one observed process identity.
///
/// The durable record and every diagnostic carry this digest, never the raw
/// process ID, start time, or image path. A boundary revalidates by recomputing
/// it over the freshly observed identity and comparing it with the originally
/// recorded value, so a substituted process fails the comparison.
///
/// # Errors
///
/// Returns [`RecoveryError::Invalid`] when the digest is not a valid
/// coordination identity.
pub fn identity_digest(identity: &ProcessIdentity) -> Result<PlatformHandle, RecoveryError> {
    PlatformHandle::new(sha256_hex(identity.stable_key().as_bytes()))
        .map_err(|_| RecoveryError::Invalid("process identity digest is not a handle".to_owned()))
}

fn validated(field: &str, handle: &PlatformHandle) -> Result<(), RecoveryError> {
    if PlatformHandle::new(handle.as_str()).is_err() {
        return Err(RecoveryError::Invalid(format!(
            "{field} is not a coordination identity"
        )));
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, RecoveryError> {
    serde_json::to_vec(value).map_err(|error| RecoveryError::Journal(error.to_string()))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, RecoveryError> {
    serde_json::from_slice(bytes)
        .map_err(|error| RecoveryError::Invalid(format!("recovery row is not canonical: {error}")))
}

fn journal(error: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::Journal(error.to_string())
}

/// The exact approved target one challenge was issued against.
///
/// Every field is a validated coordination identity or a content digest. A
/// service name alone is not a target: `registration` and `generation` are the
/// boundary evidence, and a status query that retains no process identity cannot
/// produce them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTarget {
    /// Digest of the installer-approved registration this target revalidates
    /// against at every irreversible boundary.
    pub registration: PlatformHandle,
    /// Approved generation expected to be serving this target.
    pub generation: PlatformHandle,
    /// Host-issued owner epoch the challenge was bound to. The Watchdog never
    /// derives the next epoch from this one.
    pub owner_epoch: PlatformHandle,
    /// Permitted recovery recipe identity.
    pub recipe_digest: PlatformHandle,
    /// Digest of the process identity observed at challenge time.
    pub identity_digest: PlatformHandle,
}

impl RecoveryTarget {
    /// Binds a target from one validated live observation.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Invalid`] when any supplied coordination
    /// identity is not a valid handle.
    pub fn bind(
        registration: PlatformHandle,
        generation: PlatformHandle,
        owner_epoch: PlatformHandle,
        recipe_digest: PlatformHandle,
        identity: &ProcessIdentity,
    ) -> Result<Self, RecoveryError> {
        let target = Self {
            registration,
            generation,
            owner_epoch,
            recipe_digest,
            identity_digest: identity_digest(identity)?,
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        validated("recovery target registration", &self.registration)?;
        validated("recovery target generation", &self.generation)?;
        validated("recovery target owner epoch", &self.owner_epoch)?;
        validated("recovery target recipe digest", &self.recipe_digest)?;
        validated("recovery target identity digest", &self.identity_digest)
    }
}

/// What one fresh boundary readback proved.
///
/// A readback that proves less than this cannot admit an irreversible effect:
/// `observed_registration` is the approved-registration check, the identity
/// digest is the runtime-identity check, and the generation is the
/// expected-generation check. The three are independent; none substitutes for
/// another, and none is satisfied by the service name or by an earlier status
/// query.
///
/// Every field is the OBSERVED value, never a verdict about it. A boolean such
/// as "the registration did not change" is a caller's assertion about a
/// comparison it need not have performed, and it is indistinguishable from the
/// assertion made over a substituted registration, so no boolean can carry the
/// approved-only-start guarantee. The boundary compares each observed value by
/// content against the value the operation recorded at challenge time
/// ([`RecoveryTarget::registration`], `identity_digest`, `generation`), so a
/// substitution between the challenge and the effect fails the comparison
/// instead of satisfying it. `None` is an explicit absence and refuses; it is
/// never read as agreement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryEvidence {
    /// Approved-registration identity this fresh readback compared the live SCM
    /// configuration against, when it compared one.
    pub observed_registration: Option<PlatformHandle>,
    /// Digest of the process identity the same readback carried, when it carried
    /// one.
    pub identity_digest: Option<PlatformHandle>,
    /// Generation that readback attributes the live target to, when it could
    /// attribute one.
    pub generation: Option<PlatformHandle>,
}

/// Why a boundary refused one recovery attempt.
///
/// Every refusal keeps the decision explicit. None of them is a health claim, and
/// none is recoverable by re-issuing the same request without new evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryRefusal {
    /// The readback compared no approved registration, so registration identity
    /// cannot be revalidated at this boundary.
    RegistrationUnavailable,
    /// The approved registration is no longer the one this target was bound to.
    RegistrationChanged,
    /// The readback carried no process identity, so runtime identity cannot be
    /// revalidated at this boundary.
    IdentityNotRetained,
    /// The readback's process identity is not the challenged target.
    IdentityChanged,
    /// The readback could not attribute the live target to any generation.
    GenerationUnavailable,
    /// The readback attributes the live target to a different generation.
    GenerationChanged,
    /// The target is bound to a recipe the installation has not admitted.
    RecipeNotAdmitted,
    /// The target is bound to an owner epoch the installation has not admitted.
    OwnerEpochNotAdmitted,
    /// The consecutive responsiveness failures have not reached the policy's
    /// failure threshold.
    FailureThresholdNotReached,
    /// The policy's cooldown has not elapsed since the last attempt.
    CooldownNotElapsed,
    /// A competing attempt holds the exclusive claim, or an earlier attempt is
    /// still open and unreconciled.
    ConcurrentAttempt,
    /// The policy refuses effects when an audit stream is not established, and
    /// the Event Log leg is not admitted.
    AuditFailureRefusesEffects,
    /// The SCM adapter cannot exclude a generation substitution across its own
    /// effect boundary, so no automatic recovery may be requested.
    GenerationSubstitutionNotExcluded,
}

/// Correlation identity shared by both audit streams and by the operation record
/// they belong to.
///
/// These are coordination identities and content digests only: no credential,
/// nonce, raw path, or user datum can enter the type, because every field is a
/// validated [`PlatformHandle`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCorrelation {
    /// Stable identity of the one recovery operation. It is unchanged across the
    /// stop and the start of a single attempt.
    pub operation_id: PlatformHandle,
    /// Policy identity that admitted the attempt.
    pub policy_digest: PlatformHandle,
    /// Approved generation of the target.
    pub target_generation: PlatformHandle,
    /// Digest of the challenged process identity.
    pub target_identity_digest: PlatformHandle,
}

impl AuditCorrelation {
    /// Builds the correlation identity one operation's audit records share.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Invalid`] when a supplied identity is not a
    /// valid coordination handle.
    pub fn new(
        operation_id: &PlatformHandle,
        policy_digest: &PlatformHandle,
        target: &RecoveryTarget,
    ) -> Result<Self, RecoveryError> {
        let correlation = Self {
            operation_id: operation_id.clone(),
            policy_digest: policy_digest.clone(),
            target_generation: target.generation.clone(),
            target_identity_digest: target.identity_digest.clone(),
        };
        correlation.validate()?;
        Ok(correlation)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        validated("audit correlation operation", &self.operation_id)?;
        validated("audit correlation policy", &self.policy_digest)?;
        validated(
            "audit correlation target generation",
            &self.target_generation,
        )?;
        validated(
            "audit correlation target identity",
            &self.target_identity_digest,
        )
    }
}

/// The kind of audited event. Every one is correlated by the same
/// operation/policy/target identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AuditEventKind {
    /// A challenge was issued against the bound target.
    ChallengeIssued,
    /// The bounded wait expired with no correlated owner answer.
    ChallengeTimeout,
    /// The challenge could not establish a verdict; the uncertainty is named.
    ChallengeUnresolved,
    /// A boundary or policy decision refused the attempt.
    DecisionDenied,
    /// The recovery budget is exhausted; no restart is admitted.
    BudgetExhausted,
    /// One SCM effect was requested from the owner contour.
    ScmRequest,
    /// One SCM readback was observed.
    ScmReadback,
}

/// Delivery state of the installed Windows Event Log leg.
///
/// This cell records only the fact it can prove. The installed port admits only
/// the fixed `EliotHost` source and its three Host lifecycle events, and its own
/// closed rule reports `false` for a Watchdog audit record. Nothing is submitted
/// and nothing is visible; extending the installed source/event contract is
/// coordinated through its owners (issue #984, `bins/eliot-host#889`) rather than
/// by impersonating `EliotHost` or passing an arbitrary source name.
///
/// There is deliberately no visible variant: a Watchdog audit record can never be
/// claimed readable back from this port, so no code can mistake a persisted spool
/// record for Event Log visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventLogDelivery {
    /// The installed source/event contract does not admit this record.
    NotAdmittedByInstalledSource {
        /// Owner to coordinate the closed extension with.
        owner: &'static str,
    },
}

impl EventLogDelivery {
    /// The Event Log disposition this cell can honestly record today.
    #[must_use]
    pub const fn current() -> Self {
        Self::NotAdmittedByInstalledSource {
            owner: AdmittedEventLogEvent::watchdog_audit_sink_owner(),
        }
    }

    /// Whether an Event Log record for this cell can be claimed readable back.
    ///
    /// It reads the installed port's own closed admission rule rather than
    /// assuming it, so a future owner extension flips this without a second
    /// source of truth. While it is `false` no code may treat a persisted spool
    /// record as Event Log visibility.
    #[must_use]
    pub fn readable_back(&self) -> bool {
        AdmittedEventLogEvent::admits_watchdog_audit()
    }
}

/// Delivery state of the Watchdog spool leg.
///
/// Independent of the Event Log leg: a persisted spool record is not Event Log
/// delivery, and Event Log delivery is not spool persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpoolDelivery {
    /// The correlated row is durable in `watchdog.redb` at this sequence.
    Persisted {
        /// Durable sequence of the appended row.
        sequence: u64,
    },
    /// The row is not durable, so no effect may treat this as recorded evidence.
    Unavailable,
}

/// One audited event, correlated across both streams.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualAuditRecord {
    /// Operation/policy/target identity this event belongs to.
    pub correlation: AuditCorrelation,
    /// Which audited event this is.
    pub kind: AuditEventKind,
    /// Independent spool-delivery fact.
    pub spool: SpoolDelivery,
    /// Independent Event Log-delivery fact.
    pub event_log: EventLogDelivery,
}

impl DualAuditRecord {
    /// Builds the unproven starting state of one audited event: neither stream is
    /// claimed delivered.
    #[must_use]
    pub fn new(correlation: AuditCorrelation, kind: AuditEventKind) -> Self {
        Self {
            correlation,
            kind,
            spool: SpoolDelivery::Unavailable,
            event_log: EventLogDelivery::current(),
        }
    }

    /// Records the independent spool fact established by a durable append.
    #[must_use]
    pub fn with_spool_persisted(mut self, sequence: u64) -> Self {
        self.spool = SpoolDelivery::Persisted { sequence };
        self
    }

    /// Whether the spool leg is independently established.
    #[must_use]
    pub const fn spool_persisted(&self) -> bool {
        matches!(self.spool, SpoolDelivery::Persisted { .. })
    }
}

/// A sibling branch of the supervision tree that a Host recovery affects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SiblingBranch {
    /// The Host-owned Kernel Job Object lineage.
    HostKernelLineage,
    /// The separate Host-owned canonical-store Job Object lineage.
    CanonicalStoreBranch,
    /// The independent SCM sibling Watchdog service.
    WatchdogService,
}

/// What the installed recipe does to one sibling branch.
///
/// There is no process-tree termination disposition here, and this cell has no
/// process-termination effect at all: a Host recovery accounts for each sibling
/// under existing policy instead of killing a whole tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SiblingDisposition {
    /// Closes with its Host-owned `KILL_ON_JOB_CLOSE` Job Object when the Host
    /// lineage is lost.
    ClosedWithHostJobObject,
    /// Left running under its own Host-owned Job Object; the recipe does not stop
    /// it.
    PreservedUnderExistingPolicy,
    /// An independent SCM sibling service, which a Host recovery never stops.
    IndependentSiblingService,
}

/// One sibling branch and the installed recipe's disposition for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiblingBranchDisposition {
    /// Which supervised branch this is.
    pub branch: SiblingBranch,
    /// What the installed recipe does to it.
    pub disposition: SiblingDisposition,
}

/// What one recovery attempt accounts for beyond its own target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryScope {
    /// One disposition per supervised sibling branch, checked for completeness
    /// against [`RECOVERY_SIBLING_BRANCHES`].
    pub siblings: Vec<SiblingBranchDisposition>,
}

impl RecoveryScope {
    /// Builds a scope from the installed recipe's dispositions.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::IncompleteScope`] when the dispositions do not
    /// cover exactly [`RECOVERY_SIBLING_BRANCHES`].
    pub fn new(siblings: Vec<SiblingBranchDisposition>) -> Result<Self, RecoveryError> {
        let scope = Self { siblings };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        for expected in RECOVERY_SIBLING_BRANCHES {
            let covered = self
                .siblings
                .iter()
                .filter(|entry| entry.branch == expected)
                .count();
            if covered != 1 {
                return Err(RecoveryError::IncompleteScope);
            }
        }
        Ok(())
    }
}

/// Phase of one durable recovery operation.
///
/// Stop and start are reconciled separately and an unknown outcome is its own
/// preserved phase: `StopIntentCommitted` is a *requested* stop and never an
/// observed termination, and neither unknown phase is ever treated as a completed
/// step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RecoveryPhase {
    /// A stop was requested against the fenced target. Termination is not observed
    /// yet.
    StopIntentCommitted,
    /// A readback proved the old target terminated.
    StopObserved,
    /// The stop effect outcome is unknown. It stays unknown until the original
    /// operation is reconciled; no retry and no restart may pass it.
    StopOutcomeUnknown,
    /// A start of the currently approved unchanged registration was requested,
    /// after the required old-target disposition.
    StartIntentCommitted,
    /// A readback proved the replacement is running.
    StartedObserved,
    /// The start effect outcome is unknown. It stays unknown until the original
    /// operation is reconciled.
    StartOutcomeUnknown,
}

impl RecoveryPhase {
    /// Whether this operation is still open, so a competing attempt is excluded.
    #[must_use]
    pub const fn is_open(self) -> bool {
        !matches!(self, Self::StartedObserved)
    }

    /// Whether this phase preserves an unknown effect outcome.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::StopOutcomeUnknown | Self::StartOutcomeUnknown)
    }
}

/// One reconciliation step of an open recovery operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryStep {
    /// A stop was requested against the fenced target.
    StopRequested,
    /// A readback proved the old target terminated.
    StopObserved,
    /// A readback could not establish termination, so the outcome is preserved as
    /// unknown rather than assumed.
    StopOutcomeUnknown,
    /// A start of the currently approved unchanged registration was requested.
    StartRequested,
    /// A readback proved the replacement is running, bound to its newly observed
    /// identity and the epoch the replacement Host issued for itself. Neither
    /// may replay the fenced target's own value.
    StartedObserved {
        /// Digest of the replacement's newly observed process identity.
        identity_digest: PlatformHandle,
        /// Epoch the replacement Host issued. The Watchdog only records it: it
        /// never derives the next epoch from the fenced one.
        host_issued_epoch: PlatformHandle,
    },
    /// A readback could not establish the start, so the outcome is preserved as
    /// unknown.
    StartOutcomeUnknown,
}

impl RecoveryStep {
    const fn target_phase(&self) -> RecoveryPhase {
        match self {
            Self::StopRequested => RecoveryPhase::StopIntentCommitted,
            Self::StopObserved => RecoveryPhase::StopObserved,
            Self::StopOutcomeUnknown => RecoveryPhase::StopOutcomeUnknown,
            Self::StartRequested => RecoveryPhase::StartIntentCommitted,
            Self::StartedObserved { .. } => RecoveryPhase::StartedObserved,
            Self::StartOutcomeUnknown => RecoveryPhase::StartOutcomeUnknown,
        }
    }

    /// Whether this step requests one irreversible SCM effect.
    #[must_use]
    pub const fn requests_effect(&self) -> bool {
        matches!(self, Self::StopRequested | Self::StartRequested)
    }
}

/// The one durable, Watchdog-owned recovery operation row.
///
/// It carries the challenge outcome, the budget decision, and the stable operation
/// intent, and it is persisted before any SCM effect is requested. It is not a
/// canonical record, a lease, or epoch authority: it binds nothing except this
/// Watchdog's own recovery attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOperation {
    schema_version: u16,
    /// Correlation identity every audit record of this operation carries.
    correlation: AuditCorrelation,
    /// The revalidated target. Its identity digest is the value each later
    /// boundary revalidates against.
    target: RecoveryTarget,
    /// Responsiveness verdict the challenge produced for this target.
    challenge_outcome: HostResponsiveness,
    /// Budget decision taken from the durable budget row before this operation was
    /// opened.
    budget_decision: RecoveryBudgetDecision,
    /// Current phase.
    phase: RecoveryPhase,
    /// Monotonic revision of this row; a stale expected revision is a conflict.
    revision: u64,
    /// What this attempt accounts for beyond its own target.
    scope: RecoveryScope,
    /// Digest of the replacement identity, once one has been observed.
    replacement_identity_digest: Option<PlatformHandle>,
    /// Epoch the replacement Host issued, once one has been observed.
    replacement_owner_epoch: Option<PlatformHandle>,
}

impl RecoveryOperation {
    /// Opens a recovery operation.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Invalid`] when the target, correlation, or scope is
    /// not canonical.
    pub fn begin(
        correlation: AuditCorrelation,
        target: RecoveryTarget,
        challenge_outcome: HostResponsiveness,
        budget_decision: RecoveryBudgetDecision,
        scope: RecoveryScope,
    ) -> Result<Self, RecoveryError> {
        let operation = Self {
            schema_version: RECOVERY_SCHEMA_VERSION,
            correlation,
            target,
            challenge_outcome,
            budget_decision,
            phase: RecoveryPhase::StopIntentCommitted,
            revision: 1,
            scope,
            replacement_identity_digest: None,
            replacement_owner_epoch: None,
        };
        operation.validate()?;
        Ok(operation)
    }

    /// Correlation identity of this operation.
    #[must_use]
    pub const fn correlation(&self) -> &AuditCorrelation {
        &self.correlation
    }

    /// The revalidated target of this operation.
    #[must_use]
    pub const fn target(&self) -> &RecoveryTarget {
        &self.target
    }

    /// The responsiveness verdict this operation was opened for.
    #[must_use]
    pub const fn challenge_outcome(&self) -> HostResponsiveness {
        self.challenge_outcome
    }

    /// The budget decision this operation was opened under.
    #[must_use]
    pub const fn budget_decision(&self) -> RecoveryBudgetDecision {
        self.budget_decision
    }

    /// Current phase of this operation.
    #[must_use]
    pub const fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    /// Monotonic revision of this row.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// What this attempt accounts for beyond its own target.
    #[must_use]
    pub const fn scope(&self) -> &RecoveryScope {
        &self.scope
    }

    /// The exact old-target and new-target evidence this operation names.
    ///
    /// The entries are the values the operation actually recorded: the identity the
    /// challenge was issued against, and the identity plus Host-issued epoch the
    /// replacement presented. `None` before a replacement has been observed, never a
    /// synthesized value.
    #[must_use]
    pub const fn target_evidence(
        &self,
    ) -> (
        &PlatformHandle,
        Option<&PlatformHandle>,
        Option<&PlatformHandle>,
    ) {
        (
            &self.target.identity_digest,
            self.replacement_identity_digest.as_ref(),
            self.replacement_owner_epoch.as_ref(),
        )
    }

    /// Applies one reconciliation step to this operation.
    ///
    /// A step is legal only from the phase it actually follows: a requested stop
    /// never advances straight to a start, so the required old-target disposition
    /// is a real precondition, and an unknown phase is terminal for this operation
    /// so the original operation is reconciled before any retry.
    ///
    /// The replacement observation is bound to its newly observed identity: an
    /// epoch that replays the fenced one, or an identity digest that replays the
    /// fenced one, is refused rather than recorded as a fresh Host issuance.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::IllegalPhase`] when the step does not follow the
    /// current phase, and [`RecoveryError::Invalid`] when a replacement observation
    /// carries no Host-issued epoch, or reuses the fenced epoch or the fenced
    /// identity.
    pub fn apply(&mut self, step: &RecoveryStep) -> Result<(), RecoveryError> {
        let next = step.target_phase();
        let follows = matches!(
            (self.phase, next),
            (
                RecoveryPhase::StopIntentCommitted,
                RecoveryPhase::StopObserved | RecoveryPhase::StopOutcomeUnknown
            ) | (
                RecoveryPhase::StopObserved,
                RecoveryPhase::StartIntentCommitted
            ) | (
                RecoveryPhase::StartIntentCommitted,
                RecoveryPhase::StartedObserved | RecoveryPhase::StartOutcomeUnknown
            )
        );
        if !self.phase.is_open() || !follows {
            return Err(RecoveryError::IllegalPhase);
        }
        let replacement = if let RecoveryStep::StartedObserved {
            identity_digest,
            host_issued_epoch,
        } = step
        {
            validated("replacement identity digest", identity_digest)?;
            validated("replacement host-issued epoch", host_issued_epoch)?;
            // The Watchdog only records the epoch the replacement Host issued
            // for itself: it never derives the next epoch from the fenced one.
            // The two refusals are what make "issued for a new lineage" a real
            // property rather than a shape — a replayed epoch would claim a
            // fresh issuance for the fenced Host, and a replayed identity digest
            // would attach the new epoch to the process the boundary already
            // fenced instead of to the replacement it observed.
            if *host_issued_epoch == self.target.owner_epoch {
                return Err(RecoveryError::Invalid(
                    "replacement reused the fenced owner epoch".to_owned(),
                ));
            }
            if *identity_digest == self.target.identity_digest {
                return Err(RecoveryError::Invalid(
                    "replacement reused the fenced target identity".to_owned(),
                ));
            }
            Some((identity_digest.clone(), host_issued_epoch.clone()))
        } else {
            None
        };
        // The step is applied to a candidate row and installed only once the
        // candidate is canonical, so a refused step can never leave the caller's
        // operation half-advanced (I13.5).
        let mut advanced = self.clone();
        advanced.phase = next;
        advanced.revision = advanced.revision.saturating_add(1);
        if let Some((identity_digest, host_issued_epoch)) = replacement {
            advanced.replacement_identity_digest = Some(identity_digest);
            advanced.replacement_owner_epoch = Some(host_issued_epoch);
        }
        advanced.validate()?;
        *self = advanced;
        Ok(())
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        if self.schema_version != RECOVERY_SCHEMA_VERSION || self.revision == 0 {
            return Err(RecoveryError::Invalid(
                "recovery operation row is not canonical".to_owned(),
            ));
        }
        self.correlation.validate()?;
        self.target.validate()?;
        self.scope.validate()?;
        if self.replacement_identity_digest.is_some() != self.replacement_owner_epoch.is_some() {
            return Err(RecoveryError::Invalid(
                "recovery operation replacement evidence is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Durable recovery budget and failure accounting for one installation.
///
/// This row is the only source of the used-attempt count and the consecutive
/// failure count. It is read from the Watchdog's own journal, so exhaustion
/// survives a new operation and a Watchdog restart; it is never reset and never
/// invented from a constant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBudget {
    schema_version: u16,
    /// Owner-clock timestamps of attempts already consumed, oldest first.
    attempt_timestamps_ms: Vec<u64>,
    /// Consecutive responsiveness failures observed for the current target.
    consecutive_failures: u32,
}

impl RecoveryBudget {
    /// Attempts already consumed inside the policy's budget window.
    #[must_use]
    pub fn used_attempts(&self, now_ms: u64, policy: &ApprovedRecoveryPolicy) -> u64 {
        let window_ms = policy.budget_window_secs.saturating_mul(1000);
        let counted = self
            .attempt_timestamps_ms
            .iter()
            .filter(|stamp| now_ms.saturating_sub(**stamp) <= window_ms)
            .count();
        u64::try_from(counted).unwrap_or(u64::MAX)
    }

    /// Consecutive responsiveness failures recorded for the current target.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Owner clock of the most recent consumed attempt, if any.
    #[must_use]
    pub fn last_attempt_ms(&self) -> Option<u64> {
        self.attempt_timestamps_ms.last().copied()
    }

    /// Classifies one responsiveness verdict against the approved policy.
    ///
    /// The used-attempt count comes from this durable row, so an exhausted budget
    /// stays exhausted across a Watchdog restart, and a missing row admits nothing.
    #[must_use]
    pub fn decide(
        &self,
        responsiveness: HostResponsiveness,
        now_ms: u64,
        policy: &ApprovedRecoveryPolicy,
    ) -> RecoveryBudgetDecision {
        responsiveness.recovery_eligibility(policy, self.used_attempts(now_ms, policy))
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        if self.schema_version != RECOVERY_SCHEMA_VERSION
            || self.attempt_timestamps_ms.len() > MAX_RETAINED_ATTEMPT_TIMESTAMPS
            || self
                .attempt_timestamps_ms
                .windows(2)
                .any(|pair| pair[1] < pair[0])
        {
            return Err(RecoveryError::Invalid(
                "recovery budget row is not canonical".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The exact exclusion and readback guarantees of the existing SCM adapter.
///
/// The adapter performs a fresh exact configuration/runtime admission immediately
/// before the mutation, issues at most one start or stop, and repeats the same
/// stable configuration/process-identity readback immediately after it, preserving a
/// post-boundary ambiguity as an unknown effect rather than resolving it. It
/// addresses the effect by service name: the control call itself carries no
/// generation, so a registration or generation substitution landing between the
/// boundary readback and the call is not excluded by the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScmAdapterGuarantee {
    /// The effect is addressed by service name only; the call carries no
    /// generation.
    pub effect_addresses_service_name_only: bool,
    /// The pre-effect admission and the post-effect readback are separate SCM
    /// queries from the effect call.
    pub readback_is_a_separate_query: bool,
    /// A post-boundary ambiguity is preserved as an unknown effect.
    pub post_boundary_ambiguity_preserved: bool,
}

impl ScmAdapterGuarantee {
    /// Whether this adapter can exclude a generation substitution across its own
    /// effect boundary.
    ///
    /// It cannot when the effect is addressed by service name and the readback is a
    /// separate query: nothing ties the generation the readback observed to the
    /// generation the effect actually acted on.
    #[must_use]
    pub const fn excludes_generation_substitution(self) -> bool {
        !(self.effect_addresses_service_name_only && self.readback_is_a_separate_query)
    }
}

/// The guarantees of the existing `WindowsPlatform` SCM adapter this cell is built
/// against. They are recorded here rather than assumed at the call site.
pub const EXISTING_SCM_ADAPTER_GUARANTEE: ScmAdapterGuarantee = ScmAdapterGuarantee {
    effect_addresses_service_name_only: true,
    readback_is_a_separate_query: true,
    post_boundary_ambiguity_preserved: true,
};

/// The one intent a fenced recovery attempt may act on.
///
/// It can only be produced by [`fence_recovery`], so no caller can obtain an
/// actionable intent without having revalidated the approved registration, the
/// runtime identity, and the expected generation at a fresh boundary, and without
/// the installation policy having admitted the attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedRecoveryIntent {
    /// Stable identity of this one recovery operation, unchanged across its stop
    /// and its start.
    pub operation_id: PlatformHandle,
    /// Correlation identity every audit record of this attempt carries.
    pub correlation: AuditCorrelation,
    /// The revalidated target, whose identity digest the next boundary must
    /// reproduce.
    pub target: RecoveryTarget,
}

/// Every input one boundary revalidation reads.
#[derive(Debug)]
pub struct RecoveryFence<'audit> {
    /// The installation-approved recovery policy.
    pub policy: &'audit ApprovedRecoveryPolicy,
    /// The target the challenge was issued against.
    pub target: &'audit RecoveryTarget,
    /// What a fresh readback proved.
    pub evidence: BoundaryEvidence,
    /// The guarantees of the adapter that would execute the effect.
    pub guarantee: ScmAdapterGuarantee,
    /// The operation already open in the Watchdog journal, if any.
    pub open_operation: Option<&'audit RecoveryOperation>,
    /// The durable budget and failure accounting.
    pub budget: &'audit RecoveryBudget,
    /// The audit record correlated with this attempt.
    pub audit: &'audit DualAuditRecord,
    /// Owner clock at this boundary.
    pub now_ms: u64,
}

/// Compares one fresh boundary readback against the values this operation
/// recorded when the challenge was issued.
///
/// This is the single approved-only-start comparison, shared by the opening
/// fence and by every effect-requesting step, so the two boundaries cannot drift
/// apart. Each observed value is compared by CONTENT with the operation's own
/// recorded target; an absent value is an explicit refusal, never agreement, and
/// a service name or an earlier status query cannot satisfy any of the three.
///
/// # Errors
///
/// Returns [`BoundaryRefusal::RegistrationUnavailable`],
/// [`BoundaryRefusal::RegistrationChanged`],
/// [`BoundaryRefusal::IdentityNotRetained`], [`BoundaryRefusal::IdentityChanged`],
/// [`BoundaryRefusal::GenerationUnavailable`], or
/// [`BoundaryRefusal::GenerationChanged`] for the first value that is absent or
/// no longer the one this operation was opened against.
pub fn revalidate_boundary(
    target: &RecoveryTarget,
    evidence: &BoundaryEvidence,
) -> Result<(), BoundaryRefusal> {
    match evidence.observed_registration.as_ref() {
        None => return Err(BoundaryRefusal::RegistrationUnavailable),
        Some(observed) if observed != &target.registration => {
            return Err(BoundaryRefusal::RegistrationChanged);
        }
        Some(_) => {}
    }
    match evidence.identity_digest.as_ref() {
        None => return Err(BoundaryRefusal::IdentityNotRetained),
        Some(observed) if observed != &target.identity_digest => {
            return Err(BoundaryRefusal::IdentityChanged);
        }
        Some(_) => {}
    }
    match evidence.generation.as_ref() {
        None => return Err(BoundaryRefusal::GenerationUnavailable),
        Some(observed) if observed != &target.generation => {
            return Err(BoundaryRefusal::GenerationChanged);
        }
        Some(_) => {}
    }
    Ok(())
}

/// Revalidates one boundary and decides whether a recovery attempt may proceed.
///
/// The checks run from the most specific evidence to the structural limit, so the
/// refusal that surfaces is the most specific one: approved registration, then
/// runtime identity, then expected generation (all three compared by content
/// against the operation's own target by [`revalidate_boundary`]), then the
/// installation policy's recipe, epoch, failure-threshold, cooldown, and audit
/// rules, then the competing-attempt exclusion, and finally whether the adapter
/// itself can exclude a generation substitution.
///
/// # Errors
///
/// Returns [`BoundaryRefusal`] naming the first failed check. Refusing where
/// substitution cannot be ruled out is the required behaviour, not a shortfall.
pub fn fence_recovery(
    fence: &RecoveryFence<'_>,
) -> Result<AdmittedRecoveryIntent, BoundaryRefusal> {
    revalidate_boundary(fence.target, &fence.evidence)?;
    if fence.target.recipe_digest != fence.policy.recipe_digest {
        return Err(BoundaryRefusal::RecipeNotAdmitted);
    }
    if fence.target.owner_epoch != fence.policy.owner_epoch_digest {
        return Err(BoundaryRefusal::OwnerEpochNotAdmitted);
    }
    if fence.budget.consecutive_failures() < fence.policy.failure_threshold {
        return Err(BoundaryRefusal::FailureThresholdNotReached);
    }
    let cooldown_ms = fence.policy.cooldown_secs.saturating_mul(1000);
    if fence
        .budget
        .last_attempt_ms()
        .is_some_and(|last| fence.now_ms.saturating_sub(last) < cooldown_ms)
    {
        return Err(BoundaryRefusal::CooldownNotElapsed);
    }
    if fence.policy.audit_failure_refuses_effects && !fence.audit.event_log.readable_back() {
        return Err(BoundaryRefusal::AuditFailureRefusesEffects);
    }
    let competing = fence
        .open_operation
        .is_some_and(|operation| operation.phase().is_open());
    if fence.policy.exclusive_attempt && competing {
        return Err(BoundaryRefusal::ConcurrentAttempt);
    }
    if !fence.guarantee.excludes_generation_substitution() {
        return Err(BoundaryRefusal::GenerationSubstitutionNotExcluded);
    }
    Ok(AdmittedRecoveryIntent {
        operation_id: fence.audit.correlation.operation_id.clone(),
        correlation: fence.audit.correlation.clone(),
        target: fence.target.clone(),
    })
}

/// What one challenge against a replacement process can establish.
///
/// A replacement challenge establishes the replacement's own observed
/// responsiveness and nothing else. There is deliberately no resolved variant: the
/// underlying Problem is resolved by the Governor's canonical transition, never by
/// a restart, and a replacement challenge is evidence about the declared control
/// property of one generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementChallengeScope {
    /// The replacement's own control owner answered its own challenge inside the
    /// bound. This is the declared control property of that generation only.
    ObservedResponsivenessOnly,
    /// The replacement did not answer, so nothing about it is established.
    Unresolved,
}

/// Classifies a replacement challenge strictly as observed responsiveness.
#[must_use]
pub const fn replacement_challenge_scope(
    responsiveness: HostResponsiveness,
) -> ReplacementChallengeScope {
    match responsiveness {
        HostResponsiveness::Responsive => ReplacementChallengeScope::ObservedResponsivenessOnly,
        HostResponsiveness::AliveUnresponsive | HostResponsiveness::Uncertain(_) => {
            ReplacementChallengeScope::Unresolved
        }
    }
}

/// Rechecks target identity around the bounded observation interval.
///
/// `before` is the observation taken when the challenge was issued and `after` the
/// observation taken when the bounded wait ended. A timeout is `AliveUnresponsive`
/// only when both observations describe the same live target with the same retained
/// process identity; a target that changed, lost its identity, or stopped across the
/// interval stays an explicit uncertainty and is never authenticated health and
/// never restart eligibility.
#[must_use]
pub fn bounded_responsiveness(
    before: &HostObservation,
    wait: &BoundedChallengeWait,
    attempt: &ChallengeAttemptOutcome,
    after: &HostObservation,
) -> HostResponsiveness {
    let verdict = before.responsiveness(wait, attempt);
    if !matches!(verdict, HostResponsiveness::AliveUnresponsive) {
        return verdict;
    }
    if after.state != HostObservationState::Running {
        return HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive);
    }
    match (before.identity.as_ref(), after.identity.as_ref()) {
        (Some(earlier), Some(later)) if earlier == later => verdict,
        (Some(_), Some(_)) => HostResponsiveness::Uncertain(ChallengeUncertainty::TargetChanged),
        _ => HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage),
    }
}

fn read_operation_in<D: ReadableDatabase>(
    database: &D,
) -> Result<Option<RecoveryOperation>, RecoveryError> {
    let read = database.begin_read().map_err(journal)?;
    match read.open_table(SPOOL_RECOVERY_TABLE) {
        Ok(table) => {
            let row = table.get(SPOOL_RECOVERY_KEY).map_err(journal)?;
            match row {
                None => Ok(None),
                Some(value) => {
                    let stored: RecoveryOperation = decode(value.value())?;
                    stored.validate()?;
                    Ok(Some(stored))
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(error) => Err(journal(error)),
    }
}

fn read_budget_in<D: ReadableDatabase>(
    database: &D,
) -> Result<Option<RecoveryBudget>, RecoveryError> {
    let read = database.begin_read().map_err(journal)?;
    match read.open_table(SPOOL_RECOVERY_BUDGET_TABLE) {
        Ok(table) => {
            let row = table.get(SPOOL_RECOVERY_BUDGET_KEY).map_err(journal)?;
            match row {
                None => Ok(None),
                Some(value) => {
                    let stored: RecoveryBudget = decode(value.value())?;
                    stored.validate()?;
                    Ok(Some(stored))
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(error) => Err(journal(error)),
    }
}

/// Reads the open recovery operation, if one is open.
///
/// Read-only: nothing is claimed, reserved, or removed, and an absent table is an
/// explicit absence rather than a created row.
///
/// # Errors
///
/// Returns [`RecoveryError::Journal`] when the journal cannot be read and
/// [`RecoveryError::Invalid`] when a stored row is not canonical.
pub fn read_recovery_operation(
    database: &Database,
) -> Result<Option<RecoveryOperation>, RecoveryError> {
    read_operation_in(database)
}

/// Reads the durable recovery budget, or an explicit fresh row when none exists.
///
/// # Errors
///
/// Returns [`RecoveryError::Journal`] when the journal cannot be read and
/// [`RecoveryError::Invalid`] when a stored row is not canonical.
pub fn read_recovery_budget(database: &Database) -> Result<RecoveryBudget, RecoveryError> {
    read_budget_in(database)?.map_or_else(
        || {
            Ok(RecoveryBudget {
                schema_version: RECOVERY_SCHEMA_VERSION,
                attempt_timestamps_ms: Vec::new(),
                consecutive_failures: 0,
            })
        },
        Ok,
    )
}

/// Advances the durable failure and attempt accounting.
///
/// The counts live in the Watchdog's own journal and are only ever advanced here,
/// so a Watchdog restart cannot reset the budget and no caller can invent it from a
/// constant. One consumed attempt is counted once per operation, because one fenced
/// stop/start pair is one recovery attempt.
///
/// # Errors
///
/// Returns [`RecoveryError::Invalid`] when a stored row is not canonical and
/// [`RecoveryError::Journal`] when the row cannot be written.
pub fn record_recovery_budget(
    database: &Database,
    observed_failure: bool,
    consumed_attempt_at_ms: Option<u64>,
    policy: &ApprovedRecoveryPolicy,
) -> Result<RecoveryBudget, RecoveryError> {
    let write = database.begin_write().map_err(journal)?;
    let mut budget = match write.open_table(SPOOL_RECOVERY_BUDGET_TABLE) {
        Ok(table) => {
            let row = table.get(SPOOL_RECOVERY_BUDGET_KEY).map_err(journal)?;
            match row {
                None => RecoveryBudget {
                    schema_version: RECOVERY_SCHEMA_VERSION,
                    attempt_timestamps_ms: Vec::new(),
                    consecutive_failures: 0,
                },
                Some(value) => {
                    let stored: RecoveryBudget = decode(value.value())?;
                    stored.validate()?;
                    stored
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => RecoveryBudget {
            schema_version: RECOVERY_SCHEMA_VERSION,
            attempt_timestamps_ms: Vec::new(),
            consecutive_failures: 0,
        },
        Err(error) => return Err(journal(error)),
    };
    if observed_failure {
        budget.consecutive_failures = budget.consecutive_failures.saturating_add(1);
    }
    if let Some(at_ms) = consumed_attempt_at_ms {
        let window_ms = policy.budget_window_secs.saturating_mul(1000);
        budget
            .attempt_timestamps_ms
            .retain(|stamp| at_ms.saturating_sub(*stamp) <= window_ms);
        budget.attempt_timestamps_ms.push(at_ms);
        let excess = budget
            .attempt_timestamps_ms
            .len()
            .saturating_sub(MAX_RETAINED_ATTEMPT_TIMESTAMPS);
        budget.attempt_timestamps_ms.drain(..excess);
    }
    budget.validate()?;
    let bytes = encode(&budget)?;
    {
        let mut table = write
            .open_table(SPOOL_RECOVERY_BUDGET_TABLE)
            .map_err(journal)?;
        table
            .insert(SPOOL_RECOVERY_BUDGET_KEY, bytes.as_slice())
            .map_err(journal)?;
    }
    write.commit().map_err(journal)?;
    Ok(budget)
}

/// Opens one recovery operation, or reports the open one that excludes it.
///
/// This is the competing-attempt exclusion and it is a durable row in the Watchdog's
/// own journal, not a lock held by the hung Host. The operation's challenge outcome,
/// budget decision, target, and stable intent are persisted here, before any SCM
/// effect can be requested.
///
/// # Errors
///
/// Returns [`RecoveryError::OperationOpen`] when an operation is already open and
/// unreconciled, and [`RecoveryError::Conflict`] when the stored revision does not
/// match the caller's expectation.
pub fn begin_recovery_operation(
    database: &Database,
    expected_revision: Option<u64>,
    operation: &RecoveryOperation,
) -> Result<RecoveryOperation, RecoveryError> {
    operation.validate()?;
    let write = database.begin_write().map_err(journal)?;
    let stored = match write.open_table(SPOOL_RECOVERY_TABLE) {
        Ok(table) => {
            let row = table.get(SPOOL_RECOVERY_KEY).map_err(journal)?;
            match row {
                None => None,
                Some(value) => {
                    let stored: RecoveryOperation = decode(value.value())?;
                    stored.validate()?;
                    Some(stored)
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(error) => return Err(journal(error)),
    };
    if stored
        .as_ref()
        .is_some_and(|previous| previous.phase().is_open())
    {
        return Err(RecoveryError::OperationOpen);
    }
    if expected_revision.is_some()
        && expected_revision != stored.as_ref().map(RecoveryOperation::revision)
    {
        return Err(RecoveryError::Conflict);
    }
    let mut next = operation.clone();
    next.revision = stored.map_or(1, |previous| previous.revision().saturating_add(1));
    let bytes = encode(&next)?;
    {
        let mut table = write.open_table(SPOOL_RECOVERY_TABLE).map_err(journal)?;
        table
            .insert(SPOOL_RECOVERY_KEY, bytes.as_slice())
            .map_err(journal)?;
    }
    write.commit().map_err(journal)?;
    Ok(next)
}

/// Applies one reconciliation step to the stored operation in one owner transaction.
///
/// The stored row is re-read inside the transaction and compared content-wise with
/// the caller's `expected`, so an interleaved writer can neither be overwritten nor
/// substituted. A mismatch is a conflict, never a silent advance (I13.5). A step
/// that requests an irreversible effect additionally revalidates, by content and
/// against this operation's own recorded target, the approved registration, the
/// runtime identity, and the expected generation (`revalidate_boundary`), so only
/// the currently approved unchanged registration is ever started, and only after
/// the required old-target disposition.
///
/// # Errors
///
/// Returns [`RecoveryError::Conflict`] when the stored row is not the exact expected
/// row, [`RecoveryError::Boundary`] when a fresh readback no longer matches the
/// operation's approved registration, runtime identity, or expected generation,
/// [`RecoveryError::IllegalPhase`] when the step does not follow the current phase,
/// and [`RecoveryError::Invalid`] for a non-canonical step.
pub fn commit_recovery_step(
    database: &Database,
    expected: &RecoveryOperation,
    step: &RecoveryStep,
    evidence: &BoundaryEvidence,
) -> Result<RecoveryOperation, RecoveryError> {
    let expected_bytes = encode(expected)?;
    let write = database.begin_write().map_err(journal)?;
    let mut stored = {
        let stored: Option<RecoveryOperation> = {
            let table = write.open_table(SPOOL_RECOVERY_TABLE).map_err(journal)?;
            let row = table.get(SPOOL_RECOVERY_KEY).map_err(journal)?;
            match row {
                None => None,
                Some(value) => Some(decode(value.value())?),
            }
        };
        let stored = stored.ok_or(RecoveryError::Conflict)?;
        if encode(&stored)? != expected_bytes {
            return Err(RecoveryError::Conflict);
        }
        stored
    };
    if step.requests_effect() {
        // The effect boundary repeats the SAME content comparison the opening
        // fence used, against the values this operation itself recorded: the
        // approved registration, the runtime identity, and the expected
        // generation. Only the currently approved unchanged registration is
        // ever started, and only after the required old-target disposition.
        revalidate_boundary(stored.target(), evidence).map_err(RecoveryError::Boundary)?;
    }
    stored.apply(step)?;
    let bytes = encode(&stored)?;
    {
        let mut table = write.open_table(SPOOL_RECOVERY_TABLE).map_err(journal)?;
        table
            .insert(SPOOL_RECOVERY_KEY, bytes.as_slice())
            .map_err(journal)?;
    }
    write.commit().map_err(journal)?;
    Ok(stored)
}

/// Appends one correlated audit event and reports the independent spool fact.
///
/// Spool persistence and Event Log delivery are separate facts: this returns the
/// durable sequence and leaves the Event Log leg exactly as the installed
/// source/event contract admits it. Nothing here requests, retries, or replays an SCM
/// effect, so a log failure can never cause one.
///
/// # Errors
///
/// Returns [`RecoveryError::Invalid`] when the correlation is not canonical and
/// [`RecoveryError::Journal`] when the row cannot be written.
pub fn record_recovery_audit(
    database: &Database,
    audit: &DualAuditRecord,
) -> Result<DualAuditRecord, RecoveryError> {
    audit.correlation.validate()?;
    let write = database.begin_write().map_err(journal)?;
    let sequence = {
        let mut table = write
            .open_table(SPOOL_RECOVERY_AUDIT_TABLE)
            .map_err(journal)?;
        let mut first = None;
        let mut last = 0;
        let mut retained = 0_u64;
        for item in table.iter().map_err(journal)? {
            let (key, _value) = item.map_err(journal)?;
            first.get_or_insert(key.value());
            last = key.value();
            retained = retained.saturating_add(1);
        }
        while retained >= MAX_RETAINED_RECOVERY_AUDIT_ROWS {
            let Some(oldest) = first else { break };
            table.remove(oldest).map_err(journal)?;
            retained -= 1;
            first = table
                .range((oldest + 1)..)
                .map_err(journal)?
                .next()
                .transpose()
                .map_err(journal)?
                .map(|(key, _value)| key.value());
        }
        let sequence = last.saturating_add(1);
        let row = RecoveryAuditRow {
            schema_version: RECOVERY_SCHEMA_VERSION,
            sequence,
            correlation: audit.correlation.clone(),
            kind: audit.kind,
        };
        let bytes = encode(&row)?;
        table.insert(sequence, bytes.as_slice()).map_err(journal)?;
        sequence
    };
    write.commit().map_err(journal)?;
    tracing::debug!(
        event = "watchdog.recovery_audit_recorded",
        observation = "committed",
        sequence = sequence,
        operation = audit.correlation.operation_id.as_str(),
        kind = ?audit.kind,
        "watchdog correlated recovery audit event committed; event log delivery stays unadmitted"
    );
    Ok(audit.clone().with_spool_persisted(sequence))
}

/// Reads a bounded window of the correlated audit rows, oldest first.
///
/// Read-only, and the returned sequences must be strictly increasing: a stored row
/// that repeats or regresses fails closed instead of being skipped, so a reader
/// cannot concatenate two disjoint histories.
///
/// # Errors
///
/// Returns [`RecoveryError::Journal`] when the journal cannot be read and
/// [`RecoveryError::Invalid`] when a stored row is not canonical.
pub fn read_recovery_audit(
    database: &Database,
    limit: usize,
) -> Result<Vec<DualAuditRecord>, RecoveryError> {
    let bound = u64::try_from(limit).unwrap_or(u64::MAX);
    if limit == 0 || bound > MAX_RETAINED_RECOVERY_AUDIT_ROWS {
        return Err(RecoveryError::Invalid(
            "recovery audit window is outside its bounded range".to_owned(),
        ));
    }
    let read = database.begin_read().map_err(journal)?;
    let table = match read.open_table(SPOOL_RECOVERY_AUDIT_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(error) => return Err(journal(error)),
    };
    let mut records: Vec<DualAuditRecord> = Vec::new();
    let mut previous = None;
    for item in table.iter().map_err(journal)? {
        let (key, value) = item.map_err(journal)?;
        if previous.is_some_and(|earlier| earlier >= key.value()) {
            return Err(RecoveryError::Invalid(
                "recovery audit sequences are not strictly increasing".to_owned(),
            ));
        }
        previous = Some(key.value());
        let row: RecoveryAuditRow = decode(value.value())?;
        if row.schema_version != RECOVERY_SCHEMA_VERSION || row.sequence != key.value() {
            return Err(RecoveryError::Invalid(
                "recovery audit row has an invalid schema or sequence".to_owned(),
            ));
        }
        records.push(DualAuditRecord {
            correlation: row.correlation,
            kind: row.kind,
            spool: SpoolDelivery::Persisted {
                sequence: row.sequence,
            },
            event_log: EventLogDelivery::current(),
        });
        if records.len() >= limit {
            break;
        }
    }
    Ok(records)
}

/// Durable correlated audit row.
///
/// The Event Log leg is not stored: it is a fixed property of the installed
/// source/event contract rather than a per-event fact, and it is reconstructed on read
/// so a stored row can never claim a delivery this cell cannot perform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryAuditRow {
    schema_version: u16,
    sequence: u64,
    correlation: AuditCorrelation,
    kind: AuditEventKind,
}

/// Boundary revalidation proofs for the approved-only-start and
/// replacement-binding rules (#1757 W11).
#[cfg(test)]
mod recovery_boundary_tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    /// A private journal file for one test. The recovery cell owns the file it
    /// is handed, and two tests never share one.
    fn temp_journal(label: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "eliot-watchdog-recovery-{label}-{}-{index}",
            std::process::id()
        );
        std::env::temp_dir().join(name)
    }

    /// An opaque coordination identity. It carries no process value and no
    /// approval: only the recovery cell's own comparison semantics use it.
    fn coordination(character: char) -> Fallible<PlatformHandle> {
        Ok(PlatformHandle::new(character.to_string().repeat(32))?)
    }

    fn process(process_id: u32, start_time_100ns: u64) -> ProcessIdentity {
        ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path: "C:\\Program Files\\Eliot\\eliot-host.exe".to_owned(),
        }
    }

    /// One installed-recipe sibling scope, written out branch by branch: the
    /// completeness rule compares against `RECOVERY_SIBLING_BRANCHES` itself, so
    /// a fixture that copied that list would prove nothing about it.
    fn installed_scope() -> Fallible<RecoveryScope> {
        RecoveryScope::new(vec![
            SiblingBranchDisposition {
                branch: SiblingBranch::HostKernelLineage,
                disposition: SiblingDisposition::ClosedWithHostJobObject,
            },
            SiblingBranchDisposition {
                branch: SiblingBranch::CanonicalStoreBranch,
                disposition: SiblingDisposition::PreservedUnderExistingPolicy,
            },
            SiblingBranchDisposition {
                branch: SiblingBranch::WatchdogService,
                disposition: SiblingDisposition::IndependentSiblingService,
            },
        ])
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
    }

    fn fenced_target() -> Fallible<(RecoveryTarget, ProcessIdentity)> {
        let identity = process(4_200, 1_000_000);
        let target = RecoveryTarget::bind(
            coordination('a')?,
            coordination('b')?,
            coordination('c')?,
            coordination('d')?,
            &identity,
        )?;
        Ok((target, identity))
    }

    /// What a fresh boundary readback produces while the live SCM configuration
    /// is still the approved registration this operation was opened against.
    fn reproduces_target(target: &RecoveryTarget) -> BoundaryEvidence {
        BoundaryEvidence {
            observed_registration: Some(target.registration.clone()),
            identity_digest: Some(target.identity_digest.clone()),
            generation: Some(target.generation.clone()),
        }
    }

    /// Opens one operation for `target` and reconciles its stop phase, leaving
    /// the durable row parked in `StopObserved` with a start as the next legal
    /// step. The stop observation carries no boundary evidence because a
    /// reconciliation step requests no irreversible effect.
    fn opened_and_stopped(
        database: &Database,
        target: &RecoveryTarget,
    ) -> Fallible<RecoveryOperation> {
        let correlation = AuditCorrelation::new(&coordination('e')?, &coordination('f')?, target)?;
        let operation = RecoveryOperation::begin(
            correlation,
            target.clone(),
            HostResponsiveness::AliveUnresponsive,
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 1,
            },
            installed_scope()?,
        )?;
        let opened = begin_recovery_operation(database, None, &operation)?;
        commit_recovery_step(
            database,
            &opened,
            &RecoveryStep::StopObserved,
            &BoundaryEvidence {
                observed_registration: None,
                identity_digest: None,
                generation: None,
            },
        )
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
    }

    /// Positive: evidence that reproduces the operation's own recorded
    /// registration, runtime identity, and generation agrees, so the approved
    /// unchanged registration is started — only after the observed stop — and the
    /// replacement is recorded with the epoch its Host issued for it.
    #[test]
    fn approved_unchanged_evidence_admits_start_and_binds_replacement() -> TestResult {
        let journal = temp_journal("approved-start");
        let database = Database::create(&journal)?;
        let (target, _fenced_identity) = fenced_target()?;
        assert_eq!(
            revalidate_boundary(&target, &reproduces_target(&target)),
            Ok(())
        );
        let stopped = opened_and_stopped(&database, &target)?;
        assert_eq!(stopped.phase(), RecoveryPhase::StopObserved);
        let requested = commit_recovery_step(
            &database,
            &stopped,
            &RecoveryStep::StartRequested,
            &reproduces_target(&target),
        )?;
        assert_eq!(requested.phase(), RecoveryPhase::StartIntentCommitted);
        let replacement = process(4_201, 2_000_000);
        let replacement_digest = identity_digest(&replacement)?;
        let host_issued_epoch = coordination('9')?;
        let observed = commit_recovery_step(
            &database,
            &requested,
            &RecoveryStep::StartedObserved {
                identity_digest: replacement_digest.clone(),
                host_issued_epoch: host_issued_epoch.clone(),
            },
            &reproduces_target(&target),
        )?;
        assert_eq!(observed.phase(), RecoveryPhase::StartedObserved);
        let (old_identity, new_identity, new_epoch) = observed.target_evidence();
        assert_eq!(old_identity, &target.identity_digest);
        assert_eq!(new_identity, Some(&replacement_digest));
        assert_eq!(new_epoch, Some(&host_issued_epoch));
        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// Refusal: a boundary readback that carries a DIFFERENT approved
    /// registration is refused by content comparison, and the durable operation
    /// stays exactly where the refusal left it.
    #[test]
    fn substituted_registration_refuses_start_and_preserves_operation() -> TestResult {
        let journal = temp_journal("substituted-registration");
        let database = Database::create(&journal)?;
        let (target, _fenced_identity) = fenced_target()?;
        let stopped = opened_and_stopped(&database, &target)?;
        let substituted = BoundaryEvidence {
            observed_registration: Some(coordination('7')?),
            ..reproduces_target(&target)
        };
        let refused = commit_recovery_step(
            &database,
            &stopped,
            &RecoveryStep::StartRequested,
            &substituted,
        );
        assert_eq!(
            refused.err(),
            Some(RecoveryError::Boundary(
                BoundaryRefusal::RegistrationChanged
            ))
        );
        let Some(stored) = read_recovery_operation(&database)? else {
            panic!("the refused start must leave the operation row readable");
        };
        assert_eq!(stored, stopped);
        assert_eq!(stored.phase(), RecoveryPhase::StopObserved);
        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// Refusal: an observed value the readback could not carry is an explicit
    /// absence, never agreement. Each of the three refuses under its own typed
    /// reason, and the registration refuses first because it is compared first.
    #[test]
    fn missing_observed_value_refuses_instead_of_agreeing() -> TestResult {
        let (target, _fenced_identity) = fenced_target()?;
        assert_eq!(
            revalidate_boundary(
                &target,
                &BoundaryEvidence {
                    observed_registration: None,
                    identity_digest: None,
                    generation: None,
                }
            ),
            Err(BoundaryRefusal::RegistrationUnavailable)
        );
        assert_eq!(
            revalidate_boundary(
                &target,
                &BoundaryEvidence {
                    observed_registration: None,
                    ..reproduces_target(&target)
                }
            ),
            Err(BoundaryRefusal::RegistrationUnavailable)
        );
        assert_eq!(
            revalidate_boundary(
                &target,
                &BoundaryEvidence {
                    identity_digest: None,
                    ..reproduces_target(&target)
                }
            ),
            Err(BoundaryRefusal::IdentityNotRetained)
        );
        assert_eq!(
            revalidate_boundary(
                &target,
                &BoundaryEvidence {
                    generation: None,
                    ..reproduces_target(&target)
                }
            ),
            Err(BoundaryRefusal::GenerationUnavailable)
        );
        Ok(())
    }

    /// Refusal: a replacement that presents an epoch a Host issued but the
    /// identity digest of the process this operation already fenced is not a
    /// replacement. The new epoch would otherwise be recorded against the fenced
    /// lineage, and the durable row stays in its start phase.
    #[test]
    fn replacement_reusing_fenced_identity_is_refused() -> TestResult {
        let journal = temp_journal("replayed-replacement-identity");
        let database = Database::create(&journal)?;
        let (target, fenced_identity) = fenced_target()?;
        let stopped = opened_and_stopped(&database, &target)?;
        let requested = commit_recovery_step(
            &database,
            &stopped,
            &RecoveryStep::StartRequested,
            &reproduces_target(&target),
        )?;
        let replayed = RecoveryStep::StartedObserved {
            identity_digest: identity_digest(&fenced_identity)?,
            host_issued_epoch: coordination('9')?,
        };
        let refused = commit_recovery_step(
            &database,
            &requested,
            &replayed,
            &reproduces_target(&target),
        );
        assert_eq!(
            refused.err(),
            Some(RecoveryError::Invalid(
                "replacement reused the fenced target identity".to_owned()
            ))
        );
        let Some(stored) = read_recovery_operation(&database)? else {
            panic!("the refused replacement must leave the operation row readable");
        };
        assert_eq!(stored.phase(), RecoveryPhase::StartIntentCommitted);
        assert_eq!(stored.target_evidence().1, None);
        assert_eq!(stored.target_evidence().2, None);
        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// Refusal through the production fence: with a policy, a durable budget, and
    /// a correlated audit record in hand, a substituted approved registration is
    /// refused before any recipe, epoch, threshold, cooldown, or adapter decision
    /// is reached.
    #[test]
    fn fence_refuses_substituted_registration_before_policy() -> TestResult {
        let journal = temp_journal("fence-registration");
        let database = Database::create(&journal)?;
        let (target, _fenced_identity) = fenced_target()?;
        let budget = read_recovery_budget(&database)?;
        let policy = ApprovedRecoveryPolicy {
            installation: coordination('1')?,
            service: coordination('2')?,
            owner_epoch_digest: target.owner_epoch.clone(),
            recipe_digest: target.recipe_digest.clone(),
            failure_threshold: 1,
            max_attempts: 3,
            budget_window_secs: 3_600,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        };
        let audit = DualAuditRecord::new(
            AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?,
            AuditEventKind::ChallengeTimeout,
        );
        let substituted = BoundaryEvidence {
            observed_registration: Some(coordination('7')?),
            ..reproduces_target(&target)
        };
        let fence = RecoveryFence {
            policy: &policy,
            target: &target,
            evidence: substituted,
            guarantee: EXISTING_SCM_ADAPTER_GUARANTEE,
            open_operation: None,
            budget: &budget,
            audit: &audit,
            now_ms: 0,
        };
        assert_eq!(
            fence_recovery(&fence).err(),
            Some(BoundaryRefusal::RegistrationChanged)
        );
        let _ = std::fs::remove_file(&journal);
        Ok(())
    }
}

/// Decision-pass proofs: the durable budget gate, the independence of the two
/// audit streams, the substitution refusal the existing SCM adapter forces, and
/// the installed-recipe sibling scope (#1757 W2, W3, W6, W10, W11).
#[cfg(test)]
mod recovery_decision_tests {
    use super::*;
    use crate::host_identity_observation::MAX_CHALLENGE_WAIT_SECS;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    /// A private journal file for one test. Two tests never share one, and a test
    /// that simulates a Watchdog restart reopens the SAME file after dropping the
    /// handle, so "survives a restart" is measured and not asserted.
    fn temp_journal(label: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "eliot-watchdog-decision-{label}-{}-{index}",
            std::process::id()
        );
        std::env::temp_dir().join(name)
    }

    fn coordination(character: char) -> Fallible<PlatformHandle> {
        Ok(PlatformHandle::new(character.to_string().repeat(32))?)
    }

    fn process(process_id: u32, start_time_100ns: u64) -> ProcessIdentity {
        ProcessIdentity {
            process_id,
            start_time_100ns,
            image_path: "C:\\Program Files\\Eliot\\eliot-host.exe".to_owned(),
        }
    }

    fn fenced_target() -> Fallible<RecoveryTarget> {
        RecoveryTarget::bind(
            coordination('a')?,
            coordination('b')?,
            coordination('c')?,
            coordination('d')?,
            &process(4_200, 1_000_000),
        )
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
    }

    fn reproduces_target(target: &RecoveryTarget) -> BoundaryEvidence {
        BoundaryEvidence {
            observed_registration: Some(target.registration.clone()),
            identity_digest: Some(target.identity_digest.clone()),
            generation: Some(target.generation.clone()),
        }
    }

    /// One fully-populated fence, so a case can vary exactly one input and see
    /// which check it moves.
    fn fence<'a>(
        approved: &'a ApprovedRecoveryPolicy,
        target: &'a RecoveryTarget,
        excluding: ScmAdapterGuarantee,
        budget: &'a RecoveryBudget,
        audit: &'a DualAuditRecord,
    ) -> RecoveryFence<'a> {
        RecoveryFence {
            policy: approved,
            target,
            evidence: reproduces_target(target),
            guarantee: excluding,
            open_operation: None,
            budget,
            audit,
            now_ms: 0,
        }
    }

    /// One operation identity across every reconciled phase.
    ///
    /// `apply` advances the row revision once per applied step — that is the
    /// optimistic-concurrency guard `commit_recovery_step` compares against, not a
    /// second operation — so the revision is pinned to its exact per-step sequence
    /// while the operation identity, correlation, fenced target, challenge outcome
    /// and budget decision must never change.
    fn assert_stable_operation_identity(
        opened: &RecoveryOperation,
        rows: &[(&RecoveryOperation, u64)],
    ) {
        for (row, expected_revision) in rows {
            assert_eq!(
                row.correlation().operation_id,
                opened.correlation().operation_id
            );
            assert_eq!(row.correlation(), opened.correlation());
            assert_eq!(row.target(), opened.target());
            assert_eq!(
                row.revision(),
                *expected_revision,
                "each applied step advances the row revision exactly once"
            );
            assert_eq!(row.challenge_outcome(), opened.challenge_outcome());
            assert_eq!(row.budget_decision(), opened.budget_decision());
        }
    }

    fn installed_scope() -> Fallible<RecoveryScope> {
        RecoveryScope::new(vec![
            SiblingBranchDisposition {
                branch: SiblingBranch::HostKernelLineage,
                disposition: SiblingDisposition::ClosedWithHostJobObject,
            },
            SiblingBranchDisposition {
                branch: SiblingBranch::CanonicalStoreBranch,
                disposition: SiblingDisposition::PreservedUnderExistingPolicy,
            },
            SiblingBranchDisposition {
                branch: SiblingBranch::WatchdogService,
                disposition: SiblingDisposition::IndependentSiblingService,
            },
        ])
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
    }

    /// The installation-approved policy every case here decides under. Only the
    /// budget-relevant fields vary per case, and they are named so a reader can
    /// see which rule is under test rather than inferring it from a literal.
    fn policy(max_attempts: u32, budget_window_secs: u64) -> Fallible<ApprovedRecoveryPolicy> {
        Ok(ApprovedRecoveryPolicy {
            installation: coordination('1')?,
            service: coordination('2')?,
            owner_epoch_digest: coordination('b')?,
            recipe_digest: coordination('c')?,
            failure_threshold: 1,
            max_attempts,
            budget_window_secs,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        })
    }

    /// An exhausted durable budget admits no SCM effect and is still exhausted
    /// after the journal handle is dropped and reopened. A fresh Watchdog process
    /// reads the SAME row, so exhaustion cannot be reset by restarting.
    #[test]
    fn exhausted_budget_admits_no_effect_and_survives_a_watchdog_restart() -> TestResult {
        let journal = temp_journal("exhausted-budget");
        let approved = policy(2, 3_600)?;
        let attempt_ms = 1_000_000_u64;

        {
            let database = Database::create(&journal)?;
            // A fresh journal has no row: read_recovery_budget returns an explicit
            // empty row rather than inventing attempts, and a live unresponsive
            // Host is admitted with the exact remainder.
            let fresh = read_recovery_budget(&database)?;
            assert_eq!(fresh.used_attempts(attempt_ms, &approved), 0);
            assert_eq!(fresh.consecutive_failures(), 0);
            assert_eq!(fresh.last_attempt_ms(), None);
            assert_eq!(
                fresh.decide(HostResponsiveness::AliveUnresponsive, attempt_ms, &approved),
                RecoveryBudgetDecision::Admitted {
                    remaining_attempts: 2
                }
            );

            // One fenced stop/start pair is ONE consumed attempt, recorded
            // together with the failure this pass classified.
            record_recovery_budget(&database, true, Some(attempt_ms), &approved)?;
            let after_one = read_recovery_budget(&database)?;
            assert_eq!(after_one.used_attempts(attempt_ms, &approved), 1);
            assert_eq!(after_one.consecutive_failures(), 1);
            assert_eq!(
                after_one.decide(HostResponsiveness::AliveUnresponsive, attempt_ms, &approved),
                RecoveryBudgetDecision::Admitted {
                    remaining_attempts: 1
                }
            );

            // The second attempt exhausts the window.
            record_recovery_budget(&database, false, Some(attempt_ms + 1), &approved)?;
        }

        // The Watchdog restarts: the same file, a brand new handle. The count is
        // read back from the durable row, never from a constant.
        {
            let database = Database::open(&journal)?;
            let budget = read_recovery_budget(&database)?;
            assert_eq!(budget.used_attempts(attempt_ms + 1, &approved), 2);
            let decision = budget.decide(
                HostResponsiveness::AliveUnresponsive,
                attempt_ms + 1,
                &approved,
            );
            assert_eq!(decision, RecoveryBudgetDecision::Exhausted);
            assert!(
                !decision.admits_effect(),
                "an exhausted budget must admit no SCM effect"
            );
        }

        // A zero-attempt policy admits nothing even with an untouched budget: the
        // policy, not a constant, is what refuses.
        {
            let database = Database::open(&journal)?;
            let zero = policy(0, 3_600)?;
            let budget = read_recovery_budget(&database)?;
            let decision = budget.decide(HostResponsiveness::AliveUnresponsive, attempt_ms, &zero);
            assert_eq!(decision, RecoveryBudgetDecision::Exhausted);
            assert!(!decision.admits_effect());
        }

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// An attempt that has aged out of the policy's budget window stops counting,
    /// and the remainder is read from the durable row rather than recomputed from
    /// a lifetime total. Uncertainty never admits an effect at any count.
    #[test]
    fn the_budget_window_bounds_the_count_and_uncertainty_never_admits() -> TestResult {
        let journal = temp_journal("budget-window");
        let database = Database::create(&journal)?;
        let approved = policy(3, 60)?;
        let first_ms = 1_000_000_u64;
        let inside_window_ms = first_ms + 30_000;
        let past_window_ms = first_ms + 60_001;

        record_recovery_budget(&database, true, Some(first_ms), &approved)?;
        let budget = read_recovery_budget(&database)?;
        assert_eq!(budget.last_attempt_ms(), Some(first_ms));
        assert_eq!(budget.used_attempts(inside_window_ms, &approved), 1);
        assert_eq!(budget.used_attempts(past_window_ms, &approved), 0);

        // Inside the window the exact remainder is reported; outside it, the
        // full policy budget is available again.
        assert_eq!(
            budget.decide(
                HostResponsiveness::AliveUnresponsive,
                inside_window_ms,
                &approved
            ),
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 2
            }
        );
        assert_eq!(
            budget.decide(
                HostResponsiveness::AliveUnresponsive,
                past_window_ms,
                &approved
            ),
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 3
            }
        );

        // An unresolved challenge is never restart eligibility, however much
        // budget is left.
        let uncertain = HostResponsiveness::Uncertain(ChallengeUncertainty::TargetChanged);
        let decision = budget.decide(uncertain, inside_window_ms, &approved);
        assert_eq!(decision, RecoveryBudgetDecision::ChallengeUnresolved);
        assert!(!decision.admits_effect());

        // And a responsive Host needs no recovery at all.
        assert_eq!(
            budget.decide(HostResponsiveness::Responsive, inside_window_ms, &approved),
            RecoveryBudgetDecision::NoRecoveryRequired
        );
        assert!(!RecoveryBudgetDecision::NoRecoveryRequired.admits_effect());

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// The two audit streams are independent facts. A durable spool row is not
    /// Event Log visibility: the readback reports the exact stored sequence and
    /// re-derives the Event Log leg from the installed source/event contract,
    /// which admits no Watchdog audit record, so nothing can claim it is
    /// readable back. No SCM effect is requested, retried, or replayed here.
    #[test]
    fn spool_persistence_and_event_log_delivery_stay_independent_facts() -> TestResult {
        let journal = temp_journal("dual-audit");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let correlation = AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?;

        // A fresh journal has no rows, and the window bounds are refused rather
        // than silently clamped.
        assert!(read_recovery_audit(&database, 8)?.is_empty());
        assert_eq!(
            read_recovery_audit(&database, 0).err(),
            Some(RecoveryError::Invalid(
                "recovery audit window is outside its bounded range".to_owned()
            ))
        );
        assert_eq!(
            read_recovery_audit(
                &database,
                usize::try_from(MAX_RETAINED_RECOVERY_AUDIT_ROWS)
                    .map_err(|_| "the retained-row bound does not fit a usize")?
                    + 1
            )
            .err(),
            Some(RecoveryError::Invalid(
                "recovery audit window is outside its bounded range".to_owned()
            ))
        );

        // An audit record starts with NEITHER stream claimed.
        let unproven = DualAuditRecord::new(correlation.clone(), AuditEventKind::ChallengeTimeout);
        assert!(!unproven.spool_persisted());
        assert!(!unproven.event_log.readable_back());

        let mut sequences = Vec::new();
        for kind in [
            AuditEventKind::ChallengeTimeout,
            AuditEventKind::BudgetExhausted,
            AuditEventKind::ScmRequest,
            AuditEventKind::ScmReadback,
        ] {
            let recorded =
                record_recovery_audit(&database, &DualAuditRecord::new(correlation.clone(), kind))?;
            assert!(
                recorded.spool_persisted(),
                "the durable append is the spool fact"
            );
            sequences.push(match recorded.spool {
                SpoolDelivery::Persisted { sequence } => sequence,
                SpoolDelivery::Unavailable => panic!("the append reported no sequence"),
            });
        }
        // Sequences are dense and strictly increasing: one append, one sequence.
        assert_eq!(sequences, vec![1, 2, 3, 4]);

        // The bounded readback preserves correlation, kind and order, and reports
        // the stored sequence rather than an assumed one.
        let rows = read_recovery_audit(&database, 8)?;
        assert_eq!(rows.len(), 4);
        for (row, kind) in rows.iter().zip([
            AuditEventKind::ChallengeTimeout,
            AuditEventKind::BudgetExhausted,
            AuditEventKind::ScmRequest,
            AuditEventKind::ScmReadback,
        ]) {
            assert_eq!(row.kind, kind);
            assert_eq!(row.correlation, correlation);
            assert!(row.spool_persisted());
            assert!(!row.event_log.readable_back());
        }
        let read_sequences: Vec<u64> = rows
            .iter()
            .map(|row| match row.spool {
                SpoolDelivery::Persisted { sequence } => sequence,
                SpoolDelivery::Unavailable => panic!("a stored row cannot be unavailable"),
            })
            .collect();
        assert_eq!(read_sequences, sequences);

        // A bounded window reads the OLDEST rows first and never concatenates a
        // second history.
        assert_eq!(read_recovery_audit(&database, 2)?.len(), 2);
        assert_eq!(
            read_recovery_audit(&database, 2)?[0].kind,
            AuditEventKind::ChallengeTimeout
        );

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// The failure threshold is a durable count, not a constant. A fresh budget row
    /// has no journaled failure, so the fence stops at the threshold and never
    /// reaches the checks after it.
    #[test]
    fn the_failure_threshold_refuses_until_a_failure_is_journaled() -> TestResult {
        let journal = temp_journal("failure-threshold");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let audit = DualAuditRecord::new(
            AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?,
            AuditEventKind::ChallengeTimeout,
        );
        let excluding = ScmAdapterGuarantee {
            effect_addresses_service_name_only: false,
            readback_is_a_separate_query: false,
            post_boundary_ambiguity_preserved: true,
        };
        let approved = ApprovedRecoveryPolicy {
            installation: coordination('1')?,
            service: coordination('2')?,
            owner_epoch_digest: target.owner_epoch.clone(),
            recipe_digest: target.recipe_digest.clone(),
            failure_threshold: 1,
            max_attempts: 3,
            budget_window_secs: 3_600,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        };
        let unfailed = read_recovery_budget(&database)?;
        assert_eq!(unfailed.consecutive_failures(), 0);
        assert_eq!(
            fence_recovery(&fence(&approved, &target, excluding, &unfailed, &audit)).err(),
            Some(BoundaryRefusal::FailureThresholdNotReached)
        );

        record_recovery_budget(&database, true, None, &approved)?;
        let failed = read_recovery_budget(&database)?;
        assert_eq!(failed.consecutive_failures(), 1);
        assert_ne!(
            fence_recovery(&fence(&approved, &target, excluding, &failed, &audit)).err(),
            Some(BoundaryRefusal::FailureThresholdNotReached),
            "a journaled failure moves the fence past the threshold"
        );

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// A sink failure stays visible and causes no duplicate restart. The existing
    /// SCM adapter addresses its effect by service name and reads back with a
    /// separate query, so it cannot exclude a generation substitution across its
    /// own effect boundary. The fence therefore REFUSES instead of claiming an
    /// atomic generation fence, and the policy's audit-failure rule is honoured
    /// independently of that structural refusal.
    #[test]
    fn an_unexcludable_substitution_and_a_failed_sink_both_refuse_effects() -> TestResult {
        let journal = temp_journal("sink-and-substitution");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let audit = DualAuditRecord::new(
            AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?,
            AuditEventKind::ChallengeTimeout,
        )
        .with_spool_persisted(1);

        // The adapter's own recorded guarantees, pinned as one exact value rather than
        // three trivially-true field assertions.
        assert_eq!(
            EXISTING_SCM_ADAPTER_GUARANTEE,
            ScmAdapterGuarantee {
                effect_addresses_service_name_only: true,
                readback_is_a_separate_query: true,
                post_boundary_ambiguity_preserved: true,
            },
            "the recorded guarantee is the one this cell is built against"
        );
        assert!(
            !EXISTING_SCM_ADAPTER_GUARANTEE.excludes_generation_substitution(),
            "the installed adapter cannot exclude a generation substitution"
        );

        let approved = ApprovedRecoveryPolicy {
            installation: coordination('1')?,
            service: coordination('2')?,
            owner_epoch_digest: target.owner_epoch.clone(),
            recipe_digest: target.recipe_digest.clone(),
            failure_threshold: 1,
            max_attempts: 3,
            budget_window_secs: 3_600,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        };

        // An adapter that CAN exclude the substitution passes that check, which
        // is what makes the structural refusal below a real limit rather than a
        // blanket denial.
        let excluding = ScmAdapterGuarantee {
            effect_addresses_service_name_only: false,
            readback_is_a_separate_query: false,
            post_boundary_ambiguity_preserved: true,
        };
        assert!(excluding.excludes_generation_substitution());

        // The policy's failure threshold is a durable count, so the fence only
        // reaches its later checks after this pass has journaled a real failure.
        record_recovery_budget(&database, true, None, &approved)?;
        let budget = read_recovery_budget(&database)?;
        assert_eq!(budget.consecutive_failures(), 1);

        // Even with the approved unchanged registration reproduced exactly and no
        // competing attempt, the structural refusal is the one that surfaces.
        let fence = RecoveryFence {
            policy: &approved,
            target: &target,
            evidence: reproduces_target(&target),
            guarantee: EXISTING_SCM_ADAPTER_GUARANTEE,
            open_operation: None,
            budget: &budget,
            audit: &audit,
            now_ms: 0,
        };
        assert_eq!(
            fence_recovery(&fence).err(),
            Some(BoundaryRefusal::GenerationSubstitutionNotExcluded)
        );

        // An adapter that CAN exclude the substitution passes that check, which
        // is what makes the refusal above a real structural limit rather than a
        // blanket denial.
        let admitted = RecoveryFence {
            policy: &approved,
            target: &target,
            evidence: reproduces_target(&target),
            guarantee: excluding,
            open_operation: None,
            budget: &budget,
            audit: &audit,
            now_ms: 0,
        };
        let intent = fence_recovery(&admitted)
            .map_err(|error| format!("an excluding adapter must admit: {error:?}"))?;
        assert_eq!(intent.operation_id, audit.correlation.operation_id);
        assert_eq!(intent.target.identity_digest, target.identity_digest);

        // The audit-failure disposition is the policy's own rule and is checked
        // BEFORE the structural limit: when the policy refuses effects on a failed
        // audit, the unadmitted Event Log leg is what surfaces.
        let audit_refusing = ApprovedRecoveryPolicy {
            audit_failure_refuses_effects: true,
            ..approved.clone()
        };
        let refused_on_sink = RecoveryFence {
            policy: &audit_refusing,
            target: &target,
            evidence: reproduces_target(&target),
            guarantee: excluding,
            open_operation: None,
            budget: &budget,
            audit: &audit,
            now_ms: 0,
        };
        assert_eq!(
            fence_recovery(&refused_on_sink).err(),
            Some(BoundaryRefusal::AuditFailureRefusesEffects)
        );

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// One stable operation survives stop/start uncertainty. A requested stop is
    /// not an observed termination, an unknown outcome keeps its own phase, and
    /// the operation identity never changes across phases, so a retry cannot
    /// become a second operation.
    #[test]
    fn one_stable_operation_survives_stop_and_start_uncertainty() -> TestResult {
        let journal = temp_journal("stable-operation");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let correlation = AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?;
        let intent = RecoveryOperation::begin(
            correlation,
            target.clone(),
            HostResponsiveness::AliveUnresponsive,
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 1,
            },
            installed_scope()?,
        )?;

        let opened = begin_recovery_operation(&database, None, &intent)?;
        assert_eq!(opened.phase(), RecoveryPhase::StopIntentCommitted);
        assert_eq!(opened.revision(), 1);

        // A start cannot be requested while the stop is only an intent: the
        // reconciliation order is enforced, not assumed.
        assert_eq!(
            commit_recovery_step(
                &database,
                &opened,
                &RecoveryStep::StartRequested,
                &reproduces_target(&target),
            )
            .err(),
            Some(RecoveryError::IllegalPhase),
            "a start before an observed stop must not be accepted"
        );
        assert_eq!(
            read_recovery_operation(&database)?.map(|row| row.phase()),
            Some(RecoveryPhase::StopIntentCommitted),
            "the refused step leaves the durable row where the refusal left it"
        );

        // An unreadable termination is preserved as its own phase, never assumed.
        let unknown_stop = commit_recovery_step(
            &database,
            &opened,
            &RecoveryStep::StopOutcomeUnknown,
            &BoundaryEvidence {
                observed_registration: None,
                identity_digest: None,
                generation: None,
            },
        )?;
        // The start path needs an OBSERVED stop, and it runs in its own journal so
        // the two reconciliations never overwrite each other's durable row.
        let start_journal = temp_journal("stable-operation-start");
        let start_database = Database::create(&start_journal)?;
        assert_eq!(
            read_recovery_operation(&start_database)?,
            None,
            "a second journal holds no operation of its own"
        );
        let start_opened = begin_recovery_operation(&start_database, None, &intent)?;
        assert_eq!(start_opened.phase(), RecoveryPhase::StopIntentCommitted);
        let observed_stop = commit_recovery_step(
            &start_database,
            &start_opened,
            &RecoveryStep::StopObserved,
            &BoundaryEvidence {
                observed_registration: None,
                identity_digest: None,
                generation: None,
            },
        )?;
        let requested = commit_recovery_step(
            &start_database,
            &observed_stop,
            &RecoveryStep::StartRequested,
            &reproduces_target(&target),
        )?;
        assert_eq!(requested.phase(), RecoveryPhase::StartIntentCommitted);
        let unknown_start = commit_recovery_step(
            &start_database,
            &requested,
            &RecoveryStep::StartOutcomeUnknown,
            &reproduces_target(&target),
        )?;
        assert_eq!(unknown_start.phase(), RecoveryPhase::StartOutcomeUnknown);

        // One identity throughout: the same stable operation identity, the same
        // correlation and the same fenced target in every phase. The revision is
        // NOT stable — `apply` advances it once per applied step, which is the
        // optimistic-concurrency guard `commit_recovery_step` compares against —
        // so the exact per-step sequence is asserted instead, and what must never
        // change is the operation identity inside the correlation.
        assert_stable_operation_identity(
            &opened,
            &[(&unknown_stop, 2), (&requested, 3), (&unknown_start, 4)],
        );
        // The durable row is the phase the last committed step left, never a
        // second operation opened under a new identity.
        assert_eq!(
            read_recovery_operation(&start_database)?,
            Some(unknown_start.clone())
        );
        assert_eq!(
            read_recovery_operation(&database)?,
            Some(unknown_stop.clone())
        );

        let _ = std::fs::remove_file(&journal);
        let _ = std::fs::remove_file(&start_journal);
        Ok(())
    }

    /// A replacement challenge establishes its observed responsiveness and
    /// nothing else. There is deliberately no resolved variant: the underlying
    /// Problem is resolved by the Governor's canonical transition, never by a
    /// restart.
    #[test]
    fn a_replacement_challenge_establishes_observed_responsiveness_only() {
        assert_eq!(
            replacement_challenge_scope(HostResponsiveness::Responsive),
            ReplacementChallengeScope::ObservedResponsivenessOnly
        );
        assert_eq!(
            replacement_challenge_scope(HostResponsiveness::AliveUnresponsive),
            ReplacementChallengeScope::Unresolved
        );
        for uncertain in [
            ChallengeUncertainty::TargetNotLive,
            ChallengeUncertainty::TargetChanged,
            ChallengeUncertainty::InadequateCoverage,
        ] {
            assert_eq!(
                replacement_challenge_scope(HostResponsiveness::Uncertain(uncertain)),
                ReplacementChallengeScope::Unresolved,
                "an uncertain replacement challenge establishes nothing"
            );
        }
    }

    /// An unknown outcome is its own preserved phase, never a completed step. It is
    /// terminal for the operation: it cannot be walked forward into a start, and
    /// it cannot be re-observed as a fresh `StopObserved`.
    #[test]
    fn an_unknown_stop_outcome_is_preserved_and_admits_no_start() -> TestResult {
        let journal = temp_journal("unknown-stop");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let intent = RecoveryOperation::begin(
            AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?,
            target.clone(),
            HostResponsiveness::AliveUnresponsive,
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 1,
            },
            installed_scope()?,
        )?;
        let opened = begin_recovery_operation(&database, None, &intent)?;
        let unknown_stop = commit_recovery_step(
            &database,
            &opened,
            &RecoveryStep::StopOutcomeUnknown,
            &BoundaryEvidence {
                observed_registration: None,
                identity_digest: None,
                generation: None,
            },
        )?;
        assert_eq!(unknown_stop.phase(), RecoveryPhase::StopOutcomeUnknown);

        let mut candidate = unknown_stop.clone();
        assert_eq!(
            RecoveryOperation::apply(&mut candidate, &RecoveryStep::StopObserved).err(),
            Some(RecoveryError::IllegalPhase),
            "an unknown stop outcome is not re-observed as a fresh step"
        );
        assert_eq!(
            RecoveryOperation::apply(&mut candidate, &RecoveryStep::StartRequested).err(),
            Some(RecoveryError::IllegalPhase),
            "an unknown stop outcome admits no start"
        );
        assert_eq!(
            candidate, unknown_stop,
            "a refused step never leaves the operation half-advanced"
        );
        assert_eq!(
            read_recovery_operation(&database)?,
            Some(unknown_stop),
            "the durable row keeps the unknown phase"
        );

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// A competing attempt is excluded by a durable row, not by a lock the hung
    /// Host holds, and a recovery scope must name every supervised sibling
    /// exactly once under its installed disposition.
    #[test]
    fn competing_attempts_are_excluded_durably_and_the_scope_is_complete() -> TestResult {
        let journal = temp_journal("exclusion-and-scope");
        let database = Database::create(&journal)?;
        let target = fenced_target()?;
        let audit = DualAuditRecord::new(
            AuditCorrelation::new(&coordination('e')?, &coordination('f')?, &target)?,
            AuditEventKind::ChallengeTimeout,
        );
        let excluding = ScmAdapterGuarantee {
            effect_addresses_service_name_only: false,
            readback_is_a_separate_query: false,
            post_boundary_ambiguity_preserved: true,
        };
        let approved = ApprovedRecoveryPolicy {
            installation: coordination('1')?,
            service: coordination('2')?,
            owner_epoch_digest: target.owner_epoch.clone(),
            recipe_digest: target.recipe_digest.clone(),
            failure_threshold: 1,
            max_attempts: 3,
            budget_window_secs: 3_600,
            cooldown_secs: 0,
            exclusive_attempt: true,
            audit_failure_refuses_effects: false,
        };

        // The policy's failure threshold is a durable count: without a journaled
        // failure the fence stops at the threshold and never reaches the
        // competing-attempt exclusion, so the failure is recorded first.
        record_recovery_budget(&database, true, None, &approved)?;
        let budget = read_recovery_budget(&database)?;
        assert_eq!(budget.consecutive_failures(), 1);

        // The scope names every branch of the supervision tree exactly once. The
        // completeness rule compares against RECOVERY_SIBLING_BRANCHES itself, so
        // an omitted or duplicated branch is refused.
        let complete = installed_scope()?;
        assert_eq!(complete.siblings.len(), RECOVERY_SIBLING_BRANCHES.len());
        for branch in RECOVERY_SIBLING_BRANCHES {
            assert_eq!(
                complete
                    .siblings
                    .iter()
                    .filter(|entry| entry.branch == branch)
                    .count(),
                1,
                "every supervised sibling needs exactly one disposition"
            );
        }
        let mut omitted = complete.siblings.clone();
        omitted.pop();
        assert_eq!(
            RecoveryScope::new(omitted).err(),
            Some(RecoveryError::IncompleteScope)
        );
        let mut duplicated = complete.siblings.clone();
        duplicated.push(duplicated[0]);
        assert_eq!(
            RecoveryScope::new(duplicated).err(),
            Some(RecoveryError::IncompleteScope)
        );

        // Open one operation, then prove a second one is excluded by the durable
        // row rather than by anything the process is holding.
        let intent = RecoveryOperation::begin(
            audit.correlation.clone(),
            target.clone(),
            HostResponsiveness::AliveUnresponsive,
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 1,
            },
            complete,
        )?;
        let opened = begin_recovery_operation(&database, None, &intent)?;
        let competing = RecoveryOperation::begin(
            audit.correlation.clone(),
            target.clone(),
            HostResponsiveness::AliveUnresponsive,
            RecoveryBudgetDecision::Admitted {
                remaining_attempts: 1,
            },
            installed_scope()?,
        )?;
        assert_eq!(
            begin_recovery_operation(&database, None, &competing).err(),
            Some(RecoveryError::OperationOpen)
        );

        // And the fence refuses the competing attempt under the same rule.
        let fence = RecoveryFence {
            policy: &approved,
            target: &target,
            evidence: reproduces_target(&target),
            guarantee: excluding,
            open_operation: Some(&opened),
            budget: &budget,
            audit: &audit,
            now_ms: 0,
        };
        assert_eq!(
            fence_recovery(&fence).err(),
            Some(BoundaryRefusal::ConcurrentAttempt)
        );

        let _ = std::fs::remove_file(&journal);
        Ok(())
    }

    /// The bounded observation rechecks target identity around the interval. A
    /// competently attempted challenge against a live target is
    /// `ALIVE_UNRESPONSIVE` only while the same retained process identity is still
    /// observed at the end of the interval; a target that changed, lost its
    /// identity, or stopped stays an explicit uncertainty and is never
    /// authenticated health.
    #[test]
    fn the_bounded_interval_rechecks_the_target_before_reporting_unresponsive() -> TestResult {
        let live = ProcessIdentityHolder::of(process(4_200, 1_000_000));
        let before = HostObservation {
            state: HostObservationState::Running,
            identity: Some(live.identity.clone()),
        };
        let Some(wait) = BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS) else {
            panic!("the published bound must be constructible");
        };
        let timeout = ChallengeAttemptOutcome::CompetentTimeout;

        // The stalled control loop: live, competently challenged, bound expired.
        assert_eq!(
            bounded_responsiveness(&before, &wait, &timeout, &before),
            HostResponsiveness::AliveUnresponsive
        );
        assert_eq!(
            before.responsiveness(&wait, &timeout),
            HostResponsiveness::AliveUnresponsive
        );

        // A substituted target across the interval is never health.
        let substituted = HostObservation {
            state: HostObservationState::Running,
            identity: Some(process(4_299, 1_000_000)),
        };
        assert_eq!(
            bounded_responsiveness(&before, &wait, &timeout, &substituted),
            HostResponsiveness::Uncertain(ChallengeUncertainty::TargetChanged)
        );

        // A target that lost its retained identity is inadequate coverage, not
        // agreement.
        let unidentified = HostObservation {
            state: HostObservationState::Running,
            identity: None,
        };
        assert_eq!(
            bounded_responsiveness(&before, &wait, &timeout, &unidentified),
            HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage)
        );

        // A target that stopped inside the interval is not a live unresponsive
        // Host at all.
        let stopped = HostObservation {
            state: HostObservationState::AbsentOrStopped,
            identity: Some(live.identity.clone()),
        };
        assert_eq!(
            bounded_responsiveness(&before, &wait, &timeout, &stopped),
            HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive)
        );

        // An incompetent attempt keeps its own named uncertainty, and a cancelled
        // wait never produces a verdict.
        assert_eq!(
            before.responsiveness(
                &wait,
                &ChallengeAttemptOutcome::Uncertain(ChallengeUncertainty::TargetNotLive)
            ),
            HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive)
        );
        assert_eq!(
            before.responsiveness(
                &wait,
                &ChallengeAttemptOutcome::Uncertain(ChallengeUncertainty::InadequateCoverage)
            ),
            HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage)
        );
        let mut cancelled = BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS)
            .ok_or("the published bound must be constructible")?;
        cancelled.cancel();
        assert!(cancelled.is_cancelled());
        assert_eq!(
            before.responsiveness(&cancelled, &timeout),
            HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage)
        );

        // An unbounded or zero interval cannot be constructed at all.
        assert!(BoundedChallengeWait::new(0).is_none());
        assert!(BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS + 1).is_none());

        Ok(())
    }

    /// Keeps the one retained identity in one place so the interval cases above
    /// compare content, never a copied literal.
    struct ProcessIdentityHolder {
        identity: ProcessIdentity,
    }

    impl ProcessIdentityHolder {
        fn of(identity: ProcessIdentity) -> Self {
            Self { identity }
        }
    }
}
