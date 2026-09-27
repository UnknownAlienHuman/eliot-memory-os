//! Canonical immutable Failure Capsule at the Kernel authority boundary.
//!
//! Traceability: issue #1917; I18.45
//! (`docs/architecture/I18-45-failure-capsule-and-wait-for-diagnostics-tests.md`).
//!
//! This module owns the canonical record for a terminal runtime failure. It is
//! a *record* boundary: it mints no Session, lease, canonical write, or
//! external-effect authority, and it grants no recovery. It states, for one
//! failed request attempt, what was attempted, what is still held, what is
//! still unknown, which evidence proves it, and how to reproduce it.
//!
//! Three properties are structural, not conventional:
//!
//! - **Immutable.** Every field is private and every accessor takes `&self`.
//!   The crate exposes no `&mut` path, no setter, and no `Deserialize`
//!   implementation, so a holder cannot revise a capsule after the fact. A
//!   retry does not amend the prior capsule: it mints a *new* capsule that
//!   names the prior [`AttemptLineage`].
//! - **References, not payloads.** Raw evidence is carried as
//!   [`RawEvidenceRef`] — a typed owner plus a durable locator. The record has
//!   no field that can hold raw bytes, so embedding a payload is unexpressible;
//!   a locator that would be silently truncated is refused by
//!   [`RawEvidenceRef::new`] rather than shortened.
//! - **One capsule per terminal failure.** [`TerminalFailure`] owns exactly
//!   one [`FailureCapsule`] by construction (non-optional field), so terminal
//!   failure cannot be exposed without the capsule that explains it.
//!
//! The wait-for dependency is a data description of what the failed attempt is
//! blocked on, naming the blocked owner, the blocked resource, and the
//! lifecycle transition the owner still owes. Its vocabulary is the durable
//! ORS reservation vocabulary already owned by the Kernel's store owner
//! ([`WriterReservationToken`], [`ReservedScope`], [`ReservationState`]), not a
//! local invention.
//!
//! Forbidden authority: no canonical transition, no ordering authority, no
//! effect claim beyond the disposition the caller observed.

#![forbid(unsafe_code)]

use std::fmt;

use eliot_ors::{ReservationState, ReservedScope, WriterReservationToken};
use serde::Serialize;

/// Maximum byte length of one raw-evidence locator.
///
/// A longer locator is refused, never shortened: truncation is the exact
/// failure this record exists to prevent.
const MAX_RAW_EVIDENCE_REFERENCE_BYTES: usize = 1_024;

/// The runtime failure families the contract names for this record.
///
/// These are the five families every terminal-failure path must cover; the
/// record does not widen or merge them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FailureKind {
    /// The operation exceeded its admitted deadline.
    Timeout,
    /// The operation cannot proceed because a dependency it needs is held.
    Deadlock,
    /// The process performing the operation died before the outcome was known.
    Crash,
    /// The store outcome is unknown: the write may or may not have landed.
    UnknownStoreOutcome,
    /// A promotion failed and the operation did not take effect.
    PromotionFailure,
}

impl FailureKind {
    /// Returns the stable wire name of the family.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Deadlock => "deadlock",
            Self::Crash => "crash",
            Self::UnknownStoreOutcome => "unknown_store_outcome",
            Self::PromotionFailure => "promotion_failure",
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Disposition of the process that was performing the failed operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ProcessDisposition {
    /// No external process was ever claimed for this operation.
    NoProcessClaimed,
    /// A claimed process is still running and no enforcement was observed.
    ///
    /// This is the leaked-process case: liveness without termination evidence
    /// is never reported as a stop.
    ProcessLeaked,
    /// Termination of the claimed process was directly observed.
    TerminationObserved,
}

impl ProcessDisposition {
    /// Returns the stable wire name of the disposition.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoProcessClaimed => "no_process_claimed",
            Self::ProcessLeaked => "process_leaked",
            Self::TerminationObserved => "termination_observed",
        }
    }
}

impl fmt::Display for ProcessDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Disposition of the resource the failed operation was waiting on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ResourceDisposition {
    /// A named owner still holds the resource; see [`WaitForDependency`].
    HeldByBlockedOwner,
    /// The resource was released and the release is durably observed.
    Released,
    /// Neither hold nor release is durably observed.
    ///
    /// Explicitly unknown, never inferred from the absence of a complaint.
    Unknown,
}

impl ResourceDisposition {
    /// Returns the stable wire name of the disposition.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeldByBlockedOwner => "held_by_blocked_owner",
            Self::Released => "released",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ResourceDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Disposition of the external effect the failed operation would have had.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EffectDisposition {
    /// No external effect was claimed for this request.
    NotClaimed,
    /// The effect is durably committed.
    Committed,
    /// The durable outcome is unknown; the effect may or may not have landed.
    ///
    /// This is the unknown-store-outcome case and is deliberately distinct from
    /// [`Self::NotClaimed`]: absence of an effect claim is not evidence that no
    /// effect happened.
    Unknown,
}

impl EffectDisposition {
    /// Returns the stable wire name of the disposition.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotClaimed => "not_claimed",
            Self::Committed => "committed",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for EffectDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The three dispositions every capsule states explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Disposition {
    /// What happened to the process performing the operation.
    pub process: ProcessDisposition,
    /// What happened to the contended resource.
    pub resource: ResourceDisposition,
    /// What happened to the external effect.
    pub effect: EffectDisposition,
}

impl Disposition {
    /// States all three dispositions together.
    #[must_use]
    pub fn new(
        process: ProcessDisposition,
        resource: ResourceDisposition,
        effect: EffectDisposition,
    ) -> Self {
        Self {
            process,
            resource,
            effect,
        }
    }
}

/// The identity of the failed request attempt.
///
/// Sourced from the presented request, never invented: the request identity
/// the frame carried and the governed attempt identity the owning route minted
/// for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureIdentity {
    request_id: String,
    attempt_id: String,
}

impl FailureIdentity {
    /// Binds the request identity to the attempt identity that failed.
    ///
    /// An empty request or attempt identity is refused: a capsule that cannot
    /// be attributed to an attempt is not evidence.
    pub fn new(
        request_id: impl Into<String>,
        attempt_id: impl Into<String>,
    ) -> Result<Self, FailureCapsuleError> {
        let request_id = request_id.into();
        let attempt_id = attempt_id.into();
        if request_id.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyIdentity {
                field: "request_id",
            });
        }
        if attempt_id.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyIdentity {
                field: "attempt_id",
            });
        }
        Ok(Self {
            request_id,
            attempt_id,
        })
    }

    /// Returns the request identity that failed.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the governed attempt identity that failed.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
}

/// The durable owner of one piece of raw evidence.
///
/// Each variant names a store the Kernel already owns a root for, so a
/// reference can be resolved to real bytes by the owning component.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RawEvidenceOwner {
    /// The receipt journal root.
    ReceiptJournal,
    /// The durable operational-recovery-state root.
    OperationalRecoveryState,
    /// The process-execution authority's observation record.
    ProcessAuthority,
}

impl RawEvidenceOwner {
    /// Returns the stable wire name of the evidence owner.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptJournal => "receipt_journal",
            Self::OperationalRecoveryState => "operational_recovery_state",
            Self::ProcessAuthority => "process_authority",
        }
    }
}

impl fmt::Display for RawEvidenceOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A reference to raw evidence held by a durable owner.
///
/// This type has no payload field, by construction: a capsule can name where
/// the evidence lives but cannot carry, embed, or shorten it. The locator is
/// refused when it is empty, carries control characters, or exceeds
/// [`MAX_RAW_EVIDENCE_REFERENCE_BYTES`] — a refusal, never a truncation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawEvidenceRef {
    owner: RawEvidenceOwner,
    reference: String,
}

impl RawEvidenceRef {
    /// References one durable artifact held by `owner`.
    pub fn new(
        owner: RawEvidenceOwner,
        reference: impl Into<String>,
    ) -> Result<Self, FailureCapsuleError> {
        let reference = reference.into();
        if reference.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyEvidenceReference { owner });
        }
        if reference.chars().any(char::is_control) {
            return Err(FailureCapsuleError::ControlCharacterEvidenceReference { owner });
        }
        if reference.len() > MAX_RAW_EVIDENCE_REFERENCE_BYTES {
            return Err(FailureCapsuleError::EvidenceReferenceTooLong {
                owner,
                max_bytes: MAX_RAW_EVIDENCE_REFERENCE_BYTES,
            });
        }
        Ok(Self { owner, reference })
    }

    /// Returns the durable owner that holds the evidence.
    #[must_use]
    pub fn owner(&self) -> RawEvidenceOwner {
        self.owner
    }

    /// Returns the locator of the evidence inside its owner.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

impl fmt::Display for RawEvidenceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.owner, self.reference)
    }
}

/// What the failed attempt is blocked on.
///
/// This is a description of a dependency, not a wait helper. All three parts
/// the contract names are present and typed: the blocked **owner** (the
/// reservation that holds the scope), the blocked **resource** (the reserved
/// ordering scope), and the blocked **transition** (the durable reservation
/// lifecycle state the owner still owes).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WaitForDependency {
    blocked_owner: WriterReservationToken,
    blocked_resource: ReservedScope,
    blocked_transition: ReservationState,
}

impl WaitForDependency {
    /// Names the blocked owner, resource, and awaited transition.
    #[must_use]
    pub fn new(
        blocked_owner: WriterReservationToken,
        blocked_resource: ReservedScope,
        blocked_transition: ReservationState,
    ) -> Self {
        Self {
            blocked_owner,
            blocked_resource,
            blocked_transition,
        }
    }

    /// Returns the reservation token of the blocked owner.
    #[must_use]
    pub fn blocked_owner(&self) -> &WriterReservationToken {
        &self.blocked_owner
    }

    /// Returns the reserved ordering scope that is blocked.
    #[must_use]
    pub fn blocked_resource(&self) -> &ReservedScope {
        &self.blocked_resource
    }

    /// Returns the reservation lifecycle transition the owner still owes.
    #[must_use]
    pub fn blocked_transition(&self) -> ReservationState {
        self.blocked_transition
    }

    /// Returns the blocked owner's reservation identity.
    #[must_use]
    pub fn blocked_owner_id(&self) -> &str {
        self.blocked_owner.reservation_id.as_str()
    }

    /// Returns the blocked ordering scope.
    #[must_use]
    pub fn blocked_scope(&self) -> &str {
        self.blocked_resource.scope.as_str()
    }
}

/// Deterministic reproduction material for the failed attempt.
///
/// The absent state is explicit: a failure that is not deterministic carries
/// [`Self::NotDeterministic`] rather than a fabricated seed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Reproduction {
    /// The replay seed that reproduces the failure exactly.
    Seed(String),
    /// The command that reproduces the failure exactly.
    Command(String),
    /// No deterministic reproduction material exists for this failure.
    NotDeterministic,
}

impl Reproduction {
    /// Returns the compact reproduction token for an agent-facing brief.
    #[must_use]
    pub fn as_brief_token(&self) -> Option<&str> {
        match self {
            Self::Seed(seed) => Some(seed.as_str()),
            Self::Command(command) => Some(command.as_str()),
            Self::NotDeterministic => None,
        }
    }
}

/// The attempt lineage a capsule belongs to.
///
/// A first attempt has no prior lineage. A retry mints a **new** lineage whose
/// [`Self::prior_lineage`] names the lineage it follows; the prior capsule is
/// never amended, because this record holds only the prior lineage's identity
/// and exposes no way to write through it. A lineage that declares itself as
/// its own predecessor is refused: that is the shape an overwrite would take.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttemptLineage {
    lineage_id: String,
    prior_lineage: Option<String>,
}

impl AttemptLineage {
    /// Mints the lineage for a first attempt.
    pub fn first(lineage_id: impl Into<String>) -> Result<Self, FailureCapsuleError> {
        let lineage_id = lineage_id.into();
        if lineage_id.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyLineageId);
        }
        Ok(Self {
            lineage_id,
            prior_lineage: None,
        })
    }

    /// Mints the lineage for a retry of `prior_lineage`.
    ///
    /// `lineage_id` must be distinct from `prior_lineage`; reusing it would
    /// make the retry indistinguishable from an overwrite of the prior
    /// attempt, so that substitution is refused instead of accepted.
    pub fn retry(
        lineage_id: impl Into<String>,
        prior_lineage: impl Into<String>,
    ) -> Result<Self, FailureCapsuleError> {
        let lineage_id = lineage_id.into();
        let prior_lineage = prior_lineage.into();
        if lineage_id.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyLineageId);
        }
        if prior_lineage.trim().is_empty() {
            return Err(FailureCapsuleError::EmptyPriorLineage);
        }
        if lineage_id == prior_lineage {
            return Err(FailureCapsuleError::RetryReusesPriorLineage);
        }
        Ok(Self {
            lineage_id,
            prior_lineage: Some(prior_lineage),
        })
    }

    /// Returns this attempt's lineage identity.
    #[must_use]
    pub fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    /// Returns the lineage this attempt retries, or `None` for a first attempt.
    #[must_use]
    pub fn prior_lineage(&self) -> Option<&str> {
        self.prior_lineage.as_deref()
    }
}

/// The canonical immutable record for one terminal runtime failure.
///
/// Every field is private, every accessor takes `&self`, and the type is not
/// deserializable: a capsule that has been minted states one outcome and cannot
/// be revised by any holder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FailureCapsule {
    failure: FailureKind,
    identity: FailureIdentity,
    disposition: Disposition,
    wait_for: Option<WaitForDependency>,
    raw_evidence: Vec<RawEvidenceRef>,
    reproduction: Reproduction,
    lineage: AttemptLineage,
}

impl FailureCapsule {
    /// Mints the one capsule that explains a terminal failure.
    ///
    /// `wait_for` is `Some` exactly when the attempt is blocked on a named
    /// dependency; `raw_evidence` holds references, never payloads.
    #[must_use]
    pub fn new(
        failure: FailureKind,
        identity: FailureIdentity,
        disposition: Disposition,
        wait_for: Option<WaitForDependency>,
        raw_evidence: Vec<RawEvidenceRef>,
        reproduction: Reproduction,
        lineage: AttemptLineage,
    ) -> Self {
        Self {
            failure,
            identity,
            disposition,
            wait_for,
            raw_evidence,
            reproduction,
            lineage,
        }
    }

    /// Returns the failure family this capsule records.
    #[must_use]
    pub fn failure(&self) -> FailureKind {
        self.failure
    }

    /// Returns the request/attempt identity that failed.
    #[must_use]
    pub fn identity(&self) -> &FailureIdentity {
        &self.identity
    }

    /// Returns the process/resource/effect dispositions.
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        self.disposition
    }

    /// Returns the blocked dependency, or `None` when the attempt is not
    /// blocked on a named owner.
    #[must_use]
    pub fn wait_for(&self) -> Option<&WaitForDependency> {
        self.wait_for.as_ref()
    }

    /// Returns the raw-evidence references backing this capsule.
    #[must_use]
    pub fn raw_evidence(&self) -> &[RawEvidenceRef] {
        &self.raw_evidence
    }

    /// Returns the deterministic reproduction material, when it exists.
    #[must_use]
    pub fn reproduction(&self) -> &Reproduction {
        &self.reproduction
    }

    /// Returns this attempt's lineage and the lineage it retries.
    #[must_use]
    pub fn lineage(&self) -> &AttemptLineage {
        &self.lineage
    }

    /// Projects this capsule to the compact agent-facing brief.
    ///
    /// The brief is derived from the capsule and never replaces it: every fact
    /// here is read out of the capsule, and the raw evidence stays behind the
    /// references the capsule holds.
    #[must_use]
    pub fn diagnostic_brief(&self) -> DiagnosticBrief {
        DiagnosticBrief::from_capsule(self)
    }
}

/// The compact agent-facing projection of a [`FailureCapsule`].
///
/// The brief answers "what failed, who holds it, what do I look at" in one
/// line. It is lossy on purpose and is not evidence: the capsule remains the
/// record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticBrief {
    request_id: String,
    attempt_id: String,
    lineage_id: String,
    prior_lineage: Option<String>,
    failure: &'static str,
    process: &'static str,
    resource: &'static str,
    effect: &'static str,
    wait_for: Option<WaitForSummary>,
    raw_evidence_refs: usize,
    reproduction: Option<String>,
}

/// The one-line blocked dependency carried by a [`DiagnosticBrief`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WaitForSummary {
    blocked_owner: String,
    blocked_resource: String,
    blocked_transition: String,
}

impl WaitForSummary {
    /// Returns the blocked owner's identity.
    #[must_use]
    pub fn blocked_owner(&self) -> &str {
        &self.blocked_owner
    }

    /// Returns the blocked ordering scope.
    #[must_use]
    pub fn blocked_resource(&self) -> &str {
        &self.blocked_resource
    }

    /// Returns the lifecycle transition the blocked owner still owes.
    #[must_use]
    pub fn blocked_transition(&self) -> &str {
        &self.blocked_transition
    }
}

impl DiagnosticBrief {
    /// Derives the brief from a capsule.
    #[must_use]
    pub fn from_capsule(capsule: &FailureCapsule) -> Self {
        let identity = capsule.identity();
        let disposition = capsule.disposition();
        Self {
            request_id: identity.request_id().to_owned(),
            attempt_id: identity.attempt_id().to_owned(),
            lineage_id: capsule.lineage().lineage_id().to_owned(),
            prior_lineage: capsule.lineage().prior_lineage().map(str::to_owned),
            failure: capsule.failure().as_str(),
            process: disposition.process.as_str(),
            resource: disposition.resource.as_str(),
            effect: disposition.effect.as_str(),
            wait_for: capsule.wait_for().map(WaitForSummary::from_dependency),
            raw_evidence_refs: capsule.raw_evidence().len(),
            reproduction: capsule.reproduction().as_brief_token().map(str::to_owned),
        }
    }

    /// Returns the request identity that failed.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the attempt identity that failed.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns this attempt's lineage identity.
    #[must_use]
    pub fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    /// Returns the lineage this attempt retries, or `None` for a first attempt.
    #[must_use]
    pub fn prior_lineage(&self) -> Option<&str> {
        self.prior_lineage.as_deref()
    }

    /// Returns the failure family name.
    #[must_use]
    pub fn failure(&self) -> &str {
        self.failure
    }

    /// Returns the process, resource, and effect dispositions, in that order.
    #[must_use]
    pub fn dispositions(&self) -> [&str; 3] {
        [self.process, self.resource, self.effect]
    }

    /// Returns the blocked dependency summary, or `None` when not blocked.
    #[must_use]
    pub fn wait_for(&self) -> Option<&WaitForSummary> {
        self.wait_for.as_ref()
    }

    /// Returns how many raw-evidence references back the capsule.
    #[must_use]
    pub fn raw_evidence_refs(&self) -> usize {
        self.raw_evidence_refs
    }

    /// Returns the deterministic reproduction material, when it exists.
    #[must_use]
    pub fn reproduction(&self) -> Option<&str> {
        self.reproduction.as_deref()
    }
}

impl WaitForSummary {
    fn from_dependency(dependency: &WaitForDependency) -> Self {
        Self {
            blocked_owner: dependency.blocked_owner_id().to_owned(),
            blocked_resource: dependency.blocked_scope().to_owned(),
            blocked_transition: format!("{:?}", dependency.blocked_transition()),
        }
    }
}

impl fmt::Display for DiagnosticBrief {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failure={} request={} attempt={} lineage={}",
            self.failure, self.request_id, self.attempt_id, self.lineage_id
        )?;
        if let Some(prior) = self.prior_lineage() {
            write!(formatter, " retries={prior}")?;
        }
        write!(
            formatter,
            " process={} resource={} effect={}",
            self.process, self.resource, self.effect
        )?;
        if let Some(wait) = &self.wait_for {
            write!(
                formatter,
                " blocked_on_owner={} resource={} awaiting_transition={}",
                wait.blocked_owner, wait.blocked_resource, wait.blocked_transition
            )?;
        }
        write!(formatter, " evidence_refs={}", self.raw_evidence_refs)?;
        match self.reproduction() {
            Some(reproduction) => write!(formatter, " reproduce={reproduction}"),
            None => formatter.write_str(" reproduce=none"),
        }
    }
}

/// Terminal failure exposure: exactly one capsule, by construction.
///
/// The capsule is a non-optional field, so a caller cannot expose a terminal
/// failure without the record that explains it, and cannot attach a second
/// capsule to the same exposure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TerminalFailure {
    capsule: FailureCapsule,
}

impl TerminalFailure {
    /// Exposes a terminal failure together with its one explaining capsule.
    #[must_use]
    pub fn expose(capsule: FailureCapsule) -> Self {
        Self { capsule }
    }

    /// Returns the capsule that explains this terminal failure.
    #[must_use]
    pub fn capsule(&self) -> &FailureCapsule {
        &self.capsule
    }

    /// Returns the compact agent-facing brief for this terminal failure.
    #[must_use]
    pub fn diagnostic_brief(&self) -> DiagnosticBrief {
        self.capsule.diagnostic_brief()
    }
}

/// Typed refusals from the capsule boundary.
///
/// Every refusal is a distinct kind: a caller can tell an unusable identity
/// from an unresolvable evidence reference from a retry that would overwrite
/// its own prior lineage. None of them collapses to a string or a bare code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCapsuleError {
    /// A request or attempt identity was empty, so the capsule could not be
    /// attributed.
    EmptyIdentity {
        /// The empty identity field.
        field: &'static str,
    },
    /// A raw-evidence locator was empty, so it names no artifact.
    EmptyEvidenceReference {
        /// The owner the empty reference was presented for.
        owner: RawEvidenceOwner,
    },
    /// A raw-evidence locator carried control characters.
    ControlCharacterEvidenceReference {
        /// The owner the malformed reference was presented for.
        owner: RawEvidenceOwner,
    },
    /// A raw-evidence locator exceeded the reference bound; it is refused, not
    /// truncated.
    EvidenceReferenceTooLong {
        /// The owner the oversized reference was presented for.
        owner: RawEvidenceOwner,
        /// The bound the reference exceeded.
        max_bytes: usize,
    },
    /// A lineage identity was empty.
    EmptyLineageId,
    /// A prior lineage identity was empty.
    EmptyPriorLineage,
    /// A retry declared its own lineage as the lineage it follows, which is the
    /// shape of an overwrite rather than a new attempt.
    RetryReusesPriorLineage,
}

impl fmt::Display for FailureCapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentity { field } => write!(
                formatter,
                "failure capsule {field} is empty: a capsule must name its attempt"
            ),
            Self::EmptyEvidenceReference { owner } => write!(
                formatter,
                "raw-evidence reference for {owner} is empty: a reference must name an artifact"
            ),
            Self::ControlCharacterEvidenceReference { owner } => write!(
                formatter,
                "raw-evidence reference for {owner} carries control characters"
            ),
            Self::EvidenceReferenceTooLong { owner, max_bytes } => write!(
                formatter,
                "raw-evidence reference for {owner} exceeds {max_bytes} bytes: refused, never truncated"
            ),
            Self::EmptyLineageId => formatter
                .write_str("attempt lineage id is empty: a retry must name a distinct attempt"),
            Self::EmptyPriorLineage => formatter.write_str(
                "prior attempt lineage id is empty: a retry must name the lineage it follows",
            ),
            Self::RetryReusesPriorLineage => formatter
                .write_str("retry lineage reuses its prior lineage: a retry is a distinct attempt"),
        }
    }
}

impl std::error::Error for FailureCapsuleError {}
