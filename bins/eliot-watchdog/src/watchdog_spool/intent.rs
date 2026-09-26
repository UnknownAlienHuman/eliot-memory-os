//! Watchdog-owned intent records for Governor-unavailable reconciliation.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-01.
//! Implementation: I8.1, I8.2, I2.23.
//! I8.1 direct binding: canonical Problem/Incident transitions are performed
//! by the Governor. When the Governor is unavailable, the Watchdog writes
//! `problem_intent` / `incident_intent` records into its own physically
//! separate minimal spool (`watchdog.redb`) for later reconciliation. The
//! records reuse the same restricted non-semantic envelope shape as the ORS
//! owner (`RecoveryPayloadEnvelope`: sha256 payload/record/batch digests over
//! timestamp-free material) but are never stored in the Kernel ORS failure
//! domain (`kernel-ors.redb`) or the host journal
//! (`host-state-journal.redb`), which stay readback-only from this lane.
//!
//! Case-(b) construction: the shared owner-neutral export classes
//! (`WatchdogSpoolPayloadKind` in `eliot-watchdog-core`, mirrored by the
//! Governor `WatchdogEntryKind` and consumed exhaustively by the eliotd
//! adapter) are intentionally NOT extended here — out-of-lane exhaustive
//! matches without a wildcard would break. Intent records are spool-local types
//! persisted as new `WatchdogSpoolPayload` variants through the existing spool
//! tables, batch builder, and digests, and export under the existing `Recovery`
//! (gap-like) class, so ordering and retention are unchanged.
//!
//! Reconciliation boundary (#1754): the deterministic escalation rule below is
//! the production minter for [`GovernorUnavailability`]. Its only production
//! caller is the crate-private
//! [`GovernorIntentAdmissionSource`](crate::GovernorIntentAdmissionSource),
//! which mints only from a genuinely observed admission-path failure and reaches
//! the Watchdog-owned spool through
//! [`WatchdogSpool::observe_governor_unavailability`](super::WatchdogSpool::observe_governor_unavailability),
//! which appends the resulting record inside the same owner transaction that
//! advances the rule. The fenced Kernel side is the `watchdog-spool-batch-v1`
//! route admitted by `eliot-kernel`, whose intent mutation records a pending
//! intent projection keyed by
//! [`watchdog_intent_reconciliation_idempotency_key`] and never a canonical
//! Problem or Incident decision.
//!
//! Episode continuity (#2651): one sustained, observed admission outage is one
//! open episode. That episode mints its Problem intent at
//! [`PROBLEM_INTENT_OBSERVATION_THRESHOLD`] observations, stays open, keeps
//! counting, and mints its Incident intent at
//! [`INCIDENT_INTENT_OBSERVATION_THRESHOLD`], so the configured Incident
//! threshold is reachable inside a single episode instead of only after a
//! reset. Reaching a threshold mints a record; it never closes the episode.
//! The episode is identified by the admitted source observation that opened
//! it, never by the presenting process generation and never by a retry
//! timestamp, so a Watchdog restart continues the same episode while a
//! replacement producer is recorded beside the preserved original lineage.
//!
//! Bounded truthfulness: the episode keeps exactly one observation digest per
//! unit of threshold progress and stops recording evidence once the Incident
//! threshold is reached, so a long outage stays bounded and valid without
//! erasing the original threshold evidence. Threshold progress saturates at
//! the incident threshold and is explicitly not a lifetime failure count; the
//! lifetime counters beside it are diagnostics and never stand in for the
//! identity of an emitted record.
//!
//! Emission and closure are separate durable facts. Closing an episode
//! withdraws nothing: the spooled intents stay retained and unacknowledged
//! until the fenced Kernel route reconciles them, and neither emission nor
//! closure claims a canonical Problem or Incident resolution.
//!
//! Cold-start coverage: the escalation rule above is reached on every failing
//! supervision tick, including the ticks of a Watchdog that started while the
//! Governor was already unavailable. That contour holds a gap-only sensor,
//! whose `Watchdog` object is created only inside `record_heartbeat` and
//! therefore only after a lease has been admitted, so requiring an established
//! supervision epoch before minting would have made every cold-start outage end
//! as a durable gap with no intent at all. [`IntentLineage`] therefore accepts
//! the installer-approved authority epoch of the retained binding as the
//! observation epoch for that contour; see its documentation for the two
//! accepted bases.

use eliot_contracts::sha256_hex;

use super::codec::WatchdogSpoolPayload;
use crate::{GapRecoveryReason, KernelWatchdogError, SERVICE_NAME, SpoolError};

/// True for the spool-local intent payloads, which are stored, retained for
/// forensic linkage, and exported inside their export window once the fenced
/// Kernel intent route admits them. `compaction_plan` never removes an intent,
/// so the original Watchdog record stays linked to whatever the Governor later
/// decides.
pub(crate) fn is_intent_payload(payload: &WatchdogSpoolPayload) -> bool {
    matches!(
        payload,
        WatchdogSpoolPayload::ProblemIntent { .. } | WatchdogSpoolPayload::IncidentIntent { .. }
    )
}

/// Schema revision of the spool-local intent record shape.
///
/// Bumped only by an explicit review that re-checks the canonical-semantics
/// firewall documented on the record types below.
pub(crate) const INTENT_SCHEMA_VERSION: u16 = 1;

const _: () = assert!(INTENT_SCHEMA_VERSION == 1);

/// Maximum number of evidence references carried by one intent record.
///
/// Sixteen 64-hex digests bound the record far below
/// `SPOOL_MAX_RECORD_BYTES` while leaving room for more than one
/// corroborating observation.
pub(crate) const MAX_INTENT_EVIDENCE_REFS: usize = 16;

const _: () = assert!(MAX_INTENT_EVIDENCE_REFS == 16);

/// Maximum accepted length of the intent lineage installation identity.
///
/// Mirrors `SPOOL_EXPORT_CURSOR_IDENTITY_MAX` so intent lineage never exceeds
/// the cursor identity frame it reconciles against.
pub(crate) const MAX_INTENT_LINEAGE_ID_LEN: usize = 1024;

const _: () = assert!(MAX_INTENT_LINEAGE_ID_LEN == 1024);

/// Length of one lowercase or uppercase hex SHA-256 evidence digest.
const SHA256_HEX_LEN: usize = 64;

/// True for an opaque caller-supplied digest with exact SHA-256 hex shape.
fn is_sha256_hex_shape(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Watchdog-owned lineage bound to one intent record.
///
/// Carries only the owner identities the export cursor already binds
/// (installation, generation, epoch) so a later reconciliation can place the
/// intent without inventing authority. Every field is private and [`IntentLineage::new`]
/// is the only construction path.
///
/// `observation_epoch` is whichever epoch contour the observing sensor really
/// owns: its own established supervision epoch once a signed lease has been
/// verified, or — on a gap-only sensor that has never held one — the
/// installer-approved authority epoch sequence of its retained binding. The
/// second basis exists so a Governor outage at Watchdog start escalates instead
/// of only recording a gap, and it is a retained real value rather than a
/// placeholder; the distinction never widens authority, because the record is
/// observation evidence and the fenced submission still names a verified
/// supervision lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IntentLineage {
    installation_id: String,
    watchdog_generation: u64,
    observation_epoch: u64,
}

impl IntentLineage {
    /// Binds one intent lineage; fails closed on blank, oversized, or
    /// uninitialized identities.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the installation identity is empty
    /// or exceeds the bounded frame, or the generation is uninitialized.
    pub(crate) fn new(
        installation_id: String,
        watchdog_generation: u64,
        observation_epoch: u64,
    ) -> Result<Self, SpoolError> {
        if installation_id.is_empty() || installation_id.len() > MAX_INTENT_LINEAGE_ID_LEN {
            return Err(SpoolError::Corrupt(
                "watchdog intent lineage installation identity is unusable".to_owned(),
            ));
        }
        if watchdog_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog intent lineage generation is uninitialized".to_owned(),
            ));
        }
        Ok(Self {
            installation_id,
            watchdog_generation,
            observation_epoch,
        })
    }

    /// Returns the Watchdog generation this lineage binds.
    ///
    /// The rule reads it from the lineage it was actually handed rather than
    /// from a separate argument, so the producing generation of an observation
    /// can never be stated twice or drift from the generation bound into the
    /// episode's original observation lineage.
    #[must_use]
    pub(crate) const fn watchdog_generation(&self) -> u64 {
        self.watchdog_generation
    }
}

/// Proof that the Governor admission path is unavailable, gating intent append.
///
/// The type has no "available" state by construction: both constructors
/// accept exactly the observed lease rejections that demonstrate a Governor
/// admission failure and fail closed on every other error, so retention
/// pressure ([`GapRecoveryReason::SpoolPressure`]) can never mint. A caller
/// holding a live Governor admission has no value of this type to pass.
///
/// Unlike a bare [`GapRecoveryReason`], the proof cannot be minted from a
/// caller-chosen reason: both public constructors require a genuinely
/// observed admission-path failure value. A caller holding a live Governor
/// admission has no failure value to pass, so it cannot mint this proof.
/// The carried reason is always a lease rejection the lane's own admission
/// path observed (`LeaseStale`, `LeaseFenced`, `LeaseInvalid`). Only those
/// exact observed values mint: every other spool or kernel error fails
/// closed, so a non-admission failure can never be converted into a proof.
/// Retention pressure (`SpoolPressure`) and host-identity observations
/// (`Host*`) are never Governor unavailability and never mint. The stored
/// allowlist additionally re-admits `AdmissionUnavailable` for rows minted
/// before this strictness, but no constructor mints it from a fresh
/// observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GovernorUnavailability {
    reason: GapRecoveryReason,
}

impl GovernorUnavailability {
    /// Mints the proof from an observed watchdog admission failure.
    ///
    /// Accepts exactly the lease rejections that demonstrate a Governor
    /// admission failure (`LeaseStale`, `LeaseFenced`, `InvalidLease`); any
    /// other spool error (I/O, database, serialization, corruption, root)
    /// fails closed because it is not an observed Governor admission
    /// failure. The match is deliberately exhaustive with no wildcard: a
    /// future `SpoolError` variant fails the build here instead of
    /// silently minting.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when `error` is not one of the exact
    /// lease-failure variants above.
    pub(crate) fn from_admission_error(error: &SpoolError) -> Result<Self, SpoolError> {
        let reason = match error {
            SpoolError::LeaseStale(_) => GapRecoveryReason::LeaseStale,
            SpoolError::LeaseFenced(_) => GapRecoveryReason::LeaseFenced,
            SpoolError::InvalidLease(_) => GapRecoveryReason::LeaseInvalid,
            SpoolError::Io(_)
            | SpoolError::InvalidProtectedRoot
            | SpoolError::Serialization(_)
            | SpoolError::Database(_)
            | SpoolError::Corrupt(_) => {
                return Err(SpoolError::Corrupt(
                    "watchdog admission error is not an observed Governor admission failure; refusing to mint an intent"
                        .to_owned(),
                ));
            }
        };
        Ok(Self { reason })
    }

    /// Mints the proof from an observed Kernel supervision failure.
    ///
    /// Accepts exactly the kernel lease rejections that demonstrate a
    /// Governor admission failure (`LeaseStale`, `LeaseFenced`,
    /// `LeaseInvalid`); endpoint-unavailable, generic failures, detailed
    /// failures, and retention pressure fail closed because they are not
    /// observed Governor admission failures. The match is deliberately
    /// exhaustive with no wildcard: a future `KernelWatchdogError` variant
    /// fails the build here instead of silently minting.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when `error` is not one of the exact
    /// lease-failure variants above.
    pub(crate) fn from_kernel_error(error: &KernelWatchdogError) -> Result<Self, SpoolError> {
        let reason = match error {
            KernelWatchdogError::LeaseStale => GapRecoveryReason::LeaseStale,
            KernelWatchdogError::LeaseFenced => GapRecoveryReason::LeaseFenced,
            KernelWatchdogError::LeaseInvalid => GapRecoveryReason::LeaseInvalid,
            KernelWatchdogError::Unavailable
            | KernelWatchdogError::Failed
            | KernelWatchdogError::FailedWithDetail(_)
            | KernelWatchdogError::SpoolPressure => {
                return Err(SpoolError::Corrupt(
                    "watchdog kernel error is not an observed Governor admission failure; refusing to mint an intent"
                        .to_owned(),
                ));
            }
        };
        Ok(Self { reason })
    }

    /// Re-admits a stored intent reason at the persistence boundary.
    ///
    /// Accepts exactly the admission-gap codomain the two observed-error
    /// constructors produce; retention pressure and host-identity
    /// observations fail closed here, so a forged or non-canonical row
    /// carrying them never enters the spool. The match is deliberately
    /// exhaustive with no wildcard: a future reason variant fails the build
    /// here instead of silently minting.
    fn from_stored_reason(reason: GapRecoveryReason) -> Result<Self, SpoolError> {
        match reason {
            GapRecoveryReason::AdmissionUnavailable
            | GapRecoveryReason::LeaseStale
            | GapRecoveryReason::LeaseFenced
            | GapRecoveryReason::LeaseInvalid => Ok(Self { reason }),
            GapRecoveryReason::SpoolPressure
            | GapRecoveryReason::HostAbsentOrStopped
            | GapRecoveryReason::HostPidReused
            | GapRecoveryReason::HostImageSubstituted
            | GapRecoveryReason::HostIdentityChanged
            | GapRecoveryReason::HostUnknown => Err(SpoolError::Corrupt(
                "watchdog intent reason is not an observed Governor admission failure; refusing the stored row"
                    .to_owned(),
            )),
        }
    }

    /// Returns the bounded unavailability reason carried by this proof.
    #[must_use]
    pub(crate) const fn reason(self) -> GapRecoveryReason {
        self.reason
    }
}

/// Shared bounds for both intent record shapes: watchdog-owned service, one or
/// more hex evidence digests, and an initialized observation timestamp.
fn validate_intent_fields(
    service: &str,
    evidence_refs: &[String],
    observed_at_ms: u64,
) -> Result<(), SpoolError> {
    if service != SERVICE_NAME {
        return Err(SpoolError::Corrupt(
            "watchdog intent record service is not the watchdog owner".to_owned(),
        ));
    }
    if evidence_refs.is_empty() || evidence_refs.len() > MAX_INTENT_EVIDENCE_REFS {
        return Err(SpoolError::Corrupt(
            "watchdog intent record carries no usable evidence reference".to_owned(),
        ));
    }
    if !evidence_refs
        .iter()
        .all(|digest| is_sha256_hex_shape(digest))
    {
        return Err(SpoolError::Corrupt(
            "watchdog intent evidence reference is not a 64-character hex digest".to_owned(),
        ));
    }
    if observed_at_ms == 0 {
        return Err(SpoolError::Corrupt(
            "watchdog intent observation timestamp is uninitialized".to_owned(),
        ));
    }
    Ok(())
}

/// Spool-local problem intent: evidence refs plus lineage, no semantics.
///
/// Compile-time canonical-semantics firewall (I8.1 "Watchdog does not own"):
/// this record exposes no Current Epistemic Position, task-decision,
/// module-repair, Architecture-change, completion, or model/swarm-budget
/// field by construction. Every field is private and [`ProblemIntentRecord::new`]
/// accepts only `(proof, service, evidence_refs, lineage, observed_at_ms)`; a
/// forbidden category cannot be smuggled through a struct literal outside this
/// module, and any new field requires editing this module plus bumping
/// `INTENT_SCHEMA_VERSION`, which the `const` assertion above pins. No runtime
/// string scan is relied upon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProblemIntentRecord {
    service: String,
    evidence_refs: Vec<String>,
    lineage: IntentLineage,
    observed_at_ms: u64,
    governor_unavailable_reason: GapRecoveryReason,
}

impl ProblemIntentRecord {
    /// Mints one problem intent under a Governor-unavailable proof; fails
    /// closed on any bound violation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service, evidence refs,
    /// lineage, or timestamp fail [`validate_intent_fields`] or the lineage
    /// is unusable.
    pub(crate) fn new(
        proof: GovernorUnavailability,
        service: String,
        evidence_refs: Vec<String>,
        lineage: IntentLineage,
        observed_at_ms: u64,
    ) -> Result<Self, SpoolError> {
        validate_intent_fields(&service, &evidence_refs, observed_at_ms)?;
        Ok(Self {
            service,
            evidence_refs,
            lineage,
            observed_at_ms,
            governor_unavailable_reason: proof.reason(),
        })
    }

    /// Projects this record onto its spool payload for [`super::WatchdogSpool::append`].
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::ProblemIntent {
            service: self.service.clone(),
            evidence_refs: self.evidence_refs.clone(),
            lineage_installation_id: self.lineage.installation_id.clone(),
            lineage_generation: self.lineage.watchdog_generation,
            lineage_epoch: self.lineage.observation_epoch,
            governor_unavailable_reason: self.governor_unavailable_reason,
        }
    }
}

/// Spool-local incident intent: evidence refs plus lineage, no semantics.
///
/// Same compile-time canonical-semantics firewall as [`ProblemIntentRecord`]:
/// private fields, sole proof-gated constructor, schema pinned by
/// `INTENT_SCHEMA_VERSION`. No runtime string scan is relied upon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IncidentIntentRecord {
    service: String,
    evidence_refs: Vec<String>,
    lineage: IntentLineage,
    observed_at_ms: u64,
    governor_unavailable_reason: GapRecoveryReason,
}

impl IncidentIntentRecord {
    /// Mints one incident intent under a Governor-unavailable proof; fails
    /// closed on any bound violation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service, evidence refs,
    /// lineage, or timestamp fail [`validate_intent_fields`] or the lineage
    /// is unusable.
    pub(crate) fn new(
        proof: GovernorUnavailability,
        service: String,
        evidence_refs: Vec<String>,
        lineage: IntentLineage,
        observed_at_ms: u64,
    ) -> Result<Self, SpoolError> {
        validate_intent_fields(&service, &evidence_refs, observed_at_ms)?;
        Ok(Self {
            service,
            evidence_refs,
            lineage,
            observed_at_ms,
            governor_unavailable_reason: proof.reason(),
        })
    }

    /// Projects this record onto its spool payload for [`super::WatchdogSpool::append`].
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::IncidentIntent {
            service: self.service.clone(),
            evidence_refs: self.evidence_refs.clone(),
            lineage_installation_id: self.lineage.installation_id.clone(),
            lineage_generation: self.lineage.watchdog_generation,
            lineage_epoch: self.lineage.observation_epoch,
            governor_unavailable_reason: self.governor_unavailable_reason,
        }
    }
}

/// Observed Governor-unavailability proofs within one open episode that mint
/// its `problem_intent`.
///
/// Three bounded supervision ticks (or admission probes) with a live
/// Governor-admission rejection and no intervening live admission is the
/// configured Problem threshold. The value is a Config Default, not an
/// invariant: the rule is a pure function of the durable episode state below,
/// so changing it changes only when a future episode mints.
pub(crate) const PROBLEM_INTENT_OBSERVATION_THRESHOLD: u32 = 3;

/// Observed Governor-unavailability proofs within one open episode that mint
/// its `incident_intent`.
///
/// The incident threshold is strictly above the problem threshold, so one
/// sustained outage escalates inside its own open episode: it mints one
/// Problem intent at the Problem threshold and then, in that same still-open
/// episode, one Incident intent at the Incident threshold. Neither emission
/// closes the episode, so the escalation stays reachable and the episode
/// remains open until a verified recovery closes it.
pub(crate) const INCIDENT_INTENT_OBSERVATION_THRESHOLD: u32 = 9;

const _: () = assert!(PROBLEM_INTENT_OBSERVATION_THRESHOLD >= 2);
const _: () = assert!(INCIDENT_INTENT_OBSERVATION_THRESHOLD > PROBLEM_INTENT_OBSERVATION_THRESHOLD);

/// Storage revision of the durable deterministic-rule state.
///
/// The current revision states the open episode explicitly: its stable
/// identity, its preserved original observation lineage, the replacement
/// producer that continues it, its threshold-progress counter, its finite
/// threshold evidence, and the exact spool reference of each threshold intent
/// it committed. The superseded revision is read once and explicitly
/// dispositioned through [`INTENT_RULE_LEGACY_SCHEMA_VERSION`].
pub(crate) const INTENT_RULE_SCHEMA_VERSION: u16 = 2;

/// Storage revision of the superseded rule record.
///
/// Retained only so an existing row can be read, carried forward, and marked
/// with an explicit incomplete-history disposition instead of being silently
/// reinterpreted as current state or as fresh empty state.
pub(crate) const INTENT_RULE_LEGACY_SCHEMA_VERSION: u16 = 1;

const _: () = assert!(INTENT_RULE_LEGACY_SCHEMA_VERSION < INTENT_RULE_SCHEMA_VERSION);
const _: () = assert!(INTENT_RULE_SCHEMA_VERSION == 2);

/// Watchdog-owned intent class of one retained spool record.
///
/// The class is an observation label read back from the Watchdog's own
/// restricted record. It is not a canonical Problem or Incident state: the
/// Governor performs the canonical transition after it consumes the intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentClass {
    /// `problem_intent` observation.
    Problem,
    /// `incident_intent` observation.
    Incident,
}

impl WatchdogIntentClass {
    /// Returns the exact Watchdog record kind name for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Problem => "problem_intent",
            Self::Incident => "incident_intent",
        }
    }

    /// Reads the intent class back from one stored payload.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] for a non-intent payload.
    pub(crate) fn of_payload(payload: &WatchdogSpoolPayload) -> Result<Self, SpoolError> {
        match payload {
            WatchdogSpoolPayload::ProblemIntent { .. } => Ok(Self::Problem),
            WatchdogSpoolPayload::IncidentIntent { .. } => Ok(Self::Incident),
            WatchdogSpoolPayload::Heartbeat { .. }
            | WatchdogSpoolPayload::Gap { .. }
            | WatchdogSpoolPayload::Recovery { .. } => Err(SpoolError::Corrupt(
                "watchdog spool record is not an intent payload".to_owned(),
            )),
        }
    }
}

/// Open-episode phase of the Watchdog-owned deterministic escalation rule.
///
/// The phase is the single durable statement of what the open episode has
/// already emitted, so it is never re-derived from a counter and never
/// substituted by a lifetime diagnostic total. Emitting a threshold intent
/// never moves the rule to [`Self::Closed`]: only a verified recovery does.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GovernorIntentEpisodePhase {
    /// No episode is open; the next accepted observation starts a distinct one.
    Closed,
    /// An episode is open and has not reached the Problem threshold.
    Counting,
    /// The Problem threshold was reached and one Problem intent was committed
    /// for this episode. The episode stays open and keeps counting toward the
    /// Incident threshold.
    ProblemEmitted,
    /// The Incident threshold was reached and one Incident intent linked to
    /// this episode was committed. The episode stays open and escalated: a
    /// further failure keeps this explicit state and mints no further
    /// threshold intent.
    IncidentEmitted,
}

impl GovernorIntentEpisodePhase {
    /// True only when no episode is open.
    #[must_use]
    pub(crate) const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Explicit disposition of a rule record whose episode history cannot be
/// reconstructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GovernorIntentLegacyHistory {
    /// This record was written under the current schema, so its episode
    /// identity and threshold-emission references are its own and complete.
    Current,
    /// This record was migrated from the superseded schema. The superseded
    /// schema reset its episode on every emission, so it recorded neither the
    /// identity of the episode those emissions belonged to nor a reference to
    /// the records it had already committed. The retained counters and last
    /// observation are carried forward verbatim, and nothing is inferred from
    /// them: the lifetime counters are never read as continuity, and an
    /// ambiguous reset is never labelled a verified recovery, so a migrated
    /// episode stays open instead of being silently closed.
    Incomplete,
}

/// Durable reference to one threshold intent this rule actually committed.
///
/// The reference names the exact committed spool record, never a later read of
/// the spool high-water mark, and it is persisted in the same owner
/// transaction as the record itself. It is the emission identity of the
/// episode: lifetime counters and evidence counts never stand in for it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GovernorIntentEmission {
    /// Retained spool sequence of the exact committed intent record.
    pub(crate) sequence: u64,
    /// Digest over the identity of that exact record, bound the same way an
    /// export batch binds it.
    pub(crate) record_digest: String,
    /// Digest of the admitted source observation that crossed this threshold.
    ///
    /// A replay of that same admitted source observation reconciles this
    /// emission instead of minting a second sequence, and the identity is the
    /// one the original observation already had rather than a regenerated
    /// timestamp-derived value.
    pub(crate) observation_digest: String,
    /// Owner-clock time of that crossing observation.
    pub(crate) observed_at_ms: u64,
    /// Watchdog generation that produced that crossing observation.
    pub(crate) producer_generation: u64,
}

/// Deterministic classification of one admitted source observation against the
/// current rule, computed without mutating anything.
///
/// The classification is what makes a threshold decision and its emission the
/// same fact: `ThresholdCrossing` names the one class the owner transaction
/// must append and then persist as this episode's emission reference, and
/// `AlreadyCommitted` names the emission a replay reconciles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GovernorIntentObservationClass {
    /// The same admitted source observation already crossed a threshold of
    /// this episode and its emission is already durable. Reconcile that exact
    /// emission; create nothing and advance nothing.
    AlreadyCommitted {
        /// Intent class of the emission already committed.
        intent_class: WatchdogIntentClass,
        /// The emission already committed for that observation.
        emission: GovernorIntentEmission,
    },
    /// The same admitted source observation was already counted inside this
    /// episode. It is not a further failure, so it advances nothing and mints
    /// nothing; a genuinely repeated admission check is a separate observation
    /// and takes the other arms.
    AlreadyCounted,
    /// The observation advances the open episode and crosses exactly this
    /// threshold: append that one intent and persist its reference with the
    /// advancement, under one owner transaction.
    ThresholdCrossing {
        /// Intent class this observation must append.
        intent_class: WatchdogIntentClass,
    },
    /// The observation advances the open episode and crosses no threshold.
    Observed,
}

/// Derives one bounded observation digest for a Governor-unavailability
/// episode.
///
/// The digest covers the exact observed material only: the owning
/// installation, the Watchdog generation, the closed observation source, the
/// observed unavailability reason, and the observation timestamp. It is
/// observation evidence, not a semantic claim, and it never contains project
/// meaning, task decisions, or canonical state.
#[must_use]
pub(crate) fn governor_unavailable_observation_digest(
    installation_id: &str,
    watchdog_generation: u64,
    source: &str,
    reason: GapRecoveryReason,
    observed_at_ms: u64,
) -> String {
    let reason_code = match reason {
        GapRecoveryReason::AdmissionUnavailable => "ADMISSION_UNAVAILABLE",
        GapRecoveryReason::LeaseStale => "LEASE_STALE",
        GapRecoveryReason::LeaseInvalid => "LEASE_INVALID",
        GapRecoveryReason::LeaseFenced => "LEASE_FENCED",
        GapRecoveryReason::HostAbsentOrStopped => "HOST_ABSENT_OR_STOPPED",
        GapRecoveryReason::HostPidReused => "HOST_PID_REUSED",
        GapRecoveryReason::HostImageSubstituted => "HOST_IMAGE_SUBSTITUTED",
        GapRecoveryReason::HostIdentityChanged => "HOST_IDENTITY_CHANGED",
        GapRecoveryReason::HostUnknown => "HOST_UNKNOWN",
        GapRecoveryReason::SpoolPressure => "SPOOL_PRESSURE",
    };
    let material = format!(
        "watchdog-governor-unavailable-observation-v1\0{installation_id}\0{watchdog_generation}\0{source}\0{reason_code}\0{observed_at_ms}"
    );
    sha256_hex(material.as_bytes())
}

/// Bounded number of retained intents carried by one fenced reconciliation
/// pass. The value is the ceiling of the EBP intent-batch payload, so the
/// Watchdog can never build a batch the fenced Kernel route would reject.
pub(crate) const INTENT_RECONCILIATION_MAX_SUBMISSIONS: usize = 16;

const _: () = assert!(INTENT_RECONCILIATION_MAX_SUBMISSIONS == 16);

// The Watchdog and the EBP contract must agree on the batch and evidence
// bounds, or the Watchdog could build a submission the fenced Kernel route
// rejects. These assertions fail the build on any drift instead of at runtime.
const _: () = assert!(
    INTENT_RECONCILIATION_MAX_SUBMISSIONS == eliot_protocol::MAX_WATCHDOG_SPOOL_INTENT_SUBMISSIONS
);
const _: () =
    assert!(MAX_INTENT_EVIDENCE_REFS == eliot_protocol::MAX_WATCHDOG_INTENT_EVIDENCE_REFS);

/// One accepted admitted-source observation, resolved into its durable effect.
///
/// This is the single mutation input of the rule: the owner transaction builds
/// it, appends the threshold intent named by its classification, binds the
/// exact created record into `emission`, and persists the whole advancement
/// together with that record. Nothing here is applied in two steps, so an
/// emission can never exist without its advancement and an advancement can
/// never claim an emission that was not committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernorIntentObservationRecord {
    /// Digest of the admitted source observation, kept as it was first
    /// observed rather than regenerated from a later timestamp.
    pub(crate) observation_digest: String,
    /// Observed unavailability reason carried by the admitting proof.
    pub(crate) reason: GapRecoveryReason,
    /// Owner-clock time of the observation.
    pub(crate) observed_at_ms: u64,
    /// Watchdog generation that produced the observation.
    pub(crate) producer_generation: u64,
    /// The exact threshold intent this observation committed in the same owner
    /// transaction, or `None` when it crossed no threshold.
    pub(crate) emission: Option<(WatchdogIntentClass, GovernorIntentEmission)>,
}

/// Durable state of the Watchdog-owned deterministic escalation rule.
///
/// Persisted in `watchdog.redb` beside the retained records so a restart cannot
/// reset the threshold and skip escalation, and so a live Governor admission is
/// the only thing that closes an open episode.
///
/// The open episode is the rule's real state, not a bare counter: it carries a
/// stable identity, the preserved original observation lineage beside any
/// replacement producer, a threshold-progress counter that saturates at the
/// configured Incident threshold, one finite evidence digest per unit of that
/// progress, and the exact spool reference of each threshold intent it
/// committed. The two lifetime counters are diagnostics only: they record how
/// many intents this installation ever spooled and are never read as emission
/// identity, never as episode continuity, and never as a threshold crossing.
/// There is no hidden state and no caller-chosen reason.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GovernorIntentRuleState {
    pub(crate) schema_version: u16,
    /// Monotonic revision of this record. Every accepted mutation advances it,
    /// so a writer can tell whether the row it validated is still the row it
    /// is about to replace.
    pub(crate) revision: u64,
    /// Phase of the open episode, and the only statement of what it emitted.
    pub(crate) episode_phase: GovernorIntentEpisodePhase,
    /// Disposition of history that cannot be reconstructed.
    pub(crate) legacy_history: GovernorIntentLegacyHistory,
    /// Stable identity of the open episode: the admitted source observation
    /// that opened it. It is never the presenting process generation and never
    /// a retry timestamp, so a restart continues the same episode instead of
    /// re-identifying it.
    pub(crate) episode_id: Option<String>,
    /// Watchdog generation that opened the current episode. It is preserved for
    /// the whole episode and is never overwritten by a later producer.
    pub(crate) episode_opened_by_generation: Option<u64>,
    /// Watchdog generation that most recently advanced the current episode. A
    /// generation above the opening one is recorded here as an honest
    /// replacement producer while the opening lineage stays intact beside it.
    pub(crate) episode_producer_generation: Option<u64>,
    /// Threshold progress of the open episode.
    ///
    /// It saturates at [`INCIDENT_INTENT_OBSERVATION_THRESHOLD`] and is
    /// explicitly **not** a lifetime failure count: it states how far this one
    /// episode progressed toward its two thresholds and nothing more, so a
    /// hundredth continued failure cannot present itself as a hundredth
    /// observation.
    pub(crate) threshold_progress_observations: u32,
    /// Finite threshold evidence of the open episode: exactly one observation
    /// digest per unit of [`Self::threshold_progress_observations`], and no
    /// more. Recording stops once the Incident threshold is reached, so a long
    /// outage stays bounded and valid, keeps the original threshold evidence
    /// that its intents were minted from, and can never exceed the bounded
    /// evidence frame or fail on it.
    pub(crate) threshold_evidence: Vec<String>,
    /// Owner-clock time of the newest observation this rule accepted. It is
    /// declared coverage information, not a per-observation log, so it states
    /// the last observation rather than growing with the episode.
    pub(crate) last_observed_at_ms: u64,
    pub(crate) last_reason: GapRecoveryReason,
    /// The exact `problem_intent` this open episode committed, when it has.
    pub(crate) problem_intent_emission: Option<GovernorIntentEmission>,
    /// The exact `incident_intent` this open episode committed, when it has.
    pub(crate) incident_intent_emission: Option<GovernorIntentEmission>,
    /// Lifetime diagnostic count of committed Problem intents. Diagnostic only;
    /// never emission identity and never episode continuity.
    pub(crate) problem_intents_spooled: u64,
    /// Lifetime diagnostic count of committed Incident intents. Diagnostic only;
    /// never emission identity and never episode continuity.
    pub(crate) incident_intents_spooled: u64,
}

/// Fails closed on one threshold-emission reference that is not canonical.
fn validate_intent_emission(emission: &GovernorIntentEmission) -> Result<(), SpoolError> {
    if emission.sequence == 0
        || emission.observed_at_ms == 0
        || emission.producer_generation == 0
        || !is_sha256_hex_shape(&emission.record_digest)
        || !is_sha256_hex_shape(&emission.observation_digest)
    {
        return Err(SpoolError::Corrupt(
            "watchdog intent rule threshold emission reference is not canonical".to_owned(),
        ));
    }
    Ok(())
}

impl GovernorIntentRuleState {
    /// Returns the closed state of a rule that has never observed a
    /// Governor-unavailability proof.
    #[must_use]
    pub(crate) const fn fresh() -> Self {
        Self {
            schema_version: INTENT_RULE_SCHEMA_VERSION,
            revision: 0,
            episode_phase: GovernorIntentEpisodePhase::Closed,
            legacy_history: GovernorIntentLegacyHistory::Current,
            episode_id: None,
            episode_opened_by_generation: None,
            episode_producer_generation: None,
            threshold_progress_observations: 0,
            threshold_evidence: Vec::new(),
            last_observed_at_ms: 0,
            last_reason: GapRecoveryReason::AdmissionUnavailable,
            problem_intent_emission: None,
            incident_intent_emission: None,
            problem_intents_spooled: 0,
            incident_intents_spooled: 0,
        }
    }

    /// Fails closed on a stored state that is not in canonical form, and
    /// defines every legal phase/counter/evidence combination.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the schema drifted; the threshold
    /// evidence is not canonical, not bounded, or is not exactly one digest per
    /// unit of threshold progress; the threshold progress sits above the
    /// configured incident threshold; a closed phase retains episode state; an
    /// open episode has no stable identity, an unrecorded lineage where one is
    /// required, a producer older than its opener, or a phase that disagrees
    /// with its progress; an emission reference is not canonical; or a
    /// current-schema record claims a threshold crossing it cannot name.
    pub(crate) fn validate(&self) -> Result<(), SpoolError> {
        self.validate_header()?;
        self.validate_episode_identity()?;
        self.validate_phase_against_progress()?;
        if let Some(emission) = self.problem_intent_emission.as_ref() {
            validate_intent_emission(emission)?;
        }
        if let Some(emission) = self.incident_intent_emission.as_ref() {
            validate_intent_emission(emission)?;
        }
        self.validate_current_emission_agreement()
    }

    /// Checks the shape every record must have regardless of its phase: the
    /// schema it was written under, the bounded threshold progress, and a
    /// canonical bounded evidence list.
    fn validate_header(&self) -> Result<(), SpoolError> {
        if self.schema_version != INTENT_RULE_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule state schema is unsupported".to_owned(),
            ));
        }
        if self.threshold_progress_observations > INCIDENT_INTENT_OBSERVATION_THRESHOLD {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule threshold progress is above the configured incident threshold"
                    .to_owned(),
            ));
        }
        if self.threshold_evidence.len() > MAX_INTENT_EVIDENCE_REFS
            || !self
                .threshold_evidence
                .iter()
                .all(|digest| is_sha256_hex_shape(digest))
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule threshold evidence is not canonical and bounded".to_owned(),
            ));
        }
        Ok(())
    }

    /// Checks that a closed episode retains no episode state at all, and that an
    /// open one carries a stable identity, a coherent observation lineage, and
    /// exactly one evidence digest per unit of threshold progress.
    fn validate_episode_identity(&self) -> Result<(), SpoolError> {
        if self.episode_phase.is_closed() {
            if self.episode_id.is_some()
                || self.episode_opened_by_generation.is_some()
                || self.episode_producer_generation.is_some()
                || self.threshold_progress_observations != 0
                || !self.threshold_evidence.is_empty()
                || self.problem_intent_emission.is_some()
                || self.incident_intent_emission.is_some()
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent rule retains episode state while no episode is open"
                        .to_owned(),
                ));
            }
            return Ok(());
        }
        let Some(episode_id) = self.episode_id.as_deref() else {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule open episode carries no stable identity".to_owned(),
            ));
        };
        if !is_sha256_hex_shape(episode_id) {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule episode identity is not a 64-character hex digest".to_owned(),
            ));
        }
        match (
            self.episode_opened_by_generation,
            self.episode_producer_generation,
        ) {
            (None, None) => {
                if self.legacy_history == GovernorIntentLegacyHistory::Current {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule open episode carries no observation lineage"
                            .to_owned(),
                    ));
                }
            }
            (Some(opened), Some(producer)) => {
                if producer < opened {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule open episode producer precedes its opener".to_owned(),
                    ));
                }
            }
            (Some(_), None) => {
                return Err(SpoolError::Corrupt(
                    "watchdog intent rule open episode records only part of its observation lineage"
                        .to_owned(),
                ));
            }
            (None, Some(_)) => {
                if self.legacy_history == GovernorIntentLegacyHistory::Current {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule open episode records only part of its observation lineage"
                            .to_owned(),
                    ));
                }
            }
        }
        if self.threshold_evidence.len() != self.threshold_progress_observations as usize {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule threshold evidence is not one digest per unit of threshold progress"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Checks that the recorded phase is the one the threshold progress implies,
    /// so a phase can never claim a threshold the progress does not reach.
    fn validate_phase_against_progress(&self) -> Result<(), SpoolError> {
        match self.episode_phase {
            GovernorIntentEpisodePhase::Closed | GovernorIntentEpisodePhase::Counting => {
                if self.threshold_progress_observations >= PROBLEM_INTENT_OBSERVATION_THRESHOLD {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule counting episode is at or above the configured problem threshold"
                            .to_owned(),
                    ));
                }
            }
            GovernorIntentEpisodePhase::ProblemEmitted => {
                if self.threshold_progress_observations < PROBLEM_INTENT_OBSERVATION_THRESHOLD
                    || self.threshold_progress_observations >= INCIDENT_INTENT_OBSERVATION_THRESHOLD
                {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule problem-emitted episode is not between the configured thresholds"
                            .to_owned(),
                    ));
                }
            }
            GovernorIntentEpisodePhase::IncidentEmitted => {
                if self.threshold_progress_observations != INCIDENT_INTENT_OBSERVATION_THRESHOLD {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule escalated episode is not at the configured incident threshold"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks that a current-schema record's emission references agree with the
    /// phase it reached. Only an explicitly migrated record may name a threshold
    /// whose record it cannot.
    fn validate_current_emission_agreement(&self) -> Result<(), SpoolError> {
        if self.legacy_history != GovernorIntentLegacyHistory::Current {
            return Ok(());
        }
        // A current-schema record always knows the exact record it
        // committed for a threshold it reached, so its emission references
        // and its phase must agree. Only an explicitly migrated record may
        // name a threshold whose record it cannot.
        let problem_expected = matches!(
            self.episode_phase,
            GovernorIntentEpisodePhase::ProblemEmitted
                | GovernorIntentEpisodePhase::IncidentEmitted
        );
        if problem_expected != self.problem_intent_emission.is_some() {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule problem emission does not match its episode phase".to_owned(),
            ));
        }
        let incident_expected = matches!(
            self.episode_phase,
            GovernorIntentEpisodePhase::IncidentEmitted
        );
        if incident_expected != self.incident_intent_emission.is_some() {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule incident emission does not match its episode phase"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the threshold intent this rule already committed for exactly
    /// this admitted source observation, when it committed one.
    ///
    /// The comparison is against the emission's preserved observation identity,
    /// so a replay of the same admitted source observation reconciles the
    /// emission that was already committed for it instead of minting a second
    /// sequence, and a genuinely repeated admission check — a distinct
    /// observation with an unchanged reason — is not mistaken for that replay.
    pub(crate) fn committed_emission(
        &self,
        observation_digest: &str,
    ) -> Option<(WatchdogIntentClass, GovernorIntentEmission)> {
        if let Some(emission) = self.problem_intent_emission.as_ref()
            && emission.observation_digest == observation_digest
        {
            return Some((WatchdogIntentClass::Problem, emission.clone()));
        }
        if let Some(emission) = self.incident_intent_emission.as_ref()
            && emission.observation_digest == observation_digest
        {
            return Some((WatchdogIntentClass::Incident, emission.clone()));
        }
        None
    }

    /// Classifies one admitted source observation against the current rule
    /// without mutating anything.
    ///
    /// A replay is recognised from bounded, already-retained state only: the
    /// two emission references and the finite threshold evidence of the open
    /// episode. No unbounded set of seen observations is kept, so recognising a
    /// replay can never grow the rule state.
    #[must_use]
    pub(crate) fn classify_observation(
        &self,
        observation_digest: &str,
    ) -> GovernorIntentObservationClass {
        if let Some((intent_class, emission)) = self.committed_emission(observation_digest) {
            return GovernorIntentObservationClass::AlreadyCommitted {
                intent_class,
                emission,
            };
        }
        if self
            .threshold_evidence
            .iter()
            .any(|digest| digest == observation_digest)
        {
            return GovernorIntentObservationClass::AlreadyCounted;
        }
        if self.threshold_progress_observations >= INCIDENT_INTENT_OBSERVATION_THRESHOLD {
            // Threshold progress is already saturated at the configured incident
            // threshold: a further failure keeps the episode explicitly
            // escalated and mints no further threshold intent.
            return GovernorIntentObservationClass::Observed;
        }
        let next = self.threshold_progress_observations.saturating_add(1);
        if next == PROBLEM_INTENT_OBSERVATION_THRESHOLD && self.problem_intent_emission.is_none() {
            return GovernorIntentObservationClass::ThresholdCrossing {
                intent_class: WatchdogIntentClass::Problem,
            };
        }
        if next == INCIDENT_INTENT_OBSERVATION_THRESHOLD && self.incident_intent_emission.is_none()
        {
            return GovernorIntentObservationClass::ThresholdCrossing {
                intent_class: WatchdogIntentClass::Incident,
            };
        }
        GovernorIntentObservationClass::Observed
    }

    /// Applies one accepted admitted-source observation, together with the
    /// threshold intent it committed, as a single durable advancement.
    ///
    /// This is the only mutation of the rule, and it is complete in one call:
    /// the episode is opened or continued, threshold progress advances by one
    /// and records exactly one more evidence digest, the phase states what the
    /// episode has emitted, and the emission reference is bound to the exact
    /// record the owner transaction created. Because the phase and the
    /// reference are applied together, the row is never briefly a threshold
    /// crossing that cannot name its record.
    ///
    /// After the configured Incident threshold the episode stays explicitly
    /// escalated: threshold progress saturates, evidence recording stops, and no
    /// further threshold intent is accepted, so continued failures neither
    /// overflow the counter, duplicate a threshold record, nor fail on the
    /// bounded evidence frame.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the stored state is not canonical,
    /// the observation identity is unusable, the observation was already
    /// resolved in this episode, its producer generation precedes the episode's,
    /// a threshold the episode already emitted is offered again, or a committed
    /// emission does not sit exactly on the threshold it claims.
    pub(crate) fn record_observation(
        &mut self,
        record: GovernorIntentObservationRecord,
    ) -> Result<u32, SpoolError> {
        self.validate()?;
        let GovernorIntentObservationRecord {
            observation_digest,
            reason,
            observed_at_ms,
            producer_generation,
            emission,
        } = record;
        if observed_at_ms == 0
            || producer_generation == 0
            || !is_sha256_hex_shape(&observation_digest)
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule observation is not a usable bounded identity".to_owned(),
            ));
        }
        if self.committed_emission(&observation_digest).is_some()
            || self
                .threshold_evidence
                .iter()
                .any(|digest| digest == &observation_digest)
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule refuses to count an already-resolved admitted source observation"
                    .to_owned(),
            ));
        }
        if let Some((_, committed)) = emission.as_ref() {
            validate_intent_emission(committed)?;
        }
        self.open_or_continue_episode(&observation_digest, producer_generation)?;
        let saturated =
            self.threshold_progress_observations >= INCIDENT_INTENT_OBSERVATION_THRESHOLD;
        if !saturated {
            self.threshold_progress_observations =
                self.threshold_progress_observations.saturating_add(1);
            self.threshold_evidence.push(observation_digest);
        }
        if let Some((intent_class, committed)) = emission {
            self.apply_threshold_emission(intent_class, committed)?;
        }
        self.last_observed_at_ms = observed_at_ms;
        self.last_reason = reason;
        self.revision = self.revision.saturating_add(1);
        self.validate()?;
        Ok(self.threshold_progress_observations)
    }

    /// Opens a new episode, or continues the open one without ever restarting it.
    fn open_or_continue_episode(
        &mut self,
        observation_digest: &str,
        producer_generation: u64,
    ) -> Result<(), SpoolError> {
        if self.episode_phase.is_closed() {
            self.episode_id = Some(observation_digest.to_owned());
            self.episode_opened_by_generation = Some(producer_generation);
            self.episode_producer_generation = Some(producer_generation);
            self.episode_phase = GovernorIntentEpisodePhase::Counting;
            return Ok(());
        }
        if let Some(producer) = self.episode_producer_generation
            && producer_generation < producer
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule observation was produced by an obsolete Watchdog generation"
                    .to_owned(),
            ));
        }
        if let Some(opened) = self.episode_opened_by_generation
            && producer_generation < opened
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule observation was produced by an obsolete Watchdog generation"
                    .to_owned(),
            ));
        }
        // Record the observing generation as this episode's current producer.
        // A generation above the opening one is a replacement producer
        // recorded honestly beside the preserved opening lineage, and a
        // migrated episode whose opening generation was never recorded
        // adopts this generation while that unknown lineage stays unknown
        // rather than being invented.
        self.episode_producer_generation = Some(producer_generation);
        Ok(())
    }

    /// Applies the one threshold emission this observation committed, refusing a
    /// second emission of a threshold the episode already committed and refusing
    /// an emission that does not sit exactly on the threshold it claims.
    fn apply_threshold_emission(
        &mut self,
        intent_class: WatchdogIntentClass,
        committed: GovernorIntentEmission,
    ) -> Result<(), SpoolError> {
        match intent_class {
            WatchdogIntentClass::Problem => {
                if self.problem_intent_emission.is_some() {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule episode already committed its problem intent"
                            .to_owned(),
                    ));
                }
                if self.threshold_progress_observations != PROBLEM_INTENT_OBSERVATION_THRESHOLD {
                    return Err(SpoolError::Corrupt(
                            "watchdog intent rule problem emission does not sit on the configured problem threshold"
                                .to_owned(),
                    ));
                }
                self.problem_intent_emission = Some(committed);
                self.problem_intents_spooled = self.problem_intents_spooled.saturating_add(1);
                self.episode_phase = GovernorIntentEpisodePhase::ProblemEmitted;
            }
            WatchdogIntentClass::Incident => {
                if self.incident_intent_emission.is_some() {
                    return Err(SpoolError::Corrupt(
                        "watchdog intent rule episode already committed its incident intent"
                            .to_owned(),
                    ));
                }
                if self.threshold_progress_observations != INCIDENT_INTENT_OBSERVATION_THRESHOLD {
                    return Err(SpoolError::Corrupt(
                            "watchdog intent rule incident emission does not sit on the configured incident threshold"
                                .to_owned(),
                    ));
                }
                self.incident_intent_emission = Some(committed);
                self.incident_intents_spooled = self.incident_intents_spooled.saturating_add(1);
                self.episode_phase = GovernorIntentEpisodePhase::IncidentEmitted;
            }
        }
        Ok(())
    }

    /// Closes an open episode after a live Governor admission.
    ///
    /// The caller must be the current validated admission-success path; the
    /// method has no timer, no export acknowledgement, and no episode to close
    /// for it. The episode and its revision are re-read and re-validated by the
    /// caller's single writer transaction, and a recovery that is older than the
    /// newest accepted outage observation cannot silently overwrite that newer
    /// observation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the stored state is not canonical,
    /// the recovery identity is uninitialized, or an open episode carries no
    /// stable identity.
    pub(crate) fn close_episode(
        &mut self,
        presenting_generation: u64,
        observed_at_ms: u64,
    ) -> Result<GovernorEpisodeClosure, SpoolError> {
        self.validate()?;
        if observed_at_ms == 0 || presenting_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog intent rule recovery identity is uninitialized".to_owned(),
            ));
        }
        if self.episode_phase.is_closed() {
            return Ok(GovernorEpisodeClosure::AlreadyClosed);
        }
        let episode_id = self.episode_id.clone().ok_or_else(|| {
            SpoolError::Corrupt(
                "watchdog intent rule open episode carries no stable identity".to_owned(),
            )
        })?;
        let obsolete_generation = self
            .episode_producer_generation
            .is_some_and(|producer| presenting_generation < producer);
        if obsolete_generation || observed_at_ms < self.last_observed_at_ms {
            return Ok(GovernorEpisodeClosure::Obsolete);
        }
        self.episode_phase = GovernorIntentEpisodePhase::Closed;
        self.episode_id = None;
        self.episode_opened_by_generation = None;
        self.episode_producer_generation = None;
        self.threshold_progress_observations = 0;
        self.threshold_evidence.clear();
        self.problem_intent_emission = None;
        self.incident_intent_emission = None;
        self.last_observed_at_ms = observed_at_ms;
        self.revision = self.revision.saturating_add(1);
        self.validate()?;
        Ok(GovernorEpisodeClosure::Closed { episode_id })
    }

    /// Returns the finite threshold evidence of the currently open episode.
    #[must_use]
    pub(crate) fn episode_evidence_refs(&self) -> Vec<String> {
        self.threshold_evidence.clone()
    }
}

/// Explicit disposition of one live recovery against the open episode.
///
/// The variants are deliberately distinct so a refused recovery can never be
/// reported as a closure: only a recovery that is not older than the newest
/// accepted outage observation, and is not presented by an obsolete Watchdog
/// generation, closes an episode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GovernorEpisodeClosure {
    /// No episode was open, so the recovery changed nothing.
    AlreadyClosed,
    /// The open episode was closed by this live admission. Its spooled intents
    /// are untouched and stay retained and unacknowledged until the fenced
    /// Kernel route reconciles them; nothing here claims a canonical Problem or
    /// Incident resolution.
    Closed {
        /// Stable identity of the episode this recovery closed.
        episode_id: String,
    },
    /// The recovery was refused as stale: it predates the newest accepted
    /// outage observation, or it was presented by an obsolete Watchdog
    /// generation. The newer observation stands.
    Obsolete,
}

/// Superseded deterministic-rule record, read once and explicitly dispositioned.
///
/// The first schema reset its episode on every emission, so a retained record
/// names neither the episode those emissions belonged to nor the records they
/// committed. It is retained only so its recoverable content can be carried
/// forward verbatim; nothing in it is reinterpreted, and it never becomes fresh
/// empty state.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GovernorIntentRuleStateLegacy {
    pub(crate) schema_version: u16,
    pub(crate) consecutive_unavailable_observations: u32,
    pub(crate) episode_observation_digests: Vec<String>,
    pub(crate) last_observed_at_ms: u64,
    pub(crate) last_reason: GapRecoveryReason,
    pub(crate) problem_intents_spooled: u64,
    pub(crate) incident_intents_spooled: u64,
}

impl GovernorIntentRuleStateLegacy {
    /// Returns the current-schema state this superseded record maps to.
    ///
    /// The lifetime diagnostic counters and the last observation are carried
    /// forward verbatim. The retained consecutive count becomes the migrated
    /// episode's threshold progress, saturated at the configured Incident
    /// threshold, and the retained chain becomes its threshold evidence, so the
    /// record keeps stating exactly how far it had got.
    ///
    /// Deliberately **not** inferred: no emission reference. The superseded
    /// schema recorded none, so a migrated record carries the explicit
    /// incomplete-history disposition and never claims a committed threshold
    /// intent it cannot name. In particular its lifetime counters are never
    /// read as continuity — three unrelated Problem counts are not nine
    /// failures — and its ambiguous reset is never labelled a verified
    /// recovery, so an open migrated episode stays open and a later genuine
    /// threshold crossing commits one new, nameable record.
    #[must_use]
    pub(crate) fn dispositioned(self) -> GovernorIntentRuleState {
        let progress = self
            .consecutive_unavailable_observations
            .min(INCIDENT_INTENT_OBSERVATION_THRESHOLD);
        let episode_phase = if self.consecutive_unavailable_observations == 0 {
            GovernorIntentEpisodePhase::Closed
        } else if progress < PROBLEM_INTENT_OBSERVATION_THRESHOLD {
            GovernorIntentEpisodePhase::Counting
        } else if progress < INCIDENT_INTENT_OBSERVATION_THRESHOLD {
            GovernorIntentEpisodePhase::ProblemEmitted
        } else {
            GovernorIntentEpisodePhase::IncidentEmitted
        };
        GovernorIntentRuleState {
            schema_version: INTENT_RULE_SCHEMA_VERSION,
            revision: 0,
            episode_phase,
            legacy_history: GovernorIntentLegacyHistory::Incomplete,
            episode_id: self.episode_observation_digests.first().cloned(),
            episode_opened_by_generation: None,
            episode_producer_generation: None,
            threshold_progress_observations: progress,
            threshold_evidence: self.episode_observation_digests,
            last_observed_at_ms: self.last_observed_at_ms,
            last_reason: self.last_reason,
            problem_intent_emission: None,
            incident_intent_emission: None,
            problem_intents_spooled: self.problem_intents_spooled,
            incident_intents_spooled: self.incident_intents_spooled,
        }
    }
}

/// Deterministic outcome of one observed Governor-unavailability proof,
/// resolved against the retained spool.
///
/// An emission outcome names the exact committed spool record, and a
/// non-emitting outcome is bounded: it reports how far the open episode has
/// progressed toward its thresholds and nothing more. Neither variant claims a
/// canonical Problem or Incident resolution, and neither claims the episode
/// closed: reaching a threshold mints a record and leaves the episode open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GovernorIntentOutcome {
    /// The observation was counted and no threshold was crossed, or the episode
    /// is already escalated and this observation crossed none.
    ///
    /// `consecutive` is the open episode's threshold progress, which saturates
    /// at [`INCIDENT_INTENT_OBSERVATION_THRESHOLD`]; it is not the exact number
    /// of failures this installation has ever observed. The value is reported
    /// unchanged when a replayed admitted source observation advances nothing.
    Counting { consecutive: u32 },
    /// A `problem_intent` was spooled in `watchdog.redb` by this call, or the
    /// call reconciled the one already spooled for the same admitted source
    /// observation. In both cases the reference names that exact record and the
    /// episode stays open.
    ProblemIntent(WatchdogIntentRecordRef),
    /// An `incident_intent` was spooled in `watchdog.redb` by this call, or the
    /// call reconciled the one already spooled for the same admitted source
    /// observation. In both cases the reference names that exact record, which
    /// is linked to the episode that minted it, and the episode stays open and
    /// escalated.
    IncidentIntent(WatchdogIntentRecordRef),
}

/// Watchdog-owned identity of one spooled intent record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WatchdogIntentRecordRef {
    /// Retained spool sequence of the intent record.
    pub(crate) sequence: u64,
    /// Watchdog-owned intent class of the record.
    pub(crate) intent_class: WatchdogIntentClass,
    /// Observation timestamp of the record.
    pub(crate) observed_at_ms: u64,
    /// Digest over the record identity, used as the fenced Kernel
    /// reconciliation key input.
    pub(crate) record_digest: String,
}

/// One retained Watchdog intent awaiting fenced-Kernel reconciliation.
///
/// Carries the exact original record so the submission preserves the original
/// evidence and lineage and the spool can retain the row for forensic linkage
/// after the acknowledgement. The digests are the same ones the export batch
/// binds, so the fenced route can prove the presented bytes are the retained
/// record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWatchdogIntent {
    /// The exact retained original record.
    pub record: super::WatchdogSpoolEntry,
    /// Watchdog-owned intent class of the record.
    pub intent_class: WatchdogIntentClass,
    /// Digest over the record identity (sequence, schema, timestamp, bytes).
    pub record_digest: String,
    /// Digest over the canonical record bytes.
    pub payload_digest: String,
    /// The Watchdog's own authority epoch lineage, taken from its retained
    /// installer-approved runtime binding.
    ///
    /// This is observation lineage, not a claim about the Kernel's current
    /// epoch. The fenced Kernel route stamps the durable intent record with it
    /// rather than with the presenting Kernel fence, so an exactly-once replay
    /// survives an epoch rotation instead of turning into an identity conflict
    /// and a second pending projection.
    pub epoch_lineage: eliot_contracts::EpochLineageId,
}

/// One durable submit-once receipt for a reconciled spool record.
///
/// The receipt is what makes reconciliation exactly-once per spool record: it
/// is written only after the fenced Kernel acknowledgement is in hand, and any
/// later attempt for the same retained sequence observes [`AlreadySubmitted`]
/// instead of submitting again. The receipt stores the Watchdog-owned
/// idempotency key the Kernel returned so a forged or drifted key can never be
/// written under an already-submitted record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WatchdogIntentSubmission {
    /// Retained spool sequence this receipt closes.
    pub(crate) sequence: u64,
    /// Reconciliation key the Kernel acknowledged for this record.
    pub(crate) idempotency_key: String,
    /// Digest of the Kernel acknowledgement for this record.
    pub(crate) acknowledgement_digest: String,
    /// Owner-clock time the acknowledgement was recorded.
    pub(crate) submitted_at_ms: u64,
}

/// Result of persisting one submit-once receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentSubmissionDisposition {
    /// This call wrote the first receipt for the record.
    Recorded,
    /// A receipt already existed for the record: nothing was written and no
    /// second submission may follow.
    AlreadySubmitted,
}

/// Revalidates one stored intent payload against the constructor bounds.
///
/// Heartbeat, Gap, and Recovery payloads pass through untouched. Intent
/// payloads are reconstructed through the proof-gated constructors and must
/// round-trip byte-equivalent, so a forged or non-canonical row fails closed
/// at the persistence boundary instead of entering the spool. Called from the
/// codec encode/decode paths, which own bounded structural validation.
pub(crate) fn check_stored_intent_payload(
    observed_at_ms: u64,
    payload: &WatchdogSpoolPayload,
) -> Result<(), SpoolError> {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. }
        | WatchdogSpoolPayload::Gap { .. }
        | WatchdogSpoolPayload::Recovery { .. } => Ok(()),
        WatchdogSpoolPayload::ProblemIntent {
            service,
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
        } => {
            let proof = GovernorUnavailability::from_stored_reason(*governor_unavailable_reason)?;
            let lineage = IntentLineage::new(
                lineage_installation_id.clone(),
                *lineage_generation,
                *lineage_epoch,
            )?;
            let record = ProblemIntentRecord::new(
                proof,
                service.clone(),
                evidence_refs.clone(),
                lineage,
                observed_at_ms,
            )?;
            if record.to_payload() != *payload {
                return Err(SpoolError::Corrupt(
                    "watchdog problem intent payload is not in canonical form".to_owned(),
                ));
            }
            Ok(())
        }
        WatchdogSpoolPayload::IncidentIntent {
            service,
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
        } => {
            let proof = GovernorUnavailability::from_stored_reason(*governor_unavailable_reason)?;
            let lineage = IntentLineage::new(
                lineage_installation_id.clone(),
                *lineage_generation,
                *lineage_epoch,
            )?;
            let record = IncidentIntentRecord::new(
                proof,
                service.clone(),
                evidence_refs.clone(),
                lineage,
                observed_at_ms,
            )?;
            if record.to_payload() != *payload {
                return Err(SpoolError::Corrupt(
                    "watchdog incident intent payload is not in canonical form".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::{WatchdogSpool, watchdog_spool_path};
    use super::*;
    use crate::{KernelWatchdogError, SpoolAppendOutcome, WatchdogSpoolExportLimits};
    use eliot_watchdog_core::{WatchdogSpoolCursor, WatchdogSpoolPayloadKind};

    fn evidence_ref(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn test_proof() -> GovernorUnavailability {
        GovernorUnavailability::from_admission_error(&SpoolError::InvalidLease(
            "test-lease".to_owned(),
        ))
        .expect("test lease proof")
    }

    fn test_lineage() -> IntentLineage {
        IntentLineage::new("installation-test".to_owned(), 7, 3).expect("intent lineage")
    }

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("eliot-watchdog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("intent test state dir");
        dir
    }

    #[test]
    fn intent_rows_land_in_watchdog_redb_and_export_for_fenced_reconciliation() {
        let dir = temp_root("intent-rows");
        let spool =
            WatchdogSpool::open_test(&dir.join("watchdog.redb")).expect("open intent spool");
        assert!(matches!(
            spool
                .append(
                    500,
                    WatchdogSpoolPayload::Gap {
                        service: SERVICE_NAME.to_owned(),
                        reason: GapRecoveryReason::AdmissionUnavailable,
                        coverage_claimed: false,
                    }
                )
                .expect("append leading gap"),
            SpoolAppendOutcome::Stored
        ));
        let proof = test_proof();
        let observed_problem = 1_000;
        let problem = ProblemIntentRecord::new(
            proof,
            SERVICE_NAME.to_owned(),
            vec![evidence_ref(0x0c), evidence_ref(0x0d)],
            test_lineage(),
            observed_problem,
        )
        .expect("problem intent");
        assert!(matches!(
            spool
                .append(observed_problem, problem.to_payload())
                .expect("append problem intent"),
            SpoolAppendOutcome::Stored
        ));
        let observed_incident = 2_000;
        let incident = IncidentIntentRecord::new(
            proof,
            SERVICE_NAME.to_owned(),
            vec![evidence_ref(0x0e)],
            test_lineage(),
            observed_incident,
        )
        .expect("incident intent");
        assert!(matches!(
            spool
                .append(observed_incident, incident.to_payload())
                .expect("append incident intent"),
            SpoolAppendOutcome::Stored
        ));
        let entries = spool.readback().expect("intent readback");
        assert_eq!(entries.len(), 3);
        assert!(matches!(
            &entries[0].payload,
            WatchdogSpoolPayload::Gap { .. }
        ));
        assert!(
            matches!(&entries[1].payload, WatchdogSpoolPayload::ProblemIntent {
            evidence_refs, lineage_installation_id, lineage_generation, lineage_epoch,
            governor_unavailable_reason, ..
        } if evidence_refs.len() == 2 && lineage_installation_id == "installation-test"
            && *lineage_generation == 7 && *lineage_epoch == 3
            && *governor_unavailable_reason == GapRecoveryReason::LeaseInvalid)
        );
        assert_eq!(entries[1].observed_at_ms, observed_problem);
        assert!(matches!(
            &entries[2].payload,
            WatchdogSpoolPayload::IncidentIntent { .. }
        ));
        assert_eq!(entries[2].observed_at_ms, observed_incident);
        // The export window continues past the intents: the fenced Kernel
        // intent route reconciles them, and both the leading gap and the two
        // intents ship inside one batch instead of parking the frontier.
        let predecessor = WatchdogSpoolCursor {
            schema_version: 1,
            acknowledged_sequence: 0,
            watchdog_generation: 7,
            watchdog_epoch: 3,
            installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        let high_water = spool.high_water_sequence().expect("intent high-water");
        assert_eq!(high_water, 3);
        let (batch, raws) = spool
            .export_batch(
                &predecessor,
                high_water,
                WatchdogSpoolExportLimits::default(),
            )
            .expect("export continues past intents");
        assert_eq!(batch.entries.len(), 3);
        assert_eq!(batch.first_sequence, 1);
        assert_eq!(batch.last_sequence, 3);
        assert_eq!(batch.entries[0].payload_kind, WatchdogSpoolPayloadKind::Gap);
        assert_eq!(raws.len(), 3);
        drop(spool);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn intent_headed_window_still_forms_a_batch() {
        let dir = temp_root("intent-headed");
        let spool =
            WatchdogSpool::open_test(&dir.join("watchdog.redb")).expect("open intent-headed spool");
        let problem = ProblemIntentRecord::new(
            test_proof(),
            SERVICE_NAME.to_owned(),
            vec![evidence_ref(0x0c)],
            test_lineage(),
            1_000,
        )
        .expect("head problem intent");
        assert!(matches!(
            spool
                .append(1_000, problem.to_payload())
                .expect("append head problem intent"),
            SpoolAppendOutcome::Stored
        ));
        let incident = IncidentIntentRecord::new(
            test_proof(),
            SERVICE_NAME.to_owned(),
            vec![evidence_ref(0x0d)],
            test_lineage(),
            2_000,
        )
        .expect("head incident intent");
        assert!(matches!(
            spool
                .append(2_000, incident.to_payload())
                .expect("append head incident intent"),
            SpoolAppendOutcome::Stored
        ));
        let predecessor = WatchdogSpoolCursor {
            schema_version: 1,
            acknowledged_sequence: 0,
            watchdog_generation: 7,
            watchdog_epoch: 3,
            installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        let high_water = spool
            .high_water_sequence()
            .expect("intent-headed high-water");
        assert_eq!(high_water, 2);
        let (batch, raws) = spool
            .export_batch(
                &predecessor,
                high_water,
                WatchdogSpoolExportLimits::default(),
            )
            .expect("intent-headed export");
        // The export window continues past an intent: the fenced Kernel
        // `watchdog-spool-batch-v1` intent route reconciles it, so a retained
        // intent can never park the frontier in front of later observations.
        assert!(!batch.is_empty_batch);
        assert_eq!(batch.entries.len(), 2);
        assert_eq!(raws.len(), 2);
        assert_eq!(batch.first_sequence, 1);
        assert_eq!(batch.last_sequence, 2);
        assert!(matches!(
            batch.entries[0].payload_kind,
            WatchdogSpoolPayloadKind::Recovery
        ));
        // Both intents stay retained for the Governor's later decision.
        let entries = spool.readback().expect("intent-headed readback");
        assert_eq!(entries.len(), 2);
        drop(spool);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn governor_unavailability_binds_to_observed_admission_failure() {
        // Only exact lease rejections mint, each with its own reason.
        assert_eq!(
            GovernorUnavailability::from_admission_error(&SpoolError::InvalidLease(
                "test-lease".to_owned()
            ))
            .expect("admission invalid-lease proof")
            .reason(),
            GapRecoveryReason::LeaseInvalid
        );
        assert_eq!(
            GovernorUnavailability::from_admission_error(&SpoolError::LeaseStale(
                "test-stale".to_owned()
            ))
            .expect("admission stale proof")
            .reason(),
            GapRecoveryReason::LeaseStale
        );
        assert_eq!(
            GovernorUnavailability::from_admission_error(&SpoolError::LeaseFenced(
                "test-fenced".to_owned()
            ))
            .expect("admission fenced proof")
            .reason(),
            GapRecoveryReason::LeaseFenced
        );
        // Any other spool error fails closed: it is not an observed
        // Governor admission failure and must never convert into a proof.
        for error in [
            SpoolError::Io(std::io::Error::other("test-io")),
            SpoolError::InvalidProtectedRoot,
            SpoolError::Serialization("test-serialization".to_owned()),
            SpoolError::Database("test-database".to_owned()),
            SpoolError::Corrupt("test-corrupt".to_owned()),
        ] {
            assert!(
                GovernorUnavailability::from_admission_error(&error).is_err(),
                "non-admission spool error must never mint: {error:?}"
            );
        }
        // Only exact kernel lease rejections mint, each with its own reason.
        assert_eq!(
            GovernorUnavailability::from_kernel_error(&KernelWatchdogError::LeaseInvalid)
                .expect("kernel invalid-lease proof")
                .reason(),
            GapRecoveryReason::LeaseInvalid
        );
        assert_eq!(
            GovernorUnavailability::from_kernel_error(&KernelWatchdogError::LeaseStale)
                .expect("kernel stale proof")
                .reason(),
            GapRecoveryReason::LeaseStale
        );
        assert_eq!(
            GovernorUnavailability::from_kernel_error(&KernelWatchdogError::LeaseFenced)
                .expect("kernel fenced proof")
                .reason(),
            GapRecoveryReason::LeaseFenced
        );
        // Endpoint-unavailable, generic and detailed failures, and retention
        // pressure fail closed: none of them is an observed Governor
        // admission failure.
        for error in [
            KernelWatchdogError::Unavailable,
            KernelWatchdogError::Failed,
            KernelWatchdogError::FailedWithDetail("test-detail".to_owned()),
            KernelWatchdogError::SpoolPressure,
        ] {
            assert!(
                GovernorUnavailability::from_kernel_error(&error).is_err(),
                "non-admission kernel error must never mint: {error:?}"
            );
        }
        // No caller-chosen reason mints: retention pressure and host-identity
        // observations fail closed at the persistence boundary.
        for reason in [
            GapRecoveryReason::SpoolPressure,
            GapRecoveryReason::HostAbsentOrStopped,
            GapRecoveryReason::HostPidReused,
            GapRecoveryReason::HostImageSubstituted,
            GapRecoveryReason::HostIdentityChanged,
            GapRecoveryReason::HostUnknown,
        ] {
            let forged = WatchdogSpoolPayload::ProblemIntent {
                service: SERVICE_NAME.to_owned(),
                evidence_refs: vec![evidence_ref(0xaa)],
                lineage_installation_id: "installation-test".to_owned(),
                lineage_generation: 7,
                lineage_epoch: 3,
                governor_unavailable_reason: reason,
            };
            assert!(
                check_stored_intent_payload(1_000, &forged).is_err(),
                "forged intent reason must fail: {reason:?}"
            );
        }
    }

    #[test]
    fn intent_bytes_touch_only_watchdog_redb() {
        let dir = temp_root("intent-isolation");
        let kernel_path = dir.join("kernel-ors.redb");
        let journal_path = dir.join("host-state-journal.redb");
        std::fs::write(&kernel_path, b"kernel-sentinel").expect("kernel sentinel");
        std::fs::write(&journal_path, b"journal-sentinel").expect("journal sentinel");
        let spool_path = watchdog_spool_path(&dir);
        assert_eq!(spool_path, dir.join("watchdog.redb"));
        assert_ne!(spool_path, kernel_path);
        assert_ne!(spool_path, journal_path);
        let spool = WatchdogSpool::open_test(&spool_path).expect("open isolated spool");
        let intent = ProblemIntentRecord::new(
            test_proof(),
            SERVICE_NAME.to_owned(),
            vec![evidence_ref(0x1c)],
            test_lineage(),
            3_000,
        )
        .expect("isolated intent");
        assert!(matches!(
            spool
                .append(3_000, intent.to_payload())
                .expect("append isolated intent"),
            SpoolAppendOutcome::Stored
        ));
        drop(spool);
        assert_eq!(
            std::fs::read(&kernel_path).expect("kernel reread"),
            b"kernel-sentinel"
        );
        assert_eq!(
            std::fs::read(&journal_path).expect("journal reread"),
            b"journal-sentinel"
        );
        let probe = WatchdogSpool::open_test(&spool_path).expect("reopen isolated spool");
        let entries = probe.readback().expect("isolated readback");
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].payload,
            WatchdogSpoolPayload::ProblemIntent { .. }
        ));
        drop(probe);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
