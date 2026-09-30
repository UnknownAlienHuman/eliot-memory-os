//! Watchdog-owned Signal-linked publication intents, persisted in the same
//! owner transaction as the failure-episode record that decided them.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-MOD-03, ARCH-WDG-01.
//! Implementation: I8.1, I8.2, I8.3, I8.9, I13.7, I2.23.
//!
//! What this owner is, and what it is not
//! -------------------------------------
//! I8.1 makes the canonical Problem/Incident transition the Governor's, and
//! names the Watchdog's only route out: when the Governor is unavailable the
//! Watchdog writes `problem_intent` / `incident_intent` records into its own
//! physically separate minimal spool. This module is the Signal-linked half of
//! that same route. It owns exactly one thing: **when an evidence-backed rule
//! threshold is crossed, persist one linked publication intent about the Signal,
//! and keep it pending until the admitted owner has taken it.**
//!
//! It owns no canonical state. There is deliberately no Incident-declaring class
//! anywhere below: the two classes this owner can mint are a Problem *attention*
//! intent and an Incident-*candidate* attention intent, both decided by the
//! owner-neutral core (`eliot_watchdog_core::evaluate_publication_intent`) and
//! both observation labels. It writes no ORS row, no HostStateJournal row, no
//! task state and no canonical Problem, because the record it appends carries
//! the Watchdog's own evidence refs and lineage and has no field in which any of
//! those could be expressed.
//!
//! One transaction, one intent
//! ---------------------------
//! The threshold decision, the episode advancement that justified it, the
//! appended episode record and the appended publication intent are **one
//! `redb` write transaction**. That is what makes the four properties hold
//! together rather than separately:
//!
//! * a crossing cannot be recorded without its evidence record, and the
//!   evidence record cannot exist without the crossing decision that consumed
//!   it;
//! * a replay of the same source event is classified by the *same* durable
//!   episode index the decision read, so the core refuses it structurally
//!   (`SourceEventAdmission::Retransmission` -> `PublicationDecision::
//!   AdmissionWithheld`) and no second intent can be minted;
//! * a restart re-reads the durable counted-evidence set and the durable
//!   emission reference, so it reuses the accepted revision instead of emitting
//!   a fresh alert;
//! * a lost export acknowledgement leaves the appended record retained and the
//!   export cursor where it was, so the next export replays byte-identical
//!   material under the same `intent_id` instead of appending a second intent.
//!
//! Bounded backpressure, never a silent drop
//! -----------------------------------------
//! An unavailable canonical owner is expressed by the appended record staying in
//! the spool and the export cursor not advancing. It is never expressed by
//! discarding the intent: [`is_publication_payload`] keeps a publication record
//! out of every compaction candidate, exactly as
//! [`super::intent::is_intent_payload`] does for the escalation intents, so an
//! unresolved publication intent survives acknowledgement-driven compaction and
//! is only ever dropped by the spool's own bounded retention pressure. The bound
//! at which that can happen is the existing
//! [`super::SPOOL_MAX_RECORDS`] / [`super::SPOOL_MAX_BYTES`] ceiling, not a new
//! one, and refusing to append past it is the spool's own existing behaviour
//! rather than anything this module invents.
//!
//! Codec firewall
//! --------------
//! The shared owner-neutral export classes
//! ([`eliot_watchdog_core::WatchdogSpoolPayloadKind`], mirrored by the Governor
//! `WatchdogEntryKind` and consumed exhaustively by the eliotd observation
//! adapter) are intentionally **not** extended. They are consumed by lanes this
//! one does not own, so extending them here would break those exhaustive
//! matches. A publication intent is therefore a spool-local
//! [`super::WatchdogSpoolPayload`] variant that exports under the **existing**
//! gap-like `Recovery` class, the same construction the escalation intents
//! already use. Ordering, retention and cursor semantics are consequently
//! unchanged, and the admitted owner receives a bounded, retained,
//! gap-classified observation it already admits.
//!
//! Signed request
//! --------------
//! A publication intent is an observation, not an effect. It authorizes nothing.
//! The bounded pre-authorized request that may eventually be derived from one
//! lives in [`super::request`] and is a separate record with its own identity,
//! expiry and reconciliation owner; nothing in this module mints one, and a
//! publication intent can never be read as a request.

use eliot_contracts::sha256_hex;
use eliot_watchdog_core::{
    AcknowledgementFact, AttentionPolicy, ClockDomain, CoverageRef, EvidenceRef, FailureClass,
    ObservedTime, ProfileRevision, PublicationClass, PublicationDecision, PublicationIntent,
    RecordedValue, ResolutionFact, RuleRevision, Signal, SignalAttribution, SignalDelivery,
    SignalDisposition, SignalId, SignalProcessing, SignalReferences, SignalRevision,
    SignalSeverity, SignalTarget, SourceEventRef, TimeUnit, evaluate_publication_intent,
};

use super::codec::WatchdogSpoolPayload;
use crate::SpoolError;

/// Storage revision of the durable publication state.
pub(crate) const PUBLICATION_STATE_SCHEMA_VERSION: u16 = 1;

/// Owner-issued identity of the Watchdog's attention policy.
///
/// This is a Config-owned value, not an invariant: the policy identity and its
/// immutable revision travel into every decision through
/// [`AttentionPolicy`], so a publication intent always states the exact policy
/// revision its threshold was decided under, and a later revision can never
/// silently re-decide an already published crossing.
pub(crate) const ATTENTION_POLICY_ID: &str = "watchdog_signal_attention";

/// Immutable revision of [`ATTENTION_POLICY_ID`].
pub(crate) const ATTENTION_POLICY_REVISION: u64 = 1;

/// Distinct evidence identities a Problem attention intent requires.
pub(crate) const PROBLEM_ATTENTION_EVIDENCE_THRESHOLD: usize = 2;

/// Distinct evidence identities an Incident-candidate attention intent
/// requires.
///
/// Strictly above the Problem threshold, so a genuinely recurring episode
/// escalates *within itself* instead of needing an unrelated second episode. It
/// is a candidate threshold and not an Incident declaration: the class this
/// produces is still only an attention intent, and the Governor still performs
/// the canonical transition.
pub(crate) const INCIDENT_CANDIDATE_ATTENTION_EVIDENCE_THRESHOLD: usize = 3;

const _: () = assert!(ATTENTION_POLICY_REVISION == 1);
const _: () = assert!(PROBLEM_ATTENTION_EVIDENCE_THRESHOLD >= 2);
const _: () =
    assert!(INCIDENT_CANDIDATE_ATTENTION_EVIDENCE_THRESHOLD > PROBLEM_ATTENTION_EVIDENCE_THRESHOLD);

/// Maximum distinct evidence identities one episode's publication state retains.
///
/// This mirrors the episode's own accepted-source-event bound
/// ([`super::episode::MAX_SIGNAL_EPISODE_SOURCE_EVENTS`]) so the two indices can
/// never disagree about how much evidence an episode holds, and it stays inside
/// the export batch's own evidence-reference ceiling so an appended publication
/// record can never exceed the bounded record frame.
pub(crate) const MAX_PUBLICATION_EVIDENCE_REFS: usize =
    super::episode::MAX_SIGNAL_EPISODE_SOURCE_EVENTS;

const _: () = assert!(MAX_PUBLICATION_EVIDENCE_REFS == 32);

/// Bounded identity length for every owner-issued string a publication record
/// carries.
pub(crate) const MAX_PUBLICATION_ID_LEN: usize = super::intent::MAX_INTENT_LINEAGE_ID_LEN;

const _: () = assert!(MAX_PUBLICATION_ID_LEN == 1024);

/// True for the spool-local publication payloads, which are retained for
/// forensic linkage and exported inside their export window like any other
/// covered record.
///
/// `compaction_plan` consults this, so an acknowledged publication intent is
/// never removed by acknowledgement-driven compaction: the Watchdog record stays
/// linked to whatever the Governor later decides from it, and only the spool's
/// own bounded retention pressure may ever drop it.
pub(crate) fn is_publication_payload(payload: &WatchdogSpoolPayload) -> bool {
    matches!(payload, WatchdogSpoolPayload::PublicationIntent { .. })
}

/// Watchdog-owned observation class of one retained publication record.
///
/// There is no Incident-declaring variant: this type cannot express a canonical
/// Incident decision, so an `incident_candidate` severity reaches the admitted
/// owner as a *candidate* attention intent and nothing more. The two classes are
/// the two the core can mint, mirrored as stable wire codes so the record and
/// the core decision can never disagree about which one was decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogPublicationClass {
    /// `problem_attention_intent` observation.
    ProblemAttention,
    /// `incident_candidate_attention_intent` observation; never a canonical
    /// Incident declaration.
    IncidentCandidateAttention,
}

impl WatchdogPublicationClass {
    /// Returns the exact Watchdog record kind name for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProblemAttention => "problem_attention_intent",
            Self::IncidentCandidateAttention => "incident_candidate_attention_intent",
        }
    }

    /// Reads the class back from one stored payload.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] for a non-publication payload.
    pub(crate) fn of_payload(payload: &WatchdogSpoolPayload) -> Result<Self, SpoolError> {
        match payload {
            WatchdogSpoolPayload::PublicationIntent { class, .. } => Ok(*class),
            WatchdogSpoolPayload::Heartbeat { .. }
            | WatchdogSpoolPayload::Gap { .. }
            | WatchdogSpoolPayload::Recovery { .. }
            | WatchdogSpoolPayload::ProblemIntent { .. }
            | WatchdogSpoolPayload::IncidentIntent { .. } => Err(SpoolError::Corrupt(
                "watchdog spool record is not a publication intent payload".to_owned(),
            )),
        }
    }

    /// Projects a core publication class onto this record's class.
    ///
    /// The match is total over the core enum with no wildcard, so a class the
    /// core ever adds fails the build here instead of being flattened into an
    /// existing one — an over-broad publication record can never be minted by a
    /// class this owner did not name.
    fn of_core(class: PublicationClass) -> Self {
        match class {
            PublicationClass::ProblemAttention => Self::ProblemAttention,
            PublicationClass::IncidentCandidateAttention => Self::IncidentCandidateAttention,
        }
    }
}

/// Severity this owner assigns to each observed failure class.
///
/// The mapping is exhaustive with no wildcard, so a future failure class fails
/// the build here rather than defaulting into a severity nobody reviewed. It is
/// a *severity*, not a finding: it states how strongly deterministic supervision
/// reports the observation, and the attention class is still decided by the
/// core against the owner-issued policy.
fn severity_of_failure_class(failure_class: FailureClass) -> SignalSeverity {
    match failure_class {
        // A fenced, stale, substituted or unverifiable supervision authority is
        // a hard supervision failure: the Watchdog cannot state which owner is
        // live, so it blocks rather than merely warns.
        FailureClass::SupervisionLeaseFenced
        | FailureClass::SupervisionLeaseInvalid
        | FailureClass::SupervisionLeaseStale
        | FailureClass::HostImageSubstituted
        | FailureClass::HostPidReused
        | FailureClass::HostIdentityChanged => SignalSeverity::Blocking,
        // A host that is simply not there yet, or whose liveness this owner
        // cannot determine, is a supervision gap rather than a hard failure.
        FailureClass::HostAbsentOrStopped
        | FailureClass::HostUnknown
        | FailureClass::GovernorAdmissionUnavailable
        | FailureClass::ProviderHostEventSequenceGap => SignalSeverity::Warning,
    }
}

/// Returns the exact owner-issued attention policy this owner decides under.
///
/// # Errors
///
/// Returns [`eliot_watchdog_core::SignalValidationError`] when the compiled
/// thresholds are not a valid policy, which the constant assertions above make
/// impossible for the current values.
pub(crate) fn attention_policy()
-> Result<AttentionPolicy, eliot_watchdog_core::SignalValidationError> {
    AttentionPolicy::new(
        ATTENTION_POLICY_ID.to_owned(),
        ATTENTION_POLICY_REVISION,
        PROBLEM_ATTENTION_EVIDENCE_THRESHOLD,
        INCIDENT_CANDIDATE_ATTENTION_EVIDENCE_THRESHOLD,
    )
}

/// Watchdog-owned lineage bound to one publication record.
///
/// Carries only the owner identities the export cursor already binds
/// (installation, generation, epoch), so the admitted owner can place the intent
/// without this owner inventing authority. Every field is private and
/// [`PublicationLineage::new`] is the only construction path.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationLineage {
    installation_id: String,
    watchdog_generation: u64,
    watchdog_epoch: u64,
}

impl PublicationLineage {
    /// Binds one publication lineage; fails closed on a blank, oversized, or
    /// uninitialized identity.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the installation identity is empty or
    /// over the bounded frame, or the generation is uninitialized.
    pub(crate) fn new(
        installation_id: String,
        watchdog_generation: u64,
        watchdog_epoch: u64,
    ) -> Result<Self, SpoolError> {
        if installation_id.is_empty() || installation_id.len() > MAX_PUBLICATION_ID_LEN {
            return Err(SpoolError::Corrupt(
                "watchdog publication lineage installation identity is unusable".to_owned(),
            ));
        }
        if watchdog_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog publication lineage generation is uninitialized".to_owned(),
            ));
        }
        Ok(Self {
            installation_id,
            watchdog_generation,
            watchdog_epoch,
        })
    }
}

/// One accepted publication intent, already decided by the core.
///
/// The record is spool-local and evidence-bearing. It is not a canonical
/// Problem, not a canonical Incident, not an authorization, and not a
/// resolution: a delivered or acknowledged publication intent leaves the
/// blocking attention it reports exactly as open as it was.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationIntentRecord {
    /// Stable identity of this intent, derived by the core from the signal, its
    /// revision, the policy identity and revision, and the class. Re-deciding
    /// the same crossing therefore names the same intent, which is what makes a
    /// lost acknowledgement resumable rather than duplicating.
    intent_id: String,
    /// Identity of the Signal this intent is linked to.
    signal_id: String,
    /// Exact immutable Signal revision the threshold was decided from.
    signal_revision: u64,
    /// Rule identity and immutable revision that produced the Signal.
    rule_id: String,
    rule_revision: u64,
    /// Owner-issued policy identity and revision the threshold was decided
    /// under.
    policy_id: String,
    policy_revision: u64,
    /// Observation class of this record.
    class: WatchdogPublicationClass,
    /// Exact observed subject, scope and generation.
    subject_id: String,
    scope_id: String,
    generation: u64,
    /// Owner-clock time of the crossing observation, in Unix milliseconds.
    observed_at_ms: u64,
    /// The exact distinct evidence identities this revision contributed to the
    /// crossing. An already-counted identity never appears here, so a
    /// retransmission contributes nothing.
    crossing_evidence: Vec<String>,
    /// Total distinct evidence counted for this Signal under this policy
    /// revision at the crossing.
    distinct_evidence_count: u32,
    /// The Signal's own deduplication key, carried so a later revision of the
    /// same failure episode is correlated rather than republished.
    dedup_key: String,
    /// Watchdog-owned lineage of the retained record.
    lineage: PublicationLineage,
}

impl PublicationIntentRecord {
    /// Mints one record from a core publication decision and this owner's
    /// lineage; fails closed on any bound violation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when any bound identity is blank, carries
    /// a control character, or exceeds its frame; when the crossing evidence is
    /// empty or over the bound; or when a digest is not 64 lowercase hex
    /// characters.
    pub(crate) fn new(
        intent: &PublicationIntent,
        lineage: PublicationLineage,
    ) -> Result<Self, SpoolError> {
        check_id(&intent.intent_id, "publication intent identity")?;
        check_id(&intent.signal_id.0, "publication signal identity")?;
        check_id(&intent.rule.rule_id, "publication rule identity")?;
        check_id(&intent.policy_id, "publication policy identity")?;
        check_id(&intent.target.subject_id, "publication subject identity")?;
        check_id(&intent.target.scope_id, "publication scope identity")?;
        let dedup_key = match &intent.dedup_key {
            RecordedValue::Known(key) => key.clone(),
            RecordedValue::Unknown { .. } => {
                return Err(SpoolError::Corrupt(
                    "watchdog publication intent carries no usable deduplication key".to_owned(),
                ));
            }
        };
        check_id(&dedup_key, "publication deduplication key")?;
        if intent.signal_revision == 0
            || intent.rule.revision == 0
            || intent.policy_revision == 0
            || intent.target.generation == 0
        {
            return Err(SpoolError::Corrupt(
                "watchdog publication intent carries an uninitialized revision or generation"
                    .to_owned(),
            ));
        }
        if intent.crossing_evidence.is_empty()
            || intent.crossing_evidence.len() > MAX_PUBLICATION_EVIDENCE_REFS
        {
            return Err(SpoolError::Corrupt(
                "watchdog publication intent crossing evidence is empty or above its bound"
                    .to_owned(),
            ));
        }
        for evidence in &intent.crossing_evidence {
            check_digest(evidence)?;
        }
        if intent.distinct_evidence_count == 0
            || intent.distinct_evidence_count > MAX_PUBLICATION_EVIDENCE_REFS
        {
            return Err(SpoolError::Corrupt(
                "watchdog publication intent distinct evidence count is not canonical".to_owned(),
            ));
        }
        let observed_at_ms = match &intent.observed_at {
            RecordedValue::Known(observed) => observed,
            RecordedValue::Unknown { .. } => {
                return Err(SpoolError::Corrupt(
                    "watchdog publication intent records no observed time".to_owned(),
                ));
            }
        };
        // The core's clock domain is a unix-millisecond reading on the
        // Watchdog's own clock, because the Watchdog is the only party that
        // stamped it. A different domain is refused here rather than
        // reinterpreted, so a record can never claim a time it did not observe.
        if observed_at_ms.ticks == 0
            || observed_at_ms.unit != TimeUnit::Milliseconds
            || observed_at_ms.domain != ClockDomain::UnixUtc
        {
            return Err(SpoolError::Corrupt(
                "watchdog publication intent observed time is not this owner's unix-millisecond clock"
                    .to_owned(),
            ));
        }
        Ok(Self {
            intent_id: intent.intent_id.clone(),
            signal_id: intent.signal_id.0.clone(),
            signal_revision: intent.signal_revision,
            rule_id: intent.rule.rule_id.clone(),
            rule_revision: intent.rule.revision,
            policy_id: intent.policy_id.clone(),
            policy_revision: intent.policy_revision,
            class: WatchdogPublicationClass::of_core(intent.class),
            subject_id: intent.target.subject_id.clone(),
            scope_id: intent.target.scope_id.clone(),
            generation: intent.target.generation,
            observed_at_ms: observed_at_ms.ticks,
            crossing_evidence: intent.crossing_evidence.clone(),
            distinct_evidence_count: u32::try_from(intent.distinct_evidence_count).map_err(
                |_| {
                    SpoolError::Corrupt(
                        "watchdog publication intent evidence count exceeds its bound".to_owned(),
                    )
                },
            )?,
            dedup_key,
            lineage,
        })
    }

    /// Returns the owner-clock time this record is retained at.
    ///
    /// Read through this accessor rather than off the core decision at the
    /// append site, so the retained time is the one this owner validated — and
    /// re-checked against the core's clock domain — rather than a value re-read
    /// from a different field.
    #[must_use]
    pub(crate) const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Returns the observation class this record was committed under.
    #[must_use]
    pub(crate) const fn class(&self) -> WatchdogPublicationClass {
        self.class
    }

    /// Projects this record onto its spool payload for
    /// [`super::append_in_transaction_on`].
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::PublicationIntent {
            service: crate::SERVICE_NAME.to_owned(),
            intent_id: self.intent_id.clone(),
            signal_id: self.signal_id.clone(),
            signal_revision: self.signal_revision,
            rule_id: self.rule_id.clone(),
            rule_revision: self.rule_revision,
            policy_id: self.policy_id.clone(),
            policy_revision: self.policy_revision,
            class: self.class,
            subject_id: self.subject_id.clone(),
            scope_id: self.scope_id.clone(),
            generation: self.generation,
            observed_at_ms: self.observed_at_ms,
            crossing_evidence: self.crossing_evidence.clone(),
            distinct_evidence_count: self.distinct_evidence_count,
            dedup_key: self.dedup_key.clone(),
            lineage_installation_id: self.lineage.installation_id.clone(),
            lineage_generation: self.lineage.watchdog_generation,
            lineage_epoch: self.lineage.watchdog_epoch,
        }
    }
}

/// Durable reference to one publication intent this owner actually committed.
///
/// It names the exact committed spool record, never a later read of the high
/// water mark, and it is persisted in the same owner transaction as that record
/// and as the evidence advance that authorised it. It is the emission identity
/// of the episode: a replay of the same accepted source event reconciles this
/// reference instead of minting a second record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationEmission {
    /// Retained spool sequence of the exact committed publication record.
    pub(crate) sequence: u64,
    /// Digest over the identity of that exact record, bound the way an export
    /// batch binds it.
    pub(crate) record_digest: String,
    /// Stable intent identity the core derived for this crossing.
    pub(crate) intent_id: String,
    /// Observation class the record was committed under.
    pub(crate) class: WatchdogPublicationClass,
    /// Owner-clock time of the crossing observation.
    pub(crate) observed_at_ms: u64,
}

/// The owner-issued facts one accepted episode needs before the publication
/// owner may decide anything about its Signal.
///
/// It carries exactly two values the episode row does not already hold: the
/// Watchdog's own lineage, which binds the appended record to the same owner
/// identities the export cursor binds, and the coverage identity this owner can
/// genuinely attest to for the observation. The subject, scope, generation, rule
/// revision, severity, observed time, source-event identity and payload digest
/// are deliberately **not** here — those are read from the accepted episode row
/// itself, so the Signal a publication intent is decided from is the Signal the
/// durable deduplication state actually accepted, and a caller cannot present a
/// different revision under the same episode identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationRequest {
    /// Watchdog-owned lineage of the appended record.
    pub(crate) lineage: PublicationLineage,
    /// Owner-issued coverage identity for the interval this observation covers.
    ///
    /// A blank or control-charactered identity is refused, because coverage this
    /// owner cannot name is a coverage gap and must be recorded as one rather
    /// than carried into a Signal as a reference to nothing.
    pub(crate) coverage_id: String,
}

impl PublicationRequest {
    /// Binds one publication request; fails closed on an unusable coverage
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the coverage identity is blank, over
    /// the bounded frame, or carries a control character.
    pub(crate) fn new(
        lineage: PublicationLineage,
        coverage_id: String,
    ) -> Result<Self, SpoolError> {
        check_id(&coverage_id, "publication coverage identity")?;
        Ok(Self {
            lineage,
            coverage_id,
        })
    }
}

/// Durable publication state of one failure episode.
///
/// Persisted in `watchdog.redb` beside the episode row it belongs to, in the
/// same owner transaction, so a restart cannot reset the distinct-evidence count
/// and re-publish a crossing the episode already published. It is the exact
/// answer to the two questions the core decision needs and cannot answer for
/// itself: which evidence identities this episode has already had counted, and
/// which intent, if any, that evidence already produced.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationState {
    schema_version: u16,
    /// The episode key this publication state belongs to. Re-derived and
    /// compared on every read, so a row can never be read under an identity it
    /// was not written with.
    episode_key: String,
    /// Monotonic revision of this row. Every accepted mutation advances it, so
    /// a writer can tell whether the row it validated is still the row it is
    /// about to replace.
    pub(crate) revision: u64,
    /// Owner-issued policy revision these counted evidence identities were
    /// counted under. Evidence counted under another revision is never reused,
    /// because it was counted against thresholds this decision does not apply.
    pub(crate) policy_revision: u64,
    /// Exact distinct evidence identities already counted for this episode under
    /// [`Self::policy_revision`], in admission order. Bounded and free of
    /// repeated identities.
    pub(crate) counted_evidence: Vec<String>,
    /// The exact publication intent this episode already committed, when it has.
    pub(crate) emission: Option<PublicationEmission>,
    /// Lifetime diagnostic count of committed publication intents for this
    /// episode. Diagnostic only: never emission identity and never a threshold.
    pub(crate) intents_committed: u64,
}

impl PublicationState {
    /// Returns the closed state of an episode that has published nothing.
    #[must_use]
    pub(crate) fn fresh(episode_key: &str) -> Self {
        Self {
            schema_version: PUBLICATION_STATE_SCHEMA_VERSION,
            episode_key: episode_key.to_owned(),
            revision: 0,
            policy_revision: ATTENTION_POLICY_REVISION,
            counted_evidence: Vec::new(),
            emission: None,
            intents_committed: 0,
        }
    }

    /// Fails closed on a stored row that is not in canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the schema drifted, the episode key
    /// is not the ledger key the row is filed under, the recorded policy
    /// revision is uninitialized or disagrees with the owner-issued one, the
    /// counted evidence is over the bound or repeats an identity, a counted
    /// digest is malformed, a committed emission is not canonical, or the
    /// lifetime counter disagrees with whether an emission exists.
    pub(crate) fn validate(&self, ledger_key: &str) -> Result<(), SpoolError> {
        if self.schema_version != PUBLICATION_STATE_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "watchdog publication state schema is unsupported".to_owned(),
            ));
        }
        check_id(&self.episode_key, "publication episode key")?;
        if super::episode::episode_ledger_key(&self.episode_key) != ledger_key {
            return Err(SpoolError::Corrupt(
                "watchdog publication state does not match the ledger key it is filed under"
                    .to_owned(),
            ));
        }
        if self.policy_revision != ATTENTION_POLICY_REVISION {
            return Err(SpoolError::Corrupt(
                "watchdog publication state was counted under a policy revision this owner does not apply"
                    .to_owned(),
            ));
        }
        if self.counted_evidence.len() > MAX_PUBLICATION_EVIDENCE_REFS {
            return Err(SpoolError::Corrupt(
                "watchdog publication state counted evidence exceeds its bound".to_owned(),
            ));
        }
        for evidence in &self.counted_evidence {
            check_digest(evidence)?;
            if self.counted_evidence[..]
                .iter()
                .filter(|prior| *prior == evidence)
                .count()
                > 1
            {
                return Err(SpoolError::Corrupt(
                    "watchdog publication state repeats one counted evidence identity".to_owned(),
                ));
            }
        }
        if let Some(emission) = self.emission.as_ref() {
            if emission.sequence == 0 || emission.observed_at_ms == 0 {
                return Err(SpoolError::Corrupt(
                    "watchdog publication state emission reference is not canonical".to_owned(),
                ));
            }
            check_id(&emission.intent_id, "publication emission intent identity")?;
            check_digest(&emission.record_digest)?;
        }
        if (self.emission.is_some()) != (self.intents_committed > 0) {
            return Err(SpoolError::Corrupt(
                "watchdog publication state lifetime counter disagrees with its emission"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Advances this state with one committed publication intent, in the same
    /// owner transaction that appended the record it names.
    ///
    /// The advance is what makes a replay unable to mint a second intent: the
    /// crossing evidence becomes counted evidence and the record becomes the
    /// emission reference, so the next delivery of any of those identities is
    /// refused by the core as already counted.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row is not canonical, the
    /// emission is not canonical, a counted identity repeats, or the advance
    /// would cross the evidence bound. The bound is **refused, never trimmed**:
    /// trimming a counted identity would let that identity's retransmission be
    /// admitted again as new independent evidence.
    pub(crate) fn accept_intent(
        &mut self,
        ledger_key: &str,
        intent: &PublicationIntent,
        emission: PublicationEmission,
    ) -> Result<(), SpoolError> {
        self.validate(ledger_key)?;
        if emission.sequence == 0 || emission.observed_at_ms == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog publication emission reference is uninitialized".to_owned(),
            ));
        }
        check_digest(&emission.record_digest)?;
        if self.emission.is_some() {
            // One episode publishes at most one intent per policy revision. A
            // second crossing would need a *different* policy revision, which
            // this owner does not issue, so the refusal is a real one rather
            // than an artificial cap: it states that the episode already
            // published and names the record it published.
            return Err(SpoolError::Corrupt(format!(
                "watchdog publication state already published intent {} for this episode",
                self.emission
                    .as_ref()
                    .map_or("", |value| value.intent_id.as_str())
            )));
        }
        for evidence in &intent.crossing_evidence {
            check_digest(evidence)?;
            if self.counted_evidence.contains(evidence) {
                continue;
            }
            if self.counted_evidence.len() >= MAX_PUBLICATION_EVIDENCE_REFS {
                return Err(SpoolError::Corrupt(
                    "watchdog publication counted evidence is at its bound; \
                     refusing to trim an identity that could be re-admitted as new evidence"
                        .to_owned(),
                ));
            }
            self.counted_evidence.push(evidence.clone());
        }
        self.emission = Some(emission);
        self.intents_committed = 1;
        self.revision = self.revision.saturating_add(1);
        self.validate(ledger_key)
    }

    /// Returns the emission this episode already committed, if any.
    #[must_use]
    pub(crate) const fn committed(&self) -> Option<&PublicationEmission> {
        self.emission.as_ref()
    }
}

/// Revalidates one stored publication payload against the constructor bounds.
///
/// Every other payload class passes through untouched. A publication payload is
/// reconstructed through [`PublicationIntentRecord::new`] and must round-trip
/// byte-equivalent, so a forged or non-canonical row fails closed at the
/// persistence boundary instead of entering the spool. Reached from the codec
/// encode/decode paths, which own bounded structural validation.
pub(crate) fn check_stored_publication_payload(
    observed_at_ms: u64,
    payload: &WatchdogSpoolPayload,
) -> Result<(), SpoolError> {
    let WatchdogSpoolPayload::PublicationIntent {
        service,
        intent_id,
        signal_id,
        signal_revision,
        rule_id,
        rule_revision,
        policy_id,
        policy_revision,
        class,
        subject_id,
        scope_id,
        generation,
        observed_at_ms: payload_observed_at_ms,
        crossing_evidence,
        distinct_evidence_count,
        dedup_key,
        lineage_installation_id,
        lineage_generation,
        lineage_epoch,
    } = payload
    else {
        return Ok(());
    };
    // The record's own observed time and the envelope's observation time are two
    // independent facts about one append, and they must be the same append. A
    // row where they disagree would let a record claim a crossing time other
    // than the time it was retained at.
    if *payload_observed_at_ms != observed_at_ms {
        return Err(SpoolError::Corrupt(
            "watchdog publication record observed time differs from its retained envelope"
                .to_owned(),
        ));
    }
    let lineage = PublicationLineage::new(
        lineage_installation_id.clone(),
        *lineage_generation,
        *lineage_epoch,
    )?;
    let intent = PublicationIntent {
        intent_id: intent_id.clone(),
        signal_id: SignalId(signal_id.clone()),
        signal_revision: *signal_revision,
        rule: RuleRevision {
            rule_id: rule_id.clone(),
            revision: *rule_revision,
        },
        policy_id: policy_id.clone(),
        policy_revision: *policy_revision,
        class: match class {
            WatchdogPublicationClass::ProblemAttention => PublicationClass::ProblemAttention,
            WatchdogPublicationClass::IncidentCandidateAttention => {
                PublicationClass::IncidentCandidateAttention
            }
        },
        target: SignalTarget {
            subject_id: subject_id.clone(),
            scope_id: scope_id.clone(),
            generation: *generation,
        },
        observed_at: RecordedValue::Known(ObservedTime {
            ticks: *payload_observed_at_ms,
            unit: TimeUnit::Milliseconds,
            domain: ClockDomain::UnixUtc,
        }),
        crossing_evidence: crossing_evidence.clone(),
        distinct_evidence_count: usize::try_from(*distinct_evidence_count).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog publication record evidence count exceeds its bound".to_owned(),
            )
        })?,
        dedup_key: RecordedValue::Known(dedup_key.clone()),
    };
    // The service is the Watchdog's own, and it is checked here rather than
    // through the record constructor because the record deliberately carries no
    // service field: a publication record can only ever be this owner's.
    if service != crate::SERVICE_NAME {
        return Err(SpoolError::Corrupt(
            "watchdog publication record service is not the watchdog owner".to_owned(),
        ));
    }
    let record = PublicationIntentRecord::new(&intent, lineage)?;
    if record.to_payload() != *payload {
        return Err(SpoolError::Corrupt(
            "watchdog publication intent payload is not in canonical form".to_owned(),
        ));
    }
    Ok(())
}

/// Builds the immutable Signal revision one accepted source event justifies.
///
/// The Signal is projected from owner-issued facts only: the episode's own
/// rule identity and revision, the exact observed subject, scope and generation,
/// the observed time this owner stamped, the exact source event identity with
/// the payload digest the episode recorded for it, and the coverage this owner
/// can genuinely attest to. Nothing here is caller prose and nothing is inferred
/// from a clock reading taken later.
///
/// Two axes are deliberately left *unknown* rather than filled with a success
/// default, because this owner genuinely does not observe them:
/// attribution (the Watchdog observes that a supervision lease was rejected, not
/// which principal caused it) and the expected context/authority revisions (the
/// lease it verified is evidence, not the expected revision). Recording them as
/// limitations is what keeps the publication intent honest about what it rests
/// on.
pub(crate) fn project_accepted_signal(
    episode: &super::episode::StoredSignalEpisodeProjection<'_>,
    source_event: &eliot_watchdog_core::AcceptedSourceEvent,
    evidence_id: &str,
    coverage_id: &str,
) -> Result<Signal, SpoolError> {
    // The two failure kinds are kept apart rather than flattened: a durable row
    // this owner could not read back is a spool fault, and only a structurally
    // invalid projection is a core validation failure. Reporting an unreadable
    // episode as an "invalid observation" would be exactly the confusion that
    // lets a restart treat one as fresh.
    let failure_class = episode.failure_class()?;
    let reopen_condition = episode.reopen_condition()?;
    let rule = RuleRevision {
        rule_id: episode.rule_id().to_owned(),
        revision: episode.rule_revision(),
    };
    let target = SignalTarget {
        subject_id: episode.subject_id().to_owned(),
        scope_id: episode.scope_id().to_owned(),
        generation: episode.generation(),
    };
    let observed_at = ObservedTime {
        ticks: episode.evidence_observed_at_ms(),
        unit: TimeUnit::Milliseconds,
        domain: ClockDomain::UnixUtc,
    };
    Signal::new(SignalRevision {
        signal_id: SignalId(episode.episode_key().to_owned()),
        revision: episode.revision(),
        rule,
        profile: ProfileRevision {
            profile_id: ATTENTION_POLICY_ID.to_owned(),
            revision: ATTENTION_POLICY_REVISION,
        },
        severity: severity_of_failure_class(failure_class),
        target,
        observed_at: RecordedValue::Known(observed_at.clone()),
        source_events: SignalReferences::Known(vec![SourceEventRef {
            event_id: source_event.event_id.clone(),
            payload_digest: RecordedValue::Known(source_event.payload_digest.clone()),
        }]),
        // Evidence stays per-observation and is bound to the exact accepted
        // event, so a second distinct event contributes a second distinct
        // evidence identity while a retransmission of this one re-derives the
        // identical identity and therefore contributes nothing.
        evidence: SignalReferences::Known(vec![EvidenceRef {
            evidence_id: evidence_id.to_owned(),
        }]),
        coverage: SignalReferences::Known(vec![CoverageRef {
            coverage_id: coverage_id.to_owned(),
        }]),
        attribution: SignalAttribution::Unknown {
            limitation:
                "the Watchdog observed that its own supervision admission was rejected; it does not \
                 observe which principal caused the rejection"
                    .to_owned(),
        },
        processing: SignalProcessing::Observed,
        delivery: SignalDelivery::Pending,
        disposition: SignalDisposition::ProblemCandidate,
        acknowledgement: AcknowledgementFact::NotAcknowledged,
        resolution: ResolutionFact::Unresolved,
        dedup_key: RecordedValue::Known(episode.episode_key().to_owned()),
        reopen_condition,
        expected_context_revision: eliot_watchdog_core::ExpectedRevision::Unknown {
            limitation: "the verified supervision lease is observation evidence, not the expected \
                         context revision; no context owner publishes one for this observation"
                .to_owned(),
        },
        expected_authority_revision: eliot_watchdog_core::ExpectedRevision::Unknown {
            limitation: "the verified supervision lease is observation evidence, not the expected \
                         authority revision; no authority owner publishes one for this observation"
                .to_owned(),
        },
    })
    .map_err(|error| {
        SpoolError::Corrupt(format!(
            "watchdog accepted episode cannot project a valid signal revision: {error:?}"
        ))
    })
}

/// Derives the one evidence identity a source event contributes to its episode.
///
/// The identity binds the episode key, the event identity and the payload digest
/// the episode recorded for it, so it is stable across a restart and a duplicate
/// tick — the same event re-offered derives the same identity — and distinct
/// across genuinely different events, even under the same episode.
pub(crate) fn publication_evidence_id(
    episode_key: &str,
    source_event: &eliot_watchdog_core::AcceptedSourceEvent,
) -> String {
    let material = format!(
        "watchdog-publication-evidence-v1\0{episode_key}\0{}\0{}",
        source_event.event_id, source_event.payload_digest
    );
    sha256_hex(material.as_bytes())
}

/// One retained Signal-linked publication record awaiting the admitted owner.
///
/// It is the read-side counterpart of the durable emission reference: the record
/// is read back out of the retained spool under its own sequence, its digests are
/// recomputed from its exact bytes, and the stable intent identity is recovered
/// from the record itself rather than from any side table. That is what lets a
/// lost export acknowledgement resume under the same identity without a second
/// record ever being appended, and it is why the emission reference is not
/// consulted here: the retained bytes are the record, and the side table is only
/// this owner's own note about which record it committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPublication {
    /// The exact retained original record.
    pub record: super::WatchdogSpoolEntry,
    /// Watchdog-owned observation class of the record.
    pub publication_class: WatchdogPublicationClass,
    /// Digest over the record identity (sequence, schema, timestamp, bytes).
    pub record_digest: String,
    /// Digest over the canonical record bytes.
    pub payload_digest: String,
    /// The Watchdog's own authority epoch lineage, from its retained
    /// installer-approved runtime binding.
    ///
    /// This is observation lineage, not a claim about the Kernel's current epoch.
    pub epoch_lineage: eliot_contracts::EpochLineageId,
}

impl PendingPublication {
    /// Returns the stable intent identity the retained record carries.
    ///
    /// Read from the record rather than recomputed, so a replay can only ever
    /// present the identity the original crossing was decided under. A non
    /// publication record has no identity to present and fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] for a non-publication record.
    pub(crate) fn intent_id(&self) -> Result<&str, SpoolError> {
        match &self.record.payload {
            WatchdogSpoolPayload::PublicationIntent { intent_id, .. } => Ok(intent_id.as_str()),
            _ => Err(SpoolError::Corrupt(
                "pending Watchdog publication no longer has a publication payload".to_owned(),
            )),
        }
    }
}

/// Watchdog-owned identity of one committed publication record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationRecordRef {
    /// Retained spool sequence of the exact committed record.
    pub(crate) sequence: u64,
    /// Digest over that record's identity, bound the way an export batch binds
    /// it.
    pub(crate) record_digest: String,
    /// Stable intent identity the core derived for this crossing. A lost export
    /// acknowledgement resumes under this identity; it never mints a new one.
    pub(crate) intent_id: String,
    /// Observation class the record was committed under.
    pub(crate) class: WatchdogPublicationClass,
}

/// Deterministic outcome of one accepted source event against the episode's
/// durable publication state.
///
/// Every variant except [`Self::Published`] wrote nothing and appended no
/// record, so the caller's transaction is dropped uncommitted for all of them —
/// a withheld delivery is a refusal, not a partial write. Nothing here claims a
/// canonical Problem, a canonical Incident, a delivery, or a resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicationOutcome {
    /// Exactly one publication intent was appended in the caller's transaction
    /// and is now durable beside the episode record and the evidence advance
    /// that decided it.
    Published(PublicationRecordRef),
    /// The threshold is not yet reached for this severity. Nothing is appended
    /// and no state is written; the counted evidence is unchanged.
    BelowThreshold {
        /// Distinct evidence counted for this episode so far.
        distinct_evidence_count: usize,
        /// The threshold this severity requires.
        required: usize,
    },
    /// The episode's durable failure index withheld this delivery, so it
    /// contributes no independent evidence whatever the revision references. The
    /// episode's own reason travels with the decision rather than being
    /// flattened into a repeated-delivery count.
    AdmissionWithheld {
        /// Exactly what the failure episode decided about the presented event.
        reason: withheld::Reason,
    },
    /// The projected revision records no usable evidence references, so no
    /// threshold can be substantiated. The recorded limitation travels with the
    /// decision instead of a count it cannot support.
    EvidenceUnavailable {
        /// The historical limitation the projected revision recorded.
        limitation: String,
    },
    /// The projected severity does not request attention, so no publication
    /// intent is derivable from it regardless of the evidence count.
    NotAttention {
        /// The severity that excluded publication.
        severity: SignalSeverity,
    },
    /// The episode already published an intent under this policy revision, so
    /// this delivery reuses that record instead of appending a second one. This
    /// is the arm a replay, a duplicate tick and a restart reach.
    AlreadyPublished(PublicationRecordRef),
}

/// The episode's own refusal, passed through rather than restated.
pub(crate) mod withheld {
    /// Why the durable failure episode withheld a presented source event from
    /// the threshold decision.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum Reason {
        /// The episode already accepted this exact event identity with this
        /// exact payload digest: a retransmission, which advances no occurrence
        /// count and refreshes no evidence time.
        Retransmission,
        /// The episode already accepted this event identity with a different
        /// payload digest. Changed content under a known identity is a conflict,
        /// never a delivery, and is never counted as either.
        ConflictingPayload {
            /// The payload digest the episode already recorded for this identity.
            recorded_payload_digest: String,
        },
    }
}

/// Resolves one accepted source event against the episode's durable publication
/// state and, when the threshold is crossed, appends exactly one publication
/// intent inside the caller's already-open write transaction.
///
/// This opens, closes and commits no transaction of its own, and appends through
/// the caller's [`super::WatchdogSpool::append_in_transaction`], so the appended
/// publication record, the evidence advance that authorised it, the advanced
/// episode row and the spool's own high-water update are all one durability
/// point. That is what makes a crossing impossible without its evidence, and
/// makes a lost export acknowledgement resumable from the retained record rather
/// than duplicable.
///
/// The decision itself is the owner-neutral core's
/// [`eliot_watchdog_core::evaluate_publication_intent`], applied to one
/// immutable Signal revision projected from the accepted episode row, the
/// **episode's own** [`eliot_watchdog_core::SourceEventAdmission`] for the
/// presented event, and the exact set of evidence identities this episode has
/// already had counted. The episode's admission is the sole gate on whether this
/// delivery may add independent pressure, so a caller cannot cross a threshold by
/// passing an empty already-counted list.
///
/// # Errors
///
/// Returns [`SpoolError`] when the stored publication row is not canonical, the
/// projected revision is not a valid Signal, the record cannot be encoded, or the
/// append inside the caller's transaction fails. The caller's transaction is then
/// dropped uncommitted, exactly as it would be had this step failed in place, so
/// no publication intent can exist without its evidence advance.
pub(crate) fn resolve_publication_intent(
    write: &redb::WriteTransaction,
    ledger_key: &str,
    episode: &super::episode::StoredSignalEpisode,
    admission: &eliot_watchdog_core::SourceEventAdmission,
    source_event: &eliot_watchdog_core::AcceptedSourceEvent,
    lineage: &PublicationLineage,
    coverage_id: &str,
) -> Result<(PublicationOutcome, Option<PublicationState>), SpoolError> {
    resolve_publication(
        write,
        ledger_key,
        episode,
        admission,
        source_event,
        lineage,
        coverage_id,
    )
}

/// Projects one core decision that mints nothing onto the caller's outcome.
///
/// The match is total over the non-publishing decisions with no wildcard, so a
/// decision this owner cannot account for fails the build here instead of being
/// folded into a neighbouring arm and reported as a decision it never made.
///
/// A repeated delivery is reported against the count it did not reach, which is
/// the honest answer: it advanced nothing, so it was not refused by any
/// threshold, and a synthetic "required" would claim a decision was taken that
/// was never made.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the core withheld an admission this owner
/// had already admitted, or minted an intent through an arm that mints nothing.
/// Both are unreachable while the episode's own admission is the gate the caller
/// passes in, and both are named explicitly rather than restated: this owner
/// refuses rather than reporting a decision it cannot account for.
fn non_publishing_outcome(decision: PublicationDecision) -> Result<PublicationOutcome, SpoolError> {
    match decision {
        // A repeated delivery is reported against the count it did not reach,
        // because it advanced nothing and so was not refused by any threshold.
        PublicationDecision::RepeatedDelivery {
            distinct_evidence_count,
        } => Ok(PublicationOutcome::BelowThreshold {
            distinct_evidence_count,
            required: distinct_evidence_count,
        }),
        PublicationDecision::BelowThreshold {
            distinct_evidence_count,
            required,
        } => Ok(PublicationOutcome::BelowThreshold {
            distinct_evidence_count,
            required,
        }),
        PublicationDecision::EvidenceUnavailable { limitation } => {
            Ok(PublicationOutcome::EvidenceUnavailable { limitation })
        }
        PublicationDecision::NotAttention { severity } => {
            Ok(PublicationOutcome::NotAttention { severity })
        }
        PublicationDecision::AdmissionWithheld { .. } => Err(SpoolError::Corrupt(
            "watchdog publication decision withheld an admission the episode admitted".to_owned(),
        )),
        PublicationDecision::Publish(_) => Err(SpoolError::Corrupt(
            "watchdog publication decision minted an intent through the non-publishing arm"
                .to_owned(),
        )),
    }
}

/// The single implementation behind [`resolve_publication_intent`], split out so
/// the documented entry point and the decision body are each readable on their
/// own. Both take the same arguments, so there is exactly one argument list in
/// behaviour and no second path that could diverge from it.
fn resolve_publication(
    write: &redb::WriteTransaction,
    ledger_key: &str,
    episode: &super::episode::StoredSignalEpisode,
    admission: &eliot_watchdog_core::SourceEventAdmission,
    source_event: &eliot_watchdog_core::AcceptedSourceEvent,
    lineage: &PublicationLineage,
    coverage_id: &str,
) -> Result<(PublicationOutcome, Option<PublicationState>), SpoolError> {
    // The episode's own admission is consulted before anything is counted, so a
    // delivery the durable index withheld contributes nothing regardless of what
    // the projected revision references. The match is total over the admission
    // enum, so a withheld delivery can never fall past this gate.
    let withheld = match admission {
        eliot_watchdog_core::SourceEventAdmission::NewEvidence { .. } => None,
        eliot_watchdog_core::SourceEventAdmission::Retransmission { .. } => {
            Some(withheld::Reason::Retransmission)
        }
        eliot_watchdog_core::SourceEventAdmission::ConflictingPayload {
            recorded_payload_digest,
        } => Some(withheld::Reason::ConflictingPayload {
            recorded_payload_digest: recorded_payload_digest.clone(),
        }),
    };
    let stored = {
        let table = write
            .open_table(super::episode::SIGNAL_PUBLICATION_TABLE)
            .map_err(|error| SpoolError::Database(error.to_string()))?;
        super::episode::read_publication_state(&table, ledger_key)?
    };
    if let Some(reason) = withheld {
        // Nothing is counted and nothing is minted. A state row is still
        // returned when the episode already published, so the caller can report
        // the record that exists rather than losing the link to it; the caller
        // writes nothing, so that row is identical to the stored one.
        return match stored
            .as_ref()
            .and_then(PublicationState::committed)
            .map(record_ref_from_emission)
        {
            Some(reference) => Ok((PublicationOutcome::AlreadyPublished(reference), None)),
            None => Ok((PublicationOutcome::AdmissionWithheld { reason }, None)),
        };
    }
    let mut state =
        stored.unwrap_or_else(|| PublicationState::fresh(episode.projection().episode_key()));
    // An episode that already published under this policy revision reuses that
    // record. This is the structural form of "a replay must not create a second
    // intent": there is exactly one publication per episode per policy revision,
    // and the durable emission reference is what a later delivery names.
    if let Some(emission) = state.committed().cloned() {
        return Ok((
            PublicationOutcome::AlreadyPublished(record_ref_from_emission(&emission)),
            None,
        ));
    }
    let episode_projection = episode.projection();
    let evidence_id = publication_evidence_id(episode_projection.episode_key(), source_event);
    let signal =
        project_accepted_signal(&episode_projection, source_event, &evidence_id, coverage_id)?;
    let policy = attention_policy().map_err(|error| {
        SpoolError::Corrupt(format!(
            "watchdog attention policy is not constructible: {error:?}"
        ))
    })?;
    let counted = state.counted_evidence.clone();
    let decision =
        evaluate_publication_intent(&signal, &policy, admission, &counted).map_err(|error| {
            SpoolError::Corrupt(format!(
                "watchdog publication decision is not derivable: {error:?}"
            ))
        })?;
    let intent = match decision {
        PublicationDecision::Publish(intent) => intent,
        other => return Ok((non_publishing_outcome(other)?, None)),
    };
    // The record is built first, so its own validated observed time is the one
    // the append carries: a revision that records no usable time is refused
    // before anything is retained, and the retained time can never be a value
    // this owner synthesised.
    let record = PublicationIntentRecord::new(&intent, lineage.clone())?;
    // The append happens on the caller's transaction and before the state row
    // naming that record is accepted, so no durable write moves relative to a
    // `?` or to the caller's `commit()`.
    let (_appended, created) =
        super::append_in_transaction_on(write, record.observed_at_ms(), record.to_payload())?;
    let raw = super::encode_entry(&created)?;
    let (_payload_digest, record_digest) = super::export_record_digests(&created, &raw);
    let class = record.class();
    // The emission is built once and the row's own copy of it becomes the
    // durable reference, so the caller's outcome and the persisted state can
    // never state two different records for one crossing.
    let emission = PublicationEmission {
        sequence: created.sequence,
        record_digest,
        intent_id: intent.intent_id.clone(),
        class,
        observed_at_ms: created.observed_at_ms,
    };
    state.accept_intent(ledger_key, &intent, emission)?;
    let committed = state
        .emission
        .as_ref()
        .map(record_ref_from_emission)
        .ok_or_else(|| {
            SpoolError::Corrupt(
                "watchdog publication state did not retain the emission it just accepted"
                    .to_owned(),
            )
        })?;
    Ok((PublicationOutcome::Published(committed), Some(state)))
}

/// Projects a committed emission back onto the caller's outcome reference.
fn record_ref_from_emission(emission: &PublicationEmission) -> PublicationRecordRef {
    PublicationRecordRef {
        sequence: emission.sequence,
        record_digest: emission.record_digest.clone(),
        intent_id: emission.intent_id.clone(),
        class: emission.class,
    }
}

/// Fails closed on one bounded owner identity.
pub(crate) fn check_id(value: &str, field: &'static str) -> Result<(), SpoolError> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > MAX_PUBLICATION_ID_LEN
    {
        return Err(SpoolError::Corrupt(format!(
            "watchdog {field} is not a usable bounded identity"
        )));
    }
    Ok(())
}

/// Fails closed on one digest that is not 64 lowercase hexadecimal characters.
pub(crate) fn check_digest(value: &str) -> Result<(), SpoolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SpoolError::Corrupt(
            "watchdog publication digest is not a lowercase SHA-256 digest".to_owned(),
        ));
    }
    Ok(())
}
