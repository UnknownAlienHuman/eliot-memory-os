//! Durable failure-episode deduplication and recurrence state for the
//! Watchdog's own spool.
//!
//! Architecture: ARCH-WDG-01, ARCH-WDG-02, ARCH-PORT-01.
//! Implementation: I8.3, I8.9.
//!
//! What this owner holds, and why it is separate from the escalation rule in
//! [`super::intent`]: I8.9 requires the independent axes of a Signal to stay
//! independent. The escalation rule answers "how far has this episode
//! progressed toward its thresholds"; this module answers "has this exact
//! observation already been accepted, and what is the state of its failure
//! episode". Folding the two together would make one axis a function of the
//! other, so they are persisted as two rows that one owner transaction advances
//! together.
//!
//! The episode key is derived in the owner-neutral core
//! ([`eliot_watchdog_core::FailureEpisodeKey`]) from owner-issued facts only:
//! rule identity and revision, exact scope, the actual observed subject and its
//! generation, and the discriminating failure class. The **source event identity
//! is not part of that key** and is tracked here instead, as a bounded
//! per-episode list of `(event id, payload digest)` pairs. That separation is
//! what makes the three required behaviours fall out of one mechanism:
//!
//! * a retransmitted event (same identity, same digest) advances nothing — not
//!   the independent occurrence count, not the episode's evidence time — and
//!   the caller is handed the revision this episode already accepted, so a
//!   restart, a duplicate tick and a lost acknowledgement all reuse it instead
//!   of emitting a fresh alert;
//! * a genuinely new event appends evidence, advances the accepted revision and
//!   mints exactly one new retained record;
//! * the same event identity carrying a **different** payload digest is refused
//!   as a typed conflict. It is never a silent overwrite of the recorded digest
//!   and never a second episode.
//!
//! Retention: the row lives in its own table beside the records it describes, so
//! the spool's own bounded record retention applies to records and never to this
//! row. Each bounded history is **refused** at its bound, never trimmed, because
//! trimming the oldest accepted source event identity would let its
//! retransmission be admitted again as new independent evidence, and trimming
//! reopen history would erase an unresolved episode.
//!
//! Reopen state is preserved, not erased. A live admission closes an open
//! episode; a later new source event that satisfies the episode's own stored
//! [`eliot_watchdog_core::ReopenCondition`] reopens it and appends the prior
//! instance to the reopen history, so recurrence stays observable beside the
//! episode it recurs from.

use eliot_contracts::sha256_hex;
use eliot_watchdog_core::{
    AcceptedSourceEvent, FailureClass, FailureEpisodeIdentity, FailureEpisodeKey, ReopenCondition,
    RuleRevision, SignalTarget, SourceEventAdmission, classify_source_event, reopen_permitted,
};
use redb::{ReadableTable, TableDefinition, WriteTransaction};

use crate::{GapRecoveryReason, SpoolError};

/// Storage revision of one durable failure-episode row.
pub(crate) const SIGNAL_EPISODE_SCHEMA_VERSION: u16 = 1;

/// Maximum number of distinct source event identities one episode instance
/// retains.
///
/// This is the point past which recognising a retransmission can no longer be
/// proven, so reaching it is refused rather than trimmed. Thirty-two distinct
/// events for one subject, scope, generation and failure class is far above what
/// a single episode needs before the spool's own bounded record retention is
/// the honest limit.
pub(crate) const MAX_SIGNAL_EPISODE_SOURCE_EVENTS: usize = 32;

/// Maximum number of reopen transitions one episode retains.
///
/// A reopen appends the prior instance and is never destructive, so this bound
/// is reached only by a subject that has failed, recovered and failed again
/// eight times within one owner generation. It is refused, never trimmed.
pub(crate) const MAX_SIGNAL_EPISODE_REOPENS: usize = 8;

/// Maximum number of distinct failure episodes this owner keeps at once.
///
/// One episode exists per (rule revision, scope, subject, generation, failure
/// class), so this bounds the table across every subject and class rather than
/// within one of them. It is set well above the per-episode source-event bound
/// because a single episode can legitimately hold thirty-two events while the
/// table only needs to hold the episodes that are still live. A live admission
/// closes **every** open episode, so this cap — not a partial pass — is what
/// keeps the closer's work bounded, and reaching it refuses a new episode
/// rather than dropping an existing one.
pub(crate) const MAX_SIGNAL_EPISODES: usize = 256;

const _: () = assert!(MAX_SIGNAL_EPISODE_SOURCE_EVENTS == 32);
const _: () = assert!(MAX_SIGNAL_EPISODE_REOPENS == 8);
const _: () = assert!(
    MAX_SIGNAL_EPISODES > MAX_SIGNAL_EPISODE_SOURCE_EVENTS,
    "one episode must hold fewer events than the table holds episodes"
);

/// Identity of the Watchdog-owned rule that observes a supervision gap.
///
/// This is the rule identity and immutable revision a failure episode is keyed
/// on. It is a closed constant, not caller prose, and bumping it is what
/// deliberately starts a new episode generation instead of silently
/// reinterpreting episodes decided under another rule revision.
pub(crate) const SUPERVISION_GAP_RULE_ID: &str = "watchdog_supervision_gap_observation";

/// Immutable revision of [`SUPERVISION_GAP_RULE_ID`].
pub(crate) const SUPERVISION_GAP_RULE_REVISION: u64 = 1;

const _: () = assert!(SUPERVISION_GAP_RULE_REVISION == 1);

/// One admitted source event identity with the payload digest recorded for it.
///
/// Mirrors [`eliot_watchdog_core::AcceptedSourceEvent`] one to one, because the
/// owner-neutral core contract carries no `serde` implementation. The two are
/// converted through the two functions below and neither ever shadows the
/// other: the identity says which event was observed, the digest says what was
/// observed about it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSourceEvent {
    event_id: String,
    payload_digest: String,
}

impl StoredSourceEvent {
    fn from_core(event: &AcceptedSourceEvent) -> Self {
        Self {
            event_id: event.event_id.clone(),
            payload_digest: event.payload_digest.clone(),
        }
    }

    fn to_core(&self) -> AcceptedSourceEvent {
        AcceptedSourceEvent {
            event_id: self.event_id.clone(),
            payload_digest: self.payload_digest.clone(),
        }
    }
}

/// Reference to the exact retained record one accepted Signal revision produced.
///
/// It names the record its own transaction created, not a later read of the
/// spool high-water mark, and it is persisted in the same owner transaction as
/// that record. It is the processing cursor/result a deduplicated revision points
/// at: a restart, a duplicate tick or a lost acknowledgement reuses this exact
/// reference instead of minting a second one.
///
/// Retention interaction, stated exactly: this is the record's identity **as
/// accepted**, bound once and never revised. The record itself remains under the
/// spool's existing retention and compaction policy like any other `Gap` record
/// — this row neither pins a record against that policy nor resurrects one it
/// removed, and it grants no claim that a named sequence is still retained. The
/// episode survives the record; the record is not retained for the episode.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredSignalRecordRef {
    /// Retained spool sequence of the exact record.
    pub(crate) sequence: u64,
    /// Digest over the identity of that exact record, bound the way an export
    /// batch binds it.
    pub(crate) record_digest: String,
    /// Owner-clock time the record was appended with.
    pub(crate) observed_at_ms: u64,
}

/// One reopen transition of an episode.
///
/// The prior instance is named, never erased: `prior_revision` and
/// `prior_record` say exactly which accepted revision the recurrence followed,
/// and `prior_evidence_at_ms` is the evidence time that instance stood at, so
/// the earlier episode stays represented beside the new one.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StoredReopen {
    ordinal: u64,
    prior_evidence_at_ms: u64,
    prior_revision: u64,
    prior_record: Option<StoredSignalRecordRef>,
}

/// Lifecycle phase of one failure episode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredEpisodePhase {
    /// The episode is open: a further new source event extends it in place.
    Open,
    /// The episode was closed by a live admission. Its history stays retained
    /// on the row, and a new source event that satisfies the stored reopen
    /// condition reopens it through an appended reopen record rather than by
    /// resetting it.
    Closed,
}

/// Durable failure-episode row.
///
/// Stored in the same `watchdog.redb` file as the records it describes, under
/// its own table, and written inside the same owner transaction that appends
/// the record one accepted revision produced. A restart therefore cannot lose
/// the deduplication state, and a failure before that commit can leave neither a
/// record whose episode was never updated nor an episode whose record was never
/// appended.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredSignalEpisode {
    schema_version: u16,
    /// The derived episode key. It is re-derived from the identity fields this
    /// row independently stores and compared on every read, so a row can never
    /// be read under an identity it was not written with.
    episode_key: String,
    failure_class: String,
    rule_id: String,
    rule_revision: u64,
    subject_id: String,
    scope_id: String,
    generation: u64,
    /// Stored reopen condition, as its stable class code.
    reopen_condition: String,
    phase: StoredEpisodePhase,
    /// Highest revision this episode ever accepted, across every reopen. It
    /// never decreases, so a recurrence can never reuse a revision number an
    /// earlier instance already published.
    highest_revision: u64,
    /// Accepted revision of the currently open instance.
    accepted_revision: u64,
    /// Independent occurrences of the currently open instance: exactly one per
    /// distinct source event identity it has accepted. A retransmission never
    /// advances it.
    independent_occurrences: u32,
    /// Evidence time of the newest **accepted** source event. A retransmission
    /// never refreshes it, so a stale failure cannot be made to look fresh by
    /// re-observing it.
    evidence_observed_at_ms: u64,
    accepted_source_events: Vec<StoredSourceEvent>,
    accepted_record: Option<StoredSignalRecordRef>,
    reopen_history: Vec<StoredReopen>,
}

/// What a caller may learn about one episode's standing after an admission.
///
/// The three values are the whole of what a duplicate tick, a restart or a lost
/// acknowledgement may reuse: which revision was accepted, how many independent
/// occurrences that revision rests on, and when the newest accepted evidence was
/// actually observed. None of them is derived from a clock reading taken later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SignalEpisodeProgress {
    /// Accepted revision of the currently open instance.
    pub(crate) revision: u64,
    /// Independent occurrences that revision rests on.
    pub(crate) independent_occurrences: u32,
    /// Evidence time of the newest accepted source event.
    pub(crate) evidence_observed_at_ms: u64,
}

/// One observed failure offered to the durable episode state.
///
/// The identity and the source event are supplied by the observation's owners:
/// the subject, scope and generation are retained owner identities, and the
/// payload digest is taken over the exact closed material this owner actually
/// observed. Nothing here is caller-chosen prose.
pub(crate) struct SignalEpisodeObservation {
    /// Owner-issued facts the episode key is derived from.
    pub(crate) identity: FailureEpisodeIdentity,
    /// Exact source event identity and its separately recorded payload digest.
    pub(crate) source_event: AcceptedSourceEvent,
    /// The condition under which this episode may be reopened.
    pub(crate) reopen_condition: ReopenCondition,
    /// Owner-clock time of this observation.
    pub(crate) observed_at_ms: u64,
    /// Watchdog generation that produced this observation.
    pub(crate) producer_generation: u64,
    /// The retained gap reason appended for one newly accepted revision.
    pub(crate) record_reason: GapRecoveryReason,
}

/// Typed refusal of one offered observation.
///
/// Each variant is a refusal the owner reports rather than acts on: nothing is
/// written, no record is appended, and no revision is minted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SignalEpisodeRefusal {
    /// The same source event identity was already accepted with a different
    /// payload digest. Changed content under a known event identity is never a
    /// silent overwrite and never a new episode.
    ConflictingSourceEventPayload {
        /// Identity whose recorded digest disagrees with the offered one.
        event_id: String,
        /// The payload digest this episode already recorded for it.
        recorded_payload_digest: String,
    },
    /// The episode instance already retains the maximum number of distinct
    /// source event identities. Refused rather than trimmed, because trimming
    /// the oldest identity would let its retransmission be admitted again.
    SourceEventHistoryFull {
        /// Distinct source event identities already retained.
        accepted_source_events: usize,
    },
    /// The episode already retains the maximum number of reopen transitions.
    /// Refused rather than trimmed, so an unresolved episode keeps its history.
    ReopenHistoryFull {
        /// Reopen transitions already retained.
        reopen_count: usize,
    },
}

/// Bounded report of what the publication owner decided about the Signal this
/// accepted revision produced.
///
/// It is a *label*, deliberately not the record's identity. The exact committed
/// record lives in the durable publication row and in the retained spool, and
/// reporting a second copy of that identity here would create a second place it
/// is stated — one the two could then disagree about. Every variant is an
/// observation about the Watchdog's own decision: none of them is a canonical
/// Problem, a canonical Incident, a delivery, or a resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SignalEpisodePublicationReport {
    /// Exactly one publication intent was appended in the same transaction as
    /// this accepted revision, and it is now durable beside it.
    Published {
        /// Stable intent identity the crossing was decided under.
        intent_id: String,
        /// Retained spool sequence of the exact committed record.
        sequence: u64,
    },
    /// The episode already published an intent under this policy revision, so
    /// this delivery reused that record instead of appending a second one. This
    /// is the arm a replay, a duplicate tick and a restart reach.
    AlreadyPublished {
        /// Stable intent identity of the record that already exists.
        intent_id: String,
    },
    /// Distinct evidence is accumulating but has not reached this severity's
    /// threshold. Nothing was appended.
    BelowThreshold {
        /// Distinct evidence counted for this episode so far.
        distinct_evidence_count: usize,
        /// The threshold this severity requires.
        required: usize,
    },
    /// The episode's durable index withheld this delivery, so it contributed no
    /// independent evidence and nothing was appended.
    Withheld {
        /// Closed code of the episode's own refusal.
        reason: &'static str,
    },
    /// The projected revision records no usable evidence references, so no
    /// threshold could be substantiated. The limitation travelled with the
    /// decision instead of a count it cannot support.
    EvidenceUnavailable,
    /// The projected severity does not request attention, so no publication
    /// intent is derivable from it at any evidence count.
    NotAttention,
}

/// Resolved outcome of one offered observation against the retained spool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SignalEpisodeOutcome {
    /// A genuinely new source event identity was accepted: exactly one retained
    /// record was appended in the same owner transaction, the episode advanced,
    /// and the outcome names that exact record.
    Accepted {
        /// The accepted Signal revision.
        revision: u64,
        /// Independent occurrences of the current instance after this one.
        independent_occurrences: u32,
        /// The exact retained record this revision produced.
        record: StoredSignalRecordRef,
        /// Whether this acceptance reopened a previously closed episode.
        reopened: bool,
        /// What the publication owner decided about this revision's Signal, in
        /// the same owner transaction that accepted it.
        publication: SignalEpisodePublicationReport,
    },
    /// The offered observation was a retransmission of an already accepted
    /// source event identity. Nothing was written and no record was appended;
    /// the outcome names the revision and record this episode already accepted,
    /// which is what a restart, a duplicate tick or a lost acknowledgement
    /// reuses instead of emitting a fresh alert.
    Reused {
        /// The revision this episode already accepted.
        revision: u64,
        /// Independent occurrences, reported unchanged.
        independent_occurrences: u32,
        /// Evidence time of the newest accepted source event, reported
        /// unchanged and never refreshed by a retransmission.
        evidence_observed_at_ms: u64,
        /// The exact retained record the accepted revision produced.
        record: StoredSignalRecordRef,
        /// What the publication owner decided about this same withheld delivery.
        ///
        /// Reported rather than discarded so a caller can see that the delivery
        /// reached the threshold decision and was refused *there*, instead of
        /// never being offered to it. That distinction is the difference between
        /// "this delivery added no pressure" and "this observation was not
        /// considered", and the second would be a silent supervision gap.
        publication: SignalEpisodePublicationReport,
    },
    /// The offered observation was refused; nothing was written.
    Refused(SignalEpisodeRefusal),
}

/// Maps one observed gap reason onto its discriminating failure class, or
/// refuses to key it at all.
///
/// Retention pressure is `None`: it is this owner's own storage pressure, not an
/// observed failure of a supervised subject, and keying it would let a busy
/// spool manufacture failure episodes — exactly the amplification the
/// deduplication exists to prevent. The caller keeps its existing plain gap
/// record for that case. The remaining match is exhaustive with no wildcard: a
/// future reason fails the build here instead of being folded into an existing
/// class.
pub(crate) fn failure_class_of_reason(reason: GapRecoveryReason) -> Option<FailureClass> {
    match reason {
        GapRecoveryReason::AdmissionUnavailable => Some(FailureClass::GovernorAdmissionUnavailable),
        GapRecoveryReason::LeaseStale => Some(FailureClass::SupervisionLeaseStale),
        GapRecoveryReason::LeaseFenced => Some(FailureClass::SupervisionLeaseFenced),
        GapRecoveryReason::LeaseInvalid => Some(FailureClass::SupervisionLeaseInvalid),
        GapRecoveryReason::HostAbsentOrStopped => Some(FailureClass::HostAbsentOrStopped),
        GapRecoveryReason::HostPidReused => Some(FailureClass::HostPidReused),
        GapRecoveryReason::HostImageSubstituted => Some(FailureClass::HostImageSubstituted),
        GapRecoveryReason::HostIdentityChanged => Some(FailureClass::HostIdentityChanged),
        GapRecoveryReason::HostUnknown => Some(FailureClass::HostUnknown),
        GapRecoveryReason::SpoolPressure => None,
    }
}

/// Stores a reopen condition under its stable class code.
///
/// An undecidable condition (explicit prose, or a recorded historical
/// limitation) is stored as its own code rather than replaced by a decidable
/// one: substituting a condition would let an episode reopen on a basis its
/// owner never stated.
fn reopen_condition_code(condition: &ReopenCondition) -> &'static str {
    match condition {
        ReopenCondition::NewEvidence => "new_evidence",
        ReopenCondition::RecurrenceWithNewSourceEvent => "recurrence_with_new_source_event",
        ReopenCondition::ExpectedContextChanged => "expected_context_changed",
        ReopenCondition::Explicit { .. } => "explicit",
        ReopenCondition::Unknown { .. } => "unknown",
    }
}

/// Reads one stored reopen condition back under its exact class code.
///
/// The two undecidable classes are reconstructed as themselves and never as a
/// decidable condition: `Explicit` keeps only the statement that the stored
/// condition is an explicit one this owner does not evaluate, and `Unknown`
/// keeps only that it was recorded with a historical limitation. Neither text
/// can change a decision, because the core reopen evaluation refuses both
/// classes outright.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the stored code names no condition this
/// owner writes, so a row can never be reopened under a condition it never
/// recorded.
fn stored_reopen_condition(code: &str) -> Result<ReopenCondition, SpoolError> {
    match code {
        "new_evidence" => Ok(ReopenCondition::NewEvidence),
        "recurrence_with_new_source_event" => Ok(ReopenCondition::RecurrenceWithNewSourceEvent),
        "expected_context_changed" => Ok(ReopenCondition::ExpectedContextChanged),
        "explicit" => Ok(ReopenCondition::Explicit {
            condition: "stored explicit reopen condition; not evaluated by this owner".to_owned(),
        }),
        "unknown" => Ok(ReopenCondition::Unknown {
            limitation: "stored reopen condition carries a historical limitation".to_owned(),
        }),
        _ => Err(SpoolError::Corrupt(
            "watchdog signal episode reopen condition is not a stored condition".to_owned(),
        )),
    }
}

/// Fails closed on one stored identity string that no owner could have issued.
fn check_identity_text(value: &str, field: &'static str) -> Result<(), SpoolError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SpoolError::Corrupt(format!(
            "watchdog signal episode {field} is not a usable owner identity"
        )));
    }
    Ok(())
}

/// Fails closed on one stored digest that is not a lowercase SHA-256.
fn check_digest(value: &str, field: &'static str) -> Result<(), SpoolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SpoolError::Corrupt(format!(
            "watchdog signal episode {field} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

/// The facts one genuinely new source event was accepted on.
///
/// It is separate from [`SignalEpisodeOutcome::Accepted`] rather than built
/// inside it, because the publication decision needs the *advanced* episode row
/// before the outcome can be assembled: the threshold is decided from the Signal
/// the accepted event actually produced, not from a revision restated by the
/// accepting step. The owner transaction that holds the advanced row is
/// therefore the one place the outcome is built, and this value is the only
/// thing the accepting step hands it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedSignalEpisode {
    /// The accepted Signal revision.
    pub(crate) revision: u64,
    /// Independent occurrences of the current instance after this one.
    pub(crate) independent_occurrences: u32,
    /// Evidence time of the newest **accepted** source event. Reported
    /// unchanged by a retransmission and never refreshed by one, so a stale
    /// failure cannot be made to look fresh by re-observing it.
    pub(crate) evidence_observed_at_ms: u64,
    /// The exact retained record this revision produced.
    pub(crate) record: StoredSignalRecordRef,
    /// Whether this acceptance reopened a previously closed episode.
    ///
    /// Always `false` for a reused revision, which by definition did not reopen
    /// anything: a retransmission is recognised against the episode that already
    /// accepted it.
    pub(crate) reopened: bool,
}

/// How one classified admission resolved, before the publication decision runs.
///
/// This is the accepting step's own result and nothing more. It is deliberately
/// not [`SignalEpisodeOutcome`], because the publication decision has to read
/// the *advanced* episode row a genuinely new event produced before the outcome
/// can be reported. Handing the accepting step's result back as the caller's
/// outcome would either force the report to be built before the decision or leave
/// a second place the record's identity is stated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionResolution {
    /// A genuinely new source event was accepted, and the advanced row the
    /// acceptance produced is handed back so the publication decision can be
    /// taken from the Signal this event actually justified.
    Accepted {
        /// The facts this acceptance produced.
        accepted: AcceptedSignalEpisode,
        /// The advanced episode row, in the same uncommitted transaction as the
        /// record it names.
        state: StoredSignalEpisode,
    },
    /// The offered event was a retransmission. Nothing was written; the accepted
    /// facts are reported unchanged so the caller can assemble the reused
    /// outcome.
    Reused {
        /// The facts this episode already accepted.
        accepted: AcceptedSignalEpisode,
        /// The unchanged episode row. Handed back so the owner transaction can
        /// still consult the publication decision against the same durable index
        /// that recognised the retransmission, without opening a second read.
        state: StoredSignalEpisode,
    },
    /// The offered event was refused. Nothing was written and no record was
    /// appended.
    Refused(SignalEpisodeRefusal),
}

impl SignalEpisodeOutcome {
    /// Assembles the accepted outcome from the facts the accepting step produced
    /// and the publication report the same transaction decided.
    ///
    /// The report is a separate field rather than a new outcome variant because
    /// the episode's acceptance and the publication decision are two independent
    /// axes (I8.9): an observation is accepted for deduplication whether or not
    /// it crossed an attention threshold, and a crossing is reported for an
    /// observation that was genuinely accepted. Folding them into one enum would
    /// make one axis a function of the other, which is exactly what the separate
    /// durable rows beside them exist to prevent.
    #[must_use]
    pub(crate) fn accepted(
        accepted: AcceptedSignalEpisode,
        publication: SignalEpisodePublicationReport,
    ) -> Self {
        Self::Accepted {
            revision: accepted.revision,
            independent_occurrences: accepted.independent_occurrences,
            record: accepted.record,
            reopened: accepted.reopened,
            publication,
        }
    }
}

impl StoredSignalEpisode {
    /// Builds the closed state of an episode that has accepted nothing yet.
    #[must_use]
    pub(crate) fn fresh(
        identity: &FailureEpisodeIdentity,
        episode_key: &FailureEpisodeKey,
        reopen_condition: &ReopenCondition,
    ) -> Self {
        Self {
            schema_version: SIGNAL_EPISODE_SCHEMA_VERSION,
            episode_key: episode_key.as_str().to_owned(),
            failure_class: identity.failure_class.code().to_owned(),
            rule_id: identity.rule.rule_id.clone(),
            rule_revision: identity.rule.revision,
            subject_id: identity.target.subject_id.clone(),
            scope_id: identity.target.scope_id.clone(),
            generation: identity.target.generation,
            reopen_condition: reopen_condition_code(reopen_condition).to_owned(),
            phase: StoredEpisodePhase::Open,
            highest_revision: 0,
            accepted_revision: 0,
            independent_occurrences: 0,
            evidence_observed_at_ms: 0,
            accepted_source_events: Vec::new(),
            accepted_record: None,
            reopen_history: Vec::new(),
        }
    }

    /// Fails closed on a stored row that is not in canonical form.
    ///
    /// The episode key is re-derived from the identity fields this row
    /// independently stores and compared with the key it recorded, so neither
    /// can be substituted for the other. The stored class and reopen condition
    /// are read back under their exact codes, the accepted event list is
    /// bounded and free of repeated identities, the accepted record exists
    /// exactly when the episode accepted something, and the reopen history is
    /// bounded and ordered.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the schema drifted, an identity
    /// field or the stored key is unusable, the stored class or reopen
    /// condition is not one this owner writes, the re-derived key disagrees with
    /// the stored one, the accepted event list is over the bound or repeats an
    /// identity, the occurrence count is not one per accepted identity, a record
    /// reference is present without an accepted occurrence or absent with one,
    /// accepted evidence carries no evidence time, a revision is above the
    /// episode's own highest revision, or the reopen history is over the bound
    /// or out of order.
    pub(crate) fn validate(&self) -> Result<(), SpoolError> {
        if self.schema_version != SIGNAL_EPISODE_SCHEMA_VERSION {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode schema is unsupported".to_owned(),
            ));
        }
        // The three checks below run in this fixed order and each one fails
        // closed on the same conditions it always did. They read only this row,
        // so splitting them moves no durable write and no transaction boundary:
        // a caller that validated a row before its commit still validates the
        // identical row the same way afterwards.
        self.validate_stored_identity()?;
        self.validate_accepted_evidence()?;
        self.validate_reopen_history()
    }

    /// Fails closed when the stored identity is unusable or disagrees with the
    /// episode key this row recorded for it.
    ///
    /// The key is re-derived from the identity fields the row independently
    /// stores, so neither can be substituted for the other, and the stored class
    /// and reopen condition are read back under their exact codes.
    fn validate_stored_identity(&self) -> Result<(), SpoolError> {
        check_identity_text(&self.episode_key, "episode key")?;
        check_identity_text(&self.rule_id, "rule identity")?;
        check_identity_text(&self.subject_id, "subject identity")?;
        check_identity_text(&self.scope_id, "scope identity")?;
        if self.rule_revision == 0 || self.generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode records an uninitialized rule revision or generation"
                    .to_owned(),
            ));
        }
        let failure_class = FailureClass::from_code(&self.failure_class).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog signal episode failure class is not a stored class".to_owned(),
            )
        })?;
        stored_reopen_condition(&self.reopen_condition)?;
        let rederived = FailureEpisodeKey::derive(&FailureEpisodeIdentity {
            rule: RuleRevision {
                rule_id: self.rule_id.clone(),
                revision: self.rule_revision,
            },
            target: SignalTarget {
                subject_id: self.subject_id.clone(),
                scope_id: self.scope_id.clone(),
                generation: self.generation,
            },
            failure_class,
        })
        .map_err(|_| {
            SpoolError::Corrupt(
                "watchdog signal episode identity cannot derive an episode key".to_owned(),
            )
        })?;
        if rederived.as_str() != self.episode_key {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode key does not match its own stored identity".to_owned(),
            ));
        }
        Ok(())
    }

    /// Fails closed when the accepted evidence disagrees with itself.
    ///
    /// The accepted event list is bounded and free of repeated identities, the
    /// occurrence count is exactly one per accepted identity, a record reference
    /// exists exactly when the episode accepted something, and the retained
    /// record is itself canonical.
    fn validate_accepted_evidence(&self) -> Result<(), SpoolError> {
        if self.accepted_revision > self.highest_revision {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode revision is above its own highest revision".to_owned(),
            ));
        }
        if self.accepted_source_events.len() > MAX_SIGNAL_EPISODE_SOURCE_EVENTS {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode source event history exceeds its bound".to_owned(),
            ));
        }
        let mut identities: Vec<&str> = Vec::with_capacity(self.accepted_source_events.len());
        for event in &self.accepted_source_events {
            check_identity_text(&event.event_id, "source event identity")?;
            check_digest(&event.payload_digest, "source event payload digest")?;
            if identities.contains(&event.event_id.as_str()) {
                return Err(SpoolError::Corrupt(
                    "watchdog signal episode repeats one source event identity".to_owned(),
                ));
            }
            identities.push(event.event_id.as_str());
        }
        if self.independent_occurrences as usize != self.accepted_source_events.len() {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode occurrence count is not one per accepted source event"
                    .to_owned(),
            ));
        }
        if self.accepted_record.is_some() != (self.independent_occurrences > 0) {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode record reference does not match its accepted occurrences"
                    .to_owned(),
            ));
        }
        if self.independent_occurrences > 0 && self.evidence_observed_at_ms == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode accepted evidence carries no evidence time".to_owned(),
            ));
        }
        if let Some(record) = self.accepted_record.as_ref() {
            if record.sequence == 0 || record.observed_at_ms == 0 {
                return Err(SpoolError::Corrupt(
                    "watchdog signal episode record reference is not canonical".to_owned(),
                ));
            }
            check_digest(&record.record_digest, "accepted record digest")?;
        }
        Ok(())
    }

    /// Fails closed when the reopen history is over its bound or out of order.
    ///
    /// Ordering is what keeps an earlier episode instance represented beside the
    /// newer one, so a reopened episode cannot rewrite the history behind it.
    fn validate_reopen_history(&self) -> Result<(), SpoolError> {
        if self.reopen_history.len() > MAX_SIGNAL_EPISODE_REOPENS {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode reopen history exceeds its bound".to_owned(),
            ));
        }
        let mut previous_ordinal = 0;
        for reopen in &self.reopen_history {
            if reopen.ordinal <= previous_ordinal || reopen.ordinal > self.highest_revision {
                return Err(SpoolError::Corrupt(
                    "watchdog signal episode reopen history is not ordered".to_owned(),
                ));
            }
            previous_ordinal = reopen.ordinal;
        }
        Ok(())
    }

    /// Classifies one offered source event against this episode's retained
    /// index, through the owner-neutral core decision.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row is not canonical, the
    /// retained index is contradictory, or the offered identity is unusable.
    pub(crate) fn classify(
        &self,
        presented: &AcceptedSourceEvent,
    ) -> Result<SourceEventAdmission, SpoolError> {
        self.validate()?;
        let accepted: Vec<AcceptedSourceEvent> = self
            .accepted_source_events
            .iter()
            .map(StoredSourceEvent::to_core)
            .collect();
        classify_source_event(&accepted, presented).map_err(|error| {
            SpoolError::Corrupt(format!(
                "watchdog signal episode source event is not a usable identity: {error:?}"
            ))
        })
    }

    /// Reports the bound this episode cannot advance past, as a typed refusal.
    ///
    /// Consulted before any mutation so a full bound is reported as a refusal
    /// rather than as a fail-closed corruption, and never as a silent trim.
    /// [`Self::accept`] re-checks the same bound and still fails closed, so this
    /// report can never be the only thing standing between a full history and a
    /// dropped accepted identity.
    #[must_use]
    pub(crate) fn bound_refusal(
        &self,
        admission: &SourceEventAdmission,
    ) -> Option<SignalEpisodeRefusal> {
        if admission.is_new_evidence()
            && self.accepted_source_events.len() >= MAX_SIGNAL_EPISODE_SOURCE_EVENTS
        {
            return Some(SignalEpisodeRefusal::SourceEventHistoryFull {
                accepted_source_events: self.accepted_source_events.len(),
            });
        }
        if matches!(self.phase, StoredEpisodePhase::Closed)
            && self.reopen_history.len() >= MAX_SIGNAL_EPISODE_REOPENS
        {
            return Some(SignalEpisodeRefusal::ReopenHistoryFull {
                reopen_count: self.reopen_history.len(),
            });
        }
        None
    }

    /// Applies one newly accepted source event, advancing the episode in place.
    ///
    /// A closed episode is reopened only when its own stored reopen condition
    /// permits it, and reopening appends the prior instance to the reopen
    /// history instead of resetting it: the earlier episode stays represented
    /// beside the new one. The accepted revision always advances, so a
    /// recurrence can never reuse a revision number an earlier instance already
    /// published.
    ///
    /// Returns whether this acceptance reopened a previously closed episode.
    ///
    /// Takes the three facts of the accepted observation this method reads
    /// rather than the observation itself: the source event identity, its
    /// owner-recorded time, and the producer that issued it. Nothing else in an
    /// observation can influence the resulting row.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row is not canonical, the
    /// observation carries an uninitialized time or producer, the admission is
    /// not a new source event, the episode is closed and its stored reopen
    /// condition does not permit reopening, a bound is already reached, or the
    /// resulting row is not canonical.
    pub(crate) fn accept(
        &mut self,
        source_event: &AcceptedSourceEvent,
        observed_at_ms: u64,
        producer_generation: u64,
        admission: &SourceEventAdmission,
        record: StoredSignalRecordRef,
    ) -> Result<bool, SpoolError> {
        self.validate()?;
        if !admission.is_new_evidence() {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode accepted an admission that is not new evidence".to_owned(),
            ));
        }
        if observed_at_ms == 0 || producer_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode observation carries an uninitialized time or producer"
                    .to_owned(),
            ));
        }
        if self.accepted_source_events.len() >= MAX_SIGNAL_EPISODE_SOURCE_EVENTS {
            return Err(SpoolError::Corrupt(
                "watchdog signal episode source event history is at its bound; \
                 refusing to trim an accepted identity"
                    .to_owned(),
            ));
        }
        let reopened = match self.phase {
            StoredEpisodePhase::Open => false,
            StoredEpisodePhase::Closed => {
                let condition = stored_reopen_condition(&self.reopen_condition)?;
                if !reopen_permitted(&condition, admission) {
                    return Err(SpoolError::Corrupt(
                        "watchdog signal episode is closed and its stored reopen \
                         condition does not permit reopening"
                            .to_owned(),
                    ));
                }
                if self.reopen_history.len() >= MAX_SIGNAL_EPISODE_REOPENS {
                    return Err(SpoolError::Corrupt(
                        "watchdog signal episode reopen history is at its bound; \
                         refusing to trim an unresolved episode"
                            .to_owned(),
                    ));
                }
                let next_ordinal = self
                    .reopen_history
                    .last()
                    .map_or(1, |reopen| reopen.ordinal.saturating_add(1));
                self.reopen_history.push(StoredReopen {
                    ordinal: next_ordinal,
                    prior_evidence_at_ms: self.evidence_observed_at_ms,
                    prior_revision: self.accepted_revision,
                    prior_record: self.accepted_record.clone(),
                });
                self.accepted_revision = 0;
                self.independent_occurrences = 0;
                self.accepted_source_events.clear();
                self.accepted_record = None;
                self.evidence_observed_at_ms = 0;
                self.phase = StoredEpisodePhase::Open;
                true
            }
        };
        self.accepted_source_events
            .push(StoredSourceEvent::from_core(source_event));
        self.independent_occurrences =
            self.independent_occurrences.checked_add(1).ok_or_else(|| {
                SpoolError::Corrupt(
                    "watchdog signal episode occurrence count overflowed".to_owned(),
                )
            })?;
        // A genuinely new event is the only thing that may move the episode's
        // evidence time, and it moves it to this observation's own recorded
        // time, never to a later reading of the clock.
        self.evidence_observed_at_ms = observed_at_ms;
        self.accepted_revision = self.accepted_revision.saturating_add(1);
        self.highest_revision = self.highest_revision.saturating_add(1);
        self.accepted_record = Some(record);
        self.validate()?;
        Ok(reopened)
    }

    /// Closes an open episode after a live admission, retaining its history.
    ///
    /// This is the only closer. It takes no timer, no export acknowledgement and
    /// no caller-chosen reason, and it withdraws nothing: the accepted source
    /// events, the accepted revision, its exact record reference and the reopen
    /// history all stay on the row, so a later recurrence is recognised as a
    /// recurrence of *this* episode rather than as an unrelated first
    /// observation.
    ///
    /// Returns `false` when no episode was open, so a repeated live admission
    /// cannot report a closure that did not happen.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row is not canonical or the
    /// resulting row is not canonical.
    pub(crate) fn close(&mut self) -> Result<bool, SpoolError> {
        self.validate()?;
        if matches!(self.phase, StoredEpisodePhase::Closed) {
            return Ok(false);
        }
        self.phase = StoredEpisodePhase::Closed;
        self.validate()?;
        Ok(true)
    }

    /// Returns the accepted revision and the exact record it produced.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the row is not canonical or the
    /// episode accepted nothing, which is the only state in which no accepted
    /// record exists.
    pub(crate) fn accepted(&self) -> Result<(u64, StoredSignalRecordRef), SpoolError> {
        self.validate()?;
        let record = self.accepted_record.clone().ok_or_else(|| {
            SpoolError::Corrupt("watchdog signal episode accepted no record to reuse".to_owned())
        })?;
        Ok((self.accepted_revision, record))
    }

    /// Returns the episode's standing without mutating anything.
    ///
    /// This is what a retransmission reports, unchanged: it never re-derives the
    /// evidence time from a later clock reading and never recounts occurrences.
    #[must_use]
    pub(crate) const fn progress(&self) -> SignalEpisodeProgress {
        SignalEpisodeProgress {
            revision: self.accepted_revision,
            independent_occurrences: self.independent_occurrences,
            evidence_observed_at_ms: self.evidence_observed_at_ms,
        }
    }

    /// Returns the read-only projection a sibling owner reads this row through.
    ///
    /// The projection exposes exactly the owner-issued facts and standing a
    /// sibling owner needs in order to project an immutable observation revision
    /// from *this* durable row — the publication owner in [`super::publication`].
    /// Going through named accessors rather than into this row's private fields
    /// is what keeps the two owners' reads in one place: the values are the same
    /// ones this row independently stores and re-derives on every validation, so
    /// a projection built from them cannot state an identity the row does not
    /// hold. Every accessor is a plain read and cannot mutate the row.
    #[must_use]
    pub(crate) const fn projection(&self) -> StoredSignalEpisodeProjection<'_> {
        StoredSignalEpisodeProjection { episode: self }
    }
}

/// Read-only projection of one stored episode's owner-issued identity and
/// standing.
pub(crate) struct StoredSignalEpisodeProjection<'a> {
    episode: &'a StoredSignalEpisode,
}

impl StoredSignalEpisodeProjection<'_> {
    /// Returns the core-derived episode key, which is also this episode's Signal
    /// identity and its deduplication key.
    #[must_use]
    pub(crate) const fn episode_key(&self) -> &str {
        self.episode.episode_key.as_str()
    }

    /// Returns the rule identity this episode is keyed on.
    #[must_use]
    pub(crate) const fn rule_id(&self) -> &str {
        self.episode.rule_id.as_str()
    }

    /// Returns the immutable rule revision this episode is keyed on.
    #[must_use]
    pub(crate) const fn rule_revision(&self) -> u64 {
        self.episode.rule_revision
    }

    /// Returns the exact observed subject identity.
    #[must_use]
    pub(crate) const fn subject_id(&self) -> &str {
        self.episode.subject_id.as_str()
    }

    /// Returns the exact observed scope identity.
    #[must_use]
    pub(crate) const fn scope_id(&self) -> &str {
        self.episode.scope_id.as_str()
    }

    /// Returns the observed generation of the subject in this scope.
    #[must_use]
    pub(crate) const fn generation(&self) -> u64 {
        self.episode.generation
    }

    /// Returns the discriminating failure class this episode is keyed on.
    ///
    /// The stored code is read back through the same closed parser this row's
    /// own validation used, so a projection states exactly the class the row
    /// validated rather than a copy that could drift from it.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the stored code names no class this
    /// owner writes.
    pub(crate) fn failure_class(&self) -> Result<FailureClass, SpoolError> {
        FailureClass::from_code(&self.episode.failure_class).map_err(|_| {
            SpoolError::Corrupt(
                "watchdog signal episode failure class is not a stored class".to_owned(),
            )
        })
    }

    /// Returns the accepted revision of the currently open instance.
    #[must_use]
    pub(crate) const fn revision(&self) -> u64 {
        self.episode.accepted_revision
    }

    /// Returns the evidence time of the newest **accepted** source event. A
    /// retransmission never refreshes it, so this is the observation's own
    /// recorded time and never a later clock reading.
    #[must_use]
    pub(crate) const fn evidence_observed_at_ms(&self) -> u64 {
        self.episode.evidence_observed_at_ms
    }

    /// Returns this episode's own stored reopen condition.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the stored code names no condition
    /// this owner writes.
    pub(crate) fn reopen_condition(&self) -> Result<ReopenCondition, SpoolError> {
        stored_reopen_condition(&self.episode.reopen_condition)
    }
}

/// Per-episode table inside the same `watchdog.redb` file as the records it
/// describes.
///
/// It is a separate table, not a second file and not a second database: the
/// owner keeps its single writer and its single file, and every read and write
/// below runs inside the caller's existing transaction. The row is never a
/// compaction candidate, so an unresolved episode cannot be removed by
/// acknowledgement-driven compaction the way an ordinary record can.
pub(crate) const SIGNAL_EPISODE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_signal_episode_v1");

/// Per-episode publication state, in the same `watchdog.redb` file and the same
/// owner transaction as the episode row beside it.
///
/// It is a separate table rather than more fields on the episode row because the
/// two rows answer different questions and I8.9 requires their axes to stay
/// independent: the episode row answers "has this exact event already been
/// accepted", and this one answers "which evidence has already been counted, and
/// which intent did it already produce". A single row would make one axis a
/// function of the other. They are written together, in one transaction, so the
/// separation never becomes a window in which one is advanced without the other.
pub(crate) const SIGNAL_PUBLICATION_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_watchdog_spool_signal_publication_v1");

/// Derives the ledger key one episode row is filed under.
///
/// The key is a digest of the core-derived episode key, so the table is keyed by
/// a fixed-width value while the row still stores the full key and re-derives
/// it on every read. The row and its key are two independent records of the same
/// identity and are cross-checked against each other, never one recomputed from
/// the other in place of a stored value.
pub(crate) fn episode_ledger_key(episode_key: &str) -> String {
    sha256_hex(episode_key.as_bytes())
}

/// Reads and validates one stored episode row from a caller's already-open
/// table.
///
/// The parameter is the episode table itself, not a database or a transaction.
/// `open_table` is an inherent method of redb's concrete transaction types
/// rather than a trait method, so no single trait bound can carry it across
/// both a read transaction and a write transaction; the opened table is the one
/// thing those two do share, and it is the same idiom the rest of this spool
/// already uses on its read paths (see `codec::read_high_water`).
///
/// A missing row reports `None` for an episode this owner has never accepted
/// anything under; a present row is decoded strictly and validated, including
/// the cross-check that the episode key it recorded is the key its own ledger
/// row is filed under. A row that fails any of that fails closed: an unreadable
/// episode must never be treated as a fresh one, or a restart would re-admit
/// every already-accepted event as new evidence.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the stored row does not decode, is not
/// canonical, or does not match the ledger key it was read under, and
/// [`SpoolError::Database`] when the table cannot be read.
pub(crate) fn read_episode<T>(
    table: &T,
    ledger_key: &str,
) -> Result<Option<StoredSignalEpisode>, SpoolError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let Some(value) = table
        .get(ledger_key)
        .map_err(|error| SpoolError::Database(error.to_string()))?
    else {
        return Ok(None);
    };
    let episode: StoredSignalEpisode = serde_json::from_slice(value.value()).map_err(|error| {
        SpoolError::Corrupt(format!("watchdog signal episode row is invalid: {error}"))
    })?;
    episode.validate()?;
    if episode_ledger_key(&episode.episode_key) != ledger_key {
        return Err(SpoolError::Corrupt(
            "watchdog signal episode row does not match the ledger key it is filed under"
                .to_owned(),
        ));
    }
    Ok(Some(episode))
}

/// Persists one validated episode row inside a caller's write transaction.
///
/// It never opens a transaction of its own, so a caller can commit the accepted
/// record, this row, and the spool's own high-water update as one atomic change.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the row is not canonical, and
/// [`SpoolError::Database`] or [`SpoolError::Serialization`] when the row cannot
/// be written.
pub(crate) fn write_episode(
    write: &WriteTransaction,
    ledger_key: &str,
    episode: &StoredSignalEpisode,
) -> Result<(), SpoolError> {
    episode.validate()?;
    let bytes = serde_json::to_vec(episode)
        .map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let mut table = write
        .open_table(SIGNAL_EPISODE_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    table
        .insert(ledger_key, bytes.as_slice())
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(table);
    Ok(())
}

/// Reads and validates one stored publication row from a caller's already-open
/// publication table.
///
/// Same shape and same reason as [`read_episode`]: the table is opened by the
/// caller inside whichever transaction it already holds, and a missing row
/// reports `None` for an episode that has published nothing. A present row is
/// decoded strictly and validated against the ledger key it was read under, so
/// a row that fails any of that fails closed — an unreadable publication state
/// must never be treated as a fresh one, or a restart would republish a crossing
/// the episode already published.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the stored row does not decode, is not
/// canonical, or does not match the ledger key it was read under, and
/// [`SpoolError::Database`] when the table cannot be read.
pub(crate) fn read_publication_state<T>(
    table: &T,
    ledger_key: &str,
) -> Result<Option<super::publication::PublicationState>, SpoolError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let Some(value) = table
        .get(ledger_key)
        .map_err(|error| SpoolError::Database(error.to_string()))?
    else {
        return Ok(None);
    };
    let state: super::publication::PublicationState = serde_json::from_slice(value.value())
        .map_err(|error| {
            SpoolError::Corrupt(format!(
                "watchdog publication state row is invalid: {error}"
            ))
        })?;
    state.validate(ledger_key)?;
    Ok(Some(state))
}

/// Persists one validated publication row inside a caller's write transaction.
///
/// It never opens a transaction of its own, so the caller can commit the
/// appended publication record, this row, the advanced episode row and the
/// spool's own high-water update as one atomic change.
///
/// # Errors
///
/// Returns [`SpoolError::Corrupt`] when the row is not canonical, and
/// [`SpoolError::Database`] or [`SpoolError::Serialization`] when the row cannot
/// be written.
pub(crate) fn write_publication_state(
    write: &WriteTransaction,
    ledger_key: &str,
    state: &super::publication::PublicationState,
) -> Result<(), SpoolError> {
    state.validate(ledger_key)?;
    let bytes =
        serde_json::to_vec(state).map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let mut table = write
        .open_table(SIGNAL_PUBLICATION_TABLE)
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    table
        .insert(ledger_key, bytes.as_slice())
        .map_err(|error| SpoolError::Database(error.to_string()))?;
    drop(table);
    Ok(())
}

/// Returns every stored episode ledger key, for the bounded closer.
///
/// Read-only, and over the caller's already-open episode table for the same
/// reason as [`read_episode`]. The caller bounds how many it closes, so a spool
/// with a large episode history cannot make one admission unbounded.
///
/// # Errors
///
/// Returns [`SpoolError::Database`] when the table cannot be read.
pub(crate) fn stored_episode_keys<T>(table: &T) -> Result<Vec<String>, SpoolError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    let mut keys = Vec::new();
    for item in table
        .iter()
        .map_err(|error| SpoolError::Database(error.to_string()))?
    {
        let (key, _value) = item.map_err(|error| SpoolError::Database(error.to_string()))?;
        keys.push(key.value().to_owned());
    }
    Ok(keys)
}
