//! Deterministic failure-episode derivation and source-event admission.
//!
//! I8.3 requires the loop to `deduplicate/update Signal` before anything
//! downstream sees it, and I8.9 names `dedup_key` and `reopen_condition` as two
//! separate Signal fields. This module owns both, as pure derivations: it reads
//! no clock, opens no file, mutates nothing, and returns the same value for the
//! same inputs on every process and every restart.
//!
//! The episode key is derived from four owner-issued facts and nothing else:
//! the rule identity with its immutable revision, the exact observed scope, the
//! **actual** observed subject with its generation, and the discriminating
//! failure class. Every input is a typed field an owner already validated, so
//! no cwd string, no filesystem path, and no hook text can reach the key — an
//! observation whose subject identity was never issued by an owner has no way
//! to produce one.
//!
//! The **source event identity is deliberately not part of the episode key**.
//! It is tracked separately, as a per-episode list of `(event id, payload
//! digest)` pairs. That separation is the whole mechanism:
//!
//! * a retransmitted event — same identity, same digest — is inert. It does not
//!   increase the independent occurrence count and it does not refresh the
//!   episode's evidence time, so repeated delivery of one observation cannot
//!   amplify incident pressure or make a stale failure look fresh.
//! * a genuinely new event appends evidence and does advance both.
//! * the same event identity carrying a **different** payload digest is a
//!   conflict. It is refused, never silently overwritten, and it never opens a
//!   second episode: two different payloads cannot both be the truth of one
//!   event identity.
//!
//! Admission is a pure function of already-retained bounded state, so
//! recognising a retransmission can never grow what the owner keeps.

use crate::rules::encode_identity;
use crate::signals::{
    ReopenCondition, RuleRevision, SignalTarget, SignalValidationError, positive, text,
};

/// Closed set of discriminating failure classes a failure episode can key on.
///
/// The class is the axis that separates two otherwise identical subjects: the
/// same scope, subject, generation and rule revision observed under two
/// different classes are two different episodes, never one merged episode. It
/// is a closed enum rather than free text so a caller cannot invent a class, and
/// every variant names an observed failure class rather than a conclusion about
/// who or what caused it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureClass {
    /// The owner-issued admission path reported that no supervision authority
    /// could be obtained, without yet classifying why.
    GovernorAdmissionUnavailable,
    /// A signed supervision lease was rejected as outside its validity window.
    SupervisionLeaseStale,
    /// A signed supervision lease was rejected as fenced by a newer generation.
    SupervisionLeaseFenced,
    /// A signed supervision lease was rejected as structurally unusable.
    SupervisionLeaseInvalid,
    /// The approved Host service was observed absent or stopped.
    HostAbsentOrStopped,
    /// The approved Host service identity was observed with a reused process id.
    HostPidReused,
    /// The approved Host service identity was observed running a substituted
    /// image.
    HostImageSubstituted,
    /// The approved Host service identity was observed to have changed.
    HostIdentityChanged,
    /// The approved Host service could not be observed and the reason was not
    /// classified. This class states the coverage limitation, never a healthy
    /// verdict.
    HostUnknown,
    /// A provider host-event sequence skip was proved by its own owner inside
    /// one provider attempt.
    ProviderHostEventSequenceGap,
}

impl FailureClass {
    /// Returns the stable code recorded for this class.
    ///
    /// The code is a closed constant per variant, so it is stable across
    /// processes and can be stored, compared, and read back as a stable label.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::GovernorAdmissionUnavailable => "GOVERNOR_ADMISSION_UNAVAILABLE",
            Self::SupervisionLeaseStale => "SUPERVISION_LEASE_STALE",
            Self::SupervisionLeaseFenced => "SUPERVISION_LEASE_FENCED",
            Self::SupervisionLeaseInvalid => "SUPERVISION_LEASE_INVALID",
            Self::HostAbsentOrStopped => "HOST_ABSENT_OR_STOPPED",
            Self::HostPidReused => "HOST_PID_REUSED",
            Self::HostImageSubstituted => "HOST_IMAGE_SUBSTITUTED",
            Self::HostIdentityChanged => "HOST_IDENTITY_CHANGED",
            Self::HostUnknown => "HOST_UNKNOWN",
            Self::ProviderHostEventSequenceGap => "PROVIDER_HOST_EVENT_SEQUENCE_GAP",
        }
    }

    /// Reads one class back from its stored code.
    ///
    /// A stored row whose class is not one of these exact codes is refused
    /// rather than mapped to a default, so a durable episode can never be read
    /// under a class it was not written with.
    ///
    /// # Errors
    ///
    /// Returns [`SignalValidationError::InvalidText`] when `code` names no
    /// class in this closed set.
    pub const fn from_code(code: &str) -> Result<Self, SignalValidationError> {
        match code.as_bytes() {
            b"GOVERNOR_ADMISSION_UNAVAILABLE" => Ok(Self::GovernorAdmissionUnavailable),
            b"SUPERVISION_LEASE_STALE" => Ok(Self::SupervisionLeaseStale),
            b"SUPERVISION_LEASE_FENCED" => Ok(Self::SupervisionLeaseFenced),
            b"SUPERVISION_LEASE_INVALID" => Ok(Self::SupervisionLeaseInvalid),
            b"HOST_ABSENT_OR_STOPPED" => Ok(Self::HostAbsentOrStopped),
            b"HOST_PID_REUSED" => Ok(Self::HostPidReused),
            b"HOST_IMAGE_SUBSTITUTED" => Ok(Self::HostImageSubstituted),
            b"HOST_IDENTITY_CHANGED" => Ok(Self::HostIdentityChanged),
            b"HOST_UNKNOWN" => Ok(Self::HostUnknown),
            b"PROVIDER_HOST_EVENT_SEQUENCE_GAP" => Ok(Self::ProviderHostEventSequenceGap),
            _ => Err(SignalValidationError::InvalidText("failure_class")),
        }
    }
}

/// The owner-issued facts a failure-episode key is derived from.
///
/// Nothing else contributes. In particular the source event identity and its
/// payload digest are absent by construction, which is what keeps one
/// retransmitted event from opening a second episode while a genuinely new
/// event under the same episode still appends evidence to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureEpisodeIdentity {
    /// Rule identity and immutable revision that observed the failure.
    pub rule: RuleRevision,
    /// Exact observed scope, subject and generation.
    pub target: SignalTarget,
    /// Discriminating failure class within that scope, subject and generation.
    pub failure_class: FailureClass,
}

impl FailureEpisodeIdentity {
    /// Fails closed on an identity no owner could have issued.
    ///
    /// # Errors
    ///
    /// Returns [`SignalValidationError`] when the rule identity is blank or
    /// carries control characters, the rule revision is zero, the scope or
    /// subject identity is blank or carries control characters, or the observed
    /// generation is zero.
    pub fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.rule.rule_id, "rule_id")?;
        positive(self.rule.revision, "rule_revision")?;
        text(&self.target.subject_id, "subject_id")?;
        text(&self.target.scope_id, "scope_id")?;
        positive(self.target.generation, "generation")
    }
}

/// Stable key identifying one failure episode across every revision of it.
///
/// The value is derived only from a [`FailureEpisodeIdentity`], so the same
/// owner-issued facts always name the same episode, on every process and after
/// every restart, and two different subjects, generations, rule revisions or
/// failure classes can never derive the same key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureEpisodeKey(String);

impl FailureEpisodeKey {
    /// Derives the episode key from owner-issued facts alone.
    ///
    /// The encoding is the crate's length-prefixed injective identity encoding,
    /// so no two different field lists can produce the same key.
    ///
    /// # Errors
    ///
    /// Returns [`SignalValidationError`] when the identity fails
    /// [`FailureEpisodeIdentity::validate`].
    pub fn derive(identity: &FailureEpisodeIdentity) -> Result<Self, SignalValidationError> {
        identity.validate()?;
        Ok(Self(encode_identity(&[
            identity.rule.rule_id.clone(),
            identity.rule.revision.to_string(),
            identity.target.scope_id.clone(),
            identity.target.subject_id.clone(),
            identity.target.generation.to_string(),
            identity.failure_class.code().to_owned(),
        ])))
    }

    /// Returns the derived key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One source event identity this episode has already accepted, beside the
/// payload digest that was recorded with it.
///
/// The two are stored and compared separately and neither stands in for the
/// other: the identity says *which* event was observed, the digest says *what*
/// was observed about it. A retransmission matches on both; a changed payload
/// matches on the first and conflicts on the second.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedSourceEvent {
    /// Stable source event identity issued by the observation's owner.
    pub event_id: String,
    /// Payload digest recorded for that identity by the same owner.
    pub payload_digest: String,
}

impl AcceptedSourceEvent {
    /// Binds one source event identity to its recorded payload digest.
    ///
    /// # Errors
    ///
    /// Returns [`SignalValidationError`] when either value is blank or carries
    /// control characters. A blank identity is refused rather than stored,
    /// because an empty identity would match every other blank identity and
    /// could collapse distinct events into one.
    pub fn new(event_id: String, payload_digest: String) -> Result<Self, SignalValidationError> {
        text(&event_id, "source_event_id")?;
        text(&payload_digest, "source_event_payload_digest")?;
        Ok(Self {
            event_id,
            payload_digest,
        })
    }
}

/// What admitting one source event against an episode's retained index means.
///
/// Exactly one of these holds for any presented event; there is no fourth case
/// and no default, so an unrecognised presentation cannot fall through as
/// acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceEventAdmission {
    /// This exact identity and payload has not been accepted by this episode
    /// yet. It is a new independent occurrence: evidence may be appended, the
    /// occurrence count advances, and the episode's evidence time advances to
    /// this observation.
    NewEvidence {
        /// Source event identities the episode had already accepted, which is
        /// the independent occurrence count the owner held before this one.
        accepted_source_events: usize,
    },
    /// This exact identity was already accepted with this exact payload digest.
    /// It is a retransmission: it advances nothing, refreshes no evidence time,
    /// and the caller reuses the revision the episode already accepted.
    Retransmission {
        /// Source event identities the episode holds, reported unchanged.
        accepted_source_events: usize,
    },
    /// This exact identity was already accepted with a **different** payload
    /// digest. Changed content under a known event identity is refused: it is
    /// never a silent overwrite of the recorded digest and never a new episode.
    ConflictingPayload {
        /// The payload digest the episode already recorded for this identity.
        recorded_payload_digest: String,
    },
}

impl SourceEventAdmission {
    /// True only for a genuinely new source event identity.
    ///
    /// This is the single question a threshold decision must ask: only a new
    /// event may add independent pressure, and a retransmission can never
    /// answer yes.
    #[must_use]
    pub const fn is_new_evidence(&self) -> bool {
        matches!(self, Self::NewEvidence { .. })
    }
}

/// Classifies one presented source event against an episode's retained index.
///
/// The index is the episode's own bounded accepted list; this function never
/// extends it. Comparison is on the exact identity, and a match then has to
/// agree on the exact payload digest, so neither a retransmission nor a changed
/// payload can be decided by shape alone.
///
/// # Errors
///
/// Returns [`SignalValidationError`] when the presented event carries a blank
/// or control-charactered identity or digest, or when the retained index
/// repeats one identity with two different digests — a state no accepted
/// sequence can produce and one that is therefore never repaired here.
pub fn classify_source_event(
    accepted: &[AcceptedSourceEvent],
    presented: &AcceptedSourceEvent,
) -> Result<SourceEventAdmission, SignalValidationError> {
    text(&presented.event_id, "source_event_id")?;
    text(&presented.payload_digest, "source_event_payload_digest")?;
    for event in accepted {
        text(&event.event_id, "source_event_id")?;
        text(&event.payload_digest, "source_event_payload_digest")?;
    }
    let mut known: Option<&AcceptedSourceEvent> = None;
    for event in accepted {
        if event.event_id != presented.event_id {
            continue;
        }
        match known {
            Some(previous) if previous.payload_digest != event.payload_digest => {
                return Err(SignalValidationError::InvalidText(
                    "source_event_identity_conflict",
                ));
            }
            Some(_) => {}
            None => known = Some(event),
        }
    }
    Ok(match known {
        None => SourceEventAdmission::NewEvidence {
            accepted_source_events: accepted.len(),
        },
        Some(event) if event.payload_digest == presented.payload_digest => {
            SourceEventAdmission::Retransmission {
                accepted_source_events: accepted.len(),
            }
        }
        Some(event) => SourceEventAdmission::ConflictingPayload {
            recorded_payload_digest: event.payload_digest.clone(),
        },
    })
}

/// Whether an admitted source event may reopen a closed episode under `condition`.
///
/// The stored [`ReopenCondition`] is the only thing that decides this, and it
/// can only ever *refuse*: a condition that names no decidable observation
/// (an explicit prose condition, or a recorded historical limitation) never
/// reopens, because reopening a Signal on an undecidable condition would
/// manufacture recurrence out of missing history.
#[must_use]
pub fn reopen_permitted(condition: &ReopenCondition, admission: &SourceEventAdmission) -> bool {
    match condition {
        ReopenCondition::RecurrenceWithNewSourceEvent | ReopenCondition::NewEvidence => {
            admission.is_new_evidence()
        }
        ReopenCondition::ExpectedContextChanged
        | ReopenCondition::Explicit { .. }
        | ReopenCondition::Unknown { .. } => false,
    }
}
