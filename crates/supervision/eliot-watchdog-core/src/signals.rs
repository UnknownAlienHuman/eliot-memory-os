//! Immutable, side-effect-free Watchdog signal revisions.
//!
//! A signal is an observation record. Expected context and authority revisions
//! describe what the observer saw; they do not authorize the signal or actions
//! based on it. A reported resolution is likewise not authenticated here.

/// A stable identity shared by every revision of one signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalId(pub String);

/// One immutable snapshot of a Watchdog signal.
///
/// Fields are public for construction and inspection, but [`Signal`] exposes
/// its stored revision only through a shared reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalRevision {
    /// Stable identity shared across revisions.
    pub signal_id: SignalId,
    /// Positive monotonic revision within this signal identity.
    pub revision: u64,
    /// Rule identity and immutable revision that produced the signal.
    pub rule: RuleRevision,
    /// Profile identity and immutable revision applied by the observer.
    pub profile: ProfileRevision,
    /// Severity assigned by deterministic supervision.
    pub severity: SignalSeverity,
    /// Exact subject, scope and generation observed.
    pub target: SignalTarget,
    /// Observation timestamp and its clock domain.
    pub observed_at: RecordedValue<ObservedTime>,
    /// Source-event identity and payload digest; neither stands in for the other.
    pub source_events: SignalReferences<SourceEventRef>,
    /// Supporting evidence references, or an explicit historical limitation.
    pub evidence: SignalReferences<EvidenceRef>,
    /// Coverage references, or an explicit historical limitation.
    pub coverage: SignalReferences<CoverageRef>,
    /// Observer attribution with confidence independent from severity.
    pub attribution: SignalAttribution,
    /// Processing axis.
    pub processing: SignalProcessing,
    /// Delivery axis; acknowledgement remains a separate fact.
    pub delivery: SignalDelivery,
    /// Disposition of the observation; this does not declare canonical state.
    pub disposition: SignalDisposition,
    /// Acknowledgement fact, separate from delivery and resolution.
    pub acknowledgement: AcknowledgementFact,
    /// Resolution observation, separate from acknowledgement.
    pub resolution: ResolutionFact,
    /// Stable key used to correlate duplicate observations.
    pub dedup_key: RecordedValue<String>,
    /// Condition under which a later observation may reopen this signal.
    pub reopen_condition: ReopenCondition,
    /// Expected context revision seen by the observer, not an authority grant.
    pub expected_context_revision: ExpectedRevision,
    /// Expected authority revision seen by the observer, not an authority grant.
    pub expected_authority_revision: ExpectedRevision,
}

/// A signal whose current immutable revision cannot be mutated in place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signal {
    revision: SignalRevision,
}

impl Signal {
    /// Validates and captures a complete immutable signal revision.
    pub fn new(revision: SignalRevision) -> Result<Self, SignalValidationError> {
        revision.validate()?;
        Ok(Self { revision })
    }

    /// Creates the next immutable revision while preserving signal identity.
    pub fn next_revision(&self, revision: SignalRevision) -> Result<Self, SignalValidationError> {
        if revision.signal_id != self.revision.signal_id {
            return Err(SignalValidationError::IdentityChanged);
        }
        let expected = self
            .revision
            .revision
            .checked_add(1)
            .ok_or(SignalValidationError::RevisionOverflow)?;
        if revision.revision != expected {
            return Err(SignalValidationError::UnexpectedRevision {
                expected,
                actual: revision.revision,
            });
        }
        Self::new(revision)
    }

    /// Returns the full immutable payload by shared reference.
    #[must_use]
    pub const fn revision(&self) -> &SignalRevision {
        &self.revision
    }
}

impl SignalRevision {
    fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.signal_id.0, "signal_id")?;
        positive(self.revision, "signal_revision")?;
        self.rule.validate()?;
        self.profile.validate()?;
        self.target.validate()?;
        self.observed_at.validate_with(ObservedTime::validate)?;
        self.source_events.validate_with(SourceEventRef::validate)?;
        self.evidence
            .validate_with(|reference| text(&reference.evidence_id, "evidence_id"))?;
        self.coverage
            .validate_with(|reference| text(&reference.coverage_id, "coverage_id"))?;
        self.attribution.validate()?;
        self.processing.validate()?;
        self.delivery.validate()?;
        self.disposition.validate()?;
        self.acknowledgement.validate()?;
        self.resolution.validate()?;
        self.dedup_key.validate_text("dedup_key")?;
        self.reopen_condition.validate()?;
        self.expected_context_revision
            .validate("expected_context_revision")?;
        self.expected_authority_revision
            .validate("expected_authority_revision")
    }
}

/// Rule identity plus the immutable revision used by an observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleRevision {
    /// Stable rule identity.
    pub rule_id: String,
    /// Positive immutable rule revision.
    pub revision: u64,
}

impl RuleRevision {
    fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.rule_id, "rule_id")?;
        positive(self.revision, "rule_revision")
    }
}

/// Profile identity plus the immutable revision applied by the observer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRevision {
    /// Stable profile identity.
    pub profile_id: String,
    /// Positive immutable profile revision.
    pub revision: u64,
}

impl ProfileRevision {
    fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.profile_id, "profile_id")?;
        positive(self.revision, "profile_revision")
    }
}

/// Severity is independent from attribution and lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalSeverity {
    Info,
    Warning,
    Blocking,
    IncidentCandidate,
}

/// Exact observed subject, scope and generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalTarget {
    /// Stable observed subject identity.
    pub subject_id: String,
    /// Exact observed scope identity.
    pub scope_id: String,
    /// Positive generation of the observed subject in this scope.
    pub generation: u64,
}

impl SignalTarget {
    fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.subject_id, "subject_id")?;
        text(&self.scope_id, "scope_id")?;
        positive(self.generation, "generation")
    }
}

/// Clock domain describing what the observation ticks mean.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClockDomain {
    /// Unix time measured from the UTC epoch.
    UnixUtc,
    /// Monotonic time scoped to a named clock instance.
    Monotonic { clock_id: String },
    /// Historical clock domain was not recorded; the limitation is explicit.
    Unknown { limitation: String },
}

/// Unit used by an [`ObservedTime`] tick value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeUnit {
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
}

/// Timestamp ticks paired with the clock domain that produced them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTime {
    /// Timestamp value in `unit`.
    pub ticks: u64,
    /// Unit for `ticks`.
    pub unit: TimeUnit,
    /// Clock that produced `ticks`.
    pub domain: ClockDomain,
}

impl ObservedTime {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match &self.domain {
            ClockDomain::UnixUtc => Ok(()),
            ClockDomain::Monotonic { clock_id } => text(clock_id, "clock_id"),
            ClockDomain::Unknown { limitation } => text(limitation, "clock_limitation"),
        }
    }
}

/// Source event identity and its separately recorded payload digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEventRef {
    /// Stable source event identity.
    pub event_id: String,
    /// Payload digest, or an explicit historical limitation.
    pub payload_digest: RecordedValue<String>,
}

impl SourceEventRef {
    fn validate(&self) -> Result<(), SignalValidationError> {
        text(&self.event_id, "source_event_id")?;
        self.payload_digest.validate_text("payload_digest")
    }
}

/// Evidence artifact reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRef {
    /// Stable evidence identity.
    pub evidence_id: String,
}

/// Coverage profile or interval reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRef {
    /// Stable coverage record identity.
    pub coverage_id: String,
}

/// A recorded value or an explicit limitation for unavailable history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedValue<T> {
    Known(T),
    Unknown { limitation: String },
}

impl<T> RecordedValue<T> {
    fn validate_with(
        &self,
        validate: impl FnOnce(&T) -> Result<(), SignalValidationError>,
    ) -> Result<(), SignalValidationError> {
        match self {
            Self::Known(value) => validate(value),
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
        }
    }
}

impl<T: AsRef<str>> RecordedValue<T> {
    fn validate_text(&self, field: &'static str) -> Result<(), SignalValidationError> {
        self.validate_with(|value| text(value.as_ref(), field))
    }
}

/// References whose historical availability is explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalReferences<T> {
    /// This set is known; an empty vector means known to have no references.
    Known(Vec<T>),
    /// References are unavailable in the historical record for this reason.
    Unknown { limitation: String },
}

impl<T> SignalReferences<T> {
    fn validate_with(
        &self,
        mut validate: impl FnMut(&T) -> Result<(), SignalValidationError>,
    ) -> Result<(), SignalValidationError> {
        match self {
            Self::Known(values) => values.iter().try_for_each(&mut validate),
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
        }
    }
}

/// Observer attribution and confidence, independent from severity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalAttribution {
    Known { principal_id: String },
    Suspected { principal_id: String },
    Unknown { limitation: String },
}

impl SignalAttribution {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Known { principal_id } | Self::Suspected { principal_id } => {
                text(principal_id, "attribution.principal_id")
            }
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
        }
    }
}

/// Independent processing axis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalProcessing {
    Observed,
    Triaged,
    Investigating,
    Escalated,
    Closed,
    Unknown { limitation: String },
}

impl SignalProcessing {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            _ => Ok(()),
        }
    }
}

/// Independent delivery axis; acknowledgement is recorded separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalDelivery {
    Pending,
    Delivered,
    Failed { reason: String },
    Unknown { limitation: String },
}

impl SignalDelivery {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Failed { reason } => text(reason, "delivery.reason"),
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            _ => Ok(()),
        }
    }
}

/// Disposition of an observation; it does not declare canonical state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalDisposition {
    Informational,
    ProblemCandidate,
    IncidentCandidate,
    Superseded { by_signal: SignalId },
    Unknown { limitation: String },
}

impl SignalDisposition {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            Self::Superseded { by_signal } => text(&by_signal.0, "superseding_signal_id"),
            Self::Informational | Self::ProblemCandidate | Self::IncidentCandidate => Ok(()),
        }
    }
}

/// Acknowledgement as a fact separate from delivery and resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcknowledgementFact {
    NotAcknowledged,
    Acknowledged { at: ObservedTime, by: String },
    Unknown { limitation: String },
}

impl AcknowledgementFact {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Acknowledged { at, by } => {
                at.validate()?;
                text(by, "acknowledgement.by")
            }
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            Self::NotAcknowledged => Ok(()),
        }
    }
}

/// Resolution observation separate from acknowledgement and without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionFact {
    Unresolved,
    /// A source reported resolution; this contract does not authenticate it.
    Reported {
        at: ObservedTime,
        evidence: SignalReferences<EvidenceRef>,
    },
    Unknown {
        limitation: String,
    },
}

impl ResolutionFact {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Reported { at, evidence } => {
                at.validate()?;
                evidence.validate_with(|reference| text(&reference.evidence_id, "evidence_id"))
            }
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            Self::Unresolved => Ok(()),
        }
    }
}

/// Condition under which a later observation may reopen a signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReopenCondition {
    NewEvidence,
    RecurrenceWithNewSourceEvent,
    ExpectedContextChanged,
    Explicit { condition: String },
    Unknown { limitation: String },
}

impl ReopenCondition {
    fn validate(&self) -> Result<(), SignalValidationError> {
        match self {
            Self::Explicit { condition } => text(condition, "reopen_condition"),
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
            Self::NewEvidence
            | Self::RecurrenceWithNewSourceEvent
            | Self::ExpectedContextChanged => Ok(()),
        }
    }
}

/// Expected surrounding revision observed by the producer, not an authority grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedRevision {
    Known { owner_id: String, revision: u64 },
    Unknown { limitation: String },
}

impl ExpectedRevision {
    fn validate(&self, field: &'static str) -> Result<(), SignalValidationError> {
        match self {
            Self::Known { owner_id, revision } => {
                text(owner_id, field)?;
                positive(*revision, field)
            }
            Self::Unknown { limitation } => text(limitation, "historical_limitation"),
        }
    }
}

/// Structural errors found while validating an immutable signal revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignalValidationError {
    EmptyField(&'static str),
    InvalidText(&'static str),
    ZeroValue(&'static str),
    IdentityChanged,
    RevisionOverflow,
    UnexpectedRevision { expected: u64, actual: u64 },
}

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), SignalValidationError> {
    if value.trim().is_empty() {
        return Err(SignalValidationError::EmptyField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(SignalValidationError::InvalidText(field));
    }
    Ok(())
}

pub(crate) fn positive(value: u64, field: &'static str) -> Result<(), SignalValidationError> {
    if value == 0 {
        Err(SignalValidationError::ZeroValue(field))
    } else {
        Ok(())
    }
}
