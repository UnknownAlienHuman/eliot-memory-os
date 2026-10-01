//! Governor-owned runtime integration coverage (I7.16, I7.22, I7.23).
//!
//! Architecture vs implementation:
//! - I7.16 requires an [`IntegrationCoverageProfile`] recording what the exact
//!   concrete host/adapter fingerprint actually exposes and enforces for every
//!   lifecycle/effect event, plus a revision-bearing [`GovernanceProfile`]
//!   derived by the Governor from that coverage, Watchdog supervision evidence
//!   and trace freshness. Lost guarantees revoke dependent authority.
//! - I7.22 keeps discovery (candidate profiles) separate from conformance and
//!   production observation on the exact active fingerprint. Route mismatch
//!   makes results candidate-only and invalidates dependent capability
//!   evidence.
//! - I7.23 binds completeness claims to an explicit denominator: blind
//!   intervals and missing sources yield `PARTIAL`/`UNKNOWN`, never a
//!   self-reported pass.
//!
//! Ownership:
//! - The Governor (via [`GovernorCoverageDerivation`]) is the sole owner of
//!   [`GovernanceProfile`] revisions. Watchdog [`WatchdogEvidence`] is an
//!   input to derivation, never a substitute grade.
//! - Hook observation never mints authority: only `ENFORCED` dispositions on
//!   the pre-action events can authorize enforcement-dependent operations.
//! - Discovery outputs candidate (unverified) profiles only; exact
//!   active-fingerprint production observation is required before claims
//!   become verified.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fail-closed derivation and authorization errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CoverageError {
    #[error("invalid coverage field: {0}")]
    InvalidField(&'static str),
    #[error("profile fingerprint does not match the active fingerprint")]
    FingerprintMismatch,
    #[error("verified claims require exact active-fingerprint production observation")]
    ProductionObservationRequired,
    #[error("candidate profile is not verified for production claims")]
    CandidateNotVerified,
    #[error("duplicate capability: {0}")]
    DuplicateCapability(String),
    #[error("unknown capability: {0}")]
    UnknownCapability(String),
    #[error("capability revoked after coverage loss: {0}")]
    CapabilityRevoked(String),
    #[error("capability binding is stale (revision or fingerprint drift): {0}")]
    StaleCapabilityBinding(String),
    #[error("profile does not authorize this operation: {0}")]
    CapabilityNotAuthorized(String),
}

/// The ten logical lifecycle/effect events of I7.16.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
pub enum LogicalEvent {
    SessionStart,
    UserPromptSubmit,
    SubagentStart,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PreCompact,
    PostCompact,
    SubagentStop,
    #[serde(rename = "Stop/FinishAttempt")]
    #[schemars(rename = "Stop/FinishAttempt")]
    StopFinishAttempt,
}

/// The complete I7.16 logical event set in canonical order.
pub const ALL_EVENTS: [LogicalEvent; 10] = [
    LogicalEvent::SessionStart,
    LogicalEvent::UserPromptSubmit,
    LogicalEvent::SubagentStart,
    LogicalEvent::PreToolUse,
    LogicalEvent::PermissionRequest,
    LogicalEvent::PostToolUse,
    LogicalEvent::PreCompact,
    LogicalEvent::PostCompact,
    LogicalEvent::SubagentStop,
    LogicalEvent::StopFinishAttempt,
];

/// Per-event observation/enforcement axis from I7.16.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventDisposition {
    Enforced,
    Observed,
    ExplicitObserve,
    Unavailable,
}

/// Pre/post-dispatch ordering of one event observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchOrdering {
    PreDispatch,
    PostDispatch,
    Unknown,
}

/// Completeness of one event stream or a whole profile (I7.23 denominator).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventCompleteness {
    Complete,
    Partial,
    Unknown,
    NotApplicable,
}

/// Trace freshness input to Governor derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceFreshness {
    Fresh,
    Stale,
}

/// Exact admission identity retained by the active bridge descriptor.
///
/// This binds only the admitted adapter. It is not proof that the adapter
/// conforms to the native host's lifecycle hooks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterAdmissionIdentity {
    pub descriptor_sha256: String,
    pub profile_id: String,
    pub profile_sha256: String,
    pub executable_sha256: String,
}

/// A source selector echoed by Kernel for bounded ORS observation paging.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSelectors {
    pub after_owner_sequence: u64,
    pub after_event_sequence: u64,
    pub page_limit: u16,
}

/// Exact owner binding returned by the checked ORS observation roster.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationOwner {
    pub owner_namespace: String,
    pub owner_list_sequence: u64,
    pub authority_lineage: String,
    pub principal: String,
    pub producer_id: String,
    pub local_stream: String,
    pub creating_connection: String,
    pub creating_launch_nonce: String,
    pub creating_session_epoch: u64,
    pub revision: u64,
    pub incarnation: u64,
}

/// One checked, independently bounded page of retained bridge stream owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRosterPage {
    pub authority_lineage: String,
    pub principal: String,
    pub owner_cutoff: u64,
    pub owner_total: u64,
    pub owners: Vec<ObservationOwner>,
    pub continuation: Option<u64>,
}

/// Cursor bounds for a retained original event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCursorBounds {
    pub durable_sequence: u64,
    pub observed_sequence: u64,
    pub acked_sequence: u64,
    pub compacted_sequence: u64,
}

/// A source-owned gap row retained with the stream observation page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationGap {
    pub gap_id: String,
    pub stream_id: String,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub reason_ref: String,
    pub staging_connection: String,
    pub recorded_at_ms: u64,
}

/// Original retained ORS event row, including privacy and ingest provenance.
///
/// The Governor preserves these source-issued fields but deliberately does
/// not infer an I7.16 native hook class from generic bridge payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalBridgeEventObservation {
    pub event_id: String,
    pub sequence: u64,
    pub producer_generation: u64,
    pub authority_epoch: String,
    pub envelope_sha256: String,
    pub transport_hash: String,
    pub stored_envelope_bytes: String,
    pub normalized_projection_bytes: String,
    pub staging_connection: String,
    pub staged_at_ms: u64,
    pub phase: String,
    pub redacted: bool,
    pub redaction_reason: String,
    pub redacted_classes: Vec<String>,
    pub redaction_marker: String,
    pub redaction_version: u16,
    pub admitted_source: String,
    pub admitted_scope: String,
    pub admitted_policy_revision: u64,
    pub adapter_version: String,
    pub transformation_version: u16,
    pub requested_route: String,
    pub actual_route: String,
    pub normalization_warnings: Vec<String>,
}

/// One checked page of original source rows and its independent cursor/gap
/// bounds. `records.len()` is not an expected-event denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEventPage {
    pub owner: ObservationOwner,
    pub after_event_sequence: u64,
    pub observed_through_sequence: u64,
    pub cursor: ObservationCursorBounds,
    pub records: Vec<OriginalBridgeEventObservation>,
    pub gaps: Vec<ObservationGap>,
    pub gap_total: u64,
    pub continuation: Option<u64>,
}

/// One owner-bound stream readback as returned by Kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationStreamReadback {
    pub owner: ObservationOwner,
    pub page: ObservationEventPage,
}

/// Continuation cursor returned by the bounded Kernel source query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationContinuation {
    pub after_owner_sequence: u64,
    pub after_event_sequence: u64,
}

/// A bounded original ORS source snapshot, or a source-owned unavailable
/// result. The unavailable form is still an input to Governor degradation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceReadback {
    Available {
        selectors: ObservationSelectors,
        roster: ObservationRosterPage,
        streams: Vec<ObservationStreamReadback>,
        next: Option<ObservationContinuation>,
    },
    Unavailable {
        reason: String,
    },
}

/// Source-owned evidence availability, with an explicit reason when absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceAvailability<T> {
    Available { evidence: T },
    Unavailable { reason: String },
}

/// Authenticated Kernel readback inputs for the Governor's sole live
/// coverage derivation owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorAuthorityObservation {
    pub adapter: Option<AdapterAdmissionIdentity>,
    pub source: SourceReadback,
    pub watchdog: EvidenceAvailability<WatchdogEvidence>,
    pub trace: EvidenceAvailability<TraceFreshness>,
}

/// One event's runtime coverage: disposition, ordering, completeness, proof
/// ceiling, source evidence and gap evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventCoverage {
    pub event: LogicalEvent,
    pub disposition: EventDisposition,
    pub ordering: DispatchOrdering,
    pub completeness: EventCompleteness,
    pub proof_ceiling: String,
    pub source: String,
    pub gaps: Vec<String>,
}

impl EventCoverage {
    /// Validates source, proof ceiling and gap evidence text.
    ///
    /// Gap binding (I7.23): a `PARTIAL` event must name its blind
    /// interval or missing source; a `COMPLETE` event must not carry gap
    /// evidence, otherwise the completeness claim is contradictory.
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.proof_ceiling, "event.proof_ceiling")?;
        validate_text(&self.source, "event.source")?;
        for gap in &self.gaps {
            validate_text(gap, "event.gaps.item")?;
        }
        match self.completeness {
            EventCompleteness::Partial if self.gaps.is_empty() => {
                return Err(CoverageError::InvalidField(
                    "event.gaps.required_when_partial",
                ));
            }
            EventCompleteness::Complete if !self.gaps.is_empty() => {
                return Err(CoverageError::InvalidField(
                    "event.gaps.unexpected_when_complete",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Runtime coverage for one exact host/adapter fingerprint.
///
/// A profile built by discovery is a candidate (`verified == false`). Only
/// [`Self::verify`] against the exact active fingerprint with production
/// observation promotes it to verified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCoverageProfile {
    pub fingerprint: String,
    pub verified: bool,
    pub events: Vec<EventCoverage>,
    pub completeness: EventCompleteness,
    pub proof_ceiling: String,
    pub source: String,
    pub gaps: Vec<String>,
}

impl IntegrationCoverageProfile {
    /// Builds a candidate (unverified) profile from discovery output.
    pub fn candidate(
        fingerprint: impl Into<String>,
        events: Vec<EventCoverage>,
        completeness: EventCompleteness,
        proof_ceiling: impl Into<String>,
        source: impl Into<String>,
        gaps: Vec<String>,
    ) -> Result<Self, CoverageError> {
        let profile = Self {
            fingerprint: fingerprint.into(),
            verified: false,
            events,
            completeness,
            proof_ceiling: proof_ceiling.into(),
            source: source.into(),
            gaps,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Builds an unverified profile from one authenticated Kernel/ORS
    /// observation. The fixed [`ALL_EVENTS`] set is independent of returned
    /// rows. Since the current ORS bridge stream does not prove native
    /// lifecycle classes or an expected-class denominator, every logical
    /// event remains explicitly unavailable with unknown completeness.
    pub fn from_authority_observation(
        observation: &GovernorAuthorityObservation,
        active_fingerprint: impl Into<String>,
    ) -> Result<Self, CoverageError> {
        let fingerprint = active_fingerprint.into();
        validate_text(&fingerprint, "coverage.fingerprint")?;

        let mut profile_gaps = vec![
            "No source-issued native I7.16 event-class manifest or independent expected-event denominator was included in this observation.".to_owned(),
        ];
        let (mut source, source_gaps, source_record_count) = match &observation.source {
            SourceReadback::Unavailable { reason } => {
                validate_text(reason, "observation.source.reason")?;
                (
                    format!("Kernel ORS source readback unavailable: {reason}"),
                    vec![format!("Original event source unavailable: {reason}")],
                    0,
                )
            }
            SourceReadback::Available {
                selectors,
                roster,
                streams,
                next,
            } => {
                validate_roster(roster)?;
                if selectors.page_limit == 0 {
                    return Err(CoverageError::InvalidField(
                        "observation.source.selectors.page_limit",
                    ));
                }
                let mut gaps = Vec::new();
                let mut record_count = 0_usize;
                let mut stream_bounds = Vec::new();
                for stream in streams {
                    if !roster.owners.contains(&stream.owner) {
                        return Err(CoverageError::InvalidField(
                            "observation.source.stream.owner_not_in_roster",
                        ));
                    }
                    if stream.owner != stream.page.owner {
                        return Err(CoverageError::InvalidField(
                            "observation.source.stream.page_owner_mismatch",
                        ));
                    }
                    validate_event_page(&stream.page)?;
                    record_count = record_count.saturating_add(stream.page.records.len());
                    stream_bounds.push(format!(
                        "owner-seq={} stream={} observed-through={} durable={} observed={} acked={} compacted={}",
                        stream.owner.owner_list_sequence,
                        stream.owner.local_stream,
                        stream.page.observed_through_sequence,
                        stream.page.cursor.durable_sequence,
                        stream.page.cursor.observed_sequence,
                        stream.page.cursor.acked_sequence,
                        stream.page.cursor.compacted_sequence,
                    ));
                    for gap in &stream.page.gaps {
                        gaps.push(format!(
                            "ORS retained gap {} on {} at sequences {}..{} ({})",
                            gap.gap_id,
                            gap.stream_id,
                            gap.start_sequence,
                            gap.end_sequence,
                            gap.reason_ref,
                        ));
                    }
                    if u64::try_from(stream.page.gaps.len()).unwrap_or(u64::MAX)
                        < stream.page.gap_total
                    {
                        gaps.push(format!(
                            "ORS reports {} total gaps for {} but this page retains only {}",
                            stream.page.gap_total,
                            stream.owner.local_stream,
                            stream.page.gaps.len(),
                        ));
                    }
                    if stream.page.continuation.is_some() {
                        gaps.push(format!(
                            "ORS event page for {} continues beyond this bounded readback",
                            stream.owner.local_stream,
                        ));
                    }
                }
                if roster.owners.len() < usize::try_from(roster.owner_total).unwrap_or(usize::MAX)
                    || roster.continuation.is_some()
                {
                    gaps.push(format!(
                        "ORS roster page contains {} of {} retained owners",
                        roster.owners.len(),
                        roster.owner_total,
                    ));
                }
                if next.is_some() {
                    gaps.push(
                        "Kernel source snapshot has a bounded continuation beyond this readback."
                            .to_owned(),
                    );
                }
                if streams.is_empty() || record_count == 0 {
                    gaps.push(
                        "No original retained bridge event row was available in this bounded readback."
                            .to_owned(),
                    );
                }
                let source = format!(
                    "Kernel-authenticated ORS readback: {} retained owner rows of {}; {} original event rows; selectors owner={} event={} limit={}; roster cutoff={}; cursor and scoped-gap bounds retained [{}]; adapter admission is ADAPTER identity only.",
                    roster.owners.len(),
                    roster.owner_total,
                    record_count,
                    selectors.after_owner_sequence,
                    selectors.after_event_sequence,
                    selectors.page_limit,
                    roster.owner_cutoff,
                    stream_bounds.join("; "),
                );
                (source, gaps, record_count)
            }
        };
        profile_gaps.extend(source_gaps);
        if let Some(adapter) = &observation.adapter {
            validate_adapter_identity(adapter)?;
            if adapter.descriptor_sha256 != fingerprint {
                return Err(CoverageError::FingerprintMismatch);
            }
            source.push_str(&format!(
                "; admitted adapter tuple descriptor={} profile_id={} profile_sha256={} executable_sha256={}",
                adapter.descriptor_sha256,
                adapter.profile_id,
                adapter.profile_sha256,
                adapter.executable_sha256,
            ));
        } else {
            profile_gaps.push(
                "Current adapter admission is unavailable; the prior Governor fingerprint is retained only for degradation.".to_owned(),
            );
        }
        match &observation.watchdog {
            EvidenceAvailability::Available { evidence } => evidence.validate()?,
            EvidenceAvailability::Unavailable { reason } => {
                validate_text(reason, "observation.watchdog.reason")?;
                profile_gaps.push(format!("Watchdog evidence unavailable: {reason}"));
            }
        }
        match &observation.trace {
            EvidenceAvailability::Available { .. } => {}
            EvidenceAvailability::Unavailable { reason } => {
                validate_text(reason, "observation.trace.reason")?;
                profile_gaps.push(format!("Trace freshness unavailable: {reason}"));
            }
        }

        let events = ALL_EVENTS
            .into_iter()
            .map(|event| EventCoverage {
                event,
                disposition: EventDisposition::Unavailable,
                ordering: DispatchOrdering::Unknown,
                completeness: EventCompleteness::Unknown,
                proof_ceiling: "Original retained ORS envelope, owner, cursor, and gap evidence only; native hook class and pre-action application proof absent.".to_owned(),
                source: format!(
                    "{source} No explicitly typed original native event source was joined for {event:?}.",
                ),
                gaps: vec![format!(
                    "No original retained row is proven to represent the {event:?} native lifecycle/effect event."
                )],
            })
            .collect();

        let profile = Self {
            fingerprint,
            verified: false,
            events,
            completeness: EventCompleteness::Unknown,
            proof_ceiling: format!(
                "Original Kernel/ORS source readback ({source_record_count} rows) only; no verified native-host conformance or independent ALL_EVENTS denominator."
            ),
            source,
            gaps: profile_gaps,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Promotes a candidate to verified after exact active-fingerprint
    /// production observation. Discovery output alone is never sufficient.
    /// The candidate is re-validated so a mutated profile cannot be
    /// promoted with contradictory or missing evidence.
    pub fn verify(
        mut self,
        active_fingerprint: &str,
        production_observed: bool,
    ) -> Result<Self, CoverageError> {
        self.validate()?;
        if self.fingerprint != active_fingerprint {
            return Err(CoverageError::FingerprintMismatch);
        }
        if !production_observed {
            return Err(CoverageError::ProductionObservationRequired);
        }
        self.verified = true;
        Ok(self)
    }

    /// Returns the disposition recorded for one logical event, if present.
    #[must_use]
    pub fn disposition(&self, event: LogicalEvent) -> Option<EventDisposition> {
        self.events
            .iter()
            .find(|coverage| coverage.event == event)
            .map(|coverage| coverage.disposition)
    }

    /// Validates identity, event evidence, gaps and completeness binding.
    ///
    /// Every profile declares all ten [`ALL_EVENTS`] logical events: an
    /// omitted event is rejected rather than treated as unavailable, so a
    /// missing observation/enforcement axis can never be silent (I7.16).
    /// A `COMPLETE` profile additionally requires every event to be
    /// `COMPLETE`; any partial event forces the profile to `PARTIAL` or
    /// worse with gap evidence (I7.23 denominator binding).
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.fingerprint, "coverage.fingerprint")?;
        validate_text(&self.proof_ceiling, "coverage.proof_ceiling")?;
        validate_text(&self.source, "coverage.source")?;
        if self.events.len() > ALL_EVENTS.len() {
            return Err(CoverageError::InvalidField("coverage.events"));
        }
        let mut seen = BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if !seen.insert(event.event) {
                return Err(CoverageError::InvalidField("coverage.events.duplicate"));
            }
        }
        for required in ALL_EVENTS {
            if !seen.contains(&required) {
                return Err(CoverageError::InvalidField("coverage.events.incomplete"));
            }
        }
        if self.completeness == EventCompleteness::Complete
            && self
                .events
                .iter()
                .any(|event| event.completeness != EventCompleteness::Complete)
        {
            return Err(CoverageError::InvalidField("coverage.events.completeness"));
        }
        if self.completeness != EventCompleteness::Complete && self.gaps.is_empty() {
            return Err(CoverageError::InvalidField(
                "coverage.gaps.required_when_incomplete",
            ));
        }
        for gap in &self.gaps {
            validate_text(gap, "coverage.gaps.item")?;
        }
        Ok(())
    }
}

/// Watchdog supervision evidence: an input to Governor derivation, never a
/// substitute grade and never authority by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchdogEvidence {
    pub supervisor_id: String,
    pub fresh: bool,
    pub summary: String,
}

impl WatchdogEvidence {
    /// Validates the supervision evidence binding.
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.supervisor_id, "watchdog.supervisor_id")?;
        validate_text(&self.summary, "watchdog.summary")?;
        Ok(())
    }
}

/// Governor-derived authority vector bound to one profile revision and one
/// exact fingerprint. It is a vector, never a single marketing grade.
///
/// Each boolean names one independent derivation axis (verification,
/// enforcement, completeness, Watchdog freshness, trace freshness), so the
/// excessive-bools lint is allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernanceProfile {
    pub revision: u64,
    pub fingerprint: String,
    pub verified: bool,
    pub authorizes_enforcement: bool,
    pub authorizes_complete_coverage_ops: bool,
    pub completeness: EventCompleteness,
    pub watchdog_fresh: bool,
    pub trace_fresh: bool,
}

impl GovernanceProfile {
    /// Returns whether an operation with the given requirements is authorized
    /// under this revision.
    #[must_use]
    pub const fn authorizes(&self, requires_enforced: bool, requires_complete: bool) -> bool {
        if !self.verified {
            return false;
        }
        if requires_enforced && !self.authorizes_enforcement {
            return false;
        }
        if requires_complete && !self.authorizes_complete_coverage_ops {
            return false;
        }
        true
    }
}

/// A capability bound to the exact profile revision and fingerprint that
/// authorized its issuance.
///
/// The three booleans are independent domain axes (two issuance requirements
/// plus revocation state), not a bool bag, so the excessive-bools lint is
/// allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuedCapability {
    pub capability_id: String,
    pub requires_enforced: bool,
    pub requires_complete: bool,
    pub profile_revision: u64,
    pub fingerprint: String,
    pub revoked: bool,
}

/// The Governor-owned derivation owner: the sole minter of
/// [`GovernanceProfile`] revisions and the sole revoker of capabilities bound
/// to them.
#[derive(Clone, Debug)]
pub struct GovernorCoverageDerivation {
    revision: u64,
    current: Option<GovernanceProfile>,
    capabilities: BTreeMap<String, IssuedCapability>,
    observation_binding: Option<ObservationDerivationBinding>,
}

/// Minimal last-input binding used only for revision idempotency. It records
/// source reasons and bounded coverage gaps, never caches event pages.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservationDerivationBinding {
    fingerprint: String,
    source: String,
    gaps: Vec<String>,
    watchdog: String,
    trace: String,
}

impl GovernorCoverageDerivation {
    /// Creates an empty derivation owner with no current profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0,
            current: None,
            capabilities: BTreeMap::new(),
            observation_binding: None,
        }
    }

    /// Returns the current revision (zero when nothing has been derived).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the current [`GovernanceProfile`], if one has been derived.
    #[must_use]
    pub fn current(&self) -> Option<&GovernanceProfile> {
        self.current.as_ref()
    }

    /// Derives the [`GovernanceProfile`] from runtime coverage, Watchdog evidence
    /// and trace freshness.
    ///
    /// Enforcement is authorized only when the profile is verified, trace and
    /// Watchdog evidence are fresh, and both pre-action events (`PreToolUse`,
    /// `PermissionRequest`) are `ENFORCED`. Observation alone never authorizes
    /// enforcement. An unchanged re-derivation is idempotent and keeps the
    /// current revision; any content change emits a new revision and revokes
    /// every capability the new profile no longer authorizes.
    pub fn derive(
        &mut self,
        coverage: &IntegrationCoverageProfile,
        watchdog: &WatchdogEvidence,
        trace: TraceFreshness,
    ) -> Result<GovernanceProfile, CoverageError> {
        coverage.validate()?;
        watchdog.validate()?;
        if !coverage.verified {
            return Err(CoverageError::CandidateNotVerified);
        }
        let trace_fresh = trace == TraceFreshness::Fresh;
        let pre_action_enforced = matches!(
            coverage.disposition(LogicalEvent::PreToolUse),
            Some(EventDisposition::Enforced)
        ) && matches!(
            coverage.disposition(LogicalEvent::PermissionRequest),
            Some(EventDisposition::Enforced)
        );
        let authorizes_enforcement = pre_action_enforced && watchdog.fresh && trace_fresh;
        let authorizes_complete_coverage_ops =
            coverage.completeness == EventCompleteness::Complete && watchdog.fresh && trace_fresh;
        let candidate = GovernanceProfile {
            revision: self.revision.saturating_add(1).max(1),
            fingerprint: coverage.fingerprint.clone(),
            verified: true,
            authorizes_enforcement,
            authorizes_complete_coverage_ops,
            completeness: coverage.completeness,
            watchdog_fresh: watchdog.fresh,
            trace_fresh,
        };
        if let Some(current) = self.current.as_ref()
            && (GovernanceProfile {
                revision: current.revision,
                ..candidate.clone()
            }) == *current
        {
            return Ok(current.clone());
        }
        self.revision = candidate.revision;
        self.current = Some(candidate.clone());
        self.observation_binding = None;
        self.revoke_unauthorized();
        Ok(candidate)
    }

    /// Derives a profile from source readback even when some source classes,
    /// watchdog evidence, or trace evidence are unavailable. Unknown inputs
    /// produce a new unverified/degraded revision instead of preserving a
    /// formerly healthy profile or fabricating missing evidence.
    pub fn derive_observation(
        &mut self,
        observation: &GovernorAuthorityObservation,
    ) -> Result<Option<GovernanceProfile>, CoverageError> {
        let admitted_adapter = observation
            .adapter
            .as_ref()
            .filter(|adapter| validate_adapter_identity(adapter).is_ok())
            .cloned();
        let fingerprint = admitted_adapter
            .as_ref()
            .map(|adapter| adapter.descriptor_sha256.clone())
            .or_else(|| self.current.as_ref().map(|profile| profile.fingerprint.clone()));
        let Some(fingerprint) = fingerprint else {
            return Ok(None);
        };
        let adapter = admitted_adapter;
        let validated_watchdog = match &observation.watchdog {
            EvidenceAvailability::Available { evidence } if evidence.validate().is_ok() => {
                EvidenceAvailability::Available {
                    evidence: evidence.clone(),
                }
            }
            EvidenceAvailability::Available { .. } => EvidenceAvailability::Unavailable {
                reason: "Kernel watchdog evidence failed Governor validation".to_owned(),
            },
            EvidenceAvailability::Unavailable { reason }
                if validate_optional_text(reason, "observation.watchdog.reason").is_ok()
                    && !reason.trim().is_empty() =>
            {
                EvidenceAvailability::Unavailable {
                    reason: reason.clone(),
                }
            }
            EvidenceAvailability::Unavailable { .. } => EvidenceAvailability::Unavailable {
                reason: "Kernel did not provide a valid watchdog unavailability reason".to_owned(),
            },
        };
        let validated_trace = match &observation.trace {
            EvidenceAvailability::Available { evidence } => EvidenceAvailability::Available {
                evidence: *evidence,
            },
            EvidenceAvailability::Unavailable { reason }
                if validate_optional_text(reason, "observation.trace.reason").is_ok()
                    && !reason.trim().is_empty() =>
            {
                EvidenceAvailability::Unavailable {
                    reason: reason.clone(),
                }
            }
            EvidenceAvailability::Unavailable { .. } => EvidenceAvailability::Unavailable {
                reason: "Kernel did not provide a valid trace unavailability reason".to_owned(),
            },
        };
        let mut validated_observation = GovernorAuthorityObservation {
            adapter,
            source: observation.source.clone(),
            watchdog: validated_watchdog,
            trace: validated_trace,
        };
        let coverage = match IntegrationCoverageProfile::from_authority_observation(
            &validated_observation,
            fingerprint.clone(),
        ) {
            Ok(coverage) => coverage,
            Err(error) => {
                validated_observation.source = SourceReadback::Unavailable {
                    reason: format!(
                        "Governor rejected inconsistent Kernel source evidence: {error}"
                    ),
                };
                validated_observation.watchdog = EvidenceAvailability::Unavailable {
                    reason: "Governor rejected the combined Kernel source observation".to_owned(),
                };
                validated_observation.trace = EvidenceAvailability::Unavailable {
                    reason: "Governor rejected the combined Kernel source observation".to_owned(),
                };
                IntegrationCoverageProfile::from_authority_observation(
                    &validated_observation,
                    fingerprint,
                )?
            }
        };
        let watchdog = match &validated_observation.watchdog {
            EvidenceAvailability::Available { evidence } => {
                format!("available:{}:{}", evidence.supervisor_id, evidence.fresh)
            }
            EvidenceAvailability::Unavailable { reason } => format!("unavailable:{reason}"),
        };
        let trace = match &validated_observation.trace {
            EvidenceAvailability::Available { evidence } => format!("available:{evidence:?}"),
            EvidenceAvailability::Unavailable { reason } => format!("unavailable:{reason}"),
        };
        let binding = ObservationDerivationBinding {
            fingerprint: coverage.fingerprint.clone(),
            source: coverage.source.clone(),
            gaps: coverage.gaps.clone(),
            watchdog,
            trace,
        };
        let watchdog_fresh = matches!(
            &validated_observation.watchdog,
            EvidenceAvailability::Available { evidence } if evidence.fresh
        );
        let trace_fresh = matches!(
            &validated_observation.trace,
            EvidenceAvailability::Available {
                evidence: TraceFreshness::Fresh
            }
        );
        let pre_action_enforced = coverage.verified
            && matches!(
                coverage.disposition(LogicalEvent::PreToolUse),
                Some(EventDisposition::Enforced)
            )
            && matches!(
                coverage.disposition(LogicalEvent::PermissionRequest),
                Some(EventDisposition::Enforced)
            );
        let candidate = GovernanceProfile {
            revision: self.revision.saturating_add(1).max(1),
            fingerprint: coverage.fingerprint.clone(),
            verified: coverage.verified,
            authorizes_enforcement: pre_action_enforced && watchdog_fresh && trace_fresh,
            authorizes_complete_coverage_ops: coverage.verified
                && coverage.completeness == EventCompleteness::Complete
                && watchdog_fresh
                && trace_fresh,
            completeness: coverage.completeness,
            watchdog_fresh,
            trace_fresh,
        };
        if let Some(current) = self.current.as_ref()
            && (GovernanceProfile {
                revision: current.revision,
                ..candidate.clone()
            }) == *current
            && self.observation_binding.as_ref() == Some(&binding)
        {
            return Ok(Some(current.clone()));
        }
        self.revision = candidate.revision;
        self.current = Some(candidate.clone());
        self.observation_binding = Some(binding);
        self.revoke_unauthorized();
        Ok(Some(candidate))
    }

    /// Reports an observed route mismatch: the active route is no longer the
    /// profile fingerprint. Emits a new revision that authorizes nothing and
    /// revokes every capability bound to the lost fingerprint.
    pub fn report_route_mismatch(
        &mut self,
        expected_fingerprint: &str,
        observed_fingerprint: &str,
    ) -> Result<(GovernanceProfile, Vec<String>), CoverageError> {
        validate_text(expected_fingerprint, "route.expected_fingerprint")?;
        validate_text(observed_fingerprint, "route.observed_fingerprint")?;
        if expected_fingerprint == observed_fingerprint {
            return Err(CoverageError::InvalidField("route.no_mismatch"));
        }
        let revision = self.revision.saturating_add(1).max(1);
        let profile = GovernanceProfile {
            revision,
            fingerprint: observed_fingerprint.to_owned(),
            verified: false,
            authorizes_enforcement: false,
            authorizes_complete_coverage_ops: false,
            completeness: EventCompleteness::Unknown,
            watchdog_fresh: false,
            trace_fresh: false,
        };
        self.revision = revision;
        self.current = Some(profile.clone());
        let revoked = self.revoke_all();
        Ok((profile, revoked))
    }

    /// Issues a capability bound to the current profile revision and
    /// fingerprint. Issuance records the dependency; [`Self::authorize`]
    /// enforces it.
    pub fn issue_capability(
        &mut self,
        capability_id: impl Into<String>,
        requires_enforced: bool,
        requires_complete: bool,
    ) -> Result<IssuedCapability, CoverageError> {
        let capability_id = capability_id.into();
        validate_text(&capability_id, "capability.id")?;
        if self.capabilities.contains_key(&capability_id) {
            return Err(CoverageError::DuplicateCapability(capability_id));
        }
        let current = self
            .current
            .as_ref()
            .ok_or(CoverageError::CandidateNotVerified)?;
        let capability = IssuedCapability {
            capability_id: capability_id.clone(),
            requires_enforced,
            requires_complete,
            profile_revision: current.revision,
            fingerprint: current.fingerprint.clone(),
            revoked: false,
        };
        self.capabilities.insert(capability_id, capability.clone());
        Ok(capability)
    }

    /// Authorizes one capability use under the current revision. Fails when
    /// the capability was revoked, its revision/fingerprint binding is stale,
    /// or the current profile no longer authorizes its requirements.
    pub fn authorize(&self, capability_id: &str) -> Result<(), CoverageError> {
        let capability = self
            .capabilities
            .get(capability_id)
            .ok_or_else(|| CoverageError::UnknownCapability(capability_id.to_owned()))?;
        self.authorize_issued(capability)
    }

    /// Authorizes one presented capability against the live derivation.
    ///
    /// Cross-boundary form of [`Self::authorize`]: the capability crossed the
    /// authenticated boundary as bytes (deserialized by the admitting side),
    /// so the check compares its recorded revision/fingerprint binding and
    /// requirements against the current profile instead of resolving a
    /// locally registered id. Fails when the presented binding is revoked,
    /// stale, or no longer authorized — a degraded re-derivation or a route
    /// mismatch therefore revokes the presented authority.
    pub fn authorize_issued(&self, capability: &IssuedCapability) -> Result<(), CoverageError> {
        if capability.revoked {
            return Err(CoverageError::CapabilityRevoked(
                capability.capability_id.clone(),
            ));
        }
        let current = self
            .current
            .as_ref()
            .ok_or(CoverageError::CandidateNotVerified)?;
        if capability.profile_revision != current.revision
            || capability.fingerprint != current.fingerprint
        {
            return Err(CoverageError::StaleCapabilityBinding(
                capability.capability_id.clone(),
            ));
        }
        if !current.authorizes(capability.requires_enforced, capability.requires_complete) {
            return Err(CoverageError::CapabilityNotAuthorized(
                capability.capability_id.clone(),
            ));
        }
        Ok(())
    }

    fn revoke_unauthorized(&mut self) {
        let Some(current) = self.current.as_ref() else {
            return;
        };
        for capability in self.capabilities.values_mut() {
            if capability.revoked {
                continue;
            }
            let binding_current = capability.profile_revision == current.revision
                && capability.fingerprint == current.fingerprint;
            if !binding_current
                || !current.authorizes(capability.requires_enforced, capability.requires_complete)
            {
                capability.revoked = true;
            }
        }
    }

    fn revoke_all(&mut self) -> Vec<String> {
        let mut revoked = Vec::new();
        for capability in self.capabilities.values_mut() {
            if !capability.revoked {
                capability.revoked = true;
                revoked.push(capability.capability_id.clone());
            }
        }
        revoked.sort();
        revoked
    }
}

impl Default for GovernorCoverageDerivation {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CoverageError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoverageError::InvalidField(field));
    }
    Ok(())
}

fn validate_optional_text(value: &str, field: &'static str) -> Result<(), CoverageError> {
    if value.chars().any(char::is_control) {
        return Err(CoverageError::InvalidField(field));
    }
    Ok(())
}

fn validate_adapter_identity(identity: &AdapterAdmissionIdentity) -> Result<(), CoverageError> {
    validate_text(&identity.descriptor_sha256, "adapter.descriptor_sha256")?;
    validate_text(&identity.profile_id, "adapter.profile_id")?;
    validate_text(&identity.profile_sha256, "adapter.profile_sha256")?;
    validate_text(&identity.executable_sha256, "adapter.executable_sha256")?;
    Ok(())
}

fn validate_roster(roster: &ObservationRosterPage) -> Result<(), CoverageError> {
    validate_text(&roster.authority_lineage, "observation.roster.authority_lineage")?;
    validate_text(&roster.principal, "observation.roster.principal")?;
    if roster.owners.len() > usize::try_from(roster.owner_total).unwrap_or(usize::MAX) {
        return Err(CoverageError::InvalidField(
            "observation.roster.owners_exceed_total",
        ));
    }
    let mut seen = BTreeSet::new();
    for owner in &roster.owners {
        validate_owner(owner)?;
        if owner.authority_lineage != roster.authority_lineage
            || owner.principal != roster.principal
            || !seen.insert((owner.owner_list_sequence, owner.owner_namespace.clone()))
        {
            return Err(CoverageError::InvalidField(
                "observation.roster.owner_binding",
            ));
        }
    }
    Ok(())
}

fn validate_owner(owner: &ObservationOwner) -> Result<(), CoverageError> {
    validate_text(&owner.owner_namespace, "observation.owner.namespace")?;
    validate_text(&owner.authority_lineage, "observation.owner.authority_lineage")?;
    validate_text(&owner.principal, "observation.owner.principal")?;
    validate_text(&owner.producer_id, "observation.owner.producer_id")?;
    validate_text(&owner.local_stream, "observation.owner.local_stream")?;
    validate_text(&owner.creating_connection, "observation.owner.creating_connection")?;
    validate_text(
        &owner.creating_launch_nonce,
        "observation.owner.creating_launch_nonce",
    )?;
    Ok(())
}

fn validate_event_page(page: &ObservationEventPage) -> Result<(), CoverageError> {
    if page.cursor.acked_sequence > page.cursor.observed_sequence
        || page.cursor.compacted_sequence > page.cursor.durable_sequence
        || page.observed_through_sequence > page.cursor.observed_sequence
    {
        return Err(CoverageError::InvalidField(
            "observation.stream.cursor_bounds",
        ));
    }
    for gap in &page.gaps {
        validate_text(&gap.gap_id, "observation.gap.id")?;
        validate_text(&gap.stream_id, "observation.gap.stream_id")?;
        validate_text(&gap.reason_ref, "observation.gap.reason_ref")?;
        validate_text(
            &gap.staging_connection,
            "observation.gap.staging_connection",
        )?;
        if gap.start_sequence > gap.end_sequence {
            return Err(CoverageError::InvalidField(
                "observation.gap.sequence_range",
            ));
        }
    }
    if u64::try_from(page.gaps.len()).unwrap_or(u64::MAX) > page.gap_total {
        return Err(CoverageError::InvalidField(
            "observation.gap.count_exceeds_total",
        ));
    }
    for record in &page.records {
        validate_text(&record.event_id, "observation.record.event_id")?;
        validate_text(
            &record.envelope_sha256,
            "observation.record.envelope_sha256",
        )?;
        validate_text(&record.transport_hash, "observation.record.transport_hash")?;
        validate_text(
            &record.staging_connection,
            "observation.record.staging_connection",
        )?;
        validate_text(&record.phase, "observation.record.phase")?;
        validate_optional_text(&record.authority_epoch, "observation.record.authority_epoch")?;
        validate_optional_text(&record.admitted_source, "observation.record.admitted_source")?;
        validate_optional_text(&record.admitted_scope, "observation.record.admitted_scope")?;
        validate_optional_text(&record.adapter_version, "observation.record.adapter_version")?;
        validate_optional_text(
            &record.stored_envelope_bytes,
            "observation.record.stored_envelope_bytes",
        )?;
        validate_optional_text(
            &record.normalized_projection_bytes,
            "observation.record.normalized_projection_bytes",
        )?;
        validate_optional_text(&record.redaction_reason, "observation.record.redaction_reason")?;
        validate_optional_text(&record.redaction_marker, "observation.record.redaction_marker")?;
        for class in &record.redacted_classes {
            validate_optional_text(class, "observation.record.redacted_classes.item")?;
        }
        for warning in &record.normalization_warnings {
            validate_text(warning, "observation.record.normalization_warnings.item")?;
        }
        validate_optional_text(&record.requested_route, "observation.record.requested_route")?;
        validate_optional_text(&record.actual_route, "observation.record.actual_route")?;
    }
    Ok(())
}
