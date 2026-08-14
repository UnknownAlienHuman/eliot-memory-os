//! Pure contracts for observation obligations, plans, records and coverage.
//!
//! This crate does not own a journal, start a sensor, persist an event, or
//! decide a governance/finish outcome.  It only describes the evidence a
//! producer promises to make observable and the typed result of comparing
//! that promise with an observed interval.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{ClockReading, ContractError, ContractIdentity, ContractVersion, StateFence};
use eliot_receipts::WorkScopeId;
use eliot_runtime_contracts::RuntimeContractError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable wire name for this C0-11 contract family.
pub const CONTRACT_NAME: &str = "eliot.foundation.observation-contracts";
/// Current wire revision for this contract family.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// A typed, fail-closed contract validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ObservationError {
    /// A shared C0-01 primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    /// A receipt contract rejected a shared binding.
    #[error("receipt contract: {0}")]
    Receipt(#[from] eliot_receipts::ReceiptError),
    /// A runtime contract rejected a shared fence or state.
    #[error("runtime contract: {0}")]
    Runtime(#[from] RuntimeContractError),
    /// A required field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// A cursor or time interval is reversed.
    #[error("{field} interval is reversed")]
    InvalidInterval { field: &'static str },
    /// A set that is required to be unique contains a duplicate.
    #[error("{field} contains duplicate value {value}")]
    Duplicate { field: &'static str, value: String },
    /// A coverage result cannot claim completeness for its inputs.
    #[error("coverage is incomplete: {reason}")]
    CoverageIncomplete { reason: &'static str },
    /// An ordinary record attempted to observe journal self-admission.
    #[error("ordinary observation records cannot recursively observe journal admission")]
    NonRecursiveViolation,
}

fn text(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.trim().is_empty() {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn unique(values: &[String], field: &'static str) -> Result<(), ObservationError> {
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(ObservationError::Duplicate {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn validate_clock(clock: &ClockReading, field: &'static str) -> Result<(), ObservationError> {
    clock
        .validate()
        .map_err(ObservationError::from)
        .map_err(|error| match error {
            ObservationError::Foundation(ContractError::InvalidInterval { .. }) => {
                ObservationError::InvalidInterval { field }
            }
            other => other,
        })
}

/// Event classes named by the Runtime observation contract.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    AgentFeedback,
    ContextPacket,
    MemoryDelivery,
    ToolOrRoute,
    TaskProgress,
    LoopOrNoProgress,
    FailureOrRepair,
    QueueResource,
    Configuration,
    Maintenance,
    Security,
    ProductOutcome,
    UserCorrection,
}

/// Minimum route that may carry an observation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureRoute {
    CanonicalJournal,
    WatchdogSpool,
    OrsOutbox,
    OperationalLog,
    BlobHandle,
}

/// Minimum durability promised by an obligation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Durability {
    Volatile,
    BoundedOutbox,
    Durable,
    Protected,
}

/// How a producer may reduce high-rate volume while retaining coverage.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureMode {
    Full,
    Sampled,
    OnProblem,
    DisabledWithGap,
}

/// Lifecycle of a known source interval.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageDisposition {
    Complete,
    Partial,
    IncompleteCoverage,
    Unavailable,
    Unknown,
    Blind,
    JournalReplayed,
}

/// Governance consequence declared by a producer when an obligation fails.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GapDisposition {
    Continue,
    DegradeDependentGuarantees,
    BlockDependentTransition,
    Escalate,
}

/// The record family represented by a normalized observation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationRecordKind {
    Audit,
    Telemetry,
    Change,
    Maintenance,
    CoverageGap,
}

/// Producer capability and exact generation bound to an obligation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerGenerationRef {
    /// Stable capability identity.
    pub capability: String,
    /// Generation identity observed at registration.
    pub generation: String,
}

impl ProducerGenerationRef {
    /// Validates the capability/generation binding.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.capability, "capability")?;
        text(&self.generation, "generation")
    }
}

/// Source used to derive an expected denominator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenominatorSpec {
    /// Stable source/metric identity; it is not a count supplied by a caller.
    pub source_ref: String,
    /// Expected count when the source exposes a count.
    pub expected_count: Option<u64>,
    /// Expected interval in milliseconds when the source exposes a time bound.
    pub expected_interval_ms: Option<u64>,
}

impl DenominatorSpec {
    /// Validates that at least one measurable denominator is declared.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.source_ref, "denominator.source_ref")?;
        if self.expected_count.is_none() && self.expected_interval_ms.is_none() {
            return Err(ObservationError::InvalidField {
                field: "denominator",
                reason: "must declare expected_count or expected_interval_ms",
            });
        }
        Ok(())
    }
}

/// Versioned sampling/coalescing declaration.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingPolicy {
    /// Capture mode for ordinary observations.
    pub mode: CaptureMode,
    /// Optional rate represented as numerator/denominator.
    pub rate_numerator: Option<u32>,
    pub rate_denominator: Option<u32>,
    /// Versioned aggregation rule, if samples are coalesced.
    pub aggregation_rule_ref: Option<String>,
    /// Whether the aggregate retains a raw evidence handle.
    pub raw_handle_required: bool,
}

impl SamplingPolicy {
    /// Validates a sampling declaration without deciding whether sampling is useful.
    pub fn validate(&self) -> Result<(), ObservationError> {
        match (self.rate_numerator, self.rate_denominator) {
            (Some(numerator), Some(denominator)) if denominator > 0 && numerator <= denominator => {
            }
            (None, None) => {}
            _ => {
                return Err(ObservationError::InvalidField {
                    field: "sampling.rate",
                    reason: "requires 0 <= numerator <= denominator and denominator > 0",
                });
            }
        }
        if matches!(self.mode, CaptureMode::Sampled) && self.aggregation_rule_ref.is_none() {
            return Err(ObservationError::InvalidField {
                field: "sampling.aggregation_rule_ref",
                reason: "sampled mode requires a versioned aggregation rule",
            });
        }
        if let Some(rule) = &self.aggregation_rule_ref {
            text(rule, "sampling.aggregation_rule_ref")?;
        }
        Ok(())
    }
}

/// Explicit response when an observation cannot be captured.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapPolicy {
    /// Stable reason/directive identity.
    pub reason_ref: String,
    /// Consequence for guarantees depending on this observation.
    pub disposition: GapDisposition,
    /// Whether the gap itself must use protected capacity.
    pub protected_gap_required: bool,
}

impl GapPolicy {
    /// Validates the declared failure path.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.reason_ref, "gap_policy.reason_ref")
    }
}

/// A producer's versioned observation promise.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationObligationProfile {
    /// Stable profile identity and revision.
    pub profile_id: String,
    pub profile_revision: String,
    /// Capability and generation that made the promise.
    pub producer_capability_and_generation: ProducerGenerationRef,
    /// Activation/session/task/job classes for which it applies.
    #[serde(rename = "applicable_activation_session_task_or_job_classes")]
    pub applicable_classes: Vec<String>,
    /// Event classes and trigger boundaries expected from the producer.
    pub expected_event_classes: Vec<ObservationKind>,
    pub trigger_boundaries: Vec<String>,
    /// Capture route and minimum durability.
    pub required_capture_route: CaptureRoute,
    pub minimum_durability: Durability,
    /// Denominator and sampling rules.
    #[serde(rename = "denominator_source_and_expected_count_or_interval")]
    pub denominator: DenominatorSpec,
    #[serde(rename = "allowed_sampling_coalescing_and_raw_handle_policy")]
    pub sampling: SamplingPolicy,
    /// Maximum unobserved interval and freshness requirement.
    #[serde(rename = "maximum_blind_interval_and_freshness_ms")]
    pub maximum_blind_interval_ms: Option<u64>,
    pub freshness_window_ms: Option<u64>,
    /// Explicit failure disposition and invalidation handles.
    pub failure_gap_and_governance_disposition: GapPolicy,
    pub invalidation_set: Vec<String>,
}

impl ObservationObligationProfile {
    /// Validates the complete obligation without contacting a producer.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.profile_id, "profile_id")?;
        text(&self.profile_revision, "profile_revision")?;
        self.producer_capability_and_generation.validate()?;
        if self.applicable_classes.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "applicable_classes",
                reason: "must not be empty",
            });
        }
        unique(&self.applicable_classes, "applicable_classes")?;
        if self.expected_event_classes.is_empty() || self.trigger_boundaries.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "expected_events",
                reason: "event classes and trigger boundaries must not be empty",
            });
        }
        unique(&self.trigger_boundaries, "trigger_boundaries")?;
        self.denominator.validate()?;
        self.sampling.validate()?;
        self.failure_gap_and_governance_disposition.validate()?;
        unique(&self.invalidation_set, "invalidation_set")
    }
}

/// An interval in a producer cursor or host clock.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageInterval {
    /// Inclusive starting cursor.
    pub start: u64,
    /// Inclusive ending cursor.
    pub end: u64,
}

impl CoverageInterval {
    /// Creates an interval after checking its ordering.
    pub const fn new(start: u64, end: u64) -> Result<Self, ObservationError> {
        if end < start {
            return Err(ObservationError::InvalidInterval { field: "coverage" });
        }
        Ok(Self { start, end })
    }

    /// Returns the number of covered cursor positions.
    pub const fn length(self) -> u64 {
        self.end - self.start + 1
    }
}

/// A known blind interval preserved as evidence rather than treated as silence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindInterval {
    /// Cursor range that was not independently observed.
    pub interval: CoverageInterval,
    /// Typed source of the blind interval.
    pub reason_ref: String,
}

impl BlindInterval {
    /// Validates the blind interval reference.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.reason_ref, "blind_interval.reason_ref")
    }
}

/// The admitted plan compiled for one active interval.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveObservationPlan {
    /// Stable plan identity and State Fence.
    pub plan_id: String,
    pub plan_revision: String,
    pub state_fence: StateFence,
    /// Activation/governance profile reference.
    pub activation_and_governance_profile: String,
    /// Profiles admitted into this plan.
    pub admitted_obligation_profile_refs: Vec<String>,
    /// Source capability visibility at compilation time.
    pub observable_sources: Vec<String>,
    pub unobservable_sources: Vec<String>,
    /// Expected denominator and cursor projections.
    pub expected_denominators: Vec<DenominatorSpec>,
    pub cursor_ranges: Vec<CoverageInterval>,
    /// Events whose absence cannot be silently coalesced.
    pub protected_event_classes: Vec<ObservationKind>,
    pub known_blind_intervals: Vec<BlindInterval>,
    /// Recompile/invalidation handles.
    pub expiry_and_recompile_triggers: Vec<String>,
}

impl ActiveObservationPlan {
    /// Validates that a plan is explicit about both visible and blind sources.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.plan_id, "plan_id")?;
        text(&self.plan_revision, "plan_revision")?;
        self.state_fence.validate()?;
        text(
            &self.activation_and_governance_profile,
            "activation_and_governance_profile",
        )?;
        if self.admitted_obligation_profile_refs.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "admitted_obligation_profile_refs",
                reason: "must not be empty",
            });
        }
        unique(
            &self.admitted_obligation_profile_refs,
            "admitted_obligation_profile_refs",
        )?;
        unique(&self.observable_sources, "observable_sources")?;
        unique(&self.unobservable_sources, "unobservable_sources")?;
        for source in &self.observable_sources {
            if self.unobservable_sources.contains(source) {
                return Err(ObservationError::Duplicate {
                    field: "plan sources",
                    value: source.clone(),
                });
            }
        }
        if self.expected_denominators.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "expected_denominators",
                reason: "must not be empty",
            });
        }
        for denominator in &self.expected_denominators {
            denominator.validate()?;
        }
        for interval in &self.cursor_ranges {
            CoverageInterval::new(interval.start, interval.end)?;
        }
        for blind in &self.known_blind_intervals {
            blind.validate()?;
        }
        unique(
            &self.expiry_and_recompile_triggers,
            "expiry_and_recompile_triggers",
        )
    }
}

/// Identity and source generation for an observation event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEventIdentity {
    /// Event identity assigned by the admitting owner.
    pub event_id: String,
    /// Host/Governor time readings; time is not causal order.
    pub clock: ClockReading,
}

impl ObservationEventIdentity {
    /// Validates event identity and clock ordering.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.event_id, "event_id")?;
        validate_clock(&self.clock, "event.clock")
    }
}

/// Producer generation and trace handles for a normalized event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerTrace {
    pub producer: String,
    pub generation: String,
    pub trace_ref: Option<String>,
}

impl ProducerTrace {
    /// Validates producer identity and optional trace reference.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.producer, "producer")?;
        text(&self.generation, "generation")?;
        if let Some(trace) = &self.trace_ref {
            text(trace, "trace_ref")?;
        }
        Ok(())
    }
}

/// Scope affected by an observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationScope {
    pub work_scope: WorkScopeId,
    pub task_ref: Option<String>,
    pub attempt_ref: Option<String>,
    pub module_or_route_ref: Option<String>,
}

impl ObservationScope {
    /// Validates optional task/attempt/module references.
    pub fn validate(&self) -> Result<(), ObservationError> {
        for (value, field) in [
            (&self.task_ref, "task_ref"),
            (&self.attempt_ref, "attempt_ref"),
            (&self.module_or_route_ref, "module_or_route_ref"),
        ] {
            if let Some(value) = value {
                text(value, field)?;
            }
        }
        Ok(())
    }
}

/// Privacy, retention and disclosure handles for an event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyRetentionDisclosure {
    pub privacy_domain_ref: String,
    pub retention_policy_ref: String,
    pub disclosure_class: String,
}

impl PrivacyRetentionDisclosure {
    /// Validates privacy metadata without interpreting policy.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.privacy_domain_ref, "privacy_domain_ref")?;
        text(&self.retention_policy_ref, "retention_policy_ref")?;
        text(&self.disclosure_class, "disclosure_class")
    }
}

/// Common normalized event surface shared by record families.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEventCore {
    pub event_id_and_time: ObservationEventIdentity,
    pub producer_generation_and_trace: ProducerTrace,
    pub kind: ObservationKind,
    pub affected_scope: ObservationScope,
    pub observed_delta: String,
    pub expected_baseline: Option<String>,
    pub evidence_and_raw_handles: Vec<String>,
    pub coverage_and_blind_intervals: CoverageEvidence,
    pub privacy_retention_and_disclosure: PrivacyRetentionDisclosure,
    pub candidate_importance: u8,
    pub dedup_key: String,
}

impl ObservationEventCore {
    /// Validates the common event surface and its coverage evidence.
    pub fn validate(&self) -> Result<(), ObservationError> {
        self.event_id_and_time.validate()?;
        self.producer_generation_and_trace.validate()?;
        self.affected_scope.validate()?;
        text(&self.observed_delta, "observed_delta")?;
        if let Some(baseline) = &self.expected_baseline {
            text(baseline, "expected_baseline")?;
        }
        unique(&self.evidence_and_raw_handles, "evidence_and_raw_handles")?;
        self.coverage_and_blind_intervals.validate()?;
        self.privacy_retention_and_disclosure.validate()?;
        text(&self.dedup_key, "dedup_key")
    }
}

/// The event's coverage evidence at admission time.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEvidence {
    pub disposition: CoverageDisposition,
    pub denominator_source_ref: String,
    pub interval: Option<CoverageInterval>,
    pub blind_intervals: Vec<BlindInterval>,
    pub observed_count: u64,
}

impl CoverageEvidence {
    /// Validates coverage references and interval ordering.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.denominator_source_ref, "denominator_source_ref")?;
        if let Some(interval) = self.interval {
            CoverageInterval::new(interval.start, interval.end)?;
        }
        for blind in &self.blind_intervals {
            blind.validate()?;
        }
        Ok(())
    }
}

/// Explicit normalized audit record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub record_id: String,
    pub core: ObservationEventCore,
    pub audit_action: String,
    pub state_fence: StateFence,
}

impl AuditRecord {
    /// Validates the audit record without persisting or publishing it.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.record_id, "record_id")?;
        self.core.validate()?;
        self.state_fence.validate()?;
        text(&self.audit_action, "audit_action")
    }
}

/// Bounded telemetry record; high-rate samples must retain aggregate evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryRecord {
    pub record_id: String,
    pub core: ObservationEventCore,
    pub capture_mode: CaptureMode,
    pub sample_count: u64,
    pub raw_evidence_handle: Option<String>,
}

impl TelemetryRecord {
    /// Validates the bounded telemetry record.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.record_id, "record_id")?;
        self.core.validate()?;
        if self.sample_count == 0 {
            return Err(ObservationError::InvalidField {
                field: "sample_count",
                reason: "must be greater than zero",
            });
        }
        if matches!(self.capture_mode, CaptureMode::Sampled) && self.raw_evidence_handle.is_none() {
            return Err(ObservationError::InvalidField {
                field: "raw_evidence_handle",
                reason: "sampled telemetry requires a raw evidence handle",
            });
        }
        if let Some(handle) = &self.raw_evidence_handle {
            text(handle, "raw_evidence_handle")?;
        }
        Ok(())
    }
}

/// Exact host/filesystem/VCS/process/artifact change record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRecord {
    pub record_id: String,
    pub core: ObservationEventCore,
    pub change_operation: String,
    pub origin_confidence: String,
    pub state_fence: StateFence,
}

impl ChangeRecord {
    /// Validates an exact change observation and its fence.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.record_id, "record_id")?;
        self.core.validate()?;
        self.state_fence.validate()?;
        text(&self.change_operation, "change_operation")?;
        text(&self.origin_confidence, "origin_confidence")
    }
}

/// Maintenance trigger/assessment record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceRecord {
    pub record_id: String,
    pub core: ObservationEventCore,
    pub maintenance_action: String,
    pub trigger_ref: String,
}

impl MaintenanceRecord {
    /// Validates a maintenance observation without scheduling work.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.record_id, "record_id")?;
        self.core.validate()?;
        text(&self.maintenance_action, "maintenance_action")?;
        text(&self.trigger_ref, "trigger_ref")
    }
}

/// Explicit coverage gap, never inferred from absent rows.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub gap_id: String,
    pub obligation_profile_ref: String,
    pub reason_ref: String,
    pub affected_interval: Option<CoverageInterval>,
    pub disposition: GapDisposition,
    pub protected: bool,
    pub evidence_refs: Vec<String>,
}

impl CoverageGap {
    /// Validates the explicit gap identity and interval.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.gap_id, "gap_id")?;
        text(&self.obligation_profile_ref, "obligation_profile_ref")?;
        text(&self.reason_ref, "reason_ref")?;
        if let Some(interval) = self.affected_interval {
            CoverageInterval::new(interval.start, interval.end)?;
        }
        unique(&self.evidence_refs, "evidence_refs")
    }
}

/// Common record envelope used by journal consumers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecordEnvelope {
    pub record_id: String,
    pub kind: ObservationRecordKind,
    pub event: Option<ObservationEventCore>,
    pub coverage_gap: Option<CoverageGap>,
    /// Only a dedicated control event may describe journal health/coverage.
    pub journal_control_event: bool,
    pub parent_record_id: Option<String>,
}

/// Wire-compatible name used by the Governor observation journal.
pub type SystemObservationJournalRecord = ObservationRecordEnvelope;
/// Wire-compatible name used by the Runtime prose for a normalized event.
pub type EliotSystemObservationEvent = ObservationEventCore;

impl ObservationRecordEnvelope {
    /// Validates kind/payload pairing and the non-recursive journal boundary.
    pub fn validate(&self) -> Result<(), ObservationError> {
        text(&self.record_id, "record_id")?;
        match (self.kind, self.event.is_some(), self.coverage_gap.is_some()) {
            (ObservationRecordKind::CoverageGap, false, true) => {}
            (ObservationRecordKind::CoverageGap, true, _) => {
                return Err(ObservationError::InvalidField {
                    field: "event",
                    reason: "coverage gap records do not carry ordinary events",
                });
            }
            (_, true, false) => {}
            (_, false, false) => {
                return Err(ObservationError::InvalidField {
                    field: "event",
                    reason: "ordinary records require an event",
                });
            }
            (_, _, true) => {
                return Err(ObservationError::InvalidField {
                    field: "coverage_gap",
                    reason: "only COVERAGE_GAP records carry a gap",
                });
            }
        }
        if let Some(event) = &self.event {
            event.validate()?;
        }
        if let Some(gap) = &self.coverage_gap {
            gap.validate()?;
        }
        if let Some(parent) = &self.parent_record_id {
            text(parent, "parent_record_id")?;
            if parent == &self.record_id {
                return Err(ObservationError::NonRecursiveViolation);
            }
        }
        if self.journal_control_event && !matches!(self.kind, ObservationRecordKind::Audit) {
            return Err(ObservationError::InvalidField {
                field: "journal_control_event",
                reason: "journal control events use the audit family",
            });
        }
        if self.journal_control_event && self.parent_record_id.is_some() {
            return Err(ObservationError::NonRecursiveViolation);
        }
        Ok(())
    }
}

/// A denominator/cursor comparison result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageAssessment {
    pub denominator_known: bool,
    pub interval_complete: bool,
    pub source_available: bool,
    pub expected_count: Option<u64>,
    pub observed_count: u64,
    pub blind_intervals: Vec<BlindInterval>,
    pub disposition: CoverageDisposition,
}

impl CoverageAssessment {
    /// Computes the honest disposition from explicit denominator and interval facts.
    pub fn assess(
        denominator_known: bool,
        interval_complete: bool,
        source_available: bool,
        expected_count: Option<u64>,
        observed_count: u64,
        blind_intervals: Vec<BlindInterval>,
    ) -> Result<Self, ObservationError> {
        for blind in &blind_intervals {
            blind.validate()?;
        }
        let disposition = if !source_available {
            CoverageDisposition::Unavailable
        } else if !denominator_known {
            CoverageDisposition::Unknown
        } else if !interval_complete || !blind_intervals.is_empty() {
            CoverageDisposition::IncompleteCoverage
        } else if expected_count.is_some_and(|expected| expected != observed_count) {
            CoverageDisposition::Partial
        } else {
            CoverageDisposition::Complete
        };
        Ok(Self {
            denominator_known,
            interval_complete,
            source_available,
            expected_count,
            observed_count,
            blind_intervals,
            disposition,
        })
    }

    /// Returns whether silence can honestly be interpreted as absence.
    pub const fn silence_proves_absence(&self) -> bool {
        self.denominator_known
            && self.interval_complete
            && self.source_available
            && self.blind_intervals.is_empty()
            && matches!(self.disposition, CoverageDisposition::Complete)
    }
}

/// Produces the stable schema/provenance identity for this package.
pub fn contract_identity() -> Result<ContractIdentity, ObservationError> {
    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "obligation": schemars::schema_for!(ObservationObligationProfile),
            "plan": schemars::schema_for!(ActiveObservationPlan),
            "event": schemars::schema_for!(ObservationEventCore),
            "record": schemars::schema_for!(ObservationRecordEnvelope),
            "coverage": schemars::schema_for!(CoverageAssessment),
        }),
    )
    .map_err(ObservationError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Result<ObservationScope, ObservationError> {
        Ok(ObservationScope {
            work_scope: "scope:test".parse()?,
            task_ref: None,
            attempt_ref: None,
            module_or_route_ref: None,
        })
    }

    fn core() -> Result<ObservationEventCore, ObservationError> {
        Ok(ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: "event-1".to_owned(),
                clock: ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "producer".to_owned(),
                generation: "generation-1".to_owned(),
                trace_ref: None,
            },
            kind: ObservationKind::TaskProgress,
            affected_scope: scope()?,
            observed_delta: "progressed".to_owned(),
            expected_baseline: None,
            evidence_and_raw_handles: vec!["raw-1".to_owned()],
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: "cursor:task".to_owned(),
                interval: Some(CoverageInterval::new(1, 1)?),
                blind_intervals: Vec::new(),
                observed_count: 1,
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "self".to_owned(),
                retention_policy_ref: "default".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: "task-progress:event-1".to_owned(),
        })
    }

    #[test]
    fn coverage_never_infers_absence_without_denominator() -> Result<(), ObservationError> {
        let assessment = CoverageAssessment::assess(false, true, true, None, 0, Vec::new())?;
        assert_eq!(assessment.disposition, CoverageDisposition::Unknown);
        assert!(!assessment.silence_proves_absence());
        Ok(())
    }

    #[test]
    fn coverage_gap_is_explicit_when_interval_is_blind() -> Result<(), ObservationError> {
        let gap = BlindInterval {
            interval: CoverageInterval::new(10, 12)?,
            reason_ref: "watchdog-unavailable".to_owned(),
        };
        let assessment = CoverageAssessment::assess(true, false, true, Some(3), 0, vec![gap])?;
        assert_eq!(
            assessment.disposition,
            CoverageDisposition::IncompleteCoverage
        );
        Ok(())
    }

    #[test]
    fn record_kind_and_gap_payload_must_match() -> Result<(), ObservationError> {
        let envelope = ObservationRecordEnvelope {
            record_id: "record-1".to_owned(),
            kind: ObservationRecordKind::Telemetry,
            event: None,
            coverage_gap: Some(CoverageGap {
                gap_id: "gap-1".to_owned(),
                obligation_profile_ref: "profile-1".to_owned(),
                reason_ref: "queue-pressure".to_owned(),
                affected_interval: None,
                disposition: GapDisposition::DegradeDependentGuarantees,
                protected: true,
                evidence_refs: Vec::new(),
            }),
            journal_control_event: false,
            parent_record_id: None,
        };
        assert!(envelope.validate().is_err());
        Ok(())
    }

    #[test]
    fn ordinary_journal_observation_cannot_recurse() -> Result<(), ObservationError> {
        let envelope = ObservationRecordEnvelope {
            record_id: "record-1".to_owned(),
            kind: ObservationRecordKind::Audit,
            event: Some(core()?),
            coverage_gap: None,
            journal_control_event: true,
            parent_record_id: Some("record-0".to_owned()),
        };
        assert_eq!(
            envelope.validate(),
            Err(ObservationError::NonRecursiveViolation)
        );
        Ok(())
    }

    #[test]
    fn malformed_duplicate_profile_values_fail_closed() -> Result<(), ObservationError> {
        let profile = ObservationObligationProfile {
            profile_id: "profile-1".to_owned(),
            profile_revision: "rev-1".to_owned(),
            producer_capability_and_generation: ProducerGenerationRef {
                capability: "cap".to_owned(),
                generation: "gen".to_owned(),
            },
            applicable_classes: vec!["ACTIVE".to_owned(), "ACTIVE".to_owned()],
            expected_event_classes: vec![ObservationKind::TaskProgress],
            trigger_boundaries: vec!["boundary".to_owned()],
            required_capture_route: CaptureRoute::CanonicalJournal,
            minimum_durability: Durability::Durable,
            denominator: DenominatorSpec {
                source_ref: "cursor".to_owned(),
                expected_count: Some(1),
                expected_interval_ms: None,
            },
            sampling: SamplingPolicy {
                mode: CaptureMode::Full,
                rate_numerator: None,
                rate_denominator: None,
                aggregation_rule_ref: None,
                raw_handle_required: false,
            },
            maximum_blind_interval_ms: None,
            freshness_window_ms: None,
            failure_gap_and_governance_disposition: GapPolicy {
                reason_ref: "gap".to_owned(),
                disposition: GapDisposition::DegradeDependentGuarantees,
                protected_gap_required: true,
            },
            invalidation_set: vec!["fence".to_owned()],
        };
        assert!(matches!(
            profile.validate(),
            Err(ObservationError::Duplicate { .. })
        ));
        Ok(())
    }

    #[test]
    fn serde_denies_unknown_record_fields_and_schema_is_available() -> Result<(), ObservationError>
    {
        let malformed = serde_json::json!({
            "record_id": "record-1",
            "kind": "TELEMETRY",
            "event": null,
            "coverage_gap": null,
            "journal_control_event": false,
            "parent_record_id": null,
            "unexpected": true
        });
        assert!(serde_json::from_value::<ObservationRecordEnvelope>(malformed).is_err());
        assert!(!serde_json::to_vec(&schemars::schema_for!(ActiveObservationPlan))?.is_empty());
        assert!(!contract_identity()?.shape_sha256.is_empty());
        Ok(())
    }
}
