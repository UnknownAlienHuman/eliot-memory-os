//! Provider-neutral observability contracts for the Instrument Plane.
//!
//! Logs, metrics, durable audit and reports remain distinct surfaces.  This
//! crate describes operational events, bounded metric samples and correlated
//! instrument-run telemetry; it does not execute processes, persist canonical
//! audit, export secrets, or turn activity metrics into semantic proof.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ArtifactId, ClockReading, ContractIdentity, ContractVersion, RequestId, StateFence,
    canonical_json_bytes, contract_identity as foundation_contract_identity, sha256_hex,
};
use eliot_instrument_api::{
    EvidenceCoverage, EvidenceFreshness, ExecutionStatus, InstrumentContractError,
    InstrumentInvocation, InstrumentKind, NormalizedEvidence,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this observability contract.
pub const CONTRACT_NAME: &str = "eliot.instrument.observability";
/// Current wire revision of this contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Failures at the observability boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObservabilityError {
    /// A shared foundation contract rejected an identity, clock or fence.
    #[error("foundation contract: {0}")]
    Foundation(eliot_contracts::ContractError),
    /// The invocation/evidence contract rejected an instrument record.
    #[error("instrument contract: {0}")]
    Instrument(InstrumentContractError),
    /// A required field is blank or malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required collection has no values.
    #[error("empty field {field}")]
    Empty {
        /// Stable field path.
        field: &'static str,
    },
    /// A collection contains duplicate identities.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Stable field path.
        field: &'static str,
    },
    /// A stable event/metric identity was reused with different bytes.
    #[error("observability identity conflict")]
    IdentityConflict,
    /// A metric value is not finite.
    #[error("metric value must be finite")]
    NonFiniteMetric,
    /// A label would disclose content or a secret.
    #[error("sensitive telemetry label is forbidden")]
    SensitiveLabel,
    /// A bounded buffer cannot retain a protected event.
    #[error("protected telemetry capacity is exhausted")]
    ProtectedCapacityExhausted,
    /// Canonical serialization failed before an identity could be derived.
    #[error("cannot canonicalize observability record")]
    Serialization,
}

impl From<eliot_contracts::ContractError> for ObservabilityError {
    fn from(error: eliot_contracts::ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<InstrumentContractError> for ObservabilityError {
    fn from(error: InstrumentContractError) -> Self {
        Self::Instrument(error)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ObservabilityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ObservabilityError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn unique<T: Ord>(values: impl IntoIterator<Item = T>, field: &'static str) -> Result<(), ObservabilityError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(ObservabilityError::Duplicate { field });
    }
    Ok(())
}

fn validate_clock(clock: &ClockReading, field: &'static str) -> Result<(), ObservabilityError> {
    clock
        .validate()
        .map_err(|_| ObservabilityError::InvalidField {
            field,
            reason: "clock interval is invalid",
        })
}

fn validate_id(id: &str, field: &'static str) -> Result<(), ObservabilityError> {
    text(id, field)
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), ObservabilityError> {
    if labels.len() > 16 {
        return Err(ObservabilityError::InvalidField {
            field: "labels",
            reason: "label cardinality exceeds the bounded limit",
        });
    }
    for (key, value) in labels {
        text(key, "label.key")?;
        text(value, "label.value")?;
        let normalized = key.to_ascii_lowercase();
        if [
            "secret", "token", "password", "credential", "prompt", "content", "stdout",
            "stderr", "arguments", "args", "raw", "payload",
        ]
        .iter()
        .any(|forbidden| normalized.contains(forbidden))
        {
            return Err(ObservabilityError::SensitiveLabel);
        }
    }
    Ok(())
}

/// Correlated lineage carried by every operational event and run telemetry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContext {
    pub trace_id: String,
    pub operation_id: String,
    pub task_ref: Option<String>,
    pub work_item_ref: Option<String>,
    pub attempt_ref: Option<String>,
    pub job_ref: Option<String>,
    pub principal_ref: Option<String>,
    pub session_ref: Option<String>,
    pub controller_ref: Option<String>,
    pub work_scope_ref: String,
    pub state_fence: StateFence,
    pub adapter_instance_ref: String,
    pub process_job_ref: Option<String>,
    pub native_session_ref: Option<String>,
    pub parent_ref: Option<String>,
    pub route_fingerprint_ref: Option<String>,
    pub worktree_ref: Option<String>,
    pub execution_lease_ref: Option<String>,
    pub module_generation_ref: String,
    pub authority_epoch: u64,
    pub event_cursor: Option<u64>,
    pub normalization_version: String,
    pub impact_class: String,
    pub recipe_ref: Option<String>,
    pub assurance_class: String,
}

impl TraceContext {
    /// Validates lineage while keeping secrets and content outside labels.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        text(&self.trace_id, "trace.trace_id")?;
        text(&self.operation_id, "trace.operation_id")?;
        text(&self.work_scope_ref, "trace.work_scope_ref")?;
        text(&self.adapter_instance_ref, "trace.adapter_instance_ref")?;
        text(&self.module_generation_ref, "trace.module_generation_ref")?;
        text(&self.normalization_version, "trace.normalization_version")?;
        text(&self.impact_class, "trace.impact_class")?;
        text(&self.assurance_class, "trace.assurance_class")?;
        if self.authority_epoch == 0 {
            return Err(ObservabilityError::InvalidField {
                field: "trace.authority_epoch",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate()?;
        for value in [
            self.task_ref.as_deref(),
            self.work_item_ref.as_deref(),
            self.attempt_ref.as_deref(),
            self.job_ref.as_deref(),
            self.principal_ref.as_deref(),
            self.session_ref.as_deref(),
            self.controller_ref.as_deref(),
            self.process_job_ref.as_deref(),
            self.native_session_ref.as_deref(),
            self.parent_ref.as_deref(),
            self.route_fingerprint_ref.as_deref(),
            self.worktree_ref.as_deref(),
            self.execution_lease_ref.as_deref(),
            self.recipe_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            text(value, "trace.reference")?;
        }
        Ok(())
    }
}

/// Required operational event classes from the Instrument Plane.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationalEventKind {
    ProcessStart,
    ModuleStart,
    AdapterStart,
    Handshake,
    Ready,
    Quiesce,
    Stop,
    Crash,
    Restart,
    RestartExhausted,
    Quarantine,
    CapabilityDiscovery,
    CapabilityAdmission,
    CapabilityExpiry,
    RouteMismatch,
    QueueReservation,
    QueueDefer,
    ControlReservePressure,
    StoreTransaction,
    StoreRetry,
    StoreUnknownCommit,
    SessionTransition,
    LeaseTransition,
    EpochTransition,
    NativeRawEventAppend,
    NormalizedCursorAdvance,
    HookIntegrationGap,
    CancellationRequest,
    CancellationConfirmation,
    OrphanCleanup,
    JobStart,
    JobResult,
    JobUsage,
    Verification,
    FinishDecision,
    FailureCapsule,
    TelemetryGap,
}

impl OperationalEventKind {
    /// Whether this event is a protected lifecycle/control observation.
    pub const fn is_protected(self) -> bool {
        matches!(
            self,
            Self::Crash
                | Self::RestartExhausted
                | Self::Quarantine
                | Self::RouteMismatch
                | Self::StoreUnknownCommit
                | Self::HookIntegrationGap
                | Self::CancellationRequest
                | Self::CancellationConfirmation
                | Self::OrphanCleanup
                | Self::Verification
                | Self::FinishDecision
                | Self::FailureCapsule
                | Self::TelemetryGap
        )
    }
}

/// Lifecycle importance used for bounded retention and explicit gap handling.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventPriority {
    Diagnostic,
    Normal,
    Protected,
}

impl EventPriority {
    fn is_protected(self) -> bool {
        matches!(self, Self::Protected)
    }
}

/// Observable state of one operational event.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventStatus {
    Observed,
    Started,
    Succeeded,
    Failed,
    Unknown,
    Cancelled,
}

/// One operational event.  It is not a durable audit receipt or a verifier.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalEvent {
    pub event_id: String,
    pub trace: TraceContext,
    pub kind: OperationalEventKind,
    pub priority: EventPriority,
    pub status: EventStatus,
    pub observed_at: ClockReading,
    pub labels: BTreeMap<String, String>,
    pub raw_evidence_refs: Vec<ArtifactId>,
    pub normalized_evidence_refs: Vec<ArtifactId>,
    pub coverage: EvidenceCoverage,
    pub blind_interval_ref: Option<String>,
}

impl OperationalEvent {
    /// Validates event identity, lineage, labels and explicit coverage.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_id(&self.event_id, "event.event_id")?;
        self.trace.validate()?;
        validate_clock(&self.observed_at, "event.observed_at")?;
        validate_labels(&self.labels)?;
        unique(self.raw_evidence_refs.iter(), "event.raw_evidence_refs")?;
        unique(
            self.normalized_evidence_refs.iter(),
            "event.normalized_evidence_refs",
        )?;
        if let Some(reference) = &self.blind_interval_ref {
            text(reference, "event.blind_interval_ref")?;
        }
        if self.kind.is_protected() && !self.priority.is_protected() {
            return Err(ObservabilityError::InvalidField {
                field: "event.priority",
                reason: "protected event class requires protected priority",
            });
        }
        if matches!(self.coverage, EvidenceCoverage::PartialForScope | EvidenceCoverage::Unknown)
            && self.blind_interval_ref.is_none()
        {
            return Err(ObservabilityError::InvalidField {
                field: "event.blind_interval_ref",
                reason: "partial or unknown coverage requires an explicit gap handle",
            });
        }
        Ok(())
    }

    /// Stable content hash used for idempotent event admission.
    pub fn digest(&self) -> Result<String, ObservabilityError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ObservabilityError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// Metric aggregation semantics; metric samples never become a progress score.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetricAggregation {
    Counter,
    Gauge,
    HistogramSample,
}

/// One bounded metric sample with safe labels and optional run lineage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricSample {
    pub sample_id: String,
    pub name: String,
    pub aggregation: MetricAggregation,
    pub value: f64,
    pub unit: String,
    pub captured_at: ClockReading,
    pub trace: Option<TraceContext>,
    pub labels: BTreeMap<String, String>,
}

impl MetricSample {
    /// Validates metric value, label cardinality and optional lineage.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_id(&self.sample_id, "metric.sample_id")?;
        text(&self.name, "metric.name")?;
        text(&self.unit, "metric.unit")?;
        if !self.value.is_finite() {
            return Err(ObservabilityError::NonFiniteMetric);
        }
        validate_clock(&self.captured_at, "metric.captured_at")?;
        if let Some(trace) = &self.trace {
            trace.validate()?;
        }
        validate_labels(&self.labels)
    }

    /// Stable content hash used for idempotent metric admission.
    pub fn digest(&self) -> Result<String, ObservabilityError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ObservabilityError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// Run timing stages retained as observations, not a single elapsed claim.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunTiming {
    pub queued_at: ClockReading,
    pub started_at: ClockReading,
    pub first_output_at: Option<ClockReading>,
    pub finished_at: Option<ClockReading>,
    pub cleanup_finished_at: Option<ClockReading>,
}

impl RunTiming {
    /// Validates clock readings and known-time ordering where available.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_clock(&self.queued_at, "run_timing.queued_at")?;
        validate_clock(&self.started_at, "run_timing.started_at")?;
        for (clock, field) in [
            (self.first_output_at.as_ref(), "run_timing.first_output_at"),
            (self.finished_at.as_ref(), "run_timing.finished_at"),
            (self.cleanup_finished_at.as_ref(), "run_timing.cleanup_finished_at"),
        ] {
            if let Some(clock) = clock {
                validate_clock(clock, field)?;
            }
        }
        let points = [
            self.queued_at.known_time_ms,
            Some(self.started_at).and_then(|clock| clock.known_time_ms),
            self.first_output_at.and_then(|clock| clock.known_time_ms),
            self.finished_at.and_then(|clock| clock.known_time_ms),
            self.cleanup_finished_at.and_then(|clock| clock.known_time_ms),
        ];
        let mut previous = None;
        for point in points.into_iter().flatten() {
            if previous.is_some_and(|prior| point < prior) {
                return Err(ObservabilityError::InvalidField {
                    field: "run_timing",
                    reason: "known stage times must be monotonic",
                });
            }
            previous = Some(point);
        }
        Ok(())
    }
}

/// Process-tree/resource and cleanup observations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessResourceTelemetry {
    pub process_tree_ref: Option<String>,
    pub resource_limit_ref: Option<String>,
    pub cleanup_status: CleanupStatus,
    pub orphan_count: u64,
    pub descendant_count: u64,
}

/// Disposition of process cleanup; clean exit is not semantic success.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupStatus {
    NotApplicable,
    Clean,
    Forced,
    Unknown,
    Failed,
}

impl ProcessResourceTelemetry {
    fn validate(&self) -> Result<(), ObservabilityError> {
        for value in [self.process_tree_ref.as_deref(), self.resource_limit_ref.as_deref()]
            .into_iter()
            .flatten()
        {
            text(value, "process_resource.reference")?;
        }
        Ok(())
    }
}

/// Output accounting with explicit truncation/parser-warning lineage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputTelemetry {
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub raw_evidence_refs: Vec<ArtifactId>,
    pub truncated: bool,
    pub parser_warning_refs: Vec<String>,
}

impl OutputTelemetry {
    fn validate(&self) -> Result<(), ObservabilityError> {
        unique(self.raw_evidence_refs.iter(), "output.raw_evidence_refs")?;
        unique(
            self.parser_warning_refs.iter(),
            "output.parser_warning_refs",
        )?;
        for reference in &self.parser_warning_refs {
            text(reference, "output.parser_warning_ref")?;
        }
        if self.truncated && self.raw_evidence_refs.is_empty() {
            return Err(ObservabilityError::InvalidField {
                field: "output.raw_evidence_refs",
                reason: "truncation requires a raw evidence handle",
            });
        }
        Ok(())
    }
}

/// Test discovery/selection/execution counts are counter-metrics, not proof.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTelemetry {
    pub discovered: u64,
    pub selected: u64,
    pub executed: u64,
    pub skipped: u64,
}

impl TestTelemetry {
    fn validate(&self) -> Result<(), ObservabilityError> {
        if self.selected > self.discovered || self.executed > self.selected {
            return Err(ObservabilityError::InvalidField {
                field: "tests",
                reason: "selected tests cannot exceed discovered or executed exceed selected",
            });
        }
        Ok(())
    }
}

/// Target/cache/lock observations for instrument economics.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheTelemetry {
    pub target_identity: String,
    pub cache_identity: Option<String>,
    pub lock_wait_ms: Option<u64>,
    pub cache_hit: Option<bool>,
}

impl CacheTelemetry {
    fn validate(&self) -> Result<(), ObservabilityError> {
        text(&self.target_identity, "cache.target_identity")?;
        if let Some(identity) = &self.cache_identity {
            text(identity, "cache.cache_identity")?;
        }
        Ok(())
    }
}

/// Exact rerun lineage; reruns never overwrite the first run observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RerunTelemetry {
    pub rerun_of: Option<RequestId>,
    pub rerun_profile_ref: Option<String>,
    pub exact_inputs: bool,
    pub raw_evidence_refs: Vec<ArtifactId>,
}

impl RerunTelemetry {
    fn validate(&self) -> Result<(), ObservabilityError> {
        if let Some(reference) = &self.rerun_profile_ref {
            text(reference, "rerun.profile_ref")?;
        }
        unique(self.raw_evidence_refs.iter(), "rerun.raw_evidence_refs")
    }
}

/// Correlated telemetry emitted by one Instrument API invocation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRunTelemetry {
    pub run_id: RequestId,
    pub invocation: InstrumentInvocation,
    pub profile_revision: String,
    pub stage: String,
    pub trace: TraceContext,
    pub base_identity: String,
    pub candidate_identity: String,
    pub worktree_identity: String,
    pub executable_identity: String,
    pub config_identity: String,
    pub environment_identity: String,
    pub execution: ExecutionStatus,
    pub timing: RunTiming,
    pub process: ProcessResourceTelemetry,
    pub output: OutputTelemetry,
    pub facts: Vec<String>,
    pub unknowns: Vec<String>,
    pub conflicts: Vec<String>,
    pub freshness: EvidenceFreshness,
    pub coverage: EvidenceCoverage,
    pub tests: Option<TestTelemetry>,
    pub cache: Option<CacheTelemetry>,
    pub rerun: RerunTelemetry,
    pub evidence: Vec<NormalizedEvidence>,
}

impl InstrumentRunTelemetry {
    /// Validates full Instrument Plane lineage without claiming proof.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_id(self.run_id.as_str(), "run.run_id")?;
        self.invocation.validate()?;
        if self.invocation.request.request_id != self.run_id {
            return Err(ObservabilityError::IdentityConflict);
        }
        text(&self.profile_revision, "run.profile_revision")?;
        text(&self.stage, "run.stage")?;
        self.trace.validate()?;
        if self.trace.state_fence != self.invocation.request.state_fence {
            return Err(ObservabilityError::InvalidField {
                field: "run.trace.state_fence",
                reason: "must match invocation State Fence",
            });
        }
        for (value, field) in [
            (&self.base_identity, "run.base_identity"),
            (&self.candidate_identity, "run.candidate_identity"),
            (&self.worktree_identity, "run.worktree_identity"),
            (&self.executable_identity, "run.executable_identity"),
            (&self.config_identity, "run.config_identity"),
            (&self.environment_identity, "run.environment_identity"),
        ] {
            text(value, field)?;
        }
        self.timing.validate()?;
        self.process.validate()?;
        self.output.validate()?;
        unique(self.facts.iter(), "run.facts")?;
        unique(self.unknowns.iter(), "run.unknowns")?;
        unique(self.conflicts.iter(), "run.conflicts")?;
        for value in self.facts.iter().chain(&self.unknowns).chain(&self.conflicts) {
            text(value, "run.observation_ref")?;
        }
        if let Some(tests) = self.tests {
            tests.validate()?;
        }
        if let Some(cache) = &self.cache {
            cache.validate()?;
        }
        self.rerun.validate()?;
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        if self.execution.is_terminal()
            && self.output.raw_evidence_refs.is_empty()
            && self.evidence.is_empty()
            && self.facts.is_empty()
            && self.unknowns.is_empty()
            && self.conflicts.is_empty()
        {
            return Err(ObservabilityError::Empty {
                field: "run.evidence_or_observations",
            });
        }
        Ok(())
    }

    /// Content identity for retry/replay and Failure Capsule lineage.
    pub fn digest(&self) -> Result<String, ObservabilityError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ObservabilityError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// Explicit coverage loss; absence is never inferred from a missing sample.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityGap {
    pub gap_id: String,
    pub source_ref: String,
    pub reason_ref: String,
    pub first_missing_sequence: Option<u64>,
    pub last_missing_sequence: Option<u64>,
    pub protected: bool,
    pub affected_event_kind: Option<OperationalEventKind>,
}

impl ObservabilityGap {
    /// Validates explicit telemetry coverage loss.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_id(&self.gap_id, "gap.gap_id")?;
        text(&self.source_ref, "gap.source_ref")?;
        text(&self.reason_ref, "gap.reason_ref")?;
        if let (Some(first), Some(last)) = (self.first_missing_sequence, self.last_missing_sequence)
            && last < first
        {
            return Err(ObservabilityError::InvalidField {
                field: "gap.sequence",
                reason: "missing sequence interval is reversed",
            });
        }
        if self.protected && self.affected_event_kind.is_none() {
            return Err(ObservabilityError::InvalidField {
                field: "gap.affected_event_kind",
                reason: "protected gap must name its event class",
            });
        }
        Ok(())
    }
}

/// Bounded retention configuration for the in-process observability facade.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BufferLimits {
    pub max_events: usize,
    pub max_metrics: usize,
    pub max_gaps: usize,
}

impl BufferLimits {
    /// Validates positive bounded capacities.
    pub const fn validate(self) -> Result<(), ObservabilityError> {
        if self.max_events == 0 || self.max_metrics == 0 || self.max_gaps == 0 {
            return Err(ObservabilityError::InvalidField {
                field: "buffer_limits",
                reason: "all capacities must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Deterministic result of appending an event or metric to the bounded facade.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BufferDisposition {
    Accepted,
    Replayed,
    GapRecorded,
}

/// Rebuildable bounded observability projection, not canonical audit storage.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilitySnapshot {
    pub events: Vec<OperationalEvent>,
    pub metrics: Vec<MetricSample>,
    pub gaps: Vec<ObservabilityGap>,
}

impl ObservabilitySnapshot {
    /// Validates a projection before handing it to a durable or reporting owner.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        unique(self.events.iter().map(|event| event.event_id.as_str()), "snapshot.events")?;
        unique(
            self.metrics.iter().map(|metric| metric.sample_id.as_str()),
            "snapshot.metrics",
        )?;
        unique(self.gaps.iter().map(|gap| gap.gap_id.as_str()), "snapshot.gaps")?;
        for event in &self.events {
            event.validate()?;
        }
        for metric in &self.metrics {
            metric.validate()?;
        }
        for gap in &self.gaps {
            gap.validate()?;
        }
        Ok(())
    }

    /// Stable projection identity for handoff and replay manifests.
    pub fn digest(&self) -> Result<String, ObservabilityError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ObservabilityError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// In-memory bounded facade with explicit gap preservation.
#[derive(Clone, Debug)]
pub struct ObservabilityBuffer {
    limits: BufferLimits,
    events: BTreeMap<String, (String, OperationalEvent)>,
    metrics: BTreeMap<String, (String, MetricSample)>,
    gaps: BTreeMap<String, ObservabilityGap>,
}

impl ObservabilityBuffer {
    /// Creates an empty bounded projection.
    pub fn new(limits: BufferLimits) -> Result<Self, ObservabilityError> {
        limits.validate()?;
        Ok(Self {
            limits,
            events: BTreeMap::new(),
            metrics: BTreeMap::new(),
            gaps: BTreeMap::new(),
        })
    }

    /// Appends an event with idempotent replay and protected-capacity fencing.
    pub fn append_event(&mut self, event: OperationalEvent) -> Result<BufferDisposition, ObservabilityError> {
        let digest = event.digest()?;
        if let Some((existing_digest, _)) = self.events.get(&event.event_id) {
            if existing_digest == &digest {
                return Ok(BufferDisposition::Replayed);
            }
            return Err(ObservabilityError::IdentityConflict);
        }
        if self.events.len() >= self.limits.max_events {
            if event.priority.is_protected() {
                return Err(ObservabilityError::ProtectedCapacityExhausted);
            }
            let gap = ObservabilityGap {
                gap_id: format!("gap:event:{}", event.event_id),
                source_ref: event.trace.adapter_instance_ref.clone(),
                reason_ref: "bounded-event-capacity".to_owned(),
                first_missing_sequence: event.trace.event_cursor,
                last_missing_sequence: event.trace.event_cursor,
                protected: false,
                affected_event_kind: Some(event.kind),
            };
            self.append_gap(gap)?;
            return Ok(BufferDisposition::GapRecorded);
        }
        self.events.insert(event.event_id, (digest, event));
        Ok(BufferDisposition::Accepted)
    }

    /// Appends a metric, recording a visible gap when bounded retention drops it.
    pub fn append_metric(&mut self, metric: MetricSample) -> Result<BufferDisposition, ObservabilityError> {
        let digest = metric.digest()?;
        if let Some((existing_digest, _)) = self.metrics.get(&metric.sample_id) {
            if existing_digest == &digest {
                return Ok(BufferDisposition::Replayed);
            }
            return Err(ObservabilityError::IdentityConflict);
        }
        if self.metrics.len() >= self.limits.max_metrics {
            let gap = ObservabilityGap {
                gap_id: format!("gap:metric:{}", metric.sample_id),
                source_ref: metric
                    .trace
                    .as_ref()
                    .map_or_else(|| "metric-buffer".to_owned(), |trace| trace.adapter_instance_ref.clone()),
                reason_ref: "bounded-metric-capacity".to_owned(),
                first_missing_sequence: metric.trace.as_ref().and_then(|trace| trace.event_cursor),
                last_missing_sequence: metric.trace.as_ref().and_then(|trace| trace.event_cursor),
                protected: false,
                affected_event_kind: None,
            };
            self.append_gap(gap)?;
            return Ok(BufferDisposition::GapRecorded);
        }
        self.metrics.insert(metric.sample_id, (digest, metric));
        Ok(BufferDisposition::Accepted)
    }

    /// Appends a coverage gap, retaining protected gaps even under pressure.
    pub fn append_gap(&mut self, gap: ObservabilityGap) -> Result<BufferDisposition, ObservabilityError> {
        gap.validate()?;
        if self.gaps.contains_key(&gap.gap_id) {
            if self.gaps.get(&gap.gap_id) == Some(&gap) {
                return Ok(BufferDisposition::Replayed);
            }
            return Err(ObservabilityError::IdentityConflict);
        }
        if self.gaps.len() >= self.limits.max_gaps {
            if gap.protected {
                return Err(ObservabilityError::ProtectedCapacityExhausted);
            }
            return Ok(BufferDisposition::GapRecorded);
        }
        self.gaps.insert(gap.gap_id.clone(), gap);
        Ok(BufferDisposition::Accepted)
    }

    /// Returns a deterministic snapshot for an outer durable/audit owner.
    pub fn snapshot(&self) -> ObservabilitySnapshot {
        ObservabilitySnapshot {
            events: self.events.values().map(|(_, event)| event.clone()).collect(),
            metrics: self.metrics.values().map(|(_, metric)| metric.clone()).collect(),
            gaps: self.gaps.values().cloned().collect(),
        }
    }

    /// Rehydrates a bounded projection without silently dropping records.
    pub fn from_snapshot(
        limits: BufferLimits,
        snapshot: ObservabilitySnapshot,
    ) -> Result<Self, ObservabilityError> {
        limits.validate()?;
        snapshot.validate()?;
        if snapshot.events.len() > limits.max_events
            || snapshot.metrics.len() > limits.max_metrics
            || snapshot.gaps.len() > limits.max_gaps
        {
            return Err(ObservabilityError::InvalidField {
                field: "snapshot",
                reason: "snapshot exceeds bounded retention capacities",
            });
        }
        let mut buffer = Self::new(limits)?;
        for event in snapshot.events {
            if buffer.append_event(event)? != BufferDisposition::Accepted {
                return Err(ObservabilityError::IdentityConflict);
            }
        }
        for metric in snapshot.metrics {
            if buffer.append_metric(metric)? != BufferDisposition::Accepted {
                return Err(ObservabilityError::IdentityConflict);
            }
        }
        for gap in snapshot.gaps {
            if buffer.append_gap(gap)? != BufferDisposition::Accepted {
                return Err(ObservabilityError::IdentityConflict);
            }
        }
        Ok(buffer)
    }
}

/// Converts an instrument invocation and normalized run into one concise
/// operational event without treating execution success as proof.
pub fn run_event(
    telemetry: &InstrumentRunTelemetry,
    event_id: impl Into<String>,
    status: EventStatus,
    observed_at: ClockReading,
) -> Result<OperationalEvent, ObservabilityError> {
    telemetry.validate()?;
    let kind = match telemetry.invocation.kind {
        InstrumentKind::Build
        | InstrumentKind::Test
        | InstrumentKind::Lint
        | InstrumentKind::Format => OperationalEventKind::JobResult,
        InstrumentKind::Inspect | InstrumentKind::Verify => OperationalEventKind::Verification,
    };
    let event = OperationalEvent {
        event_id: event_id.into(),
        trace: telemetry.trace.clone(),
        kind,
        priority: if matches!(kind, OperationalEventKind::Verification)
            || telemetry.execution.is_terminal() && kind.is_protected()
        {
            EventPriority::Protected
        } else if telemetry.execution.is_terminal() {
            EventPriority::Normal
        } else {
            EventPriority::Diagnostic
        },
        status,
        observed_at,
        labels: BTreeMap::new(),
        raw_evidence_refs: telemetry.output.raw_evidence_refs.clone(),
        normalized_evidence_refs: telemetry
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect(),
        coverage: telemetry.coverage,
        blind_interval_ref: if matches!(
            telemetry.coverage,
            EvidenceCoverage::PartialForScope | EvidenceCoverage::Unknown
        ) {
            Some(format!("run-coverage:{}", telemetry.run_id))
        } else {
            None
        },
    };
    event.validate()?;
    Ok(event)
}

/// Returns the content-addressed identity of this observability contract.
pub fn contract_identity() -> Result<ContractIdentity, ObservabilityError> {
    foundation_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "trace_context": schemars::schema_for!(TraceContext),
            "operational_event": schemars::schema_for!(OperationalEvent),
            "metric_sample": schemars::schema_for!(MetricSample),
            "instrument_run_telemetry": schemars::schema_for!(InstrumentRunTelemetry),
            "observability_gap": schemars::schema_for!(ObservabilityGap),
            "snapshot": schemars::schema_for!(ObservabilitySnapshot),
        }),
    )
    .map_err(ObservabilityError::Foundation)
}
