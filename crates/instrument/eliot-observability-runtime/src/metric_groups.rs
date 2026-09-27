//! Bounded metric groups for the current execution path (I16.5, issue #1841).
//!
//! I16.1 makes metrics a surface of its own: aggregated performance, health and
//! cost with **bounded labels**. [`OpenMetrics`] already owns the registry, the
//! exposition and the family-wide series bound. This module owns the *catalogue*
//! — which series exist for the current execution path, what each one means, and
//! exactly which of the six accepted label keys it emits — plus the record
//! helpers that write them.
//!
//! # Cardinality is structural, not conventional
//!
//! I16.1 requires bounded labels, and the acceptance clause of issue #1841 is
//! that repeated unique task content must not create new metric-label
//! cardinality. Four properties make that hold by construction rather than by
//! review:
//!
//! 1. **No content parameter exists.** Every helper on [`ExecutionPathMetrics`]
//!    takes typed dimensions only. There is no task id, prompt, user text,
//!    request id, attempt id, error string, or secret anywhere in a record
//!    helper's signature, so a caller holding such a value has nowhere to put it.
//! 2. **Five of the six dimensions are closed sets.** [`BinaryIdentity`],
//!    [`ModuleIdentity`], [`WorkClass`], [`LabelKey`] and each group's outcome
//!    enum are enums, so their value sets are fixed at compile time. The sixth
//!    dimension, [`RouteFingerprintId`], is a validated identifier: its only
//!    constructor rejects a blank value, a value longer than the exporter's
//!    label bound, and any byte outside the exporter's label charset.
//! 3. **The emitted label set is the declared label set.** A helper builds its
//!    labels from its [`MetricDefinition`]'s `label_keys` through
//!    [`LabelKey`], so a group can neither emit a dimension it did not declare
//!    nor declare a dimension it fails to emit.
//! 4. **The registry refuses growth visibly.** Once
//!    [`crate::config::MAX_METRIC_SERIES`] distinct series exist, a new series is
//!    refused with [`MetricError::RegistryFull`] and counted by
//!    [`OpenMetrics::rejected_series`], so even a caller that misuses the route
//!    identifier cannot grow the exposition silently.
//!
//! # What this module deliberately does not do
//!
//! * **Audit is never sampled and is never routed here** (I16.1). The audit and
//!   spool group counts the *delivery stage* of the I16.11 chain, once per
//!   submission, and carries no record identity, detail, or content. The
//!   canonical audit store remains the authority for the decision itself.
//! * **No composite performance score exists, and none can be built here**
//!   (I16.6). Every performance view keeps its axes apart by type:
//!   local-port latency is split into `module_start` and `steady_state` by
//!   [`LocalPortPhase`], the four incidental cost axes stay four fields with no
//!   summing method, and this module exposes no percentile, no quantile, and no
//!   cross-metric aggregator. Percentiles *under contention* are not encoded:
//!   the exporter has no histogram kind and the six accepted keys carry no
//!   contention dimension, so encoding them would need a seventh key.
//! * **Trace completeness is not a boolean** (I16.12). [`TraceCompletenessOutcome`]
//!   names the required part whose absence limits replay, alongside the
//!   fragment's terminal `degraded_no_proof`, and `eliot_trace_missing_parts`
//!   exposes how many parts one trace explicitly listed as missing.
//! * **Usage and cost are not here.** They are stored separately from this
//!   registry, in [`crate::usage_cost`].
//!
//! Normative anchors: I16.1 four surfaces, I16.5 metrics groups, I16.6
//! performance views, I16.9 retention and telemetry cost, I16.11 no hidden
//! telemetry failure, I16.12 trace completeness.

use crate::config::{MAX_METRIC_LABEL_CHARS, RuntimeProfile};
use crate::metrics::{
    METRIC_LABEL_KEYS, METRIC_LABEL_SCHEMA_VERSION, Metric, MetricError, MetricKind, OpenMetrics,
};

/// Number of label dimensions the accepted schema carries.
pub const LABEL_KEY_COUNT: usize = METRIC_LABEL_KEYS.len();

/// The label dimensions [`OpenMetrics`] accepts, as a closed set.
///
/// The derived declaration order is the order of `METRIC_LABEL_KEYS` in
/// [`crate::metrics`], and [`name`](Self::name) returns those exact wire names,
/// so the wire names are written once and the catalogue cannot name a dimension
/// the exporter would refuse. [`crate::usage_cost`] reuses
/// [`RouteFingerprintId`] and [`WorkClass`] from this module for the same reason:
/// it reaches the same bounded dimensions instead of naming label strings of its
/// own.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LabelKey {
    /// `binary`: the shipped bundle binary a sample came from.
    Binary,
    /// `module`: the module or adapter inside that binary.
    Module,
    /// `work_class`: the known I14.1 work class the work was admitted under.
    WorkClass,
    /// `route_fingerprint_id`: the route fingerprint the dispatch selected.
    RouteFingerprintId,
    /// `outcome`: the bounded outcome of the observed event.
    Outcome,
    /// `profile`: the installation profile the process is serving.
    Profile,
}

impl LabelKey {
    /// The wire label name the exporter accepts for this dimension.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Module => "module",
            Self::WorkClass => "work_class",
            Self::RouteFingerprintId => "route_fingerprint_id",
            Self::Outcome => "outcome",
            Self::Profile => "profile",
        }
    }

    /// Every accepted label key, in the schema's declared order.
    #[must_use]
    pub const fn all() -> [Self; LABEL_KEY_COUNT] {
        [
            Self::Binary,
            Self::Module,
            Self::WorkClass,
            Self::RouteFingerprintId,
            Self::Outcome,
            Self::Profile,
        ]
    }
}

/// A bounded route identity: the route fingerprint a dispatch selected.
///
/// This is the only non-enum label dimension in the schema, and it is a bounded
/// identifier rather than free text. Its sole constructor rejects a blank value,
/// a value longer than the exporter's label bound, and any byte outside the
/// exporter's label charset, so it can hold neither a secret-bearing URL nor
/// prompt or user text with spaces and punctuation. The route fingerprint is
/// supplied by dispatch from the route table, never derived from the work
/// content, which is what keeps a repeated-unique-task-content caller from
/// opening a new series through this dimension.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteFingerprintId(String);

impl RouteFingerprintId {
    /// Validates and wraps one route fingerprint identity.
    ///
    /// # Errors
    ///
    /// Returns [`MetricLabelError::BlankRouteFingerprintId`] for an empty value,
    /// [`MetricLabelError::OverBoundRouteFingerprintId`] when it exceeds
    /// `MAX_METRIC_LABEL_CHARS`, and
    /// [`MetricLabelError::UnrenderableRouteFingerprintId`] when it contains a
    /// byte outside the exporter's label-value charset.
    pub fn new(identifier: &str) -> Result<Self, MetricLabelError> {
        if identifier.is_empty() {
            return Err(MetricLabelError::BlankRouteFingerprintId);
        }
        let chars = identifier.chars().count();
        if chars > MAX_METRIC_LABEL_CHARS {
            return Err(MetricLabelError::OverBoundRouteFingerprintId { chars });
        }
        if !identifier.bytes().all(is_label_value_byte) {
            return Err(MetricLabelError::UnrenderableRouteFingerprintId);
        }
        Ok(Self(identifier.to_owned()))
    }

    /// The validated route fingerprint identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed route-identity rejection. No variant carries the rejected value, so a
/// refusal is never itself a disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MetricLabelError {
    /// The route fingerprint value was empty.
    #[error("route fingerprint identity must be non-blank")]
    BlankRouteFingerprintId,
    /// The route fingerprint value exceeded the exporter's label bound.
    #[error("route fingerprint identity exceeds the bounded character count at {chars} characters")]
    OverBoundRouteFingerprintId {
        /// Observed length in characters.
        chars: usize,
    },
    /// The route fingerprint value held a byte the exporter cannot render.
    #[error("route fingerprint identity holds a byte outside the exporter label charset")]
    UnrenderableRouteFingerprintId,
}

/// Returns `true` when `byte` is inside the exporter's label-value charset.
///
/// The exporter applies exactly this rule to every label value; this is the same
/// predicate, so a bounded identifier is refused here rather than silently
/// becoming an invalid label at record time.
pub(crate) const fn is_label_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
}

/// The shipped bundle binaries this runtime is reachable from, as a closed set.
///
/// I16.1 names `binary` as a bounded label dimension, so the binary is a variant
/// rather than a string: the value set is fixed at compile time. Adding a
/// shipped binary is a change to the metric label schema and therefore requires
/// a `METRIC_LABEL_SCHEMA_VERSION` bump, which is what a versioned label schema
/// is for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BinaryIdentity {
    /// The `eliot` launcher binary.
    Launcher,
    /// The `eliot-kernel` control binary.
    Kernel,
    /// The `eliotd` long-running daemon.
    Daemon,
    /// The `eliot-agent-bridge` binary.
    AgentBridge,
    /// The `eliot-doctor` binary.
    Doctor,
    /// The `eliot-dreamer` binary.
    Dreamer,
    /// The `eliot-host` binary.
    Host,
    /// The `eliot-mod-research` binary.
    ModuleResearch,
    /// The `eliot-native-worker` binary.
    NativeWorker,
    /// The `eliot-notify` binary.
    Notify,
    /// The `eliot-store-surreal` binary.
    StoreSurreal,
    /// The `eliot-testd` binary.
    Testd,
    /// The `eliot-user-broker` binary.
    UserBroker,
    /// The `eliot-wasm-host` binary.
    WasmHost,
    /// The `eliot-watchdog` binary.
    Watchdog,
}

impl BinaryIdentity {
    /// The wire binary name carried in the `binary` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Launcher => "eliot",
            Self::Kernel => "eliot-kernel",
            Self::Daemon => "eliotd",
            Self::AgentBridge => "eliot-agent-bridge",
            Self::Doctor => "eliot-doctor",
            Self::Dreamer => "eliot-dreamer",
            Self::Host => "eliot-host",
            Self::ModuleResearch => "eliot-mod-research",
            Self::NativeWorker => "eliot-native-worker",
            Self::Notify => "eliot-notify",
            Self::StoreSurreal => "eliot-store-surreal",
            Self::Testd => "eliot-testd",
            Self::UserBroker => "eliot-user-broker",
            Self::WasmHost => "eliot-wasm-host",
            Self::Watchdog => "eliot-watchdog",
        }
    }

    /// Every shipped bundle binary, in catalogue order.
    #[must_use]
    pub const fn all() -> [Self; 15] {
        [
            Self::Launcher,
            Self::Kernel,
            Self::Daemon,
            Self::AgentBridge,
            Self::Doctor,
            Self::Dreamer,
            Self::Host,
            Self::ModuleResearch,
            Self::NativeWorker,
            Self::Notify,
            Self::StoreSurreal,
            Self::Testd,
            Self::UserBroker,
            Self::WasmHost,
            Self::Watchdog,
        ]
    }
}

/// The module and adapter kinds a sample can come from, as a closed set.
///
/// The eight spellings are the `eliot_types` `ModuleKind` wire spellings, which
/// are the module/adapter taxonomy the Kernel already validates. They are
/// projected here rather than depended on because this crate deliberately
/// carries no dependency on the module registry, so the projection is a mirror
/// and the taxonomy's owner stays upstream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModuleIdentity {
    /// An in-process Rust module of the reporting binary.
    InternalRust,
    /// An MCP stdio adapter module.
    McpStdioAdapter,
    /// A local HTTP adapter module.
    LocalHttpAdapter,
    /// A command-line adapter module.
    CliAdapter,
    /// A verifier adapter module.
    VerifierAdapter,
    /// A candidate agent adapter module.
    CandidateAgentAdapter,
    /// A data-import adapter module.
    DataImportAdapter,
    /// An export adapter module.
    ExportAdapter,
}

impl ModuleIdentity {
    /// The wire module name carried in the `module` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalRust => "internal_rust",
            Self::McpStdioAdapter => "mcp_stdio_adapter",
            Self::LocalHttpAdapter => "local_http_adapter",
            Self::CliAdapter => "cli_adapter",
            Self::VerifierAdapter => "verifier_adapter",
            Self::CandidateAgentAdapter => "candidate_agent_adapter",
            Self::DataImportAdapter => "data_import_adapter",
            Self::ExportAdapter => "export_adapter",
        }
    }

    /// Every module kind, in taxonomy order.
    #[must_use]
    pub const fn all() -> [Self; 8] {
        [
            Self::InternalRust,
            Self::McpStdioAdapter,
            Self::LocalHttpAdapter,
            Self::CliAdapter,
            Self::VerifierAdapter,
            Self::CandidateAgentAdapter,
            Self::DataImportAdapter,
            Self::ExportAdapter,
        ]
    }
}

/// The known work classes a sample can be admitted under, as a closed set.
///
/// The nine spellings are the canonical I14.1 wire spellings in scheduler order:
/// `control` first, then the eight normal classes in I14.1 document order. They
/// are projected here rather than depended on for the same reason as
/// [`ModuleIdentity`]: the taxonomy's owner stays upstream and this crate keeps
/// no dependency on the coordinator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkClass {
    /// Protected control partition admission.
    Control,
    /// Interactive and named-read admission.
    Interactive,
    /// Verification work.
    Verification,
    /// Canonical Store writes.
    CanonicalWrite,
    /// Ordinary background work.
    NormalBackground,
    /// Model-job admission.
    ModelJobs,
    /// Swarm and agent admission.
    Swarm,
    /// Reporting work.
    Reporting,
    /// Maintenance work.
    Maintenance,
}

impl WorkClass {
    /// The wire work-class name carried in the `work_class` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Interactive => "interactive",
            Self::Verification => "verification",
            Self::CanonicalWrite => "canonical_write",
            Self::NormalBackground => "normal_background",
            Self::ModelJobs => "model_jobs",
            Self::Swarm => "swarm",
            Self::Reporting => "reporting",
            Self::Maintenance => "maintenance",
        }
    }

    /// Every work class, in scheduler order.
    #[must_use]
    pub const fn all() -> [Self; 9] {
        [
            Self::Control,
            Self::Interactive,
            Self::Verification,
            Self::CanonicalWrite,
            Self::NormalBackground,
            Self::ModelJobs,
            Self::Swarm,
            Self::Reporting,
            Self::Maintenance,
        ]
    }
}

/// The five subject dimensions every current-execution-path sample carries.
///
/// `outcome` is not a field: I16.5's schema has one `outcome` key, and each
/// group owns its own closed outcome vocabulary, so the outcome is a parameter of
/// the record helper that knows which group it is writing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricSubject {
    /// The shipped bundle binary reporting the sample.
    pub binary: BinaryIdentity,
    /// The module or adapter inside that binary.
    pub module: ModuleIdentity,
    /// The known work class the work was admitted under.
    pub work_class: WorkClass,
    /// The route fingerprint the dispatch selected.
    pub route: RouteFingerprintId,
    /// The installation profile the process is serving.
    pub profile: RuntimeProfile,
}

/// The I16.5 groups this pass encodes for the current execution path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MetricGroup {
    /// I16.5 `process/module/adapter health`.
    ProcessModuleHealth,
    /// I16.5 `restart/quarantine/rollback`; this pass encodes restart and
    /// quarantine.
    RestartQuarantine,
    /// I16.5 `queue depth/age/bytes and WIP admission`; this pass encodes depth
    /// and age.
    QueueDepthAge,
    /// I16.5 `active tasks, attempts, native sessions and children`; this pass
    /// encodes active claims and lease expiry.
    ClaimsLeaseExpiry,
    /// I16.5 `requested vs actual route and route drift`.
    RequestedVsActualRoute,
    /// I16.5 local-port execution outcome and latency for the running
    /// Kernel-daemon path.
    LocalPortExecution,
    /// I16.5 `native worker process-tree, cancellation, orphan and restart
    /// evidence`; this pass encodes cancellation and orphan outcomes.
    CancellationOrphan,
    /// The I16.11 audit/spool fallback chain health for critical records.
    AuditSpoolHealth,
    /// I16.12 trace completeness for a replayable Material/Critical trace.
    TraceCompleteness,
    /// I16.5 `finish outcomes and verifier coverage`.
    VerifierFinish,
}

impl MetricGroup {
    /// Every encoded group, in I16.5 order.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::ProcessModuleHealth,
            Self::RestartQuarantine,
            Self::QueueDepthAge,
            Self::ClaimsLeaseExpiry,
            Self::RequestedVsActualRoute,
            Self::LocalPortExecution,
            Self::CancellationOrphan,
            Self::AuditSpoolHealth,
            Self::TraceCompleteness,
            Self::VerifierFinish,
        ]
    }

    /// The stable group name, matching the I16.5 heading it encodes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessModuleHealth => "process_module_health",
            Self::RestartQuarantine => "restart_quarantine",
            Self::QueueDepthAge => "queue_depth_age",
            Self::ClaimsLeaseExpiry => "claims_lease_expiry",
            Self::RequestedVsActualRoute => "requested_vs_actual_route",
            Self::LocalPortExecution => "local_port_execution",
            Self::CancellationOrphan => "cancellation_orphan",
            Self::AuditSpoolHealth => "audit_spool_health",
            Self::TraceCompleteness => "trace_completeness",
            Self::VerifierFinish => "verifier_finish",
        }
    }
}

/// One catalogue entry: a fixed metric name, its aggregation kind, its help
/// text, the I16.5 group that owns it, and the exact bounded label keys it emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricDefinition {
    /// Exportable metric name.
    pub name: &'static str,
    /// Aggregation semantics of the series.
    pub kind: MetricKind,
    /// Meaning of the series, emitted as the `# HELP` line.
    pub help: &'static str,
    /// The bounded group this series belongs to.
    pub group: MetricGroup,
    /// The exact label keys this series emits.
    pub label_keys: &'static [LabelKey],
}

const BINARY_MODULE_OUTCOME_KEYS: &[LabelKey] = &[
    LabelKey::Binary,
    LabelKey::Module,
    LabelKey::Profile,
    LabelKey::Outcome,
];
const QUEUE_KEYS: &[LabelKey] = &[
    LabelKey::Binary,
    LabelKey::Module,
    LabelKey::WorkClass,
    LabelKey::Profile,
];
const TRACE_KEYS: &[LabelKey] = &[
    LabelKey::Binary,
    LabelKey::Module,
    LabelKey::RouteFingerprintId,
    LabelKey::Profile,
];
const WORK_KEYS: &[LabelKey] = &[
    LabelKey::Binary,
    LabelKey::Module,
    LabelKey::WorkClass,
    LabelKey::RouteFingerprintId,
    LabelKey::Profile,
];
const OUTCOME_WORK_KEYS: &[LabelKey] = &[
    LabelKey::Binary,
    LabelKey::Module,
    LabelKey::WorkClass,
    LabelKey::RouteFingerprintId,
    LabelKey::Outcome,
    LabelKey::Profile,
];

const MODULE_HEALTH: MetricDefinition = MetricDefinition {
    name: "eliot_module_health",
    kind: MetricKind::Gauge,
    help: "current module health state; 1 on the current state, 0 on every other state",
    group: MetricGroup::ProcessModuleHealth,
    label_keys: BINARY_MODULE_OUTCOME_KEYS,
};

const MODULE_LIFECYCLE: MetricDefinition = MetricDefinition {
    name: "eliot_module_lifecycle_total",
    kind: MetricKind::Counter,
    help: "supervised restarts, restart exhaustion and quarantine decisions, one per decision",
    group: MetricGroup::RestartQuarantine,
    label_keys: BINARY_MODULE_OUTCOME_KEYS,
};

const QUEUE_DEPTH: MetricDefinition = MetricDefinition {
    name: "eliot_queue_depth",
    kind: MetricKind::Gauge,
    help: "admitted units currently queued for one work class",
    group: MetricGroup::QueueDepthAge,
    label_keys: QUEUE_KEYS,
};

const QUEUE_OLDEST_AGE: MetricDefinition = MetricDefinition {
    name: "eliot_queue_oldest_age_seconds",
    kind: MetricKind::Gauge,
    help: "age in seconds of the oldest admitted unit still queued for one work class",
    group: MetricGroup::QueueDepthAge,
    label_keys: QUEUE_KEYS,
};

const ACTIVE_CLAIMS: MetricDefinition = MetricDefinition {
    name: "eliot_active_claims",
    kind: MetricKind::Gauge,
    help: "work items currently claimed under this route and work class",
    group: MetricGroup::ClaimsLeaseExpiry,
    label_keys: WORK_KEYS,
};

const LEASE_EXPIRY: MetricDefinition = MetricDefinition {
    name: "eliot_lease_expiry_total",
    kind: MetricKind::Counter,
    help: "work-lease expiries observed, counted once per expiry",
    group: MetricGroup::ClaimsLeaseExpiry,
    label_keys: WORK_KEYS,
};

const ROUTE_DISPATCH: MetricDefinition = MetricDefinition {
    name: "eliot_route_dispatch_total",
    kind: MetricKind::Counter,
    help: "dispatch decisions by requested-versus-actual route relationship",
    group: MetricGroup::RequestedVsActualRoute,
    label_keys: OUTCOME_WORK_KEYS,
};

const LOCAL_PORT_EXECUTIONS: MetricDefinition = MetricDefinition {
    name: "eliot_local_port_executions_total",
    kind: MetricKind::Counter,
    help: "local-port executions by terminal outcome, counted once per execution",
    group: MetricGroup::LocalPortExecution,
    label_keys: OUTCOME_WORK_KEYS,
};

const LOCAL_PORT_LATENCY_MODULE_START: MetricDefinition = MetricDefinition {
    name: "eliot_local_port_latency_module_start_seconds",
    kind: MetricKind::Summary,
    help: "local-port execution seconds at module start, apart from steady state",
    group: MetricGroup::LocalPortExecution,
    label_keys: WORK_KEYS,
};

const LOCAL_PORT_LATENCY_STEADY_STATE: MetricDefinition = MetricDefinition {
    name: "eliot_local_port_latency_steady_state_seconds",
    kind: MetricKind::Summary,
    help: "local-port execution seconds in steady state, apart from module start",
    group: MetricGroup::LocalPortExecution,
    label_keys: WORK_KEYS,
};

const WORK_TERMINATION: MetricDefinition = MetricDefinition {
    name: "eliot_work_termination_total",
    kind: MetricKind::Counter,
    help: "cancellation, orphan detection and orphan reaping outcomes for native work",
    group: MetricGroup::CancellationOrphan,
    label_keys: OUTCOME_WORK_KEYS,
};

const AUDIT_FALLBACK: MetricDefinition = MetricDefinition {
    name: "eliot_audit_fallback_total",
    kind: MetricKind::Counter,
    help: "critical-record submissions by the chain stage that carried them, never sampled",
    group: MetricGroup::AuditSpoolHealth,
    label_keys: BINARY_MODULE_OUTCOME_KEYS,
};

const AUDIT_SPOOL_HEALTH: MetricDefinition = MetricDefinition {
    name: "eliot_audit_spool_health",
    kind: MetricKind::Gauge,
    help: "current audit and spool chain state; 1 on the current stage, 0 on the rest",
    group: MetricGroup::AuditSpoolHealth,
    label_keys: BINARY_MODULE_OUTCOME_KEYS,
};

const TRACE_COMPLETENESS: MetricDefinition = MetricDefinition {
    name: "eliot_trace_completeness_total",
    kind: MetricKind::Counter,
    help: "assessed traces by the required part whose absence limits replay",
    group: MetricGroup::TraceCompleteness,
    label_keys: OUTCOME_WORK_KEYS,
};

const TRACE_MISSING_PARTS: MetricDefinition = MetricDefinition {
    name: "eliot_trace_missing_parts",
    kind: MetricKind::Gauge,
    help: "required trace parts the last assessed trace explicitly listed as missing",
    group: MetricGroup::TraceCompleteness,
    label_keys: TRACE_KEYS,
};

const FINISH_OUTCOMES: MetricDefinition = MetricDefinition {
    name: "eliot_finish_total",
    kind: MetricKind::Counter,
    help: "terminal finish decisions by outcome, counted once per decision",
    group: MetricGroup::VerifierFinish,
    label_keys: OUTCOME_WORK_KEYS,
};

const VERIFIER_COVERAGE: MetricDefinition = MetricDefinition {
    name: "eliot_verifier_coverage",
    kind: MetricKind::Gauge,
    help: "fraction of judged finish decisions in the current reading that a verifier judged",
    group: MetricGroup::VerifierFinish,
    label_keys: WORK_KEYS,
};

const CATALOGUE: &[MetricDefinition] = &[
    MODULE_HEALTH,
    MODULE_LIFECYCLE,
    QUEUE_DEPTH,
    QUEUE_OLDEST_AGE,
    ACTIVE_CLAIMS,
    LEASE_EXPIRY,
    ROUTE_DISPATCH,
    LOCAL_PORT_EXECUTIONS,
    LOCAL_PORT_LATENCY_MODULE_START,
    LOCAL_PORT_LATENCY_STEADY_STATE,
    WORK_TERMINATION,
    AUDIT_FALLBACK,
    AUDIT_SPOOL_HEALTH,
    TRACE_COMPLETENESS,
    TRACE_MISSING_PARTS,
    FINISH_OUTCOMES,
    VERIFIER_COVERAGE,
];

/// Returns the complete current-execution-path metric catalogue.
///
/// Every entry states the metric name, its [`MetricKind`], its help text, the
/// I16.5 group that owns it, and the exact bounded label keys it emits, so a
/// consumer can read the whole label surface of one scrape without recording a
/// sample. The label keys of every entry are members of [`LabelKey`], so the
/// catalogue itself cannot name a seventh dimension.
#[must_use]
pub const fn metric_catalogue() -> &'static [MetricDefinition] {
    CATALOGUE
}

/// Returns the label schema revision this catalogue is written against.
#[must_use]
pub const fn metric_label_schema_version() -> u32 {
    METRIC_LABEL_SCHEMA_VERSION
}

/// The bounded outcome vocabulary of the process/module health group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModuleHealthOutcome {
    /// The module is serving.
    Healthy,
    /// The module is serving with a stated degradation.
    Degraded,
    /// The module is not serving.
    Unavailable,
}

impl ModuleHealthOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }

    /// Every health outcome, in increasing severity.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Healthy, Self::Degraded, Self::Unavailable]
    }
}

/// The bounded outcome vocabulary of the restart/quarantine group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifecycleOutcome {
    /// A supervised restart was performed.
    Restarted,
    /// Restart intensity was exhausted.
    RestartExhausted,
    /// The unit was quarantined.
    Quarantined,
}

impl LifecycleOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restarted => "restarted",
            Self::RestartExhausted => "restart_exhausted",
            Self::Quarantined => "quarantined",
        }
    }

    /// Every lifecycle outcome, in increasing severity.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Restarted, Self::RestartExhausted, Self::Quarantined]
    }
}

/// The bounded outcome vocabulary of the requested-vs-actual-route group.
///
/// I16.5 asks for `requested vs actual route and route drift`. The requested
/// fingerprint is the `route_fingerprint_id` label, so the relationship between
/// requested and actual is exactly this closed outcome: nothing else has to be
/// encoded as a label.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RouteOutcome {
    /// The actual route is the requested route.
    Matched,
    /// The actual route is not the requested route.
    Drifted,
    /// The dispatch exposed a decision but no actual route.
    ActualNotExposed,
}

impl RouteOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Drifted => "drifted",
            Self::ActualNotExposed => "actual_not_exposed",
        }
    }

    /// Every route outcome.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Matched, Self::Drifted, Self::ActualNotExposed]
    }
}

/// The bounded outcome vocabulary of the local-port execution group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocalPortOutcome {
    /// The local port carried the execution.
    Succeeded,
    /// The execution reached the port and did not succeed.
    Failed,
    /// Admission refused the execution before it reached the port.
    Rejected,
}

impl LocalPortOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
        }
    }

    /// Every local-port outcome.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Succeeded, Self::Failed, Self::Rejected]
    }
}

/// I16.6's `module start vs steady state` axis for local-port latency.
///
/// The axis is a type and each variant owns a separate metric name, so a
/// module-start sample can never be summed into a steady-state sample and no
/// reader can pool them without choosing to do so. Neither variant is a
/// percentile and neither carries a contention dimension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LocalPortPhase {
    /// The first execution after the module started.
    ModuleStart,
    /// An execution observed after the module reached steady state.
    SteadyState,
}

impl LocalPortPhase {
    /// The wire phase name, matching the metric name suffix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModuleStart => "module_start",
            Self::SteadyState => "steady_state",
        }
    }

    /// Every phase.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::ModuleStart, Self::SteadyState]
    }
}

/// The bounded outcome vocabulary of the cancellation/orphan group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkTerminationOutcome {
    /// A cancellation reached its terminal state.
    Cancelled,
    /// An orphan was detected.
    OrphanDetected,
    /// An orphan was reaped.
    OrphanReaped,
}

impl WorkTerminationOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::OrphanDetected => "orphan_detected",
            Self::OrphanReaped => "orphan_reaped",
        }
    }

    /// Every termination outcome, in observation order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Cancelled, Self::OrphanDetected, Self::OrphanReaped]
    }
}

/// The bounded outcome vocabulary of the audit/spool health group.
///
/// These are the terminal states of the I16.11 chain, so the group reports the
/// chain rather than any record: `ControlLoss` is the fragment's visible
/// state when no stage carried the record. The canonical audit store stays the
/// authority; nothing here is an audit receipt and nothing here is sampled.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuditSinkOutcome {
    /// The normal audit write carried the record.
    NormalAudit,
    /// The ORS or Watchdog event spool carried the record.
    EventSpool,
    /// The last-resort control slot or Windows Event Log carried the record.
    LastResortEventLog,
    /// No stage carried the record; the visible control-loss state is in force.
    ControlLoss,
}

impl AuditSinkOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalAudit => "normal_audit",
            Self::EventSpool => "event_spool",
            Self::LastResortEventLog => "last_resort_event_log",
            Self::ControlLoss => "control_loss",
        }
    }

    /// Every chain outcome, in the order the chain attempts them.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::NormalAudit,
            Self::EventSpool,
            Self::LastResortEventLog,
            Self::ControlLoss,
        ]
    }
}

/// The bounded outcome vocabulary of the I16.12 trace-completeness group.
///
/// I16.12 names nine required parts of a replayable Material/Critical trace. A
/// completeness assessment is therefore not a boolean: each non-replayable
/// outcome names the required part whose absence limits replay, and
/// `DegradedNoProof` is the fragment's own terminal state for a trace that
/// cannot be replayed. The full list of missing parts stays in the trace record
/// and its size is exposed by `eliot_trace_missing_parts`; neither is a label.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TraceCompletenessOutcome {
    /// Every required part is present, so the trace is replayable.
    Replayable,
    /// The Task/Action contract or State Fence is absent.
    ContractOrStateFenceAbsent,
    /// The Active View or packet manifest is absent.
    ActiveViewManifestAbsent,
    /// The principal, Session, lease or policy snapshot is absent.
    PrincipalSessionLeasePolicySnapshotAbsent,
    /// A tool, model or module call has neither inputs and outputs nor an
    /// immutable handle.
    CallInputsOutputsAbsent,
    /// An external-effect attempt or its observed side effect is absent.
    ExternalEffectEvidenceAbsent,
    /// A verifier or artifact result is absent.
    VerifierArtifactResultAbsent,
    /// A canonical receipt is absent.
    CanonicalReceiptAbsent,
    /// The finish decision is absent.
    FinishDecisionAbsent,
    /// Replay is limited without a single naming part; the fragment's
    /// `DEGRADED_NO_PROOF` state applies.
    DegradedNoProof,
}

impl TraceCompletenessOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replayable => "replayable",
            Self::ContractOrStateFenceAbsent => "contract_or_state_fence_absent",
            Self::ActiveViewManifestAbsent => "active_view_manifest_absent",
            Self::PrincipalSessionLeasePolicySnapshotAbsent => {
                "principal_session_lease_policy_snapshot_absent"
            }
            Self::CallInputsOutputsAbsent => "call_inputs_outputs_absent",
            Self::ExternalEffectEvidenceAbsent => "external_effect_evidence_absent",
            Self::VerifierArtifactResultAbsent => "verifier_artifact_result_absent",
            Self::CanonicalReceiptAbsent => "canonical_receipt_absent",
            Self::FinishDecisionAbsent => "finish_decision_absent",
            Self::DegradedNoProof => "degraded_no_proof",
        }
    }

    /// Every completeness outcome, in I16.12 part order.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::Replayable,
            Self::ContractOrStateFenceAbsent,
            Self::ActiveViewManifestAbsent,
            Self::PrincipalSessionLeasePolicySnapshotAbsent,
            Self::CallInputsOutputsAbsent,
            Self::ExternalEffectEvidenceAbsent,
            Self::VerifierArtifactResultAbsent,
            Self::CanonicalReceiptAbsent,
            Self::FinishDecisionAbsent,
            Self::DegradedNoProof,
        ]
    }

    /// Whether this outcome states that every required part is present.
    #[must_use]
    pub const fn is_replayable(self) -> bool {
        matches!(self, Self::Replayable)
    }
}

/// The bounded outcome vocabulary of the finish group.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FinishOutcome {
    /// A verifier accepted the unit and it was finished.
    Verified,
    /// The unit was finished without a verifier verdict.
    Unverified,
    /// A verifier refuted the unit's claimed result.
    Refuted,
    /// The unit was abandoned without a finish decision.
    Abandoned,
}

impl FinishOutcome {
    /// The wire outcome name carried in the `outcome` label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::Refuted => "refuted",
            Self::Abandoned => "abandoned",
        }
    }

    /// Every finish outcome.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Verified,
            Self::Unverified,
            Self::Refuted,
            Self::Abandoned,
        ]
    }
}

/// Outcome placeholder for a group whose label set does not declare `outcome`.
///
/// [`BoundedLabels`] is built from the definition's declared keys, so the
/// placeholder is never emitted. It is the empty string, which the exporter
/// rejects, so a call that pairs an outcome-less group with an outcome is a typed
/// [`MetricError`] rather than a silent omission.
const NO_OUTCOME: &str = "";

/// A fixed-capacity builder for one sample's bounded label pairs.
///
/// Capacity is the accepted label-key count, so a sample can never carry more
/// pairs than the schema has keys, independent of the exporter's own
/// `MAX_METRIC_LABELS`. Every key is a `&'static str` returned by
/// [`LabelKey::name`], and every value is a `&'static str` from a closed enum or
/// a bounded borrow of a validated identifier, so no value on this path is ever
/// a freshly allocated or unbounded string.
#[derive(Debug)]
struct BoundedLabels<'value> {
    pairs: [(&'static str, &'value str); LABEL_KEY_COUNT],
    len: usize,
}

impl<'value> BoundedLabels<'value> {
    fn new() -> Self {
        Self {
            pairs: [("", ""); LABEL_KEY_COUNT],
            len: 0,
        }
    }

    #[must_use]
    fn with(mut self, key: LabelKey, value: &'value str) -> Self {
        if let Some(slot) = self.pairs.get_mut(self.len) {
            *slot = (key.name(), value);
            self.len = self.len.saturating_add(1);
        }
        self
    }

    fn as_slice(&self) -> &[(&'static str, &'value str)] {
        self.pairs.get(..self.len).unwrap_or_default()
    }
}

/// Builds the label set a definition declares, resolving every dimension from a
/// closed set.
///
/// The `match` is exhaustive over [`LabelKey`], so adding a dimension to the
/// schema fails to compile here until every builder accounts for it.
fn definition_labels<'value>(
    definition: &MetricDefinition,
    subject: &'value MetricSubject,
    outcome: &'static str,
) -> BoundedLabels<'value> {
    let mut labels = BoundedLabels::new();
    for key in definition.label_keys {
        let value: &'value str = match key {
            LabelKey::Binary => subject.binary.as_str(),
            LabelKey::Module => subject.module.as_str(),
            LabelKey::WorkClass => subject.work_class.as_str(),
            LabelKey::RouteFingerprintId => subject.route.as_str(),
            LabelKey::Outcome => outcome,
            LabelKey::Profile => subject.profile.as_str(),
        };
        labels = labels.with(*key, value);
    }
    labels
}

/// Bounded recorder for the current-execution-path metric groups.
///
/// One handle owns the mutable borrow of the registry, so a scrape-time
/// publisher can refresh every gauge it owns without a second owner of the
/// registry. Every helper returns the exporter's own typed verdict: a refused
/// sample is reported, never folded into another series.
#[derive(Debug)]
pub struct ExecutionPathMetrics<'registry> {
    registry: &'registry mut OpenMetrics,
}

impl<'registry> ExecutionPathMetrics<'registry> {
    /// Borrows the registry for bounded recording.
    #[must_use]
    pub fn new(registry: &'registry mut OpenMetrics) -> Self {
        Self { registry }
    }

    /// Records the current health state of one module.
    ///
    /// The gauge emits one series per state, carrying `1` on the state the caller
    /// reported and `0` on every other state of the same module, so a scrape can
    /// never read a stale `1` from a superseded state and the three I16.5 states
    /// are not collapsed into a boolean.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses a sample, including
    /// [`MetricError::RegistryFull`] once the bounded series cardinality is
    /// reached.
    pub fn record_module_health(
        &mut self,
        subject: &MetricSubject,
        outcome: ModuleHealthOutcome,
    ) -> Result<(), MetricError> {
        for candidate in ModuleHealthOutcome::all() {
            let value = if candidate == outcome { 1.0 } else { 0.0 };
            self.record_definition(&MODULE_HEALTH, subject, candidate.as_str(), value)?;
        }
        Ok(())
    }

    /// Records one supervised restart, restart-intensity exhaustion, or
    /// quarantine decision.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_lifecycle(
        &mut self,
        subject: &MetricSubject,
        outcome: LifecycleOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&MODULE_LIFECYCLE, subject, outcome.as_str(), 1.0)
    }

    /// Records the current queue depth for one work class.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_queue_depth(
        &mut self,
        subject: &MetricSubject,
        depth: u32,
    ) -> Result<(), MetricError> {
        self.record_definition(&QUEUE_DEPTH, subject, NO_OUTCOME, f64::from(depth))
    }

    /// Records the age of the oldest admitted unit still queued.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample, including
    /// [`MetricError::NonFiniteValue`] for a non-finite age.
    pub fn record_queue_oldest_age_seconds(
        &mut self,
        subject: &MetricSubject,
        age_seconds: f64,
    ) -> Result<(), MetricError> {
        self.record_definition(&QUEUE_OLDEST_AGE, subject, NO_OUTCOME, age_seconds)
    }

    /// Records the current number of active claims.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_active_claims(
        &mut self,
        subject: &MetricSubject,
        claims: u32,
    ) -> Result<(), MetricError> {
        self.record_definition(&ACTIVE_CLAIMS, subject, NO_OUTCOME, f64::from(claims))
    }

    /// Records one work-lease expiry.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_lease_expiry(&mut self, subject: &MetricSubject) -> Result<(), MetricError> {
        self.record_definition(&LEASE_EXPIRY, subject, NO_OUTCOME, 1.0)
    }

    /// Records one dispatch decision and its relationship between the requested
    /// route fingerprint and the actual one.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_route_dispatch(
        &mut self,
        subject: &MetricSubject,
        outcome: RouteOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&ROUTE_DISPATCH, subject, outcome.as_str(), 1.0)
    }

    /// Records one local-port execution and its terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_local_port_execution(
        &mut self,
        subject: &MetricSubject,
        outcome: LocalPortOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&LOCAL_PORT_EXECUTIONS, subject, outcome.as_str(), 1.0)
    }

    /// Records one local-port execution latency observation under its I16.6
    /// phase.
    ///
    /// The phase selects the metric, so a module-start observation and a
    /// steady-state observation are separate series with separate sample counts.
    /// This is a count and a sum; it is not a percentile, not a quantile, and
    /// not a score.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample, including
    /// [`MetricError::NonFiniteValue`] for a non-finite duration.
    pub fn record_local_port_latency(
        &mut self,
        subject: &MetricSubject,
        phase: LocalPortPhase,
        seconds: f64,
    ) -> Result<(), MetricError> {
        let definition = match phase {
            LocalPortPhase::ModuleStart => &LOCAL_PORT_LATENCY_MODULE_START,
            LocalPortPhase::SteadyState => &LOCAL_PORT_LATENCY_STEADY_STATE,
        };
        self.record_definition(definition, subject, NO_OUTCOME, seconds)
    }

    /// Records one cancellation, orphan detection, or orphan reaping outcome.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_work_termination(
        &mut self,
        subject: &MetricSubject,
        outcome: WorkTerminationOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&WORK_TERMINATION, subject, outcome.as_str(), 1.0)
    }

    /// Records one critical-record submission and the chain stage that carried
    /// it.
    ///
    /// This is a delivery-stage health aggregate, not audit proof: it is counted
    /// once per submission, never sampled, and it carries no record identity,
    /// detail, or content. The canonical audit store remains the authority for
    /// the audited decision itself.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_audit_fallback(
        &mut self,
        subject: &MetricSubject,
        outcome: AuditSinkOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&AUDIT_FALLBACK, subject, outcome.as_str(), 1.0)
    }

    /// Records the current audit and spool chain state.
    ///
    /// As with the health gauge, one series per chain state carries `1` on the
    /// current state and `0` on the others, so the three stages all read `0`
    /// while the `control_loss` state is in force and no stage is credited with
    /// having carried a record that it did not carry.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses a sample.
    pub fn record_audit_spool_health(
        &mut self,
        subject: &MetricSubject,
        outcome: AuditSinkOutcome,
    ) -> Result<(), MetricError> {
        for candidate in AuditSinkOutcome::all() {
            let value = if candidate == outcome { 1.0 } else { 0.0 };
            self.record_definition(&AUDIT_SPOOL_HEALTH, subject, candidate.as_str(), value)?;
        }
        Ok(())
    }

    /// Records one assessed trace and the required part whose absence limits
    /// its replay.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_trace_completeness(
        &mut self,
        subject: &MetricSubject,
        outcome: TraceCompletenessOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&TRACE_COMPLETENESS, subject, outcome.as_str(), 1.0)
    }

    /// Records how many required parts the last assessed trace explicitly listed
    /// as missing.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_trace_missing_parts(
        &mut self,
        subject: &MetricSubject,
        missing: u8,
    ) -> Result<(), MetricError> {
        self.record_definition(
            &TRACE_MISSING_PARTS,
            subject,
            NO_OUTCOME,
            f64::from(missing),
        )
    }

    /// Records one terminal finish decision.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError`] when the registry refuses the sample.
    pub fn record_finish(
        &mut self,
        subject: &MetricSubject,
        outcome: FinishOutcome,
    ) -> Result<(), MetricError> {
        self.record_definition(&FINISH_OUTCOMES, subject, outcome.as_str(), 1.0)
    }

    /// Records verifier coverage over the finish decisions in the current
    /// reading.
    ///
    /// A reading with no judged decision is not a coverage fraction and is not
    /// exported as one.
    ///
    /// # Errors
    ///
    /// Returns [`MetricError::NonFiniteValue`] when `judged` is zero, and
    /// [`MetricError`] when the registry refuses the sample.
    pub fn record_verifier_coverage(
        &mut self,
        subject: &MetricSubject,
        covered: u32,
        judged: u32,
    ) -> Result<(), MetricError> {
        if judged == 0 {
            return Err(MetricError::NonFiniteValue);
        }
        let fraction = f64::from(covered) / f64::from(judged);
        self.record_definition(&VERIFIER_COVERAGE, subject, NO_OUTCOME, fraction)
    }

    fn record_definition(
        &mut self,
        definition: &MetricDefinition,
        subject: &MetricSubject,
        outcome: &'static str,
        value: f64,
    ) -> Result<(), MetricError> {
        let labels = definition_labels(definition, subject, outcome);
        self.registry.record(
            &Metric::new(definition.name, definition.kind, definition.help, value)
                .with_labels(labels.as_slice()),
        )
    }
}
