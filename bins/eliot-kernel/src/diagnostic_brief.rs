//! Kernel problem-diagnostic projection (issue #1844; I16.7).
//!
//! Architecture: A0.4 (insufficient evidence preserves the unknown and
//! selects a probe), A2.2 (a registered bounded repair belongs to the repair
//! owner), A2.3, A13.2 (repeated failure becomes Problem State), ARCH-MOD-01.
//! Implementation: I16.4 (required operational events), I16.7
//! (problem-oriented logging and Diagnostic Brief), I16.9 (retention and
//! telemetry cost), I16.17 (Diagnostic Brief instead of raw log search), and
//! the Kernel-owned durable audit chain of issue #1837.
//!
//! This module is the Kernel's read-only problem-diagnostic projection. It
//! joins the closed canonical audit chain ([`AuditRecord`]) with the bounded
//! operational log windows the caller already captured, and emits one
//! [`DiagnosticBrief`] per problem condition.
//!
//! Two structural properties keep the projection honest:
//!
//! - It carries **references**, never content. A brief holds a
//!   [`LogWindowRef`] (source, process/module generation, time/sequence
//!   range, hash, redaction status, retention) plus a bounded
//!   [`CausalEventRef`] timeline of audit handles. No rolling log body, page,
//!   or dump crosses this boundary, so a full rolling operational log can
//!   never enter canonical state or agent context by default (I16.7).
//! - It never assigns a cause. Correlated changes are carried as
//!   [`ChangeHypothesis`] values, and when the required telemetry does not
//!   exist the brief reports an [`ObservationGap`] naming the exact requested
//!   observation and selects that observation as its one next step, instead of
//!   inventing a diagnosis (I16.7, I16.9).
//!
//! Every brief carries the exact [`StateFence`] observed with the trigger and
//! the closed [`BriefInvalidation`] conditions that actually govern it.
//! Affected scope, trace context, and unknown fields are read from the
//! existing `AuditLineage` owner including its `missing_fields`
//! declarations, and severity is the existing
//! [`AuditEventKind::assurance_class`] I16.9 assurance class. This module
//! therefore adds no second lineage, fence, severity, or lifecycle owner.
//!
//! The brief is also the reader of the replayable trace context. I16.7 joins
//! "exact LogWindowRef/evidence handles" and "unknowns and observation gaps",
//! and I16.12 requires a replayable trace to carry the action contract, State
//! Fence, principal/Session, lease, requested and actual route, call
//! input/output handles, receipts, finish decision, and "missing parts
//! explicitly listed". Those classes already have one durable owner: the sealed
//! [`TraceManifest`] on the same audit chain. [`compile_diagnostic_brief`]
//! replays that body with
//! [`TraceManifest::find_sealed`](crate::trace_manifest::TraceManifest::find_sealed)
//! and serves it whole, so a brief names the exact contract, fence,
//! caller/session, lease, routes, handles, receipt, and finish decision of the
//! operation the condition belongs to. The manifest's own completion gate
//! decides servability; a body that withholds a required part is served as the
//! degraded record it is, and a self-contradicting one is served as nothing, so
//! the brief reports a gap rather than an unqualified trace (I16.12: "Missing
//! trace does not invent failure or success; it limits replay and may force
//! `DEGRADED_NO_PROOF`"). No digest, schema, or completion rule is
//! re-created here: the reader reads, and reports what the record says.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

use super::kernel_audit::{AuditAssuranceClass, AuditEventKind, AuditRecord};
use crate::trace_manifest::TraceManifest;

/// I16.9 redaction status of one bounded operational log window.
///
/// A window is addressable only with its redaction status known: an
/// unestablished status is reported as an observation gap, never assumed
/// clean and never assumed sensitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LogWindowRedaction {
    /// The captured window carries only the bounded nonsecret fields the
    /// diagnostics facade contract admits, so no redaction pass applied.
    #[serde(rename = "NON_SECRET_FIELDS_ONLY")]
    NonSecretFieldsOnly,
    /// A redaction pass ran before the window became addressable; the
    /// referenced digest covers the redacted bytes.
    #[serde(rename = "REDACTED")]
    Redacted,
    /// No redaction disposition is established for the captured bytes.
    #[serde(rename = "UNESTABLISHED")]
    Unestablished,
}

impl LogWindowRedaction {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonSecretFieldsOnly => "NON_SECRET_FIELDS_ONLY",
            Self::Redacted => "REDACTED",
            Self::Unestablished => "UNESTABLISHED",
        }
    }
}

/// I16.9 retention disposition of one bounded operational log window.
///
/// Operational logs carry a rolling policy (I16.9), so a window is
/// addressable only while the rolling file still retains its range. A window
/// whose retention is unestablished is reported as an observation gap; it is
/// never treated as durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LogWindowRetention {
    /// The window is retained under the rolling operational log policy only.
    #[serde(rename = "ROLLING_OPERATIONAL_LOG")]
    RollingOperationalLog,
    /// No retention disposition is established for the window.
    #[serde(rename = "UNESTABLISHED")]
    Unestablished,
}

impl LogWindowRetention {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RollingOperationalLog => "ROLLING_OPERATIONAL_LOG",
            Self::Unestablished => "UNESTABLISHED",
        }
    }
}

/// One bounded operational log window captured for a problem condition.
///
/// This is an **input**: the caller that owns the operational log source
/// captures the bounded window and hands its exact identity here. The
/// projection derives a [`LogWindowRef`] from it and never retains the window
/// bytes, so no window content can leak into canonical state or agent context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedLogWindow {
    /// Exact operational log source identity that produced the window.
    pub source: String,
    /// Process/module generation the window belongs to.
    pub process_generation: String,
    /// First window sequence (inclusive).
    pub sequence_from: u64,
    /// Last window sequence (inclusive).
    pub sequence_to: u64,
    /// Wall-clock start of the window in unix milliseconds.
    pub started_at_ms: u64,
    /// Wall-clock end of the window in unix milliseconds.
    pub ended_at_ms: u64,
    /// Digest over the exact window bytes.
    pub window_sha256: String,
    /// I16.9 redaction status of the captured window.
    pub redaction: LogWindowRedaction,
    /// I16.9 retention disposition of the captured window.
    pub retention: LogWindowRetention,
}

/// The exact bounded operational log window a brief points at (I16.7).
///
/// Records the source/process generation, the time and sequence range, the
/// hash, the redaction status, and the retention of one captured window. The
/// struct has no field able to carry log content: an agent following the
/// reference reads the window at its owner, under the owner's retention.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogWindowRef {
    /// Exact operational log source identity that produced the window.
    pub source: String,
    /// Process/module generation the window belongs to.
    pub process_generation: String,
    /// First window sequence (inclusive).
    pub sequence_from: u64,
    /// Last window sequence (inclusive).
    pub sequence_to: u64,
    /// Wall-clock start of the window in unix milliseconds.
    pub started_at_ms: u64,
    /// Wall-clock end of the window in unix milliseconds.
    pub ended_at_ms: u64,
    /// Digest over the exact window bytes.
    pub window_sha256: String,
    /// I16.9 redaction status of the captured window.
    pub redaction: LogWindowRedaction,
    /// I16.9 retention disposition of the captured window.
    pub retention: LogWindowRetention,
}

impl LogWindowRef {
    /// Projects one captured bounded window into its exact reference.
    ///
    /// The reference is a pure projection: it copies the captured identity and
    /// disposition fields and retains no window content.
    #[must_use]
    pub fn from_window(window: &BoundedLogWindow) -> Self {
        Self {
            source: window.source.clone(),
            process_generation: window.process_generation.clone(),
            sequence_from: window.sequence_from,
            sequence_to: window.sequence_to,
            started_at_ms: window.started_at_ms,
            ended_at_ms: window.ended_at_ms,
            window_sha256: window.window_sha256.clone(),
            redaction: window.redaction,
            retention: window.retention,
        }
    }
}

/// The closed I16.7 diagnostic-compilation trigger classes.
///
/// These are the six triggers I16.7 names. The Kernel compiles a brief only
/// for a condition its canonical audit chain actually records; the classes the
/// Kernel chain cannot represent stay reachable and are reported as an
/// observation gap rather than silently mapped onto a recorded event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DiagnosticTrigger {
    /// Problem opened/updated.
    #[serde(rename = "PROBLEM_OPENED_OR_UPDATED")]
    ProblemOpenedOrUpdated,
    /// Repeated failure/no-progress.
    #[serde(rename = "REPEATED_FAILURE_OR_NO_PROGRESS")]
    RepeatedFailureOrNoProgress,
    /// Module crash or restart exhaustion.
    #[serde(rename = "MODULE_CRASH_OR_RESTART_EXHAUSTION")]
    ModuleCrashOrRestartExhaustion,
    /// Security/integration gap.
    #[serde(rename = "SECURITY_OR_INTEGRATION_GAP")]
    SecurityOrIntegrationGap,
    /// User/agent request.
    #[serde(rename = "USER_OR_AGENT_REQUEST")]
    UserOrAgentRequest,
    /// Release/canary failure.
    #[serde(rename = "RELEASE_OR_CANARY_FAILURE")]
    ReleaseOrCanaryFailure,
}

impl DiagnosticTrigger {
    /// Every I16.7 trigger class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ProblemOpenedOrUpdated,
        Self::RepeatedFailureOrNoProgress,
        Self::ModuleCrashOrRestartExhaustion,
        Self::SecurityOrIntegrationGap,
        Self::UserOrAgentRequest,
        Self::ReleaseOrCanaryFailure,
    ];

    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProblemOpenedOrUpdated => "PROBLEM_OPENED_OR_UPDATED",
            Self::RepeatedFailureOrNoProgress => "REPEATED_FAILURE_OR_NO_PROGRESS",
            Self::ModuleCrashOrRestartExhaustion => "MODULE_CRASH_OR_RESTART_EXHAUSTION",
            Self::SecurityOrIntegrationGap => "SECURITY_OR_INTEGRATION_GAP",
            Self::UserOrAgentRequest => "USER_OR_AGENT_REQUEST",
            Self::ReleaseOrCanaryFailure => "RELEASE_OR_CANARY_FAILURE",
        }
    }

    /// Classifies one closed canonical audit kind into its trigger class.
    ///
    /// Returns `None` for a kind that is not a problem trigger, and for the
    /// two classes the Kernel audit chain has no canonical event for
    /// ([`Self::UserOrAgentRequest`], [`Self::ReleaseOrCanaryFailure`]). An
    /// unrepresentable class is reported as an observation gap by the
    /// compiler; it is never approximated by a neighbouring record.
    #[must_use]
    pub fn from_audit_kind(kind: &str) -> Option<Self> {
        match kind {
            AuditEventKind::PROCESS_DEGRADED => Some(Self::ProblemOpenedOrUpdated),
            // The progress route emits this only after the stale-miss horizon
            // expired the lease, that is, after repeated blocked renewals.
            AuditEventKind::LEASE_SUPERVISION_EXPIRED => Some(Self::RepeatedFailureOrNoProgress),
            AuditEventKind::PROCESS_FAILED | AuditEventKind::PROCESS_LAUNCH_FAILED => {
                Some(Self::ModuleCrashOrRestartExhaustion)
            }
            AuditEventKind::RESULT_STALE_QUARANTINED | AuditEventKind::ORPHAN_CONNECTION_FENCED => {
                Some(Self::SecurityOrIntegrationGap)
            }
            _ => None,
        }
    }
}

/// The exact bounded canonical audit range one brief may read.
///
/// The bound is the caller's, never a constant of this module: a brief is
/// compiled from one declared window, so a full rolling audit history can
/// never be projected by default (I16.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticWindow {
    /// First canonical audit sequence in the window (inclusive, 1-based).
    pub first_audit_seq: u64,
    /// Last canonical audit sequence in the window (inclusive).
    pub last_audit_seq: u64,
}

/// One problem condition handed to the compiler.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticProblem {
    /// Closed I16.7 trigger class the observed condition belongs to.
    pub trigger: DiagnosticTrigger,
    /// The exact bounded canonical audit window the brief may read.
    pub window: DiagnosticWindow,
    /// Bounded operational log windows already captured for the condition.
    /// Empty is a legal, reported state: it becomes an observation gap.
    pub log_windows: Vec<BoundedLogWindow>,
}

/// One causal event of the bounded timeline, as an exact audit handle.
///
/// The timeline carries sequence, time, kind, and the record's own digests.
/// It never carries the record body: the body stays in the canonical chain at
/// the digest, so a brief stays bounded however long the window is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEventRef {
    /// 1-based canonical audit sequence of the record.
    pub audit_seq: u64,
    /// Wall-clock milliseconds when the boundary appended the record.
    pub emitted_at_ms: u64,
    /// Closed canonical audit kind.
    pub audit_kind: String,
    /// Digest of the canonical event body; the body stays in the chain.
    pub event_digest: String,
    /// Hash-covered record handle: the exact immutable evidence handle.
    pub current_hash: String,
    /// I16.9 assurance class of the record.
    pub assurance: AuditAssuranceClass,
    /// Actual route receipt when the record binds one.
    pub route_receipt_actual: Option<String>,
}

impl CausalEventRef {
    fn from_record(record: &AuditRecord) -> Self {
        Self {
            audit_seq: record.seq,
            emitted_at_ms: record.emitted_at_ms,
            audit_kind: record.kind.clone(),
            event_digest: record.event_digest.clone(),
            current_hash: record.current_hash.clone(),
            assurance: record.assurance,
            route_receipt_actual: record.lineage.route_receipt_actual.clone(),
        }
    }
}

/// The affected trace/work scope, read from the existing `AuditLineage` owner.
///
/// `unknown_fields` is the lineage's own `missing_fields` declaration
/// (I16.12): the brief reports the absent slots instead of guessing them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedScope {
    /// Request-scoped trace identity.
    pub trace_id: Option<String>,
    /// Governor-owned task identity.
    pub task_id: Option<String>,
    /// Governor-owned `WorkScope` identity.
    pub work_scope: Option<String>,
    /// Queued work-item handle.
    pub work_item: Option<String>,
    /// Kernel operation handle.
    pub operation_id: Option<String>,
    /// Durable semantic session identity.
    pub session_id: Option<String>,
    /// Governed attempt identity.
    pub attempt_id: Option<String>,
    /// Durable job identity.
    pub job_id: Option<String>,
    /// Lease under which the work runs.
    pub environment_lease: Option<String>,
    /// Executor-observed process identity.
    pub process_identity: Option<String>,
    /// Module/process generation text.
    pub module_generation: Option<String>,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: Option<String>,
    /// Executing controller leg.
    pub controller: Option<String>,
    /// I16.3 lineage slots with no observed value for the trigger record.
    pub unknown_fields: Vec<String>,
}

/// One correlated code/config/module-generation change, carried strictly as a
/// hypothesis.
///
/// I16.7: correlation is a hypothesis until an intervention or a verifier
/// observes it. The audit chain proves co-occurrence and order, never cause,
/// so the type itself is the hypothesis marker and no verified variant exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeHypothesis {
    /// Canonical audit sequence that carries the correlated change.
    pub audit_seq: u64,
    /// Closed canonical audit kind of the change record.
    pub audit_kind: String,
    /// Digest/identity-only change detail; content stays in the chain.
    pub detail: serde_json::Value,
}

/// One dependency relation the bounded window proves.
///
/// The relation is the exact module generation and authority epoch that
/// produced the window's records, plus any route divergence the window shows
/// (I16.4 route mismatch). It is derived, never asserted from prose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRelation {
    /// Executing controller leg.
    pub controller: String,
    /// Module/process generation text.
    pub module_generation: String,
    /// Authority epoch `lineage_id:sequence` text.
    pub authority_epoch: String,
    /// First requested-capability versus actual-route-receipt divergence.
    pub route_divergence: Option<RouteDivergence>,
}

/// One observed capability route mismatch inside the window.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDivergence {
    /// Canonical audit sequence that recorded the divergence.
    pub audit_seq: u64,
    /// Requested capability.
    pub requested: String,
    /// Actual route receipt bound by the record.
    pub actual: String,
}

/// The symptom and severity the compiler observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSymptom {
    /// Closed I16.7 trigger class of the observed condition.
    pub trigger: DiagnosticTrigger,
    /// Closed canonical audit kind of the trigger record.
    pub audit_kind: String,
    /// Canonical audit sequence of the trigger record.
    pub observed_at_audit_seq: u64,
    /// Wall-clock milliseconds when the trigger record was appended.
    pub emitted_at_ms: u64,
    /// I16.9 assurance class of the trigger record, used as severity.
    pub severity: AuditAssuranceClass,
}

/// Closed required-observation gap codes.
///
/// A gap names telemetry I16.4 requires and the brief does not hold. Missing
/// telemetry stays missing: it is never read as evidence that no event
/// occurred (I16.9).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObservationGapCode {
    /// No bounded operational log window was captured for the condition.
    #[serde(rename = "LOG_WINDOW_ABSENT")]
    LogWindowAbsent,
    /// A captured window's redaction status is unestablished.
    #[serde(rename = "LOG_WINDOW_REDACTION_UNESTABLISHED")]
    LogWindowRedactionUnestablished,
    /// A captured window's retention disposition is unestablished.
    #[serde(rename = "LOG_WINDOW_RETENTION_UNESTABLISHED")]
    LogWindowRetentionUnestablished,
    /// The trigger claims recurrence but the window holds one occurrence.
    #[serde(rename = "TRIGGER_RECURRENCE_UNOBSERVED")]
    TriggerRecurrenceUnobserved,
    /// The Kernel audit chain has no canonical event for the trigger class.
    #[serde(rename = "TRIGGER_CLASS_NOT_IN_CANONICAL_AUDIT")]
    TriggerClassNotInCanonicalAudit,
    /// The trigger record names no trace identity or `WorkScope`.
    #[serde(rename = "AFFECTED_SCOPE_UNATTRIBUTED")]
    AffectedScopeUnattributed,
    /// No generation or authority-epoch change is present to correlate.
    #[serde(rename = "GENERATION_CHANGE_NOT_CORRELATED")]
    GenerationChangeNotCorrelated,
    /// No prior repair or renewal record is present in the window.
    #[serde(rename = "PRIOR_REPAIR_NOT_IN_WINDOW")]
    PriorRepairNotInWindow,
    /// The operation the condition belongs to has no sealed trace manifest the
    /// replay read may serve, so the I16.12 classes cannot be identified
    /// (issue #1838).
    #[serde(rename = "REPLAYABLE_TRACE_UNSERVABLE")]
    ReplayableTraceUnservable,
}

impl ObservationGapCode {
    /// Every gap code, ordered cheapest-to-close first.
    ///
    /// The order is the brief's next-step order: a further observation that
    /// only needs a capture is cheaper than one that needs a canonical event,
    /// so the first gap is the cheapest useful probe.
    pub const ALL: &'static [Self] = &[
        Self::LogWindowAbsent,
        Self::LogWindowRedactionUnestablished,
        Self::LogWindowRetentionUnestablished,
        Self::TriggerRecurrenceUnobserved,
        Self::TriggerClassNotInCanonicalAudit,
        Self::AffectedScopeUnattributed,
        Self::GenerationChangeNotCorrelated,
        Self::PriorRepairNotInWindow,
        Self::ReplayableTraceUnservable,
    ];

    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LogWindowAbsent => "LOG_WINDOW_ABSENT",
            Self::LogWindowRedactionUnestablished => "LOG_WINDOW_REDACTION_UNESTABLISHED",
            Self::LogWindowRetentionUnestablished => "LOG_WINDOW_RETENTION_UNESTABLISHED",
            Self::TriggerRecurrenceUnobserved => "TRIGGER_RECURRENCE_UNOBSERVED",
            Self::TriggerClassNotInCanonicalAudit => "TRIGGER_CLASS_NOT_IN_CANONICAL_AUDIT",
            Self::AffectedScopeUnattributed => "AFFECTED_SCOPE_UNATTRIBUTED",
            Self::GenerationChangeNotCorrelated => "GENERATION_CHANGE_NOT_CORRELATED",
            Self::PriorRepairNotInWindow => "PRIOR_REPAIR_NOT_IN_WINDOW",
            Self::ReplayableTraceUnservable => "REPLAYABLE_TRACE_UNSERVABLE",
        }
    }

    /// Returns the exact observation that would close this gap.
    #[must_use]
    pub const fn required_observation(self) -> &'static str {
        match self {
            Self::LogWindowAbsent => {
                "bounded operational log window for the trigger source and process generation"
            }
            Self::LogWindowRedactionUnestablished => {
                "redaction disposition of the captured operational log window"
            }
            Self::LogWindowRetentionUnestablished => {
                "retention disposition of the captured operational log window"
            }
            Self::TriggerRecurrenceUnobserved => {
                "second canonical audit record of the same trigger class inside the bounded window"
            }
            Self::TriggerClassNotInCanonicalAudit => {
                "canonical audit event for this I16.7 trigger class"
            }
            Self::AffectedScopeUnattributed => {
                "audit lineage trace_id and work_scope for the trigger record"
            }
            Self::GenerationChangeNotCorrelated => {
                "generation or authority-epoch change record inside the bounded window"
            }
            Self::PriorRepairNotInWindow => {
                "prior repair or renewal record inside the bounded window"
            }
            Self::ReplayableTraceUnservable => {
                "trace.manifest_sealed record for the condition's operation_id, carrying the \
                 required I16.12 evidence classes"
            }
        }
    }
}

/// One required observation the brief could not satisfy.
///
/// A gap is not a cause and never blocks the brief: it is the honest record of
/// which I16.4 telemetry is missing and what would supply it (I16.7).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationGap {
    /// Closed gap code.
    pub code: ObservationGapCode,
    /// The exact observation that would close this gap.
    pub required_observation: String,
}

impl ObservationGap {
    /// Builds one gap with its required observation kept in step with `code`.
    #[must_use]
    pub fn new(code: ObservationGapCode) -> Self {
        Self {
            code,
            required_observation: code.required_observation().to_owned(),
        }
    }
}

/// The closed classes of the single next step a brief selects.
///
/// A read-only projection never performs a repair: registered bounded repairs
/// belong to the repair owner (A2.2), so the closed set is one further
/// observation or an escalation to that owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NextActionKind {
    /// One further observation that discriminates the retained hypotheses.
    #[serde(rename = "PROBE")]
    Probe,
    /// Escalation to the owner of the next authority epoch.
    #[serde(rename = "ESCALATE")]
    Escalate,
}

impl NextActionKind {
    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "PROBE",
            Self::Escalate => "ESCALATE",
        }
    }
}

/// The single cheapest useful next observation, repair, or escalation.
///
/// Exactly one is selected. A brief that still holds an observation gap probes
/// the cheapest one; a brief with no gap escalates, because the evidence is
/// then complete enough to act on (A0.4).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextAction {
    /// Closed action class.
    pub kind: NextActionKind,
    /// The gap this action closes; present for a probe, absent otherwise.
    pub closes: Option<ObservationGapCode>,
    /// Canonical audit sequence of the trigger record the action acts on.
    pub target_audit_seq: u64,
}

/// Closed conditions that invalidate a compiled brief.
///
/// A brief is valid only while its exact State Fence still authorizes, its
/// audit window is still the head of the retained chain, and every window it
/// references is still retained (I16.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BriefInvalidation {
    /// A different authority epoch or resource generation is now observed.
    #[serde(rename = "STATE_FENCE_SUPERSEDED")]
    StateFenceSuperseded,
    /// A canonical audit record was appended after the compiled window head.
    #[serde(rename = "AUDIT_CHAIN_ADVANCED")]
    AuditChainAdvanced,
    /// A referenced bounded log window is no longer retained.
    #[serde(rename = "LOG_WINDOW_NOT_RETAINED")]
    LogWindowNotRetained,
}

impl BriefInvalidation {
    /// Every closed invalidation condition, in the order
    /// [`BriefStateFence::observe_invalidation`] checks them.
    ///
    /// This is the one list the brief's declared
    /// `invalidation_conditions` is filled from, so the set a brief declares
    /// is exactly the set the reader evaluates: a brief can no longer name one
    /// arm while being governed by all three (I16.7: a brief has a State Fence
    /// and an invalidation condition).
    pub const ALL: &'static [Self] = &[
        Self::StateFenceSuperseded,
        Self::AuditChainAdvanced,
        Self::LogWindowNotRetained,
    ];

    /// Returns the stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateFenceSuperseded => "STATE_FENCE_SUPERSEDED",
            Self::AuditChainAdvanced => "AUDIT_CHAIN_ADVANCED",
            Self::LogWindowNotRetained => "LOG_WINDOW_NOT_RETAINED",
        }
    }
}

/// The brief's State Fence and the conditions that invalidate it.
///
/// The declared `invalidation_conditions` is the closed set
/// [`BriefStateFence::observe_invalidation`] actually evaluates, not a
/// single representative arm: the compiler cannot know which of the three
/// fires first, so declaring one of them would be a claim it has not
/// observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BriefStateFence {
    /// Exact State Fence observed with the trigger decision.
    pub state_fence: StateFence,
    /// Canonical audit sequence the brief's evidence was compiled from.
    pub compiled_at_audit_seq: u64,
    /// Closed invalidation conditions, in the order they are checked.
    pub invalidation_conditions: Vec<BriefInvalidation>,
}

impl BriefStateFence {
    /// Returns the invalidation condition currently observed, if any.
    ///
    /// The conditions are checked cheapest-first so the reported one is
    /// stable. A superseding authority epoch outranks a chain advance, because
    /// a new epoch invalidates every decision taken under the old one
    /// regardless of what else moved (I1.5, I16.7).
    ///
    /// The checked set is exactly
    /// [`BriefStateFence::invalidation_conditions`], which the compiler fills
    /// from [`BriefInvalidation::ALL`]: a reader and a serialized brief can
    /// never disagree about which conditions govern it. `log_windows_retained`
    /// is the caller's observed answer for the referenced windows, never a
    /// constant.
    #[must_use]
    pub fn observe_invalidation(
        &self,
        current_state_fence: &StateFence,
        current_audit_head_seq: u64,
        log_windows_retained: bool,
    ) -> Option<BriefInvalidation> {
        if !current_state_fence.is_compatible_with(&self.state_fence) {
            return Some(BriefInvalidation::StateFenceSuperseded);
        }
        if current_audit_head_seq > self.compiled_at_audit_seq {
            return Some(BriefInvalidation::AuditChainAdvanced);
        }
        if !log_windows_retained {
            return Some(BriefInvalidation::LogWindowNotRetained);
        }
        None
    }
}

/// One compiled problem-diagnostic brief (I16.7).
///
/// The brief joins the symptom and severity, the affected trace/work scope,
/// the bounded causal event timeline from the canonical audit chain, the exact
/// bounded `LogWindowRef` references, the correlated change hypotheses, the
/// dependency relations, the prior failures and attempted repairs, the
/// unknowns, the observation gaps, and exactly one next step — all under one
/// State Fence and one invalidation condition. It never carries a cause, and
/// it never carries rolling log content.
///
/// The I16.12 replayable trace context is joined whole: [`Self::trace_replay`]
/// is the sealed [`TraceManifest`] of the condition's operation exactly as the
/// canonical chain recorded it, never a projection of counts over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBrief {
    /// Symptom and severity observed on the canonical audit chain.
    pub symptom: DiagnosticSymptom,
    /// Affected Module/WorkScope/tasks read from the trigger lineage.
    pub affected_scope: AffectedScope,
    /// Bounded causal timeline, in canonical audit sequence order.
    pub causal_timeline: Vec<CausalEventRef>,
    /// Exact bounded operational log windows the brief points at.
    pub log_window_refs: Vec<LogWindowRef>,
    /// Correlated changes, carried strictly as hypotheses.
    pub change_hypotheses: Vec<ChangeHypothesis>,
    /// Dependency relations the bounded window proves.
    pub dependencies: Vec<DependencyRelation>,
    /// Earlier failure records inside the window, before the trigger record.
    pub prior_failures: Vec<CausalEventRef>,
    /// Attempted repair or renewal records inside the window.
    pub attempted_repairs: Vec<CausalEventRef>,
    /// I16.3 lineage slots with no observed value for the trigger record.
    pub unknowns: Vec<String>,
    /// The replayed I16.12 trace context of the condition's operation, read
    /// back from the canonical audit chain; `None` when no sealed body is
    /// servable, which is itself reported as
    /// [`ObservationGapCode::ReplayableTraceUnservable`].
    pub trace_replay: Option<TraceManifest>,
    /// Required observations the brief could not satisfy.
    pub observation_gaps: Vec<ObservationGap>,
    /// The single cheapest useful next step.
    pub next_action: NextAction,
    /// State Fence and invalidation condition for the whole brief.
    pub fence: BriefStateFence,
}

impl DiagnosticBrief {
    /// Returns whether the brief reports a gap instead of a diagnosis.
    ///
    /// Always false for a brief with no observation gap. A brief with a gap
    /// names what is missing and what would supply it; it never stands in for
    /// a cause (I16.7).
    #[must_use]
    pub fn reports_gap_not_cause(&self) -> bool {
        !self.observation_gaps.is_empty()
    }

    /// Returns the replayed I16.12 trace context of the condition's operation.
    ///
    /// The body is served exactly as the canonical chain sealed it, so the
    /// action contract, State Fence, caller/session, lease, requested and
    /// actual route, call input/output handles, result receipt, finish
    /// decision, and explicit missing parts are the recorded ones. `None` means
    /// no sealed body was servable, never an invented one (issue #1838).
    #[must_use]
    pub fn trace_replay(&self) -> Option<&TraceManifest> {
        self.trace_replay.as_ref()
    }

    /// Returns whether the replayed trace is a proof-bearing complete one.
    ///
    /// The gate is the manifest's own recorded finish decision
    /// ([`crate::trace_manifest::TraceFinish::is_complete`]), not a
    /// re-derivation: the replay read already refused every body whose recorded
    /// completion claim the recorded required slots do not carry, so a manifest
    /// this brief holds is complete exactly when the record says so. A manifest
    /// that withheld a required part is reported with its missing parts and
    /// never as complete (I16.12).
    #[must_use]
    pub fn replay_is_complete(&self) -> bool {
        self.trace_replay
            .as_ref()
            .is_some_and(|replay| replay.finish.is_complete())
    }

    /// Returns the required I16.12 classes the replayed trace reports missing.
    ///
    /// The list is the manifest's own explicit missing-parts list, carried
    /// through unchanged: the reader never recomputes it from a partial view.
    #[must_use]
    pub fn replay_missing_parts(&self) -> &[String] {
        self.trace_replay
            .as_ref()
            .map_or(&[], |replay| replay.missing_parts.as_slice())
    }
}

/// Typed refusals of the diagnostic compiler.
///
/// Every refusal is a claim the canonical evidence does not support, so the
/// compiler emits no brief rather than a partial diagnosis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticBriefError {
    /// The declared window is empty or inverted.
    EmptyWindow,
    /// The supplied records are not a gapless canonical audit sequence.
    ChainNotContiguous {
        /// Sequence position that broke the gapless order.
        audit_seq: u64,
    },
    /// The declared window is outside the supplied records.
    WindowOutsideChain {
        /// Declared window head sequence.
        audit_seq: u64,
        /// Highest sequence present in the supplied records.
        chain_head_seq: u64,
    },
    /// The window head record's kind does not belong to the trigger class.
    TriggerNotObserved {
        /// Closed canonical audit kind of the window head.
        audit_kind: String,
        /// Declared trigger class.
        trigger: DiagnosticTrigger,
    },
    /// The trigger record carries no State Fence, so no brief can be fenced.
    TriggerStateFenceAbsent {
        /// Canonical audit sequence of the unfenced trigger record.
        audit_seq: u64,
    },
    /// A captured log window is not a forward, non-empty range.
    LogWindowRangeInvalid {
        /// Operational log source identity of the invalid window.
        source: String,
    },
}

impl std::fmt::Display for DiagnosticBriefError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyWindow => formatter.write_str("diagnostic window is empty or inverted"),
            Self::ChainNotContiguous { audit_seq } => {
                write!(
                    formatter,
                    "audit chain is not contiguous at seq {audit_seq}"
                )
            }
            Self::WindowOutsideChain {
                audit_seq,
                chain_head_seq,
            } => write!(
                formatter,
                "diagnostic window head {audit_seq} is outside the supplied chain head {chain_head_seq}"
            ),
            Self::TriggerNotObserved {
                audit_kind,
                trigger,
            } => write!(
                formatter,
                "audit kind {audit_kind} is not a {} trigger",
                trigger.as_str()
            ),
            Self::TriggerStateFenceAbsent { audit_seq } => write!(
                formatter,
                "trigger record at seq {audit_seq} carries no state fence"
            ),
            Self::LogWindowRangeInvalid { source } => {
                write!(formatter, "log window {source} has an invalid range")
            }
        }
    }
}

impl std::error::Error for DiagnosticBriefError {}

/// Audit kinds that record a bounded recovery attempt or renewal.
const REPAIR_KINDS: &[&str] = &[
    AuditEventKind::LEASE_SUPERVISION_ESTABLISHED,
    AuditEventKind::LEASE_SUPERVISION_RENEWED,
    AuditEventKind::PROCESS_LAUNCH_COMMITTED,
    AuditEventKind::RECEIPT_LIVE_PUBLISHED,
    AuditEventKind::RESULT_KERNEL_BOUND,
];

/// Audit kinds that record a generation or authority-epoch change.
const GENERATION_CHANGE_KINDS: &[&str] = &[
    AuditEventKind::EPOCH_CUTOVER_APPLIED,
    AuditEventKind::PROCESS_LAUNCH_COMMITTED,
];

/// Compiles one problem-diagnostic brief from the canonical audit chain and
/// the bounded operational log windows the caller captured (I16.7).
///
/// `records` is the retained canonical audit chain exactly as
/// `KernelComposition::audit_chain_records` returns it: a gapless, verified
/// sequence whose head is the chain head. `problem` declares the closed
/// trigger class, the exact bounded window the brief may read, and the
/// captured windows.
///
/// The window head record is the condition itself. The brief is refused when
/// the chain does not actually record that condition under the declared class,
/// when the window is not a bounded range of the supplied chain, or when the
/// trigger record carries no State Fence. A refused compilation yields no
/// brief, never a partially attributed cause.
///
/// The brief also replays the I16.12 trace context of the condition's
/// operation from the same supplied chain (issue #1838). The read is the
/// manifest owner's own
/// [`TraceManifest::find_sealed`](crate::trace_manifest::TraceManifest::find_sealed),
/// so the recorded completion gate decides servability and this module
/// re-implements no completion rule.
pub fn compile_diagnostic_brief(
    records: &[AuditRecord],
    problem: &DiagnosticProblem,
) -> Result<DiagnosticBrief, DiagnosticBriefError> {
    let selected = select_window(records, problem.window)?;
    let trigger = &selected[selected.len() - 1];
    verify_declared_trigger(trigger, problem.trigger)?;
    let state_fence = trigger.lineage.state_fence.clone().ok_or(
        DiagnosticBriefError::TriggerStateFenceAbsent {
            audit_seq: trigger.seq,
        },
    )?;
    let log_window_refs = project_log_window_refs(&problem.log_windows)?;
    let attempted_repairs = family_events(selected, REPAIR_KINDS);
    let prior_failures = prior_failure_events(selected, trigger.seq);
    let change_hypotheses = correlated_change_hypotheses(selected);
    let affected_scope = project_affected_scope(trigger);
    let unknowns = affected_scope.unknown_fields.clone();
    let trace_replay = read_sealed_trace_replay(records, affected_scope.operation_id.as_deref());
    let observation_gaps = observation_gaps(
        selected,
        &log_window_refs,
        problem.trigger,
        &affected_scope,
        &change_hypotheses,
        &attempted_repairs,
        trace_replay.as_ref(),
    );
    Ok(DiagnosticBrief {
        symptom: project_symptom(trigger, problem.trigger),
        affected_scope,
        causal_timeline: selected.iter().map(CausalEventRef::from_record).collect(),
        log_window_refs,
        change_hypotheses,
        dependencies: dependency_relations(selected),
        prior_failures,
        attempted_repairs,
        unknowns,
        trace_replay,
        next_action: select_next_action(&observation_gaps, trigger.seq),
        observation_gaps,
        fence: BriefStateFence {
            state_fence,
            compiled_at_audit_seq: problem.window.last_audit_seq,
            invalidation_conditions: BriefInvalidation::ALL.to_vec(),
        },
    })
}

/// Replays the sealed trace manifest of one operation (issue #1838).
///
/// The operation identity comes from the trigger record's own
/// `AuditLineage` owner — the same slot [`AffectedScope::operation_id`]
/// reports — so the brief replays the operation the observed condition
/// belongs to and never an operation it selected for itself.
///
/// The read itself is
/// [`TraceManifest::find_sealed`](crate::trace_manifest::TraceManifest::find_sealed):
/// the manifest's own recorded gate refuses a body whose completion claim its
/// own recorded required slots do not carry, so this reader cannot serve a
/// self-contradicting success and does not re-implement that rule. A body that
/// genuinely withheld a required part is served as the degraded record it is,
/// with its explicit missing parts intact (I16.12).
fn read_sealed_trace_replay(
    records: &[AuditRecord],
    operation_id: Option<&str>,
) -> Option<TraceManifest> {
    let operation_id = operation_id?;
    TraceManifest::find_sealed(records, operation_id)
}

/// Selects the exact bounded window out of the retained canonical chain.
///
/// The supplied records must be the gapless verified chain the audit owner
/// returns; a broken sequence is refused rather than read as a shorter
/// timeline, so a brief can never be compiled from a partially readable chain.
fn select_window(
    records: &[AuditRecord],
    window: DiagnosticWindow,
) -> Result<&[AuditRecord], DiagnosticBriefError> {
    if window.first_audit_seq == 0
        || window.first_audit_seq > window.last_audit_seq
        || records.is_empty()
    {
        return Err(DiagnosticBriefError::EmptyWindow);
    }
    for (index, record) in records.iter().enumerate() {
        if record.seq != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1) {
            return Err(DiagnosticBriefError::ChainNotContiguous {
                audit_seq: record.seq,
            });
        }
    }
    let chain_head_seq = records[records.len() - 1].seq;
    if window.last_audit_seq > chain_head_seq {
        return Err(DiagnosticBriefError::WindowOutsideChain {
            audit_seq: window.last_audit_seq,
            chain_head_seq,
        });
    }
    let outside = |audit_seq: u64| DiagnosticBriefError::WindowOutsideChain {
        audit_seq,
        chain_head_seq,
    };
    let first =
        usize::try_from(window.first_audit_seq - 1).map_err(|_| outside(window.first_audit_seq))?;
    let last =
        usize::try_from(window.last_audit_seq - 1).map_err(|_| outside(window.last_audit_seq))?;
    Ok(&records[first..=last])
}

/// Verifies that the recorded condition belongs to the declared class.
///
/// The check applies only where the class has a canonical audit
/// representation. The two classes the Kernel chain cannot represent are not
/// approximated by a neighbouring record; they become an observation gap in
/// the compiled brief instead.
fn verify_declared_trigger(
    trigger: &AuditRecord,
    declared: DiagnosticTrigger,
) -> Result<(), DiagnosticBriefError> {
    if let Some(observed) = DiagnosticTrigger::from_audit_kind(&trigger.kind)
        && observed != declared
    {
        return Err(DiagnosticBriefError::TriggerNotObserved {
            audit_kind: trigger.kind.clone(),
            trigger: declared,
        });
    }
    Ok(())
}

/// Projects the captured bounded windows into their exact references.
fn project_log_window_refs(
    captured: &[BoundedLogWindow],
) -> Result<Vec<LogWindowRef>, DiagnosticBriefError> {
    let mut refs = Vec::with_capacity(captured.len());
    for window in captured {
        if window.sequence_from == 0
            || window.sequence_from > window.sequence_to
            || window.ended_at_ms < window.started_at_ms
        {
            return Err(DiagnosticBriefError::LogWindowRangeInvalid {
                source: window.source.clone(),
            });
        }
        refs.push(LogWindowRef::from_window(window));
    }
    Ok(refs)
}

/// Projects every record of one closed audit family inside the window.
fn family_events(records: &[AuditRecord], kinds: &[&str]) -> Vec<CausalEventRef> {
    records
        .iter()
        .filter(|record| kinds.contains(&record.kind.as_str()))
        .map(CausalEventRef::from_record)
        .collect()
}

/// Projects the earlier failure records of the window, excluding the trigger.
fn prior_failure_events(records: &[AuditRecord], trigger_seq: u64) -> Vec<CausalEventRef> {
    records
        .iter()
        .filter(|record| {
            record.seq != trigger_seq && DiagnosticTrigger::from_audit_kind(&record.kind).is_some()
        })
        .map(CausalEventRef::from_record)
        .collect()
}

/// Projects the correlated generation/authority-epoch change records.
fn correlated_change_hypotheses(records: &[AuditRecord]) -> Vec<ChangeHypothesis> {
    records
        .iter()
        .filter(|record| GENERATION_CHANGE_KINDS.contains(&record.kind.as_str()))
        .map(|record| ChangeHypothesis {
            audit_seq: record.seq,
            audit_kind: record.kind.clone(),
            detail: record.event_body.clone(),
        })
        .collect()
}

/// Projects the affected trace/work scope of the trigger record.
fn project_affected_scope(trigger: &AuditRecord) -> AffectedScope {
    AffectedScope {
        trace_id: trigger.lineage.trace_id.clone(),
        task_id: trigger.lineage.task_id.clone(),
        work_scope: trigger.lineage.work_scope.clone(),
        work_item: trigger.lineage.work_item.clone(),
        operation_id: trigger.lineage.operation_id.clone(),
        session_id: trigger.lineage.session_id.clone(),
        attempt_id: trigger.lineage.attempt_id.clone(),
        job_id: trigger.lineage.job_id.clone(),
        environment_lease: trigger.lineage.environment_lease.clone(),
        process_identity: trigger.lineage.process_identity.clone(),
        module_generation: trigger.lineage.module_generation.clone(),
        authority_epoch: trigger.lineage.authority_epoch.clone(),
        controller: trigger.lineage.controller.clone(),
        unknown_fields: trigger.lineage.missing_fields.clone(),
    }
}

/// Projects the symptom and severity of the trigger record.
fn project_symptom(trigger: &AuditRecord, declared: DiagnosticTrigger) -> DiagnosticSymptom {
    DiagnosticSymptom {
        trigger: declared,
        audit_kind: trigger.kind.clone(),
        observed_at_audit_seq: trigger.seq,
        emitted_at_ms: trigger.emitted_at_ms,
        severity: AuditEventKind::assurance_class(&trigger.kind),
    }
}

/// Selects the single cheapest useful next step.
///
/// A brief that still holds an observation gap probes the cheapest one; a
/// brief with no gap escalates, because the evidence is then complete enough
/// to hand to the owner (A0.4).
fn select_next_action(gaps: &[ObservationGap], target_audit_seq: u64) -> NextAction {
    match gaps.first() {
        Some(gap) => NextAction {
            kind: NextActionKind::Probe,
            closes: Some(gap.code),
            target_audit_seq,
        },
        None => NextAction {
            kind: NextActionKind::Escalate,
            closes: None,
            target_audit_seq,
        },
    }
}

/// Derives the dependency relations the bounded window proves.
///
/// A relation is one exact module generation under one exact authority epoch,
/// plus the first capability route mismatch observed for it. Records whose
/// controller, module generation, or authority epoch is undeclared contribute
/// no relation: the missing slot stays in the lineage's own declaration.
fn dependency_relations(records: &[AuditRecord]) -> Vec<DependencyRelation> {
    let mut ordered: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
    for record in records {
        if let (Some(controller), Some(module_generation), Some(authority_epoch)) = (
            record.lineage.controller.as_deref(),
            record.lineage.module_generation.as_deref(),
            record.lineage.authority_epoch.as_deref(),
        ) {
            ordered.insert((controller, module_generation, authority_epoch));
        }
    }
    let mut relations: Vec<DependencyRelation> = ordered
        .into_iter()
        .map(
            |(controller, module_generation, authority_epoch)| DependencyRelation {
                controller: controller.to_owned(),
                module_generation: module_generation.to_owned(),
                authority_epoch: authority_epoch.to_owned(),
                route_divergence: None,
            },
        )
        .collect();
    for record in records {
        let (Some(requested), Some(actual)) = (
            record.lineage.route_receipt_requested.as_deref(),
            record.lineage.route_receipt_actual.as_deref(),
        ) else {
            continue;
        };
        if requested == actual {
            continue;
        }
        let (Some(controller), Some(module_generation), Some(authority_epoch)) = (
            record.lineage.controller.as_deref(),
            record.lineage.module_generation.as_deref(),
            record.lineage.authority_epoch.as_deref(),
        ) else {
            continue;
        };
        let Some(relation) = relations.iter_mut().find(|relation| {
            relation.controller == controller
                && relation.module_generation == module_generation
                && relation.authority_epoch == authority_epoch
        }) else {
            continue;
        };
        if relation.route_divergence.is_none() {
            relation.route_divergence = Some(RouteDivergence {
                audit_seq: record.seq,
                requested: requested.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }
    relations
}

/// Derives the required observations the brief cannot satisfy.
///
/// Every branch below is a fact about the retained evidence, and the emitted
/// order is the cheapest-to-close order the next-step rule consumes. None of
/// the branches assigns a cause: a missing observation is reported with the
/// exact evidence that would supply it (I16.7, I16.9).
fn observation_gaps(
    records: &[AuditRecord],
    log_window_refs: &[LogWindowRef],
    trigger: DiagnosticTrigger,
    affected_scope: &AffectedScope,
    change_hypotheses: &[ChangeHypothesis],
    attempted_repairs: &[CausalEventRef],
    trace_replay: Option<&TraceManifest>,
) -> Vec<ObservationGap> {
    let mut gaps = Vec::new();
    if log_window_refs.is_empty() {
        gaps.push(ObservationGap::new(ObservationGapCode::LogWindowAbsent));
    }
    if log_window_refs
        .iter()
        .any(|window| window.redaction == LogWindowRedaction::Unestablished)
    {
        gaps.push(ObservationGap::new(
            ObservationGapCode::LogWindowRedactionUnestablished,
        ));
    }
    if log_window_refs
        .iter()
        .any(|window| window.retention == LogWindowRetention::Unestablished)
    {
        gaps.push(ObservationGap::new(
            ObservationGapCode::LogWindowRetentionUnestablished,
        ));
    }
    if trigger == DiagnosticTrigger::RepeatedFailureOrNoProgress {
        let occurrences = records
            .iter()
            .filter(|record| DiagnosticTrigger::from_audit_kind(&record.kind) == Some(trigger))
            .count();
        if occurrences < 2 {
            gaps.push(ObservationGap::new(
                ObservationGapCode::TriggerRecurrenceUnobserved,
            ));
        }
    }
    if DiagnosticTrigger::from_audit_kind(records.last().map_or("", |record| record.kind.as_str()))
        .is_none()
    {
        gaps.push(ObservationGap::new(
            ObservationGapCode::TriggerClassNotInCanonicalAudit,
        ));
    }
    if affected_scope.trace_id.is_none() || affected_scope.work_scope.is_none() {
        gaps.push(ObservationGap::new(
            ObservationGapCode::AffectedScopeUnattributed,
        ));
    }
    if change_hypotheses.is_empty() {
        gaps.push(ObservationGap::new(
            ObservationGapCode::GenerationChangeNotCorrelated,
        ));
    }
    if attempted_repairs.is_empty() {
        gaps.push(ObservationGap::new(
            ObservationGapCode::PriorRepairNotInWindow,
        ));
    }
    // Issue #1838 (I16.12): a condition whose operation has no servable sealed
    // trace manifest cannot name the replay context at all, so the gap is
    // reported with the exact record that would supply it rather than being
    // read as a complete trace.
    if trace_replay.is_none() {
        gaps.push(ObservationGap::new(
            ObservationGapCode::ReplayableTraceUnservable,
        ));
    }
    gaps
}

/// Caller-declared maximum canonical audit records one brief may read.
///
/// I16.7 names no window cap and the compiler takes its bound from the
/// caller, so this production caller declares one: the trigger record plus
/// its bounded predecessors. The causal timeline stays small however long
/// the retained chain grows (I16.9: telemetry costs what it observes),
/// while still covering recurrence, repair, and generation-change evidence.
const DIAGNOSTIC_BRIEF_WINDOW_LEN: u64 = 32;

impl crate::KernelComposition {
    /// Compiles and retains one Diagnostic Brief for an observed problem
    /// trigger (issue #1844; I16.7).
    ///
    /// This is the single trigger registration: the canonical
    /// problem/failure/no-progress owners call it after appending their
    /// trigger record (lease expiry, daemon degraded/failed, launch
    /// failure, stale quarantine, orphan fencing). The bounded audit
    /// window comes from the existing evidence owner
    /// ([`crate::KernelComposition::audit_chain_records`]); no second
    /// evidence store is read and no rolling log content is copied.
    ///
    /// No bounded operational-log capture owner exists
    /// (`kernel_diagnostics` emits to `tracing`/stderr and keeps no
    /// queryable stream), so no log window can honestly be supplied: the
    /// problem carries none and the brief reports the specified
    /// [`ObservationGapCode::LogWindowAbsent`] gap with its requested
    /// observation instead of inventing one (I16.7, I16.9).
    ///
    /// Best-effort like every observation: `None` when the chain is
    /// unreadable, when no record of the trigger class exists (the two
    /// classes without a canonical event never match), or when the
    /// compiler refuses the evidence. A refusal retains nothing and
    /// disturbs no previously retained brief; the trigger record itself
    /// is already durable evidence.
    pub(crate) fn observe_diagnostic_problem(
        &self,
        trigger: DiagnosticTrigger,
    ) -> Option<DiagnosticBrief> {
        let records = self.audit_chain_records().ok()?;
        let trigger_seq = records
            .iter()
            .rev()
            .find(|record| DiagnosticTrigger::from_audit_kind(&record.kind) == Some(trigger))?
            .seq;
        let problem = DiagnosticProblem {
            trigger,
            window: DiagnosticWindow {
                first_audit_seq: trigger_seq
                    .saturating_sub(DIAGNOSTIC_BRIEF_WINDOW_LEN - 1)
                    .max(1),
                last_audit_seq: trigger_seq,
            },
            log_windows: Vec::new(),
        };
        let brief = compile_diagnostic_brief(&records, &problem).ok()?;
        self.diagnostic_brief.lock().ok()?.replace(brief.clone());
        Some(brief)
    }

    /// Returns the retained brief while its State Fence still authorizes it.
    ///
    /// The brief is retained under its invalidation condition (I16.7): a
    /// superseding authority epoch, an advanced audit head, or a referenced
    /// log window whose retention is no longer established drops it and reads
    /// `None`, so a stale brief is never served as current. Retention is read
    /// off the brief's own [`DiagnosticBrief::log_window_refs`] instead of
    /// asserted: a window whose retention disposition is
    /// [`LogWindowRetention::Unestablished`] is exactly the "not retained"
    /// case, and claiming otherwise would check nothing. An unreadable policy
    /// or audit head fails closed to `None` without dropping the retained
    /// brief; only an observed invalidation clears it, and only when the
    /// slot still holds that same brief.
    pub(crate) fn retained_diagnostic_brief(&self) -> Option<DiagnosticBrief> {
        let retained = self.diagnostic_brief.lock().ok()?.clone()?;
        let current = self.current_state_fence()?;
        let (head_seq, _) = self.audit_head()?;
        let log_windows_retained = retained
            .log_window_refs
            .iter()
            .all(|window| window.retention != LogWindowRetention::Unestablished);
        if retained
            .fence
            .observe_invalidation(&current, head_seq, log_windows_retained)
            .is_some()
        {
            if let Ok(mut slot) = self.diagnostic_brief.lock()
                && slot.as_ref() == Some(&retained)
            {
                slot.take();
            }
            return None;
        }
        Some(retained)
    }
}
