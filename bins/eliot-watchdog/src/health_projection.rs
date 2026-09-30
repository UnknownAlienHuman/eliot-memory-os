//! I8.18 continuous health detection joined to the bounded supervision loop.
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose),
//! ARCH-WDG-01, ARCH-WDG-02.
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes),
//! I8.3 (docs/architecture/I08-03-supervision-decisions-and-containment.md#i83-supervision-decisions-and-containment),
//! I8.18 (docs/architecture/I08-18-system-feedback-memorycontext-health-and-maintenance-debt.md#i818-system-feedback-memorycontext-health-and-maintenance-debt).
//! Issue #2381 steps 1, 2, 3 and 4.
//!
//! The five I8.18 rules are pure functions in `eliot_watchdog_core::health_detectors`.
//! They were written, exported, and never invoked: nothing joined them to an
//! input source, so no signal could ever open and no acceptance could hold. This
//! module is that join, and [`evaluate_interval_health`] is the only place the
//! five rules are called.
//!
//! # What the evidence actually is
//!
//! I8.18 says the Watchdog "continuously correlates the self-scope observation
//! bank with task and runtime evidence". The self-scope observation bank of
//! *this* owner is exactly two things it already holds, with one writer each:
//!
//! - the bounded retained spool (`watchdog.redb`), read through one bounded
//!   read transaction by
//!   [`crate::watchdog_spool::WatchdogSpool::health_corpus_summary`]; and
//! - the per-interval I8.2 coverage cell, whose closed report *is* the #1755
//!   manifest for that interval.
//!
//! Every count below is a measured value over those two sources and every
//! denominator is stated: the packet and replay bounds are the owner's own
//! declared retention ceilings, the expected lineage is summed from
//! [`SENSOR_CHANNEL_MAP`] - the independent declared expected set, never a copy
//! of the list of channels the tick happened to read - and the corpus counts are
//! bounded by the spool's own retention ceiling, which the read refuses to
//! exceed.
//!
//! # What this module does not claim
//!
//! Nothing here is a statement about an agent's mind or about a principal
//! responsible for anything. A channel whose map says this owner has no
//! competent source is a measured structural limitation and is reported as an
//! *explained* gap, so the permanent missing adapters can never open a signal
//! and can never be read as a bypass. Only a channel the map says is wired, and
//! that still did not cover the interval, is the unexplained case. An
//! installation that recorded no new retained activity produces no delta at
//! all, and an idle agent with no external change is not a violation.
//!
//! # Prose bar
//!
//! Every signal leaves this module through [`emit_health_signal`], whose only
//! exit denies all three [`ProhibitedEffectClass`]es through
//! [`ProhibitedEffectAttempt::deny`] and carries the denials on the emission.
//! There is no other constructor for [`HealthSignalEmission`], so no path can
//! emit a health output without also emitting the refusal of all three
//! forbidden effects, and each refusal names the subject that stayed untouched.
//!
//! # Ownership
//!
//! Observation projection only. This module reads, computes, and publishes a
//! bounded trace. It writes no spool record, mints no lease, epoch, authority,
//! or intent, performs no canonical, `ORS`, or `HostStateJournal` write, and starts
//! no second escalation path. Persistent or cross-cutting drift is compiled here
//! into one Diagnostic Brief input with one bounded Dreamer/Watchdog-Agent
//! analysis request through the existing #1761 [`RiskRoute`] contract
//! ([`RiskRoute::CheapDiagnosis`]); the request is published on the same bounded
//! trace the signals use, so no parallel escalation path and no Dreamer
//! dependency are introduced.

use std::sync::Mutex;

use eliot_contracts::sha256_hex;
use eliot_watchdog_core::{
    BriefPersistence, ClockDomain, ContextQualityBounds, ContextQualityObservation, CountDelta,
    CoverageGapExplanation, CoverageRef, EvidenceRef, ExpectedRevision, HealthAnalysisRequest,
    HealthDetection, HealthDiagnosticBrief, HealthEvidenceHandles, HealthNoSignalReason,
    HealthObservationPair, HealthOutputFamily, HealthSignalContext, MaintenanceDebtInput,
    MemoryUtilityDeltas, ObservationCoverageInput, ObservedTime, PolicyBound, ProfileRevision,
    ProhibitedEffectAttempt, ProhibitedEffectClass, ProhibitedEffectDenial, RecordedValue,
    RiskRoute, Signal, SignalReferences, SignalTarget, SourceEventRef, StateDeltaPresence,
    TimeUnit, compile_health_brief, evaluate_agent_loop, evaluate_context_quality,
    evaluate_maintenance_debt, evaluate_memory_utility, evaluate_observation_coverage,
    request_health_analysis,
};

use crate::PROTOCOL_VERSION;
use crate::observation_coverage::{
    CoverageDisposition, IntervalCoverageReport, SENSOR_CHANNEL_MAP, SENSOR_MAP_REVISION,
    channel_capability,
};
use crate::watchdog_spool::WatchdogSpoolBackupLimits;
use crate::watchdog_spool::{SPOOL_MAX_BYTES, SPOOL_MAX_RECORDS};

/// Rule identity of the repeated-signature detector.
const AGENT_LOOP_RULE: &str = "agent_loop_signal";
/// Rule identity of the context-packet detector.
const CONTEXT_QUALITY_RULE: &str = "context_quality_drift";
/// Rule identity of the retained-corpus utility detector.
const MEMORY_UTILITY_RULE: &str = "memory_utility_drift";
/// Rule identity of the observation-coverage detector.
const OBSERVATION_COVERAGE_RULE: &str = "observation_coverage_gap";
/// Rule identity of the maintenance-debt detector.
const MAINTENANCE_DEBT_RULE: &str = "maintenance_debt";

/// Owner-retained identities this sensor holds for the health projection.
///
/// Both values are the sensor's own retained binding facts, the same ones the
/// export, backup, and intent paths already bind against. Neither is derived
/// from a current directory, a process name, a path, a port, or hook text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogHealthOwner {
    /// Installer-approved installation identity retained at sensor construction.
    pub installation_id: String,
    /// Installer-approved Watchdog generation retained at sensor construction.
    pub watchdog_generation: u64,
}

/// One bounded, read-only measurement of this owner's retained observation bank.
///
/// Every field is a count or an owner-declared position over the retained
/// records of `watchdog.redb` at one instant. No field interprets the content
/// of a record beyond the owner's own stable classification of what it recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogHealthCorpus {
    /// Retained records covered by the read.
    pub retained_records: u64,
    /// Total encoded bytes of the retained records covered by the read.
    pub retained_bytes: u64,
    /// Retained records whose encoded content digest was not seen earlier in
    /// the retained set: genuinely new observation content.
    pub distinct_content: u64,
    /// Retained records whose encoded content digest repeats an earlier
    /// retained record: the same observation content present more than once.
    pub content_duplicates: u64,
    /// Retained records whose content digest also appears at or below the
    /// acknowledged cursor: content already delivered and acknowledged, present
    /// again.
    pub reused_acknowledged_content: u64,
    /// Retained records whose content digest also appears on a record that
    /// already holds a submit-once receipt: content present again after its
    /// downstream submission was already receipted.
    pub reactivated_after_receipt: u64,
    /// Highest consecutively acknowledged sequence from the stored export cursor.
    pub acknowledged_sequence: u64,
    /// Retained records past the acknowledged cursor: retained and not yet
    /// acknowledged by any sink.
    pub unacknowledged_records: u64,
    /// Retained records at or below the acknowledged cursor with no
    /// submit-once receipt: delivered to the sink and never receipted.
    pub delivered_without_receipt: u64,
    /// Retained intent records with no submit-once receipt: this owner's own
    /// escalation rule activated and produced no downstream submission.
    pub intents_without_receipt: u64,
    /// Retained records older than the owner's declared freshness window at the
    /// owner clock.
    pub stale_records: u64,
    /// Distinct retained gap reasons with no accepted heartbeat recorded at or
    /// after the newest gap carrying that reason.
    pub deferred_gap_reasons: u64,
    /// Sequence of the newest retained accepted-heartbeat record, or zero when
    /// the retained set holds none.
    pub newest_heartbeat_sequence: u64,
    /// Stable class name of the newest retained record's payload.
    pub newest_payload_class: String,
    /// Digest binding every count above to the exact read that produced it.
    pub evidence_id: String,
}

/// One bounded read of the owner identities and the retained observation bank.
///
/// A port that owns no durable spool supplies `None` (see
/// [`crate::KernelWatchdogPort::health_evidence`]), which the projection treats
/// as unknown evidence rather than as an empty corpus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogHealthEvidence {
    /// Owner-retained binding identities.
    pub owner: WatchdogHealthOwner,
    /// Bounded measurement of the retained observation bank.
    pub corpus: WatchdogHealthCorpus,
}

/// Owner-issued revisions and scope the last admitted supervision tick observed.
///
/// [`ExpectedRevision`] records what the observer saw, never what it was
/// granted, so these are copied from the admitted lease verbatim and are
/// retained unchanged across a degraded tick rather than replaced from an
/// absent lease.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedRevisions {
    scope_ref: String,
    context: ExpectedRevision,
    authority: ExpectedRevision,
}

/// Everything one closed interval contributes to the next pairwise comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
struct IntervalRecord {
    target: SignalTarget,
    event: SourceEventRef,
    evidence_id: String,
    signature: String,
    state_delta_present: bool,
    corpus: WatchdogHealthCorpus,
    blocking_channels: u64,
    non_continuum_channels: u64,
}

/// Retained comparison state of this owner.
#[derive(Debug, Default)]
struct HealthProjectionState {
    /// The last revisions a verified lease bound, retained across degraded
    /// ticks. `None` until the first admitted tick, which is the honest state
    /// of a sensor that has never held a lease: it has observed no scope and no
    /// positive revision, so it can build no signal target.
    revisions: Option<ObservedRevisions>,
    /// The previous closed interval, or `None` before the second one.
    previous: Option<IntervalRecord>,
    /// Rule identities the last compared interval emitted, or empty when it
    /// emitted nothing or was never compared. At most one entry per rule, so
    /// this never exceeds the five I8.18 rule families. A non-compared interval
    /// clears it, so persistence always means consecutive compared intervals.
    previous_emission_rules: Vec<&'static str>,
    /// Compiled-brief identities already requested, oldest first, with the
    /// request count each has drawn. Bounded by [`MAX_TRACKED_BRIEFS`]: the
    /// oldest identity is evicted first, which only loses degradation memory
    /// for drift that stopped recurring.
    requested_briefs: Vec<BriefRequestRecord>,
}

/// The bounded comparison state of this owner's health projection.
///
/// One slot per closed interval. It is an observation buffer, not durable
/// state: it is never serialized, never fenced, never backed by a second
/// writer, and a restart loses it, which costs exactly one interval of
/// comparison and can never fabricate a delta.
#[derive(Debug, Default)]
pub struct HealthProjectionCell {
    state: Mutex<HealthProjectionState>,
}

/// Every measured value one closed coverage interval contributes.
struct IntervalObservation {
    evidence_id: String,
    gap_evidence_id: String,
    signature: String,
    explanation: CoverageGapExplanation,
    blocking_channels: u64,
    non_continuum_channels: u64,
    expected_lineage: u64,
}

/// One opened health signal and the effect denials that bound it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSignalEmission {
    /// The rule that opened the signal.
    pub rule_id: &'static str,
    /// The immutable evidence-only Watchdog signal.
    pub signal: Signal,
    /// Exact subject the cited output was claimed against.
    pub subject: String,
    /// One fail-closed denial per prohibited effect class.
    pub denied_effects: Vec<ProhibitedEffectDenial>,
}

/// Maximum compiled-brief identities retained for ineffective-analysis counting.
///
/// The history exists only so a recompiled brief proves its earlier analysis
/// request did not clear the drift. It is an observation buffer, not durable
/// state: a restart loses it, which only restarts degradation counting and can
/// never fabricate a request.
const MAX_TRACKED_BRIEFS: usize = 8;

/// One compiled-brief identity with the bounded analysis requests it has drawn.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BriefRequestRecord {
    /// Deterministic identity of the compiled brief.
    brief_id: String,
    /// Bounded analysis requests already published for this identity.
    requests: u32,
}

/// One compiled Diagnostic Brief with its bounded analysis request.
///
/// The brief carries the member health signals whole with the explicit analysis
/// question and stop condition; the request carries both unchanged onto the
/// existing #1761 diagnosis route. The denials bound both outputs: three
/// fail-closed refusals against the brief and three against the request, so no
/// memory delete, policy alter, or work termination can be derived from either.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HealthBriefEmission {
    /// The compiled persistent or cross-cutting drift input.
    brief: HealthDiagnosticBrief,
    /// The one bounded analysis request this compilation drew.
    request: HealthAnalysisRequest,
    /// Fail-closed denials for every prohibited class on both outputs.
    denied_effects: Vec<ProhibitedEffectDenial>,
}

impl HealthProjectionCell {
    /// Records the scope and revisions one admitted supervision tick observed.
    ///
    /// Reached from the same verified lease the tick supervises through, so the
    /// retained revisions are always real owner observations. A degraded tick
    /// that never admits a lease leaves the last admitted revisions in place
    /// instead of substituting a placeholder.
    pub fn observe_admitted(
        &self,
        installation_id: &str,
        scope_ref: &str,
        kernel_epoch: u64,
        watchdog_epoch: u64,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if installation_id.trim().is_empty() || scope_ref.trim().is_empty() {
            return;
        }
        state.revisions = Some(ObservedRevisions {
            scope_ref: scope_ref.to_owned(),
            context: expected_revision(installation_id, kernel_epoch),
            authority: expected_revision(installation_id, watchdog_epoch),
        });
    }
}

/// Records one owner-observed revision, or an explicit unknown when the
/// observed value is not a positive sequence.
///
/// A zero epoch is a real value this owner can hold — a gap-only sensor has
/// never established its own supervision epoch — and reporting it as `Unknown`
/// is the honest projection: it says the observer saw no positive revision, not
/// that it saw a different one.
fn expected_revision(owner_id: &str, revision: u64) -> ExpectedRevision {
    if revision == 0 {
        return ExpectedRevision::Unknown {
            limitation: "the observing sensor retained no positive owner revision for this axis"
                .to_owned(),
        };
    }
    ExpectedRevision::Known {
        owner_id: owner_id.to_owned(),
        revision,
    }
}

/// Length-prefixes each field into one unambiguous identity string.
///
/// The same injective encoding the `eliot_watchdog_core` identity rules use, so
/// two different field splits can never produce one identity and one identity
/// can never be reached from two different field lists. Shared with this
/// crate's spool owner so the corpus digest and the signal evidence identities
/// are built by one encoding, not two.
pub(crate) fn encode_identity(fields: &[String]) -> String {
    let mut encoded = String::new();
    for field in fields {
        encoded.push_str(&field.len().to_string());
        encoded.push(':');
        encoded.push_str(field);
    }
    encoded
}

/// Measures everything one closed I8.2 interval contributes.
///
/// The expected lineage is summed from [`SENSOR_CHANNEL_MAP`], the independent
/// declared expected set. It is deliberately *not* summed from the channels the
/// tick happened to read: a completeness term derived from the caller's own
/// list can never disagree with itself, and disagreeing with what was observed
/// is this module's entire purpose.
fn observe_interval(
    report: &IntervalCoverageReport,
    corpus: &WatchdogHealthCorpus,
) -> IntervalObservation {
    let mut signature: Vec<String> = vec![
        "watchdog_supervision_interval".to_owned(),
        SENSOR_MAP_REVISION.to_string(),
    ];
    let mut evidence_fields: Vec<String> = Vec::new();
    let mut gap_fields: Vec<String> = Vec::new();
    let mut expected_lineage = 0_u64;
    let mut blocking_channels = 0_u64;
    let mut non_continuum_channels = 0_u64;
    let mut any_unclosed = false;
    for capability in &SENSOR_CHANNEL_MAP {
        expected_lineage += capability.supported_classes.len() as u64;
    }
    for record in report.records() {
        let capability = channel_capability(record.channel());
        signature.push(capability.channel.as_str().to_owned());
        signature.push(record.disposition().as_str().to_owned());
        signature.push(record.interval_closed().to_string());
        evidence_fields.push(capability.channel.as_str().to_owned());
        evidence_fields.push(record.disposition().as_str().to_owned());
        evidence_fields.push(record.observed_classes().len().to_string());
        evidence_fields.push(record.dropped_samples().to_string());
        for gap in record.gaps() {
            signature.push(gap.reason.to_owned());
            gap_fields.push(gap.reason.to_owned());
        }
        if !record.interval_closed() {
            any_unclosed = true;
        }
        match record.disposition() {
            // A continuous channel is no blocking channel either. A channel
            // the map says has no competent source is a measured structural
            // limitation at this build, not a capability that degraded between
            // two intervals, so it is neither an unexplained blocking channel
            // nor a stale capability.
            CoverageDisposition::Continuous | CoverageDisposition::Blind => {}
            CoverageDisposition::Partial | CoverageDisposition::Unknown => {
                blocking_channels += 1;
                if capability.wiring.is_wired() {
                    non_continuum_channels += 1;
                }
            }
        }
    }
    // The two facts the agent-loop signature takes from the retained bank are
    // appended here so both windows of a pair are encoded the same way.
    signature.push(corpus.newest_payload_class.clone());
    signature.push(corpus.deferred_gap_reasons.to_string());
    // A report that is not internally consistent, or whose interval no tick
    // closed, cannot establish what was covered, so it is unknown rather than
    // either verdict. An interval short of full coverage only through measured
    // missing adapters reports no blocking channel at all and is therefore
    // explained; any other short channel is a gap this owner cannot account for.
    let explanation = if !report.valid() || any_unclosed {
        CoverageGapExplanation::Unknown
    } else if blocking_channels == 0 {
        CoverageGapExplanation::Explained
    } else {
        CoverageGapExplanation::Unexplained
    };
    IntervalObservation {
        evidence_id: sha256_hex(encode_identity(&evidence_fields).as_bytes()),
        gap_evidence_id: sha256_hex(encode_identity(&gap_fields).as_bytes()),
        signature: encode_identity(&signature),
        explanation,
        blocking_channels,
        non_continuum_channels,
        expected_lineage,
    }
}

/// Builds the owner-issued signal context for one closed interval.
///
/// The target is the owner's own retained installation identity and generation
/// with the scope a verified lease bound. None of it comes from a working
/// directory, a process name, a port, or hook text.
fn signal_context(
    owner: &WatchdogHealthOwner,
    revisions: &ObservedRevisions,
    report: &IntervalCoverageReport,
    coverage_id: String,
) -> HealthSignalContext {
    HealthSignalContext {
        target: SignalTarget {
            subject_id: owner.installation_id.clone(),
            scope_id: revisions.scope_ref.clone(),
            generation: owner.watchdog_generation,
        },
        profile: ProfileRevision {
            profile_id: PROTOCOL_VERSION.to_owned(),
            revision: u64::from(SENSOR_MAP_REVISION),
        },
        observed_at: ObservedTime {
            ticks: report.interval().end_ms,
            unit: TimeUnit::Milliseconds,
            domain: ClockDomain::UnixUtc,
        },
        coverage: CoverageRef { coverage_id },
        expected_context_revision: revisions.context.clone(),
        expected_authority_revision: revisions.authority.clone(),
    }
}

/// Builds the exact source event identity of one closed interval.
///
/// The identity is the interval's own owner-clock bounds under the sensor map
/// revision it was derived under, and the payload digest is computed over the
/// per-channel projection this owner actually published for it. Two different
/// intervals therefore never share an identity, and the digest binds this
/// owner's own recorded publication rather than restating another owner's
/// bytes.
fn interval_event(report: &IntervalCoverageReport, evidence_id: &str) -> SourceEventRef {
    let interval = report.interval();
    SourceEventRef {
        event_id: encode_identity(&[
            "watchdog_coverage_interval".to_owned(),
            interval.start_ms.to_string(),
            interval.end_ms.to_string(),
            report.sensor_map_revision().to_string(),
        ]),
        payload_digest: RecordedValue::Known(evidence_id.to_owned()),
    }
}

/// Builds the supporting and counterevidence handles for one comparison.
///
/// Both sides are always present and both are real. The supporting side carries
/// this interval's own publication digest, the bounded retained-corpus digest,
/// and the previous interval's publication digest. The counterevidence side
/// carries the named coverage gaps and the acknowledged-cursor position, which
/// are exactly the facts that can withhold a signal.
fn evidence_handles(
    current: &IntervalObservation,
    previous: &IntervalRecord,
    corpus: &WatchdogHealthCorpus,
) -> HealthEvidenceHandles {
    HealthEvidenceHandles {
        supporting: vec![
            EvidenceRef {
                evidence_id: current.evidence_id.clone(),
            },
            EvidenceRef {
                evidence_id: corpus.evidence_id.clone(),
            },
            EvidenceRef {
                evidence_id: previous.evidence_id.clone(),
            },
        ],
        counterevidence: vec![
            EvidenceRef {
                evidence_id: current.gap_evidence_id.clone(),
            },
            EvidenceRef {
                evidence_id: sha256_hex(
                    encode_identity(&[
                        "watchdog_acknowledged_cursor".to_owned(),
                        corpus.acknowledged_sequence.to_string(),
                    ])
                    .as_bytes(),
                ),
            },
        ],
    }
}

/// The one exit by which a health signal leaves this owner.
///
/// Every class in [`ProhibitedEffectClass`] is denied here, against the signal
/// the caller actually holds, and the denials travel with the emission. There is
/// no other constructor for [`HealthSignalEmission`], so no path can emit a
/// health output without also emitting the refusal of all three forbidden
/// effects, and each refusal names the subject that stayed untouched.
fn emit_health_signal(
    rule_id: &'static str,
    signal: &Signal,
    subject: String,
) -> HealthSignalEmission {
    let denied_effects = [
        ProhibitedEffectClass::MemoryDelete,
        ProhibitedEffectClass::PolicyAlter,
        ProhibitedEffectClass::WorkTerminate,
    ]
    .into_iter()
    .map(|class| {
        ProhibitedEffectAttempt::for_signal(
            HealthOutputFamily::Signal,
            class,
            signal,
            subject.clone(),
        )
        .deny()
    })
    .collect();
    HealthSignalEmission {
        rule_id,
        signal: signal.clone(),
        subject,
        denied_effects,
    }
}

/// Publishes the opened signals and the refusals that bound them.
///
/// The trace is the same bounded operator evidence the I8.2 coverage
/// publication already emits: the signal identity, rule, target, coverage,
/// evidence count, and the exact reason each forbidden effect was refused. It
/// is a trace, not a route: nothing is written, dispatched, or authorized here.
fn publish(emissions: &[HealthSignalEmission]) {
    for emission in emissions {
        let revision = emission.signal.revision();
        let denied = emission
            .denied_effects
            .iter()
            .map(|denial| format!("{}={}", denial.class.as_str(), denial.reason))
            .collect::<Vec<_>>();
        tracing::warn!(
            event = "watchdog.health_signal_opened",
            observation = "observed",
            rule_id = emission.rule_id,
            signal_id = revision.signal_id.0.as_str(),
            subject_id = revision.target.subject_id.as_str(),
            scope_id = revision.target.scope_id.as_str(),
            subject = emission.subject.as_str(),
            supporting_evidence = match &revision.evidence {
                SignalReferences::Known(references) => references.len(),
                SignalReferences::Unknown { .. } => 0,
            },
            denied_effects = ?denied,
            "I8.18 health drift opened from an observed delta; no memory delete, policy alter, or work termination is derived from it"
        );
    }
}

/// Runs the five I8.18 rules over one closed supervision interval.
///
/// When the opened signals show persistent or cross-cutting drift,
/// [`consider_diagnostic_brief`] compiles one Diagnostic Brief input with one
/// bounded Dreamer/Watchdog-Agent analysis request through the existing #1761
/// diagnosis route and publishes it beside the signals.
///
/// This is the production caller of `evaluate_agent_loop`,
/// `evaluate_context_quality`, `evaluate_memory_utility`,
/// `evaluate_observation_coverage`, and `evaluate_maintenance_debt`, reached
/// from the bounded supervision tick in
/// [`crate::watchdog_composition::WatchdogComposition::start_with_shutdown_and_host_and_heartbeat`]
/// on every tick that has a closed interval to project.
///
/// Three source facts bound what can be claimed, and each is an explicit
/// unknown rather than a substituted value:
///
/// - `evidence` is `None` when the injected Kernel port owns no durable spool;
/// - no admitted lease has been observed yet, so no owner-issued target exists;
/// - this is the first closed interval, so there is no second source event and
///   no delta can be proved.
///
/// Every rule that stays silent is traced with its own
/// [`HealthNoSignalReason`], so "no competent source reached this owner" stays
/// distinguishable from "the source observed no delta".
#[allow(
    clippy::too_many_lines,
    reason = "the five I8.18 rules, the pair they share, and the slot that follows them stay in one reviewable contour"
)]
pub fn evaluate_interval_health(
    cell: &HealthProjectionCell,
    report: &IntervalCoverageReport,
    evidence: Option<&WatchdogHealthEvidence>,
) {
    let Some(evidence) = evidence else {
        trace_unavailable(HealthNoSignalReason::OwnerEvidenceUnknown);
        reset_emission_history(cell);
        return;
    };
    let Ok(mut state) = cell.state.lock() else {
        trace_unavailable(HealthNoSignalReason::OwnerEvidenceUnknown);
        return;
    };
    let Some(revisions) = state.revisions.clone() else {
        trace_unavailable(HealthNoSignalReason::OwnerEvidenceUnknown);
        state.previous_emission_rules = Vec::new();
        return;
    };
    let observation = observe_interval(report, &evidence.corpus);
    let current_event = interval_event(report, &observation.evidence_id);
    let current = signal_context(
        &evidence.owner,
        &revisions,
        report,
        current_event.event_id.clone(),
    );
    let corpus = &evidence.corpus;
    let Some(previous) = state.previous.clone() else {
        // One closed interval is not a comparison. It is recorded so the next
        // tick has a real previous observation to compare against, and no rule
        // runs: with one source event there is no delta any of them could
        // prove, and inventing the other side of the pair is exactly what the
        // pairwise contract forbids. Nothing was emitted, so no later interval
        // may claim persistence against this one.
        state.previous_emission_rules = Vec::new();
        state.previous = Some(IntervalRecord {
            target: current.target,
            event: current_event,
            evidence_id: observation.evidence_id,
            signature: observation.signature,
            state_delta_present: false,
            corpus: corpus.clone(),
            blocking_channels: observation.blocking_channels,
            non_continuum_channels: observation.non_continuum_channels,
        });
        return;
    };
    // A newly accepted supervision heartbeat is the only event this owner
    // records that proves the supervised state moved.
    let current_state_delta =
        if corpus.newest_heartbeat_sequence > previous.corpus.newest_heartbeat_sequence {
            StateDeltaPresence::Present
        } else {
            StateDeltaPresence::Absent
        };
    let previous_state_delta = if previous.state_delta_present {
        StateDeltaPresence::Present
    } else {
        StateDeltaPresence::Absent
    };
    let pair = HealthObservationPair {
        previous_target: previous.target.clone(),
        current,
        previous_event: previous.event.clone(),
        current_event: current_event.clone(),
        evidence: evidence_handles(&observation, &previous, corpus),
    };

    let mut silent: Vec<(&'static str, HealthNoSignalReason)> = Vec::new();
    let mut emissions: Vec<HealthSignalEmission> = Vec::new();

    if let Some(emission) = open_agent_loop(
        &previous,
        pair.clone(),
        &observation,
        current_state_delta,
        previous_state_delta,
        &mut silent,
    ) {
        emissions.push(emission);
    }
    if let Some(emission) =
        open_context_quality(&previous, pair.clone(), corpus, &observation, &mut silent)
    {
        emissions.push(emission);
    }
    if let Some(emission) = open_memory_utility(&previous, pair.clone(), corpus, &mut silent) {
        emissions.push(emission);
    }
    if let Some(emission) =
        open_observation_coverage(&previous, pair.clone(), &observation, corpus, &mut silent)
    {
        emissions.push(emission);
    }
    if let Some(emission) =
        open_maintenance_debt(&previous, pair, &observation, corpus, &mut silent)
    {
        emissions.push(emission);
    }

    // The interval becomes the previous observation only after every rule has
    // read it, so no rule can compare an interval against itself.
    state.previous = Some(IntervalRecord {
        target: previous.target,
        event: current_event,
        evidence_id: observation.evidence_id,
        signature: observation.signature,
        state_delta_present: matches!(current_state_delta, StateDeltaPresence::Present),
        corpus: corpus.clone(),
        blocking_channels: observation.blocking_channels,
        non_continuum_channels: observation.non_continuum_channels,
    });
    // I8.18 (#2381 W3/A2): persistent or cross-cutting drift compiles exactly
    // one Diagnostic Brief input with exactly one bounded Dreamer/Watchdog-Agent
    // analysis request through the existing #1761 diagnosis route. The history
    // update and the compilation happen under the projection lock, so two ticks
    // can never compile one interval twice.
    let brief = consider_diagnostic_brief(&mut state, &emissions);
    // The comparison slot is released before anything is traced, so a slow
    // subscriber can never hold the projection against the next tick.
    drop(state);

    for (rule_id, reason) in silent {
        tracing::debug!(
            event = "watchdog.health_rule_silent",
            observation = "silent",
            rule_id = rule_id,
            reason_code = reason.as_str(),
            "I8.18 health rule observed no applicable delta"
        );
    }
    publish(&emissions);
    if let Some(brief) = brief.as_ref() {
        publish_brief(brief);
    }
}

/// Forgets the last compared interval's emission rules.
///
/// A non-compared interval breaks persistence: the next compared interval must
/// not claim continuity with an emission from before the gap.
fn reset_emission_history(cell: &HealthProjectionCell) {
    if let Ok(mut state) = cell.state.lock() {
        state.previous_emission_rules = Vec::new();
    }
}

/// Compiles persistent or cross-cutting drift into one Diagnostic Brief input.
///
/// Persistent drift is one rule family opening on two consecutive compared
/// intervals; cross-cutting drift is two or more rule families opening on this
/// interval. Either compiles the member signals whole — with the explicit
/// analysis question and stop condition — and draws exactly one bounded
/// Dreamer/Watchdog-Agent analysis request through the existing #1761
/// [`RiskRoute::CheapDiagnosis`] route: never a campaign, and no parallel
/// escalation path.
///
/// The ineffective-analysis history is the recompiled-brief identity itself: the
/// brief identity derives deterministically from its member signals, so the same
/// identity compiling again proves the earlier analysis request did not clear
/// the drift, and the route degrades per I09-17's rollback rule — one
/// ineffective analysis steps the route down, a repeated one requires Human
/// review. The request is published on the bounded trace; nothing is written,
/// dispatched, or authorized here.
fn consider_diagnostic_brief(
    state: &mut HealthProjectionState,
    emissions: &[HealthSignalEmission],
) -> Option<HealthBriefEmission> {
    let mut rules: Vec<&'static str> = emissions.iter().map(|emission| emission.rule_id).collect();
    rules.sort_unstable();
    rules.dedup();
    let persistent = rules
        .iter()
        .any(|rule| state.previous_emission_rules.contains(rule));
    let cross_cutting = rules.len() >= 2;
    state.previous_emission_rules.clone_from(&rules);
    let persistence = match (persistent, cross_cutting) {
        (true, true) => BriefPersistence::PersistentAndCrossCutting,
        (true, false) => BriefPersistence::Persistent,
        (false, true) => BriefPersistence::CrossCutting,
        (false, false) => return None,
    };
    let signals: Vec<Signal> = emissions
        .iter()
        .map(|emission| emission.signal.clone())
        .collect();
    let (question, stop_condition) = brief_question_and_stop(persistence, &rules);
    let brief = match compile_health_brief(question, stop_condition, persistence, signals) {
        Ok(brief) => brief,
        Err(error) => {
            tracing::debug!(
                event = "watchdog.health_brief_refused",
                observation = "refused",
                detail = ?error,
                "I8.18 drift could not compile into a Diagnostic Brief input"
            );
            return None;
        }
    };
    let prior_ineffective_analyses = state
        .requested_briefs
        .iter()
        .find(|record| record.brief_id == brief.brief_id)
        .map(|record| record.requests)
        .unwrap_or_default();
    let request = request_health_analysis(
        &brief,
        RiskRoute::CheapDiagnosis,
        prior_ineffective_analyses,
    );
    let subject = brief
        .signals
        .first()
        .map(|signal| signal.revision().target.subject_id.clone())
        .unwrap_or_default();
    let denied_effects = deny_brief_effects(&brief, &request, &subject);
    if let Some(record) = state
        .requested_briefs
        .iter_mut()
        .find(|record| record.brief_id == brief.brief_id)
    {
        record.requests += 1;
    } else {
        if state.requested_briefs.len() >= MAX_TRACKED_BRIEFS {
            state.requested_briefs.remove(0);
        }
        state.requested_briefs.push(BriefRequestRecord {
            brief_id: brief.brief_id.clone(),
            requests: 1,
        });
    }
    Some(HealthBriefEmission {
        brief,
        request,
        denied_effects,
    })
}

/// Builds the explicit question and stop condition one brief carries.
///
/// Both derive deterministically from the persistence classification and the
/// sorted member rule identities, so the same drift always asks the same
/// question under the same stop condition. The question names the I08-18
/// proposal vocabulary only; the stop condition repeats the prose bar, so the
/// bounded analysis is asked for a proposal and stopped before any effect.
fn brief_question_and_stop(
    persistence: BriefPersistence,
    rules: &[&'static str],
) -> (String, String) {
    let question = format!(
        "which observed {} drift across {} requires a smaller packet, scope resync, curation, new discriminator, route change, maintenance plan, or Human decision?",
        persistence.as_str(),
        rules.join("+")
    );
    let stop_condition = "stop when the member signals clear on a later interval, when the route degrades to Human review, or when the members no longer compile into one brief; the analysis proposes only and deletes no memory, alters no policy, and terminates no work."
        .to_owned();
    (question, stop_condition)
}

/// Names the #1761 route one bounded analysis request travels.
///
/// The match is exhaustive with no fallback arm, so a new route variant fails
/// compilation here instead of silently travelling under a wrong name.
fn risk_route_name(route: RiskRoute) -> &'static str {
    match route {
        RiskRoute::Observe => "observe",
        RiskRoute::RequestResync => "request_resync",
        RiskRoute::CheapDiagnosis => "cheap_diagnosis",
        RiskRoute::StrongDiagnosis => "strong_diagnosis",
        RiskRoute::Concilium => "concilium",
        RiskRoute::PreauthorizedContainment => "preauthorized_containment",
        RiskRoute::HumanEscalation => "human_escalation",
    }
}

/// Denies every prohibited effect class against the brief and its request.
///
/// Three fail-closed refusals name the brief, three name the bounded analysis
/// request, and each names the subject that stayed untouched. There is no exit
/// that admits a memory delete, a policy alter, or a work termination.
fn deny_brief_effects(
    brief: &HealthDiagnosticBrief,
    request: &HealthAnalysisRequest,
    subject: &str,
) -> Vec<ProhibitedEffectDenial> {
    [
        ProhibitedEffectClass::MemoryDelete,
        ProhibitedEffectClass::PolicyAlter,
        ProhibitedEffectClass::WorkTerminate,
    ]
    .into_iter()
    .flat_map(|class| {
        [
            ProhibitedEffectAttempt::for_health_brief(class, brief, subject.to_owned()).deny(),
            ProhibitedEffectAttempt::for_health_analysis(class, request, subject.to_owned()).deny(),
        ]
    })
    .collect()
}

/// Publishes the compiled Brief, its bounded request, and the refusals.
///
/// The trace is the same bounded operator evidence the signal publication
/// emits: the brief identity, persistence classification, member signal
/// identities, the explicit question and stop condition, the #1761 route the
/// request names with its ineffective-analysis history, and the exact reason
/// each forbidden effect was refused. It is a trace, not a route: nothing is
/// written, dispatched, or authorized here.
fn publish_brief(emission: &HealthBriefEmission) {
    let brief = &emission.brief;
    let request = &emission.request;
    let member_ids = brief
        .signals
        .iter()
        .map(|signal| signal.revision().signal_id.0.clone())
        .collect::<Vec<_>>();
    let denied = emission
        .denied_effects
        .iter()
        .map(|denial| format!("{}={}", denial.class.as_str(), denial.reason))
        .collect::<Vec<_>>();
    tracing::warn!(
        event = "watchdog.health_brief_compiled",
        observation = "observed",
        brief_id = brief.brief_id.as_str(),
        persistence = brief.persistence.as_str(),
        member_signals = ?member_ids,
        question = brief.question.as_str(),
        stop_condition = brief.stop_condition.as_str(),
        route = risk_route_name(request.route),
        prior_ineffective_analyses = request.prior_ineffective_analyses,
        denied_effects = ?denied,
        "I8.18 persistent or cross-cutting drift compiled into one Diagnostic Brief with one bounded Watchdog-Agent analysis request; the analysis proposes only and derives no memory delete, policy alter, or work termination"
    );
}

/// Traces that no health evidence is established, and names the reason.
fn trace_unavailable(reason: HealthNoSignalReason) {
    tracing::debug!(
        event = "watchdog.health_projection_unavailable",
        observation = "unknown",
        reason_code = reason.as_str(),
        "I8.18 health projection has no owner-issued evidence; no signal is opened"
    );
}

/// `AgentLoopSignal`: a repeated supervision signature with no state delta.
///
/// The signature is this owner's own bounded classification of one interval —
/// the sensor map revision, every channel's disposition and interval-close
/// state, every named gap reason, the class of the newest retained record, and
/// the deferred-gap count — built only from typed owner values, never from free
/// text. The state delta is the presence of a newly accepted supervision
/// heartbeat: that append is the only event this owner records which proves the
/// supervised state moved, so a repeated signature with no new heartbeat
/// between the two intervals is a repeated outcome with no state delta behind
/// it. A healthy installation records one heartbeat per tick, so its state
/// delta is present on every interval and the rule stays silent.
fn open_agent_loop(
    previous: &IntervalRecord,
    pair: HealthObservationPair,
    observation: &IntervalObservation,
    current_state_delta: StateDeltaPresence,
    previous_state_delta: StateDeltaPresence,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
) -> Option<HealthSignalEmission> {
    let result = evaluate_agent_loop(
        pair,
        &previous.signature,
        observation.signature.clone(),
        previous_state_delta,
        current_state_delta,
    );
    finish(
        AGENT_LOOP_RULE,
        result,
        silent,
        |detected: eliot_watchdog_core::AgentLoopSignal| {
            emit_health_signal(AGENT_LOOP_RULE, &detected.signal, detected.loop_signature)
        },
    )
}

/// `ContextQualityDrift`: the retained observation packet exceeds the owner's
/// own declared bound while useful expansion stalls and omission regret grows.
///
/// The packet is this owner's bounded retained observation bank, and its bounds
/// are the owner's declared retention ceilings rather than a chosen number, each
/// carrying the evidence identity of the policy value it came from. Acknowledged
/// use is the owner's own acknowledged-cursor advance, so an export window the
/// sink is actually consuming withholds this signal by name — which is exactly
/// the "one-off large packet with acknowledged use" case I8.18 must not open.
fn open_context_quality(
    previous: &IntervalRecord,
    pair: HealthObservationPair,
    corpus: &WatchdogHealthCorpus,
    observation: &IntervalObservation,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
) -> Option<HealthSignalEmission> {
    let before = &previous.corpus;
    let input = ContextQualityObservation {
        packet_bytes: CountDelta {
            previous: before.retained_bytes,
            current: corpus.retained_bytes,
        },
        replay_count: CountDelta {
            previous: before.content_duplicates,
            current: corpus.content_duplicates,
        },
        useful_expansion: CountDelta {
            previous: before.distinct_content,
            current: corpus.distinct_content,
        },
        omission_regret: CountDelta {
            previous: previous.blocking_channels,
            current: observation.blocking_channels,
        },
        acknowledged_use: CountDelta {
            previous: before.acknowledged_sequence,
            current: corpus.acknowledged_sequence,
        },
        bounds: ContextQualityBounds {
            packet_bytes: Some(PolicyBound {
                value: SPOOL_MAX_BYTES,
                policy_evidence: declared_bound_evidence("retention_bytes", SPOOL_MAX_BYTES),
            }),
            replay_count: Some(PolicyBound {
                value: SPOOL_MAX_RECORDS,
                policy_evidence: declared_bound_evidence("retention_records", SPOOL_MAX_RECORDS),
            }),
        },
        pair,
    };
    finish(
        CONTEXT_QUALITY_RULE,
        evaluate_context_quality(input),
        silent,
        |detected: eliot_watchdog_core::ContextQualityDrift| {
            emit_health_signal(
                CONTEXT_QUALITY_RULE,
                &detected.signal,
                detected.signal.revision().target.subject_id.clone(),
            )
        },
    )
}

/// `MemoryUtilityDrift`: the retained corpus grew or degraded along an axis this
/// owner can measure without interpreting anyone's intent.
///
/// Every axis is a count over the same retained records the export and
/// acknowledgement paths already read:
///
/// - `candidates` — records retained past the acknowledged cursor;
/// - `stale` — records past the owner's declared freshness window;
/// - `duplicates` — records repeating an earlier record's encoded content;
/// - `delivery_without_use` — delivered records with no submit-once receipt;
/// - `false_activation` — already-acknowledged content present again;
/// - `negative_transfer` — content present again after its downstream
///   submission was already receipted;
/// - `no_downstream_outcome` — retained intent records whose own escalation
///   produced no submission receipt.
///
/// These are the self-scope observation bank's own axes. They say nothing about
/// any agent's memory, and the rule reads no other field of any record.
fn open_memory_utility(
    previous: &IntervalRecord,
    pair: HealthObservationPair,
    corpus: &WatchdogHealthCorpus,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
) -> Option<HealthSignalEmission> {
    let before = &previous.corpus;
    let input = MemoryUtilityDeltas {
        candidates: CountDelta {
            previous: before.unacknowledged_records,
            current: corpus.unacknowledged_records,
        },
        stale: CountDelta {
            previous: before.stale_records,
            current: corpus.stale_records,
        },
        duplicates: CountDelta {
            previous: before.content_duplicates,
            current: corpus.content_duplicates,
        },
        delivery_without_use: CountDelta {
            previous: before.delivered_without_receipt,
            current: corpus.delivered_without_receipt,
        },
        false_activation: CountDelta {
            previous: before.reused_acknowledged_content,
            current: corpus.reused_acknowledged_content,
        },
        negative_transfer: CountDelta {
            previous: before.reactivated_after_receipt,
            current: corpus.reactivated_after_receipt,
        },
        no_downstream_outcome: CountDelta {
            previous: before.intents_without_receipt,
            current: corpus.intents_without_receipt,
        },
    };
    finish(
        MEMORY_UTILITY_RULE,
        evaluate_memory_utility(pair, input),
        silent,
        |detected: eliot_watchdog_core::MemoryUtilityDrift| {
            emit_health_signal(
                MEMORY_UTILITY_RULE,
                &detected.signal,
                detected.signal.revision().target.subject_id.clone(),
            )
        },
    )
}

/// `ObservationCoverageGap`: retained process activity grew while the expected
/// observation lineage did not, over an interval this owner cannot account for.
///
/// The expected lineage is the independent declared total from
/// [`SENSOR_CHANNEL_MAP`] and is therefore identical in both windows by
/// construction — that is the point: the expected set is a declaration, not a
/// copy of what was read. The activity is the number of retained records the
/// spool owner actually appended, so an installation that recorded nothing new
/// produces no delta and opens nothing. The explanation is this owner's own
/// verdict: only a short channel the map says is wired is unexplained, so the
/// measured missing adapters can never be read as a bypass.
fn open_observation_coverage(
    previous: &IntervalRecord,
    pair: HealthObservationPair,
    observation: &IntervalObservation,
    corpus: &WatchdogHealthCorpus,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
) -> Option<HealthSignalEmission> {
    let input = ObservationCoverageInput {
        manifest_interval_id: pair_current_event(&pair),
        manifest_evidence: EvidenceRef {
            evidence_id: observation.evidence_id.clone(),
        },
        activity: CountDelta {
            previous: previous.corpus.retained_records,
            current: corpus.retained_records,
        },
        expected_lineage: CountDelta {
            previous: observation.expected_lineage,
            current: observation.expected_lineage,
        },
        explanation: observation.explanation,
        pair,
    };
    finish(
        OBSERVATION_COVERAGE_RULE,
        evaluate_observation_coverage(input),
        silent,
        |detected: eliot_watchdog_core::ObservationCoverageGap| {
            emit_health_signal(
                OBSERVATION_COVERAGE_RULE,
                &detected.signal,
                detected.manifest_interval_id,
            )
        },
    )
}

/// `MaintenanceDebt`: this owner's own declared maintenance obligation fell
/// behind, or the escalation work it already started was deferred again.
///
/// The due policy is the owner's own declared backup/export freshness window —
/// the same bound [`crate::WatchdogBackupPort`] already applies to a capture —
/// so a record older than it is a real overdue obligation against a real
/// owner-declared policy rather than a second debt definition. The deferred
/// Problems are this owner's own retained gap reasons with no accepted
/// heartbeat after them, and the stale capabilities are the declared-required
/// channels that have a competent source and still did not cover the interval.
/// The #1689 end-of-activity assessment is untouched: it still runs once before
/// drain, and nothing here duplicates its drain decision.
fn open_maintenance_debt(
    previous: &IntervalRecord,
    pair: HealthObservationPair,
    observation: &IntervalObservation,
    corpus: &WatchdogHealthCorpus,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
) -> Option<HealthSignalEmission> {
    let before = &previous.corpus;
    let input = MaintenanceDebtInput {
        due_policy_overdue: Some(CountDelta {
            previous: before.stale_records,
            current: corpus.stale_records,
        }),
        due_policy_evidence: Some(EvidenceRef {
            evidence_id: sha256_hex(
                encode_identity(&[
                    "watchdog_declared_backup_freshness_ms".to_owned(),
                    WatchdogSpoolBackupLimits::default().page_ttl_ms.to_string(),
                ])
                .as_bytes(),
            ),
        }),
        deferred_problems: CountDelta {
            previous: before.deferred_gap_reasons,
            current: corpus.deferred_gap_reasons,
        },
        stale_capabilities: CountDelta {
            previous: previous.non_continuum_channels,
            current: observation.non_continuum_channels,
        },
        pair,
    };
    finish(
        MAINTENANCE_DEBT_RULE,
        evaluate_maintenance_debt(input),
        silent,
        |detected: eliot_watchdog_core::MaintenanceDebt| {
            emit_health_signal(
                MAINTENANCE_DEBT_RULE,
                &detected.signal,
                detected.due_policy_evidence.evidence_id,
            )
        },
    )
}

/// The evidence identity of one owner-declared retention bound.
fn declared_bound_evidence(name: &str, value: u64) -> EvidenceRef {
    EvidenceRef {
        evidence_id: sha256_hex(
            encode_identity(&[format!("watchdog_declared_{name}"), value.to_string()]).as_bytes(),
        ),
    }
}

/// The manifest interval identity the coverage rule records.
///
/// Read back off the pair's current source event, so the record names the exact
/// interval this owner published rather than a restated label supplied beside
/// it.
fn pair_current_event(pair: &HealthObservationPair) -> String {
    pair.current_event.event_id.clone()
}

/// Routes one rule result into the emission list or the named silence list.
///
/// A refused revision is not a signal and not a silence: it is a typed refusal
/// traced under its own event, so a malformed owner projection is visible
/// rather than indistinguishable from an observed absence.
fn finish<T, F>(
    rule_id: &'static str,
    result: Result<HealthDetection<T>, eliot_watchdog_core::SignalValidationError>,
    silent: &mut Vec<(&'static str, HealthNoSignalReason)>,
    emit: F,
) -> Option<HealthSignalEmission>
where
    F: FnOnce(T) -> HealthSignalEmission,
{
    match result {
        Ok(HealthDetection::Detected(detected)) => Some(emit(detected)),
        Ok(HealthDetection::NoSignal(reason)) => {
            silent.push((rule_id, reason));
            None
        }
        Err(error) => {
            tracing::debug!(
                event = "watchdog.health_rule_refused",
                observation = "refused",
                rule_id = rule_id,
                detail = error.to_string().as_str(),
                "I8.18 health rule refused an unusable signal revision"
            );
            None
        }
    }
}
