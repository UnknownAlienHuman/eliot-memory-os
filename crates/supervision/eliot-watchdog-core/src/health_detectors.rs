//! Evidence-only health drift rules for the existing Watchdog signal model.
//!
//! This module accepts owner-projected observations and policy bounds. It does
//! not read stores, infer intent, accumulate durable state, or authorize an
//! effect. Missing source projections remain explicit `NoSignal` outcomes.

use crate::signals::{
    AcknowledgementFact, CoverageRef, EvidenceRef, ExpectedRevision, ObservedTime, ProfileRevision,
    RecordedValue, ReopenCondition, RuleRevision, Signal, SignalAttribution, SignalDelivery,
    SignalDisposition, SignalId, SignalProcessing, SignalReferences, SignalRevision,
    SignalSeverity, SignalTarget, SourceEventRef,
};

const HEALTH_RULE_REVISION: u64 = 1;

/// Owner-issued context required to construct a normal Watchdog `Signal`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSignalContext {
    /// Exact observed subject, scope, and generation.
    pub target: SignalTarget,
    /// Owner-issued profile revision applied to this observation.
    pub profile: ProfileRevision,
    /// Timestamp for the later observation in the compared pair.
    pub observed_at: ObservedTime,
    /// Owner-issued coverage interval or profile reference.
    pub coverage: CoverageRef,
    /// Context revision observed by the sensor, not an authority grant.
    pub expected_context_revision: ExpectedRevision,
    /// Authority revision observed by the sensor, not an authority grant.
    pub expected_authority_revision: ExpectedRevision,
}

/// Exact source evidence that supports or limits one pairwise comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthEvidenceHandles {
    /// Handles supporting the observed delta.
    pub supporting: Vec<EvidenceRef>,
    /// Handles recording counterevidence or an applicable limitation.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Two source observations that must belong to the same exact target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthObservationPair {
    /// Target identity attached to the earlier source event.
    pub previous_target: SignalTarget,
    /// Later owner-projected observation context.
    pub current: HealthSignalContext,
    /// Exact source event for the earlier observation.
    pub previous_event: SourceEventRef,
    /// Exact source event for the later observation.
    pub current_event: SourceEventRef,
    /// Supporting and counterevidence for the pairwise delta.
    pub evidence: HealthEvidenceHandles,
}

/// Why the source facts do not open a health signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthNoSignalReason {
    /// The input does not contain two distinct source events.
    DistinctObservationsNotProved,
    /// The two observations do not bind the same subject, scope, and generation.
    TargetChanged,
    /// Supporting and counterevidence handles are not both present.
    IncompleteEvidence,
    /// The input contains an explicit unknown source fact or policy bound.
    OwnerEvidenceUnknown,
    /// The compared measurements do not show the required observed delta.
    RequiredDeltaAbsent,
    /// The source manifest explains the coverage gap.
    CoverageGapExplained,
    /// The context packet shows acknowledged useful expansion.
    AcknowledgedUseObserved,
}

/// Result of one deterministic health detector evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthDetection<T> {
    /// A typed evidence-only signal record was produced.
    Detected(T),
    /// Available evidence does not prove an applicable delta.
    NoSignal(HealthNoSignalReason),
}

/// Before and after values copied from one owner projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountDelta {
    /// Value in the earlier observation.
    pub previous: u64,
    /// Value in the later observation.
    pub current: u64,
}

impl CountDelta {
    const fn increased(self) -> bool {
        self.current > self.previous
    }

    const fn unchanged(self) -> bool {
        self.current == self.previous
    }

    const fn did_not_increase(self) -> bool {
        self.current <= self.previous
    }
}

/// Whether an owner-projected source proves an observed state delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDeltaPresence {
    /// The source proves the paired observations have no state delta.
    Absent,
    /// The source proves a state delta occurred.
    Present,
    /// The source cannot establish whether state changed.
    Unknown,
}

/// A repeated tool/plan/error signature without a state delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentLoopSignal {
    /// Existing immutable Watchdog signal envelope.
    pub signal: Signal,
    /// Exact repeated signature from task/runtime evidence.
    pub loop_signature: String,
    /// State-delta result for the earlier observation.
    pub previous_state_delta: StateDeltaPresence,
    /// State-delta result for the later observation.
    pub current_state_delta: StateDeltaPresence,
    /// Handles supporting the repeated no-delta observation.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Handles preserving counterevidence or limitations.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Evaluates a repeated exact signature across two source events.
pub fn evaluate_agent_loop(
    pair: HealthObservationPair,
    previous_signature: &str,
    current_signature: String,
    previous_state_delta: StateDeltaPresence,
    current_state_delta: StateDeltaPresence,
) -> Result<HealthDetection<AgentLoopSignal>, crate::signals::SignalValidationError> {
    if let Some(reason) = pair_no_signal_reason(&pair) {
        return Ok(HealthDetection::NoSignal(reason));
    }
    if previous_state_delta == StateDeltaPresence::Unknown
        || current_state_delta == StateDeltaPresence::Unknown
        || previous_signature.trim().is_empty()
        || current_signature.trim().is_empty()
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    }
    if previous_signature != current_signature.as_str()
        || previous_state_delta != StateDeltaPresence::Absent
        || current_state_delta != StateDeltaPresence::Absent
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::RequiredDeltaAbsent,
        ));
    }
    let signal = build_health_signal("agent_loop_signal", previous_signature, &pair)?;
    Ok(HealthDetection::Detected(AgentLoopSignal {
        signal,
        loop_signature: current_signature,
        previous_state_delta,
        current_state_delta,
        supporting_evidence: pair.evidence.supporting,
        counterevidence: pair.evidence.counterevidence,
    }))
}

/// Source-owned packet/replay bounds, with the exact policy evidence that set them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextQualityBounds {
    /// Maximum packet size supplied by the applicable owner policy.
    pub packet_bytes: Option<PolicyBound>,
    /// Maximum replay count supplied by the applicable owner policy.
    pub replay_count: Option<PolicyBound>,
}

/// A bound and the evidence handle of the policy that supplied it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBound {
    /// Exact bound value from the owner policy.
    pub value: u64,
    /// Evidence handle for that policy value.
    pub policy_evidence: EvidenceRef,
}

/// Source-projected context quality measurements for an observation pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextQualityObservation {
    /// Exact pair and signal metadata.
    pub pair: HealthObservationPair,
    /// Serialized packet size before and after.
    pub packet_bytes: CountDelta,
    /// Replayed packet count before and after.
    pub replay_count: CountDelta,
    /// Useful expansion measure before and after.
    pub useful_expansion: CountDelta,
    /// Omission-regret measure before and after.
    pub omission_regret: CountDelta,
    /// Newly acknowledged-use measure before and after.
    pub acknowledged_use: CountDelta,
    /// Applicable source-owned policy bounds.
    pub bounds: ContextQualityBounds,
}

/// Context packet/replay drift with low expansion and rising omission regret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextQualityDrift {
    /// Existing immutable Watchdog signal envelope.
    pub signal: Signal,
    /// Packet-size change measured from source values.
    pub packet_bytes: CountDelta,
    /// Replay-count change measured from source values.
    pub replay_count: CountDelta,
    /// Useful-expansion change measured from source values.
    pub useful_expansion: CountDelta,
    /// Omission-regret change measured from source values.
    pub omission_regret: CountDelta,
    /// Acknowledged-use change retained as counterevidence.
    pub acknowledged_use: CountDelta,
    /// Exact policy bounds used by this rule.
    pub bounds: ContextQualityBounds,
    /// Handles supporting the observed context-quality delta.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Handles preserving counterevidence or limitations.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Evaluates context drift using only the applicable owner-supplied bounds.
pub fn evaluate_context_quality(
    observation: ContextQualityObservation,
) -> Result<HealthDetection<ContextQualityDrift>, crate::signals::SignalValidationError> {
    if let Some(reason) = pair_no_signal_reason(&observation.pair) {
        return Ok(HealthDetection::NoSignal(reason));
    }
    let (Some(packet_bound), Some(replay_bound)) = (
        observation.bounds.packet_bytes.as_ref(),
        observation.bounds.replay_count.as_ref(),
    ) else {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    };
    if packet_bound.policy_evidence.evidence_id.trim().is_empty()
        || replay_bound.policy_evidence.evidence_id.trim().is_empty()
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    }
    if observation.acknowledged_use.increased() {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::AcknowledgedUseObserved,
        ));
    }
    let packet_or_replay_pressure = observation.packet_bytes.current > packet_bound.value
        || observation.replay_count.current > replay_bound.value;
    if !packet_or_replay_pressure
        || !observation.useful_expansion.did_not_increase()
        || !observation.omission_regret.increased()
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::RequiredDeltaAbsent,
        ));
    }
    let evidence_key = encode_identity(&[
        "context_quality_drift".to_owned(),
        packet_bound.policy_evidence.evidence_id.clone(),
        replay_bound.policy_evidence.evidence_id.clone(),
    ]);
    let mut pair = observation.pair;
    pair.evidence
        .supporting
        .push(packet_bound.policy_evidence.clone());
    pair.evidence
        .supporting
        .push(replay_bound.policy_evidence.clone());
    let signal = build_health_signal("context_quality_drift", &evidence_key, &pair)?;
    Ok(HealthDetection::Detected(ContextQualityDrift {
        signal,
        packet_bytes: observation.packet_bytes,
        replay_count: observation.replay_count,
        useful_expansion: observation.useful_expansion,
        omission_regret: observation.omission_regret,
        acknowledged_use: observation.acknowledged_use,
        bounds: observation.bounds,
        supporting_evidence: pair.evidence.supporting,
        counterevidence: pair.evidence.counterevidence,
    }))
}

/// Owner-projected corpus and downstream-utility counts across one pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryUtilityDeltas {
    /// Candidate corpus count.
    pub candidates: CountDelta,
    /// Stale corpus count.
    pub stale: CountDelta,
    /// Duplicate corpus count.
    pub duplicates: CountDelta,
    /// Delivered items without acknowledged use.
    pub delivery_without_use: CountDelta,
    /// False activations.
    pub false_activation: CountDelta,
    /// Negative-transfer outcomes.
    pub negative_transfer: CountDelta,
    /// Delivered items with no downstream outcome.
    pub no_downstream_outcome: CountDelta,
}

/// Memory utility drift backed by corpus and outcome observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryUtilityDrift {
    /// Existing immutable Watchdog signal envelope.
    pub signal: Signal,
    /// Exact source-projected deltas evaluated by the rule.
    pub observed_delta: MemoryUtilityDeltas,
    /// Handles supporting the observed corpus/outcome delta.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Handles preserving counterevidence or limitations.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Opens on a positive source-derived corpus or adverse utility delta.
pub fn evaluate_memory_utility(
    pair: HealthObservationPair,
    observed_delta: MemoryUtilityDeltas,
) -> Result<HealthDetection<MemoryUtilityDrift>, crate::signals::SignalValidationError> {
    if let Some(reason) = pair_no_signal_reason(&pair) {
        return Ok(HealthDetection::NoSignal(reason));
    }
    let any_increase = observed_delta.candidates.increased()
        || observed_delta.stale.increased()
        || observed_delta.duplicates.increased()
        || observed_delta.delivery_without_use.increased()
        || observed_delta.false_activation.increased()
        || observed_delta.negative_transfer.increased()
        || observed_delta.no_downstream_outcome.increased();
    if !any_increase {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::RequiredDeltaAbsent,
        ));
    }
    let signal = build_health_signal("memory_utility_drift", "memory_utility", &pair)?;
    Ok(HealthDetection::Detected(MemoryUtilityDrift {
        signal,
        observed_delta,
        supporting_evidence: pair.evidence.supporting,
        counterevidence: pair.evidence.counterevidence,
    }))
}

/// Manifest explanation status for an activity/lineage coverage comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageGapExplanation {
    /// The owner manifest records an explanation for the gap.
    Explained,
    /// The owner manifest establishes the gap has no explanation.
    Unexplained,
    /// The owner manifest cannot establish explanation status.
    Unknown,
}

/// Activity and expected-lineage deltas bound to a #1755 interval manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationCoverageInput {
    /// Exact pair and signal metadata.
    pub pair: HealthObservationPair,
    /// Exact interval identity in the owner manifest.
    pub manifest_interval_id: String,
    /// Handle for the owner-issued interval manifest.
    pub manifest_evidence: EvidenceRef,
    /// Observed workspace/process activity count.
    pub activity: CountDelta,
    /// Expected agent/bridge/self-observation lineage count.
    pub expected_lineage: CountDelta,
    /// Whether the manifest explains the observed coverage gap.
    pub explanation: CoverageGapExplanation,
}

/// An observation-coverage gap not explained by the owner manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationCoverageGap {
    /// Existing immutable Watchdog signal envelope.
    pub signal: Signal,
    /// Exact manifest interval evaluated by the rule.
    pub manifest_interval_id: String,
    /// Exact owner-issued manifest evidence handle.
    pub manifest_evidence: EvidenceRef,
    /// Activity delta from the source manifest interval.
    pub activity: CountDelta,
    /// Expected-lineage delta from the source manifest interval.
    pub expected_lineage: CountDelta,
    /// Handles supporting the observed coverage delta.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Handles preserving counterevidence or limitations.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Opens only when activity grows without expected lineage in an unexplained interval.
pub fn evaluate_observation_coverage(
    input: ObservationCoverageInput,
) -> Result<HealthDetection<ObservationCoverageGap>, crate::signals::SignalValidationError> {
    if let Some(reason) = pair_no_signal_reason(&input.pair) {
        return Ok(HealthDetection::NoSignal(reason));
    }
    if input.manifest_interval_id.trim().is_empty()
        || input.manifest_evidence.evidence_id.trim().is_empty()
        || input.explanation == CoverageGapExplanation::Unknown
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    }
    if input.explanation == CoverageGapExplanation::Explained {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::CoverageGapExplained,
        ));
    }
    if !input.activity.increased() || !input.expected_lineage.unchanged() {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::RequiredDeltaAbsent,
        ));
    }
    let mut pair = input.pair;
    pair.evidence
        .supporting
        .push(input.manifest_evidence.clone());
    let signal = build_health_signal(
        "observation_coverage_gap",
        &input.manifest_interval_id,
        &pair,
    )?;
    Ok(HealthDetection::Detected(ObservationCoverageGap {
        signal,
        manifest_interval_id: input.manifest_interval_id,
        manifest_evidence: input.manifest_evidence,
        activity: input.activity,
        expected_lineage: input.expected_lineage,
        supporting_evidence: pair.evidence.supporting,
        counterevidence: pair.evidence.counterevidence,
    }))
}

/// Continuous debt counts projected from #1689 due-policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceDebtInput {
    /// Exact pair and signal metadata.
    pub pair: HealthObservationPair,
    /// Due-policy facts from the existing maintenance owner.
    pub due_policy_overdue: Option<CountDelta>,
    /// Evidence handle for the applicable #1689 due-policy projection.
    pub due_policy_evidence: Option<EvidenceRef>,
    /// Deferred Problem count.
    pub deferred_problems: CountDelta,
    /// Stale capability count.
    pub stale_capabilities: CountDelta,
}

/// Overdue maintenance, deferred Problems, or stale capabilities as observed deltas.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceDebt {
    /// Existing immutable Watchdog signal envelope.
    pub signal: Signal,
    /// Due-policy overdue delta supplied by the maintenance owner.
    pub due_policy_overdue: CountDelta,
    /// Exact owner-issued due-policy evidence handle.
    pub due_policy_evidence: EvidenceRef,
    /// Deferred Problem delta.
    pub deferred_problems: CountDelta,
    /// Stale-capability delta.
    pub stale_capabilities: CountDelta,
    /// Handles supporting the observed maintenance delta.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Handles preserving counterevidence or limitations.
    pub counterevidence: Vec<EvidenceRef>,
}

/// Opens only from a source-projected due-policy or maintenance-debt delta.
pub fn evaluate_maintenance_debt(
    input: MaintenanceDebtInput,
) -> Result<HealthDetection<MaintenanceDebt>, crate::signals::SignalValidationError> {
    if let Some(reason) = pair_no_signal_reason(&input.pair) {
        return Ok(HealthDetection::NoSignal(reason));
    }
    let Some(due_policy_overdue) = input.due_policy_overdue else {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    };
    let Some(due_policy_evidence) = input.due_policy_evidence else {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    };
    if due_policy_evidence.evidence_id.trim().is_empty() {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    }
    if !due_policy_overdue.increased()
        && !input.deferred_problems.increased()
        && !input.stale_capabilities.increased()
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::RequiredDeltaAbsent,
        ));
    }
    let mut pair = input.pair;
    pair.evidence.supporting.push(due_policy_evidence.clone());
    let signal = build_health_signal("maintenance_debt", &due_policy_evidence.evidence_id, &pair)?;
    Ok(HealthDetection::Detected(MaintenanceDebt {
        signal,
        due_policy_overdue,
        due_policy_evidence,
        deferred_problems: input.deferred_problems,
        stale_capabilities: input.stale_capabilities,
        supporting_evidence: pair.evidence.supporting,
        counterevidence: pair.evidence.counterevidence,
    }))
}

fn pair_no_signal_reason(pair: &HealthObservationPair) -> Option<HealthNoSignalReason> {
    if pair.previous_event.event_id == pair.current_event.event_id {
        return Some(HealthNoSignalReason::DistinctObservationsNotProved);
    }
    if pair.previous_target != pair.current.target {
        return Some(HealthNoSignalReason::TargetChanged);
    }
    if pair.evidence.supporting.is_empty()
        || pair.evidence.counterevidence.is_empty()
        || pair.previous_event.event_id.trim().is_empty()
        || pair.current_event.event_id.trim().is_empty()
    {
        return Some(HealthNoSignalReason::IncompleteEvidence);
    }
    None
}

fn build_health_signal(
    rule_id: &str,
    correlation: &str,
    pair: &HealthObservationPair,
) -> Result<Signal, crate::signals::SignalValidationError> {
    let identity_fields = vec![
        rule_id.to_owned(),
        HEALTH_RULE_REVISION.to_string(),
        pair.current.target.subject_id.clone(),
        pair.current.target.scope_id.clone(),
        pair.current.target.generation.to_string(),
        correlation.to_owned(),
    ];
    let dedup_key = encode_identity(&identity_fields);
    let mut evidence = pair.evidence.supporting.clone();
    evidence.extend(pair.evidence.counterevidence.iter().cloned());
    Signal::new(SignalRevision {
        signal_id: SignalId(dedup_key.clone()),
        revision: 1,
        rule: RuleRevision {
            rule_id: rule_id.to_owned(),
            revision: HEALTH_RULE_REVISION,
        },
        profile: pair.current.profile.clone(),
        severity: SignalSeverity::Warning,
        target: pair.current.target.clone(),
        observed_at: RecordedValue::Known(pair.current.observed_at.clone()),
        source_events: SignalReferences::Known(vec![
            pair.previous_event.clone(),
            pair.current_event.clone(),
        ]),
        evidence: SignalReferences::Known(evidence),
        coverage: SignalReferences::Known(vec![pair.current.coverage.clone()]),
        attribution: SignalAttribution::Unknown {
            limitation: "Health drift is an observed delta and does not attribute intent or cause"
                .to_owned(),
        },
        processing: SignalProcessing::Observed,
        delivery: SignalDelivery::Pending,
        disposition: SignalDisposition::Informational,
        acknowledgement: AcknowledgementFact::NotAcknowledged,
        resolution: crate::signals::ResolutionFact::Unresolved,
        dedup_key: RecordedValue::Known(dedup_key),
        reopen_condition: ReopenCondition::RecurrenceWithNewSourceEvent,
        expected_context_revision: pair.current.expected_context_revision.clone(),
        expected_authority_revision: pair.current.expected_authority_revision.clone(),
    })
}

fn encode_identity(fields: &[String]) -> String {
    let mut encoded = String::new();
    for field in fields {
        encoded.push_str(&field.len().to_string());
        encoded.push(':');
        encoded.push_str(field);
    }
    encoded
}
