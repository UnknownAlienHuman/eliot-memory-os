//! Evidence-only health drift rules for the existing Watchdog signal model.
//!
//! This module accepts owner-projected observations and policy bounds. It does
//! not read stores, infer intent, accumulate durable state, or authorize an
//! effect. Missing source projections remain explicit `NoSignal` outcomes.
//!
//! Prose bar: no output of this module - signal, Diagnostic Brief, or analysis
//! request - may delete memory, alter a policy, or terminate work. An attempt to
//! derive such an effect is refused by [`ProhibitedEffectAttempt::deny`], which
//! is the only exit from an effect attempt and admits no class.

use crate::risk::RiskRoute;
use crate::signals::{
    AcknowledgementFact, CoverageRef, EvidenceRef, ExpectedRevision, ObservedTime, ProfileRevision,
    RecordedValue, ReopenCondition, RuleRevision, Signal, SignalAttribution, SignalDelivery,
    SignalDisposition, SignalId, SignalProcessing, SignalReferences, SignalRevision,
    SignalSeverity, SignalTarget, SourceEventRef,
};
use std::collections::BTreeSet;

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

impl HealthNoSignalReason {
    /// Returns the stable wire name of this reason.
    ///
    /// A rule that stayed silent must still say why, in a name the owner can
    /// publish. A caller that reports a `NoSignal` without a reason would make
    /// "no competent source reached this owner" indistinguishable from "the
    /// source observed no delta", and those two are different claims.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DistinctObservationsNotProved => "distinct_observations_not_proved",
            Self::TargetChanged => "target_changed",
            Self::IncompleteEvidence => "incomplete_evidence",
            Self::OwnerEvidenceUnknown => "owner_evidence_unknown",
            Self::RequiredDeltaAbsent => "required_delta_absent",
            Self::CoverageGapExplained => "coverage_gap_explained",
            Self::AcknowledgedUseObserved => "acknowledged_use_observed",
        }
    }
}

/// Result of one deterministic health detector evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthDetection<T> {
    /// A typed evidence-only signal record was produced.
    Detected(T),
    /// Available evidence does not prove an applicable delta.
    NoSignal(HealthNoSignalReason),
}

/// Output families a caller may try to derive from a health evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthOutputFamily {
    /// The evidence-only `Signal` emitted by one detector rule.
    Signal,
    /// A Diagnostic Brief compiled from persistent or cross-cutting drift.
    DiagnosticBrief,
    /// A bounded Dreamer/Watchdog-Agent analysis request.
    AnalysisRequest,
}

/// Effect classes the I08-18 prose bar forbids on every health output.
///
/// A health output is an observed delta. It carries no authority to delete
/// memory, alter a policy, or terminate work, so no effect of these classes can
/// be derived from one - see [`ProhibitedEffectAttempt::deny`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProhibitedEffectClass {
    /// Deleting or purging a memory record.
    MemoryDelete,
    /// Altering an active policy, bound, or authority revision.
    PolicyAlter,
    /// Terminating work the health output does not own.
    WorkTerminate,
}

/// An attempt to execute one forbidden effect on the authority of a health output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProhibitedEffectAttempt {
    /// Output family the caller cites as justification.
    pub output: HealthOutputFamily,
    /// Effect class the caller asks to execute.
    pub class: ProhibitedEffectClass,
    /// Signal identity the caller cites.
    pub signal_id: SignalId,
    /// Exact subject the caller wants the effect applied to.
    pub subject: String,
}

/// Fail-closed outcome: the attempt is refused and nothing is executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProhibitedEffectDenial {
    /// Output family that was cited.
    pub output: HealthOutputFamily,
    /// Effect class that was refused.
    pub class: ProhibitedEffectClass,
    /// Signal identity that was cited.
    pub signal_id: SignalId,
    /// Subject that remains untouched.
    pub subject: String,
    /// Why the cited output carries no authority for this class.
    pub reason: &'static str,
}

impl ProhibitedEffectClass {
    /// Returns the stable wire name of this forbidden effect class.
    ///
    /// A caller publishing a denial names the class it was refused, so the name
    /// an operator reads is the class itself rather than a restatement of the
    /// denial text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryDelete => "memory_delete",
            Self::PolicyAlter => "policy_alter",
            Self::WorkTerminate => "work_terminate",
        }
    }
}

impl ProhibitedEffectAttempt {
    /// Builds the attempt from the signal the caller actually holds.
    ///
    /// The signal identity is read from the immutable revision, so the attempt
    /// is anchored to the output it cites rather than to a restated name.
    #[must_use]
    pub fn for_signal(
        output: HealthOutputFamily,
        class: ProhibitedEffectClass,
        signal: &Signal,
        subject: String,
    ) -> Self {
        Self {
            output,
            class,
            signal_id: signal.revision().signal_id.clone(),
            subject,
        }
    }

    /// Builds the attempt from the Diagnostic Brief the caller actually holds.
    ///
    /// The cited identity is the brief's own derived identity, reused through
    /// the existing [`SignalId`] rather than a new identifier: the attempt must
    /// name the output it cites, and no second identity scheme is introduced.
    /// The only exit remains [`ProhibitedEffectAttempt::deny`].
    #[must_use]
    pub fn for_health_brief(
        class: ProhibitedEffectClass,
        brief: &HealthDiagnosticBrief,
        subject: String,
    ) -> Self {
        Self {
            output: HealthOutputFamily::DiagnosticBrief,
            class,
            signal_id: SignalId(brief.brief_id.clone()),
            subject,
        }
    }

    /// Builds the attempt from the bounded analysis request the caller holds.
    ///
    /// The cited identity is the owning brief's identity, so the attempt stays
    /// anchored to the validated brief input rather than to a restated label.
    /// The only exit remains [`ProhibitedEffectAttempt::deny`].
    #[must_use]
    pub fn for_health_analysis(
        class: ProhibitedEffectClass,
        request: &HealthAnalysisRequest,
        subject: String,
    ) -> Self {
        Self {
            output: HealthOutputFamily::AnalysisRequest,
            class,
            signal_id: SignalId(request.brief_id.clone()),
            subject,
        }
    }

    /// Refuses the attempt.
    ///
    /// This is the only exit from an effect attempt against a health output:
    /// there is no branch that admits a memory delete, a policy change, or a
    /// work termination, and the denial names the subject that stayed
    /// untouched. Each forbidden class states its own reason, so admitting a
    /// new class later would require a new arm here.
    #[must_use]
    pub fn deny(&self) -> ProhibitedEffectDenial {
        ProhibitedEffectDenial {
            output: self.output,
            class: self.class,
            signal_id: self.signal_id.clone(),
            subject: self.subject.clone(),
            reason: match self.class {
                ProhibitedEffectClass::MemoryDelete => "health_output_cannot_delete_memory",
                ProhibitedEffectClass::PolicyAlter => "health_output_cannot_alter_policy",
                ProhibitedEffectClass::WorkTerminate => "health_output_cannot_terminate_work",
            },
        }
    }
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

/// Owner-projected Safety Floor presence for one context observation pair.
///
/// STITCH copies this from the applicable owner policy evaluation: whether the
/// context packet applied to this pair carried the owner-required Safety Floor.
/// The core reads no policy store; an unknown projection stays
/// [`HealthNoSignalReason::OwnerEvidenceUnknown`], never a substituted value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyFloorPresence {
    /// The owner projection establishes the Safety Floor was present.
    Present,
    /// The owner projection establishes the Safety Floor was missing.
    Missing,
    /// The owner projection cannot establish Safety Floor presence.
    Unknown,
}

/// Owner-projected scope and freshness of the feedback applied to one pair.
///
/// STITCH copies this from the owning feedback record: whether the feedback the
/// context packet carries applies to the observed scope and is fresh. A
/// wrong-scope or stale projection is I08-18 pressure; an unknown projection
/// stays [`HealthNoSignalReason::OwnerEvidenceUnknown`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackPlacement {
    /// Feedback applies to the observed scope and is fresh.
    InScopeFresh,
    /// Feedback applies to a different scope than the one observed.
    WrongScope,
    /// Feedback applies to the observed scope but is stale.
    Stale,
    /// Scope or freshness cannot be established by the owner projection.
    Unknown,
}

/// Owner-projected canonical context that completes one context-quality pair.
///
/// The packet/replay bounds in [`ContextQualityObservation`] carry the
/// quantitative pressure; this context carries the two remaining I08-18
/// canonical branches - missing Safety Floor and wrong-scope/stale feedback -
/// as projected by their owners. Both sides are validated originals: unknown
/// stays unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextQualityCanonicalContext {
    /// Safety Floor presence projected by the applicable owner policy.
    pub safety_floor: SafetyFloorPresence,
    /// Feedback scope and freshness projected by the owning feedback record.
    pub feedback: FeedbackPlacement,
}

/// Evaluates context drift using only the applicable owner-supplied bounds.
pub fn evaluate_context_quality(
    observation: ContextQualityObservation,
) -> Result<HealthDetection<ContextQualityDrift>, crate::signals::SignalValidationError> {
    context_quality_with_pressure(observation, false)
}

/// Evaluates context drift with the I08-18 canonical Safety Floor and
/// feedback branches included.
///
/// A missing Safety Floor or wrong-scope/stale feedback is pressure alongside
/// an over-bound packet or replay count: it still requires stalled useful
/// expansion, rising omission regret, and no acknowledged use before a signal
/// opens, so the one-off large packet with acknowledged use stays silent. The
/// shared core below is the single rule body; this entry only validates the
/// canonical originals and names the extra pressure.
pub fn evaluate_context_quality_with_canonical_context(
    observation: ContextQualityObservation,
    canonical: ContextQualityCanonicalContext,
) -> Result<HealthDetection<ContextQualityDrift>, crate::signals::SignalValidationError> {
    if canonical.safety_floor == SafetyFloorPresence::Unknown
        || canonical.feedback == FeedbackPlacement::Unknown
    {
        return Ok(HealthDetection::NoSignal(
            HealthNoSignalReason::OwnerEvidenceUnknown,
        ));
    }
    let canonical_pressure = canonical.safety_floor == SafetyFloorPresence::Missing
        || matches!(
            canonical.feedback,
            FeedbackPlacement::WrongScope | FeedbackPlacement::Stale
        );
    context_quality_with_pressure(observation, canonical_pressure)
}

/// Single shared body of the context-quality rule.
///
/// Both public entries evaluate here, so the pairwise guards, the
/// acknowledged-use suppression, and the expansion/regret thresholds cannot
/// drift between the bounds-only and the canonical-context projections.
fn context_quality_with_pressure(
    observation: ContextQualityObservation,
    canonical_pressure: bool,
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
        || observation.replay_count.current > replay_bound.value
        || canonical_pressure;
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

/// Owner-projected #1755 interval manifest values for one coverage comparison.
///
/// STITCH copies these from the actual owner-issued interval manifest on the
/// same interval the [`ObservationCoverageInput`] names. The core reads no
/// manifest store; this projection is how the supplied interval, evidence, and
/// explanation are validated against the owner's own record before a gap signal
/// may stand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageManifestProjection {
    /// Exact interval identity in the owner-issued manifest.
    pub interval_id: String,
    /// Handle for the owner-issued interval manifest.
    pub evidence: EvidenceRef,
    /// Whether the owner manifest explains the coverage gap.
    pub explanation: CoverageGapExplanation,
}

/// How supplied coverage values contradict the owner-issued manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverageManifestMismatch {
    /// The supplied interval identity differs from the manifest interval.
    IntervalMismatch,
    /// The supplied manifest evidence differs from the manifest handle.
    EvidenceMismatch,
    /// The supplied explanation differs from the manifest verdict.
    ExplanationMismatch,
}

/// Validates supplied coverage values against the owner-issued manifest.
///
/// A gap signal that names a different interval, cites different evidence, or
/// claims a different explanation than the #1755 manifest on that interval is
/// a contradictory coverage claim and must not stand. Each mismatch class is
/// typed so STITCH can project the exact correction.
pub fn validate_observation_coverage_against_manifest(
    input: &ObservationCoverageInput,
    manifest: &CoverageManifestProjection,
) -> Result<(), CoverageManifestMismatch> {
    if input.manifest_interval_id != manifest.interval_id {
        return Err(CoverageManifestMismatch::IntervalMismatch);
    }
    if input.manifest_evidence != manifest.evidence {
        return Err(CoverageManifestMismatch::EvidenceMismatch);
    }
    if input.explanation != manifest.explanation {
        return Err(CoverageManifestMismatch::ExplanationMismatch);
    }
    Ok(())
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

/// Revision of the health Diagnostic Brief input contract.
const HEALTH_BRIEF_REVISION: u64 = 1;

/// Maximum member signals compiled into one Diagnostic Brief input.
///
/// A brief carries its member signals whole, so bounding the member count
/// bounds the evidence the brief can carry into a Dreamer/Watchdog-Agent
/// analysis request.
pub const MAX_BRIEF_SIGNALS: usize = 8;

/// Ineffective-analysis count at which a brief's route requires Human review.
///
/// One ineffective analysis steps the requested #1761 route down; a repeated
/// ineffective analysis rolls back to Human review per I09-17: a repeatedly
/// ineffective action may roll back the candidate route/profile or require
/// Human review.
pub const HUMAN_REVIEW_AFTER_INEFFECTIVE_ANALYSES: u32 = 2;

/// Persistence classification of the drift one brief compiles.
///
/// I08-18 compiles a brief only from persistent or cross-cutting drift: a
/// single-interval delta is a signal, not a brief. The classification travels
/// on the brief so the analysis route can see which claim it is asked about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BriefPersistence {
    /// Drift persisted across the compared observation pairs.
    Persistent,
    /// Drift cuts across more than one rule family or scope.
    CrossCutting,
    /// Drift both persisted and cuts across families or scopes.
    PersistentAndCrossCutting,
}

impl BriefPersistence {
    /// Returns the stable wire name of this persistence classification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::CrossCutting => "cross_cutting",
            Self::PersistentAndCrossCutting => "persistent_and_cross_cutting",
        }
    }
}

/// Diagnostic Brief input compiled from persistent or cross-cutting drift.
///
/// This is the I08-18 brief input, not the doctor's repair-domain brief: it
/// carries member health signals whole, the explicit analysis question, and
/// the stop condition the bounded analysis must honor. It carries no effect
/// authority - see [`ProhibitedEffectAttempt::for_health_brief`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthDiagnosticBrief {
    /// Deterministic identity derived from the member signal identities.
    pub brief_id: String,
    /// Explicit question the bounded analysis is asked.
    pub question: String,
    /// Explicit condition at which the bounded analysis must stop.
    pub stop_condition: String,
    /// Persistence classification the brief was compiled under.
    pub persistence: BriefPersistence,
    /// Independent member signals this brief compiles.
    pub signals: Vec<Signal>,
}

/// Structural failure while compiling a Diagnostic Brief input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BriefBuildError {
    /// No member signal was supplied.
    EmptySignals,
    /// More member signals were supplied than one brief may carry.
    TooManySignals {
        /// Supplied member count.
        actual: usize,
        /// Maximum member count.
        maximum: usize,
    },
    /// The same signal identity was supplied twice; brief members must be an
    /// independent set so one observation is never counted twice.
    DuplicateSignalId {
        /// Repeated signal identity.
        signal_id: String,
    },
    /// A member signal carries an unknown evidence, coverage, or source-event
    /// record, so its original cannot be validated.
    UnvalidatedOriginal {
        /// Signal identity that cannot be validated.
        signal_id: String,
    },
    /// The analysis question is empty or carries control characters.
    EmptyQuestion,
    /// The stop condition is empty or carries control characters.
    EmptyStopCondition,
}

/// Compiles member health signals into one Diagnostic Brief input.
///
/// Every member original is validated: evidence, coverage, and source events
/// must be known records, and member identities must form an independent set.
/// The brief identity derives deterministically from the sorted member
/// identities, so the same member set always compiles to the same brief.
pub fn compile_health_brief(
    question: String,
    stop_condition: String,
    persistence: BriefPersistence,
    signals: Vec<Signal>,
) -> Result<HealthDiagnosticBrief, BriefBuildError> {
    if !non_empty_text(&question) {
        return Err(BriefBuildError::EmptyQuestion);
    }
    if !non_empty_text(&stop_condition) {
        return Err(BriefBuildError::EmptyStopCondition);
    }
    if signals.is_empty() {
        return Err(BriefBuildError::EmptySignals);
    }
    if signals.len() > MAX_BRIEF_SIGNALS {
        return Err(BriefBuildError::TooManySignals {
            actual: signals.len(),
            maximum: MAX_BRIEF_SIGNALS,
        });
    }
    let mut member_ids = BTreeSet::new();
    for signal in &signals {
        let revision = signal.revision();
        if !original_validated(revision) {
            return Err(BriefBuildError::UnvalidatedOriginal {
                signal_id: revision.signal_id.0.clone(),
            });
        }
        if !member_ids.insert(revision.signal_id.0.clone()) {
            return Err(BriefBuildError::DuplicateSignalId {
                signal_id: revision.signal_id.0.clone(),
            });
        }
    }
    let mut identity_fields = vec![
        "health_diagnostic_brief".to_owned(),
        HEALTH_BRIEF_REVISION.to_string(),
        persistence.as_str().to_owned(),
    ];
    identity_fields.extend(member_ids);
    Ok(HealthDiagnosticBrief {
        brief_id: encode_identity(&identity_fields),
        question,
        stop_condition,
        persistence,
        signals,
    })
}

/// One bounded Dreamer/Watchdog-Agent analysis request for a compiled brief.
///
/// Exactly one request leaves per call: a persistent drift compiles a brief
/// and one bounded analysis request, never a campaign. The route reuses the
/// existing #1761 [`RiskRoute`] contract - no parallel escalation path is
/// introduced here. The request carries the brief's question and stop
/// condition unchanged and no effect authority - see
/// [`ProhibitedEffectAttempt::for_health_analysis`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthAnalysisRequest {
    /// Identity of the owning compiled brief.
    pub brief_id: String,
    /// #1761 route selected for this request after rollback degradation.
    pub route: RiskRoute,
    /// Explicit question carried over from the owning brief.
    pub question: String,
    /// Explicit stop condition carried over from the owning brief.
    pub stop_condition: String,
    /// Ineffective-analysis count observed for this brief before this request.
    pub prior_ineffective_analyses: u32,
}

/// Requests one bounded analysis for a compiled brief through #1761 routes.
///
/// The route degrades with the ineffective-analysis history per I09-17's
/// rollback rule: one ineffective analysis steps the route down, a repeated
/// ineffective history requires Human review. The question and stop condition
/// are carried over from the validated brief unchanged.
#[must_use]
pub fn request_health_analysis(
    brief: &HealthDiagnosticBrief,
    route: RiskRoute,
    prior_ineffective_analyses: u32,
) -> HealthAnalysisRequest {
    HealthAnalysisRequest {
        brief_id: brief.brief_id.clone(),
        route: degraded_route_for_ineffective_history(route, prior_ineffective_analyses),
        question: brief.question.clone(),
        stop_condition: brief.stop_condition.clone(),
        prior_ineffective_analyses,
    }
}

/// Degrades a requested route with the ineffective-analysis history.
///
/// A first ineffective analysis steps the requested route down one authority
/// level; a repeatedly ineffective history rolls back to Human review. A route
/// that already is Human review stays there.
fn degraded_route_for_ineffective_history(
    route: RiskRoute,
    prior_ineffective_analyses: u32,
) -> RiskRoute {
    if prior_ineffective_analyses >= HUMAN_REVIEW_AFTER_INEFFECTIVE_ANALYSES {
        return RiskRoute::HumanEscalation;
    }
    if prior_ineffective_analyses == 0 {
        return route;
    }
    match route {
        RiskRoute::Observe | RiskRoute::RequestResync | RiskRoute::CheapDiagnosis => {
            RiskRoute::Observe
        }
        RiskRoute::StrongDiagnosis => RiskRoute::CheapDiagnosis,
        RiskRoute::Concilium => RiskRoute::StrongDiagnosis,
        RiskRoute::PreauthorizedContainment => RiskRoute::Concilium,
        RiskRoute::HumanEscalation => RiskRoute::HumanEscalation,
    }
}

/// Whether a member signal original is validated for brief membership.
///
/// The evidence, coverage, and source-event records must all be known and
/// non-empty: a brief compiled over an unknown original could not say what
/// the analysis is asked about.
fn original_validated(revision: &SignalRevision) -> bool {
    let evidence_known = match &revision.evidence {
        SignalReferences::Known(references) => !references.is_empty(),
        SignalReferences::Unknown { .. } => false,
    };
    let coverage_known = match &revision.coverage {
        SignalReferences::Known(references) => !references.is_empty(),
        SignalReferences::Unknown { .. } => false,
    };
    let source_events_known = match &revision.source_events {
        SignalReferences::Known(references) => !references.is_empty(),
        SignalReferences::Unknown { .. } => false,
    };
    evidence_known && coverage_known && source_events_known
}

/// Whether a question or stop condition carries publishable text.
///
/// Both fields travel into a bounded analysis request, so neither may be
/// empty, blank, or carry control characters.
fn non_empty_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}
