//! Versioned, deterministic Watchdog risk evidence accumulation with top-level input bounds.
//!
//! This module preserves the multidimensional evidence vector and groups
//! observations by retained event identity and explicit common lineage.
//! Numeric pressure and routing remain unconfigured until a policy owner
//! supplies and approves their parameters.

use crate::signals::{
    ClockDomain, CoverageRef, EvidenceRef, ObservedTime, ProfileRevision, RecordedValue, Signal,
    SignalReferences, SignalRevision, SignalTarget, TimeUnit,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Version of the closed input and result contract.
pub const RISK_ACCUMULATOR_SCHEMA_VERSION: u16 = 1;

/// Exact subject, scope, and resource generations considered together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskSubject {
    /// Subject, scope, and generation targeted by every considered signal.
    pub target: SignalTarget,
    /// Exact resource generations in this risk scope.
    pub resource_generations: BTreeMap<String, u64>,
}

/// Inclusive start and exclusive end of the observation window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskObservationWindow {
    /// Start of the window.
    pub start: ObservedTime,
    /// End of the window.
    pub end: ObservedTime,
}

/// Explicit clock reading and continuity evidence for one evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskTimeReading {
    /// Current time reading.
    pub at: ObservedTime,
    /// Whether the interval since the previous trusted reading is continuous.
    pub continuity: RiskClockContinuity,
}

/// Clock continuity state supplied by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskClockContinuity {
    /// The caller establishes an uninterrupted interval in this clock domain.
    Continuous,
    /// A jump, reboot, or missing interval prevents safe decay.
    Discontinuous { reason: String },
    /// Continuity cannot be established.
    Unknown { limitation: String },
}

/// Observation coverage state for the evaluated window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskCoverageState {
    /// The sensor observed the interval live.
    Continuous,
    /// A journal covered the interval after wake.
    JournalReplayed,
    /// Some sources or sequence ranges are missing.
    Partial,
    /// No competent source covered the interval.
    Blind,
    /// Coverage cannot be established.
    Unknown { limitation: String },
}

/// Coverage manifest bound to the exact risk window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskCoverageManifest {
    /// Window for which coverage is claimed.
    pub window: RiskObservationWindow,
    /// Coverage state.
    pub state: RiskCoverageState,
    /// Coverage records supporting the state.
    pub sources: Vec<CoverageRef>,
    /// Explicit source or interval gaps.
    pub gaps: Vec<String>,
}

/// Retained producer, cursor, event, and content identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RiskSourceIdentity {
    /// Producer that emitted the observation.
    pub producer_id: String,
    /// Retained producer cursor or partition position.
    pub cursor_id: String,
    /// Stable event identity at that cursor.
    pub event_id: String,
    /// Digest of the event content.
    pub content_digest: String,
}

/// Source identity, or an explicit limitation when origin is unavailable.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskSourceLineage {
    /// Producer, cursor, event, and content digest are retained.
    Known(RiskSourceIdentity),
    /// Origin is unavailable and must not be treated as independent.
    Unknown { limitation: String },
}

/// Immutable identity for one signal revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RiskSignalRevisionRef {
    /// Stable signal identity.
    pub signal_id: String,
    /// Exact immutable revision.
    pub revision: u64,
}

/// Provenance reference for one assessed risk value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskProvenance {
    /// Signal revision used by the assessment.
    Signal(RiskSignalRevisionRef),
    /// Evidence artifact used by the assessment.
    Evidence(EvidenceRef),
    /// Coverage artifact used by the assessment.
    Coverage(CoverageRef),
    /// Retained source event used by the assessment.
    SourceEvent(RiskSourceIdentity),
    /// Versioned deterministic derivation used by the assessment.
    Derivation { method_id: String, revision: u64 },
}

/// A measured, inferred, or explicitly unknown value with provenance.
#[derive(Clone, Debug, PartialEq)]
pub enum RiskAssessment<T> {
    /// Directly measured value.
    Measured {
        /// Observed value.
        value: T,
        /// Evidence lineage for the measurement.
        provenance: Vec<RiskProvenance>,
    },
    /// Inferred value.
    Inferred {
        /// Inferred value.
        value: T,
        /// Evidence lineage and derivation for the inference.
        provenance: Vec<RiskProvenance>,
    },
    /// Value is unavailable or cannot be established.
    Unknown {
        /// Explicit limitation.
        limitation: String,
        /// Evidence lineage or source of the limitation.
        provenance: Vec<RiskProvenance>,
    },
}

/// Impact and effect classes without a Watchdog-invented taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactEffectClass {
    /// Producer or policy supplied impact class.
    pub impact_class: String,
    /// Producer or policy supplied effect class.
    pub effect_class: String,
}

/// One separately evidenced occurrence, including a reopen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskOccurrence {
    /// Stable identity used to avoid counting retransmissions twice.
    pub occurrence_id: String,
    /// Time of the occurrence in its recorded clock domain.
    pub at: ObservedTime,
    /// Whether this is a new occurrence or an explicit reopen.
    pub kind: RiskOccurrenceKind,
    /// Provenance for the occurrence identity and time.
    pub provenance: Vec<RiskProvenance>,
}

/// Occurrence lifecycle classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskOccurrenceKind {
    /// A distinct recurrence.
    Recurrence,
    /// An explicitly reopened observation.
    Reopened,
}

/// Recurrence evidence with stable occurrence identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecurrenceEvidence {
    /// Occurrences supplied by the evidence producer.
    pub occurrences: Vec<RiskOccurrence>,
}

/// Observation confidence and coverage as separate values.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceConfidenceCoverage {
    /// Confidence in the evidence, when quantified by its producer.
    pub confidence: Option<f64>,
    /// Coverage state supporting the evidence.
    pub coverage: RiskCoverageState,
}

/// One propagation path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskPropagationPath {
    /// Source resource.
    pub from: String,
    /// Destination resource.
    pub to: String,
    /// Intermediary resources in observed order.
    pub via: Vec<String>,
}

/// Propagation evidence and affected resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropagationEvidence {
    /// Resources within the observed propagation scope.
    pub affected_resources: Vec<String>,
    /// Supported propagation paths.
    pub paths: Vec<RiskPropagationPath>,
}

/// Reversibility and remaining external effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReversibilityResidualEffects {
    /// Producer or policy supplied reversibility classification.
    pub reversibility: String,
    /// Residual or external effects that may remain.
    pub residual_effects: Vec<String>,
}

/// Persistence and compromise potential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistenceCompromise {
    /// Persistence classification.
    pub persistence: String,
    /// Compromise-potential classification.
    pub compromise_potential: String,
}

/// Uncertainty and common-lineage claims retained as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UncertaintyCommonLineage {
    /// Explicit uncertainties.
    pub uncertainties: Vec<String>,
    /// Common-lineage claims, including unresolved attribution.
    pub common_lineage_claims: Vec<String>,
}

/// One damage or repair history item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DamageRepairEntry {
    /// Event time; unknown history remains explicit.
    pub at: RecordedValue<ObservedTime>,
    /// Producer or policy supplied event class.
    pub event_class: String,
    /// Description of damage, repair, failure, or residual effect.
    pub description: String,
    /// Supporting evidence handles.
    pub evidence: Vec<EvidenceRef>,
}

/// Damage and repair history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DamageRepairHistory {
    /// Ordered history entries.
    pub entries: Vec<DamageRepairEntry>,
}

/// Attribution for one supporting or counterevidence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskAttribution {
    /// Attribution is known.
    Known { principal_id: String },
    /// Attribution is suspected.
    Suspected { principal_id: String },
    /// Attribution is unknown.
    Unknown { limitation: String },
}

/// One evidence claim; contradictory claims and attribution are preserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskEvidenceClaim {
    /// Evidence artifact.
    pub evidence: EvidenceRef,
    /// Claim text or producer supplied classification.
    pub statement: String,
    /// Attribution attached to this claim.
    pub attribution: RiskAttribution,
}

/// Complete multidimensional risk evidence vector.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskEvidenceVector {
    /// Impact and effect class.
    pub impact_effect_class: RiskAssessment<ImpactEffectClass>,
    /// Recurrence and explicit reopen history.
    pub recurrence: RiskAssessment<RecurrenceEvidence>,
    /// Evidence confidence and observation coverage.
    pub evidence_confidence_coverage: RiskAssessment<EvidenceConfidenceCoverage>,
    /// Propagation and blast radius.
    pub propagation: RiskAssessment<PropagationEvidence>,
    /// Reversibility and residual effects.
    pub reversibility_residual_effects: RiskAssessment<ReversibilityResidualEffects>,
    /// Persistence and compromise potential.
    pub persistence_compromise: RiskAssessment<PersistenceCompromise>,
    /// Uncertainty and common-lineage evidence.
    pub uncertainty_common_lineage: RiskAssessment<UncertaintyCommonLineage>,
    /// Current damage and repair history.
    pub damage_repair_history: RiskAssessment<DamageRepairHistory>,
    /// Supporting evidence; all claims remain visible.
    pub supporting_evidence: RiskAssessment<Vec<RiskEvidenceClaim>>,
    /// Counterevidence; all claims remain visible.
    pub counterevidence: RiskAssessment<Vec<RiskEvidenceClaim>>,
}

/// One immutable observation and its complete evidence vector.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskObservation {
    /// Immutable Watchdog signal revision.
    pub signal: Signal,
    /// Retained event identity, or explicit unknown origin.
    pub source_lineage: RiskSourceLineage,
    /// Exact resource generations observed with this signal.
    pub resource_generations: BTreeMap<String, u64>,
    /// Complete multidimensional evidence vector.
    pub evidence: RiskEvidenceVector,
}

/// Explicit shared-origin relation between retained events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskLineageRelation {
    /// First source event.
    pub left: RiskSourceIdentity,
    /// Second source event.
    pub right: RiskSourceIdentity,
    /// Evidence supporting the common-lineage relation.
    pub provenance: Vec<RiskProvenance>,
}

/// Closed, versioned input to one deterministic accumulation.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskAccumulatorInput {
    /// Input schema version.
    pub schema_version: u16,
    /// Exact subject, scope, and resource generations.
    pub subject: RiskSubject,
    /// Policy revision governing this evaluation.
    pub policy_revision: ProfileRevision,
    /// Evaluated observation window.
    pub window: RiskObservationWindow,
    /// Explicit current time and clock continuity.
    pub time: RiskTimeReading,
    /// Coverage manifest for this window.
    pub coverage: RiskCoverageManifest,
    /// Signals and their multidimensional evidence.
    pub observations: Vec<RiskObservation>,
    /// Explicit common-lineage relationships.
    pub lineage_relations: Vec<RiskLineageRelation>,
}

/// Frozen profile for top-level input bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskAccumulatorProfile {
    /// Exact policy revision used by the input.
    pub revision: ProfileRevision,
    /// Maximum source observations accepted by one evaluation.
    pub maximum_observations: u32,
    /// Maximum explicit lineage relations accepted by one evaluation.
    pub maximum_lineage_relations: u32,
    /// Maximum observation-window duration.
    pub maximum_window: Duration,
}

/// Stable identity of a considered source observation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskMemberId {
    /// Retained producer/cursor/event identity and payload digest.
    Known(RiskSourceIdentity),
    /// Unknown-origin observation keyed by immutable signal revision.
    Unknown(RiskSignalRevisionRef),
}

/// Window-membership confidence for a retained member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskWindowMembership {
    /// Event time was verified inside the requested window.
    Verified,
    /// Event time or clock domain cannot establish membership.
    Unverifiable,
}

/// Complete considered membership for one deduplicated source observation.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskAccumulatorMember {
    /// Deterministic member identity.
    pub id: RiskMemberId,
    /// Every distinct signal revision associated with this exact event.
    pub observations: Vec<RiskObservation>,
    /// Number of exact duplicate signal revisions collapsed.
    pub exact_replay_count: u32,
    /// Whether this member's timestamp could be placed in the window.
    pub window_membership: RiskWindowMembership,
}

/// Relationship of members inside a lineage group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskLineageKind {
    /// One known source event without a shared-origin relation.
    Independent,
    /// Multiple events share explicit or identical source origin.
    Correlated,
    /// Origin is unknown; members are conservatively not independent.
    UnknownOrigin,
}

/// Deterministic lineage-group identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RiskLineageGroupId {
    /// First member in canonical order.
    pub first_member: RiskMemberId,
}

/// Pressure state for one lineage group.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskPressureView {
    /// Numeric decayed pressure, unavailable until a qualified numeric profile exists.
    pub decayed: Option<f64>,
    /// Distinct reopen occurrence identities retained in this group.
    pub reopened_occurrences: Vec<String>,
    /// Why pressure could not be computed.
    pub unavailable_reason: Option<RiskPressureUnavailableReason>,
}

/// Reason a numeric pressure projection is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskPressureUnavailableReason {
    /// No numeric parameters were supplied by an approved policy owner.
    NumericPolicyNotConfigured,
    /// Clock continuity is discontinuous or unknown.
    ClockContinuityUnqualified,
    /// Evidence coverage is incomplete.
    CoverageIncomplete,
}

/// Correlated lineage group with complete membership.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskLineageGroup {
    /// Deterministic group identity.
    pub id: RiskLineageGroupId,
    /// Group members in canonical order.
    pub members: Vec<RiskMemberId>,
    /// Independence status.
    pub kind: RiskLineageKind,
    /// Decayed and reopened triage pressure reference.
    pub pressure: RiskPressureView,
}

/// Explicit reason an observation was excluded.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskExclusionReason {
    /// Signal subject, scope, or subject generation differs.
    SubjectMismatch,
    /// Resource generations differ from the requested scope.
    ResourceGenerationMismatch,
    /// Event time is outside the observation window.
    OutsideObservationWindow,
}

/// Signal excluded from considered membership with its exact reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskExclusion {
    /// Exact excluded signal revision.
    pub signal: RiskSignalRevisionRef,
    /// Exclusion reason.
    pub reason: RiskExclusionReason,
}

/// Explicit coverage or provenance gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskCoverageGap {
    /// Stable gap classification.
    pub reason: RiskCoverageGapReason,
    /// Signal revision when the gap is local to one observation.
    pub signal: Option<RiskSignalRevisionRef>,
    /// Human-readable source limitation.
    pub detail: String,
}

/// Closed gap classifications emitted by this evaluator.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskCoverageGapReason {
    /// Declared coverage state is incomplete.
    DeclaredCoverageIncomplete,
    /// Observation timestamp is unknown or incomparable.
    ObservationTimeUnverifiable,
    /// Explicit lineage relation names a missing event.
    LineageEndpointMissing,
    /// Origin is unknown and cannot establish independence.
    UnknownOrigin,
    /// Clock continuity cannot support safe time decay.
    ClockContinuityUnqualified,
    /// Coverage window differs from the evaluated window.
    CoverageWindowMismatch,
}

/// Selected response route, or an explicit unselected state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskRouteSelection {
    /// A policy selected this route; it does not authorize the effect.
    Selected { route: RiskRoute, rule_id: String },
    /// No numeric policy is configured to select a route.
    Unselected {
        reason: RiskPressureUnavailableReason,
    },
}

/// Flexible Watchdog response route from the risk contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskRoute {
    /// Continue observation.
    Observe,
    /// Request an observation resync.
    RequestResync,
    /// Request inexpensive diagnosis.
    CheapDiagnosis,
    /// Request stronger diagnosis.
    StrongDiagnosis,
    /// Request Concilium review.
    Concilium,
    /// Select a preauthorized-containment route for a separate authority check.
    PreauthorizedContainment,
    /// Escalate to a Human.
    HumanEscalation,
}

/// Closed, versioned accumulator result.
#[derive(Clone, Debug, PartialEq)]
pub struct RiskAccumulatorView {
    /// Result schema version.
    pub schema_version: u16,
    /// Exact subject and resource generations.
    pub subject: RiskSubject,
    /// Policy revision used by this evaluation.
    pub policy_revision: ProfileRevision,
    /// Window and clock reading used by this evaluation.
    pub window: RiskObservationWindow,
    /// Explicit clock reading and continuity evidence.
    pub time: RiskTimeReading,
    /// Coverage manifest used by this evaluation.
    pub coverage: RiskCoverageManifest,
    /// Complete considered membership after exact replay collapse.
    pub considered_members: Vec<RiskAccumulatorMember>,
    /// Explicitly excluded observations.
    pub exclusions: Vec<RiskExclusion>,
    /// Explicit gaps and unknowns.
    pub gaps: Vec<RiskCoverageGap>,
    /// Transitive, deterministic lineage groups.
    pub lineage_groups: Vec<RiskLineageGroup>,
    /// Optional policy score; absent until an approved numeric profile exists.
    pub score: Option<f64>,
    /// Explanation for the score state.
    pub score_explanation: String,
    /// Selected route, or the explicit lack of a qualified selection.
    pub selected_route: RiskRouteSelection,
}

/// Structural or bound failure during risk accumulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RiskAccumulatorError {
    /// Input schema is not supported.
    UnsupportedSchema { observed: u16 },
    /// Input and frozen profile revisions differ.
    PolicyRevisionMismatch,
    /// A required identity or limitation is empty or malformed.
    InvalidField(&'static str),
    /// Window or time reading cannot be compared in one clock domain.
    InvalidWindowClock,
    /// Window end precedes its start.
    InvalidWindowOrder,
    /// Window exceeds the frozen profile bound.
    WindowLimitExceeded,
    /// Observation count exceeds the frozen profile bound.
    ObservationLimitExceeded { actual: usize, maximum: u32 },
    /// Lineage relation count exceeds the frozen profile bound.
    LineageLimitExceeded { actual: usize, maximum: u32 },
    /// Same immutable signal revision carried conflicting content or source identity.
    ConflictingSignalRevision(RiskSignalRevisionRef),
}

/// Evaluates one bounded risk input with an explicit frozen profile.
pub fn evaluate_risk_accumulator(
    input: RiskAccumulatorInput,
    profile: &RiskAccumulatorProfile,
) -> Result<RiskAccumulatorView, RiskAccumulatorError> {
    validate_accumulator_input(&input, profile)?;
    let mut gaps = initial_coverage_gaps(&input);
    let (mut members, mut exclusions) = collect_observations(&input, &mut gaps)?;
    let mut lineage_groups = build_lineage_groups(&members, &input, &mut gaps)?;
    sort_result_metadata(
        &mut members,
        &mut exclusions,
        &mut gaps,
        &mut lineage_groups,
    );

    Ok(RiskAccumulatorView {
        schema_version: RISK_ACCUMULATOR_SCHEMA_VERSION,
        subject: input.subject,
        policy_revision: input.policy_revision,
        window: input.window,
        time: input.time,
        coverage: input.coverage,
        considered_members: members.into_values().collect(),
        exclusions,
        gaps,
        lineage_groups,
        score: None,
        score_explanation: "no approved numeric accumulation profile is configured; raw dimensions and lineage are retained".to_owned(),
        selected_route: RiskRouteSelection::Unselected {
            reason: RiskPressureUnavailableReason::NumericPolicyNotConfigured,
        },
    })
}

fn validate_accumulator_input(
    input: &RiskAccumulatorInput,
    profile: &RiskAccumulatorProfile,
) -> Result<(), RiskAccumulatorError> {
    if input.schema_version != RISK_ACCUMULATOR_SCHEMA_VERSION {
        return Err(RiskAccumulatorError::UnsupportedSchema {
            observed: input.schema_version,
        });
    }
    if input.policy_revision != profile.revision {
        return Err(RiskAccumulatorError::PolicyRevisionMismatch);
    }
    if profile.maximum_observations == 0
        || profile.maximum_lineage_relations == 0
        || profile.maximum_window.is_zero()
    {
        return Err(RiskAccumulatorError::InvalidField("profile_bounds"));
    }
    validate_input_limits(input, profile)?;
    validate_window(&input.window, &input.time.at, profile.maximum_window)?;
    validate_profile_revision(&profile.revision)?;
    validate_subject(&input.subject)
}

fn validate_input_limits(
    input: &RiskAccumulatorInput,
    profile: &RiskAccumulatorProfile,
) -> Result<(), RiskAccumulatorError> {
    if input.observations.len() > profile.maximum_observations as usize {
        return Err(RiskAccumulatorError::ObservationLimitExceeded {
            actual: input.observations.len(),
            maximum: profile.maximum_observations,
        });
    }
    if input.lineage_relations.len() > profile.maximum_lineage_relations as usize {
        return Err(RiskAccumulatorError::LineageLimitExceeded {
            actual: input.lineage_relations.len(),
            maximum: profile.maximum_lineage_relations,
        });
    }
    Ok(())
}

fn initial_coverage_gaps(input: &RiskAccumulatorInput) -> Vec<RiskCoverageGap> {
    let mut gaps = Vec::new();
    if input.coverage.window != input.window {
        gaps.push(RiskCoverageGap {
            reason: RiskCoverageGapReason::CoverageWindowMismatch,
            signal: None,
            detail: "coverage manifest window differs from accumulator window".to_owned(),
        });
    }
    if !matches!(
        &input.coverage.state,
        RiskCoverageState::Continuous | RiskCoverageState::JournalReplayed
    ) || !input.coverage.gaps.is_empty()
        || input.coverage.sources.is_empty()
    {
        gaps.push(RiskCoverageGap {
            reason: RiskCoverageGapReason::DeclaredCoverageIncomplete,
            signal: None,
            detail: if input.coverage.sources.is_empty() {
                "coverage manifest has no source references".to_owned()
            } else {
                "coverage state or manifest reports a gap".to_owned()
            },
        });
    }
    if !matches!(&input.time.continuity, RiskClockContinuity::Continuous) {
        gaps.push(RiskCoverageGap {
            reason: RiskCoverageGapReason::ClockContinuityUnqualified,
            signal: None,
            detail: match &input.time.continuity {
                RiskClockContinuity::Continuous => String::new(),
                RiskClockContinuity::Discontinuous { reason } => reason.clone(),
                RiskClockContinuity::Unknown { limitation } => limitation.clone(),
            },
        });
    }
    gaps
}

fn collect_observations(
    input: &RiskAccumulatorInput,
    gaps: &mut Vec<RiskCoverageGap>,
) -> Result<
    (
        BTreeMap<RiskMemberId, RiskAccumulatorMember>,
        Vec<RiskExclusion>,
    ),
    RiskAccumulatorError,
> {
    let mut members = BTreeMap::new();
    let mut exclusions = Vec::new();
    let mut revisions = BTreeMap::<RiskSignalRevisionRef, RiskObservation>::new();

    for observation in &input.observations {
        validate_observation(observation)?;
        let signal_ref = signal_revision_ref(observation.signal.revision());
        if let Some(existing) = revisions.get(&signal_ref) {
            if existing != observation {
                return Err(RiskAccumulatorError::ConflictingSignalRevision(signal_ref));
            }
        } else {
            revisions.insert(signal_ref.clone(), observation.clone());
        }
        collect_observation(
            observation,
            &signal_ref,
            input,
            &mut members,
            &mut exclusions,
            gaps,
        )?;
    }
    Ok((members, exclusions))
}

fn collect_observation(
    observation: &RiskObservation,
    signal_ref: &RiskSignalRevisionRef,
    input: &RiskAccumulatorInput,
    members: &mut BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    exclusions: &mut Vec<RiskExclusion>,
    gaps: &mut Vec<RiskCoverageGap>,
) -> Result<(), RiskAccumulatorError> {
    let Some(window_membership) =
        classify_observation(observation, signal_ref, input, exclusions, gaps)
    else {
        return Ok(());
    };
    if let RiskSourceLineage::Unknown { limitation } = &observation.source_lineage {
        gaps.push(RiskCoverageGap {
            reason: RiskCoverageGapReason::UnknownOrigin,
            signal: Some(signal_ref.clone()),
            detail: limitation.clone(),
        });
    }
    let id = match &observation.source_lineage {
        RiskSourceLineage::Known(identity) => RiskMemberId::Known(identity.clone()),
        RiskSourceLineage::Unknown { .. } => RiskMemberId::Unknown(signal_ref.clone()),
    };
    insert_member(members, id, observation, signal_ref, window_membership)
}

fn classify_observation(
    observation: &RiskObservation,
    signal_ref: &RiskSignalRevisionRef,
    input: &RiskAccumulatorInput,
    exclusions: &mut Vec<RiskExclusion>,
    gaps: &mut Vec<RiskCoverageGap>,
) -> Option<RiskWindowMembership> {
    let revision = observation.signal.revision();
    if revision.target != input.subject.target {
        exclusions.push(RiskExclusion {
            signal: signal_ref.clone(),
            reason: RiskExclusionReason::SubjectMismatch,
        });
        return None;
    }
    if observation.resource_generations != input.subject.resource_generations {
        exclusions.push(RiskExclusion {
            signal: signal_ref.clone(),
            reason: RiskExclusionReason::ResourceGenerationMismatch,
        });
        return None;
    }
    classify_window_membership(revision, signal_ref, &input.window, gaps, exclusions)
}

fn classify_window_membership(
    revision: &SignalRevision,
    signal_ref: &RiskSignalRevisionRef,
    window: &RiskObservationWindow,
    gaps: &mut Vec<RiskCoverageGap>,
    exclusions: &mut Vec<RiskExclusion>,
) -> Option<RiskWindowMembership> {
    match &revision.observed_at {
        RecordedValue::Known(at) => match in_window(at, window) {
            Some(true) => Some(RiskWindowMembership::Verified),
            Some(false) => {
                exclusions.push(RiskExclusion {
                    signal: signal_ref.clone(),
                    reason: RiskExclusionReason::OutsideObservationWindow,
                });
                None
            }
            None => {
                gaps.push(RiskCoverageGap {
                    reason: RiskCoverageGapReason::ObservationTimeUnverifiable,
                    signal: Some(signal_ref.clone()),
                    detail: "signal clock domain cannot be compared with the window".to_owned(),
                });
                Some(RiskWindowMembership::Unverifiable)
            }
        },
        RecordedValue::Unknown { limitation } => {
            gaps.push(RiskCoverageGap {
                reason: RiskCoverageGapReason::ObservationTimeUnverifiable,
                signal: Some(signal_ref.clone()),
                detail: limitation.clone(),
            });
            Some(RiskWindowMembership::Unverifiable)
        }
    }
}

fn insert_member(
    members: &mut BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    id: RiskMemberId,
    observation: &RiskObservation,
    signal_ref: &RiskSignalRevisionRef,
    window_membership: RiskWindowMembership,
) -> Result<(), RiskAccumulatorError> {
    match members.get_mut(&id) {
        Some(member) => {
            if let Some(existing) = member
                .observations
                .iter()
                .find(|item| signal_revision_ref(item.signal.revision()) == *signal_ref)
            {
                if existing != observation {
                    return Err(RiskAccumulatorError::ConflictingSignalRevision(
                        signal_ref.clone(),
                    ));
                }
                member.exact_replay_count = member
                    .exact_replay_count
                    .checked_add(1)
                    .ok_or(RiskAccumulatorError::InvalidField("exact_replay_count"))?;
            } else {
                member.observations.push(observation.clone());
            }
            if window_membership == RiskWindowMembership::Unverifiable {
                member.window_membership = window_membership;
            }
        }
        None => {
            members.insert(
                id.clone(),
                RiskAccumulatorMember {
                    id,
                    observations: vec![observation.clone()],
                    exact_replay_count: 0,
                    window_membership,
                },
            );
        }
    }
    Ok(())
}

fn build_lineage_groups(
    members: &BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    input: &RiskAccumulatorInput,
    gaps: &mut Vec<RiskCoverageGap>,
) -> Result<Vec<RiskLineageGroup>, RiskAccumulatorError> {
    let grouped = group_member_ids(members, &input.lineage_relations, gaps)?;
    let mut groups = Vec::with_capacity(grouped.len());
    for group_members in grouped.into_values() {
        groups.push(build_lineage_group(
            group_members,
            members,
            &input.time,
            gaps,
        )?);
    }
    Ok(groups)
}

fn group_member_ids(
    members: &BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    relations: &[RiskLineageRelation],
    gaps: &mut Vec<RiskCoverageGap>,
) -> Result<BTreeMap<usize, Vec<RiskMemberId>>, RiskAccumulatorError> {
    let member_ids: Vec<_> = members.keys().cloned().collect();
    let mut parents: Vec<usize> = (0..member_ids.len()).collect();
    let (identity_indexes, source_event_indexes, unknown_indexes) =
        index_lineage_members(&member_ids);
    merge_index_groups(&mut parents, source_event_indexes.values());
    merge_index_slice(&mut parents, &unknown_indexes);
    merge_explicit_relations(&mut parents, &identity_indexes, relations, gaps)?;

    let mut grouped: BTreeMap<usize, Vec<RiskMemberId>> = BTreeMap::new();
    for (index, id) in member_ids.into_iter().enumerate() {
        let root = find_root(&mut parents, index);
        grouped.entry(root).or_default().push(id);
    }
    Ok(grouped)
}

type SourceEventKey = (String, String, String);
type LineageIndexes = (
    BTreeMap<RiskSourceIdentity, usize>,
    BTreeMap<SourceEventKey, Vec<usize>>,
    Vec<usize>,
);

fn index_lineage_members(member_ids: &[RiskMemberId]) -> LineageIndexes {
    let mut identity_indexes = BTreeMap::new();
    let mut source_event_indexes: BTreeMap<SourceEventKey, Vec<usize>> = BTreeMap::new();
    let mut unknown_indexes = Vec::new();
    for (index, id) in member_ids.iter().enumerate() {
        match id {
            RiskMemberId::Known(identity) => {
                identity_indexes.insert(identity.clone(), index);
                source_event_indexes
                    .entry((
                        identity.producer_id.clone(),
                        identity.cursor_id.clone(),
                        identity.event_id.clone(),
                    ))
                    .or_default()
                    .push(index);
            }
            RiskMemberId::Unknown(_) => unknown_indexes.push(index),
        }
    }
    (identity_indexes, source_event_indexes, unknown_indexes)
}

fn merge_index_groups<'a>(parents: &mut [usize], groups: impl Iterator<Item = &'a Vec<usize>>) {
    for indexes in groups {
        merge_index_slice(parents, indexes);
    }
}

fn merge_index_slice(parents: &mut [usize], indexes: &[usize]) {
    if let Some(first) = indexes.first() {
        for other in indexes.iter().skip(1) {
            union(parents, *first, *other);
        }
    }
}

fn merge_explicit_relations(
    parents: &mut [usize],
    identity_indexes: &BTreeMap<RiskSourceIdentity, usize>,
    relations: &[RiskLineageRelation],
    gaps: &mut Vec<RiskCoverageGap>,
) -> Result<(), RiskAccumulatorError> {
    for relation in relations {
        if relation.provenance.is_empty() {
            return Err(RiskAccumulatorError::InvalidField(
                "lineage_relation_provenance",
            ));
        }
        match (
            identity_indexes.get(&relation.left),
            identity_indexes.get(&relation.right),
        ) {
            (Some(left), Some(right)) => union(parents, *left, *right),
            _ => gaps.push(RiskCoverageGap {
                reason: RiskCoverageGapReason::LineageEndpointMissing,
                signal: None,
                detail: "lineage relation endpoint is outside considered membership".to_owned(),
            }),
        }
    }
    Ok(())
}

fn build_lineage_group(
    mut group_members: Vec<RiskMemberId>,
    members: &BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    time: &RiskTimeReading,
    gaps: &[RiskCoverageGap],
) -> Result<RiskLineageGroup, RiskAccumulatorError> {
    group_members.sort();
    let first_member = group_members
        .first()
        .cloned()
        .ok_or(RiskAccumulatorError::InvalidField("empty_lineage_group"))?;
    let has_unknown = group_members
        .iter()
        .any(|member| matches!(member, RiskMemberId::Unknown(_)));
    let kind = lineage_kind(group_members.len(), has_unknown);
    let reopened_occurrences = reopened_occurrences(&group_members, members);
    Ok(RiskLineageGroup {
        id: RiskLineageGroupId { first_member },
        members: group_members,
        kind,
        pressure: RiskPressureView {
            decayed: None,
            reopened_occurrences,
            unavailable_reason: Some(pressure_unavailable_reason(time, gaps)),
        },
    })
}

fn lineage_kind(member_count: usize, has_unknown: bool) -> RiskLineageKind {
    if has_unknown {
        RiskLineageKind::UnknownOrigin
    } else if member_count > 1 {
        RiskLineageKind::Correlated
    } else {
        RiskLineageKind::Independent
    }
}

fn reopened_occurrences(
    group_members: &[RiskMemberId],
    members: &BTreeMap<RiskMemberId, RiskAccumulatorMember>,
) -> Vec<String> {
    let mut reopened = BTreeSet::new();
    for member_id in group_members {
        if let Some(member) = members.get(member_id) {
            for observation in &member.observations {
                if let RiskAssessment::Measured { value, .. }
                | RiskAssessment::Inferred { value, .. } = &observation.evidence.recurrence
                {
                    reopened.extend(
                        value
                            .occurrences
                            .iter()
                            .filter(|occurrence| occurrence.kind == RiskOccurrenceKind::Reopened)
                            .map(|occurrence| occurrence.occurrence_id.clone()),
                    );
                }
            }
        }
    }
    reopened.into_iter().collect()
}

fn pressure_unavailable_reason(
    time: &RiskTimeReading,
    gaps: &[RiskCoverageGap],
) -> RiskPressureUnavailableReason {
    if !matches!(&time.continuity, RiskClockContinuity::Continuous) {
        RiskPressureUnavailableReason::ClockContinuityUnqualified
    } else if !gaps.is_empty() {
        RiskPressureUnavailableReason::CoverageIncomplete
    } else {
        RiskPressureUnavailableReason::NumericPolicyNotConfigured
    }
}

fn sort_result_metadata(
    members: &mut BTreeMap<RiskMemberId, RiskAccumulatorMember>,
    exclusions: &mut [RiskExclusion],
    gaps: &mut [RiskCoverageGap],
    lineage_groups: &mut [RiskLineageGroup],
) {
    for member in members.values_mut() {
        member
            .observations
            .sort_by_key(|item| signal_revision_ref(item.signal.revision()));
    }
    exclusions
        .sort_by(|left, right| (&left.signal, left.reason).cmp(&(&right.signal, right.reason)));
    gaps.sort_by(|left, right| {
        (left.reason, &left.signal, &left.detail).cmp(&(right.reason, &right.signal, &right.detail))
    });
    lineage_groups.sort_by(|left, right| left.id.cmp(&right.id));
}
fn validate_window(
    window: &RiskObservationWindow,
    reading: &ObservedTime,
    maximum: Duration,
) -> Result<(), RiskAccumulatorError> {
    if window.start.domain != window.end.domain
        || window.end.domain != reading.domain
        || matches!(&window.start.domain, ClockDomain::Unknown { .. })
    {
        return Err(RiskAccumulatorError::InvalidWindowClock);
    }
    let start = ticks_as_nanos(&window.start).ok_or(RiskAccumulatorError::InvalidWindowClock)?;
    let end = ticks_as_nanos(&window.end).ok_or(RiskAccumulatorError::InvalidWindowClock)?;
    let now = ticks_as_nanos(reading).ok_or(RiskAccumulatorError::InvalidWindowClock)?;
    if end < start || now < end {
        return Err(RiskAccumulatorError::InvalidWindowOrder);
    }
    if end - start > maximum.as_nanos() {
        return Err(RiskAccumulatorError::WindowLimitExceeded);
    }
    Ok(())
}

fn validate_profile_revision(revision: &ProfileRevision) -> Result<(), RiskAccumulatorError> {
    validate_text(&revision.profile_id, "policy_profile_id")?;
    if revision.revision == 0 {
        return Err(RiskAccumulatorError::InvalidField("policy_revision"));
    }
    Ok(())
}

fn validate_subject(subject: &RiskSubject) -> Result<(), RiskAccumulatorError> {
    validate_text(&subject.target.subject_id, "subject_id")?;
    validate_text(&subject.target.scope_id, "scope_id")?;
    if subject.target.generation == 0 {
        return Err(RiskAccumulatorError::InvalidField("subject_generation"));
    }
    for (resource, generation) in &subject.resource_generations {
        validate_text(resource, "resource_id")?;
        if *generation == 0 {
            return Err(RiskAccumulatorError::InvalidField("resource_generation"));
        }
    }
    Ok(())
}

fn validate_observation(observation: &RiskObservation) -> Result<(), RiskAccumulatorError> {
    for (resource, generation) in &observation.resource_generations {
        validate_text(resource, "resource_id")?;
        if *generation == 0 {
            return Err(RiskAccumulatorError::InvalidField("resource_generation"));
        }
    }
    match &observation.source_lineage {
        RiskSourceLineage::Known(identity) => {
            validate_text(&identity.producer_id, "producer_id")?;
            validate_text(&identity.cursor_id, "cursor_id")?;
            validate_text(&identity.event_id, "event_id")?;
            validate_text(&identity.content_digest, "content_digest")?;
            let revision = observation.signal.revision();
            let bound = match &revision.source_events {
                SignalReferences::Known(events) => events.iter().any(|event| {
                    event.event_id == identity.event_id
                        && event.payload_digest
                            == RecordedValue::Known(identity.content_digest.clone())
                }),
                SignalReferences::Unknown { .. } => false,
            };
            if !bound {
                return Err(RiskAccumulatorError::InvalidField(
                    "source_identity_not_bound_to_signal",
                ));
            }
        }
        RiskSourceLineage::Unknown { limitation } => {
            validate_text(limitation, "unknown_origin_limitation")?;
        }
    }
    validate_vector(&observation.evidence)
}

fn validate_vector(vector: &RiskEvidenceVector) -> Result<(), RiskAccumulatorError> {
    validate_assessment(&vector.impact_effect_class, "impact_effect_class")?;
    validate_assessment(&vector.recurrence, "recurrence")?;
    validate_assessment(
        &vector.evidence_confidence_coverage,
        "evidence_confidence_coverage",
    )?;
    validate_assessment(&vector.propagation, "propagation")?;
    validate_assessment(
        &vector.reversibility_residual_effects,
        "reversibility_residual_effects",
    )?;
    validate_assessment(&vector.persistence_compromise, "persistence_compromise")?;
    validate_assessment(
        &vector.uncertainty_common_lineage,
        "uncertainty_common_lineage",
    )?;
    validate_assessment(&vector.damage_repair_history, "damage_repair_history")?;
    validate_assessment(&vector.supporting_evidence, "supporting_evidence")?;
    validate_assessment(&vector.counterevidence, "counterevidence")?;
    match &vector.evidence_confidence_coverage {
        RiskAssessment::Measured { value, .. } | RiskAssessment::Inferred { value, .. }
            if value.confidence.is_some_and(|confidence| {
                !confidence.is_finite() || !(0.0..=1.0).contains(&confidence)
            }) =>
        {
            return Err(RiskAccumulatorError::InvalidField("evidence_confidence"));
        }
        _ => {}
    }
    if let RiskAssessment::Measured { value, .. } | RiskAssessment::Inferred { value, .. } =
        &vector.recurrence
    {
        for occurrence in &value.occurrences {
            validate_text(&occurrence.occurrence_id, "occurrence_id")?;
            if occurrence.provenance.is_empty() {
                return Err(RiskAccumulatorError::InvalidField("occurrence_provenance"));
            }
        }
    }
    Ok(())
}

fn validate_assessment<T>(
    value: &RiskAssessment<T>,
    field: &'static str,
) -> Result<(), RiskAccumulatorError> {
    let provenance = match value {
        RiskAssessment::Measured { provenance, .. }
        | RiskAssessment::Inferred { provenance, .. }
        | RiskAssessment::Unknown { provenance, .. } => provenance,
    };
    if provenance.is_empty() {
        return Err(RiskAccumulatorError::InvalidField(field));
    }
    if let RiskAssessment::Unknown { limitation, .. } = value {
        validate_text(limitation, field)?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), RiskAccumulatorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(RiskAccumulatorError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn signal_revision_ref(revision: &SignalRevision) -> RiskSignalRevisionRef {
    RiskSignalRevisionRef {
        signal_id: revision.signal_id.0.clone(),
        revision: revision.revision,
    }
}

fn in_window(time: &ObservedTime, window: &RiskObservationWindow) -> Option<bool> {
    if time.domain != window.start.domain {
        return None;
    }
    let value = ticks_as_nanos(time)?;
    let start = ticks_as_nanos(&window.start)?;
    let end = ticks_as_nanos(&window.end)?;
    Some(value >= start && value < end)
}

fn ticks_as_nanos(time: &ObservedTime) -> Option<u128> {
    let factor = match time.unit {
        TimeUnit::Nanoseconds => 1_u128,
        TimeUnit::Microseconds => 1_000,
        TimeUnit::Milliseconds => 1_000_000,
        TimeUnit::Seconds => 1_000_000_000,
    };
    u128::from(time.ticks).checked_mul(factor)
}

fn find_root(parents: &mut [usize], index: usize) -> usize {
    let parent = parents[index];
    if parent != index {
        let root = find_root(parents, parent);
        parents[index] = root;
    }
    parents[index]
}

fn union(parents: &mut [usize], left: usize, right: usize) {
    let left_root = find_root(parents, left);
    let right_root = find_root(parents, right);
    if left_root != right_root {
        let (first, second) = if left_root < right_root {
            (left_root, right_root)
        } else {
            (right_root, left_root)
        };
        parents[second] = first;
    }
}
