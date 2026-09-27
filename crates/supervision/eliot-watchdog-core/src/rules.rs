//! Bounded deterministic Watchdog rule evaluations.
//!
//! This module currently implements only the coordinator's typed provider
//! host-event sequence-gap observation. The coordinator package is deliberately
//! not a dependency of this pure core: STITCH projects the fields only after
//! matching `CoordinatorEvent::ProviderHostEventGap`, and supplies the
//! owner-issued `SignalTarget`, profile, clock, coverage and revisions that the
//! event itself does not carry.

use crate::signals::{
    AcknowledgementFact, EvidenceRef, ExpectedRevision, ObservedTime, ProfileRevision,
    RecordedValue, ReopenCondition, RuleRevision, Signal, SignalAttribution, SignalDelivery,
    SignalDisposition, SignalId, SignalProcessing, SignalReferences, SignalRevision,
    SignalSeverity, SignalTarget, SourceEventRef,
};

/// The single currently implemented rule. Other W2 rules remain unimplemented.
pub const PROVIDER_HOST_EVENT_GAP_RULE: IntegrationGapRule = IntegrationGapRule {
    rule_id: "provider_host_event_sequence_gap",
    revision: 1,
    required_observations: "owner-supplied attempt, event, sequence pair, SignalTarget, state fence, and competent coverage",
    correlation: "one provider event within one attempt and owner-supplied SignalTarget; preserve the context StateFence separately",
    bound: "one source event per evaluation; no recurrence accumulation",
    threshold: "observed_sequence is greater than expected_sequence; the proven skip count is the difference",
    result: "warning Signal candidate for a provider host-event sequence supervision gap",
    permissible_proposal: "candidate-only signal routing or coverage inspection; no effect authority",
};

/// Declarative applicability for the one bounded rule implemented here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrationGapRule {
    pub rule_id: &'static str,
    pub revision: u64,
    pub required_observations: &'static str,
    pub correlation: &'static str,
    pub bound: &'static str,
    pub threshold: &'static str,
    pub result: &'static str,
    pub permissible_proposal: &'static str,
}

/// Returns the finite rule descriptor used by the public evaluation entrypoint.
#[must_use]
pub const fn provider_host_event_gap_rule() -> &'static IntegrationGapRule {
    &PROVIDER_HOST_EVENT_GAP_RULE
}

/// Owner-issued provider attempt identity from `ProviderHostEventGap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAttemptIdentity(pub String);

/// Owner-issued provider event identity from `ProviderHostEventGap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEventIdentity(pub String);

/// Exact relevant `StateFence` fields projected by their owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateFenceProjection {
    pub authority_lineage_id: String,
    pub authority_sequence: u64,
    pub resource_generation: u64,
    pub task_revision: Option<String>,
    pub policy_revision: Option<String>,
    pub integration_revision: Option<String>,
}

/// Explicit reference to the competent sequence-gap sensor.
///
/// STITCH may construct this only from the coordinator event variant whose
/// producer emitted a forward sequence jump. The coverage reference is
/// supplied by the integration owner; this type does not invent it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompetentIntegrationCoverage {
    pub coverage_id: String,
    pub source_sensor: IntegrationGapSensor,
}

/// Closed source-sensor class accepted by this rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationGapSensor {
    CoordinatorProviderHostEventGap,
}

/// Owner-supplied values needed to complete a Signal candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapSignalContext {
    /// Exact source-owner supplied subject, scope and generation.
    pub target: SignalTarget,
    pub profile: ProfileRevision,
    pub observed_at: ObservedTime,
    pub coverage: CompetentIntegrationCoverage,
    pub expected_context_revision: ExpectedRevision,
    pub expected_authority_revision: ExpectedRevision,
}

/// Typed projection of one `CoordinatorEvent::ProviderHostEventGap`.
///
/// The first four fields must be copied from that exact event by STITCH. The
/// state fence is copied from its `ExecutionContext`; other signal context is
/// separately supplied by the owning integration because it is absent from
/// the event payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapObservation {
    pub attempt: ProviderAttemptIdentity,
    pub event: ProviderEventIdentity,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
    pub state_fence: StateFenceProjection,
    pub signal_context: IntegrationGapSignalContext,
}

/// Why an input did not prove a provider host-event sequence gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationGapUnknown {
    EmptyAttemptIdentity,
    EmptyEventIdentity,
    AttemptMismatch,
    InvalidSequenceOrder,
    EmptyFenceIdentity,
    ZeroFenceGeneration,
    ZeroExpectedSequence,
}

/// Evidence-only result from evaluating the provider host-event gap rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationGapEvaluation {
    /// One forward sequence skip is proved by the owner-supplied observation.
    GapDetected(Box<IntegrationGapSignalCandidate>),
    /// The source projection did not prove a forward gap.
    Unknown(IntegrationGapUnknown),
}

/// Complete immutable Signal candidate plus its exact typed source projection.
///
/// This value is evidence only. It cannot declare a canonical Problem or
/// Incident, authorize containment, or prove a workspace-change gap or bypass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapSignalCandidate {
    pub signal: Signal,
    pub attempt: ProviderAttemptIdentity,
    pub event: ProviderEventIdentity,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
    pub skipped_sequence_count: u64,
    pub state_fence: StateFenceProjection,
    pub competent_coverage: CompetentIntegrationCoverage,
}

/// Evaluates one typed owner projection without persistence or effect authority.
///
/// STITCH is the external caller. It matches the exact coordinator event
/// variant and passes its attempt/event IDs, sequence pair and context fence,
/// along with owner-issued `SignalTarget` and signal metadata. Callers must not derive
/// those identities from cwd strings, arbitrary paths, or hook text.
pub fn evaluate_provider_host_event_gap(
    observation: IntegrationGapObservation,
) -> Result<IntegrationGapEvaluation, crate::signals::SignalValidationError> {
    let skipped_sequence_count = match prove_sequence_gap(&observation) {
        Ok(count) => count,
        Err(unknown) => return Ok(IntegrationGapEvaluation::Unknown(unknown)),
    };
    let signal = build_signal(&observation)?;

    Ok(IntegrationGapEvaluation::GapDetected(Box::new(
        IntegrationGapSignalCandidate {
            signal,
            attempt: observation.attempt,
            event: observation.event,
            expected_sequence: observation.expected_sequence,
            observed_sequence: observation.observed_sequence,
            skipped_sequence_count,
            state_fence: observation.state_fence,
            competent_coverage: observation.signal_context.coverage,
        },
    )))
}

fn prove_sequence_gap(
    observation: &IntegrationGapObservation,
) -> Result<u64, IntegrationGapUnknown> {
    if observation.attempt.0.trim().is_empty() {
        return Err(IntegrationGapUnknown::EmptyAttemptIdentity);
    }
    if observation.event.0.trim().is_empty() {
        return Err(IntegrationGapUnknown::EmptyEventIdentity);
    }
    if observation.signal_context.target.subject_id != observation.attempt.0 {
        return Err(IntegrationGapUnknown::AttemptMismatch);
    }
    if observation.state_fence.resource_generation == 0 {
        return Err(IntegrationGapUnknown::ZeroFenceGeneration);
    }
    if observation
        .state_fence
        .authority_lineage_id
        .trim()
        .is_empty()
        || observation.state_fence.authority_sequence == 0
    {
        return Err(IntegrationGapUnknown::EmptyFenceIdentity);
    }
    if observation.expected_sequence == 0 {
        return Err(IntegrationGapUnknown::ZeroExpectedSequence);
    }
    let Some(skipped_sequence_count) = observation
        .observed_sequence
        .checked_sub(observation.expected_sequence)
        .filter(|count| *count > 0)
    else {
        return Err(IntegrationGapUnknown::InvalidSequenceOrder);
    };
    Ok(skipped_sequence_count)
}

fn build_signal(
    observation: &IntegrationGapObservation,
) -> Result<Signal, crate::signals::SignalValidationError> {
    let rule = provider_host_event_gap_rule();
    let mut identity_fields = vec![
        rule.rule_id.to_owned(),
        rule.revision.to_string(),
        observation.attempt.0.clone(),
        observation.event.0.clone(),
        observation.signal_context.target.scope_id.clone(),
        observation.signal_context.target.generation.to_string(),
        observation.state_fence.authority_lineage_id.clone(),
        observation.state_fence.authority_sequence.to_string(),
        observation.state_fence.resource_generation.to_string(),
    ];
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.task_revision.as_deref(),
    );
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.policy_revision.as_deref(),
    );
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.integration_revision.as_deref(),
    );
    let dedup_key = encode_identity(&identity_fields);
    let signal_id = dedup_key.clone();
    let mut evidence_fields = identity_fields;
    evidence_fields.extend([
        observation.expected_sequence.to_string(),
        observation.observed_sequence.to_string(),
    ]);
    let evidence_id = encode_identity(&evidence_fields);
    Signal::new(SignalRevision {
        signal_id: SignalId(signal_id),
        revision: 1,
        rule: RuleRevision {
            rule_id: rule.rule_id.to_owned(),
            revision: rule.revision,
        },
        profile: observation.signal_context.profile.clone(),
        severity: SignalSeverity::Warning,
        target: observation.signal_context.target.clone(),
        observed_at: RecordedValue::Known(observation.signal_context.observed_at.clone()),
        source_events: SignalReferences::Known(vec![SourceEventRef {
            event_id: observation.event.0.clone(),
            payload_digest: RecordedValue::Unknown {
                limitation: "ProviderHostEventGap supplies event identity and sequence only; no payload digest is present".to_owned(),
            },
        }]),
        evidence: SignalReferences::Known(vec![EvidenceRef { evidence_id }]),
        coverage: SignalReferences::Known(vec![crate::signals::CoverageRef {
            coverage_id: observation.signal_context.coverage.coverage_id.clone(),
        }]),
        attribution: SignalAttribution::Unknown {
            limitation: "ProviderHostEventGap identifies the attempt and missing sequence, not a principal responsible for the gap".to_owned(),
        },
        processing: SignalProcessing::Observed,
        delivery: SignalDelivery::Pending,
        disposition: SignalDisposition::Informational,
        acknowledgement: AcknowledgementFact::NotAcknowledged,
        resolution: crate::signals::ResolutionFact::Unresolved,
        dedup_key: RecordedValue::Known(dedup_key),
        reopen_condition: ReopenCondition::RecurrenceWithNewSourceEvent,
        expected_context_revision: observation.signal_context.expected_context_revision.clone(),
        expected_authority_revision: observation.signal_context.expected_authority_revision.clone(),
    })
}

fn append_optional_identity(fields: &mut Vec<String>, value: Option<&str>) {
    match value {
        Some(value) => {
            fields.push("some".to_owned());
            fields.push(value.to_owned());
        }
        None => fields.push("none".to_owned()),
    }
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
