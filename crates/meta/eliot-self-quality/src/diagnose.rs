//! Pure bounded self-quality diagnosis over a frozen [`SelfQualityInput`].
//!
//! [`diagnose_self_quality`] applies one deterministic decision tree and emits
//! either a validated [`SelfQualityDiagnosisCandidate`] or an explicit
//! non-candidate disposition. It performs no planning, scoring, clock reads,
//! I/O, mutation, or authority issuance, and it never emits
//! [`CauseHypothesisStatus::ProvenCause`]: a symptom stays a symptom until an
//! external owner proves otherwise.

use std::collections::BTreeSet;

use eliot_conformance_contracts::{
    BlockedDiagnosis, CauseHypothesisStatus, ConflictedDiagnosis, DenominatorCompleteness,
    DimensionOutcome, DimensionStatus, IncompleteDiagnosis, InterventionState, NoActionDisposition,
    NoProblemDisposition, ObservationWindow, Priority, Recurrence, SELF_QUALITY_CONTRACT_VERSION,
    SelfQualityDiagnosisCandidate, SelfQualityDimension, SelfQualityHandoff,
    SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation, Severity, UnknownDiagnosis,
    digest_self_quality_input, digest_self_quality_policy, validate_blocked_against_input,
    validate_candidate_against_input, validate_conflicted_against_input,
    validate_dimension_outcome, validate_incomplete_against_input,
    validate_no_action_against_input, validate_no_problem_against_input,
    validate_self_quality_input, validate_unknown_against_input,
};

use crate::error::SelfQualityError;
use crate::routing::{make_handoff, route_owner};

/// Bounded outcome of diagnosing one frozen self-quality snapshot.
#[allow(clippy::large_enum_variant)]
pub enum SelfQualityOutcome {
    /// A validated per-dimension diagnosis candidate with inert handoffs.
    Candidate(SelfQualityDiagnosisCandidate),
    /// Evidence-backed clean bill: complete coverage, every observation passing.
    NoProblem(NoProblemDisposition),
    /// Complete coverage with no failure; partial findings explicitly tolerated.
    NoAction(NoActionDisposition),
    /// The denominator is incomplete; the exact shortfall is named.
    Incomplete(IncompleteDiagnosis),
    /// Evidence is missing or stale; the exact unknown scopes are named.
    Unknown(UnknownDiagnosis),
    /// An explicit blocker or a failed blind repetition stops diagnosis.
    Blocked(BlockedDiagnosis),
    /// Conflicting evidence sides are named; nothing is resolved here.
    Conflicted(ConflictedDiagnosis),
}

/// Diagnose one frozen self-quality snapshot.
///
/// Pure and deterministic: no clock, no I/O, no mutation. Each step is applied
/// in order and the first matching step decides the outcome:
///
/// 1. Validate the input with [`validate_self_quality_input`]; contract
///    rejections become [`SelfQualityError::Contract`].
/// 2. Blocked: any observation whose `intervention_refs` carry a ref starting
///    with `blocked:` yields `Blocked` with the sorted unique blocked refs.
/// 3. Blind-repetition guard: a prior-history record with
///    [`InterventionState::Failed`] on the input's own `configuration_ref`
///    yields `Blocked` naming that record's `intervention_ref`, so a failed
///    intervention is never retried blindly.
/// 4. Denominator: a non-`Complete` denominator yields `Incomplete` naming one
///    `missing:<axis>:<shortfall>` ref per axis whose expected count exceeds
///    its supplied count.
/// 5. Conflict: any observation with counterevidence, any `MEMORY_CONFLICT`
///    family member, or any dimension holding both a `Fail` and a `Pass`
///    observation yields `Conflicted` with the sorted unique conflicting
///    observation refs plus their counterevidence refs (at least two sides; a
///    lone ref gains its `family:<FAMILY>:<ref>` fallback).
/// 6. Per-dimension rollup over observed dimensions in canonical order with
///    status precedence Fail > Missing > Partial > Inconclusive > Pass
///    (`NotApplicable` is ignored unless it is the whole dimension), severity
///    Critical for Fail in SecurityPrivacy/Correctness, High for other Fail,
///    Medium for Partial, Low for Inconclusive, Negligible otherwise, and
///    matching priorities Urgent/High/Medium/Low/None. The hypothesis is
///    `Symptom` unless prior history exists and the dimension carries
///    intervention refs (then `Hypothesis`, never `ProvenCause`); recurrence
///    is `Unknown` unless the same linkage holds (then the last history
///    record's recurrence).
/// 7. A `Missing` rollup with no `Fail` rollup yields `Unknown` naming the
///    sorted missing-dimension observation refs.
/// 8. A `Fail` rollup yields a `Candidate` covering every observed dimension,
///    with maxima for overall severity/priority, sorted failing symptom refs,
///    no mechanism refs, collected counterevidence refs, one handoff per
///    failing dimension (routed by [`route_owner`] over the first failing
///    observation, with `memory-repair:<observation_ref>` problem refs for
///    `MEMORY_PROVENANCE` findings sent to maintenance planning) plus one
///    [`SelfQualityHandoffOwner::Instrumentation`] handoff per `Inconclusive`
///    dimension, handoffs sorted by ref, and an expiry one hour after input
///    creation; the candidate is validated against the exact input.
/// 9. Freshness: observations whose window plus the policy time bound ends
///    before input creation yield `Unknown` naming the sorted stale refs,
///    because stale evidence cannot support no-action or no-problem.
/// 10. A `Partial` or `Inconclusive` rollup yields `NoAction` with sorted
///     `tolerated:<dimension>` justification refs, validated against the input.
/// 11. Otherwise every observed dimension passes and `NoProblem` is returned
///     with the exact completed dimensions and the widest observation window,
///     validated against the input.
pub fn diagnose_self_quality(
    input: &SelfQualityInput,
) -> Result<SelfQualityOutcome, SelfQualityError> {
    validate_self_quality_input(input).map_err(SelfQualityError::Contract)?;
    let input_digest = digest_self_quality_input(input);

    if let Some(outcome) = blocked_outcome(input, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = blind_repetition_outcome(input, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = incomplete_outcome(input, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = conflict_outcome(input, &input_digest)? {
        return Ok(outcome);
    }

    let rollups = rollup_dimensions(input);
    if let Some(outcome) = missing_unknown_outcome(input, &rollups, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = candidate_outcome(input, &rollups, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = freshness_unknown_outcome(input, &input_digest)? {
        return Ok(outcome);
    }
    if let Some(outcome) = no_action_outcome(input, &rollups, &input_digest)? {
        return Ok(outcome);
    }
    no_problem_outcome(input, &rollups, &input_digest)
}

/// Per-dimension aggregation used by every post-validation decision step.
struct DimensionRollup {
    dimension: SelfQualityDimension,
    status: DimensionStatus,
    severity: Severity,
    priority: Priority,
    hypothesis: CauseHypothesisStatus,
    recurrence: Recurrence,
}

/// Decision step 2: explicit `blocked:` intervention refs stop diagnosis.
fn blocked_outcome(
    input: &SelfQualityInput,
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    let mut blockers = BTreeSet::new();
    for observation in &input.observations {
        for intervention in &observation.core().intervention_refs {
            if intervention.starts_with("blocked:") {
                blockers.insert(intervention.clone());
            }
        }
    }
    if blockers.is_empty() {
        return Ok(None);
    }
    let diagnosis = BlockedDiagnosis {
        input_digest: input_digest.to_owned(),
        blocker_refs: blockers.into_iter().collect(),
    };
    validate_blocked_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Blocked(diagnosis)))
}

/// Decision step 3: never retry a failed intervention on the same configuration.
fn blind_repetition_outcome(
    input: &SelfQualityInput,
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    for record in &input.prior_history {
        if record.intervention_state == InterventionState::Failed
            && record.configuration_ref == input.source.configuration_ref
        {
            let diagnosis = BlockedDiagnosis {
                input_digest: input_digest.to_owned(),
                blocker_refs: vec![record.intervention_ref.clone()],
            };
            validate_blocked_against_input(&diagnosis, input)
                .map_err(SelfQualityError::Contract)?;
            return Ok(Some(SelfQualityOutcome::Blocked(diagnosis)));
        }
    }
    Ok(None)
}

/// Decision step 4: a non-complete denominator names its exact shortfall.
fn incomplete_outcome(
    input: &SelfQualityInput,
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    if input.denominator.completeness == DenominatorCompleteness::Complete {
        return Ok(None);
    }
    let denominator = &input.denominator;
    let mut missing = Vec::new();
    let shortfalls = [
        (
            "dimensions",
            denominator.expected_dimensions,
            denominator.supplied_dimensions,
        ),
        (
            "sources",
            denominator.expected_sources,
            denominator.supplied_sources,
        ),
        (
            "members",
            denominator.expected_members,
            denominator.supplied_members,
        ),
    ];
    for (axis, expected, supplied) in shortfalls {
        if expected > supplied {
            missing.push(format!("missing:{axis}:{}", expected - supplied));
        }
    }
    missing.sort();
    let diagnosis = IncompleteDiagnosis {
        input_digest: input_digest.to_owned(),
        missing_evidence_refs: missing,
    };
    validate_incomplete_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Incomplete(diagnosis)))
}

/// Decision step 5: conflicting evidence sides are named, never resolved.
fn conflict_outcome(
    input: &SelfQualityInput,
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    let mut sides = BTreeSet::new();
    for observation in &input.observations {
        let core = observation.core();
        if !core.counterevidence_refs.is_empty() || observation.family_name() == "MEMORY_CONFLICT" {
            sides.insert(core.observation_ref.clone());
            for counter in &core.counterevidence_refs {
                sides.insert(counter.clone());
            }
        }
    }
    for dimension in SelfQualityDimension::ALL {
        let failing = input.observations.iter().any(|observation| {
            let core = observation.core();
            core.dimension == dimension && core.status == DimensionStatus::Fail
        });
        let passing = input.observations.iter().any(|observation| {
            let core = observation.core();
            core.dimension == dimension && core.status == DimensionStatus::Pass
        });
        if failing && passing {
            for observation in &input.observations {
                let core = observation.core();
                if core.dimension == dimension {
                    sides.insert(core.observation_ref.clone());
                    for counter in &core.counterevidence_refs {
                        sides.insert(counter.clone());
                    }
                }
            }
        }
    }
    if sides.is_empty() {
        return Ok(None);
    }
    let mut conflict_refs: Vec<String> = sides.into_iter().collect();
    if conflict_refs.len() == 1 {
        let sole = conflict_refs[0].clone();
        let family = input
            .observations
            .iter()
            .find(|observation| observation.core().observation_ref == sole)
            .map_or("UNKNOWN", SelfQualityObservation::family_name);
        conflict_refs.push(format!("family:{family}:{sole}"));
        conflict_refs.sort();
    }
    let diagnosis = ConflictedDiagnosis {
        input_digest: input_digest.to_owned(),
        conflict_refs,
    };
    validate_conflicted_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Conflicted(diagnosis)))
}

/// Decision step 6: roll every observed dimension up to one outcome.
fn rollup_dimensions(input: &SelfQualityInput) -> Vec<DimensionRollup> {
    let mut rollups = Vec::new();
    for dimension in SelfQualityDimension::ALL {
        let present: Vec<&SelfQualityObservation> = input
            .observations
            .iter()
            .filter(|observation| observation.core().dimension == dimension)
            .collect();
        if present.is_empty() {
            continue;
        }
        let has = |status: DimensionStatus| {
            present
                .iter()
                .any(|observation| observation.core().status == status)
        };
        let status = if has(DimensionStatus::Fail) {
            DimensionStatus::Fail
        } else if has(DimensionStatus::Missing) {
            DimensionStatus::Missing
        } else if has(DimensionStatus::Partial) {
            DimensionStatus::Partial
        } else if has(DimensionStatus::Inconclusive) {
            DimensionStatus::Inconclusive
        } else if has(DimensionStatus::Pass) {
            DimensionStatus::Pass
        } else {
            DimensionStatus::NotApplicable
        };
        let severity = match status {
            DimensionStatus::Fail
                if dimension == SelfQualityDimension::SecurityPrivacy
                    || dimension == SelfQualityDimension::Correctness =>
            {
                Severity::Critical
            }
            DimensionStatus::Fail => Severity::High,
            DimensionStatus::Partial => Severity::Medium,
            DimensionStatus::Inconclusive => Severity::Low,
            DimensionStatus::Pass | DimensionStatus::Missing | DimensionStatus::NotApplicable => {
                Severity::Negligible
            }
        };
        let priority = match severity {
            Severity::Critical => Priority::Urgent,
            Severity::High => Priority::High,
            Severity::Medium => Priority::Medium,
            Severity::Low => Priority::Low,
            Severity::Negligible => Priority::None,
        };
        let linked = !input.prior_history.is_empty()
            && present
                .iter()
                .any(|observation| !observation.core().intervention_refs.is_empty());
        let hypothesis = if linked {
            CauseHypothesisStatus::Hypothesis
        } else {
            CauseHypothesisStatus::Symptom
        };
        let recurrence = if linked {
            input
                .prior_history
                .last()
                .map_or(Recurrence::Unknown, |record| record.recurrence)
        } else {
            Recurrence::Unknown
        };
        rollups.push(DimensionRollup {
            dimension,
            status,
            severity,
            priority,
            hypothesis,
            recurrence,
        });
    }
    rollups
}

/// Sorted observation refs of one dimension, optionally restricted to a status.
fn dimension_refs(
    input: &SelfQualityInput,
    dimension: SelfQualityDimension,
    status: Option<DimensionStatus>,
) -> Vec<String> {
    let mut refs: Vec<String> = input
        .observations
        .iter()
        .filter(|observation| {
            let core = observation.core();
            core.dimension == dimension && status.is_none_or(|want| core.status == want)
        })
        .map(|observation| observation.core().observation_ref.clone())
        .collect();
    refs.sort();
    refs
}

/// Decision step 7: missing evidence without failure is unknown, never clean.
fn missing_unknown_outcome(
    input: &SelfQualityInput,
    rollups: &[DimensionRollup],
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    if rollups
        .iter()
        .any(|rollup| rollup.status == DimensionStatus::Fail)
    {
        return Ok(None);
    }
    let mut unknown = BTreeSet::new();
    for rollup in rollups {
        if rollup.status == DimensionStatus::Missing {
            for reference in dimension_refs(input, rollup.dimension, None) {
                unknown.insert(reference);
            }
        }
    }
    if unknown.is_empty() {
        return Ok(None);
    }
    let diagnosis = UnknownDiagnosis {
        input_digest: input_digest.to_owned(),
        unknown_refs: unknown.into_iter().collect(),
    };
    validate_unknown_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Unknown(diagnosis)))
}

/// Decision step 8: failing dimensions become a validated candidate.
fn candidate_outcome(
    input: &SelfQualityInput,
    rollups: &[DimensionRollup],
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    if !rollups
        .iter()
        .any(|rollup| rollup.status == DimensionStatus::Fail)
    {
        return Ok(None);
    }
    let mut outcomes = Vec::new();
    let mut overall_severity = Severity::Negligible;
    let mut overall_priority = Priority::None;
    for rollup in rollups {
        let outcome = DimensionOutcome {
            dimension: rollup.dimension,
            status: rollup.status,
            severity: rollup.severity,
            priority: rollup.priority,
            hypothesis: rollup.hypothesis,
            recurrence: rollup.recurrence,
        };
        validate_dimension_outcome(&outcome).map_err(SelfQualityError::Contract)?;
        if outcome.severity > overall_severity {
            overall_severity = outcome.severity;
        }
        if outcome.priority > overall_priority {
            overall_priority = outcome.priority;
        }
        outcomes.push(outcome);
    }

    let mut symptoms = BTreeSet::new();
    let mut counterevidence = BTreeSet::new();
    for observation in &input.observations {
        let core = observation.core();
        if core.status == DimensionStatus::Fail {
            symptoms.insert(core.observation_ref.clone());
        }
        for counter in &core.counterevidence_refs {
            counterevidence.insert(counter.clone());
        }
    }

    let mut handoffs = Vec::new();
    let mut handoff_index = 0_u32;
    for rollup in rollups {
        if rollup.status != DimensionStatus::Fail {
            continue;
        }
        let first_failing = input.observations.iter().find(|observation| {
            let core = observation.core();
            core.dimension == rollup.dimension && core.status == DimensionStatus::Fail
        });
        if let Some(observation) = first_failing {
            handoffs.push(failing_handoff(input, rollup, observation, handoff_index)?);
            handoff_index += 1;
        }
    }
    let instr_handoffs = candidate_instrumentation_handoffs(input, rollups, handoff_index)?;
    handoffs.extend(instr_handoffs);
    handoffs.sort_by(|left, right| left.handoff_ref.cmp(&right.handoff_ref));

    let candidate = SelfQualityDiagnosisCandidate {
        contract_version: SELF_QUALITY_CONTRACT_VERSION,
        candidate_ref: format!("candidate-self-quality-{}", &input_digest[..8]),
        input_digest: input_digest.to_owned(),
        policy_digest: digest_self_quality_policy(&input.policy),
        outcomes,
        overall_severity,
        overall_priority,
        symptom_refs: symptoms.into_iter().collect(),
        mechanism_refs: Vec::new(),
        counterevidence_refs: counterevidence.into_iter().collect(),
        handoffs,
        expires_at_ms: input.created_at_ms.saturating_add(3_600_000),
    };
    validate_candidate_against_input(&candidate, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Candidate(candidate)))
}

/// Bounded inert instrumentation handoffs for Inconclusive and Missing dimensions.
fn candidate_instrumentation_handoffs(
    input: &SelfQualityInput,
    rollups: &[DimensionRollup],
    start_index: u32,
) -> Result<Vec<SelfQualityHandoff>, SelfQualityError> {
    let mut handoffs = Vec::new();
    let mut index = start_index;
    for rollup in rollups {
        if rollup.status != DimensionStatus::Inconclusive
            && rollup.status != DimensionStatus::Missing
        {
            continue;
        }
        let tag = format!("{:?}", rollup.dimension);
        let observations = dimension_refs(input, rollup.dimension, None);
        let missing = dimension_refs(
            input,
            rollup.dimension,
            if rollup.status == DimensionStatus::Missing {
                Some(DimensionStatus::Missing)
            } else {
                Some(DimensionStatus::Inconclusive)
            },
        );
        let priority = if rollup.priority == Priority::None {
            Priority::Low
        } else {
            rollup.priority
        };
        handoffs.push(make_handoff(
            &format!("handoff-{}-{index}", tag.to_ascii_lowercase()),
            SelfQualityHandoffOwner::Instrumentation,
            &observations,
            &[format!("problem:{tag}")],
            &observations,
            &missing,
            &[format!("applies:{tag}")],
            priority,
            &["ceiling:privacy-authority-proof".to_owned()],
            &[format!("invalidate:{}", input.input_ref)],
        )?);
        index += 1;
    }
    Ok(handoffs)
}

/// One handoff for a failing dimension, routed over its first failing observation.
fn failing_handoff(
    input: &SelfQualityInput,
    rollup: &DimensionRollup,
    observation: &SelfQualityObservation,
    handoff_index: u32,
) -> Result<SelfQualityHandoff, SelfQualityError> {
    let owner = route_owner(observation);
    let tag = format!("{:?}", rollup.dimension);
    let problems = if owner == SelfQualityHandoffOwner::MaintenancePlan677
        && observation.family_name() == "MEMORY_PROVENANCE"
    {
        vec![format!(
            "memory-repair:{}",
            observation.core().observation_ref
        )]
    } else {
        vec![format!("problem:{tag}")]
    };
    let missing = if owner == SelfQualityHandoffOwner::Instrumentation {
        let mut m = dimension_refs(input, rollup.dimension, Some(DimensionStatus::Inconclusive));
        m.extend(dimension_refs(
            input,
            rollup.dimension,
            Some(DimensionStatus::Missing),
        ));
        m.sort();
        m.dedup();
        m
    } else {
        Vec::new()
    };
    let observations = dimension_refs(input, rollup.dimension, None);
    make_handoff(
        &format!("handoff-{}-{handoff_index}", tag.to_ascii_lowercase()),
        owner,
        &observations,
        &problems,
        &observations,
        &missing,
        &[format!("applies:{tag}")],
        rollup.priority,
        &["ceiling:privacy-authority-proof".to_owned()],
        &[format!("invalidate:{}", input.input_ref)],
    )
}

/// Decision step 9: stale evidence cannot support no-action or no-problem.
fn freshness_unknown_outcome(
    input: &SelfQualityInput,
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    let mut stale = BTreeSet::new();
    for observation in &input.observations {
        if observation
            .core()
            .window
            .observed_to_ms
            .saturating_add(input.policy.limits.max_time_ms)
            < input.created_at_ms
        {
            stale.insert(observation.core().observation_ref.clone());
        }
    }
    if stale.is_empty() {
        return Ok(None);
    }
    let diagnosis = UnknownDiagnosis {
        input_digest: input_digest.to_owned(),
        unknown_refs: stale.into_iter().collect(),
    };
    validate_unknown_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::Unknown(diagnosis)))
}

/// Decision step 10: partial or inconclusive findings are tolerated explicitly.
fn no_action_outcome(
    input: &SelfQualityInput,
    rollups: &[DimensionRollup],
    input_digest: &str,
) -> Result<Option<SelfQualityOutcome>, SelfQualityError> {
    let tolerated: Vec<SelfQualityDimension> = rollups
        .iter()
        .filter(|rollup| {
            rollup.status == DimensionStatus::Partial
                || rollup.status == DimensionStatus::Inconclusive
        })
        .map(|rollup| rollup.dimension)
        .collect();
    if tolerated.is_empty() {
        return Ok(None);
    }
    let mut justification: Vec<String> = tolerated
        .iter()
        .map(|dimension| format!("tolerated:{dimension:?}"))
        .collect();
    justification.sort();
    let disposition = NoActionDisposition {
        input_digest: input_digest.to_owned(),
        justification_refs: justification,
        tolerated_dimensions: tolerated,
    };
    validate_no_action_against_input(&disposition, input).map_err(SelfQualityError::Contract)?;
    Ok(Some(SelfQualityOutcome::NoAction(disposition)))
}

/// Decision step 11: complete passing coverage is the only clean evidence.
fn no_problem_outcome(
    input: &SelfQualityInput,
    rollups: &[DimensionRollup],
    input_digest: &str,
) -> Result<SelfQualityOutcome, SelfQualityError> {
    let completed: Vec<SelfQualityDimension> =
        rollups.iter().map(|rollup| rollup.dimension).collect();
    let earliest = input
        .observations
        .iter()
        .map(|observation| observation.core().window.observed_from_ms)
        .min();
    let latest = input
        .observations
        .iter()
        .max_by_key(|observation| observation.core().window.observed_to_ms);
    if let (Some(observed_from_ms), Some(newest)) = (earliest, latest) {
        let disposition = NoProblemDisposition {
            input_digest: input_digest.to_owned(),
            completed_dimensions: completed,
            window: ObservationWindow {
                observed_from_ms,
                observed_to_ms: newest.core().window.observed_to_ms,
                environment_ref: newest.core().window.environment_ref.clone(),
                platform_ref: newest.core().window.platform_ref.clone(),
                toolchain_ref: newest.core().window.toolchain_ref.clone(),
            },
        };
        validate_no_problem_against_input(&disposition, input)
            .map_err(SelfQualityError::Contract)?;
        return Ok(SelfQualityOutcome::NoProblem(disposition));
    }
    let diagnosis = UnknownDiagnosis {
        input_digest: input_digest.to_owned(),
        unknown_refs: vec!["unknown:empty-coverage".to_owned()],
    };
    validate_unknown_against_input(&diagnosis, input).map_err(SelfQualityError::Contract)?;
    Ok(SelfQualityOutcome::Unknown(diagnosis))
}
