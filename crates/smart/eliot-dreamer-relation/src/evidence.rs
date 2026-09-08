//! Semantic qualification of admitted endpoints and supplied evidence.

use eliot_dreamer_contracts::{
    CurationAcceptanceCtx, RelationEvidence, RelationEvidencePolarity, RelationInput,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceFreshness,
    LifecycleState,
};

use crate::policy::{
    CausalMaterialBinding, EvidenceBindingKind, RelationPolicy, grade_binding_digest,
};

type EvidenceQualification =
    Result<(Vec<String>, Vec<String>, Vec<String>), eliot_dreamer_contracts::ContractViolation>;
use eliot_epistemic_contracts::{EvidenceGrade, GradeAssignment};

fn rejected(field: &'static str, reason: &str) -> eliot_dreamer_contracts::ContractViolation {
    eliot_dreamer_contracts::ContractViolation::BindingMismatch {
        field,
        reason: reason.to_owned(),
    }
}

/// Checks endpoint lifecycle, freshness and epistemic status.
pub fn qualify_endpoints(
    input: &RelationInput,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    for (endpoint, field) in [
        (&input.source, "relation.source"),
        (&input.target, "relation.target"),
    ] {
        if endpoint.admitted.lifecycle != LifecycleState::Active {
            return Err(rejected(
                field,
                "endpoint is not currently admitted and active",
            ));
        }
        if !matches!(
            endpoint.admitted.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        ) {
            return Err(rejected(field, "endpoint freshness is not current"));
        }
        if !matches!(
            endpoint.status,
            EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified
        ) {
            return Err(rejected(
                field,
                "endpoint epistemic status is not admissible",
            ));
        }
    }
    Ok(())
}

fn envelope_qualified(
    evidence: &RelationEvidence,
    input: &RelationInput,
    policy: &RelationPolicy,
    assignment: Option<&GradeAssignment>,
) -> bool {
    let envelope = &evidence.named.foundation_evidence_envelope;
    envelope.provenance.scope == input.scope_id
        && envelope.state_fence == input.state_fence
        && matches!(
            envelope.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        )
        && matches!(
            envelope.status,
            EpistemicStatus::Supported | EpistemicStatus::Verified
        )
        && envelope.assertability == Assertability::Assertable
        && matches!(
            envelope.authority,
            EvidenceAuthority::CompilerLanguage
                | EvidenceAuthority::CompilerDerivedSemantics
                | EvidenceAuthority::DeterministicRuntimeTest
        )
        && matches!(
            envelope.coverage,
            EvidenceCoverage::CompleteForScope | EvidenceCoverage::NotApplicable
        )
        && assignment.is_none_or(|value| {
            value
                .known_grade()
                .is_some_and(|grade| grade.rank() >= policy.required_grade.rank())
        })
}

fn grade_for<'a>(
    evidence: &'a RelationEvidence,
    policy: &'a RelationPolicy,
) -> Result<Option<&'a GradeAssignment>, eliot_dreamer_contracts::ContractViolation> {
    let Some(binding) = policy
        .grade_bindings
        .iter()
        .find(|value| value.evidence_id == evidence.evidence_id())
    else {
        return Ok(None);
    };
    let Some(reference) = evidence.named.external_grade.as_ref() else {
        return Ok(None);
    };
    if reference != &binding.reference || grade_binding_digest(binding)? != reference.digest {
        return Ok(None);
    }
    let Some(grade) = binding.assignment.known_grade() else {
        return Ok(None);
    };
    if grade.rank() < policy.required_grade.rank() || grade.rank() > policy.maximum_grade.rank() {
        return Ok(None);
    }
    Ok(Some(&binding.assignment))
}

fn alternative_evidence(evidence: &RelationEvidence, input: &RelationInput) -> bool {
    input
        .rivals
        .iter()
        .chain(input.no_relation_alternative.iter())
        .any(|alternative| {
            alternative
                .evidence_refs
                .iter()
                .any(|reference| reference == evidence.evidence_id())
                && alternative.family == evidence.predicate.family
                && alternative.direction == evidence.predicate.direction
                && alternative.source_id == evidence.predicate.source_id
                && alternative.target_id == evidence.predicate.target_id
        })
}

fn primary(evidence: &RelationEvidence, input: &RelationInput) -> bool {
    let p = &evidence.predicate;
    p.family == Some(input.family)
        && p.direction == Some(input.direction)
        && p.source_id == input.source.endpoint_id()
        && p.target_id == input.target.endpoint_id()
}

/// Returns support, counterevidence and unknown primary references in stable order.
pub fn qualify_evidence(input: &RelationInput, policy: &RelationPolicy) -> EvidenceQualification {
    let mut support = Vec::new();
    let mut counter = Vec::new();
    let mut unknown = Vec::new();
    for evidence in input.evidence.iter().chain(&input.counterevidence) {
        let assignment = grade_for(evidence, policy)?;
        if assignment.is_none() {
            if !alternative_evidence(evidence, input) {
                unknown.push(evidence.evidence_id().to_owned());
            }
            continue;
        }
        if !envelope_qualified(evidence, input, policy, assignment) {
            if !alternative_evidence(evidence, input) {
                unknown.push(evidence.evidence_id().to_owned());
            }
            continue;
        }
        if alternative_evidence(evidence, input) {
            continue;
        }
        if !primary(evidence, input) {
            unknown.push(evidence.evidence_id().to_owned());
            continue;
        }
        if evidence.named.foundation_evidence_envelope.coverage
            != EvidenceCoverage::CompleteForScope
        {
            unknown.push(evidence.evidence_id().to_owned());
            continue;
        }
        let collection_matches = if input
            .evidence
            .iter()
            .any(|v| v.evidence_id() == evidence.evidence_id())
        {
            matches!(
                evidence.polarity,
                RelationEvidencePolarity::Support | RelationEvidencePolarity::Unknown
            )
        } else {
            matches!(
                evidence.polarity,
                RelationEvidencePolarity::Counter | RelationEvidencePolarity::Unknown
            )
        };
        if !collection_matches {
            unknown.push(evidence.evidence_id().to_owned());
            continue;
        }
        match evidence.polarity {
            RelationEvidencePolarity::Support => support.push(evidence.evidence_id().to_owned()),
            RelationEvidencePolarity::Counter => counter.push(evidence.evidence_id().to_owned()),
            RelationEvidencePolarity::Unknown => unknown.push(evidence.evidence_id().to_owned()),
        }
    }
    support.sort();
    counter.sort();
    unknown.sort();
    validate_causal_bindings(input, policy)?;
    Ok((support, counter, unknown))
}

fn validate_causal_bindings(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    for binding in &policy.causal_bindings {
        let Some(evidence) = input
            .evidence
            .iter()
            .chain(&input.counterevidence)
            .find(|v| v.evidence_id() == binding.evidence_id)
        else {
            return Err(rejected(
                "relation.evidence.binding",
                "typed semantic evidence binding is missing",
            ));
        };
        if binding.grade.validate().is_err()
            || !envelope_qualified(evidence, input, policy, Some(&binding.grade))
        {
            return Err(rejected(
                "relation.evidence.binding",
                "typed semantic evidence binding is not qualified",
            ));
        }
        let Some(named_assignment) = grade_for(evidence, policy)? else {
            return Err(rejected(
                "relation.evidence.binding",
                "causal role lacks exact named evidence grade binding",
            ));
        };
        if named_assignment != &binding.grade {
            return Err(rejected(
                "relation.evidence.binding",
                "causal role grade differs from canonical named assignment",
            ));
        }
        if matches!(
            binding.kind,
            EvidenceBindingKind::Mechanism
                | EvidenceBindingKind::Discriminator
                | EvidenceBindingKind::TransitivePath
        ) && !primary(evidence, input)
        {
            return Err(rejected(
                "relation.evidence.binding",
                "mechanism/path binding is not bound to the exact relation",
            ));
        }
        if binding.kind == EvidenceBindingKind::Rival && !alternative_evidence(evidence, input) {
            return Err(rejected(
                "relation.evidence.binding",
                "rival binding is not bound to an exact retained alternative",
            ));
        }
    }
    Ok(())
}

/// Qualifies retained rival/no-relation evidence independently of the primary
/// predicate, returning only unknown evidence references and rival support.
pub fn qualify_alternatives(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<(Vec<String>, bool, bool), eliot_dreamer_contracts::ContractViolation> {
    let mut unknown = Vec::new();
    let mut supported = false;
    let mut unknown_alternative = false;
    for alternative in input
        .rivals
        .iter()
        .chain(input.no_relation_alternative.iter())
    {
        if alternative.evidence_refs.is_empty() {
            unknown_alternative = true;
            continue;
        }
        let mut alternative_support = false;
        let mut alternative_counter = false;
        let mut alternative_unknown = false;
        for reference in &alternative.evidence_refs {
            let Some(evidence) = input
                .evidence
                .iter()
                .chain(&input.counterevidence)
                .find(|value| value.evidence_id() == reference)
            else {
                return Err(rejected(
                    "relation.alternative.evidence",
                    "alternative evidence reference is not retained",
                ));
            };
            let exact_tuple = evidence.predicate.family == alternative.family
                && evidence.predicate.direction == alternative.direction
                && evidence.predicate.source_id == alternative.source_id
                && evidence.predicate.target_id == alternative.target_id;
            let assignment = grade_for(evidence, policy)?;
            let qualified = assignment.is_some()
                && envelope_qualified(evidence, input, policy, assignment)
                && exact_tuple;
            let collection_polarity = if input
                .evidence
                .iter()
                .any(|value| value.evidence_id() == evidence.evidence_id())
            {
                matches!(
                    evidence.polarity,
                    RelationEvidencePolarity::Support | RelationEvidencePolarity::Unknown
                )
            } else {
                matches!(
                    evidence.polarity,
                    RelationEvidencePolarity::Counter | RelationEvidencePolarity::Unknown
                )
            };
            if !qualified
                || !collection_polarity
                || matches!(evidence.polarity, RelationEvidencePolarity::Unknown)
            {
                alternative_unknown = true;
                unknown.push(evidence.evidence_id().to_owned());
            } else if matches!(evidence.polarity, RelationEvidencePolarity::Support) {
                alternative_support = true;
            } else if matches!(evidence.polarity, RelationEvidencePolarity::Counter) {
                alternative_counter = true;
            }
        }
        if alternative_support && alternative_counter {
            alternative_unknown = true;
            unknown.extend(alternative.evidence_refs.iter().cloned());
        }
        if alternative_unknown {
            unknown_alternative = true;
        } else if alternative_support {
            supported = true;
        }
    }
    unknown.sort();
    unknown.dedup();
    Ok((unknown, supported, unknown_alternative))
}

/// Material support requires at least the canonical Grounded grade even when
/// a caller permits orienting observations for an inconclusive result.
pub fn material_evidence_grounded(
    input: &RelationInput,
    policy: &RelationPolicy,
    refs: &[String],
) -> bool {
    refs.iter().all(|reference| {
        input
            .evidence
            .iter()
            .find(|value| value.evidence_id() == reference)
            .zip(
                policy
                    .grade_bindings
                    .iter()
                    .find(|binding| binding.evidence_id == *reference),
            )
            .and_then(|(evidence, binding)| {
                (evidence.named.external_grade.as_ref() == Some(&binding.reference)
                    && grade_binding_digest(binding).ok().as_deref()
                        == Some(binding.reference.digest.as_str()))
                .then(|| binding.assignment.known_grade())
                .flatten()
            })
            .is_some_and(|grade| grade.rank() >= EvidenceGrade::Grounded.rank())
    })
}

/// Association privacy is an independent qualification from endpoint privacy.
pub fn qualify_disclosure(
    input: &RelationInput,
    positive: bool,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    if !positive {
        return Ok(());
    }
    let Some(evidence) = &input.disclosure_evidence else {
        return Err(rejected(
            "relation.disclosure",
            "protected association lacks a disclosure decision",
        ));
    };
    if evidence.permitted != Some(true)
        || !matches!(
            evidence.decision,
            EpistemicStatus::Supported | EpistemicStatus::Verified
        )
        || evidence.owner.trim().is_empty()
    {
        return Err(rejected(
            "relation.disclosure",
            "association disclosure is not explicitly permitted by a current owner decision",
        ));
    }
    Ok(())
}

/// Validates the explicit temporal requirement without ordering clock domains.
pub fn qualify_temporal(
    input: &RelationInput,
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    if !policy.temporal_required {
        return Ok(());
    }
    let t = &input.temporal;
    if matches!(
        t.temporal_status,
        EpistemicStatus::Stale
            | EpistemicStatus::Unknown
            | EpistemicStatus::Contested
            | EpistemicStatus::Rejected
    ) {
        return Err(rejected(
            "relation.temporal",
            "temporal evidence is unknown, stale or contested",
        ));
    }
    let points = [
        &t.event_time,
        &t.effective_time,
        &t.observation_time,
        &t.ingestion_time,
        &t.commit_time,
    ];
    let mut present = 0_u32;
    for point in points.into_iter().flatten() {
        present = present
            .checked_add(1)
            .ok_or_else(|| rejected("relation.temporal", "temporal point count overflow"))?;
        if point.uncertainty_ms > policy.max_uncertainty_ms {
            return Err(rejected(
                "relation.temporal",
                "temporal uncertainty exceeds policy",
            ));
        }
    }
    if present == 0 {
        return Err(rejected(
            "relation.temporal",
            "temporal policy requires an explicit time point",
        ));
    }
    Ok(())
}

/// Qualifies a canonical causal claim against retained evidence, accepted
/// source materials and all five explicit A03 clock readings.
pub fn qualify_causal_claim(
    input: &RelationInput,
    ctx: &CurationAcceptanceCtx<'_>,
    policy: &RelationPolicy,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let Some(claim) = &policy.causal_claim else {
        return Ok(());
    };
    if claim.scope != input.scope_id || claim.fence != input.state_fence {
        return Err(rejected(
            "relation.causal_claim",
            "claim scope or fence drift",
        ));
    }
    let Some(predicate) = &policy.causal_predicate else {
        return Err(rejected(
            "relation.causal_claim.predicate",
            "causal predicate mapping is absent",
        ));
    };
    if predicate.subject != claim.subject.as_str()
        || predicate.predicate.family != Some(input.family)
        || predicate.predicate.direction != Some(input.direction)
        || predicate.predicate.source_id != input.source.endpoint_id()
        || predicate.predicate.target_id != input.target.endpoint_id()
    {
        return Err(rejected(
            "relation.causal_claim.predicate",
            "causal subject or directed predicate does not join relation",
        ));
    }
    let weak_status = !matches!(
        claim.status,
        eliot_epistemic_contracts::CausalStatus::InterventionSupported
            | eliot_epistemic_contracts::CausalStatus::AblationSupported
    );
    if weak_status {
        return Ok(());
    }
    if claim.ceiling == EvidenceGrade::ScienceGrade {
        return Err(rejected(
            "relation.causal_claim.ceiling",
            "causal claim cannot claim science grade",
        ));
    }
    let retained: Vec<&RelationEvidence> = input
        .evidence
        .iter()
        .chain(&input.counterevidence)
        .collect();
    qualify_causal_roles(input, policy, claim, &retained)?;
    for reference in &claim.evidence_refs {
        let Some(evidence) = retained
            .iter()
            .find(|value| value.evidence_id() == reference.as_str())
        else {
            return Err(rejected(
                "relation.causal_claim.evidence",
                "claim evidence is not retained",
            ));
        };
        let Some(assignment) = grade_for(evidence, policy)? else {
            return Err(rejected(
                "relation.causal_claim.evidence",
                "claim evidence grade is not qualified",
            ));
        };
        if assignment
            .known_grade()
            .is_some_and(|grade| claim.ceiling.rank() > grade.rank())
        {
            return Err(rejected(
                "relation.causal_claim.ceiling",
                "claim ceiling is above bound evidence",
            ));
        }
        let provenance = &evidence.named.foundation_evidence_envelope.provenance;
        if provenance.source_id != claim.source
            || provenance.revision.as_deref() != Some(claim.source_lineage.revision.as_str())
            || provenance.raw_handle.as_deref() != claim.source_lineage.raw_handle.as_deref()
        {
            return Err(rejected(
                "relation.causal_claim.provenance",
                "claim source lineage does not join evidence",
            ));
        }
    }
    let Some(material) = &policy.causal_material else {
        return Err(rejected(
            "relation.causal_claim.material",
            "causal source and proof handles are absent",
        ));
    };
    qualify_material_binding(ctx, claim, material)?;
    qualify_causal_times(input, claim, policy, ctx)
}

fn qualify_causal_roles(
    input: &RelationInput,
    policy: &RelationPolicy,
    claim: &eliot_epistemic_contracts::CausalClaim,
    retained: &[&RelationEvidence],
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let role_bound = |kind: EvidenceBindingKind,
                      expected_fact: Option<&str>,
                      alternative_id: Option<&str>,
                      primary: bool| {
        policy.causal_bindings.iter().any(|binding| {
            binding.kind == kind
                && expected_fact.is_none_or(|fact| binding.fact == fact)
                && binding.alternative_id.as_deref() == alternative_id
                && claim
                    .evidence_refs
                    .iter()
                    .any(|value| value.as_str() == binding.evidence_id)
                && retained.iter().any(|evidence| {
                    evidence.evidence_id() == binding.evidence_id
                        && evidence.predicate.expression == binding.fact
                        && (!primary || self::primary(evidence, input))
                        && grade_for(evidence, policy)
                            .ok()
                            .flatten()
                            .is_some_and(|assignment| *assignment == binding.grade)
                        && alternative_id.is_none_or(|id| {
                            input.rivals.iter().any(|alternative| {
                                alternative.alternative_id == id
                                    && alternative.evidence_refs.contains(&binding.evidence_id)
                            })
                        })
                })
        })
    };
    let primary_fact =
        |kind: EvidenceBindingKind, fact: Option<&str>| role_bound(kind, fact, None, true);
    let all_required_roles_bound = [
        EvidenceBindingKind::Mechanism,
        EvidenceBindingKind::Intervention,
        EvidenceBindingKind::Outcome,
        EvidenceBindingKind::Control,
        EvidenceBindingKind::Rival,
        EvidenceBindingKind::Confounder,
        EvidenceBindingKind::Discriminator,
    ]
    .iter()
    .all(|kind| {
        policy.causal_bindings.iter().any(|binding| {
            binding.kind == *kind
                && claim
                    .evidence_refs
                    .iter()
                    .any(|value| value.as_str() == binding.evidence_id)
        })
    });
    let valid = all_required_roles_bound
        && primary_fact(EvidenceBindingKind::Mechanism, Some(&claim.mechanism))
        && primary_fact(EvidenceBindingKind::Outcome, Some(&claim.outcome))
        && primary_fact(EvidenceBindingKind::Control, Some(&claim.control))
        && primary_fact(EvidenceBindingKind::Intervention, None)
        && primary_fact(EvidenceBindingKind::Discriminator, None)
        && claim.rivals.iter().all(|rival| {
            policy.causal_bindings.iter().any(|binding| {
                binding.kind == EvidenceBindingKind::Rival
                    && binding.fact == *rival
                    && binding.alternative_id.is_some()
                    && role_bound(
                        EvidenceBindingKind::Rival,
                        Some(rival),
                        binding.alternative_id.as_deref(),
                        false,
                    )
            })
        })
        && claim
            .confounders
            .iter()
            .all(|confounder| primary_fact(EvidenceBindingKind::Confounder, Some(confounder)));
    if valid {
        Ok(())
    } else {
        Err(rejected(
            "relation.causal_claim.roles",
            "causal facts do not join exact role, predicate, alternative and primary evidence bindings",
        ))
    }
}

fn qualify_material_binding(
    ctx: &CurationAcceptanceCtx<'_>,
    claim: &eliot_epistemic_contracts::CausalClaim,
    material: &CausalMaterialBinding,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let source = ctx
        .bundle
        .materials
        .iter()
        .find(|value| value.handle == material.source_handle);
    let proof = ctx
        .bundle
        .materials
        .iter()
        .find(|value| value.handle == material.proof_handle);
    let (Some(source), Some(proof)) = (source, proof) else {
        return Err(rejected(
            "relation.causal_claim.material",
            "causal material handle absent",
        ));
    };
    if matches!(
        source.disposition,
        eliot_dreamer_contracts::SourceDisposition::Excluded
    ) || matches!(
        proof.disposition,
        eliot_dreamer_contracts::SourceDisposition::Excluded
    ) {
        return Err(rejected(
            "relation.causal_claim.material",
            "causal material is explicitly excluded",
        ));
    }
    if claim.source_lineage.raw_handle.as_deref() != Some(material.source_handle.as_str()) {
        return Err(rejected(
            "relation.causal_claim.material",
            "causal source handle does not join source lineage",
        ));
    }
    if source.digest != claim.source_lineage.content_digest || proof.digest != claim.proof_digest {
        return Err(rejected(
            "relation.causal_claim.material",
            "causal material digest does not join claim",
        ));
    }
    Ok(())
}

fn qualify_causal_times(
    input: &RelationInput,
    claim: &eliot_epistemic_contracts::CausalClaim,
    policy: &RelationPolicy,
    ctx: &CurationAcceptanceCtx<'_>,
) -> Result<(), eliot_dreamer_contracts::ContractViolation> {
    let claim_times = [
        claim.temporal.event_ms,
        claim.temporal.effective_ms,
        claim.temporal.observation_ms,
        claim.temporal.ingestion_ms,
        claim.temporal.commit_ms,
    ];
    let points = [
        input.temporal.event_time.as_ref(),
        input.temporal.effective_time.as_ref(),
        input.temporal.observation_time.as_ref(),
        input.temporal.ingestion_time.as_ref(),
        input.temporal.commit_time.as_ref(),
    ];
    let Some(first) = points[0] else {
        return Err(rejected(
            "relation.causal_claim.temporal",
            "all five causal times are required",
        ));
    };
    for (expected, point) in claim_times.into_iter().zip(points) {
        let Some(point) = point else {
            return Err(rejected(
                "relation.causal_claim.temporal",
                "all five causal times are required",
            ));
        };
        let Some(actual) = point.reading.valid_time_ms else {
            return Err(rejected(
                "relation.causal_claim.temporal",
                "causal time lacks Unix milliseconds",
            ));
        };
        if actual != expected || point.uncertainty_ms > policy.max_uncertainty_ms {
            return Err(rejected(
                "relation.causal_claim.temporal",
                "causal time or uncertainty mismatch",
            ));
        }
        if point.clock_ref != first.clock_ref {
            return Err(rejected(
                "relation.causal_claim.temporal",
                "cross-clock conversion lacks an exact typed mapping",
            ));
        }
        if point.conversion_ref.as_deref().is_some_and(|handle| {
            !ctx.bundle
                .materials
                .iter()
                .any(|value| value.handle == handle)
        }) {
            return Err(rejected(
                "relation.causal_claim.temporal",
                "clock conversion material is absent",
            ));
        }
    }
    Ok(())
}
