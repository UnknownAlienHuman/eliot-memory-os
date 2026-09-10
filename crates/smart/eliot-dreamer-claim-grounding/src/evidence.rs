//! Manifest-only evidence resolution and conservative aggregation.

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::grounding::GroundingPolicy;
use eliot_dreamer_contracts::grounding::canonical::EvidenceFreshness;
use eliot_dreamer_contracts::grounding::canonical::{
    ArtifactId, EvidenceGrade, GradeAssignment, PositionAssertability, SupportRecord, SupportResult,
};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, AssertionWitness, ClaimGroundingRecord, MaterialClaim,
    PrecisionPayload, TypedEvidenceAssertion,
};

use crate::precision;

pub(crate) struct EvaluatedClaim {
    pub accepted_support: BTreeSet<ArtifactId>,
    pub rejected_support: BTreeSet<ArtifactId>,
    pub unresolved_support: BTreeSet<ArtifactId>,
    pub accepted_counterevidence: BTreeSet<ArtifactId>,
    pub rejected_counterevidence: BTreeSet<ArtifactId>,
    pub unresolved_counterevidence: BTreeSet<ArtifactId>,
    pub witnesses: Vec<AssertionWitness>,
    pub component_outcomes: BTreeMap<String, SupportResult>,
    /// Components with an actual manifest observation. Initial Unknown values
    /// are only missing-data sentinels and must not turn the first witness into
    /// a Partial result.
    pub observed_components: BTreeSet<String>,
    pub disposition: SupportResult,
    pub grades: Vec<GradeAssignment>,
    pub grade: Option<GradeAssignment>,
    pub grade_ceiling: EvidenceGrade,
    pub assertability_ceiling: PositionAssertability,
    pub caps: Vec<PositionAssertability>,
    pub coverage_denominator_ids: BTreeSet<String>,
    pub dependence_groups: BTreeSet<String>,
    pub unknowns: BTreeSet<String>,
    pub precision_findings: BTreeSet<String>,
}

impl Default for EvaluatedClaim {
    fn default() -> Self {
        Self {
            accepted_support: BTreeSet::new(),
            rejected_support: BTreeSet::new(),
            unresolved_support: BTreeSet::new(),
            accepted_counterevidence: BTreeSet::new(),
            rejected_counterevidence: BTreeSet::new(),
            unresolved_counterevidence: BTreeSet::new(),
            witnesses: Vec::new(),
            component_outcomes: BTreeMap::new(),
            observed_components: BTreeSet::new(),
            disposition: SupportResult::Unknown,
            grades: Vec::new(),
            grade: None,
            grade_ceiling: EvidenceGrade::Orienting,
            assertability_ceiling: PositionAssertability::UnknownWithheldQuarantined,
            caps: Vec::new(),
            coverage_denominator_ids: BTreeSet::new(),
            dependence_groups: BTreeSet::new(),
            unknowns: BTreeSet::new(),
            precision_findings: BTreeSet::new(),
        }
    }
}

pub(crate) fn evaluate_claim(
    claim: &MaterialClaim,
    manifest: &AllowedReferenceManifest,
    policy: &GroundingPolicy,
) -> Result<ClaimGroundingRecord, ContractViolation> {
    let mut evaluated = EvaluatedClaim::default();
    let denominator_id = absence_denominator(claim);
    let has_denominator = absence_manifest_complete(claim, manifest);
    if let Some(id) = denominator_id {
        if has_denominator {
            evaluated.coverage_denominator_ids.insert(id);
        } else {
            evaluated
                .unknowns
                .insert("absence denominator is not retained in the manifest".into());
        }
    }
    for finding in precision::precision_findings(claim, has_denominator) {
        evaluated.precision_findings.insert(finding.to_owned());
    }
    if !policy.permitted_kinds.contains(&claim.kind) {
        evaluated
            .precision_findings
            .insert("claim kind is outside the grounding policy".into());
    }
    for component in claim.component_digests.keys() {
        evaluated
            .component_outcomes
            .insert(component.clone(), SupportResult::Unknown);
    }

    for handle in &claim.proposed_support {
        resolve_handle(claim, manifest, handle, false, &mut evaluated)?;
    }
    for handle in &claim.proposed_counterevidence {
        resolve_handle(claim, manifest, handle, true, &mut evaluated)?;
    }

    evaluated.disposition = aggregate_components(&evaluated.component_outcomes);
    if !policy.permitted_kinds.contains(&claim.kind) {
        evaluated.disposition = SupportResult::Unknown;
    }
    if !precision::class_is_groundable(claim, has_denominator)
        && matches!(evaluated.disposition, SupportResult::Supported)
    {
        evaluated.disposition = SupportResult::Unknown;
    }
    if evaluated.component_outcomes.is_empty() && claim.subclaim_ids.is_empty() {
        evaluated.disposition = SupportResult::Unknown;
        if claim.component_digests.is_empty() {
            evaluated
                .unknowns
                .insert("claim has no claim-addressable component".into());
        }
    }
    evaluated.grade = weakest_grade(&evaluated.grades)?;
    evaluated.grade_ceiling = evaluated
        .grade
        .as_ref()
        .and_then(GradeAssignment::known_grade)
        .unwrap_or(EvidenceGrade::Orienting);
    evaluated.assertability_ceiling = assertability(&evaluated);

    let mut record = ClaimGroundingRecord {
        claim_id: claim.claim_id.clone(),
        proposition: claim.proposition.clone(),
        proposition_digest: claim.proposition_digest.clone(),
        kind: claim.kind,
        proposed_support: claim.proposed_support.clone(),
        accepted_support: evaluated.accepted_support,
        rejected_support: evaluated.rejected_support,
        unresolved_support: evaluated.unresolved_support,
        proposed_counterevidence: claim.proposed_counterevidence.clone(),
        accepted_counterevidence: evaluated.accepted_counterevidence,
        rejected_counterevidence: evaluated.rejected_counterevidence,
        unresolved_counterevidence: evaluated.unresolved_counterevidence,
        witnesses: evaluated.witnesses,
        component_outcomes: evaluated.component_outcomes,
        disposition: evaluated.disposition,
        grade: evaluated.grade,
        grade_ceiling: evaluated.grade_ceiling,
        assertability_ceiling: evaluated.assertability_ceiling,
        coverage_denominator_ids: evaluated.coverage_denominator_ids,
        dependence_groups: evaluated.dependence_groups,
        unknowns: evaluated.unknowns,
        precision_findings: evaluated.precision_findings,
        record_digest: String::new(),
    };
    // Grounding is a candidate-only transformation. It may carry upstream
    // ceilings downward, but it cannot mint an observed fact or material effect.
    record.assertability_ceiling = weaker(
        record.assertability_ceiling,
        PositionAssertability::HypothesisCandidate,
    );
    Ok(record)
}

fn resolve_handle(
    claim: &MaterialClaim,
    manifest: &AllowedReferenceManifest,
    handle: &ArtifactId,
    counterevidence: bool,
    result: &mut EvaluatedClaim,
) -> Result<(), ContractViolation> {
    let Some(reference) = manifest.references.get(handle) else {
        if counterevidence {
            result.unresolved_counterevidence.insert(handle.clone());
        } else {
            result.unresolved_support.insert(handle.clone());
        }
        for component in claim.component_digests.keys() {
            observe_component(result, component, SupportResult::OutsideManifest);
        }
        result
            .unknowns
            .insert("proposed handle is absent from the frozen manifest".into());
        return Ok(());
    };
    if !reference_is_usable(reference) {
        let rejected_result = if reference.invalidated || reference.revocation_reason.is_some() {
            SupportResult::Superseded
        } else if reference.stale || reference.freshness == EvidenceFreshness::Stale {
            SupportResult::Stale
        } else {
            SupportResult::Unknown
        };
        for component in claim.component_digests.keys() {
            observe_component(result, component, rejected_result);
        }
        if counterevidence {
            result.rejected_counterevidence.insert(handle.clone());
        } else {
            result.rejected_support.insert(handle.clone());
        }
        result.precision_findings.insert(
            match rejected_result {
                SupportResult::Superseded => "reference is invalidated or revoked",
                SupportResult::Stale => "reference freshness is stale",
                _ => "reference freshness is unknown",
            }
            .into(),
        );
        return Ok(());
    }

    let mut matched = false;
    for assertion in &reference.assertions {
        if !assertion_matches(claim, assertion, handle, manifest)? {
            continue;
        }
        let Some(support) = assertion.support.as_deref() else {
            continue;
        };
        matched = true;
        let lineage_closed = reference_lineage_closed(reference, manifest);
        let outcome = if matches!(
            support.result,
            SupportResult::Supported | SupportResult::Partial
        ) && !lineage_closed
        {
            result
                .unknowns
                .insert("supported relation lacks a closed retained source lineage".into());
            SupportResult::Unknown
        } else {
            support.result
        };
        let role_mismatch = counterevidence && outcome == SupportResult::Supported;
        if !role_mismatch {
            observe_component(result, &assertion.component, outcome);
        }
        result.witnesses.push(AssertionWitness {
            claim_id: claim.claim_id.clone(),
            component: assertion.component.clone(),
            handle: handle.clone(),
            assertion_id: assertion.assertion_id.clone(),
        });
        if counterevidence {
            result.accepted_counterevidence.insert(handle.clone());
        } else {
            result.accepted_support.insert(handle.clone());
        }
        // A counter-proposed Supported relation is retained as exact evidence
        // but cannot become affirmative support merely from its proposal role.
        if role_mismatch {
            result.unknowns.insert(
                "supported relation was proposed as counterevidence; proposal role cannot rewrite it"
                    .into(),
            );
        }
        collect_metadata(reference, support, manifest, result)?;
    }
    if !matched {
        if counterevidence {
            result.unresolved_counterevidence.insert(handle.clone());
        } else {
            result.unresolved_support.insert(handle.clone());
        }
        result
            .unknowns
            .insert("reference has no exact typed support relation for this claim".into());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn assertion_matches(
    claim: &MaterialClaim,
    assertion: &TypedEvidenceAssertion,
    handle: &ArtifactId,
    manifest: &AllowedReferenceManifest,
) -> Result<bool, ContractViolation> {
    if assertion.proposition != claim.proposition
        || assertion.proposition_digest != claim.proposition_digest
        || assertion.precision.kind() != claim.kind
        || !claim.component_digests.contains_key(&assertion.component)
        || !precision::payload_matches(claim, &assertion.precision)
    {
        return Ok(false);
    }
    if let Some(expected) = claim.component_digests.get(&assertion.component)
        && eliot_dreamer_contracts::grounding::component_content_digest(
            &claim.proposition,
            &assertion.component,
        )? != *expected
    {
        return Ok(false);
    }
    if let PrecisionPayload::QuoteAttribution { source, .. } = &claim.payload
        && source != handle
    {
        return Ok(false);
    }
    if let PrecisionPayload::TemporalVersioned { temporal, .. } = &claim.payload
        && assertion
            .support
            .as_deref()
            .and_then(|support| support.temporal.as_ref())
            != Some(temporal)
    {
        return Ok(false);
    }
    let Some(support) = assertion.support.as_deref() else {
        return Ok(false);
    };
    if support.proposition != claim.proposition {
        return Ok(false);
    }
    let proposed: BTreeSet<_> = claim
        .proposed_support
        .iter()
        .chain(&claim.proposed_counterevidence)
        .collect();
    if !support.handles.iter().all(|nested| {
        proposed.contains(nested)
            && manifest.references.get(nested).is_some_and(|reference| {
                reference_is_usable(reference)
                    && reference_dependencies(reference, manifest).is_some()
            })
    }) {
        return Ok(false);
    }
    if let PrecisionPayload::Causal { causal } = &claim.payload {
        let Some(enclosing) = manifest.references.get(handle) else {
            return Ok(false);
        };
        if !enclosing.source_lineage.as_ref().is_some_and(|lineage| {
            lineage == &causal.source_lineage
                && lineage.owner == causal.source
                && lineage.revision == causal.assurance.revision
                && lineage.content_digest == enclosing.content_digest
        }) || !enclosing
            .source_assurance
            .as_ref()
            .is_some_and(|assurance| {
                assurance.source == causal.assurance.source
                    && assurance.revision == causal.assurance.revision
                    && assurance.proof_digest == causal.assurance.proof_digest
            })
            || !support.assurance.as_ref().is_none_or(|assurance| {
                assurance.source == causal.assurance.source
                    && assurance.revision == causal.assurance.revision
                    && assurance.proof_digest == causal.assurance.proof_digest
            })
        {
            return Ok(false);
        }
        if !causal.evidence_refs.iter().all(|nested| {
            proposed.contains(nested)
                && support.handles.contains(nested)
                && manifest.references.get(nested).is_some_and(|reference| {
                    reference_is_usable(reference)
                        && reference_dependencies(reference, manifest).is_some()
                        && reference.source_lineage.as_ref().is_some_and(|lineage| {
                            lineage.owner == causal.source
                                && lineage.revision == causal.assurance.revision
                                && lineage.content_digest == reference.content_digest
                        })
                        && reference
                            .source_assurance
                            .as_ref()
                            .is_some_and(|assurance| {
                                assurance.source == causal.assurance.source
                                    && assurance.revision == causal.assurance.revision
                                    && assurance.proof_digest == causal.assurance.proof_digest
                            })
                })
        }) {
            return Ok(false);
        }
    }
    let Some(reference) = manifest.references.get(handle) else {
        return Ok(false);
    };
    if let PrecisionPayload::TemporalVersioned { revision, .. } = &claim.payload
        && reference.source_revision != *revision
    {
        return Ok(false);
    }
    if !support.validity.covers_candidate(
        &claim_validity_scope(claim, manifest),
        claim_validity_window(claim),
        &claim_validity_version(claim, reference),
        &support.validity.precision,
    ) {
        return Ok(false);
    }
    Ok(support.handles.contains(handle)
        && !matches!(support.result, SupportResult::OutsideManifest)
        && manifest.contains(handle))
}

fn observe_component(result: &mut EvaluatedClaim, component: &str, outcome: SupportResult) {
    if result.observed_components.insert(component.to_owned()) {
        result
            .component_outcomes
            .insert(component.to_owned(), outcome);
    } else {
        let current = result
            .component_outcomes
            .get(component)
            .copied()
            .unwrap_or(SupportResult::Unknown);
        result
            .component_outcomes
            .insert(component.to_owned(), aggregate_pair(current, outcome));
    }
}

fn claim_validity_scope(claim: &MaterialClaim, manifest: &AllowedReferenceManifest) -> String {
    match &claim.payload {
        PrecisionPayload::IdentityEntity { scope, .. } => scope.clone(),
        PrecisionPayload::Causal { causal } => causal.scope.clone(),
        _ => manifest.scope_id.clone(),
    }
}

fn claim_validity_version(
    claim: &MaterialClaim,
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
) -> String {
    match &claim.payload {
        PrecisionPayload::TemporalVersioned { version, .. }
        | PrecisionPayload::IdentityEntity { version, .. } => version.clone(),
        PrecisionPayload::Causal { causal } => causal.source_lineage.revision.clone(),
        PrecisionPayload::AbsenceExhaustiveNegative { denominator, .. } => {
            denominator.validity.version.clone()
        }
        _ => reference.source_revision.clone(),
    }
}

fn reference_is_usable(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
) -> bool {
    !reference.invalidated
        && !reference.stale
        && reference.revocation_reason.is_none()
        && !matches!(
            reference.freshness,
            EvidenceFreshness::Stale | EvidenceFreshness::Unknown
        )
}

fn claim_validity_window(claim: &MaterialClaim) -> (Option<i64>, Option<i64>) {
    match &claim.payload {
        PrecisionPayload::TemporalVersioned { temporal, .. } => {
            (Some(temporal.effective_ms), Some(temporal.effective_ms))
        }
        PrecisionPayload::Causal { causal } => (
            Some(causal.temporal.effective_ms),
            Some(causal.temporal.effective_ms),
        ),
        PrecisionPayload::AbsenceExhaustiveNegative { denominator, .. } => (
            denominator.validity.window_start_ms,
            denominator.validity.window_end_ms,
        ),
        _ => (None, None),
    }
}

fn absence_manifest_complete(claim: &MaterialClaim, manifest: &AllowedReferenceManifest) -> bool {
    let PrecisionPayload::AbsenceExhaustiveNegative {
        denominator,
        receipt,
        absence_proof,
        ..
    } = &claim.payload
    else {
        return false;
    };
    let Some(manifest_denominator) = manifest.coverage_denominators.get(&denominator.digest) else {
        return false;
    };
    if manifest_denominator != denominator.as_ref() {
        return false;
    }
    let Some(proof) = absence_proof else {
        return false;
    };
    let Some(manifest_receipt) = manifest.coverage_receipts.get(&denominator.digest) else {
        return false;
    };
    receipt
        .as_deref()
        .is_some_and(|payload_receipt| payload_receipt == manifest_receipt)
        && proof.receipt == *manifest_receipt
}

#[allow(clippy::too_many_lines)]
fn collect_metadata(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    support: &SupportRecord,
    manifest: &AllowedReferenceManifest,
    result: &mut EvaluatedClaim,
) -> Result<(), ContractViolation> {
    result.grades.push(support.grade.clone());
    result
        .grades
        .push(GradeAssignment::known(reference.grade_ceiling));
    if reference.source_lineage.is_none() && reference.provenance.is_none() {
        result
            .unknowns
            .insert("accepted reference has no provenance closure".into());
        result.caps.push(PositionAssertability::HypothesisCandidate);
    }
    result.caps.push(reference.assertability_ceiling);
    result
        .caps
        .push(PositionAssertability::authority_cap(reference.authority));
    result
        .caps
        .push(PositionAssertability::disclosure_cap(reference.disclosure));
    result.caps.push(match reference.privacy {
        eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Unrestricted => {
            PositionAssertability::MaterialEffect
        }
        eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::RestrictedHandling => {
            PositionAssertability::QualifiedInference
        }
        eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Purged => {
            PositionAssertability::HypothesisCandidate
        }
    });
    result.caps.push(
        PositionAssertability::support_cap(&[support.result]).map_err(|error| {
            ContractViolation::BindingMismatch {
                field: "assertion.support",
                reason: error.to_string(),
            }
        })?,
    );
    if let Some(dependencies) = reference_dependencies(reference, manifest) {
        for dependency in dependencies {
            let Some(dependency_reference) = manifest.references.get(&dependency) else {
                result
                    .unknowns
                    .insert("source lineage dependency is outside the retained manifest".into());
                result.caps.push(PositionAssertability::HypothesisCandidate);
                continue;
            };
            result
                .grades
                .push(GradeAssignment::known(dependency_reference.grade_ceiling));
            result.caps.push(dependency_reference.assertability_ceiling);
            result.caps.push(PositionAssertability::authority_cap(
                dependency_reference.authority,
            ));
            result.caps.push(PositionAssertability::disclosure_cap(
                dependency_reference.disclosure,
            ));
            result.caps.push(match dependency_reference.privacy {
                eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Unrestricted => {
                    PositionAssertability::MaterialEffect
                }
                eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::RestrictedHandling => {
                    PositionAssertability::QualifiedInference
                }
                eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Purged => {
                    PositionAssertability::HypothesisCandidate
                }
            });
            if dependency != reference.handle {
                let raw_bound = dependency_reference
                    .support
                    .as_ref()
                    .is_some_and(|raw_support| {
                        raw_support.validity.covers_candidate(
                            &support.validity.scope,
                            (
                                support.validity.window_start_ms,
                                support.validity.window_end_ms,
                            ),
                            &support.validity.version,
                            &support.validity.precision,
                        )
                    });
                if !raw_bound {
                    result.unknowns.insert(
                        "raw provenance support does not cover the derived observation".into(),
                    );
                    result.caps.push(PositionAssertability::HypothesisCandidate);
                }
            }
        }
        result
            .dependence_groups
            .extend(reference_dependence_groups(reference, manifest));
    } else {
        result
            .unknowns
            .insert("accepted reference has no closed retained source lineage".into());
        result.caps.push(PositionAssertability::HypothesisCandidate);
    }
    if support.grade.is_unknown() {
        result.unknowns.insert("support grade is unknown".into());
    }
    if matches!(
        support.result,
        SupportResult::Unknown | SupportResult::Partial
    ) {
        result
            .unknowns
            .insert("support relation is incomplete".into());
    }
    Ok(())
}

fn reference_lineage_closed(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    manifest: &AllowedReferenceManifest,
) -> bool {
    reference_dependencies(reference, manifest).is_some()
}

/// Resolves only explicit, typed lineage edges. Content similarity and
/// manifest-wide scans are deliberately unavailable as a fallback.
#[allow(clippy::too_many_lines)]
fn reference_dependencies(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    manifest: &AllowedReferenceManifest,
) -> Option<BTreeSet<ArtifactId>> {
    let Some(closure) = reference.provenance.as_ref() else {
        let lineage = reference.source_lineage.as_ref()?;
        if !lineage.predecessors.is_empty() {
            return None;
        }
        let mut dependencies = BTreeSet::from([reference.handle.clone()]);
        if let Some(raw_handle) = &lineage.raw_handle {
            let Ok(raw_id) = ArtifactId::new(raw_handle.clone()) else {
                return None;
            };
            if manifest
                .references
                .get(&raw_id)
                .is_none_or(|raw| !reference_is_usable(raw))
            {
                return None;
            }
            dependencies.insert(raw_id);
        }
        return Some(dependencies);
    };
    let target_digest = closure.record_origin.get(&reference.handle)?;
    if target_digest != &reference.content_digest {
        return None;
    }
    let lineage_by_content: BTreeMap<
        &str,
        &eliot_dreamer_contracts::grounding::canonical::SourceLineage,
    > = closure
        .lineage
        .iter()
        .map(|lineage| (lineage.content_digest.as_str(), lineage))
        .collect();
    let target = lineage_by_content.get(target_digest.as_str())?;
    if target.revision != reference.source_revision
        || reference
            .source_lineage
            .as_ref()
            .is_some_and(|lineage| lineage != *target)
    {
        return None;
    }
    let mut dependencies = BTreeSet::new();
    let mut pending = vec![target_digest.as_str()];
    let mut seen = BTreeSet::new();
    while let Some(content) = pending.pop() {
        if !seen.insert(content) {
            continue;
        }
        let entry = lineage_by_content.get(content)?;
        for predecessor in &entry.predecessors {
            if !lineage_by_content.contains_key(predecessor.as_str()) {
                return None;
            }
            pending.push(predecessor.as_str());
        }
        if let Some(raw_handle) = &entry.raw_handle {
            let Ok(raw_id) = ArtifactId::new(raw_handle.clone()) else {
                return None;
            };
            if !closure.records.contains(&raw_id)
                || manifest
                    .references
                    .get(&raw_id)
                    .is_none_or(|raw| !reference_is_usable(raw))
            {
                return None;
            }
            dependencies.insert(raw_id);
        }
    }
    let mut mapped_contents = BTreeSet::new();
    for (handle, content) in &closure.record_origin {
        if !seen.contains(content.as_str()) {
            continue;
        }
        if !closure.records.contains(handle) {
            return None;
        }
        let candidate = manifest.references.get(handle)?;
        if !reference_is_usable(candidate) {
            return None;
        }
        let lineage = lineage_by_content.get(content.as_str())?;
        if candidate.content_digest != *content || candidate.source_revision != lineage.revision {
            return None;
        }
        if candidate
            .source_lineage
            .as_ref()
            .is_some_and(|entry| entry != *lineage)
        {
            return None;
        }
        mapped_contents.insert(content.as_str());
        dependencies.insert(handle.clone());
    }
    if seen
        .iter()
        .any(|content| !mapped_contents.contains(content))
    {
        return None;
    }
    Some(dependencies)
}

fn reference_dependence_groups(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    manifest: &AllowedReferenceManifest,
) -> BTreeSet<String> {
    let mut groups = BTreeSet::new();
    let mut lineages = Vec::new();
    if let Some(closure) = &reference.provenance {
        let by_content: BTreeMap<_, _> = closure
            .lineage
            .iter()
            .map(|lineage| (lineage.content_digest.as_str(), lineage))
            .collect();
        let Some(target) = closure.record_origin.get(&reference.handle) else {
            return groups;
        };
        let mut pending = vec![target.as_str()];
        let mut seen = BTreeSet::new();
        while let Some(content) = pending.pop() {
            if !seen.insert(content) {
                continue;
            }
            let Some(lineage) = by_content.get(content) else {
                return BTreeSet::new();
            };
            lineages.push(*lineage);
            pending.extend(lineage.predecessors.iter().map(String::as_str));
        }
    } else if let Some(lineage) = &reference.source_lineage {
        lineages.push(lineage);
    }
    for lineage in lineages {
        groups.insert(lineage.owner.to_string());
        if lineage.predecessors.is_empty() {
            groups.insert(lineage.content_digest.clone());
        }
        if let Some(raw_handle) = &lineage.raw_handle {
            let Ok(raw_id) = ArtifactId::new(raw_handle.clone()) else {
                return BTreeSet::new();
            };
            if manifest
                .references
                .get(&raw_id)
                .is_some_and(reference_is_usable)
            {
                groups.insert(raw_handle.clone());
            }
        }
    }
    groups
}

fn weakest_grade(
    assignments: &[GradeAssignment],
) -> Result<Option<GradeAssignment>, ContractViolation> {
    if assignments.is_empty() {
        return Ok(None);
    }
    GradeAssignment::weakest(assignments)
        .map(Some)
        .map_err(|error| ContractViolation::BindingMismatch {
            field: "assertion.support.grade",
            reason: error.to_string(),
        })
}

fn absence_denominator(claim: &MaterialClaim) -> Option<String> {
    match &claim.payload {
        PrecisionPayload::AbsenceExhaustiveNegative { denominator, .. } => {
            Some(denominator.digest.clone())
        }
        _ => None,
    }
}

/// Aggregation deliberately differs from canonical `weakest_link`: a supported
/// component plus an incomplete component is Partial, while contradictions win.
pub(crate) fn aggregate_pair(left: SupportResult, right: SupportResult) -> SupportResult {
    if left == SupportResult::Contradicted || right == SupportResult::Contradicted {
        return SupportResult::Contradicted;
    }
    if left == right {
        return left;
    }
    if left == SupportResult::Supported || right == SupportResult::Supported {
        return SupportResult::Partial;
    }
    if left == SupportResult::Partial || right == SupportResult::Partial {
        return SupportResult::Partial;
    }
    if left == SupportResult::OutsideManifest || right == SupportResult::OutsideManifest {
        return if left == SupportResult::OutsideManifest && right == SupportResult::OutsideManifest
        {
            SupportResult::OutsideManifest
        } else {
            SupportResult::Unknown
        };
    }
    if left == SupportResult::Unknown || right == SupportResult::Unknown {
        return SupportResult::Unknown;
    }
    SupportResult::Unknown
}

pub(crate) fn aggregate_components(outcomes: &BTreeMap<String, SupportResult>) -> SupportResult {
    outcomes
        .values()
        .copied()
        .reduce(aggregate_pair)
        .unwrap_or(SupportResult::Unknown)
}

/// Reapplies the record's own grade and assertability ceilings after a
/// parent has incorporated child dispositions.
pub(crate) fn recompute_record_assertability(record: &mut ClaimGroundingRecord) {
    let base = match record.disposition {
        SupportResult::Contradicted
        | SupportResult::Unknown
        | SupportResult::OutsideManifest
        | SupportResult::Stale
        | SupportResult::Superseded
        | SupportResult::JustifiedNotApplicable => {
            PositionAssertability::UnknownWithheldQuarantined
        }
        SupportResult::Partial | SupportResult::Unsupported => {
            PositionAssertability::HypothesisCandidate
        }
        SupportResult::Supported => {
            if record
                .grade
                .as_ref()
                .is_some_and(GradeAssignment::is_unknown)
            {
                PositionAssertability::HypothesisCandidate
            } else {
                PositionAssertability::MaterialEffect
            }
        }
    };
    record.assertability_ceiling = weaker(base, record.assertability_ceiling);
}

pub(crate) fn cap_record_assertability(
    record: &mut ClaimGroundingRecord,
    cap: PositionAssertability,
) {
    record.assertability_ceiling = weaker(record.assertability_ceiling, cap);
}

fn assertability(result: &EvaluatedClaim) -> PositionAssertability {
    let base = match result.disposition {
        SupportResult::Contradicted
        | SupportResult::Unknown
        | SupportResult::OutsideManifest
        | SupportResult::Stale
        | SupportResult::Superseded
        | SupportResult::JustifiedNotApplicable => {
            PositionAssertability::UnknownWithheldQuarantined
        }
        SupportResult::Partial | SupportResult::Unsupported => {
            PositionAssertability::HypothesisCandidate
        }
        SupportResult::Supported => {
            if result
                .grade
                .as_ref()
                .is_some_and(GradeAssignment::is_unknown)
            {
                PositionAssertability::HypothesisCandidate
            } else {
                PositionAssertability::MaterialEffect
            }
        }
    };
    result.caps.iter().copied().fold(base, weaker)
}

fn weaker(left: PositionAssertability, right: PositionAssertability) -> PositionAssertability {
    let rank = |value| match value {
        PositionAssertability::UnknownWithheldQuarantined => 0,
        PositionAssertability::PlanningOnly => 1,
        PositionAssertability::HypothesisCandidate => 2,
        PositionAssertability::ConflictQualificationRequired => 3,
        PositionAssertability::QualifiedInference => 4,
        PositionAssertability::ObservedFact => 5,
        PositionAssertability::MaterialEffect => 6,
    };
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}
