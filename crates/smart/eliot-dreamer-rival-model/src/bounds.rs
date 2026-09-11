//! Borrowed wire preflight and aggregate work limits.

use crate::error::RivalModelError;
use eliot_dreamer_contracts::ValidatedGroundingCandidate;
use eliot_dreamer_contracts::grounding::PrecisionPayload;
use eliot_dreamer_contracts::rival::{
    DeclarationAvailability, RivalDeclarationSet, RivalModelSlot,
};
use serde::Serialize;
use std::io::{self, Write};

/// Maximum serialized candidate envelope accepted by this consumer.
pub const MAX_CANDIDATE_WIRE_BYTES: usize = 1024 * 1024;
/// Maximum serialized rival output envelope accepted by this consumer.
pub const MAX_RIVAL_WIRE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum entries in one retained rival table.
pub const MAX_RIVAL_ITEMS: usize = 256;
/// Maximum direct bounded work reserved for one operation.
pub const MAX_RIVAL_WORK: usize = 4096;

struct CountingWriter {
    count: usize,
    ceiling: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "serialized size overflow"))?;
        if next > self.ceiling {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "serialized size bound",
            ));
        }
        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Measures a borrowed serde wire without allocating its serialized bytes.
pub fn preflight<T: Serialize>(value: &T, ceiling: usize) -> Result<usize, RivalModelError> {
    let mut writer = CountingWriter { count: 0, ceiling };
    serde_json::to_writer(&mut writer, value).map_err(|_| RivalModelError::Bound {
        field: "serialized_wire",
        maximum: ceiling,
        actual: writer.count.saturating_add(1),
    })?;
    Ok(writer.count)
}

/// Returns the direct bounded work reserved by a candidate envelope.
pub fn candidate_work(candidate: &ValidatedGroundingCandidate) -> Result<usize, RivalModelError> {
    let input = &candidate.input;
    let grounded = &input.grounded;
    let bundle = &grounded.input.bundle;
    let model = &grounded.input;
    let mut total = 0usize;
    for (field, count) in [
        ("claims", model.claims.len()),
        ("non_material_claims", model.non_material_claims.len()),
        ("bundle.materials", bundle.materials.len()),
        ("bundle.omissions", bundle.omissions.len()),
        ("manifest.references", grounded.manifest.references.len()),
        ("ledger.records", grounded.ledger.records.len()),
    ] {
        bounded_add(&mut total, count, field)?;
    }
    if let Some(declarations) = input.rival_declarations.as_deref() {
        count_declarations(declarations, &mut total)?;
    }
    if total > MAX_RIVAL_WORK {
        return Err(RivalModelError::Bound {
            field: "candidate_work",
            maximum: MAX_RIVAL_WORK,
            actual: total,
        });
    }
    Ok(total)
}

/// Independent counts of canonical records and their direct typed references.
/// `material` counts claim, assumption, prediction, model-reference, nested
/// component, precision-denominator, and coverage-member entries;
/// `reference` counts source/bundle/manifest slots, provenance entries, and
/// every declared typed evidence handle occurrence; `evidence` counts ledger
/// records, assertions, support/causal records, and coverage receipts;
/// `conflict` counts conflict records and positions plus rival, confounder,
/// evidence, defeated-reference, and residue entries.
#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateDomainCounts {
    /// Material claims and their typed nested records.
    pub material: usize,
    /// Distinct-reference-bearing collection entries.
    pub reference: usize,
    /// Evidence records and assertions.
    pub evidence: usize,
    /// Conflict and rival-analysis records.
    pub conflict: usize,
}

/// Returns checked independent counts before lower-owner validation.
pub fn candidate_domain_counts(
    candidate: &ValidatedGroundingCandidate,
) -> Result<CandidateDomainCounts, RivalModelError> {
    let grounded = &candidate.input.grounded;
    let bundle = &grounded.input.bundle;
    let mut counts = CandidateDomainCounts::default();
    add(
        &mut counts.material,
        grounded.input.claims.len(),
        "material",
    )?;
    add(&mut counts.material, bundle.materials.len(), "material")?;
    add(&mut counts.reference, bundle.materials.len(), "reference")?;
    add(&mut counts.reference, bundle.omissions.len(), "reference")?;
    add(
        &mut counts.evidence,
        grounded.ledger.records.len(),
        "evidence",
    )?;
    for record in grounded.ledger.records.values() {
        count_grounding_record(record, &mut counts)?;
    }
    for claim in &grounded.input.claims {
        add_claim(&mut counts, claim)?;
    }
    for reference in grounded.manifest.references.values() {
        add(&mut counts.reference, 1, "reference")?;
        count_authorized_reference(reference, &mut counts)?;
    }
    if let Some(declarations) = candidate.input.rival_declarations.as_deref() {
        count_rival_declarations(declarations, &mut counts)?;
        count_coverage(&declarations.model_coverage, &mut counts)?;
        count_coverage(&declarations.source_coverage, &mut counts)?;
    }
    let total = counts
        .material
        .checked_add(counts.reference)
        .and_then(|total| total.checked_add(counts.evidence))
        .and_then(|total| total.checked_add(counts.conflict))
        .ok_or(RivalModelError::Bound {
            field: "candidate_domain_counts",
            maximum: MAX_RIVAL_WORK,
            actual: usize::MAX,
        })?;
    if total > MAX_RIVAL_WORK {
        return Err(RivalModelError::Bound {
            field: "candidate_domain_counts",
            maximum: MAX_RIVAL_WORK,
            actual: total,
        });
    }
    Ok(counts)
}

/// Returns the distinct typed artifact-reference width of the candidate.
///
/// This is separate from [`CandidateDomainCounts::reference`], which counts
/// every occurrence for local work limits. The budget width counts each
/// `ArtifactId` identity once, across the manifest, grounded ledger, retained
/// material, and rival declaration tables. Identity domains that are strings
/// (claim and assumption IDs) are intentionally excluded.
pub fn candidate_reference_width(
    candidate: &ValidatedGroundingCandidate,
) -> Result<usize, RivalModelError> {
    let grounded = &candidate.input.grounded;
    let mut ids = std::collections::BTreeSet::new();
    for handle in grounded.manifest.references.keys() {
        ids.insert(handle.as_str().to_owned());
    }
    for reference in grounded.manifest.references.values() {
        collect_authorized_reference_ids(reference, &mut ids);
    }
    for record in grounded.ledger.records.values() {
        collect_grounding_record_ids(record, &mut ids);
    }
    for claim in &grounded.input.claims {
        collect_claim_ids(claim, &mut ids);
    }
    if let Some(declarations) = candidate.input.rival_declarations.as_deref() {
        collect_rival_ids(declarations, &mut ids);
    }
    if ids.len() > MAX_RIVAL_WORK {
        return Err(RivalModelError::Bound {
            field: "reference_width",
            maximum: MAX_RIVAL_WORK,
            actual: ids.len(),
        });
    }
    Ok(ids.len())
}

fn collect_id(
    ids: &mut std::collections::BTreeSet<String>,
    id: &eliot_dreamer_contracts::grounding::ArtifactId,
) {
    ids.insert(id.as_str().to_owned());
}

fn collect_grounding_record_ids(
    record: &eliot_dreamer_contracts::grounding::ClaimGroundingRecord,
    ids: &mut std::collections::BTreeSet<String>,
) {
    for handles in [
        &record.proposed_support,
        &record.accepted_support,
        &record.rejected_support,
        &record.unresolved_support,
        &record.proposed_counterevidence,
        &record.accepted_counterevidence,
        &record.rejected_counterevidence,
        &record.unresolved_counterevidence,
    ] {
        for handle in handles {
            collect_id(ids, handle);
        }
    }
    for witness in &record.witnesses {
        collect_id(ids, &witness.handle);
    }
}

fn collect_claim_ids(
    claim: &eliot_dreamer_contracts::grounding::MaterialClaim,
    ids: &mut std::collections::BTreeSet<String>,
) {
    for handle in claim
        .proposed_support
        .iter()
        .chain(claim.proposed_counterevidence.iter())
    {
        collect_id(ids, handle);
    }
    collect_precision_ids(&claim.payload, ids);
}

fn collect_precision_ids(
    precision: &PrecisionPayload,
    ids: &mut std::collections::BTreeSet<String>,
) {
    match precision {
        PrecisionPayload::Causal { causal } => {
            for handle in &causal.evidence_refs {
                collect_id(ids, handle);
            }
        }
        PrecisionPayload::AbsenceExhaustiveNegative {
            denominator,
            receipt,
            absence_proof,
            ..
        } => {
            for handle in &denominator.members {
                collect_id(ids, handle);
            }
            if let Some(receipt) = receipt {
                collect_receipt_ids(receipt, ids);
            }
            if let Some(proof) = absence_proof {
                collect_receipt_ids(&proof.receipt, ids);
            }
        }
        PrecisionPayload::QuoteAttribution { source, .. } => collect_id(ids, source),
        _ => {}
    }
}

fn collect_receipt_ids(
    receipt: &eliot_dreamer_contracts::grounding::CoverageReceipt,
    ids: &mut std::collections::BTreeSet<String>,
) {
    for member in &receipt.members {
        collect_id(ids, &member.member);
    }
    for omission in &receipt.omissions {
        collect_id(ids, &omission.member);
    }
}

fn collect_authorized_reference_ids(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    ids: &mut std::collections::BTreeSet<String>,
) {
    collect_id(ids, &reference.handle);
    if let Some(support) = &reference.support {
        for handle in &support.handles {
            collect_id(ids, handle);
        }
    }
    if let Some(provenance) = &reference.provenance {
        for handle in &provenance.records {
            collect_id(ids, handle);
        }
    }
    for assertion in &reference.assertions {
        if let Some(support) = &assertion.support {
            for handle in &support.handles {
                collect_id(ids, handle);
            }
        }
        collect_precision_ids(&assertion.precision, ids);
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded owner-ID collection preserves deterministic declaration order"
)]
fn collect_rival_ids(
    declarations: &RivalDeclarationSet,
    ids: &mut std::collections::BTreeSet<String>,
) {
    use eliot_dreamer_contracts::rival::{
        DeclarationAvailability, RivalDependency, RivalModelSlot, RivalPredictionSlot,
        RivalSourceSlot,
    };
    for slot in &declarations.models {
        collect_id(ids, slot.stable_id());
        if let RivalModelSlot::Retained { declaration } = slot {
            for predecessor in &declaration.predecessors {
                collect_id(ids, &predecessor.model_id);
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.prediction_refs {
                for reference in entries {
                    collect_id(ids, &reference.prediction_id);
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.dependency_refs {
                for dependency in entries {
                    match dependency {
                        RivalDependency::Model { reference } => {
                            collect_id(ids, &reference.model_id);
                        }
                        RivalDependency::Record { record_id, .. } => collect_id(ids, record_id),
                    }
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.support_observations
            {
                for support in entries {
                    for handle in &support.handles {
                        collect_id(ids, handle);
                    }
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.causal_readings {
                for causal in entries {
                    for handle in &causal.evidence_refs {
                        collect_id(ids, handle);
                    }
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.conflicts {
                for conflict in entries {
                    for handle in conflict
                        .evidence_refs
                        .iter()
                        .chain(conflict.defeated_refs.iter())
                    {
                        collect_id(ids, handle);
                    }
                    for position in &conflict.positions {
                        for handle in &position.counters {
                            collect_id(ids, handle);
                        }
                    }
                }
            }
            if let eliot_dreamer_contracts::rival::SuppliedLineage::Retained { closure } =
                &declaration.lineage
            {
                for handle in &closure.records {
                    collect_id(ids, handle);
                }
            }
        }
    }
    for related in &declarations.related_models {
        collect_id(ids, &related.reference.model_id);
    }
    for slot in &declarations.claims {
        if let eliot_dreamer_contracts::rival::RivalClaimSlot::Retained { claim } = slot {
            collect_claim_ids(claim, ids);
        }
    }
    for slot in &declarations.predictions {
        if let RivalPredictionSlot::Retained { prediction } = slot {
            collect_id(ids, &prediction.prediction_id);
        }
    }
    for slot in &declarations.sources {
        if let RivalSourceSlot::Retained { reference } = slot {
            collect_authorized_reference_ids(reference, ids);
        } else {
            collect_id(ids, slot.stable_id());
        }
    }
    for coverage in [&declarations.model_coverage, &declarations.source_coverage] {
        let (denominator, receipt) = match coverage {
            eliot_dreamer_contracts::rival::RivalCoverageDeclaration::Supplied {
                denominator,
                receipt,
            } => (Some(denominator.as_ref()), receipt),
            eliot_dreamer_contracts::rival::RivalCoverageDeclaration::Unknown {
                receipt, ..
            } => (None, receipt),
        };
        if let Some(denominator) = denominator {
            for handle in &denominator.members {
                collect_id(ids, handle);
            }
        }
        if let eliot_dreamer_contracts::rival::RivalCoverageReceipt::Supplied { receipt } = receipt
        {
            for member in &receipt.members {
                collect_id(ids, &member.member);
            }
            for omission in &receipt.omissions {
                collect_id(ids, &omission.member);
            }
        }
    }
}

fn count_grounding_record(
    record: &eliot_dreamer_contracts::grounding::ClaimGroundingRecord,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    for handles in [
        &record.proposed_support,
        &record.accepted_support,
        &record.rejected_support,
        &record.unresolved_support,
        &record.proposed_counterevidence,
        &record.accepted_counterevidence,
        &record.rejected_counterevidence,
        &record.unresolved_counterevidence,
    ] {
        add(&mut counts.reference, handles.len(), "reference")?;
    }
    add(&mut counts.evidence, record.witnesses.len(), "evidence")?;
    add(
        &mut counts.evidence,
        record.component_outcomes.len(),
        "evidence",
    )?;
    add(
        &mut counts.material,
        record.coverage_denominator_ids.len(),
        "material",
    )?;
    add(
        &mut counts.evidence,
        record.dependence_groups.len(),
        "evidence",
    )?;
    add(&mut counts.evidence, record.unknowns.len(), "evidence")?;
    add(
        &mut counts.evidence,
        record.precision_findings.len(),
        "evidence",
    )
}

fn add_claim(
    counts: &mut CandidateDomainCounts,
    claim: &eliot_dreamer_contracts::grounding::MaterialClaim,
) -> Result<(), RivalModelError> {
    add(&mut counts.material, claim.subclaim_ids.len(), "material")?;
    add(
        &mut counts.material,
        claim.component_digests.len(),
        "material",
    )?;
    add(
        &mut counts.reference,
        claim.proposed_support.len(),
        "reference",
    )?;
    add(
        &mut counts.reference,
        claim.proposed_counterevidence.len(),
        "reference",
    )?;
    count_precision(&claim.payload, counts)
}

fn count_precision(
    precision: &PrecisionPayload,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    match precision {
        PrecisionPayload::Causal { causal } => {
            add(&mut counts.conflict, causal.rivals.len(), "conflict")?;
            add(&mut counts.conflict, causal.confounders.len(), "conflict")?;
            add(
                &mut counts.reference,
                causal.evidence_refs.len(),
                "reference",
            )?;
            add(&mut counts.evidence, 1, "evidence")?;
        }
        PrecisionPayload::AbsenceExhaustiveNegative {
            denominator,
            receipt,
            absence_proof,
            ..
        } => {
            add(&mut counts.material, denominator.members.len(), "material")?;
            add(&mut counts.material, denominator.roles.len(), "material")?;
            if let Some(receipt) = receipt {
                add_receipt(receipt, counts)?;
            }
            if let Some(proof) = absence_proof {
                add(&mut counts.evidence, 1, "evidence")?;
                add(&mut counts.reference, 1, "reference")?;
                add(
                    &mut counts.evidence,
                    usize::try_from(proof.proof.byte_len).unwrap_or(usize::MAX),
                    "evidence",
                )?;
                add_receipt(&proof.receipt, counts)?;
            }
        }
        PrecisionPayload::RecommendationNormativeInference {
            fact_components,
            assumptions,
            ..
        } => {
            add(&mut counts.material, fact_components.len(), "material")?;
            add(&mut counts.material, assumptions.len(), "material")?;
        }
        _ => {}
    }
    Ok(())
}

fn add_receipt(
    receipt: &eliot_dreamer_contracts::grounding::CoverageReceipt,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    add(&mut counts.evidence, 1, "evidence")?;
    add(&mut counts.reference, receipt.groups.len(), "reference")?;
    add(&mut counts.reference, receipt.members.len(), "reference")?;
    add(&mut counts.reference, receipt.omissions.len(), "reference")
}

fn count_authorized_reference(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    add(&mut counts.evidence, reference.assertions.len(), "evidence")?;
    if let Some(support) = &reference.support {
        add(&mut counts.evidence, 1, "evidence")?;
        add(&mut counts.reference, support.handles.len(), "reference")?;
    }
    if let Some(provenance) = &reference.provenance {
        add(&mut counts.reference, provenance.records.len(), "reference")?;
        add(&mut counts.reference, provenance.lineage.len(), "reference")?;
    }
    for assertion in &reference.assertions {
        if let Some(support) = &assertion.support {
            add(&mut counts.evidence, 1, "evidence")?;
            add(&mut counts.reference, support.handles.len(), "reference")?;
        }
    }
    Ok(())
}

fn count_coverage(
    coverage: &eliot_dreamer_contracts::rival::RivalCoverageDeclaration,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    match coverage {
        eliot_dreamer_contracts::rival::RivalCoverageDeclaration::Supplied {
            denominator,
            receipt,
        } => {
            add(&mut counts.material, denominator.members.len(), "material")?;
            add(&mut counts.material, denominator.roles.len(), "material")?;
            if let eliot_dreamer_contracts::rival::RivalCoverageReceipt::Supplied { receipt } =
                receipt
            {
                add_receipt(receipt, counts)?;
            }
        }
        eliot_dreamer_contracts::rival::RivalCoverageDeclaration::Unknown { receipt, .. } => {
            if let eliot_dreamer_contracts::rival::RivalCoverageReceipt::Supplied { receipt } =
                receipt
            {
                add_receipt(receipt, counts)?;
            }
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "declaration counting keeps independent domain limits in one pass"
)]
fn count_rival_declarations(
    declarations: &RivalDeclarationSet,
    counts: &mut CandidateDomainCounts,
) -> Result<(), RivalModelError> {
    for slot in &declarations.models {
        add(&mut counts.material, 1, "material")?;
        if let RivalModelSlot::Retained { declaration } = slot {
            add(
                &mut counts.material,
                declaration.predecessors.len(),
                "material",
            )?;
            add(
                &mut counts.material,
                declaration.explanations.len(),
                "material",
            )?;
            add_availability_entries(&declaration.assumptions, &mut counts.material)?;
            add_availability_entries(&declaration.prediction_refs, &mut counts.material)?;
            add_availability_entries(&declaration.dependency_refs, &mut counts.material)?;
            for claims in [
                &declaration.supporting_claims,
                &declaration.counterevidence_claims,
                &declaration.revision_conditions,
                &declaration.invalidation_conditions,
                &declaration.successful_transfers,
                &declaration.failed_transfers,
                &declaration.downstream_effects,
            ] {
                if let eliot_dreamer_contracts::rival::ClaimDeclarations::Supplied { claims } =
                    claims
                {
                    add(&mut counts.material, claims.len(), "material")?;
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.support_observations
            {
                add(&mut counts.evidence, entries.len(), "evidence")?;
                for support in entries {
                    add(&mut counts.reference, support.handles.len(), "reference")?;
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.causal_readings {
                add(&mut counts.evidence, entries.len(), "evidence")?;
                for causal in entries {
                    add(&mut counts.conflict, causal.rivals.len(), "conflict")?;
                    add(&mut counts.conflict, causal.confounders.len(), "conflict")?;
                    add(
                        &mut counts.reference,
                        causal.evidence_refs.len(),
                        "reference",
                    )?;
                }
            }
            if let DeclarationAvailability::Supplied { entries } = &declaration.conflicts {
                add(&mut counts.conflict, entries.len(), "conflict")?;
                for conflict in entries {
                    add(&mut counts.conflict, conflict.positions.len(), "conflict")?;
                    add(
                        &mut counts.conflict,
                        conflict.evidence_refs.len(),
                        "conflict",
                    )?;
                    add(
                        &mut counts.reference,
                        conflict.evidence_refs.len(),
                        "reference",
                    )?;
                    add(
                        &mut counts.conflict,
                        conflict.defeated_refs.len(),
                        "conflict",
                    )?;
                    add(
                        &mut counts.reference,
                        conflict.defeated_refs.len(),
                        "reference",
                    )?;
                    for position in &conflict.positions {
                        add(&mut counts.conflict, position.assumptions.len(), "conflict")?;
                        add(&mut counts.reference, position.counters.len(), "reference")?;
                    }
                }
            }
            if let eliot_dreamer_contracts::rival::CommonModeDisclosure::Supplied { basis, .. } =
                &declaration.common_mode
                && let eliot_dreamer_contracts::rival::ClaimDeclarations::Supplied { claims } =
                    basis
            {
                add(&mut counts.material, claims.len(), "material")?;
            }
            if let eliot_dreamer_contracts::rival::TemporalAvailability::Supplied { .. } =
                &declaration.temporal
            {
                add(&mut counts.evidence, 1, "evidence")?;
            }
            if let eliot_dreamer_contracts::rival::SuppliedLineage::Retained { closure } =
                &declaration.lineage
            {
                add(&mut counts.reference, closure.records.len(), "reference")?;
                add(&mut counts.reference, closure.lineage.len(), "reference")?;
            }
        }
    }
    add(
        &mut counts.material,
        declarations.related_models.len(),
        "material",
    )?;
    for slot in &declarations.claims {
        add(&mut counts.material, 1, "material")?;
        if let eliot_dreamer_contracts::rival::RivalClaimSlot::Retained { claim } = slot {
            add_claim(counts, claim)?;
        }
    }
    add(
        &mut counts.material,
        declarations.assumptions.len(),
        "material",
    )?;
    for slot in &declarations.assumptions {
        if let eliot_dreamer_contracts::rival::RivalAssumptionSlot::Retained { assumption } = slot {
            add(
                &mut counts.material,
                assumption.dependents.len(),
                "material",
            )?;
        }
    }
    add(
        &mut counts.material,
        declarations.predictions.len(),
        "material",
    )?;
    for slot in &declarations.predictions {
        if let eliot_dreamer_contracts::rival::RivalPredictionSlot::Retained { prediction } = slot {
            add(
                &mut counts.material,
                prediction.condition_assumptions.len(),
                "material",
            )?;
            add(&mut counts.material, 1, "material")?;
            for forecast in [
                &prediction.forecast.verifier_verdict,
                &prediction.forecast.diagnostic_change,
                &prediction.forecast.effect_blast_radius,
                &prediction.forecast.expected_value_or_range,
            ] {
                if matches!(
                    forecast,
                    eliot_dreamer_contracts::rival::ForecastAvailability::Claim { .. }
                ) {
                    add(&mut counts.material, 1, "material")?;
                }
            }
        }
    }
    for slot in &declarations.sources {
        if let eliot_dreamer_contracts::rival::RivalSourceSlot::Retained { reference } = slot {
            add(&mut counts.reference, 1, "reference")?;
            count_authorized_reference(reference, counts)?;
        } else {
            add(&mut counts.reference, 1, "reference")?;
        }
    }
    Ok(())
}

fn add_availability_entries<T>(
    availability: &DeclarationAvailability<T>,
    total: &mut usize,
) -> Result<(), RivalModelError> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        add(total, entries.len(), "material")?;
    }
    Ok(())
}

fn add(total: &mut usize, amount: usize, field: &'static str) -> Result<(), RivalModelError> {
    *total = total.checked_add(amount).ok_or(RivalModelError::Bound {
        field,
        maximum: MAX_RIVAL_WORK,
        actual: usize::MAX,
    })?;
    if *total > MAX_RIVAL_WORK {
        return Err(RivalModelError::Bound {
            field,
            maximum: MAX_RIVAL_WORK,
            actual: *total,
        });
    }
    Ok(())
}

fn count_declarations(
    declarations: &RivalDeclarationSet,
    total: &mut usize,
) -> Result<(), RivalModelError> {
    for (field, count) in [
        ("rival.models", declarations.models.len()),
        ("rival.related_models", declarations.related_models.len()),
        ("rival.claims", declarations.claims.len()),
        ("rival.assumptions", declarations.assumptions.len()),
        ("rival.predictions", declarations.predictions.len()),
        ("rival.sources", declarations.sources.len()),
    ] {
        if count > MAX_RIVAL_ITEMS {
            return Err(RivalModelError::Bound {
                field,
                maximum: MAX_RIVAL_ITEMS,
                actual: count,
            });
        }
        bounded_add(total, count, field)?;
    }
    Ok(())
}

fn bounded_add(
    total: &mut usize,
    count: usize,
    field: &'static str,
) -> Result<(), RivalModelError> {
    *total = total.checked_add(count).ok_or(RivalModelError::Bound {
        field,
        maximum: MAX_RIVAL_WORK,
        actual: usize::MAX,
    })?;
    Ok(())
}
