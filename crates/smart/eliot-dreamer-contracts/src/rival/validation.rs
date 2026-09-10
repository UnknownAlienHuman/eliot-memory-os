//! Private bounds and canonical encoding helpers for rival declarations.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::PropositionId;
use serde::Serialize;

use super::model::{
    ClaimDeclarations, DeclarationAvailability, RivalAssumptionSlot, RivalClaimSlot,
    RivalCoverageDeclaration, RivalCoverageReceipt, RivalDeclarationSet, RivalDependency,
    RivalModelSlot, RivalPredictionSlot, RivalSourceSlot,
};
use super::prediction::{ConditionAssumptionRef, ForecastAvailability};
use crate::error::{ContractViolation, check_text, is_hex64_lower};
use crate::grounding::PrecisionPayload;

pub(super) const MAX_RIVAL_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_RIVAL_TEXT_BYTES: usize = 4096;
pub(super) const MAX_RIVAL_ITEMS: usize = 256;
pub(super) const MAX_RIVAL_SET_WORK: usize = 4096;

pub(super) fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    check_text(value, field, MAX_RIVAL_TEXT_BYTES)
}

pub(super) fn artifact(value: &ArtifactId, field: &'static str) -> Result<(), ContractViolation> {
    text(value.as_str(), field)
}

pub(super) fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected a lowercase SHA-256 digest".to_owned(),
        })
    }
}

pub(super) fn sequence(len: usize, field: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_vec_bound(len, MAX_RIVAL_ITEMS, field)
}

pub(super) fn set_sequence(
    len: usize,
    total: &mut usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    sequence(len, field)?;
    set_work(total, len, field)
}

pub(super) fn set_work(
    total: &mut usize,
    amount: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    *total = total
        .checked_add(amount)
        .ok_or(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: crate::error::len_i64(MAX_RIVAL_SET_WORK),
            got: i64::MAX,
        })?;
    if *total > MAX_RIVAL_SET_WORK {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: crate::error::len_i64(MAX_RIVAL_SET_WORK),
            got: crate::error::len_i64(*total),
        });
    }
    Ok(())
}

/// Performs the bounded borrowed serialization pass before canonical allocation.
pub(super) fn preflight<T: Serialize>(value: &T) -> Result<usize, ContractViolation> {
    let mut writer = CountingWriter::new(MAX_RIVAL_WIRE_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|error| ContractViolation::Malformed {
        field: "rival.canonical_preflight",
        reason: format!("bounded serialization failed: {error}"),
    })?;
    Ok(writer.count)
}

pub(super) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ContractViolation> {
    preflight(value)?;
    Ok(crate::digest_hex(&crate::canonical_bytes(value)?))
}

pub(super) fn validate_reference_closure(
    set: &RivalDeclarationSet,
) -> Result<(), ContractViolation> {
    let ClaimIndexes {
        expectations: mut claims,
        slots: claim_slots,
    } = index_claims(set)?;
    let mut assumptions = index_assumptions(set)?;
    let mut predictions = index_predictions(set)?;
    let mut models = index_models(set)?;
    let related = index_related_models(set)?;
    validate_related_against_current(&models, &related)?;
    let mut sources = index_sources(set)?;

    for slot in &set.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        for reference in &declaration.explanations {
            resolve_claim(&mut claims, reference, "rival.model.explanations")?;
        }
        for declaration_set in [
            &declaration.supporting_claims,
            &declaration.counterevidence_claims,
            &declaration.revision_conditions,
            &declaration.invalidation_conditions,
            &declaration.successful_transfers,
            &declaration.failed_transfers,
            &declaration.downstream_effects,
        ] {
            resolve_claim_declarations(&mut claims, declaration_set)?;
        }
        if let super::model::CommonModeDisclosure::Supplied { basis, .. } = &declaration.common_mode
        {
            resolve_claim_declarations(&mut claims, basis)?;
        }
        if let DeclarationAvailability::Supplied { entries } = &declaration.assumptions {
            for reference in entries {
                resolve_assumption(&mut assumptions, reference)?;
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &declaration.prediction_refs {
            for reference in entries {
                resolve_prediction(&mut predictions, reference)?;
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &declaration.dependency_refs {
            for dependency in entries {
                match dependency {
                    RivalDependency::Model { reference } => {
                        resolve_model(reference, &mut models, &related)?;
                    }
                    RivalDependency::Record {
                        record_id,
                        content_digest,
                        source_revision,
                    } => resolve_source(
                        &mut sources,
                        record_id,
                        Some(content_digest),
                        Some(source_revision),
                        "rival.declaration_set.record_reference",
                    )?,
                }
            }
        }
        resolve_model_sources(declaration, &mut sources)?;
        for reference in &declaration.predecessors {
            resolve_model(reference, &mut models, &related)?;
        }
    }

    for slot in &set.predictions {
        let RivalPredictionSlot::Retained { prediction } = slot else {
            continue;
        };
        resolve_claim(&mut claims, &prediction.target, "rival.prediction.target")?;
        for assumption in &prediction.condition_assumptions {
            resolve_assumption(&mut assumptions, assumption)?;
        }
        for forecast in [
            &prediction.forecast.verifier_verdict,
            &prediction.forecast.diagnostic_change,
            &prediction.forecast.effect_blast_radius,
            &prediction.forecast.expected_value_or_range,
        ] {
            if let ForecastAvailability::Claim { reference } = forecast {
                resolve_claim(&mut claims, reference, "rival.prediction.forecast")?;
            }
        }
    }

    for slot in &set.claims {
        let RivalClaimSlot::Retained { claim } = slot else {
            continue;
        };
        resolve_claim_sources(claim, &mut sources)?;
    }
    for slot in &set.sources {
        let RivalSourceSlot::Retained { reference } = slot else {
            continue;
        };
        resolve_authorized_reference_sources(reference, &mut sources)?;
    }

    validate_subclaim_forest(set, &claim_slots)
}

pub(super) fn validate_coverage_reconciliation(
    set: &RivalDeclarationSet,
) -> Result<(), ContractViolation> {
    let model_ids: BTreeSet<_> = set
        .models
        .iter()
        .map(|slot| slot.stable_id().clone())
        .collect();
    let source_ids: BTreeSet<_> = set
        .sources
        .iter()
        .map(|slot| slot.stable_id().clone())
        .collect();
    reconcile_coverage(
        &model_ids,
        &set.model_coverage,
        &set.task_id,
        &set.scope,
        &set.state_fence,
        "rival.declaration_set.model_coverage",
    )?;
    reconcile_coverage(
        &source_ids,
        &set.source_coverage,
        &set.task_id,
        &set.scope,
        &set.state_fence,
        "rival.declaration_set.source_coverage",
    )
}

fn reconcile_coverage(
    table_ids: &BTreeSet<ArtifactId>,
    declaration: &RivalCoverageDeclaration,
    task_id: &TaskId,
    scope: &str,
    fence: &StateFence,
    field: &'static str,
) -> Result<(), ContractViolation> {
    match declaration {
        RivalCoverageDeclaration::Supplied {
            denominator,
            receipt,
        } => {
            if denominator.scope != scope || denominator.fence != *fence {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "coverage denominator scope or fence differs from set".to_owned(),
                });
            }
            if denominator.roles.len() != 1 || denominator.members != *table_ids {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "supplied denominator must have one role and exactly the table IDs"
                        .to_owned(),
                });
            }
            if let RivalCoverageReceipt::Supplied { receipt } = receipt {
                reconcile_complete_receipt(
                    receipt,
                    denominator,
                    table_ids,
                    task_id,
                    scope,
                    fence,
                    field,
                )?;
            }
            Ok(())
        }
        RivalCoverageDeclaration::Unknown { receipt, .. } => {
            if let RivalCoverageReceipt::Supplied { receipt } = receipt {
                reconcile_partial_receipt(receipt, table_ids, task_id, scope, fence, field)?;
            }
            Ok(())
        }
    }
}

fn reconcile_complete_receipt(
    receipt: &eliot_epistemic_contracts::CoverageReceipt,
    denominator: &eliot_epistemic_contracts::CoverageDenominator,
    table_ids: &BTreeSet<ArtifactId>,
    task_id: &TaskId,
    scope: &str,
    fence: &StateFence,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if receipt.denominator != denominator.digest
        || receipt.denominator_size != denominator.members.len() as u64
        || denominator.query.as_ref() != Some(&receipt.query)
        || denominator.frontier.as_ref() != Some(&receipt.frontier)
        || receipt.task_id != *task_id
        || receipt.scope != scope
        || receipt.fence != *fence
    {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "receipt does not bind the complete denominator and set context".to_owned(),
        });
    }
    let role = denominator
        .roles
        .iter()
        .next()
        .ok_or(ContractViolation::MissingField(field))?;
    let mut seen = BTreeSet::new();
    for member in &receipt.members {
        if member.role != *role
            || !table_ids.contains(&member.member)
            || !seen.insert(member.member.clone())
        {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "receipt member is foreign, duplicated, or has the wrong role".to_owned(),
            });
        }
    }
    for omission in &receipt.omissions {
        if !table_ids.contains(&omission.member) || !seen.insert(omission.member.clone()) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "receipt omission is foreign or overlaps a member".to_owned(),
            });
        }
    }
    if seen != *table_ids {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "receipt members and omissions do not cover the table IDs".to_owned(),
        });
    }
    Ok(())
}

fn reconcile_partial_receipt(
    receipt: &eliot_epistemic_contracts::CoverageReceipt,
    table_ids: &BTreeSet<ArtifactId>,
    task_id: &TaskId,
    scope: &str,
    fence: &StateFence,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if receipt.task_id != *task_id || receipt.scope != scope || receipt.fence != *fence {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "receipt context differs from set".to_owned(),
        });
    }
    for member in &receipt.members {
        if !table_ids.contains(&member.member) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "partial receipt member is outside the current table".to_owned(),
            });
        }
    }
    for omission in &receipt.omissions {
        if !table_ids.contains(&omission.member) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "partial receipt omission is outside the current table".to_owned(),
            });
        }
    }
    Ok(())
}

struct ClaimExpectation {
    proposition: Option<PropositionId>,
    digest: Option<String>,
}

struct ClaimIndexes {
    expectations: BTreeMap<String, ClaimExpectation>,
    slots: BTreeMap<String, usize>,
}

fn index_claims(set: &RivalDeclarationSet) -> Result<ClaimIndexes, ContractViolation> {
    let mut expectations = BTreeMap::new();
    let mut slots = BTreeMap::new();
    for (index, slot) in set.claims.iter().enumerate() {
        let (id, proposition, digest) = match slot {
            RivalClaimSlot::Retained { claim } => (
                claim.claim_id.clone(),
                Some(claim.proposition.clone()),
                Some(claim.source_preimage_digest.clone()),
            ),
            RivalClaimSlot::Unavailable {
                claim_id,
                proposition,
                claim_preimage_digest,
                ..
            } => (
                claim_id.clone(),
                proposition.clone(),
                claim_preimage_digest.clone(),
            ),
        };
        if expectations
            .insert(
                id.clone(),
                ClaimExpectation {
                    proposition,
                    digest,
                },
            )
            .is_some()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.claims",
                reason: "duplicate claim identity in closure index".to_owned(),
            });
        }
        slots.insert(id, index);
    }
    Ok(ClaimIndexes {
        expectations,
        slots,
    })
}

struct AssumptionExpectation {
    digest: Option<String>,
}

fn index_assumptions(
    set: &RivalDeclarationSet,
) -> Result<BTreeMap<String, AssumptionExpectation>, ContractViolation> {
    let mut index = BTreeMap::new();
    for slot in &set.assumptions {
        let (id, digest) = match slot {
            RivalAssumptionSlot::Retained { assumption } => (
                assumption.assumption_id.clone(),
                Some(assumption.digest.clone()),
            ),
            RivalAssumptionSlot::Unavailable {
                assumption_id,
                assumption_digest,
                ..
            } => (assumption_id.clone(), assumption_digest.clone()),
        };
        if index.insert(id, AssumptionExpectation { digest }).is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.assumptions",
                reason: "duplicate assumption identity in closure index".to_owned(),
            });
        }
    }
    Ok(index)
}

struct PredictionExpectation {
    digest: Option<String>,
}

fn index_predictions(
    set: &RivalDeclarationSet,
) -> Result<BTreeMap<ArtifactId, PredictionExpectation>, ContractViolation> {
    let mut index = BTreeMap::new();
    for slot in &set.predictions {
        let (id, digest) = match slot {
            RivalPredictionSlot::Retained { prediction } => (
                prediction.prediction_id.clone(),
                Some(prediction.digest.clone()),
            ),
            RivalPredictionSlot::Unavailable {
                prediction_id,
                prediction_digest,
                ..
            } => (prediction_id.clone(), prediction_digest.clone()),
        };
        if index.insert(id, PredictionExpectation { digest }).is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.predictions",
                reason: "duplicate prediction identity in closure index".to_owned(),
            });
        }
    }
    Ok(index)
}

struct ModelExpectation {
    revision: Option<u64>,
    digest: Option<String>,
}

fn index_models(
    set: &RivalDeclarationSet,
) -> Result<BTreeMap<ArtifactId, ModelExpectation>, ContractViolation> {
    let mut index = BTreeMap::new();
    for slot in &set.models {
        let (id, revision, digest) = match slot {
            RivalModelSlot::Retained { declaration } => (
                declaration.model_id.clone(),
                Some(declaration.model_revision),
                Some(declaration.digest.clone()),
            ),
            RivalModelSlot::Unavailable {
                model_id,
                model_revision,
                declaration_digest,
                ..
            } => (
                model_id.clone(),
                *model_revision,
                declaration_digest.clone(),
            ),
        };
        if index
            .insert(id, ModelExpectation { revision, digest })
            .is_some()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.models",
                reason: "duplicate model identity in closure index".to_owned(),
            });
        }
    }
    Ok(index)
}

fn index_related_models(
    set: &RivalDeclarationSet,
) -> Result<BTreeMap<(ArtifactId, u64), String>, ContractViolation> {
    let mut index = BTreeMap::new();
    for related in &set.related_models {
        let key = (
            related.reference.model_id.clone(),
            related.reference.model_revision,
        );
        if let Some(previous) = index.insert(key, related.reference.declaration_digest.clone())
            && previous != related.reference.declaration_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.related_models",
                reason: "related model identity has conflicting declaration digests".to_owned(),
            });
        }
    }
    Ok(index)
}

fn validate_related_against_current(
    current: &BTreeMap<ArtifactId, ModelExpectation>,
    related: &BTreeMap<(ArtifactId, u64), String>,
) -> Result<(), ContractViolation> {
    for ((model_id, revision), digest) in related {
        if let Some(expectation) = current.get(model_id)
            && expectation.revision == Some(*revision)
            && let Some(current_digest) = &expectation.digest
            && current_digest != digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.related_models",
                reason: "related model digest conflicts with current model identity".to_owned(),
            });
        }
    }
    Ok(())
}

struct SourceExpectation {
    content_digest: Option<String>,
    source_revision: Option<String>,
}

fn index_sources(
    set: &RivalDeclarationSet,
) -> Result<BTreeMap<ArtifactId, SourceExpectation>, ContractViolation> {
    let mut index = BTreeMap::new();
    for slot in &set.sources {
        let (handle, content_digest, source_revision) = match slot {
            RivalSourceSlot::Retained { reference } => (
                reference.handle.clone(),
                Some(reference.content_digest.clone()),
                Some(reference.source_revision.clone()),
            ),
            RivalSourceSlot::Unavailable {
                handle,
                content_digest,
                source_revision,
                ..
            } => (
                handle.clone(),
                content_digest.clone(),
                source_revision.clone(),
            ),
        };
        if index
            .insert(
                handle,
                SourceExpectation {
                    content_digest,
                    source_revision,
                },
            )
            .is_some()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.sources",
                reason: "duplicate source handle in closure index".to_owned(),
            });
        }
    }
    Ok(index)
}

fn resolve_claim(
    index: &mut BTreeMap<String, ClaimExpectation>,
    reference: &super::model::MaterialClaimRef,
    field: &'static str,
) -> Result<(), ContractViolation> {
    let Some(expectation) = index.get_mut(&reference.claim_id) else {
        return missing_reference(field, &reference.claim_id);
    };
    merge_known(
        &mut expectation.proposition,
        Some(&reference.proposition),
        field,
    )?;
    merge_known(
        &mut expectation.digest,
        Some(&reference.claim_preimage_digest),
        field,
    )
}

fn resolve_claim_declarations(
    index: &mut BTreeMap<String, ClaimExpectation>,
    declarations: &ClaimDeclarations,
) -> Result<(), ContractViolation> {
    if let ClaimDeclarations::Supplied { claims } = declarations {
        for reference in claims {
            resolve_claim(index, reference, "rival.declaration_set.claim_reference")?;
        }
    }
    Ok(())
}

fn resolve_assumption(
    index: &mut BTreeMap<String, AssumptionExpectation>,
    reference: &ConditionAssumptionRef,
) -> Result<(), ContractViolation> {
    let Some(expectation) = index.get_mut(&reference.assumption_id) else {
        return missing_reference(
            "rival.declaration_set.assumption_reference",
            &reference.assumption_id,
        );
    };
    merge_known(
        &mut expectation.digest,
        Some(&reference.assumption_digest),
        "rival.declaration_set.assumption_reference",
    )
}

fn resolve_prediction(
    index: &mut BTreeMap<ArtifactId, PredictionExpectation>,
    reference: &super::model::RivalPredictionRef,
) -> Result<(), ContractViolation> {
    let Some(expectation) = index.get_mut(&reference.prediction_id) else {
        return missing_reference(
            "rival.declaration_set.prediction_reference",
            reference.prediction_id.as_str(),
        );
    };
    merge_known(
        &mut expectation.digest,
        Some(&reference.prediction_digest),
        "rival.declaration_set.prediction_reference",
    )
}

fn resolve_model(
    reference: &super::model::RivalModelRef,
    current: &mut BTreeMap<ArtifactId, ModelExpectation>,
    related: &BTreeMap<(ArtifactId, u64), String>,
) -> Result<(), ContractViolation> {
    if let Some(digest) = related.get(&(reference.model_id.clone(), reference.model_revision)) {
        if digest == &reference.declaration_digest {
            return Ok(());
        }
        return Err(ContractViolation::BindingMismatch {
            field: "rival.declaration_set.model_reference",
            reason: "related model reference digest conflicts with retained related identity"
                .to_owned(),
        });
    }
    let Some(expectation) = current.get_mut(&reference.model_id) else {
        return missing_reference(
            "rival.declaration_set.model_reference",
            reference.model_id.as_str(),
        );
    };
    if let Some(revision) = expectation.revision
        && revision != reference.model_revision
    {
        return missing_reference(
            "rival.declaration_set.model_reference",
            reference.model_id.as_str(),
        );
    }
    if let Some(digest) = &expectation.digest
        && digest != &reference.declaration_digest
    {
        return Err(ContractViolation::BindingMismatch {
            field: "rival.declaration_set.model_reference",
            reason: "model reference digest conflicts with retained current identity".to_owned(),
        });
    }
    if expectation.revision.is_none() {
        expectation.revision = Some(reference.model_revision);
    }
    if expectation.digest.is_none() {
        expectation.digest = Some(reference.declaration_digest.clone());
    }
    Ok(())
}

fn resolve_source(
    index: &mut BTreeMap<ArtifactId, SourceExpectation>,
    handle: &ArtifactId,
    content_digest: Option<&str>,
    source_revision: Option<&str>,
    field: &'static str,
) -> Result<(), ContractViolation> {
    let Some(expectation) = index.get_mut(handle) else {
        return missing_reference(field, handle.as_str());
    };
    merge_source_text(&mut expectation.content_digest, content_digest, field)?;
    merge_source_text(&mut expectation.source_revision, source_revision, field)?;
    Ok(())
}

fn merge_source_text(
    known: &mut Option<String>,
    incoming: Option<&str>,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if let Some(incoming) = incoming {
        if let Some(existing) = known
            && existing != incoming
        {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "source handle has conflicting known content or revision".to_owned(),
            });
        }
        if known.is_none() {
            *known = Some(incoming.to_owned());
        }
    }
    Ok(())
}

fn resolve_model_sources(
    declaration: &super::model::RivalModelDeclaration,
    sources: &mut BTreeMap<ArtifactId, SourceExpectation>,
) -> Result<(), ContractViolation> {
    if let DeclarationAvailability::Supplied { entries } = &declaration.support_observations {
        for support in entries {
            for handle in &support.handles {
                resolve_source(sources, handle, None, None, "rival.model.support.handles")?;
            }
        }
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.causal_readings {
        for causal in entries {
            for handle in &causal.evidence_refs {
                resolve_source(
                    sources,
                    handle,
                    None,
                    None,
                    "rival.model.causal.evidence_refs",
                )?;
            }
        }
    }
    if let DeclarationAvailability::Supplied { entries } = &declaration.conflicts {
        for conflict in entries {
            for handle in conflict.evidence_refs.iter().chain(&conflict.defeated_refs) {
                resolve_source(
                    sources,
                    handle,
                    None,
                    None,
                    "rival.model.conflict.evidence_refs",
                )?;
            }
            for position in &conflict.positions {
                for handle in &position.counters {
                    resolve_source(sources, handle, None, None, "rival.model.conflict.counters")?;
                }
            }
        }
    }
    if let super::model::SuppliedLineage::Retained { closure } = &declaration.lineage {
        resolve_provenance_sources(closure, sources)?;
    }
    Ok(())
}

fn resolve_claim_sources(
    claim: &crate::grounding::MaterialClaim,
    sources: &mut BTreeMap<ArtifactId, SourceExpectation>,
) -> Result<(), ContractViolation> {
    for handle in claim
        .proposed_support
        .iter()
        .chain(&claim.proposed_counterevidence)
    {
        resolve_source(sources, handle, None, None, "rival.claim.source_handles")?;
    }
    resolve_precision_sources(&claim.payload, sources)
}

fn resolve_precision_sources(
    payload: &PrecisionPayload,
    sources: &mut BTreeMap<ArtifactId, SourceExpectation>,
) -> Result<(), ContractViolation> {
    match payload {
        PrecisionPayload::QuoteAttribution { source, .. } => {
            resolve_source(sources, source, None, None, "rival.claim.quote.source")
        }
        PrecisionPayload::Causal { causal } => {
            for handle in &causal.evidence_refs {
                resolve_source(
                    sources,
                    handle,
                    None,
                    None,
                    "rival.claim.causal.evidence_refs",
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn resolve_authorized_reference_sources(
    reference: &crate::grounding::AuthorizedReference,
    sources: &mut BTreeMap<ArtifactId, SourceExpectation>,
) -> Result<(), ContractViolation> {
    if let Some(support) = &reference.support {
        for handle in &support.handles {
            resolve_source(sources, handle, None, None, "rival.source.support.handles")?;
        }
    }
    if let Some(provenance) = &reference.provenance {
        resolve_provenance_sources(provenance, sources)?;
    }
    for assertion in &reference.assertions {
        if let Some(support) = &assertion.support {
            for handle in &support.handles {
                resolve_source(
                    sources,
                    handle,
                    None,
                    None,
                    "rival.source.assertion.support.handles",
                )?;
            }
        }
        resolve_precision_sources(&assertion.precision, sources)?;
    }
    Ok(())
}

fn resolve_provenance_sources(
    closure: &eliot_epistemic_contracts::ProvenanceClosure,
    sources: &mut BTreeMap<ArtifactId, SourceExpectation>,
) -> Result<(), ContractViolation> {
    for handle in &closure.records {
        resolve_source(sources, handle, None, None, "rival.provenance.records")?;
    }
    for (handle, content_digest) in &closure.record_origin {
        resolve_source(
            sources,
            handle,
            Some(content_digest),
            None,
            "rival.provenance.record_origin",
        )?;
        if let Some(lineage) = closure
            .lineage
            .iter()
            .find(|entry| entry.content_digest == *content_digest)
        {
            resolve_source(
                sources,
                handle,
                None,
                Some(lineage.revision.as_str()),
                "rival.provenance.record_origin",
            )?;
        }
    }
    Ok(())
}

fn merge_known<T: Clone + PartialEq>(
    known: &mut Option<T>,
    incoming: Option<&T>,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if let Some(incoming) = incoming {
        if let Some(existing) = known
            && existing != incoming
        {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "references carry conflicting known identity metadata".to_owned(),
            });
        }
        if known.is_none() {
            // The expectation is local closure state; this does not mutate supplied payload data.
            *known = Some(incoming.clone());
        }
    }
    Ok(())
}

fn missing_reference(field: &'static str, identity: &str) -> Result<(), ContractViolation> {
    Err(ContractViolation::BindingMismatch {
        field,
        reason: format!(
            "reference does not resolve a retained or explicit unavailable slot: {identity}"
        ),
    })
}

fn validate_subclaim_forest(
    set: &RivalDeclarationSet,
    slots: &BTreeMap<String, usize>,
) -> Result<(), ContractViolation> {
    let mut parent = BTreeMap::new();
    for (index, slot) in set.claims.iter().enumerate() {
        let RivalClaimSlot::Retained { claim } = slot else {
            continue;
        };
        for child in &claim.subclaim_ids {
            let Some(child_index) = slots.get(child) else {
                return missing_reference("rival.declaration_set.subclaim_ids", child);
            };
            if *child_index == index {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.subclaim_ids",
                    reason: "subclaim self-edge is not a forest".to_owned(),
                });
            }
            if parent.insert(child.clone(), index).is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.subclaim_ids",
                    reason: "subclaim child has multiple known parents".to_owned(),
                });
            }
        }
    }
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for (id, index) in slots {
        if done.contains(id) {
            continue;
        }
        let mut stack = vec![(id.clone(), *index, false)];
        while let Some((current, current_index, exiting)) = stack.pop() {
            if exiting {
                active.remove(&current);
                done.insert(current);
                continue;
            }
            if done.contains(&current) {
                continue;
            }
            if !active.insert(current.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.subclaim_ids",
                    reason: "subclaim cycle detected".to_owned(),
                });
            }
            stack.push((current, current_index, true));
            if let RivalClaimSlot::Retained { claim } = &set.claims[current_index] {
                for child in claim.subclaim_ids.iter().rev() {
                    let child_index =
                        *slots.get(child).ok_or(ContractViolation::BindingMismatch {
                            field: "rival.declaration_set.subclaim_ids",
                            reason: "subclaim child is not represented by a slot".to_owned(),
                        })?;
                    if active.contains(child) {
                        return Err(ContractViolation::BindingMismatch {
                            field: "rival.declaration_set.subclaim_ids",
                            reason: "subclaim cycle detected".to_owned(),
                        });
                    }
                    stack.push((child.clone(), child_index, false));
                }
            }
        }
    }
    Ok(())
}

struct CountingWriter {
    count: usize,
    ceiling: usize,
}

impl CountingWriter {
    const fn new(ceiling: usize) -> Self {
        Self { count: 0, ceiling }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("rival byte counter overflow"))?;
        if self.count > self.ceiling {
            return Err(io::Error::other("rival declaration exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
