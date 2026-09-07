//! Pure, deterministic Context membership admission.
//!
//! This prototype consumes the complete A-15 input closure. It only admits
//! already validated whole units or exact handles and accounts for qualified
//! UTF-8 contributions. Providers, renderers, tokenizers, stores and runtime
//! effects remain outside this crate.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionMeasuredCost, AdmissionRecord, AdmissionResult,
    AdmittedAtom, AdmittedContextSet, AtomAvailability, ContextEconomyReceipt, ContextError,
    ContextOutcome, DecisionContextIncomplete, EconomyAllocations, MeasurementRef, OmissionReason,
    OmissionRecord, RepresentationKind,
};
use eliot_receipts::ProofCeiling;

/// Admit one immutable candidate set under one exact recipe and route profile.
///
/// Selection is floor-first and deterministic. Every candidate receives one
/// disposition, and optional omissions retain the supplied reversible handle
/// or non-recoverable reason. No source is fetched and no representation is
/// generated here.
#[allow(clippy::too_many_lines)]
pub fn admit_context(input: &AdmissionInput) -> Result<AdmissionResult, ContextError> {
    input.validate_additive_measurements()?;
    validate_selection_contract(input)?;
    let input_digest = input.canonical_digest()?;
    let profile_digest = input.measurement_profile.canonical_digest()?;
    let candidates: BTreeMap<_, _> = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| (candidate.atom_id.clone(), candidate))
        .collect();
    let priorities: BTreeMap<_, _> = input
        .priority
        .priorities
        .iter()
        .map(|priority| (priority.atom_id.clone(), priority))
        .collect();
    let supplied: BTreeMap<_, _> = input
        .supplied_omissions
        .iter()
        .map(|binding| (binding.atom_id.clone(), binding))
        .collect();

    // Capacity validation is deliberately before any candidate selection.
    input.recipe.capacity.validate()?;
    let floor_ids = floor_closure(input, &candidates)?;
    for candidate in candidates.values() {
        if !floor_ids.contains(&candidate.atom_id)
            && (candidate.protected
                || candidate.loss_policy == eliot_context_contracts::LossPolicy::NonDroppable)
        {
            return Err(ContextError::MissingFloor);
        }
        validate_representation(
            input,
            candidate,
            &supplied,
            floor_ids.contains(&candidate.atom_id),
        )?;
    }
    if let Some(incomplete) = floor_gap(input, &candidates, &floor_ids)? {
        return incomplete_result(input, input_digest, profile_digest, &incomplete);
    }
    let mut admitted: BTreeMap<_, _> = BTreeMap::new();
    let mut required_cost = 0_u64;
    for atom_id in &floor_ids {
        let candidate = candidates.get(atom_id).ok_or(ContextError::MissingFloor)?;
        let cost = exact_cost(input, candidate)?;
        required_cost = if let Some(total) = required_cost.checked_add(cost) {
            total
        } else {
            let mut incomplete =
                DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
            incomplete.oversized.extend(floor_ids.iter().cloned());
            incomplete
                .measurements
                .extend(floor_measurement_ids(input, &floor_ids));
            incomplete.reopening_requirements.push(
                "reopen with a qualified route envelope that can hold the exact Safety Floor"
                    .to_owned(),
            );
            return incomplete_result(input, input_digest, profile_digest, &incomplete);
        };
        let disposition = if candidate.representation.kind() == RepresentationKind::Handle {
            AdmissionDisposition::HandleOnly
        } else {
            AdmissionDisposition::Include
        };
        admitted.insert(
            atom_id.clone(),
            AdmittedAtom {
                candidate: (*candidate).clone(),
                disposition,
                rule_evidence: input.rule.rule_id.clone(),
            },
        );
    }
    let fixed = fixed_cost(input)?;
    let Some(floor_total) = fixed.checked_add(required_cost) else {
        let mut incomplete =
            DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
        incomplete.oversized.extend(floor_ids.iter().cloned());
        incomplete
            .measurements
            .extend(floor_measurement_ids(input, &floor_ids));
        incomplete.reopening_requirements.push(
            "reopen with a qualified route envelope that can hold the exact Safety Floor"
                .to_owned(),
        );
        return incomplete_result(input, input_digest, profile_digest, &incomplete);
    };
    if floor_total > input.recipe.capacity.route_capacity {
        let mut incomplete =
            DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
        incomplete.oversized.extend(floor_ids.iter().cloned());
        incomplete
            .measurements
            .extend(floor_measurement_ids(input, &floor_ids));
        incomplete.reopening_requirements.push(
            "reopen with a qualified route envelope that can hold the exact Safety Floor"
                .to_owned(),
        );
        incomplete.validate()?;
        return incomplete_result(input, input_digest, profile_digest, &incomplete);
    }

    let mut optional_cost = 0_u64;
    let mut failure_causes: BTreeMap<eliot_contracts::ArtifactId, (OmissionReason, String)> =
        BTreeMap::new();
    let mut optional_ids: Vec<_> = candidates
        .keys()
        .filter(|id| !floor_ids.contains(*id))
        .cloned()
        .collect();
    optional_ids.sort_by(|left, right| {
        let Some(l) = priorities.get(left) else {
            return std::cmp::Ordering::Equal;
        };
        let Some(r) = priorities.get(right) else {
            return std::cmp::Ordering::Equal;
        };
        (l.class, l.ordinal, left).cmp(&(r.class, r.ordinal, right))
    });
    let available = input
        .recipe
        .capacity
        .route_capacity
        .checked_sub(fixed)
        .and_then(|value| value.checked_sub(required_cost))
        .ok_or(ContextError::Overflow)?;
    for atom_id in optional_ids {
        if admitted.contains_key(&atom_id) {
            continue;
        }
        let candidate = candidates
            .get(&atom_id)
            .ok_or(ContextError::DenominatorMismatch)?;
        let closure = optional_closure(&atom_id, &floor_ids, &candidates)?;
        let closure_candidates = closure
            .iter()
            .filter_map(|id| candidates.get(id).copied())
            .filter(|candidate| !admitted.contains_key(&candidate.atom_id))
            .collect::<Vec<_>>();
        let closure_missing = closure.iter().any(|id| !candidates.contains_key(id));
        let cost = match candidate.availability {
            AtomAvailability::PresentCurrent => match exact_cost(input, candidate) {
                Ok(value) => Some(value),
                Err(ContextError::UnknownMeasurement) => None,
                Err(error) => return Err(error),
            },
            _ => None,
        };
        let closure_cost = closure_candidates.iter().try_fold(0_u64, |total, item| {
            exact_cost(input, item)
                .and_then(|value| total.checked_add(value).ok_or(ContextError::Overflow))
        });
        let closure_current = closure_candidates
            .iter()
            .all(|item| item.availability == AtomAvailability::PresentCurrent);
        let fits = !closure_missing
            && closure_current
            && candidate.availability == AtomAvailability::PresentCurrent
            && cost.is_some()
            && closure_cost.as_ref().is_ok_and(|value| {
                optional_cost
                    .checked_add(*value)
                    .is_some_and(|total| total <= available)
            });
        if fits {
            let value = closure_cost?;
            for item in closure_candidates {
                validate_representation(input, item, &supplied, false)?;
                let disposition = if item.representation.kind() == RepresentationKind::Handle {
                    AdmissionDisposition::HandleOnly
                } else {
                    AdmissionDisposition::Include
                };
                admitted.insert(
                    item.atom_id.clone(),
                    AdmittedAtom {
                        candidate: item.clone(),
                        disposition,
                        rule_evidence: input.rule.rule_id.clone(),
                    },
                );
            }
            optional_cost = optional_cost
                .checked_add(value)
                .ok_or(ContextError::Overflow)?;
        } else {
            let failure = optional_failure_cause(
                input,
                &closure,
                &candidates,
                &closure_candidates,
                closure_missing,
            )?;
            failure_causes.insert(
                atom_id,
                failure.unwrap_or((
                    OmissionReason::Capacity,
                    "optional allocation exceeds remaining capacity".to_owned(),
                )),
            );
        }
    }
    let mut omissions = Vec::new();
    for (atom_id, candidate) in &candidates {
        if floor_ids.contains(atom_id) || admitted.contains_key(atom_id) {
            continue;
        }
        let item_cost = exact_cost(input, candidate).ok();
        let failure = failure_causes.get(atom_id).cloned();
        omissions.push(make_omission(
            input, candidate, &supplied, item_cost, failure,
        )?);
    }
    omissions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));

    let records: Vec<_> = admitted.into_values().collect();
    let admissions = records
        .iter()
        .map(|record| AdmissionRecord {
            atom_id: record.candidate.atom_id.clone(),
            provider_role: record.candidate.provider_role.clone(),
            disposition: record.disposition,
            rule_evidence: record.rule_evidence.clone(),
        })
        .collect::<Vec<_>>();
    let admitted_ids = records
        .iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect::<Vec<_>>();
    let requested = candidates.keys().cloned().collect::<Vec<_>>();
    let displaced = omissions
        .iter()
        .map(|omission| omission.atom_id.clone())
        .collect::<Vec<_>>();
    let allocations = EconomyAllocations {
        fixed_overhead: input.recipe.capacity.fixed_overhead,
        output_reserve: input.recipe.capacity.output_reserve,
        review_reserve: input.recipe.capacity.review_reserve,
        admitted_required: required_cost,
        admitted_optional: optional_cost,
        remaining_headroom: input
            .recipe
            .capacity
            .route_capacity
            .checked_sub(fixed)
            .and_then(|value| value.checked_sub(required_cost))
            .and_then(|value| value.checked_sub(optional_cost))
            .ok_or(ContextError::Overflow)?,
        route_capacity: input.recipe.capacity.route_capacity,
    };
    let economy = ContextEconomyReceipt {
        binding: input.binding.clone(),
        decision_id: input.binding.decision_id.clone(),
        measurement: MeasurementRef {
            digest: "0".repeat(64),
            serializer: input.measurement_profile.serializer_id.clone(),
        },
        requested,
        admitted: admitted_ids,
        displaced,
        omissions: omissions.clone(),
        applied_rule: input.rule.rule_id.clone(),
        allocations,
        receipt_digest: "0".repeat(64),
    };
    let mut admitted_set = AdmittedContextSet {
        binding: input.binding.clone(),
        records,
        admissions: admissions.clone(),
        floor: input.floor.floor.clone(),
        economy,
    };
    let selection_digest = admitted_set.canonical_payload_digest()?;
    admitted_set
        .economy
        .measurement
        .digest
        .clone_from(&selection_digest);
    let mut economy = admitted_set.economy.clone();
    let mut unsigned_economy = economy.clone();
    unsigned_economy.receipt_digest = "0".repeat(64);
    economy.receipt_digest = eliot_context_contracts::canonical_digest(&unsigned_economy)?;
    admitted_set
        .economy
        .receipt_digest
        .clone_from(&economy.receipt_digest);
    admitted_set.validate()?;
    let evidence = eliot_context_contracts::AdmissionDecisionEvidence {
        binding: input.binding.clone(),
        decisions: all_decisions(input, &admitted_set, &omissions),
        omissions: omissions.clone(),
        supplied_omissions: omissions
            .iter()
            .filter_map(|omission| supplied.get(&omission.atom_id).copied().cloned())
            .collect(),
        incomplete: None,
        economy: Some(admitted_set.economy.clone()),
        proof_ceiling: proof_ceiling(input),
    };
    let mut result = AdmissionResult {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: input.binding.clone(),
        input_digest,
        recipe_digest: input.recipe.recipe_sha256.clone(),
        profile_digest,
        floor_id: input.floor.floor_id.clone(),
        outcome: ContextOutcome::Complete(admitted_set),
        evidence,
        selection_digest,
        result_digest: "0".repeat(64),
    };
    result.result_digest = eliot_context_contracts::canonical_digest(&result)?;
    result.validate_for(input)?;
    Ok(result)
}

fn floor_closure(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
) -> Result<BTreeSet<eliot_contracts::ArtifactId>, ContextError> {
    let mut queue = VecDeque::new();
    queue.extend(input.floor.floor.mandatory_atoms.iter().cloned());
    queue.extend(
        input
            .floor
            .floor
            .interpretation_dependencies
            .iter()
            .cloned(),
    );
    queue.extend(
        input
            .floor
            .floor
            .members
            .iter()
            .flat_map(|member| member.required_dependencies.iter().cloned()),
    );
    let mut visited = BTreeSet::new();
    while let Some(atom_id) = queue.pop_front() {
        if !visited.insert(atom_id.clone()) {
            continue;
        }
        if let Some(candidate) = candidates.get(&atom_id) {
            queue.extend(candidate.dependencies.iter().cloned());
        }
        if visited.len() > 4096 {
            return Err(ContextError::Bounds {
                field: "floor.closure",
            });
        }
    }
    Ok(visited)
}

fn validate_selection_contract(input: &AdmissionInput) -> Result<(), ContextError> {
    let recipe_slots: BTreeSet<_> = input.recipe.denominator.requested.iter().collect();
    let candidate_slots: BTreeSet<_> = input.candidates.denominator.requested.iter().collect();
    if recipe_slots != candidate_slots {
        return Err(ContextError::DenominatorMismatch);
    }
    let recipe_roles: BTreeSet<_> = input.recipe.mandatory_roles.iter().collect();
    let floor_roles: BTreeSet<_> = input.floor.floor.mandatory_roles.iter().collect();
    if recipe_roles != floor_roles {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(())
}

fn floor_gap(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
) -> Result<Option<DecisionContextIncomplete>, ContextError> {
    let mut gap = DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
    for atom_id in floor_ids {
        let expected = input
            .floor
            .floor
            .members
            .iter()
            .find(|member| member.atom_id == *atom_id);
        let Some(candidate) = candidates.get(atom_id) else {
            gap.missing.push(atom_id.clone());
            continue;
        };
        let state = expected.map_or(candidate.availability, |member| member.availability);
        match state {
            AtomAvailability::PresentCurrent => {
                if candidate.availability != AtomAvailability::PresentCurrent {
                    gap.stale.push(atom_id.clone());
                } else if let Err(error) = exact_cost(input, candidate) {
                    if error != ContextError::UnknownMeasurement {
                        return Err(error);
                    }
                    let measurement = input
                        .measurement(&candidate.atom_id, candidate.representation.kind())
                        .ok_or(ContextError::DenominatorMismatch)?;
                    match measurement.cost {
                        AdmissionMeasuredCost::Unavailable => gap.unavailable.push(atom_id.clone()),
                        AdmissionMeasuredCost::Unknown => gap.unknown.push(atom_id.clone()),
                        _ => return Err(ContextError::UnknownMeasurement),
                    }
                    gap.measurements.push(measurement.measurement_id.clone());
                    gap.reopening_requirements.push(format!(
                        "reopen measurement {} for exact UTF-8 contribution",
                        measurement.measurement_id
                    ));
                }
            }
            AtomAvailability::Missing => gap.missing.push(atom_id.clone()),
            AtomAvailability::Stale => gap.stale.push(atom_id.clone()),
            AtomAvailability::Blocked => gap.blocked.push(atom_id.clone()),
            AtomAvailability::Unavailable => gap.unavailable.push(atom_id.clone()),
            AtomAvailability::Omitted => gap.omitted.push(atom_id.clone()),
            AtomAvailability::Exhausted => gap.exhausted.push(atom_id.clone()),
            AtomAvailability::Unknown => gap.unknown.push(atom_id.clone()),
            AtomAvailability::KnownEmpty => gap.known_empty.push(atom_id.clone()),
            AtomAvailability::Partial => gap.partial.push(atom_id.clone()),
        }
        if state != AtomAvailability::PresentCurrent {
            if let Some(measurement) =
                input.measurement(&candidate.atom_id, candidate.representation.kind())
            {
                gap.measurements.push(measurement.measurement_id.clone());
            }
            gap.reopening_requirements.push(format!(
                "reopen mandatory atom {atom_id} after its floor gap is resolved"
            ));
        }
    }
    for disposition in &input.floor.floor.providers.dispositions {
        if disposition.state != AtomAvailability::PresentCurrent {
            gap.provider_gaps
                .push(eliot_context_contracts::ProviderRoleGap {
                    slot: disposition.slot.clone(),
                    state: disposition.state,
                });
        }
    }
    for values in [
        &mut gap.missing,
        &mut gap.stale,
        &mut gap.blocked,
        &mut gap.unavailable,
        &mut gap.omitted,
        &mut gap.exhausted,
        &mut gap.unknown,
        &mut gap.known_empty,
        &mut gap.partial,
    ] {
        values.sort();
        values.dedup();
    }
    gap.provider_gaps.sort_by(|a, b| a.slot.cmp(&b.slot));
    gap.provider_gaps.dedup_by(|a, b| a.slot == b.slot);
    gap.measurements.sort();
    gap.measurements.dedup();
    if gap.missing.is_empty()
        && gap.stale.is_empty()
        && gap.blocked.is_empty()
        && gap.unavailable.is_empty()
        && gap.omitted.is_empty()
        && gap.exhausted.is_empty()
        && gap.unknown.is_empty()
        && gap.known_empty.is_empty()
        && gap.partial.is_empty()
        && gap.provider_gaps.is_empty()
    {
        Ok(None)
    } else {
        gap.validate()?;
        Ok(Some(gap))
    }
}

fn optional_closure(
    root: &eliot_contracts::ArtifactId,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
) -> Result<BTreeSet<eliot_contracts::ArtifactId>, ContextError> {
    let mut queue = VecDeque::from([root.clone()]);
    let mut closure = BTreeSet::new();
    while let Some(atom_id) = queue.pop_front() {
        if floor_ids.contains(&atom_id) || !closure.insert(atom_id.clone()) {
            continue;
        }
        if let Some(candidate) = candidates.get(&atom_id) {
            queue.extend(candidate.dependencies.iter().cloned());
        }
        if closure.len() > 4096 {
            return Err(ContextError::Bounds {
                field: "optional.closure",
            });
        }
    }
    Ok(closure)
}

fn floor_measurement_ids(
    input: &AdmissionInput,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
) -> Vec<eliot_contracts::ArtifactId> {
    let mut ids = input
        .measurements
        .iter()
        .filter(|measurement| floor_ids.contains(&measurement.atom_id))
        .map(|measurement| measurement.measurement_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn fixed_cost(input: &AdmissionInput) -> Result<u64, ContextError> {
    input
        .recipe
        .capacity
        .fixed_overhead
        .checked_add(input.recipe.capacity.output_reserve)
        .and_then(|value| value.checked_add(input.recipe.capacity.review_reserve))
        .ok_or(ContextError::Overflow)
}

fn exact_cost(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
) -> Result<u64, ContextError> {
    let measurement = input
        .measurement(&candidate.atom_id, candidate.representation.kind())
        .ok_or(ContextError::DenominatorMismatch)?;
    match measurement.cost {
        AdmissionMeasuredCost::ExactUtf8Bytes { value } => Ok(value),
        AdmissionMeasuredCost::Unknown | AdmissionMeasuredCost::Unavailable => {
            Err(ContextError::UnknownMeasurement)
        }
        AdmissionMeasuredCost::ConservativeStu { .. }
        | AdmissionMeasuredCost::ExactTokenizer { .. } => Err(ContextError::UnknownMeasurement),
    }
}

fn optional_failure_cause(
    input: &AdmissionInput,
    closure: &BTreeSet<eliot_contracts::ArtifactId>,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    closure_candidates: &[&eliot_context_contracts::ContextCandidate],
    closure_missing: bool,
) -> Result<Option<(OmissionReason, String)>, ContextError> {
    if closure_missing {
        let missing = closure
            .iter()
            .find(|atom_id| !candidates.contains_key(*atom_id))
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_owned());
        return Ok(Some((
            OmissionReason::Blocked,
            format!("required dependency closure is missing atom {missing}"),
        )));
    }
    for candidate in closure_candidates {
        let cause = match candidate.availability {
            AtomAvailability::PresentCurrent => match exact_cost(input, candidate) {
                Ok(_) => None,
                Err(ContextError::UnknownMeasurement) => {
                    let measurement = input
                        .measurement(&candidate.atom_id, candidate.representation.kind())
                        .ok_or(ContextError::DenominatorMismatch)?;
                    Some(match measurement.cost {
                        AdmissionMeasuredCost::Unavailable => (
                            OmissionReason::MeasurementUnavailable,
                            format!("measurement {} is unavailable", measurement.measurement_id),
                        ),
                        AdmissionMeasuredCost::Unknown => (
                            OmissionReason::UnknownMeasurement,
                            format!(
                                "measurement {} has unknown exact UTF-8 contribution",
                                measurement.measurement_id
                            ),
                        ),
                        _ => return Err(ContextError::UnknownMeasurement),
                    })
                }
                Err(error) => return Err(error),
            },
            AtomAvailability::Stale => Some((
                OmissionReason::Stale,
                format!("candidate {} is stale", candidate.atom_id),
            )),
            AtomAvailability::Blocked => Some((
                OmissionReason::Blocked,
                format!("candidate {} is blocked", candidate.atom_id),
            )),
            AtomAvailability::Unavailable
            | AtomAvailability::Missing
            | AtomAvailability::KnownEmpty
            | AtomAvailability::Partial
            | AtomAvailability::Exhausted => Some((
                OmissionReason::Blocked,
                format!(
                    "required dependency {} is {:?}",
                    candidate.atom_id, candidate.availability
                ),
            )),
            AtomAvailability::Unknown => Some((
                OmissionReason::UnknownMeasurement,
                format!("candidate {} state is unknown", candidate.atom_id),
            )),
            AtomAvailability::Omitted => Some((
                OmissionReason::Policy,
                format!(
                    "candidate {} was already omitted by policy",
                    candidate.atom_id
                ),
            )),
        };
        if cause.is_some() {
            return Ok(cause);
        }
    }
    Ok(None)
}

fn validate_representation(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    required: bool,
) -> Result<(), ContextError> {
    let Some(policy) = input
        .recipe
        .role_policies
        .iter()
        .find(|policy| policy.role == candidate.provider_role.role)
    else {
        return Err(ContextError::WholeUnitRequired);
    };
    if !policy
        .allowed_representations
        .contains(&candidate.representation.kind())
    {
        return Err(ContextError::WholeUnitRequired);
    }
    if matches!(
        candidate.representation.kind(),
        RepresentationKind::Extractive | RepresentationKind::Summary
    ) {
        return Err(ContextError::WholeUnitRequired);
    }
    if let eliot_context_contracts::AtomRepresentation::Handle { handle } =
        &candidate.representation
    {
        let Some(binding) = supplied.get(&candidate.atom_id) else {
            if required {
                return Err(ContextError::OmissionHandleInvalid);
            }
            return Ok(());
        };
        let Some(expansion) = &binding.expansion else {
            return Err(ContextError::OmissionHandleInvalid);
        };
        if expansion.handle_id != *handle
            || expansion.context != candidate.binding
            || expansion.atom_id != candidate.atom_id
            || expansion.source_id.as_str() != candidate.source.source_id.as_str()
            || expansion.source_revision != candidate.source.revision
            || expansion.decision != input.recipe.decision
            || expansion.provider_role != candidate.provider_role
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
    }
    Ok(())
}

fn make_omission(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    cost: Option<u64>,
    cause: Option<(OmissionReason, String)>,
) -> Result<OmissionRecord, ContextError> {
    let binding = supplied
        .get(&candidate.atom_id)
        .ok_or(ContextError::OmissionHandleInvalid)?;
    let (reason, constraint) = cause.unwrap_or_else(|| match candidate.availability {
        AtomAvailability::Stale => (OmissionReason::Stale, "candidate is stale".to_owned()),
        AtomAvailability::Blocked => (OmissionReason::Blocked, "candidate is blocked".to_owned()),
        AtomAvailability::Unavailable => (
            OmissionReason::Unavailable,
            "provider unavailable".to_owned(),
        ),
        AtomAvailability::Missing => (
            OmissionReason::Unavailable,
            "candidate is missing".to_owned(),
        ),
        AtomAvailability::Unknown => (
            OmissionReason::UnknownMeasurement,
            "candidate state is unknown".to_owned(),
        ),
        AtomAvailability::KnownEmpty => (
            OmissionReason::Unavailable,
            "provider has authoritative empty coverage".to_owned(),
        ),
        AtomAvailability::Partial => (
            OmissionReason::Unavailable,
            "provider coverage is partial".to_owned(),
        ),
        AtomAvailability::Omitted => (
            OmissionReason::Policy,
            "candidate was already omitted by policy".to_owned(),
        ),
        AtomAvailability::Exhausted => (
            OmissionReason::Unavailable,
            "provider source is exhausted".to_owned(),
        ),
        AtomAvailability::PresentCurrent if cost.is_none() => {
            let unavailable = input
                .measurement(&candidate.atom_id, candidate.representation.kind())
                .is_some_and(|measurement| {
                    matches!(measurement.cost, AdmissionMeasuredCost::Unavailable)
                });
            if unavailable {
                (
                    OmissionReason::MeasurementUnavailable,
                    "measurement owner could not provide an exact contribution".to_owned(),
                )
            } else {
                (
                    OmissionReason::UnknownMeasurement,
                    "exact UTF-8 contribution is unknown".to_owned(),
                )
            }
        }
        AtomAvailability::PresentCurrent => (
            OmissionReason::Capacity,
            "optional allocation exceeds remaining capacity".to_owned(),
        ),
    });
    let task_revision = input
        .binding
        .state_fence
        .task_revision
        .ok_or(ContextError::OmissionHandleInvalid)?;
    let mut omission = OmissionRecord {
        atom_id: candidate.atom_id.clone(),
        source_id: eliot_contracts::ArtifactId::new(candidate.source.source_id.as_str())
            .map_err(|_| ContextError::InvalidField("omission.source_id"))?,
        provider_role: candidate.provider_role.clone(),
        decision: input.recipe.decision.clone(),
        task_revision,
        reason,
        competing_constraint: constraint,
        measured_cost: cost,
        allowed_representation: binding.policy,
        expansion: binding.expansion.clone(),
        non_recoverable_reason: binding.non_recoverable_reason,
        authorization_requirement: binding.authorization_requirement.clone(),
        privacy_requirement: binding.privacy_requirement.clone(),
        proof_requirement: binding.proof_requirement.clone(),
        expires: binding.expires.clone(),
        invalidation: binding.invalidation.clone(),
        digest: "0".repeat(64),
    };
    omission.digest = eliot_context_contracts::canonical_digest(&omission)?;
    Ok(omission)
}

fn all_decisions(
    input: &AdmissionInput,
    admitted: &AdmittedContextSet,
    omissions: &[OmissionRecord],
) -> Vec<AdmissionRecord> {
    let mut decisions = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| {
            if let Some(record) = admitted
                .records
                .iter()
                .find(|record| record.candidate.atom_id == candidate.atom_id)
            {
                AdmissionRecord {
                    atom_id: candidate.atom_id.clone(),
                    provider_role: candidate.provider_role.clone(),
                    disposition: record.disposition,
                    rule_evidence: record.rule_evidence.clone(),
                }
            } else {
                let disposition = omissions
                    .iter()
                    .find(|omission| omission.atom_id == candidate.atom_id)
                    .map_or(
                        AdmissionDisposition::Unavailable,
                        |omission| match omission.reason {
                            OmissionReason::Stale | OmissionReason::UnknownMeasurement => {
                                AdmissionDisposition::Revalidate
                            }
                            OmissionReason::Blocked => AdmissionDisposition::Blocked,
                            OmissionReason::Unavailable
                            | OmissionReason::MeasurementUnavailable => {
                                AdmissionDisposition::Unavailable
                            }
                            OmissionReason::Capacity | OmissionReason::ProtectedReserve => {
                                AdmissionDisposition::OverBudget
                            }
                            OmissionReason::Privacy
                            | OmissionReason::Authority
                            | OmissionReason::Policy => AdmissionDisposition::Suppress,
                        },
                    );
                AdmissionRecord {
                    atom_id: candidate.atom_id.clone(),
                    provider_role: candidate.provider_role.clone(),
                    disposition,
                    rule_evidence: input.rule.rule_id.clone(),
                }
            }
        })
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    decisions
}

fn proof_ceiling(input: &AdmissionInput) -> ProofCeiling {
    let _ = input;
    ProofCeiling::Observation
}

fn incomplete_result(
    input: &AdmissionInput,
    input_digest: String,
    profile_digest: String,
    incomplete: &DecisionContextIncomplete,
) -> Result<AdmissionResult, ContextError> {
    let mut decisions = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| AdmissionRecord {
            atom_id: candidate.atom_id.clone(),
            provider_role: candidate.provider_role.clone(),
            disposition: AdmissionDisposition::Blocked,
            rule_evidence: input.rule.rule_id.clone(),
        })
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    let evidence = eliot_context_contracts::AdmissionDecisionEvidence {
        binding: input.binding.clone(),
        decisions,
        omissions: Vec::new(),
        supplied_omissions: Vec::new(),
        incomplete: Some(incomplete.clone()),
        economy: None,
        proof_ceiling: proof_ceiling(input),
    };
    let mut result = AdmissionResult {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: input.binding.clone(),
        input_digest,
        recipe_digest: input.recipe.recipe_sha256.clone(),
        profile_digest,
        floor_id: input.floor.floor_id.clone(),
        outcome: ContextOutcome::Incomplete(incomplete.clone()),
        evidence,
        selection_digest: eliot_context_contracts::canonical_digest(&incomplete)?,
        result_digest: "0".repeat(64),
    };
    result.result_digest = eliot_context_contracts::canonical_digest(&result)?;
    result.validate_for(input)?;
    Ok(result)
}
