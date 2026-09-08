//! Borrowed preflight bounds before validation, cloning, or canonicalization.

use eliot_context_contracts::{
    AdmittedContextSet, AtomRepresentation, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};

use crate::AssemblyError;

pub(crate) const MAX_MEMBERS: usize = 4096;
pub(crate) const MAX_REFERENCES: usize = 4096;
pub(crate) const MAX_TEXT_BYTES: usize = 1_048_576;
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

struct Budget(u64);

impl Budget {
    fn text(&mut self, value: &str, field: &'static str) -> Result<(), AssemblyError> {
        let length = u64::try_from(value.len()).map_err(|_| {
            AssemblyError::Contract(eliot_context_contracts::ContextError::Overflow)
        })?;
        if value.len() > MAX_TEXT_BYTES {
            return Err(AssemblyError::Bounds(field));
        }
        self.0 = self
            .0
            .checked_add(length)
            .ok_or(AssemblyError::Bounds("assembly.input_bytes"))?;
        if self.0 > MAX_INPUT_BYTES {
            return Err(AssemblyError::Bounds("assembly.input_bytes"));
        }
        Ok(())
    }
}

fn count(value: usize, maximum: usize, field: &'static str) -> Result<(), AssemblyError> {
    if value > maximum {
        Err(AssemblyError::Bounds(field))
    } else {
        Ok(())
    }
}

fn binding(
    value: &eliot_context_contracts::ContextBinding,
    budget: &mut Budget,
) -> Result<(), AssemblyError> {
    budget.text(value.task_id.as_str(), "binding.task_id")?;
    budget.text(value.attempt_id.as_str(), "binding.attempt_id")?;
    budget.text(value.scope_id.as_str(), "binding.scope_id")?;
    budget.text(value.decision_id.as_str(), "binding.decision_id")?;
    if let Some(operation) = &value.operation_id {
        budget.text(operation.as_str(), "binding.operation_id")?;
    }
    Ok(())
}

fn measurement_ref(
    value: &eliot_context_contracts::MeasurementRef,
    budget: &mut Budget,
) -> Result<(), AssemblyError> {
    budget.text(&value.digest, "measurement.digest")?;
    budget.text(&value.serializer, "measurement.serializer")
}

fn candidate(
    candidate: &eliot_context_contracts::ContextCandidate,
    budget: &mut Budget,
) -> Result<(), AssemblyError> {
    binding(&candidate.binding, budget)?;
    budget.text(candidate.atom_id.as_str(), "candidate.atom_id")?;
    budget.text(
        candidate.provider_role.provider.as_str(),
        "candidate.provider",
    )?;
    budget.text(
        candidate.source.source_id.as_str(),
        "candidate.source.source_id",
    )?;
    budget.text(
        candidate.source.snapshot_id.as_str(),
        "candidate.source.snapshot_id",
    )?;
    budget.text(candidate.source.owner.as_str(), "candidate.source.owner")?;
    budget.text(&candidate.source.revision, "candidate.source.revision")?;
    budget.text(
        &candidate.source.content_sha256,
        "candidate.source.content_sha256",
    )?;
    if let Some(predecessor) = &candidate.source.predecessor {
        budget.text(predecessor.as_str(), "candidate.source.predecessor")?;
    }
    measurement_ref(&candidate.measurement, budget)?;
    budget.text(
        candidate.proof.evidence_id.as_str(),
        "candidate.proof.evidence_id",
    )?;
    count(candidate.dependencies.len(), 256, "candidate.dependencies")?;
    for dependency in &candidate.dependencies {
        budget.text(dependency.as_str(), "candidate.dependencies")?;
    }
    match &candidate.representation {
        AtomRepresentation::Whole { content }
        | AtomRepresentation::Extractive { content, .. }
        | AtomRepresentation::Summary { content, .. } => {
            budget.text(content, "representation.content")?;
        }
        AtomRepresentation::Handle { handle } => {
            budget.text(handle.as_str(), "representation.handle")?;
        }
    }
    if let AtomRepresentation::Extractive { manifest, .. } = &candidate.representation {
        count(manifest.len(), 256, "representation.manifest")?;
        for value in manifest {
            budget.text(value, "representation.manifest")?;
        }
    }
    if let AtomRepresentation::Summary { source_digest, .. } = &candidate.representation {
        budget.text(source_digest, "representation.source_digest")?;
    }
    Ok(())
}

fn provider_denominator(
    value: &eliot_context_contracts::ProviderRoleDenominator,
    budget: &mut Budget,
) -> Result<(), AssemblyError> {
    count(value.requested.len(), MAX_MEMBERS, "denominator.requested")?;
    count(
        value.dispositions.len(),
        MAX_MEMBERS,
        "denominator.dispositions",
    )?;
    for slot in &value.requested {
        budget.text(slot.provider.as_str(), "denominator.provider")?;
    }
    for disposition in &value.dispositions {
        budget.text(disposition.slot.provider.as_str(), "denominator.provider")?;
        if let Some(proof) = &disposition.evidence {
            budget.text(proof.evidence_id.as_str(), "denominator.evidence")?;
        }
    }
    Ok(())
}

fn floor_fields(admitted: &AdmittedContextSet, budget: &mut Budget) -> Result<(), AssemblyError> {
    count(admitted.floor.members.len(), 256, "floor.members")?;
    count(
        admitted.floor.mandatory_atoms.len(),
        256,
        "floor.mandatory_atoms",
    )?;
    count(
        admitted.floor.mandatory_roles.len(),
        64,
        "floor.mandatory_roles",
    )?;
    count(
        admitted.floor.interpretation_dependencies.len(),
        256,
        "floor.interpretation_dependencies",
    )?;
    binding(&admitted.floor.binding, budget)?;
    provider_denominator(&admitted.floor.providers, budget)?;
    for member in &admitted.floor.members {
        budget.text(member.atom_id.as_str(), "floor.member.atom_id")?;
        count(
            member.required_dependencies.len(),
            256,
            "floor.required_dependencies",
        )?;
        for dependency in &member.required_dependencies {
            budget.text(dependency.as_str(), "floor.required_dependencies")?;
        }
        if let Some(measurement) = &member.measurement {
            measurement_ref(measurement, budget)?;
        }
    }
    budget.text(admitted.floor.rule_evidence.as_str(), "floor.rule_evidence")
}

fn economy_fields(admitted: &AdmittedContextSet, budget: &mut Budget) -> Result<(), AssemblyError> {
    for (value, field) in [
        (admitted.economy.requested.len(), "economy.requested"),
        (admitted.economy.admitted.len(), "economy.admitted"),
        (admitted.economy.displaced.len(), "economy.displaced"),
        (admitted.economy.omissions.len(), "economy.omissions"),
    ] {
        count(value, MAX_REFERENCES, field)?;
    }
    measurement_ref(&admitted.economy.measurement, budget)?;
    binding(&admitted.economy.binding, budget)?;
    budget.text(admitted.economy.decision_id.as_str(), "economy.decision_id")?;
    budget.text(
        admitted.economy.applied_rule.as_str(),
        "economy.applied_rule",
    )?;
    budget.text(&admitted.economy.receipt_digest, "economy.receipt_digest")
}

fn record_fields(admitted: &AdmittedContextSet, budget: &mut Budget) -> Result<(), AssemblyError> {
    for record in &admitted.records {
        candidate(&record.candidate, budget)?;
        budget.text(record.rule_evidence.as_str(), "admitted.rule_evidence")?;
    }
    for admission in &admitted.admissions {
        budget.text(admission.atom_id.as_str(), "admission.atom_id")?;
        budget.text(
            admission.provider_role.provider.as_str(),
            "admission.provider",
        )?;
        budget.text(admission.rule_evidence.as_str(), "admission.rule_evidence")?;
    }
    for value in admitted
        .floor
        .mandatory_atoms
        .iter()
        .chain(admitted.floor.interpretation_dependencies.iter())
        .chain(admitted.economy.requested.iter())
        .chain(admitted.economy.admitted.iter())
        .chain(admitted.economy.displaced.iter())
    {
        budget.text(value.as_str(), "admitted.identity")?;
    }
    Ok(())
}

fn omission_fields(
    admitted: &AdmittedContextSet,
    budget: &mut Budget,
) -> Result<(), AssemblyError> {
    for omission in &admitted.economy.omissions {
        budget.text(omission.atom_id.as_str(), "omission.atom_id")?;
        budget.text(omission.source_id.as_str(), "omission.source_id")?;
        budget.text(
            omission.provider_role.provider.as_str(),
            "omission.provider",
        )?;
        budget.text(
            &omission.competing_constraint,
            "omission.competing_constraint",
        )?;
        budget.text(
            &omission.authorization_requirement,
            "omission.authorization_requirement",
        )?;
        budget.text(
            &omission.privacy_requirement,
            "omission.privacy_requirement",
        )?;
        budget.text(&omission.proof_requirement, "omission.proof_requirement")?;
        budget.text(&omission.digest, "omission.digest")?;
        budget.text(
            omission.decision.decision_id.as_str(),
            "omission.decision_id",
        )?;
        budget.text(&omission.decision.policy_sha256, "omission.policy_sha256")?;
        for value in [&omission.expires, &omission.invalidation]
            .into_iter()
            .flatten()
        {
            budget.text(value.as_str(), "omission.lifecycle")?;
        }
        if let Some(expansion) = &omission.expansion {
            budget.text(expansion.handle_id.as_str(), "expansion.handle_id")?;
            budget.text(expansion.atom_id.as_str(), "expansion.atom_id")?;
            budget.text(expansion.source_id.as_str(), "expansion.source_id")?;
            budget.text(&expansion.source_revision, "expansion.source_revision")?;
            budget.text(
                expansion.decision.decision_id.as_str(),
                "expansion.decision_id",
            )?;
            budget.text(&expansion.decision.policy_sha256, "expansion.policy_sha256")?;
            budget.text(
                expansion.provider_role.provider.as_str(),
                "expansion.provider",
            )?;
            binding(&expansion.context, budget)?;
            budget.text(&expansion.handle_digest, "expansion.handle_digest")?;
            for value in [&expansion.expires, &expansion.invalidation]
                .into_iter()
                .flatten()
            {
                budget.text(value.as_str(), "expansion.lifecycle")?;
            }
        }
    }
    Ok(())
}

/// Check every reachable admitted field that can contribute to the view.
pub(crate) fn admitted(admitted: &AdmittedContextSet) -> Result<(), AssemblyError> {
    let mut budget = Budget(0);
    binding(&admitted.binding, &mut budget)?;
    count(admitted.records.len(), MAX_MEMBERS, "admitted.records")?;
    count(
        admitted.admissions.len(),
        MAX_MEMBERS,
        "admitted.admissions",
    )?;
    floor_fields(admitted, &mut budget)?;
    economy_fields(admitted, &mut budget)?;
    record_fields(admitted, &mut budget)?;
    omission_fields(admitted, &mut budget)
}
/// Check the recipe's reachable vectors before its canonical digest clone.
pub(crate) fn recipe(recipe: &ContextRecipe) -> Result<(), AssemblyError> {
    let mut budget = Budget(0);
    binding(&recipe.binding, &mut budget)?;
    budget.text(&recipe.recipe_sha256, "recipe.recipe_sha256")?;
    budget.text(recipe.decision.decision_id.as_str(), "recipe.decision_id")?;
    budget.text(&recipe.decision.policy_sha256, "recipe.policy_sha256")?;
    if let Some(value) = &recipe.predecessor {
        budget.text(value.as_str(), "recipe.predecessor")?;
    }
    if let Some(value) = &recipe.invalidation {
        budget.text(value.as_str(), "recipe.invalidation")?;
    }
    count(
        recipe.denominator.requested.len(),
        MAX_MEMBERS,
        "recipe.denominator.requested",
    )?;
    count(
        recipe.denominator.dispositions.len(),
        MAX_MEMBERS,
        "recipe.denominator.dispositions",
    )?;
    provider_denominator(&recipe.denominator, &mut budget)?;
    count(recipe.mandatory_roles.len(), 64, "recipe.mandatory_roles")?;
    count(recipe.role_policies.len(), 64, "recipe.role_policies")?;
    for policy in &recipe.role_policies {
        count(
            policy.allowed_representations.len(),
            4,
            "recipe.allowed_representations",
        )?;
    }
    Ok(())
}

/// Check the scorecard before the caller's value is consumed by assembly.
pub(crate) fn quality(scorecard: &QualityScorecard) -> Result<(), AssemblyError> {
    let mut budget = Budget(0);
    binding(&scorecard.binding, &mut budget)?;
    count(scorecard.results.len(), 12, "quality.results")?;
    for result in &scorecard.results {
        binding(&result.binding, &mut budget)?;
        count(result.evidence.len(), MAX_REFERENCES, "quality.evidence")?;
        count(
            result.measurements.len(),
            MAX_REFERENCES,
            "quality.measurements",
        )?;
        count(
            result.unknown_evidence.len(),
            MAX_REFERENCES,
            "quality.unknown_evidence",
        )?;
        for evidence in result.evidence.iter().chain(result.unknown_evidence.iter()) {
            budget.text(evidence.as_str(), "quality.evidence")?;
        }
        if let Some(invariant) = &result.failed_invariant {
            budget.text(invariant.as_str(), "quality.failed_invariant")?;
        }
        if let Some(invalidation) = &result.invalidation {
            budget.text(invalidation.as_str(), "quality.invalidation")?;
        }
        for measurement in &result.measurements {
            measurement_ref(measurement, &mut budget)?;
        }
    }
    Ok(())
}

/// Check a measurement returned by the injected measurement operation.
pub(crate) fn measurement(value: &SerializedContextMeasurement) -> Result<(), AssemblyError> {
    let mut budget = Budget(0);
    binding(&value.context, &mut budget)?;
    budget.text(value.measurement_id.as_str(), "measurement.measurement_id")?;
    budget.text(&value.envelope_digest, "measurement.envelope_digest")?;
    budget.text(&value.serializer_id, "measurement.serializer_id")?;
    budget.text(&value.serializer_version, "measurement.serializer_version")?;
    budget.text(
        &value.serializer_options_digest,
        "measurement.serializer_options_digest",
    )?;
    budget.text(&value.route_id, "measurement.route_id")?;
    budget.text(&value.model_id, "measurement.model_id")?;
    if let Some(tokenizer) = &value.tokenizer {
        budget.text(&tokenizer.tokenizer_id, "measurement.tokenizer_id")?;
        budget.text(
            &tokenizer.tokenizer_version,
            "measurement.tokenizer_version",
        )?;
        budget.text(&tokenizer.tokenizer_hash, "measurement.tokenizer_hash")?;
    }
    if let Some(value) = &value.false_safe_overflow {
        budget.text(value.as_str(), "measurement.false_safe_overflow")?;
    }
    if let Some(value) = &value.false_rejection_or_decomposition {
        budget.text(
            value.as_str(),
            "measurement.false_rejection_or_decomposition",
        )?;
    }
    if let Some(value) = &value.valid_until {
        budget.text(value.as_str(), "measurement.valid_until")?;
    }
    Ok(())
}
