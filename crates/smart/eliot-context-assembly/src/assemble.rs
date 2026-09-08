//! Public assembly operation and its explicit phases.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, ContextRecipe, MeasurementStatus,
    QualityScorecard, SerializedContextMeasurement,
};

use crate::{AssemblyError, bounds, measurement, render};

/// Stable local ordering revision for the A-15 canonical rendered payload.
pub const ASSEMBLY_ORDERING_REVISION: &str = "a18.role-provider-atom.v1";

/// Caller-owned immutable parameters for one A-18 projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssemblyPolicy {
    /// Digest of the state fence used by the admission decision.
    pub fence_digest: String,
    /// Maximum canonical rendered payload bytes accepted by this route.
    pub max_serialized_bytes: u64,
    /// Required serializer identity for the injected measurement.
    pub serializer_id: String,
    /// Required serializer revision for the injected measurement.
    pub serializer_version: String,
    /// Required serializer-options digest.
    pub serializer_options_digest: String,
    /// Required route identity.
    pub route_id: String,
    /// Required model/tokenizer route identity.
    pub model_id: String,
    /// Measurement status qualified for this route; this prototype supports
    /// only exact UTF-8 bytes, while tokenizer/STU observations remain data.
    pub measurement_status: MeasurementStatus,
}

impl AssemblyPolicy {
    fn validate(&self) -> Result<(), AssemblyError> {
        validate_digest(&self.fence_digest, "assembly.fence_digest")?;
        if self.max_serialized_bytes == 0 {
            return Err(AssemblyError::Bounds("assembly.max_serialized_bytes"));
        }
        for (value, field) in [
            (&self.serializer_id, "assembly.serializer_id"),
            (&self.serializer_version, "assembly.serializer_version"),
            (&self.route_id, "assembly.route_id"),
            (&self.model_id, "assembly.model_id"),
        ] {
            if value.len() > bounds::MAX_TEXT_BYTES {
                return Err(AssemblyError::Bounds(field));
            }
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(AssemblyError::Contract(ContextError::InvalidField(field)));
            }
        }
        validate_digest(
            &self.serializer_options_digest,
            "assembly.serializer_options_digest",
        )?;
        if self.measurement_status != MeasurementStatus::ExactUtf8 {
            return Err(AssemblyError::Contract(ContextError::UnknownMeasurement));
        }
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), AssemblyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AssemblyError::Contract(ContextError::InvalidDigest(field)));
    }
    Ok(())
}

/// Assemble one exact admitted set using one injected measurement call.
///
/// The callback receives the exact canonical A-15 rendered payload bytes and
/// is invoked once. This prototype accepts only exact UTF-8 byte measurement;
/// tokenizer and STU observations remain data for a later qualified route.
pub fn assemble_active_view<F>(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<ActiveUnderstandingViewResult, AssemblyError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    preflight(admitted, recipe, &quality, policy)?;
    recipe.validate()?;
    if recipe.binding != admitted.binding || recipe.capacity != admitted.floor.capacity {
        return Err(AssemblyError::Contract(ContextError::IdentityConflict));
    }
    admitted.validate()?;
    validate_recipe_membership(admitted, recipe)?;
    if quality.binding != admitted.binding {
        return Err(AssemblyError::Contract(ContextError::InvalidFence));
    }
    let allocations = &admitted.economy.allocations;
    let capacity = &admitted.floor.capacity;
    if allocations.route_capacity != capacity.route_capacity
        || allocations.fixed_overhead != capacity.fixed_overhead
        || allocations.output_reserve != capacity.output_reserve
        || allocations.review_reserve != capacity.review_reserve
    {
        return Err(AssemblyError::Contract(ContextError::EconomyMismatch));
    }
    if let Some(incomplete) = admitted.floor.incomplete()? {
        return Err(AssemblyError::Incomplete(Box::new(incomplete)));
    }
    if let Err(error) = quality.validate() {
        if error == ContextError::QualityIncomplete {
            return Err(AssemblyError::QualityIncomplete(Box::new(quality)));
        }
        return Err(error.into());
    }
    if !quality.results.iter().all(|result| result.passed) {
        return Err(AssemblyError::QualityIncomplete(Box::new(quality)));
    }
    let rendered = render::render(admitted);
    let (output_digest, bytes) = measurement::canonical_matches(
        &admitted.binding,
        &recipe.recipe_sha256,
        &policy.fence_digest,
        &rendered,
    )?;
    let final_bytes =
        u64::try_from(bytes.len()).map_err(|_| AssemblyError::Contract(ContextError::Overflow))?;
    if final_bytes > policy.max_serialized_bytes {
        return Err(AssemblyError::Bounds("assembly.final_bytes"));
    }
    let measured = measure(&bytes)?;
    let measured = measurement::verify(
        measured,
        &admitted.binding,
        &bytes,
        &output_digest,
        &admitted.floor.capacity,
        policy,
        policy.max_serialized_bytes,
    )?;
    let ids = rendered
        .iter()
        .map(|atom| atom.atom_id.clone())
        .collect::<Vec<_>>();
    let selection = eliot_context_contracts::SelectionIntegrityProof {
        binding: admitted.binding.clone(),
        admitted_ids: ids.clone(),
        rendered_ids: ids.clone(),
        omission_evidence: admitted.economy.displaced.clone(),
        output_digest: output_digest.clone(),
    };
    selection.validate()?;
    let view = ActiveUnderstandingView {
        binding: admitted.binding.clone(),
        admitted_ids: ids,
        rendered,
        selection,
        quality,
        measurement: measured,
        output_digest,
        recipe_digest: recipe.recipe_sha256.clone(),
        fence_digest: policy.fence_digest.clone(),
    };
    view.validate_against(admitted)?;
    Ok(ActiveUnderstandingViewResult {
        view,
        admitted: admitted.clone(),
        serialized_bytes: bytes,
    })
}

fn preflight(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: &QualityScorecard,
    policy: &AssemblyPolicy,
) -> Result<(), AssemblyError> {
    policy.validate()?;
    bounds::admitted(admitted)?;
    bounds::recipe(recipe)?;
    bounds::quality(quality)
}

fn validate_recipe_membership(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
) -> Result<(), AssemblyError> {
    for slot in &admitted.floor.providers.requested {
        let matching = recipe
            .denominator
            .requested
            .iter()
            .any(|candidate| candidate == slot);
        if !matching {
            return Err(AssemblyError::Contract(ContextError::DenominatorMismatch));
        }
    }
    for record in &admitted.records {
        let candidate = &record.candidate;
        let slot = recipe
            .denominator
            .dispositions
            .iter()
            .find(|disposition| disposition.slot == candidate.provider_role)
            .ok_or(AssemblyError::Contract(ContextError::DenominatorMismatch))?;
        if slot.state != candidate.availability {
            return Err(AssemblyError::Contract(ContextError::IdentityConflict));
        }
        let role_policy = recipe
            .role_policies
            .iter()
            .find(|policy| policy.role == candidate.provider_role.role)
            .ok_or(AssemblyError::Contract(ContextError::IdentityConflict))?;
        if role_policy.loss_policy != candidate.loss_policy
            || !role_policy
                .allowed_representations
                .contains(&candidate.representation.kind())
        {
            return Err(AssemblyError::Contract(ContextError::WholeUnitRequired));
        }
    }
    Ok(())
}

/// Complete projection result retaining the exact A-15 accounting evidence
/// that the compact view schema represents only through omission identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveUnderstandingViewResult {
    /// Canonical rendered candidate view.
    pub view: ActiveUnderstandingView,
    /// Exact admitted records, admissions, floor and economy retained for reconstruction.
    pub admitted: AdmittedContextSet,
    /// Exact bytes handed to the measurement callback.
    pub serialized_bytes: Vec<u8>,
}
