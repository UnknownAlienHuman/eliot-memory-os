//! Typed A04 assembly ingress and deterministic input normalization.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::MeasurementCompositionProfile;
use eliot_dreamer_contracts::assembly::{
    AssemblyMaterial, AssemblyOmissionCoverage, ContributionMeasurement, DreamInputRole,
    DreamJobRecipe, MaterialRepresentation, SuppliedItemIdentity,
};
use eliot_dreamer_contracts::bundle::OmissionHandle;
use eliot_dreamer_contracts::error::check_text;
use eliot_dreamer_contracts::grounding::{AllowedReferenceManifest, AuthorizedReference};
use eliot_dreamer_contracts::{ContractViolation, RecipeInput, RecipeRole, RoleDisposition};
use eliot_evidence::EvidenceFreshness;

/// Explicit controls supplied by the caller; no ambient clock or cancellation
/// source is consulted by assembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssemblyPolicy {
    /// Stop before selection and retain a cancelled disposition.
    pub cancelled: bool,
    /// Stop before selection and retain a deadline disposition.
    pub deadline_reached: bool,
    /// Caller-observed elapsed execution time; no ambient clock is read.
    pub elapsed_ms: u64,
    /// Caller-observed attempt count; zero is retained as an explicit value.
    pub attempts: u64,
}

/// Owner-reported availability of one supplied item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppliedItemState {
    /// The owner supplied a material envelope and representation.
    Available,
    /// The owner could not provide the item for a typed reason.
    Unavailable(eliot_dreamer_contracts::MaterialOutcomeReason),
    /// The current closure prevents use of the item for a typed reason.
    Blocked(eliot_dreamer_contracts::MaterialOutcomeReason),
}

/// One immutable owner-supplied item before A04 chooses the selected closure.
///
/// This is deliberately not a final-selection ledger: A04 derives the ledger,
/// dispositions, role outcomes, reserves, budget usage and frontiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedAssemblyItem {
    /// Stable role/item identity supplied by the upstream owner.
    pub identity: SuppliedItemIdentity,
    /// Material representation, present only when the owner reports available.
    pub material: Option<AssemblyMaterial>,
    /// Owner availability state.
    pub state: SuppliedItemState,
    /// Optional owner-qualified contribution observation.
    pub measurement: Option<ContributionMeasurement>,
    /// Optional owner omission handle for an unavailable or blocked item.
    pub omission: Option<OmissionHandle>,
    /// Optional exact coverage member mapping for that omission.
    pub omission_coverage: Option<AssemblyOmissionCoverage>,
    /// Bounded owner detail retained for unavailable or blocked items.
    pub note: Option<String>,
}

/// Immutable A04 operation input. The route measurement profile is frozen
/// before selection and must be retained unchanged by finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssemblyRequest {
    /// Versioned job recipe and its admitted job envelope.
    pub recipe: DreamJobRecipe,
    /// Complete upstream-frozen manifest; A04 never opens handles.
    pub manifest: AllowedReferenceManifest,
    /// All owner-supplied items, including unavailable or blocked entries.
    pub supplied_items: Vec<SuppliedAssemblyItem>,
    /// Exact A15 closure, when required by the recipe.
    pub context: Option<eliot_dreamer_contracts::ContextMaterialClosure>,
    /// Exact Curation closure for a Curation recipe.
    pub curation: Option<eliot_dreamer_contracts::CurationMaterial>,
    /// Qualified route/profile identity used for bounded selection.
    pub measurement_profile: MeasurementCompositionProfile,
    /// Explicit cancellation/deadline controls.
    pub policy: AssemblyPolicy,
}

/// Validated, normalized input consumed by later A04 selection phases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NormalizedAssemblyInput {
    pub(crate) recipe: DreamJobRecipe,
    pub(crate) manifest: AllowedReferenceManifest,
    pub(crate) supplied_items: Vec<SuppliedAssemblyItem>,
    pub(crate) supplied_identities: Vec<SuppliedItemIdentity>,
    pub(crate) context: Option<eliot_dreamer_contracts::ContextMaterialClosure>,
    pub(crate) curation: Option<eliot_dreamer_contracts::CurationMaterial>,
    pub(crate) measurement_profile: MeasurementCompositionProfile,
    pub(crate) policy: AssemblyPolicy,
}

/// Validate and deterministically normalize one assembly request.
pub(crate) fn validate_and_normalize(
    request: AssemblyRequest,
) -> Result<NormalizedAssemblyInput, ContractViolation> {
    bound_raw_payload(&request.supplied_items)?;
    validate_request_header(&request)?;
    let source_free = derive_source_free_identities(&request.recipe)?;
    let denominator_len = source_free
        .len()
        .checked_add(request.supplied_items.len())
        .ok_or(ContractViolation::Budget {
            dimension: "source_width",
            reason: "combined material denominator overflows".to_owned(),
        })?;
    eliot_dreamer_contracts::check_vec_bound(
        denominator_len,
        1_024,
        "request.material_denominator",
    )?;
    let mut request = request;
    if request.policy.cancelled || request.policy.deadline_reached {
        normalize_early_stop_items(&mut request)?;
    } else {
        validate_supplied_items(&mut request)?;
    }
    let mut supplied_items = request.supplied_items;
    supplied_items
        .sort_by(|left, right| item_order(left, right, &request.recipe, &request.manifest));
    let mut supplied_identities = source_free;
    supplied_identities.extend(supplied_items.iter().map(|item| item.identity.clone()));
    supplied_identities.sort();
    Ok(NormalizedAssemblyInput {
        recipe: request.recipe,
        manifest: request.manifest,
        supplied_items,
        supplied_identities,
        context: request.context,
        curation: request.curation,
        measurement_profile: request.measurement_profile,
        policy: request.policy,
    })
}

fn normalize_early_stop_items(request: &mut AssemblyRequest) -> Result<(), ContractViolation> {
    for item in &mut request.supplied_items {
        if !matches!(item.state, SuppliedItemState::Available) {
            item.material = None;
            item.measurement = None;
            continue;
        }
        let exact_manifest_identity = item
            .identity
            .handle
            .as_ref()
            .and_then(|handle| request.manifest.references.get(handle))
            .is_some_and(|reference| {
                item.identity.source_revision.as_deref() == Some(reference.source_revision.as_str())
                    && item.identity.content_digest.as_deref()
                        == Some(reference.content_digest.as_str())
            });
        let role = request
            .recipe
            .roles
            .iter()
            .find(|role| role.role == item.identity.role);
        if exact_manifest_identity {
            if let (Some(role), Some(handle)) = (role, item.identity.handle.as_ref()) {
                if let Some(reference) = request.manifest.references.get(handle) {
                    if let Some(reason) = source_policy_reason(reference, role) {
                        item.state = SuppliedItemState::Blocked(reason);
                    } else {
                        item.state = SuppliedItemState::Blocked(
                            eliot_dreamer_contracts::MaterialOutcomeReason::Unprocessed,
                        );
                    }
                } else {
                    item.state = SuppliedItemState::Blocked(
                        eliot_dreamer_contracts::MaterialOutcomeReason::Unprocessed,
                    );
                }
            } else {
                item.state = SuppliedItemState::Blocked(
                    eliot_dreamer_contracts::MaterialOutcomeReason::Unprocessed,
                );
            }
        } else {
            item.state = SuppliedItemState::Blocked(
                eliot_dreamer_contracts::MaterialOutcomeReason::Unprocessed,
            );
        }
        item.material = None;
        item.measurement = None;
        if item.note.is_none() {
            item.note = Some("assembly stopped before payload validation".to_owned());
        }
    }
    validate_supplied_items(request)
}

fn validate_request_header(request: &AssemblyRequest) -> Result<(), ContractViolation> {
    request.recipe.validate()?;
    request.manifest.validate()?;
    if request.manifest.computed_digest()? != request.manifest.digest {
        return Err(ContractViolation::BindingMismatch {
            field: "request.manifest.digest",
            reason: "manifest digest does not match its immutable contents".to_owned(),
        });
    }
    if request.manifest.digest != request.recipe.job.frozen_manifest_digest
        || request.manifest.task_id.as_str() != request.recipe.job.task_id
        || request.manifest.scope_id != request.recipe.job.scope_id
        || request.manifest.state_fence != request.recipe.job.state_fence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "request.manifest",
            reason: "manifest differs from the recipe task, scope, fence or digest".to_owned(),
        });
    }
    request
        .measurement_profile
        .validate()
        .map_err(|error| ContractViolation::BindingMismatch {
            field: "request.measurement_profile",
            reason: error.to_string(),
        })?;
    request.recipe.reserves.total_for(
        &request.measurement_profile.profile_id,
        request.measurement_profile.unit,
    )?;
    validate_route_input(request)
}

fn validate_route_input(request: &AssemblyRequest) -> Result<(), ContractViolation> {
    let routes = request.recipe.inputs.iter().find_map(|input| match input {
        RecipeInput::AllowedModelRoutes { routes } => Some(routes),
        _ => None,
    });
    let routes = routes.ok_or(ContractViolation::MissingField(
        "recipe.inputs.allowed_model_routes",
    ))?;
    if !routes
        .iter()
        .any(|route| route == &request.measurement_profile.route_id)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "request.measurement_profile.route_id",
            reason: "route is absent from the exact AllowedModelRoutes recipe input".to_owned(),
        });
    }
    if let Some(context) = request.context.as_ref() {
        let job = &request.recipe.job;
        context.validate_for(
            &job.task_id,
            &job.scope_id,
            &job.state_fence,
            &request.recipe.attempt.attempt_id,
            Some(&job.operation_id),
        )?;
    }
    Ok(())
}

fn derive_source_free_identities(
    recipe: &DreamJobRecipe,
) -> Result<Vec<SuppliedItemIdentity>, ContractViolation> {
    let mut identities = Vec::new();
    for role in &recipe.roles {
        if role.disposition == RoleDisposition::NotApplicable || !role.source_rule.is_none() {
            continue;
        }
        if let Some(content_digest) = recipe.source_free_value_digest(role.role)? {
            identities.push(SuppliedItemIdentity {
                role: role.role,
                ordinal: 0,
                handle: None,
                content_digest: Some(content_digest),
                source_revision: None,
            });
        }
    }
    Ok(identities)
}

fn validate_supplied_items(request: &mut AssemblyRequest) -> Result<(), ContractViolation> {
    eliot_dreamer_contracts::check_vec_bound(
        request.supplied_items.len(),
        1_024,
        "request.supplied_items",
    )?;
    let mut identities = BTreeSet::new();
    let mut role_ordinals = BTreeSet::new();
    let mut handles = BTreeMap::new();
    let (recipe, manifest, items) = (
        &request.recipe,
        &request.manifest,
        &mut request.supplied_items,
    );
    for item in items {
        let role = recipe
            .roles
            .iter()
            .find(|role| role.role == item.identity.role)
            .ok_or(ContractViolation::BindingMismatch {
                field: "request.supplied_items.role",
                reason: "supplied role is absent from the recipe denominator".to_owned(),
            })?;
        validate_supplied_item(item, recipe, manifest, &request.measurement_profile, role)?;
        if !identities.insert(item.identity.clone()) {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.duplicate_identity",
                reason: "supplied item identity is duplicated".to_owned(),
            });
        }
        if !role_ordinals.insert((item.identity.role, item.identity.ordinal)) {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.role_ordinal_conflict",
                reason: "one role/ordinal identity has conflicting supplied entries".to_owned(),
            });
        }
        if let Some(handle) = &item.identity.handle
            && let Some(previous) =
                handles.insert(handle.clone(), (item.identity.role, item.identity.ordinal))
            && previous != (item.identity.role, item.identity.ordinal)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.handle_conflict",
                reason: "one handle is assigned to multiple role/ordinal identities".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_supplied_item(
    item: &mut SuppliedAssemblyItem,
    recipe: &DreamJobRecipe,
    manifest: &AllowedReferenceManifest,
    profile: &MeasurementCompositionProfile,
    role: &RecipeRole,
) -> Result<(), ContractViolation> {
    if let Some(note) = &item.note {
        check_text(note, "request.supplied_items.note", 256)?;
    }
    item.identity.validate()?;
    if role.disposition == RoleDisposition::NotApplicable {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.role",
            reason: "supplied item names a not-applicable role".to_owned(),
        });
    }
    if role.source_rule.is_none() {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.source_free",
            reason: "source-free values are derived exactly once from recipe inputs".to_owned(),
        });
    }
    validate_handle_item(item, manifest, profile, role)?;
    validate_item_state(item)?;
    validate_omission_metadata(item, recipe)
}

fn validate_handle_item(
    item: &mut SuppliedAssemblyItem,
    manifest: &AllowedReferenceManifest,
    profile: &MeasurementCompositionProfile,
    role: &RecipeRole,
) -> Result<(), ContractViolation> {
    let handle = item
        .identity
        .handle
        .clone()
        .ok_or(ContractViolation::MissingField(
            "request.supplied_items.handle",
        ))?;
    let Some(reference) = manifest.references.get(&handle) else {
        if !foreign_identity_allowed(item) {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.handle",
                reason: "handle is absent from the frozen manifest".to_owned(),
            });
        }
        validate_foreign_item(item, profile)?;
        return Ok(());
    };
    let identity_matches = item.identity.source_revision.as_deref()
        == Some(reference.source_revision.as_str())
        && item.identity.content_digest.as_deref() == Some(reference.content_digest.as_str());
    if !identity_matches {
        if !foreign_identity_allowed(item) {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.identity_conflict",
                reason: "supplied handle identity differs from the frozen manifest".to_owned(),
            });
        }
        if let Some(material) = &item.material {
            material.validate()?;
            item.material = None;
        }
        if let Some(measurement) = &item.measurement {
            validate_contribution(measurement, item, None, profile)?;
        }
        return Ok(());
    }
    validate_material_join(item, reference, &handle, profile)?;
    if !matches!(item.state, SuppliedItemState::Available) {
        item.material = None;
    }
    if let Some(reason) = source_policy_reason(reference, role)
        && matches!(item.state, SuppliedItemState::Available)
    {
        item.state = SuppliedItemState::Blocked(reason);
        item.material = None;
        item.note = Some("owner material is outside the recipe source policy".to_owned());
    }
    Ok(())
}

fn validate_foreign_item(
    item: &mut SuppliedAssemblyItem,
    profile: &MeasurementCompositionProfile,
) -> Result<(), ContractViolation> {
    if let Some(material) = &item.material {
        material.validate()?;
        item.material = None;
    }
    if let Some(measurement) = &item.measurement {
        validate_contribution(measurement, item, None, profile)?;
    }
    Ok(())
}

fn validate_material_join(
    item: &mut SuppliedAssemblyItem,
    reference: &AuthorizedReference,
    handle: &eliot_contracts::ArtifactId,
    profile: &MeasurementCompositionProfile,
) -> Result<(), ContractViolation> {
    if let Some(material) = &item.material {
        material.validate()?;
        if material.role != item.identity.role
            || material.ordinal != item.identity.ordinal
            || material.reference != *handle
            || material.material.handle != handle.as_str()
            || material.material.digest != reference.content_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.material",
                reason: "material does not join the supplied identity and manifest member"
                    .to_owned(),
            });
        }
    }
    if let Some(measurement) = &item.measurement {
        validate_contribution(measurement, item, item.material.as_ref(), profile)?;
        if measurement.material_digest != reference.content_digest
            || measurement.source_revision != reference.source_revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.measurement",
                reason: "contribution measurement differs from the manifest identity".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_contribution(
    measurement: &ContributionMeasurement,
    item: &SuppliedAssemblyItem,
    material: Option<&AssemblyMaterial>,
    profile: &MeasurementCompositionProfile,
) -> Result<(), ContractViolation> {
    measurement.validate()?;
    if measurement.profile != *profile {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.measurement.profile",
            reason: "contribution profile differs from the frozen request profile".to_owned(),
        });
    }
    let handle = item
        .identity
        .handle
        .as_ref()
        .ok_or(ContractViolation::MissingField(
            "request.supplied_items.handle",
        ))?;
    if measurement.material != *handle {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.measurement.material",
            reason: "contribution material differs from the supplied handle".to_owned(),
        });
    }
    if measurement.source_revision != item.identity.source_revision.as_deref().unwrap_or_default()
        || measurement.material_digest
            != item.identity.content_digest.as_deref().unwrap_or_default()
    {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.measurement.identity",
            reason: "contribution identity differs from the supplied item".to_owned(),
        });
    }
    if let Some(material) = material {
        let representation_id = match &material.representation {
            MaterialRepresentation::Utf8 {
                representation_id, ..
            }
            | MaterialRepresentation::Bytes {
                representation_id, ..
            }
            | MaterialRepresentation::HandleOnly { representation_id } => representation_id,
        };
        if measurement.representation != *representation_id {
            return Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.measurement.representation",
                reason: "contribution representation differs from retained material".to_owned(),
            });
        }
        if measurement.status == eliot_dreamer_contracts::ContributionStatus::Exact {
            let bytes = match &material.representation {
                MaterialRepresentation::Utf8 { content, .. } => content.len(),
                MaterialRepresentation::Bytes { content, .. } => content.len(),
                MaterialRepresentation::HandleOnly { .. } => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "request.supplied_items.measurement.bytes",
                        reason: "handle-only representation cannot claim exact bytes".to_owned(),
                    });
                }
            };
            let bytes = u64::try_from(bytes).map_err(|_| ContractViolation::Budget {
                dimension: "input_bytes",
                reason: "representation byte count overflows budget accounting".to_owned(),
            })?;
            if measurement.bytes != Some(bytes) {
                return Err(ContractViolation::BindingMismatch {
                    field: "request.supplied_items.measurement.bytes",
                    reason: "exact contribution bytes differ from the retained representation"
                        .to_owned(),
                });
            }
        }
    } else if measurement.status == eliot_dreamer_contracts::ContributionStatus::Exact {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.measurement.bytes",
            reason: "exact contribution requires a retained representation".to_owned(),
        });
    }
    Ok(())
}

fn source_policy_reason(
    reference: &AuthorizedReference,
    role: &RecipeRole,
) -> Option<eliot_dreamer_contracts::MaterialOutcomeReason> {
    let source_rule = &role.source_rule;
    if reference.invalidated
        || reference.revocation_reason.is_some()
        || reference.stale
        || matches!(
            reference.freshness,
            EvidenceFreshness::Stale | EvidenceFreshness::KnownOlderSnapshot
        )
    {
        return Some(eliot_dreamer_contracts::MaterialOutcomeReason::Stale);
    }
    if matches!(reference.freshness, EvidenceFreshness::Unknown) {
        return Some(eliot_dreamer_contracts::MaterialOutcomeReason::Unknown);
    }
    if source_rule
        .allowed_owner
        .as_ref()
        .is_some_and(|owner| actual_source_owner(reference).as_deref() != Some(owner.as_str()))
        || !source_rule.allowed_authority.contains(&reference.authority)
        || !source_rule
            .allowed_proof
            .contains(&reference.assertability_ceiling)
    {
        return Some(eliot_dreamer_contracts::MaterialOutcomeReason::AuthorityMismatch);
    }
    if !source_rule.allowed_privacy.contains(&reference.privacy)
        || !source_rule
            .allowed_disclosure
            .contains(&reference.disclosure)
    {
        return Some(eliot_dreamer_contracts::MaterialOutcomeReason::PrivacyMismatch);
    }
    None
}

fn foreign_identity_allowed(item: &SuppliedAssemblyItem) -> bool {
    matches!(
        item.state,
        SuppliedItemState::Blocked(
            eliot_dreamer_contracts::MaterialOutcomeReason::AuthorityMismatch
                | eliot_dreamer_contracts::MaterialOutcomeReason::ScopeMismatch
                | eliot_dreamer_contracts::MaterialOutcomeReason::Stale
                | eliot_dreamer_contracts::MaterialOutcomeReason::Conflict
        ) | SuppliedItemState::Unavailable(
            eliot_dreamer_contracts::MaterialOutcomeReason::AuthorityMismatch
                | eliot_dreamer_contracts::MaterialOutcomeReason::ScopeMismatch
                | eliot_dreamer_contracts::MaterialOutcomeReason::Stale
                | eliot_dreamer_contracts::MaterialOutcomeReason::Conflict
        )
    )
}

fn validate_item_state(item: &SuppliedAssemblyItem) -> Result<(), ContractViolation> {
    match item.state {
        SuppliedItemState::Available if item.material.is_none() => Err(
            ContractViolation::MissingField("request.supplied_items.material"),
        ),
        SuppliedItemState::Unavailable(_) | SuppliedItemState::Blocked(_)
            if item.note.is_none() =>
        {
            Err(ContractViolation::MissingField(
                "request.supplied_items.note",
            ))
        }
        SuppliedItemState::Unavailable(_) | SuppliedItemState::Blocked(_)
            if item.material.is_some() =>
        {
            Err(ContractViolation::BindingMismatch {
                field: "request.supplied_items.material",
                reason: "unavailable or blocked item cannot carry selected material".to_owned(),
            })
        }
        _ => Ok(()),
    }
}

fn validate_omission_metadata(
    item: &SuppliedAssemblyItem,
    recipe: &DreamJobRecipe,
) -> Result<(), ContractViolation> {
    let Some(omission) = &item.omission else {
        if item.omission_coverage.is_some() {
            return Err(ContractViolation::MissingField(
                "request.supplied_items.omission",
            ));
        }
        return Ok(());
    };
    omission.validate()?;
    if item
        .identity
        .handle
        .as_ref()
        .map(eliot_contracts::ArtifactId::as_str)
        != Some(omission.handle.as_str())
        || omission.task_id != recipe.job.task_id
        || omission.scope_id != recipe.job.scope_id
    {
        return Err(ContractViolation::BindingMismatch {
            field: "request.supplied_items.omission",
            reason: "omission handle differs from the supplied task/scope identity".to_owned(),
        });
    }
    if let Some(coverage) = &item.omission_coverage
        && !eliot_dreamer_contracts::is_hex64_lower(&coverage.denominator)
    {
        return Err(ContractViolation::Malformed {
            field: "request.supplied_items.omission_coverage.denominator",
            reason: "coverage denominator must be a lowercase SHA-256 digest".to_owned(),
        });
    }
    Ok(())
}

fn item_order(
    left: &SuppliedAssemblyItem,
    right: &SuppliedAssemblyItem,
    recipe: &DreamJobRecipe,
    manifest: &AllowedReferenceManifest,
) -> Ordering {
    source_priority(recipe, left.identity.role)
        .cmp(&source_priority(recipe, right.identity.role))
        .then_with(|| {
            role_index(recipe, left.identity.role).cmp(&role_index(recipe, right.identity.role))
        })
        .then_with(|| {
            actual_source_owner_for_item(left, manifest)
                .cmp(&actual_source_owner_for_item(right, manifest))
        })
        .then_with(|| left.identity.cmp(&right.identity))
}

fn role_index(recipe: &DreamJobRecipe, role: DreamInputRole) -> usize {
    recipe
        .roles
        .iter()
        .position(|candidate| candidate.role == role)
        .unwrap_or(usize::MAX)
}

fn source_priority(recipe: &DreamJobRecipe, role: DreamInputRole) -> u16 {
    recipe
        .roles
        .iter()
        .find(|candidate| candidate.role == role)
        .map_or(0, |candidate| candidate.source_priority)
}

fn actual_source_owner_for_item(
    item: &SuppliedAssemblyItem,
    manifest: &AllowedReferenceManifest,
) -> String {
    item.identity
        .handle
        .as_ref()
        .and_then(|handle| manifest.references.get(handle))
        .and_then(actual_source_owner)
        .unwrap_or_default()
}

fn actual_source_owner(reference: &AuthorizedReference) -> Option<String> {
    reference
        .source_lineage
        .as_ref()
        .map(|lineage| lineage.owner.as_str().to_owned())
        .or_else(|| {
            reference.provenance.as_ref().and_then(|provenance| {
                provenance
                    .lineage
                    .iter()
                    .find(|lineage| {
                        lineage.content_digest == reference.content_digest
                            && lineage.revision == reference.source_revision
                    })
                    .map(|lineage| lineage.owner.as_str().to_owned())
            })
        })
}

fn bound_raw_payload(items: &[SuppliedAssemblyItem]) -> Result<(), ContractViolation> {
    const CEILING: usize = 8 * 1024 * 1024;
    eliot_dreamer_contracts::check_vec_bound(items.len(), 1_024, "request.supplied_items")?;
    let mut total = 0_usize;
    for item in items {
        let Some(material) = &item.material else {
            continue;
        };
        let bytes = match &material.representation {
            MaterialRepresentation::Utf8 { content, .. } => content.len(),
            MaterialRepresentation::Bytes { content, .. } => content.len(),
            MaterialRepresentation::HandleOnly { .. } => 0,
        };
        total = total.checked_add(bytes).ok_or(ContractViolation::Budget {
            dimension: "assembly_carrier",
            reason: "raw representation byte count overflows the assembly ceiling".to_owned(),
        })?;
        if total > CEILING {
            return Err(ContractViolation::Budget {
                dimension: "assembly_carrier",
                reason: "raw supplied representations exceed the retained assembly ceiling"
                    .to_owned(),
            });
        }
    }
    Ok(())
}
