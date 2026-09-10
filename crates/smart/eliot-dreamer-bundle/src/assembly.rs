//! Immutable A04 material-carrier construction.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::assembly::{
    AssemblyMaterial, AssemblyMaterialSet, ConditionalEvaluationState, ContributionMeasurement,
    DreamInputRole, MaterialDisposition, MaterialLedgerEntry, MaterialOutcomeReason,
    RoleDisposition, RoleOutcome, RoleOutcomeState, SuppliedItemIdentity, material_schema_version,
};
use eliot_dreamer_contracts::bundle::SourceDisposition;
use eliot_dreamer_contracts::{ContractViolation, CurationMaterial, JobClass};

use crate::budget::CoreBudgetAccounting;
use crate::input::{NormalizedAssemblyInput, SuppliedItemState};
use crate::recipe::{CoreAssemblyPlan, RoleDemand};

struct SelectedSourceMaterials {
    materials: Vec<AssemblyMaterial>,
    references: BTreeMap<
        eliot_contracts::ArtifactId,
        eliot_dreamer_contracts::grounding::AuthorizedReference,
    >,
    measurements: Vec<ContributionMeasurement>,
}

/// Opaque frozen plan state retained between A04 planning and finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssemblyPlan {
    pub(crate) input: NormalizedAssemblyInput,
    carrier: AssemblyMaterialSet,
    model_input: Vec<u8>,
    model_input_digest: String,
    budget: CoreBudgetAccounting,
    pub(crate) core: CoreAssemblyPlan,
}

impl AssemblyPlan {
    /// Return the frozen normalized operation input.
    pub(crate) const fn input(&self) -> &NormalizedAssemblyInput {
        &self.input
    }

    /// Return the validated immutable material carrier.
    pub fn carrier(&self) -> &AssemblyMaterialSet {
        &self.carrier
    }

    /// Return the exact canonical model-visible bytes.
    pub fn model_input(&self) -> &[u8] {
        &self.model_input
    }

    /// Return the digest bound to the exact model-visible bytes.
    pub fn model_input_digest(&self) -> &str {
        &self.model_input_digest
    }

    /// Return the exact serializer/profile frozen at planning time.
    pub fn measurement_profile(&self) -> &eliot_context_contracts::MeasurementCompositionProfile {
        &self.input.measurement_profile
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        NormalizedAssemblyInput,
        AssemblyMaterialSet,
        Vec<u8>,
        String,
        CoreAssemblyPlan,
        CoreBudgetAccounting,
    ) {
        (
            self.input,
            self.carrier,
            self.model_input,
            self.model_input_digest,
            self.core,
            self.budget,
        )
    }

    /// Return the exact pre-execution budget observations.
    pub(crate) const fn budget(&self) -> &CoreBudgetAccounting {
        &self.budget
    }
}

/// Freeze core planning state and compute canonical pre-execution accounting.
pub(crate) fn build_plan(
    input: &NormalizedAssemblyInput,
    core: &CoreAssemblyPlan,
) -> Result<AssemblyPlan, ContractViolation> {
    let packed = crate::packing::pack_optionals(input, core)?;
    let carrier = build_material_set(input, &packed)?;
    let model_input = carrier.model_input_bytes()?;
    let model_input_digest = carrier.model_input_digest()?;
    let budget = crate::budget::compute_core_budget(input, &carrier, &model_input)?;
    Ok(AssemblyPlan {
        input: input.clone(),
        carrier,
        model_input,
        model_input_digest,
        budget,
        core: packed,
    })
}

/// Construct and validate the immutable carrier handed to later packing and
/// finalization phases.
pub(crate) fn build_material_set(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
) -> Result<AssemblyMaterialSet, ContractViolation> {
    validate_contiguous_ordinals(input)?;
    let selected: BTreeSet<_> = plan.selected.iter().cloned().collect();
    let selected_materials = selected_source_materials(input, plan, &selected)?;
    let ledger = build_ledger(input, plan, &selected)?;
    let role_outcomes = build_role_outcomes(input, plan, &selected)?;
    let curation = closed_curation(input, &selected)?;
    let material_set = AssemblyMaterialSet {
        schema_version: material_schema_version(),
        recipe: input.recipe.clone(),
        manifest: input.manifest.clone(),
        selected_references: selected_materials.references,
        selected_manifest_digest: String::new(),
        materials: selected_materials.materials,
        ledger,
        supplied_items: input.supplied_identities.clone(),
        role_outcomes,
        conditional_evaluations: plan.conditional_evaluations.clone(),
        measurements: selected_materials.measurements,
        context: input.context.clone(),
        curation,
    };
    let selected_manifest_digest = material_set.computed_selected_manifest_digest()?;
    let mut material_set = material_set;
    material_set.selected_manifest_digest = selected_manifest_digest;
    material_set.validate()?;
    material_set.model_input_bytes()?;
    Ok(material_set)
}

fn validate_contiguous_ordinals(input: &NormalizedAssemblyInput) -> Result<(), ContractViolation> {
    for role in &input.recipe.roles {
        let mut ordinals = input
            .supplied_identities
            .iter()
            .filter(|identity| identity.role == role.role)
            .map(|identity| identity.ordinal)
            .collect::<Vec<_>>();
        ordinals.sort_unstable();
        for (expected, actual) in ordinals.iter().enumerate() {
            if u32::try_from(expected) != Ok(*actual) {
                return Err(ContractViolation::BindingMismatch {
                    field: "request.supplied_items.ordinal",
                    reason: "supplied role ordinals must remain contiguous from zero".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn selected_source_materials(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<SelectedSourceMaterials, ContractViolation> {
    let mut materials = Vec::new();
    let mut selected_references = BTreeMap::new();
    let mut measurements = Vec::new();
    for identity in selected {
        let Some(handle) = identity.handle.as_ref() else {
            continue;
        };
        let item = input
            .supplied_items
            .iter()
            .find(|item| item.identity == *identity)
            .ok_or(ContractViolation::BindingMismatch {
                field: "material.selected_items",
                reason: "selected source identity is absent from the supplied pool".to_owned(),
            })?;
        let mut material = item
            .material
            .clone()
            .ok_or(ContractViolation::MissingField(
                "material.selected.material",
            ))?;
        material.material.disposition = source_disposition(input, plan, identity)?;
        let reference = input.manifest.references.get(handle).cloned().ok_or(
            ContractViolation::BindingMismatch {
                field: "material.selected.reference",
                reason: "selected source identity is absent from the frozen manifest".to_owned(),
            },
        )?;
        let measurement = item
            .measurement
            .clone()
            .ok_or(ContractViolation::MissingField(
                "material.selected.measurement",
            ))?;
        selected_references.insert(handle.clone(), reference);
        measurements.push(measurement);
        materials.push(material);
    }
    Ok(SelectedSourceMaterials {
        materials,
        references: selected_references,
        measurements,
    })
}

fn source_disposition(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    identity: &SuppliedItemIdentity,
) -> Result<SourceDisposition, ContractViolation> {
    let role = input
        .recipe
        .roles
        .iter()
        .find(|role| role.role == identity.role)
        .ok_or(ContractViolation::BindingMismatch {
            field: "material.selected.role",
            reason: "selected source identity names no recipe role".to_owned(),
        })?;
    if role.disposition == RoleDisposition::Conditional {
        return Ok(SourceDisposition::Conditional);
    }
    let promoted = plan.core_selected.iter().any(|core| core == identity)
        || role.protected
        || role.omission_policy
            == eliot_dreamer_contracts::assembly::RoleOmissionPolicy::NonDroppable;
    if role.disposition == RoleDisposition::Required || promoted {
        Ok(SourceDisposition::Required)
    } else {
        Ok(SourceDisposition::Optional)
    }
}

fn build_ledger(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Vec<MaterialLedgerEntry>, ContractViolation> {
    input
        .supplied_identities
        .iter()
        .map(|identity| ledger_entry(input, plan, identity, selected.contains(identity)))
        .collect()
}

fn ledger_entry(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    identity: &SuppliedItemIdentity,
    is_selected: bool,
) -> Result<MaterialLedgerEntry, ContractViolation> {
    if is_selected {
        return Ok(MaterialLedgerEntry {
            role: identity.role,
            ordinal: identity.ordinal,
            handle: identity.handle.clone(),
            content_digest: identity.content_digest.clone(),
            source_revision: identity.source_revision.clone(),
            disposition: MaterialDisposition::Included,
            reason: None,
            omission: None,
            note: None,
            omission_accounting: None,
        });
    }
    if let Some(omission) = plan
        .omissions
        .iter()
        .find(|omission| omission.identity == *identity)
    {
        let item = input
            .supplied_items
            .iter()
            .find(|item| item.identity == *identity)
            .ok_or(ContractViolation::BindingMismatch {
                field: "material.ledger.omission",
                reason: "planned omission identity is absent from the supplied pool".to_owned(),
            })?;
        return Ok(MaterialLedgerEntry {
            role: identity.role,
            ordinal: identity.ordinal,
            handle: identity.handle.clone(),
            content_digest: identity.content_digest.clone(),
            source_revision: identity.source_revision.clone(),
            disposition: MaterialDisposition::Omitted,
            reason: Some(omission.reason),
            omission: item.omission.clone(),
            note: item.note.clone(),
            omission_accounting: Some(omission.accounting.clone()),
        });
    }
    if let Some(deferred) = plan
        .deferred
        .iter()
        .find(|deferred| deferred.identity == *identity)
    {
        let item = input
            .supplied_items
            .iter()
            .find(|item| item.identity == *identity);
        return Ok(MaterialLedgerEntry {
            role: identity.role,
            ordinal: identity.ordinal,
            handle: identity.handle.clone(),
            content_digest: identity.content_digest.clone(),
            source_revision: identity.source_revision.clone(),
            disposition: MaterialDisposition::Blocked,
            reason: Some(deferred.reason),
            omission: item.and_then(|item| item.omission.clone()),
            note: item.and_then(|item| item.note.clone()).or_else(|| {
                Some("candidate retained as blocked after an atomic selection trial".to_owned())
            }),
            omission_accounting: None,
        });
    }
    Ok(unselected_entry(input, identity))
}

fn unselected_entry(
    input: &NormalizedAssemblyInput,
    identity: &SuppliedItemIdentity,
) -> MaterialLedgerEntry {
    let item = input
        .supplied_items
        .iter()
        .find(|item| item.identity == *identity);
    let (disposition, reason, note) = match item.map(|item| item.state) {
        Some(SuppliedItemState::Unavailable(reason)) => (
            MaterialDisposition::Unavailable,
            reason,
            item.and_then(|item| item.note.clone()),
        ),
        Some(SuppliedItemState::Blocked(reason)) => (
            MaterialDisposition::Blocked,
            reason,
            item.and_then(|item| item.note.clone()),
        ),
        Some(SuppliedItemState::Available)
            if item.is_some_and(|item| item.measurement.is_none()) =>
        {
            (
                MaterialDisposition::Blocked,
                MaterialOutcomeReason::Unknown,
                Some("owner did not supply a qualified contribution measurement".to_owned()),
            )
        }
        Some(SuppliedItemState::Available) | None => (
            MaterialDisposition::Blocked,
            MaterialOutcomeReason::Unprocessed,
            Some("item was not selected in the core plan".to_owned()),
        ),
    };
    MaterialLedgerEntry {
        role: identity.role,
        ordinal: identity.ordinal,
        handle: identity.handle.clone(),
        content_digest: identity.content_digest.clone(),
        source_revision: identity.source_revision.clone(),
        disposition,
        reason: Some(reason),
        omission: item.and_then(|item| item.omission.clone()),
        note,
        omission_accounting: None,
    }
}

fn build_role_outcomes(
    input: &NormalizedAssemblyInput,
    plan: &CoreAssemblyPlan,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Vec<RoleOutcome>, ContractViolation> {
    input
        .recipe
        .roles
        .iter()
        .map(|role| {
            let supplied_count = count_role(&input.supplied_identities, role.role)?;
            let retained_count =
                count_role(&selected.iter().cloned().collect::<Vec<_>>(), role.role)?;
            let demand = plan
                .demands
                .iter()
                .find(|demand| demand.role == role.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.role_outcomes",
                    reason: "core plan is missing a recipe role demand".to_owned(),
                })?;
            let condition = plan
                .conditional_evaluations
                .iter()
                .find(|evaluation| evaluation.role == role.role);
            let (state, reason) = role_outcome_state(
                role.disposition,
                supplied_count,
                retained_count,
                demand,
                condition.map(|evaluation| evaluation.state),
            );
            Ok(RoleOutcome {
                role: role.role,
                state,
                supplied_count,
                retained_count,
                reason,
            })
        })
        .collect()
}

fn role_outcome_state(
    disposition: RoleDisposition,
    supplied_count: u32,
    retained_count: u32,
    demand: &RoleDemand,
    condition: Option<ConditionalEvaluationState>,
) -> (RoleOutcomeState, Option<MaterialOutcomeReason>) {
    if disposition == RoleDisposition::NotApplicable {
        return (RoleOutcomeState::NotApplicable, None);
    }
    if condition == Some(ConditionalEvaluationState::KnownFalse) {
        return (
            if supplied_count == 0 {
                RoleOutcomeState::KnownEmpty
            } else {
                RoleOutcomeState::Applicable
            },
            None,
        );
    }
    if supplied_count == 0 {
        return match condition {
            Some(ConditionalEvaluationState::Unresolved) => (
                RoleOutcomeState::Unresolved,
                Some(MaterialOutcomeReason::Unknown),
            ),
            Some(ConditionalEvaluationState::True) => (
                RoleOutcomeState::Missing,
                Some(MaterialOutcomeReason::Missing),
            ),
            None if disposition == RoleDisposition::Required => (
                RoleOutcomeState::Missing,
                Some(MaterialOutcomeReason::Missing),
            ),
            None => (RoleOutcomeState::KnownEmpty, None),
            Some(ConditionalEvaluationState::KnownFalse) => (
                if supplied_count == 0 {
                    RoleOutcomeState::KnownEmpty
                } else {
                    RoleOutcomeState::Applicable
                },
                None,
            ),
        };
    }
    if condition == Some(ConditionalEvaluationState::Unresolved) {
        return (
            RoleOutcomeState::Unresolved,
            Some(MaterialOutcomeReason::Unknown),
        );
    }
    if retained_count < demand.requested {
        return (
            RoleOutcomeState::Unresolved,
            Some(MaterialOutcomeReason::Missing),
        );
    }
    (RoleOutcomeState::Applicable, None)
}

fn count_role(
    identities: &[SuppliedItemIdentity],
    role: DreamInputRole,
) -> Result<u32, ContractViolation> {
    u32::try_from(
        identities
            .iter()
            .filter(|identity| identity.role == role)
            .count(),
    )
    .map_err(|_| ContractViolation::Budget {
        dimension: "source_width",
        reason: "role count exceeds the finite assembly ledger bound".to_owned(),
    })
}

fn closed_curation(
    input: &NormalizedAssemblyInput,
    selected: &BTreeSet<SuppliedItemIdentity>,
) -> Result<Option<CurationMaterial>, ContractViolation> {
    let Some(curation) = input.curation.as_ref() else {
        return Ok(None);
    };
    for evidence in &curation.payload.facets().evidence_refs {
        eliot_contracts::ArtifactId::new(evidence.as_str()).map_err(|_| {
            ContractViolation::BindingMismatch {
                field: "assembly.curation.evidence_refs",
                reason: "Curation evidence reference is not a valid artifact identity".to_owned(),
            }
        })?;
    }
    let job = &input.recipe.job;
    if job.job_class != JobClass::Curation {
        return Err(ContractViolation::BindingMismatch {
            field: "assembly.curation",
            reason: "Curation material is only valid for a Curation job".to_owned(),
        });
    }
    curation.validate_for(&job.task_id, &job.scope_id, &job.state_fence)?;
    if curation.source_snapshot != input.manifest.source_snapshot
        || curation.source_revision != input.manifest.source_revision
    {
        return Err(ContractViolation::BindingMismatch {
            field: "assembly.curation.source_snapshot",
            reason: "Curation source identity differs from the frozen manifest".to_owned(),
        });
    }
    let required = [
        (
            DreamInputRole::CurationSourceSnapshot,
            &curation.source_snapshot_ref,
        ),
        (
            DreamInputRole::CurationSourceDenominator,
            &curation.source_denominator_ref,
        ),
        (
            DreamInputRole::CurationScreenProfile,
            &curation.screen_profile_ref,
        ),
        (
            DreamInputRole::CurationProtectionCoverage,
            &curation.protection_coverage_contract,
        ),
    ];
    if required.iter().any(|(role, handle)| {
        !selected
            .iter()
            .any(|identity| identity.role == *role && identity.handle.as_ref() == Some(*handle))
    }) {
        return Ok(None);
    }
    for evidence in &curation.payload.facets().evidence_refs {
        let handle = eliot_contracts::ArtifactId::new(evidence.as_str()).map_err(|_| {
            ContractViolation::BindingMismatch {
                field: "assembly.curation.evidence_refs",
                reason: "Curation evidence reference is not a valid artifact identity".to_owned(),
            }
        })?;
        if !selected.iter().any(|identity| {
            identity.role == DreamInputRole::CurationEvidenceSet
                && identity.handle.as_ref() == Some(&handle)
        }) {
            return Ok(None);
        }
    }
    if curation.target_materials.values().any(|handle| {
        !selected.iter().any(|identity| {
            identity.role == DreamInputRole::CurationTargetSet
                && identity.handle.as_ref() == Some(handle)
        })
    }) {
        return Ok(None);
    }
    Ok(Some(curation.clone()))
}
