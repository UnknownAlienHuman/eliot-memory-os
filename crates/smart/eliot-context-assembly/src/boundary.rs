//! Boundary preservation adapter for the A-18 admission-to-render transform.
//!
//! This is the narrow adapter the shared boundary contract needs in order to stop
//! being caller-less. It is a *preservation* adapter: it projects the admitted set
//! into boundary envelopes without changing membership, and it emits the exact
//! input-to-output member relation the contract requires, so a later readback can
//! prove that two adjacent outputs from different sources stayed separately
//! addressable with their own scope, fence and source order.
//!
//! It does not re-rank, re-admit, merge, or synthesize. Each rendered atom keeps
//! its own source snapshot and task/scope/fence binding, and its admitted source
//! order. The role/provider/atom sort applied later during rendering is
//! presentation order and is deliberately not recorded as source order.

pub use eliot_context_contracts::{
    assembly_boundary_limits, boundary_binding_digest, read_back_boundaries,
    verify_boundary_binding,
};

use eliot_context_contracts::{
    AdmissionDisposition, AdmittedAtom, AdmittedContextSet, AtomRepresentation,
    BOUNDARY_METADATA_SCHEMA_REVISION, BoundaryCompleteness, BoundaryDenominator,
    BoundaryDisposition, BoundaryDispositionRecord, BoundaryMember, BoundaryMemberCoverage,
    BoundaryMemberOrigin, BoundaryMemberReference, BoundaryMemberRelation, BoundaryMemberRole,
    BoundaryMetadataEnvelope, BoundaryMetadataSet, BoundaryPrecision, BoundaryRecovery,
    BoundaryTransformRelation, BoundaryTransformerRevision, BoundaryUnitKind, ContextBinding,
    ContextError, ContextRecipe,
};
use eliot_contracts::{ArtifactId, ContractVersion, sha256_hex};

/// Stable transformer identity for the A-18 admission-to-render projection.
pub const BOUNDARY_ASSEMBLY_TRANSFORMER_ID: &str = "context.assembly.render";

/// Contract revision of the A-18 boundary projection.
pub const BOUNDARY_ASSEMBLY_TRANSFORMER_REVISION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Project one admitted set into a validated, digest-bound boundary metadata set.
///
/// The parent batch declares a denominator of exactly the admitted source order of
/// the atoms this projection renders, and retains exactly those members in that same
/// order. Presentation sorting happens afterwards, so declared source order is
/// recorded here rather than recovered from the rendered sequence.
///
/// An admitted set with no renderable atom yields an empty set rather than a
/// synthetic empty batch: a batch with no declared member is not a complete unit.
pub fn project_assembly_boundaries(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
) -> Result<BoundaryMetadataSet, ContextError> {
    let rendered = renderable_atoms(admitted);
    if rendered.is_empty() {
        let empty = BoundaryMetadataSet {
            units: Vec::new(),
            transforms: Vec::new(),
            boundary_digest: String::new(),
        }
        .bind_recorded_digest()?;
        empty.validate(&assembly_boundary_limits())?;
        return Ok(empty);
    }

    let mut units = Vec::with_capacity(rendered.len() + 1);
    for (order, record) in rendered.iter().enumerate() {
        units.push(unit_envelope(
            admitted,
            recipe,
            record,
            u64::try_from(order).map_err(|_| ContextError::Overflow)?,
        ));
    }
    let batch_unit_id = batch_unit_id(&admitted.binding, rendered.len())?;
    units.push(batch_envelope(
        admitted,
        recipe,
        batch_unit_id.clone(),
        &rendered,
    ));

    let set = BoundaryMetadataSet {
        units,
        transforms: vec![batch_transform(recipe, batch_unit_id, &rendered)],
        boundary_digest: String::new(),
    }
    .bind_recorded_digest()?;
    set.validate(&assembly_boundary_limits())?;
    Ok(set)
}

/// Admitted atoms this projection renders, in admitted source order.
fn renderable_atoms(admitted: &AdmittedContextSet) -> Vec<&AdmittedAtom> {
    admitted
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            )
        })
        .collect()
}

/// Project one admitted atom into its own independently addressable unit.
fn unit_envelope(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    record: &AdmittedAtom,
    source_order: u64,
) -> BoundaryMetadataEnvelope {
    let candidate = &record.candidate;
    let member_id = candidate.atom_id.clone();
    BoundaryMetadataEnvelope {
        unit_id: member_id.clone(),
        unit_kind: BoundaryUnitKind::Unit,
        binding: admitted.binding.clone(),
        source: Some(candidate.source.clone()),
        source_attempt_id: Some(admitted.binding.attempt_id.clone()),
        source_stage: Some(BOUNDARY_ASSEMBLY_TRANSFORMER_ID.to_string()),
        source_order: Some(source_order),
        coverage: BoundaryMemberCoverage {
            denominator: BoundaryDenominator::Declared(vec![BoundaryMember {
                order: 0,
                role: BoundaryMemberRole::SourceMember,
                reference: BoundaryMemberReference::SourceMember {
                    member_id: member_id.clone(),
                    range: None,
                },
            }]),
            retained_members: vec![member_id],
            known_gaps: Vec::new(),
        },
        provenance_refs: candidate.dependencies.clone(),
        disclosure_refs: Vec::new(),
        influence_closure_refs: Vec::new(),
        omission_refs: Vec::new(),
        expansion_refs: expansion_handle(record),
        completeness: BoundaryCompleteness::Complete,
        precision: BoundaryPrecision::Exact,
        disposition: unit_disposition(record),
        schema_revision: BOUNDARY_METADATA_SCHEMA_REVISION,
        transformer: Some(transformer_revision(recipe)),
    }
}

/// The exact expansion handle this record's own representation names, if any.
///
/// The handle comes from the admitted `AtomRepresentation::Handle`, never from a
/// name this projection invents, so an unavailable or forbidden original cannot
/// acquire a handle here.
fn expansion_handle(record: &AdmittedAtom) -> Vec<ArtifactId> {
    match &record.candidate.representation {
        AtomRepresentation::Handle { handle } => vec![handle.clone()],
        AtomRepresentation::Whole { .. }
        | AtomRepresentation::Extractive { .. }
        | AtomRepresentation::Summary { .. } => Vec::new(),
    }
}

/// The permitted degradation this admitted record already declares, if any.
///
/// A `HandleOnly` admission carries the atom as an exact expansion handle, so the
/// envelope records `ExactHandleOnly` and names the handle a consumer reopens
/// through. A `Whole`, `Extractive` or `Summary` representation is rendered from
/// its producer-issued form, so the assembly projection preserves it exactly and
/// adds no disposition of its own. Assembly never invents a degradation the
/// admission decision did not make, and never grants launch authority.
fn unit_disposition(record: &AdmittedAtom) -> Option<BoundaryDispositionRecord> {
    if record.disposition != AdmissionDisposition::HandleOnly {
        return None;
    }
    let AtomRepresentation::Handle { handle } = &record.candidate.representation else {
        return None;
    };
    Some(BoundaryDispositionRecord {
        disposition: BoundaryDisposition::ExactHandleOnly,
        reason: "admitted as an exact expansion handle without content".to_string(),
        rule_evidence: record.rule_evidence.clone(),
        delivered_precision: BoundaryPrecision::Exact,
        recovery: BoundaryRecovery::ExpansionHandles(vec![handle.clone()]),
        grants_launch_authority: false,
    })
}

/// The parent batch: a source-less composite referencing each child by identity.
fn batch_envelope(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    unit_id: ArtifactId,
    rendered: &[&AdmittedAtom],
) -> BoundaryMetadataEnvelope {
    let members: Vec<BoundaryMember> = rendered
        .iter()
        .enumerate()
        .map(|(order, record)| BoundaryMember {
            order: u64::try_from(order).unwrap_or(u64::MAX),
            role: BoundaryMemberRole::ChildUnit,
            reference: BoundaryMemberReference::ChildUnit {
                unit_id: record.candidate.atom_id.clone(),
            },
        })
        .collect();
    let retained = members
        .iter()
        .map(|member| match &member.reference {
            BoundaryMemberReference::ChildUnit { unit_id } => unit_id.clone(),
            BoundaryMemberReference::SourceMember { member_id, .. } => member_id.clone(),
        })
        .collect();
    BoundaryMetadataEnvelope {
        unit_id,
        unit_kind: BoundaryUnitKind::Batch,
        binding: admitted.binding.clone(),
        source: None,
        source_attempt_id: None,
        source_stage: None,
        source_order: None,
        coverage: BoundaryMemberCoverage {
            denominator: BoundaryDenominator::Declared(members),
            retained_members: retained,
            known_gaps: Vec::new(),
        },
        provenance_refs: Vec::new(),
        disclosure_refs: Vec::new(),
        influence_closure_refs: Vec::new(),
        omission_refs: Vec::new(),
        expansion_refs: Vec::new(),
        completeness: BoundaryCompleteness::Complete,
        precision: BoundaryPrecision::Exact,
        // A batch references each child by identity and inherits no disposition of
        // its own: each child states its own degradation, so the parent cannot
        // present a handle-only or extractive child as a complete one.
        disposition: None,
        schema_revision: BOUNDARY_METADATA_SCHEMA_REVISION,
        transformer: Some(transformer_revision(recipe)),
    }
}
/// The exact input-to-output member relation this one transform emitted.
fn batch_transform(
    recipe: &ContextRecipe,
    output_unit_id: ArtifactId,
    rendered: &[&AdmittedAtom],
) -> BoundaryTransformRelation {
    BoundaryTransformRelation {
        transformer: transformer_revision(recipe),
        output_unit_id,
        member_relations: rendered
            .iter()
            .map(|record| BoundaryMemberRelation {
                input_unit_id: record.candidate.atom_id.clone(),
                input_member_id: record.candidate.atom_id.clone(),
                output_member_id: record.candidate.atom_id.clone(),
                origin: BoundaryMemberOrigin::Retained,
            })
            .collect(),
    }
}

fn transformer_revision(recipe: &ContextRecipe) -> BoundaryTransformerRevision {
    BoundaryTransformerRevision {
        transformer_id: BOUNDARY_ASSEMBLY_TRANSFORMER_ID.to_string(),
        revision: BOUNDARY_ASSEMBLY_TRANSFORMER_REVISION,
        configuration_sha256: recipe.recipe_sha256.clone(),
    }
}

/// Deterministic parent identity derived from the admitted decision identity.
///
/// It is deliberately distinct from every child unit identity, so a parent batch can
/// never be mistaken for one of the units it references.
fn batch_unit_id(binding: &ContextBinding, child_count: usize) -> Result<ArtifactId, ContextError> {
    let raw = format!(
        "{BOUNDARY_ASSEMBLY_TRANSFORMER_ID}:{}:{}:{}:{child_count}",
        binding.task_id.as_str(),
        binding.decision_id.as_str(),
        binding.scope_id.as_str()
    );
    ArtifactId::new(format!("boundary-batch-{}", sha256_hex(raw.as_bytes())))
        .map_err(|_| ContextError::InvalidField("boundary.batch_unit_id"))
}
