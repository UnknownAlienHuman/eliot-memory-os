//! Finite typed dependency graph checks for retained model declarations.

use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter};
use crate::states::WorkStage;
use eliot_dreamer_contracts::rival::{
    DeclarationAvailability, RivalDeclarationSet, RivalDependency, RivalModelDeclaration,
    RivalModelSlot,
};
use std::collections::{BTreeMap, BTreeSet};

#[allow(
    clippy::too_many_lines,
    reason = "dependency validation combines bounded indexing, ordering, and cycle checks"
)]
pub(crate) fn validate(
    set: &RivalDeclarationSet,
    meter: &mut OperationMeter,
) -> Result<(), RivalModelError> {
    if matches!(
        meter.charge(
            set.models.len(),
            WorkStage::DependencyRetainedCollection,
            None,
            None,
        )?,
        MeterCharge::Exhausted
    ) {
        return Ok(());
    }
    let mut retained = Vec::with_capacity(set.models.len());
    for slot in &set.models {
        let model_id = match slot {
            RivalModelSlot::Retained { declaration } => Some(&declaration.model_id),
            RivalModelSlot::Unavailable { model_id, .. } => Some(model_id),
        };
        if matches!(
            meter.charge(1, WorkStage::DependencyIndexEntry, model_id, None)?,
            MeterCharge::Exhausted
        ) {
            return Ok(());
        }
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        retained.push(declaration.as_ref());
    }
    if retained.len() > 256 {
        return Err(RivalModelError::Bound {
            field: "dependency_models",
            maximum: 256,
            actual: retained.len(),
        });
    }
    let mut index = BTreeMap::new();
    for (position, declaration) in retained.iter().enumerate() {
        if matches!(
            meter.charge(
                1,
                WorkStage::DependencyIndexInsert,
                Some(&declaration.model_id),
                None
            )?,
            MeterCharge::Exhausted
        ) {
            return Ok(());
        }
        index.insert(
            (
                declaration.model_id.as_str().to_owned(),
                declaration.model_revision,
            ),
            position,
        );
    }
    if matches!(
        meter.charge(retained.len(), WorkStage::DependencyEdgeTable, None, None)?,
        MeterCharge::Exhausted
    ) {
        return Ok(());
    }
    let mut edges = vec![Vec::new(); retained.len()];
    for (position, declaration) in retained.iter().enumerate() {
        if matches!(
            meter.charge(
                1,
                WorkStage::DependencyNode,
                Some(&declaration.model_id),
                None
            )?,
            MeterCharge::Exhausted
        ) {
            return Ok(());
        }
        let DeclarationAvailability::Supplied { entries } = &declaration.dependency_refs else {
            continue;
        };
        for dependency in entries {
            if matches!(
                meter.charge(
                    1,
                    WorkStage::DependencyReference,
                    Some(&declaration.model_id),
                    None
                )?,
                MeterCharge::Exhausted
            ) {
                return Ok(());
            }
            let RivalDependency::Model { reference } = dependency else {
                continue;
            };
            if matches!(
                meter.charge(
                    1,
                    WorkStage::DependencyEdge,
                    Some(&declaration.model_id),
                    Some((&declaration.model_id, &reference.model_id)),
                )?,
                MeterCharge::Exhausted
            ) {
                return Ok(());
            }
            if let Some(target) = index.get(&(
                reference.model_id.as_str().to_owned(),
                reference.model_revision,
            )) {
                if retained[*target].digest != reference.declaration_digest {
                    return Err(RivalModelError::InvalidContract("dependency_digest"));
                }
                edges[position].push(*target);
                continue;
            }
            let mut related = false;
            for candidate in &set.related_models {
                if matches!(
                    meter.charge(
                        1,
                        WorkStage::RelatedDependencyScan,
                        Some(&declaration.model_id),
                        None
                    )?,
                    MeterCharge::Exhausted
                ) {
                    return Ok(());
                }
                if candidate.reference == *reference {
                    related = true;
                    break;
                }
            }
            let mut unavailable = false;
            for slot in &set.models {
                if matches!(
                    meter.charge(
                        1,
                        WorkStage::UnavailableDependencyScan,
                        Some(&declaration.model_id),
                        None
                    )?,
                    MeterCharge::Exhausted
                ) {
                    return Ok(());
                }
                if let RivalModelSlot::Unavailable {
                    model_id,
                    model_revision,
                    declaration_digest,
                    ..
                } = slot
                    && model_id == &reference.model_id
                    && *model_revision == Some(reference.model_revision)
                    && declaration_digest.as_ref() == Some(&reference.declaration_digest)
                {
                    unavailable = true;
                    break;
                }
            }
            if !related && !unavailable {
                return Err(RivalModelError::InvalidContract(
                    "unresolved_model_dependency",
                ));
            }
        }
    }
    detect_cycle(&edges, &retained, meter)
}

fn detect_cycle(
    edges: &[Vec<usize>],
    models: &[&RivalModelDeclaration],
    meter: &mut OperationMeter,
) -> Result<(), RivalModelError> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for start in 0..edges.len() {
        if visited.contains(&start) {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((node, exiting)) = stack.pop() {
            if matches!(
                meter.charge(
                    1,
                    WorkStage::DependencyDfsNode,
                    Some(&models[node].model_id),
                    None
                )?,
                MeterCharge::Exhausted
            ) {
                return Ok(());
            }
            if exiting {
                visiting.remove(&node);
                visited.insert(node);
                continue;
            }
            if !visiting.insert(node) {
                return Err(RivalModelError::InvalidContract("dependency_cycle"));
            }
            stack.push((node, true));
            for target in edges[node].iter().rev() {
                if matches!(
                    meter.charge(
                        1,
                        WorkStage::DependencyDfsEdge,
                        Some(&models[node].model_id),
                        Some((&models[node].model_id, &models[*target].model_id)),
                    )?,
                    MeterCharge::Exhausted
                ) {
                    return Ok(());
                }
                if !visited.contains(target) {
                    stack.push((*target, false));
                }
            }
        }
    }
    Ok(())
}
