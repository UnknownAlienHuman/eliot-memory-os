use eliot_learning_contracts::{
    ChangeOperation, ChangeSurface, InverseChange, OverlayChange, OverlayOrigin, SlotDisposition,
    ValueState,
};

use crate::{OverlayComposeInput, OverlayError, base};

pub(crate) fn collect_changes(
    input: &OverlayComposeInput<'_>,
) -> Result<Vec<OverlayChange>, OverlayError> {
    let slots = base::slot_map(input)?;
    let mut changes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for delta in input.deltas {
        if delta.binding != input.view.binding || delta.target != input.view.target {
            return Err(OverlayError::Contract(
                eliot_learning_contracts::LearningContractError::ScopeMismatch {
                    field: "delta.binding",
                },
            ));
        }
        if !delta.dependencies.is_empty() {
            return Err(OverlayError::Unsupported {
                field: "delta.dependencies",
            });
        }
        delta.validate_against_view(input.view)?;
        for operation in &delta.changes {
            let target = operation.target().as_str();
            let (spec, projection) =
                slots
                    .get(target)
                    .copied()
                    .ok_or(OverlayError::Unsupported {
                        field: "change.target",
                    })?;
            if !seen.insert(target) {
                return Err(OverlayError::Conflict {
                    field: "change.target",
                });
            }
            changes.push(build_change(operation, spec, projection)?);
        }
    }
    if changes.is_empty() {
        return Err(OverlayError::Unsupported {
            field: "deltas.changes",
        });
    }
    changes.sort_by(|left, right| left.target.as_str().cmp(right.target.as_str()));
    Ok(changes)
}

fn build_change(
    operation: &ChangeOperation,
    spec: &eliot_learning_contracts::SlotSpec,
    projection: &eliot_learning_contracts::SlotProjection,
) -> Result<OverlayChange, OverlayError> {
    let surface = match operation {
        ChangeOperation::Replace { surface, .. }
        | ChangeOperation::Add { surface, .. }
        | ChangeOperation::Remove { surface, .. } => *surface,
    };
    if !matches!(
        surface,
        ChangeSurface::VerificationOrder | ChangeSurface::SearchProbeStopping
    ) {
        return Err(OverlayError::Unsupported {
            field: "change.surface",
        });
    }
    let (base, proposed, inverse) = match operation {
        ChangeOperation::Add {
            target,
            after,
            surface,
        } => {
            if projection.disposition != SlotDisposition::KnownEmpty
                || !spec.declared_members.is_empty()
                || !projection.members.is_empty()
                || projection.evidence.is_empty()
            {
                return Err(OverlayError::Unsupported {
                    field: "change.add",
                });
            }
            (
                ValueState {
                    present: false,
                    digest: None,
                },
                after.clone(),
                ChangeOperation::Remove {
                    target: target.clone(),
                    surface: *surface,
                    before: after.clone(),
                },
            )
        }
        ChangeOperation::Remove {
            target,
            before,
            surface,
        } => {
            base::current_member(spec, projection, before)?;
            (
                before.clone(),
                ValueState {
                    present: false,
                    digest: None,
                },
                ChangeOperation::Add {
                    target: target.clone(),
                    surface: *surface,
                    after: before.clone(),
                },
            )
        }
        ChangeOperation::Replace {
            target,
            before,
            after,
            surface,
        } => {
            base::current_member(spec, projection, before)?;
            (
                before.clone(),
                after.clone(),
                ChangeOperation::Replace {
                    target: target.clone(),
                    surface: *surface,
                    before: after.clone(),
                    after: before.clone(),
                },
            )
        }
    };
    let change = OverlayChange {
        target: operation.target().clone(),
        surface,
        base,
        proposed,
        inverse: InverseChange {
            forward_target: operation.target().clone(),
            inverse,
        },
        origin: OverlayOrigin::Overlay,
    };
    change.validate()?;
    Ok(change)
}
