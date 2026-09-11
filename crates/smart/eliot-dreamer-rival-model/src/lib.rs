//! Candidate-only structuring of retained, typed rival declarations.
//!
//! This crate preserves supplied rival models and their uncertainty for a
//! later consumer. It performs bounded input binding and returns a retained
//! declaration carrier; it does not select a winner, execute an experiment,
//! or promote a position to current truth.

#![forbid(unsafe_code)]

mod analysis;
mod bounds;
mod comparison;
mod dependencies;
mod equivalence;
mod error;
mod meter;
mod model_detail;
mod packing;
mod policy;
mod result;
mod states;
mod unknown;

pub use analysis::{
    DiscriminatorOutcome, DiscriminatorPeerAddress, DiscriminatorRequirement,
    DiscriminatorRequirementFacet, DiscriminatorRequirementReason, DiscriminatorSearch,
    InertDiscriminator, ModelDisposition, OmissionFrontier, RivalEquivalenceClass,
    RivalModelAssessment, SearchCompletion,
};
pub use comparison::{
    ComparisonCompletion, ComparisonField, ComparisonMap, ComparisonPhase, SharedInputGroup,
    SharedInputKind, SourceAddress,
};
pub use error::RivalModelError;
pub use model_detail::{ModelBodyOmissionReason, RivalModelDetail};
pub use policy::{
    RIVAL_POLICY_SCHEMA_VERSION, RivalOperationObservation, RivalPolicy, RivalPolicyLimits,
};
pub use result::{RIVAL_MODEL_SET_SCHEMA_VERSION, RivalModelDisposition, RivalModelSet};
pub use states::{
    ModelOmissionReason, ModelUnavailableReason, ModelUnknownReason, OutputSection, WorkStage,
};
pub use unknown::{UnknownField, UnknownSlotRef, UnknownTable};

use eliot_dreamer_contracts::rival::{
    CurrentPositionAvailability, CurrentPositionBinding, RivalCoverageDeclaration,
    RivalCoverageReceipt, RivalModelSlot,
};
use eliot_dreamer_contracts::{DreamInputBundle, ValidatedGroundingCandidate};
use eliot_epistemic_contracts::{CurrentEpistemicPosition, DenominatorKind};
use meter::{OperationMeter, SourceWidthObservation};
use std::collections::BTreeSet;

/// Structures supplied rival declarations after exact candidate and context
/// binding. The expected policy is local caller input; this function does not
/// treat a snapshot or declaration digest as an authority decision.
#[allow(
    clippy::too_many_lines,
    reason = "public pipeline preserves staged owner validation and shared resource bounds"
)]
pub fn structure_rival_models(
    bundle: &DreamInputBundle,
    validated_draft: &ValidatedGroundingCandidate,
    current_position: &CurrentEpistemicPosition,
    rival_policy: &RivalPolicy,
) -> Result<RivalModelSet, RivalModelError> {
    let _candidate_wire_bytes =
        bounds::preflight(validated_draft, bounds::MAX_CANDIDATE_WIRE_BYTES)?;
    bounds::preflight(bundle, bounds::MAX_CANDIDATE_WIRE_BYTES)?;
    bounds::preflight(current_position, bounds::MAX_CANDIDATE_WIRE_BYTES)?;
    bounds::preflight(rival_policy, 16 * 1024)?;
    let input_wire_bytes = bounds::preflight(
        &(bundle, validated_draft, current_position, rival_policy),
        bounds::MAX_RIVAL_WIRE_BYTES,
    )?;
    rival_policy.validate()?;
    if rival_policy.cancellation_requested || validated_draft.input.cancellation_requested {
        return Err(RivalModelError::Cancelled);
    }
    let work = bounds::candidate_work(validated_draft)?;
    let counts = bounds::candidate_domain_counts(validated_draft)?;
    let reference_width = bounds::candidate_reference_width(validated_draft)?;
    let source_width = candidate_source_width(validated_draft)?;
    let declarations = validated_draft
        .input
        .rival_declarations
        .as_ref()
        .ok_or(RivalModelError::MissingRivalDeclarations)?;
    let unknowns =
        unknown::collect_unknown_slots(declarations, &source_width.unknown_owner_handles)?;
    check_budget(
        validated_draft,
        &rival_policy.current_usage,
        input_wire_bytes,
        reference_width,
        source_width.upper_bound,
    )?;
    if u64::try_from(work).map_or(true, |work| work > rival_policy.max_work_units) {
        return Err(RivalModelError::Bound {
            field: "policy.max_work_units",
            maximum: usize::try_from(rival_policy.max_work_units).unwrap_or(usize::MAX),
            actual: work,
        });
    }
    for (field, actual, maximum) in [
        (
            "policy.max_material_items",
            counts.material,
            rival_policy.max_material_items,
        ),
        (
            "policy.max_reference_items",
            counts.reference,
            rival_policy.max_reference_items,
        ),
        (
            "policy.max_evidence_items",
            counts.evidence,
            rival_policy.max_evidence_items,
        ),
        (
            "policy.max_conflict_items",
            counts.conflict,
            rival_policy.max_conflict_items,
        ),
    ] {
        if actual > usize::try_from(maximum).unwrap_or(usize::MAX) {
            return Err(RivalModelError::Bound {
                field,
                maximum: usize::try_from(maximum).unwrap_or(usize::MAX),
                actual,
            });
        }
    }
    // `reserved_unknown_slots` is a minimum output reservation.  The actual
    // count is retained for result packing; it is never used as an input
    // rejection threshold here.
    if rival_policy.observed_elapsed_ms > rival_policy.max_elapsed_ms {
        return Err(RivalModelError::Bound {
            field: "policy.max_elapsed_ms",
            maximum: usize::try_from(rival_policy.max_elapsed_ms).unwrap_or(usize::MAX),
            actual: usize::try_from(rival_policy.observed_elapsed_ms).unwrap_or(usize::MAX),
        });
    }
    if rival_policy.observed_stu_used > rival_policy.max_stu {
        return Err(RivalModelError::Bound {
            field: "policy.max_stu",
            maximum: usize::try_from(rival_policy.max_stu).unwrap_or(usize::MAX),
            actual: usize::try_from(rival_policy.observed_stu_used).unwrap_or(usize::MAX),
        });
    }
    let grounded = &validated_draft.input.grounded;
    let observed_time = rival_policy.observation_time_ms;
    if let (Some(handler), Some(previous)) =
        (observed_time, validated_draft.input.observation_time_ms)
        && handler < previous
    {
        return Err(RivalModelError::IdentityMismatch(
            "operation_time_regression",
        ));
    }
    if rival_policy
        .deadline_ms
        .is_some_and(|deadline| observed_time.is_none_or(|observed| observed > deadline))
    {
        return Err(RivalModelError::IdentityMismatch("policy.deadline"));
    }
    if grounded
        .input
        .job
        .deadline_ms
        .is_some_and(|deadline| observed_time.is_none_or(|observed| observed > deadline))
    {
        return Err(RivalModelError::IdentityMismatch("job.deadline"));
    }

    validated_draft
        .validate_binding()
        .map_err(|_| RivalModelError::InvalidContract("validated_grounding_candidate"))?;
    bundle
        .validate()
        .map_err(|_| RivalModelError::InvalidContract("input_bundle"))?;
    if bundle != &grounded.input.bundle {
        return Err(RivalModelError::IdentityMismatch("bundle"));
    }
    if bundle.task_id != grounded.task_id.as_str() || bundle.scope_id != grounded.scope_id {
        return Err(RivalModelError::IdentityMismatch("task_or_scope"));
    }
    if bundle.state_fence != grounded.state_fence {
        return Err(RivalModelError::IdentityMismatch("state_fence"));
    }
    let position_binding = CurrentPositionBinding::from_view(current_position)
        .map_err(|_| RivalModelError::InvalidContract("current_position"))?;
    if current_position.admission.scope != bundle.scope_id
        || current_position.admission.fence != bundle.state_fence
    {
        return Err(RivalModelError::IdentityMismatch(
            "current_position_context",
        ));
    }
    declarations
        .validate()
        .map_err(|_| RivalModelError::InvalidContract("rival_declarations"))?;
    if declarations.task_id != grounded.task_id
        || declarations.scope != grounded.scope_id
        || declarations.state_fence != grounded.state_fence
    {
        return Err(RivalModelError::IdentityMismatch("rival_context"));
    }
    for slot in &declarations.models {
        let RivalModelSlot::Retained { declaration } = slot else {
            continue;
        };
        match &declaration.current_position {
            CurrentPositionAvailability::Referenced { binding } if binding != &position_binding => {
                return Err(RivalModelError::IdentityMismatch("model.current_position"));
            }
            CurrentPositionAvailability::Unknown {
                position_id: Some(position_id),
                ..
            } if position_id != &position_binding.position_id => {
                return Err(RivalModelError::IdentityMismatch("model.position_id"));
            }
            CurrentPositionAvailability::Unknown {
                position_revision: Some(revision),
                ..
            } if revision != &position_binding.position_revision => {
                return Err(RivalModelError::IdentityMismatch("model.position_revision"));
            }
            CurrentPositionAvailability::Unknown {
                view_digest: Some(digest),
                ..
            } if digest != &position_binding.view_digest => {
                return Err(RivalModelError::IdentityMismatch("model.view_digest"));
            }
            _ => {}
        }
    }

    let mut meter = OperationMeter::new(
        rival_policy.max_work_units,
        work,
        input_wire_bytes,
        unknowns,
        reference_width,
        source_width,
    )?;
    result::RivalModelSet::from_validated(
        validated_draft,
        position_binding,
        declarations,
        rival_policy,
        &mut meter,
    )
}

fn check_budget(
    candidate: &ValidatedGroundingCandidate,
    current_usage: &eliot_dreamer_contracts::BudgetUsage,
    input_wire_bytes: usize,
    reference_width: usize,
    source_width: usize,
) -> Result<(), RivalModelError> {
    let limits = &candidate.input.grounded.input.job.budget;
    limits
        .require_exact()
        .map_err(|_| RivalModelError::InvalidContract("job.budget"))?;
    let prior = &candidate.input.usage;
    check_measured("input_bytes", input_wire_bytes, limits.input_bytes)?;
    check_measured("reference_width", reference_width, limits.reference_width)?;
    check_measured("source_width", source_width, limits.source_width)?;
    let measured_reference_width =
        u64::try_from(reference_width).map_err(|_| RivalModelError::Bound {
            field: "reference_width",
            maximum: usize::MAX,
            actual: reference_width,
        })?;
    let measured_source_width =
        u64::try_from(source_width).map_err(|_| RivalModelError::Bound {
            field: "source_width",
            maximum: usize::MAX,
            actual: source_width,
        })?;
    let measured_input_bytes =
        u64::try_from(input_wire_bytes).map_err(|_| RivalModelError::Bound {
            field: "input_bytes",
            maximum: usize::MAX,
            actual: input_wire_bytes,
        })?;
    let current_input_bytes = current_usage.input_bytes.max(measured_input_bytes);
    let usage = eliot_dreamer_contracts::BudgetUsage {
        input_bytes: checked_usage("input_bytes", prior.input_bytes, current_input_bytes)?,
        output_bytes: checked_usage(
            "output_bytes",
            prior.output_bytes,
            current_usage.output_bytes,
        )?,
        source_width: prior
            .source_width
            .max(current_usage.source_width)
            .max(measured_source_width),
        reference_width: prior
            .reference_width
            .max(current_usage.reference_width)
            .max(measured_reference_width),
        model_calls: checked_usage("model_calls", prior.model_calls, current_usage.model_calls)?,
        attempts: checked_usage("attempts", prior.attempts, current_usage.attempts)?,
        candidates: checked_usage("candidates", prior.candidates, current_usage.candidates)?,
        wall_ms: checked_usage("wall_ms", prior.wall_ms, current_usage.wall_ms)?,
        work_fan_out: checked_usage(
            "work_fan_out",
            prior.work_fan_out,
            current_usage.work_fan_out,
        )?,
        report_bytes: checked_usage(
            "report_bytes",
            prior.report_bytes,
            current_usage.report_bytes,
        )?,
        stu_used: checked_usage("max_stu", prior.stu_used, current_usage.stu_used)?,
    };
    usage
        .fits(limits)
        .map_err(|_| RivalModelError::InvalidContract("job.budget.usage"))?;
    Ok(())
}

fn checked_usage(field: &'static str, prior: u64, current: u64) -> Result<u64, RivalModelError> {
    prior.checked_add(current).ok_or(RivalModelError::Bound {
        field,
        maximum: usize::MAX,
        actual: usize::MAX,
    })
}

fn check_measured(
    field: &'static str,
    actual: usize,
    limit: Option<u64>,
) -> Result<(), RivalModelError> {
    let limit = limit.ok_or(RivalModelError::InvalidContract("job.budget"))?;
    if u64::try_from(actual).map_or(true, |actual| actual > limit) {
        return Err(RivalModelError::Bound {
            field,
            maximum: usize::try_from(limit).unwrap_or(usize::MAX),
            actual,
        });
    }
    Ok(())
}

/// Returns a conservative source-owner width for consulted retained references.
///
/// Known `SourceId` owners are deduplicated. A retained reference without a
/// matching owner lineage, or an unavailable consulted source slot, contributes
/// one distinct unknown-owner handle so omission is not silently treated as a
/// known source. Bundle material and omission handles are not consulted owners.
fn candidate_source_width(
    candidate: &ValidatedGroundingCandidate,
) -> Result<SourceWidthObservation, RivalModelError> {
    let grounded = &candidate.input.grounded;
    let mut owners = BTreeSet::new();
    let mut known_handles = BTreeSet::<eliot_dreamer_contracts::grounding::ArtifactId>::new();
    let mut unknown_handles = BTreeSet::new();
    for reference in grounded.manifest.references.values() {
        add_source_owner(
            reference,
            &mut owners,
            &mut known_handles,
            &mut unknown_handles,
        );
    }
    if let Some(declarations) = candidate.input.rival_declarations.as_deref() {
        for slot in &declarations.sources {
            match slot {
                eliot_dreamer_contracts::rival::RivalSourceSlot::Retained { reference } => {
                    add_source_owner(
                        reference,
                        &mut owners,
                        &mut known_handles,
                        &mut unknown_handles,
                    );
                }
                eliot_dreamer_contracts::rival::RivalSourceSlot::Unavailable { handle, .. } => {
                    if !known_handles.contains(handle) {
                        unknown_handles.insert(handle.clone());
                    }
                }
            }
        }
    }
    for known_handle in &known_handles {
        unknown_handles.remove(known_handle);
    }
    let upper_bound =
        owners
            .len()
            .checked_add(unknown_handles.len())
            .ok_or(RivalModelError::Bound {
                field: "source_width",
                maximum: usize::MAX,
                actual: usize::MAX,
            })?;
    Ok(SourceWidthObservation {
        known_owner_count: owners.len(),
        unknown_owner_handles: unknown_handles,
        upper_bound,
    })
}

fn add_source_owner(
    reference: &eliot_dreamer_contracts::grounding::AuthorizedReference,
    owners: &mut BTreeSet<String>,
    known_handles: &mut BTreeSet<eliot_dreamer_contracts::grounding::ArtifactId>,
    unknown_handles: &mut BTreeSet<eliot_dreamer_contracts::grounding::ArtifactId>,
) {
    if let Some(lineage) = &reference.source_lineage {
        owners.insert(lineage.owner.as_str().to_owned());
        known_handles.insert(reference.handle.clone());
        return;
    }
    if let Some(provenance) = &reference.provenance
        && let Some(lineage) = provenance.lineage.iter().find(|lineage| {
            lineage.content_digest == reference.content_digest
                && lineage.revision == reference.source_revision
        })
    {
        owners.insert(lineage.owner.as_str().to_owned());
        known_handles.insert(reference.handle.clone());
    } else {
        unknown_handles.insert(reference.handle.clone());
    }
}

/// Reports whether the retained candidate has the narrow complete-input
/// precondition needed by later result packing. This is an intrinsic shape
/// predicate: it does not issue a receipt, authenticate evidence, or promote
/// any supplied declaration.
pub(crate) fn candidate_is_complete(candidate: &ValidatedGroundingCandidate) -> bool {
    if candidate.validated.receipt.terminal_disposition != "accepted"
        || candidate.input.preservation.overall().is_err()
    {
        return false;
    }
    let Some(declarations) = candidate.input.rival_declarations.as_deref() else {
        return false;
    };
    matches!(
        (
            &declarations.model_coverage,
            &declarations.source_coverage
        ),
        (
            RivalCoverageDeclaration::Supplied {
                denominator: model_denominator,
                receipt: RivalCoverageReceipt::Supplied {
                    receipt: model_receipt
                }
            },
            RivalCoverageDeclaration::Supplied {
                denominator: source_denominator,
                receipt: RivalCoverageReceipt::Supplied {
                    receipt: source_receipt
                }
            }
        ) if model_denominator.kind == DenominatorKind::CompleteScope
            && source_denominator.kind == DenominatorKind::CompleteScope
            && model_receipt.is_terminal()
            && source_receipt.is_terminal()
    )
}
