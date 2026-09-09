//! Deterministic, side-effect-free activation-to-delivery planning.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use eliot_context_contracts::{
    AttentionResolution, ContextPlanningView, CriticalAttentionMember, CriticalAttentionProjection,
    DecisionContextIncomplete, IntegrationCoverageProfile, ReactiveDeliveryMode,
    ReactiveInputError, SessionDeliverySnapshot, SnapshotCompleteness, canonical_planning_digest,
};
use eliot_contracts::{ArtifactId, OperationId, RequestId, canonical_json_bytes};
use eliot_cue_contracts::{ActivationResult, Completeness};
use eliot_protocol::{
    ReactiveContextContentRef, ReactiveContextPrivacy, ReactiveContextStage,
    reactive_context_contract_identity,
};
use eliot_receipts::ProofCeiling;

use crate::input::{AttentionDisclosureRule, ReactiveCueActivation, ReactiveDeliveryPolicy};
use crate::result::{
    ActivationEvidenceKind, DeliveryDisposition, InertDeliveryRequest, NoInjectionDisposition,
    PendingContextInjectionPlan, PlannedAttentionBinding, PlannedContextItem, PlannedItemKind,
    PlanningAccounting, PlanningErrorDisposition, PlanningErrorKind, ReactiveContextPlanResult,
    ReactiveContextPlanningError,
};

const MAX_DIAGNOSTIC: usize = 256;
const MAX_INERT_REQUEST_SERIALIZATION_PASSES: u64 = 6;

/// Plan one bounded pending Context injection from six immutable projections.
pub fn plan_pending_context_injection(
    view: &ContextPlanningView,
    cue_activation: &ReactiveCueActivation,
    session_snapshot: &SessionDeliverySnapshot,
    critical_attention: &CriticalAttentionProjection,
    integration_coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> ReactiveContextPlanResult {
    match plan_inner(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    ) {
        Ok(result) => result,
        Err(error) => ReactiveContextPlanResult::Error(error),
    }
}

struct ValidatedInputs<'a> {
    view: &'a ContextPlanningView,
    cue_activation: &'a ReactiveCueActivation,
    session_snapshot: &'a SessionDeliverySnapshot,
    critical_attention: &'a CriticalAttentionProjection,
    integration_coverage: &'a IntegrationCoverageProfile,
    policy: &'a ReactiveDeliveryPolicy,
    input_bytes: u64,
    preflight_work: u64,
    input_references: u64,
}

type ActivationMap = BTreeMap<
    String,
    (
        ActivationEvidenceKind,
        eliot_cue_contracts::ActivationStrength,
        Vec<eliot_cue_contracts::TargetHandle>,
    ),
>;

struct PlanningEvidence {
    base: OutputIdentity,
    floor_safety_refusal: Option<FloorSafetyRefusal>,
    frontier: Vec<String>,
    incomplete_activation: bool,
    mode: Option<ReactiveDeliveryMode>,
    selected_mode: ReactiveDeliveryMode,
    effective_proof_ceiling: ProofCeiling,
    activation_map: ActivationMap,
    profile_ref: ReactiveContextContentRef,
    attention_blocked: bool,
}

struct ItemLedger {
    items: Vec<PlannedContextItem>,
    required_ids: BTreeSet<String>,
    sticky_obligations: u64,
    required_attention: bool,
    planning_work: u64,
    work_exhausted: bool,
}

/// Plan one bounded context injection from six immutable projections.
fn plan_inner(
    view: &ContextPlanningView,
    cue_activation: &ReactiveCueActivation,
    session_snapshot: &SessionDeliverySnapshot,
    critical_attention: &CriticalAttentionProjection,
    integration_coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    let inputs = validate_planning_inputs(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    )?;
    let evidence = derive_planning_evidence(&inputs)?;
    let ledger = build_item_ledger(&inputs, &evidence)?;
    resolve_selection_and_emit(&inputs, evidence, ledger)
}

fn validate_planning_inputs<'a>(
    view: &'a ContextPlanningView,
    cue_activation: &'a ReactiveCueActivation,
    session_snapshot: &'a SessionDeliverySnapshot,
    critical_attention: &'a CriticalAttentionProjection,
    integration_coverage: &'a IntegrationCoverageProfile,
    policy: &'a ReactiveDeliveryPolicy,
) -> Result<ValidatedInputs<'a>, ReactiveContextPlanningError> {
    policy.validate_preflight().map_err(invalid_preflight)?;
    let (input_bytes, preflight_work, input_references) = preflight_inputs(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    )?;
    policy.validate().map_err(|error| invalid(error, policy))?;
    view.validate().map_err(|error| invalid(error, policy))?;
    cue_activation
        .validate_against(view)
        .map_err(|error| invalid(error, policy))?;
    session_snapshot
        .validate()
        .map_err(|error| invalid(error, policy))?;
    critical_attention
        .validate()
        .map_err(|error| invalid(error, policy))?;
    integration_coverage
        .validate()
        .map_err(|error| invalid(error, policy))?;
    validate_cross_bindings(
        view,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    )?;
    Ok(ValidatedInputs {
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
        input_bytes,
        preflight_work,
        input_references,
    })
}

fn derive_planning_evidence(
    inputs: &ValidatedInputs<'_>,
) -> Result<PlanningEvidence, ReactiveContextPlanningError> {
    let ValidatedInputs {
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
        ..
    } = inputs;
    let input_digest = derive_input_identity(inputs)?;

    let activation_digest =
        canonical_planning_digest(cue_activation).map_err(|error| invalid(error, policy))?;
    let session_digest = session_snapshot
        .canonical_digest()
        .map_err(|error| invalid(error, policy))?;
    let attention_digest = critical_attention
        .canonical_digest()
        .map_err(|error| invalid(error, policy))?;
    let coverage_digest = integration_coverage
        .canonical_digest()
        .map_err(|error| invalid(error, policy))?;
    let floor_safety_refusal =
        inspect_floor_safety(view).map_err(|error| invalid(error, policy))?;

    let mut frontier = activation_frontier(&cue_activation.result);
    let incomplete_activation =
        !matches!(cue_activation.result.completeness, Completeness::Complete);
    if incomplete_activation && frontier.is_empty() {
        frontier.push("activation:incomplete".to_owned());
    }
    let mode = choose_mode(integration_coverage, policy);
    let selected_mode = mode.unwrap_or(ReactiveDeliveryMode::ToolOnly);
    let effective_proof_ceiling =
        effective_proof_ceiling(integration_coverage, policy, selected_mode);
    let activation_map =
        activation_targets(&cue_activation.result, &cue_activation.target_bindings);
    frontier.extend(unmatched_activation_targets(
        &cue_activation.result,
        &cue_activation.target_bindings,
    ));
    let profile_ref = profile_reference(policy);
    let attention_blocked = critical_attention.members.iter().any(|member| {
        matches!(
            member.resolution,
            AttentionResolution::Open | AttentionResolution::Unknown
        ) && !attention_rule_allowed(member, policy, integration_coverage)
    });
    let base = OutputIdentity {
        request_id: policy.request_id.clone(),
        operation_id: policy.operation_id.clone(),
        idempotency_key: policy.idempotency_key.clone(),
        plan_id: policy.plan_id.clone(),
        input_digest,
        view_digest: view.view.output_digest.clone(),
        admitted_set_digest: view.admitted_canonical_sha256.clone(),
        assembly_digest: view.view.selection.output_digest.clone(),
        activation_digest,
        session_snapshot_digest: session_digest,
        attention_projection_digest: attention_digest,
        coverage_profile_digest: coverage_digest,
        coverage_completeness: integration_coverage.completeness,
        coverage_gaps: integration_coverage.gaps.clone(),
        selected_event_evidence: integration_coverage
            .events
            .iter()
            .filter(|event| event.event == policy.target_event)
            .cloned()
            .collect(),
        session_completeness: session_snapshot.denominator.completeness,
        session_denominator: session_snapshot.denominator,
        context_measurement: view.view.measurement.clone(),
        floor_capacity: view.admitted.floor.capacity,
        floor_incomplete: floor_safety_refusal
            .as_ref()
            .and_then(|refusal| refusal.incomplete.clone()),
        policy_digest: policy.policy_digest.clone(),
        activation_result: cue_activation.result.clone(),
    };
    Ok(PlanningEvidence {
        base,
        floor_safety_refusal,
        frontier,
        incomplete_activation,
        mode,
        selected_mode,
        effective_proof_ceiling,
        activation_map,
        profile_ref,
        attention_blocked,
    })
}

fn derive_input_identity(
    inputs: &ValidatedInputs<'_>,
) -> Result<String, ReactiveContextPlanningError> {
    let ValidatedInputs {
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
        ..
    } = inputs;
    let bounds = policy.planning_bounds();
    let input_digest = canonical_planning_digest(&(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    ))
    .map_err(|error| invalid(error, policy))?;
    let measurement_digest = canonical_planning_digest(&view.view.measurement)
        .map_err(|error| invalid(error, policy))?;
    let bindings = eliot_context_contracts::ReactivePlanningBindings {
        request_id: policy.request_id.clone(),
        operation_id: policy.operation_id.clone(),
        idempotency_key: policy.idempotency_key.clone(),
        task_id: view.view.binding.task_id.clone(),
        attempt_id: view.view.binding.attempt_id.clone(),
        scope_id: view.view.binding.scope_id.clone(),
        state_fence: view.view.binding.state_fence.clone(),
        view_id: view.view_id.clone(),
        view_digest: view.view.output_digest.clone(),
        admitted_set_digest: view.admitted_canonical_sha256.clone(),
        assembly_digest: view.view.selection.output_digest.clone(),
        measurement_digest: measurement_digest.clone(),
        input_digest: canonical_planning_digest(&(
            &policy.request_id,
            &policy.operation_id,
            &policy.idempotency_key,
            &view.view.binding.task_id,
            &view.view.binding.attempt_id,
            &view.view.binding.scope_id,
            &view.view.binding.state_fence,
            &view.view_id,
            &view.view.output_digest,
            &view.admitted_canonical_sha256,
            &view.view.selection.output_digest,
            &measurement_digest,
            &bounds,
        ))
        .map_err(|error| invalid(error, policy))?,
        bounds,
    };
    bindings
        .validate_against(view)
        .map_err(|error| invalid(error, policy))?;
    Ok(input_digest)
}

fn build_item_ledger(
    inputs: &ValidatedInputs<'_>,
    evidence: &PlanningEvidence,
) -> Result<ItemLedger, ReactiveContextPlanningError> {
    let ValidatedInputs {
        view,
        session_snapshot,
        critical_attention,
        policy,
        preflight_work,
        ..
    } = inputs;
    let remaining_work = policy
        .max_work
        .checked_sub(*preflight_work)
        .ok_or_else(|| {
            internal(
                ReactiveInputError::InvalidField {
                    field: "planning.floor_work",
                    reason: "preflight consumed the complete planning work budget",
                },
                policy,
                &evidence.base.input_digest,
            )
        })?;
    let (required_ids, floor_scan_work) =
        required_floor_ids(view, remaining_work).ok_or_else(|| {
            internal(
                ReactiveInputError::InvalidField {
                    field: "planning.floor_work",
                    reason: "required floor traversal work overflowed",
                },
                policy,
                &evidence.base.input_digest,
            )
        })?;
    let mut atoms = view.view.rendered.clone();
    atoms.sort_by_key(|atom| {
        (
            policy
                .priority
                .iter()
                .position(|role| role == &atom.role)
                .unwrap_or(policy.priority.len()),
            i32::from(!matches!(
                evidence
                    .activation_map
                    .get(atom.atom_id.as_str())
                    .map(|(kind, _, _)| kind),
                Some(ActivationEvidenceKind::Direct | ActivationEvidenceKind::DirectAndDerived,)
            )),
            evidence.activation_map.get(atom.atom_id.as_str()).map_or(
                Reverse(eliot_cue_contracts::ActivationStrength(0)),
                |(_, strength, _)| Reverse(*strength),
            ),
            atom.atom_id.to_string(),
            atom.source_revision.clone(),
            atom.source_digest.clone(),
        )
    });
    let mut atom_handles = BTreeMap::new();
    for atom in &atoms {
        let handles = item_handles(atom, policy)
            .map_err(|error| internal(error, policy, &evidence.base.input_digest))?;
        atom_handles.insert(atom.atom_id.to_string(), handles);
    }
    if session_operation_conflict(session_snapshot, policy, view, &atom_handles) {
        return Err(planning_error(
            policy,
            PlanningErrorDisposition::StaleOrConflict,
            PlanningErrorKind::IdentityConflict,
            "OPERATION_OR_IDEMPOTENCY_CONFLICT",
            "supplied delivery identity conflicts with retained current history",
        ));
    }
    let mut items = build_context_items(
        &atoms,
        &atom_handles,
        view,
        session_snapshot,
        policy,
        &required_ids,
        evidence,
    )?;
    append_attention_items(&mut items, critical_attention, policy, evidence)?;
    items.extend(build_omission_items(view, policy, evidence)?);

    let summary = finish_item_ledger(
        &items,
        floor_scan_work,
        *preflight_work,
        policy,
        &evidence.base.input_digest,
    )?;
    Ok(ItemLedger {
        items,
        required_ids,
        sticky_obligations: summary.sticky_obligations,
        required_attention: summary.required_attention,
        planning_work: summary.planning_work,
        work_exhausted: summary.work_exhausted,
    })
}

fn append_attention_items(
    items: &mut Vec<PlannedContextItem>,
    critical_attention: &CriticalAttentionProjection,
    policy: &ReactiveDeliveryPolicy,
    evidence: &PlanningEvidence,
) -> Result<(), ReactiveContextPlanningError> {
    for member in &critical_attention.members {
        items.push(
            attention_item(
                member,
                &evidence.profile_ref,
                evidence.selected_mode,
                &evidence.base.attention_projection_digest,
            )
            .map_err(|error| internal(error, policy, &evidence.base.input_digest))?,
        );
    }
    Ok(())
}

struct ItemLedgerSummary {
    sticky_obligations: u64,
    required_attention: bool,
    planning_work: u64,
    work_exhausted: bool,
}

fn finish_item_ledger(
    items: &[PlannedContextItem],
    floor_scan_work: u64,
    preflight_work: u64,
    policy: &ReactiveDeliveryPolicy,
    input_digest: &str,
) -> Result<ItemLedgerSummary, ReactiveContextPlanningError> {
    let sticky_obligations = items
        .iter()
        .filter(|item| {
            item.kind == PlannedItemKind::Attention
                && item
                    .attention
                    .as_ref()
                    .is_some_and(|attention| attention.sticky)
        })
        .count() as u64;
    let required_attention = sticky_obligations != 0;
    let mut planning_work = preflight_work;
    let item_count = u64::try_from(items.len()).map_err(|_| {
        internal(
            ReactiveInputError::InvalidField {
                field: "planning.items",
                reason: "item ledger count overflowed",
            },
            policy,
            input_digest,
        )
    })?;
    let ledger_units = floor_scan_work
        .checked_add(item_count)
        .and_then(|work| work.checked_add(item_count))
        .and_then(|work| work.checked_add(item_count))
        .and_then(|work| work.checked_add(2))
        .ok_or_else(|| {
            internal(
                ReactiveInputError::InvalidField {
                    field: "planning.work",
                    reason: "item ledger work overflowed",
                },
                policy,
                input_digest,
            )
        })?;
    let work_exhausted = !charge_planning_work(&mut planning_work, ledger_units, policy.max_work)
        .map_err(|error| internal(error, policy, input_digest))?;
    Ok(ItemLedgerSummary {
        sticky_obligations,
        required_attention,
        planning_work,
        work_exhausted,
    })
}

fn build_context_items(
    atoms: &[eliot_context_contracts::RenderedAtom],
    atom_handles: &BTreeMap<
        String,
        (
            Vec<ReactiveContextContentRef>,
            Vec<ReactiveContextContentRef>,
            u64,
        ),
    >,
    view: &ContextPlanningView,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    required_ids: &BTreeSet<String>,
    evidence: &PlanningEvidence,
) -> Result<Vec<PlannedContextItem>, ReactiveContextPlanningError> {
    let mut items = Vec::new();
    for atom in atoms {
        let (content, source, byte_cost) = atom_handles
            .get(atom.atom_id.as_str())
            .cloned()
            .ok_or_else(|| {
                internal(
                    ReactiveInputError::InvalidField {
                        field: "delivery.item_handles",
                        reason: "current atom handles were not retained",
                    },
                    policy,
                    &evidence.base.input_digest,
                )
            })?;
        let activated = evidence
            .activation_map
            .get(atom.atom_id.as_str())
            .map(|(kind, _, _)| *kind);
        let current_record = session
            .records
            .iter()
            .find(|record| record.item_id == atom.atom_id.as_str());
        let (disposition, reason) = classify_normal(
            atom,
            current_record,
            activated,
            evidence.selected_mode,
            &content,
            &source,
            &evidence.profile_ref,
            evidence.effective_proof_ceiling,
            session.denominator.completeness,
            evidence.incomplete_activation,
            required_ids.contains(atom.atom_id.as_str()),
            view,
            session,
        );
        let activation_targets = evidence
            .activation_map
            .get(atom.atom_id.as_str())
            .map(|(_, _, handles)| handles.clone())
            .unwrap_or_default();
        items.push(PlannedContextItem {
            item_id: atom.atom_id.to_string(),
            kind: PlannedItemKind::Context,
            rendered: Some(atom.clone()),
            content,
            source,
            profile: evidence.profile_ref.clone(),
            activation_kind: activated,
            activation_targets,
            attention_kind: None,
            attention: None,
            omission: None,
            disposition,
            byte_cost,
            stu_cost: None,
            reason,
        });
    }
    Ok(items)
}

fn build_omission_items(
    view: &ContextPlanningView,
    policy: &ReactiveDeliveryPolicy,
    evidence: &PlanningEvidence,
) -> Result<Vec<PlannedContextItem>, ReactiveContextPlanningError> {
    view.admitted
        .economy
        .omissions
        .iter()
        .map(|omission| {
            let omission_bytes = canonical_json_bytes(omission)
                .map_err(|error| internal(error, policy, &evidence.base.input_digest))?;
            Ok(PlannedContextItem {
                item_id: format!("omission:{}", omission.atom_id),
                kind: PlannedItemKind::Omission,
                rendered: None,
                content: Vec::new(),
                source: Vec::new(),
                profile: evidence.profile_ref.clone(),
                activation_kind: None,
                activation_targets: Vec::new(),
                attention_kind: None,
                attention: None,
                omission: Some(omission.clone()),
                disposition: DeliveryDisposition::OmissionReferenceOnly,
                byte_cost: u64::try_from(omission_bytes.len()).map_err(|_| {
                    internal(
                        ReactiveInputError::InvalidField {
                            field: "delivery.omission",
                            reason: "omission size overflowed",
                        },
                        policy,
                        &evidence.base.input_digest,
                    )
                })?,
                stu_cost: None,
                reason: format!("admitted omission: {:?}", omission.reason),
            })
        })
        .collect()
}

struct SelectionRefusal {
    disposition: DeliveryDisposition,
    reason: String,
    frontier: Vec<String>,
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn early_selection_refusal(
    policy: &ReactiveDeliveryPolicy,
    mode: Option<ReactiveDeliveryMode>,
    expired: bool,
    deadline_unknown: bool,
    floor_safety_refusal: Option<&FloorSafetyRefusal>,
    work_exhausted: bool,
    items: &[PlannedContextItem],
    required_ids: &BTreeSet<String>,
    attention_blocked: bool,
) -> Option<SelectionRefusal> {
    if let Some(reason) = global_selection_refusal(policy, expired, deadline_unknown, mode) {
        return Some(SelectionRefusal {
            disposition: DeliveryDisposition::UnsupportedCapability,
            reason: reason.to_owned(),
            frontier: vec![format!("global:{reason}")],
        });
    }
    if let Some(refusal) = floor_safety_refusal {
        let FloorSafetyRefusal {
            reason, evidence, ..
        } = refusal;
        return Some(SelectionRefusal {
            disposition: DeliveryDisposition::WithheldProfile,
            reason: reason.clone(),
            frontier: evidence.clone(),
        });
    }
    if work_exhausted {
        return Some(SelectionRefusal {
            disposition: DeliveryDisposition::WithheldBudget,
            reason: "PLANNING_WORK_EXCEEDED".to_owned(),
            frontier: Vec::new(),
        });
    }
    if let Some(reason) = required_safety_refusal(items, required_ids) {
        return Some(SelectionRefusal {
            disposition: DeliveryDisposition::WithheldProfile,
            frontier: vec![format!("floor:required:{reason}")],
            reason,
        });
    }
    attention_blocked.then(|| SelectionRefusal {
        disposition: DeliveryDisposition::WithheldPrivacy,
        reason: "ATTENTION_DISCLOSURE_RULE_REQUIRED".to_owned(),
        frontier: vec!["attention:disclosure-rule-required".to_owned()],
    })
}

fn resolve_selection_and_emit(
    inputs: &ValidatedInputs<'_>,
    evidence: PlanningEvidence,
    ledger: ItemLedger,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    let ValidatedInputs {
        session_snapshot,
        policy,
        input_bytes,
        input_references,
        ..
    } = inputs;
    let PlanningEvidence {
        base,
        floor_safety_refusal,
        mut frontier,
        mode,
        selected_mode,
        attention_blocked,
        ..
    } = evidence;
    let ItemLedger {
        mut items,
        required_ids,
        sticky_obligations,
        required_attention,
        mut planning_work,
        work_exhausted,
    } = ledger;
    let input_bytes = *input_bytes;
    let input_references = *input_references;
    let deadline_unknown =
        policy.deadline_ms.is_some() && policy.observed_at.valid_time_ms.is_none();
    let expired = policy
        .deadline_ms
        .zip(policy.observed_at.valid_time_ms)
        .is_some_and(|(deadline, observed)| deadline < observed);
    if let Some(refusal) = early_selection_refusal(
        policy,
        mode,
        expired,
        deadline_unknown,
        floor_safety_refusal.as_ref(),
        work_exhausted,
        &items,
        &required_ids,
        attention_blocked,
    ) {
        refuse_before_selection(&mut items, refusal.disposition, &refusal.reason);
        frontier.extend(refusal.frontier);
        return no_injection_for_ledger(
            &base,
            &refusal.reason,
            items,
            &required_ids,
            required_attention,
            input_bytes,
            planning_work,
            sticky_obligations,
            input_references,
            frontier,
            policy,
        );
    }
    let trigger = has_new_obligation(&items, required_attention);
    if trigger {
        force_complete_floor(&mut items, &required_ids, selected_mode);
    }
    let (selected, accounting, no_new_work) = run_selection_and_accounting(
        &mut items,
        &required_ids,
        trigger,
        selected_mode,
        session_snapshot,
        policy,
        input_bytes,
        input_references,
        required_attention,
        sticky_obligations,
        &base.input_digest,
        &mut planning_work,
    )?;
    finish_selection_outcome(
        &base,
        selected_mode,
        items,
        &required_ids,
        required_attention,
        input_bytes,
        planning_work,
        sticky_obligations,
        input_references,
        frontier,
        policy,
        trigger,
        selected,
        accounting,
        no_new_work,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_selection_outcome(
    base: &OutputIdentity,
    selected_mode: ReactiveDeliveryMode,
    mut items: Vec<PlannedContextItem>,
    required_ids: &BTreeSet<String>,
    required_attention: bool,
    input_bytes: u64,
    planning_work: u64,
    sticky_obligations: u64,
    input_references: u64,
    frontier: Vec<String>,
    policy: &ReactiveDeliveryPolicy,
    trigger: bool,
    selected: Option<InertDeliveryRequest>,
    mut accounting: PlanningAccounting,
    no_new_work: bool,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    if trigger && selected.is_none() {
        for item in &mut items {
            if selection_candidate(item) {
                item.disposition = DeliveryDisposition::WithheldBudget;
                "required Safety Floor or Attention cannot fit final request"
                    .clone_into(&mut item.reason);
            }
        }
        accounting = build_accounting(
            &items,
            policy,
            required_ids,
            required_attention,
            input_bytes,
            planning_work,
            None,
            sticky_obligations,
            input_references,
        )?;
        accounting.budget_fit = false;
        return no_injection_with_items(
            base,
            "REQUIRED_CAPACITY_OR_UNKNOWN_COST",
            items,
            accounting,
            frontier,
        );
    }
    if !accounting.budget_fit {
        return no_injection_for_ledger(
            base,
            "REQUIRED_CAPACITY_OR_UNKNOWN_COST",
            items,
            required_ids,
            required_attention,
            input_bytes,
            planning_work,
            sticky_obligations,
            input_references,
            frontier,
            policy,
        );
    }
    if no_new_work {
        return no_injection_for_ledger(
            base,
            if required_attention {
                "STICKY_ATTENTION_RETAINED"
            } else {
                "NO_NEW_ELIGIBLE_ITEMS"
            },
            items,
            required_ids,
            required_attention,
            input_bytes,
            planning_work,
            sticky_obligations,
            input_references,
            frontier,
            policy,
        );
    }

    let request = selected.ok_or_else(|| {
        internal(
            ReactiveInputError::InvalidField {
                field: "delivery.request",
                reason: "required selection did not produce a request",
            },
            policy,
            &base.input_digest,
        )
    })?;
    emit_pending(
        base,
        selected_mode,
        items,
        accounting,
        frontier,
        request,
        policy,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_selection_and_accounting(
    items: &mut [PlannedContextItem],
    required_ids: &BTreeSet<String>,
    trigger: bool,
    selected_mode: ReactiveDeliveryMode,
    session_snapshot: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    input_bytes: u64,
    input_references: u64,
    required_attention: bool,
    sticky_obligations: u64,
    input_digest: &str,
    planning_work: &mut u64,
) -> Result<(Option<InertDeliveryRequest>, PlanningAccounting, bool), ReactiveContextPlanningError>
{
    let selected = select_required_then_optional(
        items,
        required_ids,
        trigger,
        selected_mode,
        session_snapshot,
        policy,
        planning_work,
    )
    .map_err(|error| internal(error, policy, input_digest))?;
    let accounting = build_accounting(
        items,
        policy,
        required_ids,
        required_attention,
        input_bytes,
        *planning_work,
        selected.as_ref(),
        sticky_obligations,
        input_references,
    )?;
    let no_new_work = !items.iter().any(|item| {
        matches!(
            item.disposition,
            DeliveryDisposition::EventPlan
                | DeliveryDisposition::ToolOnlyAdvisory
                | DeliveryDisposition::StickyPendingResolution
        )
    });
    Ok((selected, accounting, no_new_work))
}

fn emit_pending(
    base: &OutputIdentity,
    selected_mode: ReactiveDeliveryMode,
    items: Vec<PlannedContextItem>,
    accounting: PlanningAccounting,
    frontier: Vec<String>,
    request: InertDeliveryRequest,
    policy: &ReactiveDeliveryPolicy,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    let result_digest = output_digest(
        base,
        "PENDING",
        Some(selected_mode),
        None,
        &items,
        &accounting,
        &frontier,
        &[],
        Some(&request),
    )
    .map_err(|error| invalid(error, policy))?;
    Ok(ReactiveContextPlanResult::Pending(
        PendingContextInjectionPlan {
            request_id: base.request_id.clone(),
            operation_id: base.operation_id.clone(),
            idempotency_key: base.idempotency_key.clone(),
            plan_id: base.plan_id.clone(),
            input_digest: base.input_digest.clone(),
            result_digest,
            view_digest: base.view_digest.clone(),
            admitted_set_digest: base.admitted_set_digest.clone(),
            assembly_digest: base.assembly_digest.clone(),
            activation_digest: base.activation_digest.clone(),
            activation_result: base.activation_result.clone(),
            session_snapshot_digest: base.session_snapshot_digest.clone(),
            attention_projection_digest: base.attention_projection_digest.clone(),
            coverage_profile_digest: base.coverage_profile_digest.clone(),
            coverage_completeness: base.coverage_completeness,
            coverage_gaps: base.coverage_gaps.clone(),
            selected_event_evidence: base.selected_event_evidence.clone(),
            session_completeness: base.session_completeness,
            session_denominator: base.session_denominator,
            context_measurement: base.context_measurement.clone(),
            floor_capacity: base.floor_capacity,
            floor_incomplete: base.floor_incomplete.clone(),
            policy_digest: base.policy_digest.clone(),
            mode: selected_mode,
            items,
            accounting,
            frontier,
            invalidation: Vec::new(),
            request,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn no_injection_for_ledger(
    base: &OutputIdentity,
    reason: &str,
    items: Vec<PlannedContextItem>,
    required_ids: &BTreeSet<String>,
    required_attention: bool,
    input_bytes: u64,
    planning_work: u64,
    sticky_obligations: u64,
    input_references: u64,
    frontier: Vec<String>,
    policy: &ReactiveDeliveryPolicy,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    let accounting = build_accounting(
        &items,
        policy,
        required_ids,
        required_attention,
        input_bytes,
        planning_work,
        None,
        sticky_obligations,
        input_references,
    )?;
    no_injection_with_items(base, reason, items, accounting, frontier)
}

fn invalid_preflight<E: std::fmt::Display>(error: E) -> ReactiveContextPlanningError {
    ReactiveContextPlanningError {
        disposition: PlanningErrorDisposition::InvalidRequest,
        kind: PlanningErrorKind::InvalidSchema,
        reason_code: "INVALID_POLICY_PREFLIGHT".to_owned(),
        operation_id: None,
        request_id: None,
        input_digest: None,
        detail: bounded_detail(error.to_string()),
    }
}

fn preflight_inputs(
    view: &ContextPlanningView,
    activation: &ReactiveCueActivation,
    session: &SessionDeliverySnapshot,
    attention: &CriticalAttentionProjection,
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Result<(u64, u64, u64), ReactiveContextPlanningError> {
    let cap = usize::try_from(policy.max_input_bytes).unwrap_or(0);
    let mut writer = CappedWriter { written: 0, cap };
    serde_json::to_writer(
        &mut writer,
        &(view, activation, session, attention, coverage, policy),
    )
    .map_err(|_| {
        planning_error(
            policy,
            PlanningErrorDisposition::UnavailableOrCapacity,
            PlanningErrorKind::Overflow,
            "INPUT_BYTES_EXCEEDED",
            "six-input canonical size exceeds policy limit",
        )
    })?;
    // Only after the capped stream succeeds do we walk retained nested
    // collections. This keeps structural counting from becoming an
    // uncapped scan of attacker-sized inputs.
    let (work, references) = count_input_work(
        view, activation, session, attention, coverage, policy,
    )
    .ok_or_else(|| {
        planning_error(
            policy,
            PlanningErrorDisposition::UnavailableOrCapacity,
            PlanningErrorKind::Overflow,
            "INPUT_PREFLIGHT_WORK_OVERFLOW",
            "six-input bounded preflight counters overflowed",
        )
    })?;
    if work > policy.max_work {
        return Err(planning_error(
            policy,
            PlanningErrorDisposition::UnavailableOrCapacity,
            PlanningErrorKind::Overflow,
            "INPUT_PREFLIGHT_WORK_EXCEEDED",
            "six-input bounded preflight work exceeds policy limit",
        ));
    }
    let bytes = u64::try_from(writer.written).map_err(|_| {
        planning_error(
            policy,
            PlanningErrorDisposition::UnavailableOrCapacity,
            PlanningErrorKind::Overflow,
            "INPUT_PREFLIGHT_BYTES_OVERFLOW",
            "six-input canonical size does not fit the bounded counter",
        )
    })?;
    if bytes > policy.max_input_bytes {
        return Err(planning_error(
            policy,
            PlanningErrorDisposition::UnavailableOrCapacity,
            PlanningErrorKind::Overflow,
            "INPUT_BYTES_EXCEEDED",
            "six-input canonical size exceeds policy limit",
        ));
    }
    Ok((bytes, work, references))
}

struct CappedWriter {
    written: usize,
    cap: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("bounded serialization overflow"))?;
        if next > self.cap {
            return Err(io::Error::other("bounded serialization exceeded cap"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bump(total: &mut u64, amount: usize) -> Option<()> {
    *total = total.checked_add(u64::try_from(amount).ok()?)?;
    Some(())
}

fn bounded_bump(total: &mut u64, amount: usize, limit: u64) -> Option<()> {
    bump(total, amount)?;
    (*total <= limit).then_some(())
}

fn sum_lengths(parts: &[usize]) -> Option<usize> {
    parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part))
}

/// Count logical retained visits and reference handles without canonicalizing.
/// A unit is a bounded collection element or nested handle, never elapsed CPU.
fn count_input_work(
    view: &ContextPlanningView,
    activation: &ReactiveCueActivation,
    session: &SessionDeliverySnapshot,
    attention: &CriticalAttentionProjection,
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Option<(u64, u64)> {
    let mut work = 1u64;
    // Keep the view reference denominator aligned with A15's authoritative
    // enumeration, including selection, quality, provider, proof and
    // measurement handles. The owner helper is private, so this bounded
    // package-local mirror is intentional.
    let mut references = count_view_references(view)?;
    count_view_input_work(
        view, activation, session, attention, coverage, policy, &mut work,
    )?;
    count_session_input_work(session, &mut work, &mut references)?;
    count_attention_input_work(attention, &mut work, &mut references)?;
    count_coverage_input_work(coverage, &mut work, &mut references)?;
    count_activation_input_work(activation, &mut work, &mut references)?;
    count_delivery_input_work(view, activation, &mut work, &mut references)?;
    Some((work, references))
}

fn count_view_input_work(
    view: &ContextPlanningView,
    activation: &ReactiveCueActivation,
    session: &SessionDeliverySnapshot,
    attention: &CriticalAttentionProjection,
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
    work: &mut u64,
) -> Option<()> {
    for length in [
        view.view.rendered.len(),
        view.view.admitted_ids.len(),
        view.admitted.floor.members.len(),
        view.admitted.floor.mandatory_atoms.len(),
        view.admitted.floor.interpretation_dependencies.len(),
        view.admitted.floor.providers.requested.len(),
        view.admitted.floor.providers.dispositions.len(),
        view.admitted.records.len(),
        view.admitted.admissions.len(),
        view.admitted.economy.omissions.len(),
        view.view.quality.results.len(),
        session.records.len(),
        attention.members.len(),
        coverage.events.len(),
        coverage.gaps.len(),
        activation.request.seeds.len(),
        activation.request.relation_edges.len(),
        activation.result.direct.len(),
        activation.result.derived.len(),
        activation.result.trace.steps.len(),
        activation.target_bindings.len(),
        policy.allowed_modes.len(),
        policy.priority.len(),
        policy.attention_disclosure.len(),
    ] {
        bump(work, length)?;
    }
    for atom in &view.view.rendered {
        bump(work, atom.dependencies.len())?;
    }
    for member in &view.admitted.floor.members {
        bump(work, member.required_dependencies.len())?;
    }
    Some(())
}

fn count_session_input_work(
    session: &SessionDeliverySnapshot,
    work: &mut u64,
    references: &mut u64,
) -> Option<()> {
    for record in &session.records {
        bump(work, record.predecessor_ids.len())?;
        bump(references, sum_lengths(&[3, record.predecessor_ids.len()])?)?;
        if let Some(closure) = &record.closure {
            *references = references.checked_add(count_view_references(&closure.context_view)?)?;
            bump(work, 1)?; // context_view
            bump(work, 1)?; // profile
            bump(work, usize::from(closure.delivery_claim.is_some()))?;
            bump(work, usize::from(closure.delivery_owner_id.is_some()))?;
            bump(work, 1)?; // assembly_receipt
            bump(work, 1)?; // payload
            bump(work, 1)?; // event
            bump(work, closure.acknowledgements.len())?;
            bump(work, closure.receipts.len())?;
            bump(work, closure.evidence.len())?;
            bump(
                references,
                sum_lengths(&[
                    1,
                    1,
                    usize::from(closure.delivery_claim.is_some()),
                    usize::from(closure.delivery_owner_id.is_some()),
                    1,
                    1,
                    1,
                    closure.acknowledgements.len(),
                    closure.receipts.len(),
                    closure.evidence.len(),
                ])?,
            )?;
        }
    }
    Some(())
}

fn count_attention_input_work(
    attention: &CriticalAttentionProjection,
    work: &mut u64,
    references: &mut u64,
) -> Option<()> {
    for member in &attention.members {
        bump(work, member.source.len())?;
        bump(work, member.evidence.len())?;
        bump(
            references,
            sum_lengths(&[member.source.len(), member.evidence.len()])?,
        )?;
        bump(work, member.owner_closure.source.len())?;
        bump(work, member.owner_closure.receipts.len())?;
        bump(work, member.owner_closure.evidence.len())?;
        bump(
            work,
            usize::from(member.owner_closure.resolution_receipt.is_some()),
        )?;
        bump(
            references,
            sum_lengths(&[
                member.owner_closure.source.len(),
                member.owner_closure.receipts.len(),
                member.owner_closure.evidence.len(),
                usize::from(member.owner_closure.resolution_receipt.is_some()),
            ])?,
        )?;
    }
    Some(())
}

fn count_coverage_input_work(
    coverage: &IntegrationCoverageProfile,
    work: &mut u64,
    references: &mut u64,
) -> Option<()> {
    for event in &coverage.events {
        bump(work, event.gaps.len())?;
        bump(work, event.receipts.len())?;
        bump(work, event.evidence.len())?;
        bump(
            references,
            sum_lengths(&[
                1,
                event.gaps.len(),
                event.receipts.len(),
                event.evidence.len(),
            ])?,
        )?;
    }
    Some(())
}

fn count_activation_input_work(
    activation: &ReactiveCueActivation,
    work: &mut u64,
    references: &mut u64,
) -> Option<()> {
    for seed in &activation.request.seeds {
        bump(work, seed.comparison_keys.len())?;
        bump(work, seed.transformation_evidence.len())?;
        bump(
            references,
            sum_lengths(&[
                seed.comparison_keys.len(),
                seed.transformation_evidence.len(),
            ])?,
        )?;
        if let eliot_cue_contracts::NormalizationOutcome::Ambiguous { rivals } = &seed.outcome {
            bump(work, rivals.len())?;
            bump(references, rivals.len())?;
        }
    }
    for _edge in &activation.request.relation_edges {
        bump(work, 2)?;
        bump(references, 3)?;
    }
    for _direct in &activation.result.direct {
        bump(work, 2)?;
        bump(references, 2)?;
    }
    for derived in &activation.result.derived {
        let units = sum_lengths(&[2, derived.path.len()])?;
        bump(work, units)?;
        bump(references, units)?;
    }
    for step in &activation.result.trace.steps {
        let units = sum_lengths(&[1, usize::from(step.edge.is_some())])?;
        bump(work, units)?;
        bump(references, units)?;
    }
    match &activation.result.completeness {
        Completeness::Truncated { frontier, .. } | Completeness::Partial { frontier } => {
            bump(work, frontier.len())?;
            bump(references, frontier.len())?;
        }
        _ => {}
    }
    Some(())
}

fn count_delivery_input_work(
    view: &ContextPlanningView,
    activation: &ReactiveCueActivation,
    work: &mut u64,
    references: &mut u64,
) -> Option<()> {
    for binding in &activation.target_bindings {
        bump(work, 2)?;
        let optional = sum_lengths(&[
            usize::from(binding.source_revision.is_some()),
            usize::from(binding.source_digest.is_some()),
        ])?;
        bump(work, optional)?;
        bump(references, 2)?;
        bump(references, optional)?;
    }
    for omission in &view.admitted.economy.omissions {
        bump(work, 2)?;
        let optional = sum_lengths(&[
            usize::from(omission.expansion.is_some()),
            usize::from(omission.expires.is_some()),
            usize::from(omission.invalidation.is_some()),
        ])?;
        bump(work, optional)?;
        if let Some(expansion) = &omission.expansion {
            let expansion_units = sum_lengths(&[
                1,
                usize::from(expansion.expires.is_some()),
                usize::from(expansion.invalidation.is_some()),
            ])?;
            bump(work, expansion_units)?;
        }
    }
    Some(())
}

/// Mirror A15's retained-reference accounting without importing its private
/// counter. Each unit is a semantic handle or retained collection element.
fn count_view_references(view: &ContextPlanningView) -> Option<u64> {
    let mut references = 0u64;
    for count in [
        view.view.admitted_ids.len(),
        view.view.rendered.len(),
        view.view.selection.admitted_ids.len(),
        view.view.selection.rendered_ids.len(),
        view.view.selection.omission_evidence.len(),
        view.admitted.records.len(),
        view.admitted.admissions.len(),
        view.admitted.floor.members.len(),
        view.admitted.floor.mandatory_atoms.len(),
        view.admitted.floor.mandatory_roles.len(),
        view.admitted.economy.requested.len(),
        view.admitted.economy.admitted.len(),
        view.admitted.economy.displaced.len(),
        view.admitted.economy.omissions.len(),
        view.admitted.floor.providers.requested.len(),
        view.admitted.floor.providers.dispositions.len(),
        view.view.quality.results.len(),
    ] {
        bump(&mut references, count)?;
    }
    bump(&mut references, 2)?; // economy.applied_rule and floor.rule_evidence
    bump(
        &mut references,
        view.admitted.floor.interpretation_dependencies.len(),
    )?;
    for item in &view.view.rendered {
        bump(&mut references, 1)?; // source_id
        bump(&mut references, item.dependencies.len())?;
        bump(
            &mut references,
            usize::from(item.source_predecessor.is_some()),
        )?;
        bump(&mut references, 2)?; // measurement and proof evidence
    }
    for record in &view.admitted.records {
        bump(&mut references, 1)?; // candidate.source.snapshot_id
        bump(&mut references, record.candidate.dependencies.len())?;
        bump(
            &mut references,
            usize::from(record.candidate.source.predecessor.is_some()),
        )?;
        bump(&mut references, 3)?; // rule evidence, proof evidence, measurement
    }
    for member in &view.admitted.floor.members {
        bump(&mut references, member.required_dependencies.len())?;
        bump(&mut references, usize::from(member.measurement.is_some()))?;
    }
    bump(&mut references, view.admitted.admissions.len())?; // rule evidence
    for disposition in &view.admitted.floor.providers.dispositions {
        bump(&mut references, usize::from(disposition.evidence.is_some()))?;
    }
    for result in &view.view.quality.results {
        bump(&mut references, result.evidence.len())?;
        bump(&mut references, result.measurements.len())?;
        bump(&mut references, result.unknown_evidence.len())?;
        bump(
            &mut references,
            usize::from(result.failed_invariant.is_some()),
        )?;
        bump(&mut references, usize::from(result.invalidation.is_some()))?;
    }
    for omission in &view.admitted.economy.omissions {
        bump(&mut references, 2)?; // source_id and decision
        bump(&mut references, usize::from(omission.expires.is_some()))?;
        bump(
            &mut references,
            usize::from(omission.invalidation.is_some()),
        )?;
        if omission.expansion.is_some() {
            bump(&mut references, 6)?; // expansion handle and its bounds
        }
    }
    Some(references)
}

fn charge_planning_work(
    total: &mut u64,
    amount: u64,
    limit: u64,
) -> Result<bool, ReactiveInputError> {
    let next = total
        .checked_add(amount)
        .ok_or(ReactiveInputError::InvalidField {
            field: "planning.work",
            reason: "deterministic planning work overflowed",
        })?;
    if next > limit {
        return Ok(false);
    }
    *total = next;
    Ok(true)
}

fn planning_error(
    policy: &ReactiveDeliveryPolicy,
    disposition: PlanningErrorDisposition,
    kind: PlanningErrorKind,
    reason_code: &str,
    detail: &str,
) -> ReactiveContextPlanningError {
    ReactiveContextPlanningError {
        disposition,
        kind,
        reason_code: reason_code.to_owned(),
        operation_id: Some(policy.operation_id.clone()),
        request_id: Some(policy.request_id.clone()),
        input_digest: None,
        detail: detail.to_owned(),
    }
}

fn has_new_obligation(items: &[PlannedContextItem], required_attention: bool) -> bool {
    required_attention
        || items.iter().any(|item| {
            item.kind == PlannedItemKind::Context
                && matches!(
                    item.disposition,
                    DeliveryDisposition::EventPlan | DeliveryDisposition::ToolOnlyAdvisory
                )
        })
}

fn global_selection_refusal(
    policy: &ReactiveDeliveryPolicy,
    expired: bool,
    deadline_unknown: bool,
    mode: Option<ReactiveDeliveryMode>,
) -> Option<&'static str> {
    if policy.cancelled {
        Some("CANCELLED")
    } else if expired {
        Some("DEADLINE_EXPIRED")
    } else if deadline_unknown {
        Some("DEADLINE_UNVERIFIED")
    } else if mode.is_none() {
        Some("UNSUPPORTED_MODE_OR_COVERAGE")
    } else {
        None
    }
}

fn refuse_before_selection(
    items: &mut [PlannedContextItem],
    disposition: DeliveryDisposition,
    reason: &str,
) {
    for item in items {
        if matches!(
            item.disposition,
            DeliveryDisposition::EventPlan
                | DeliveryDisposition::ToolOnlyAdvisory
                | DeliveryDisposition::StickyPendingResolution
        ) {
            item.disposition = disposition;
            reason.clone_into(&mut item.reason);
        }
    }
}

fn required_safety_refusal(
    items: &[PlannedContextItem],
    required_ids: &BTreeSet<String>,
) -> Option<String> {
    items
        .iter()
        .filter(|item| required_ids.contains(&item.item_id))
        .find_map(|item| {
            let category = match item.disposition {
                DeliveryDisposition::WithheldPrivacy => "PRIVACY",
                DeliveryDisposition::WithheldProfile => "PROFILE_OR_PROOF",
                DeliveryDisposition::BoundedOutFrontier => "INCOMPLETE_ACTIVATION",
                DeliveryDisposition::AmbiguousUnknown => "UNKNOWN_DELIVERY",
                DeliveryDisposition::InFlight => "IN_FLIGHT",
                DeliveryDisposition::UnsupportedCapability => "UNSUPPORTED",
                _ => return None,
            };
            Some(format!("REQUIRED_FLOOR_{category}:{}", item.item_id))
        })
}

struct FloorSafetyRefusal {
    reason: String,
    evidence: Vec<String>,
    incomplete: Option<DecisionContextIncomplete>,
}

fn inspect_floor_safety(
    view: &ContextPlanningView,
) -> Result<Option<FloorSafetyRefusal>, ReactiveInputError> {
    let capacity = view.admitted.floor.capacity;
    let measurement = &view.view.measurement;
    if measurement.fixed_overhead != capacity.fixed_overhead
        || measurement.output_reserve != capacity.output_reserve
        || measurement.review_reserve != capacity.review_reserve
    {
        return Err(ReactiveInputError::BindingMismatch {
            field: "view.measurement.floor_capacity",
        });
    }
    let incomplete =
        view.admitted
            .floor
            .incomplete()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "admitted.floor.incomplete",
                reason: "floor completeness could not be evaluated",
            })?;
    if let Some(gap) = incomplete {
        let mut evidence = vec![format!("floor:rule:{}", gap.failed_floor_rule)];
        for (label, ids) in [
            ("missing", &gap.missing),
            ("stale", &gap.stale),
            ("blocked", &gap.blocked),
            ("unavailable", &gap.unavailable),
            ("omitted", &gap.omitted),
            ("exhausted", &gap.exhausted),
            ("unknown", &gap.unknown),
            ("known_empty", &gap.known_empty),
            ("partial", &gap.partial),
            ("oversized", &gap.oversized),
            ("measurement", &gap.measurements),
        ] {
            evidence.extend(ids.iter().map(|id| format!("floor:{label}:{id}")));
        }
        evidence.extend(
            gap.provider_gaps
                .iter()
                .map(|gap| format!("floor:provider:{:?}", gap.slot)),
        );
        evidence.extend(
            gap.reopening_requirements
                .iter()
                .map(|requirement| format!("floor:reopen:{requirement}")),
        );
        return Ok(Some(FloorSafetyRefusal {
            reason: "FLOOR_INCOMPLETE".to_owned(),
            evidence,
            incomplete: Some(gap),
        }));
    }
    match view.view.measurement.proves_fit(capacity.route_capacity) {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(FloorSafetyRefusal {
            reason: "FLOOR_ROUTE_CAPACITY".to_owned(),
            evidence: vec!["floor:measurement:not_fit".to_owned()],
            incomplete: None,
        })),
        Err(eliot_context_contracts::ContextError::UnknownMeasurement) => {
            Ok(Some(FloorSafetyRefusal {
                reason: "FLOOR_MEASUREMENT_UNQUALIFIED".to_owned(),
                evidence: vec!["floor:measurement:unknown_or_unavailable".to_owned()],
                incomplete: None,
            }))
        }
        Err(_) => Err(ReactiveInputError::InvalidField {
            field: "admitted.floor.measurement",
            reason: "floor measurement validation failed",
        }),
    }
}

fn item_references(item: &PlannedContextItem) -> Option<u64> {
    u64::try_from(
        item.content
            .len()
            .checked_add(item.source.len())?
            .checked_add(1)?,
    )
    .ok()
}

fn reserve_bytes(policy: &ReactiveDeliveryPolicy) -> Option<u64> {
    [
        policy.fixed_reserve,
        policy.protocol_reserve,
        policy.output_reserve,
        policy.review_reserve,
        policy.delivery_reserve,
    ]
    .into_iter()
    .try_fold(0u64, u64::checked_add)
}

fn request_fits(
    selected: &[PlannedContextItem],
    request: &InertDeliveryRequest,
    policy: &ReactiveDeliveryPolicy,
    planning_work: u64,
) -> bool {
    let refs = selected
        .iter()
        .try_fold(0u64, |sum, item| sum.checked_add(item_references(item)?));
    let reserves = reserve_bytes(policy);
    let stu = request
        .serialized_bytes
        .checked_add(2)
        .map(|bytes| bytes / 3);
    refs.is_some_and(|refs| refs <= policy.max_references)
        && selected.len() as u64 <= policy.max_items
        && planning_work <= policy.max_work
        && reserves
            .and_then(|reserves| reserves.checked_add(request.serialized_bytes))
            .is_some_and(|total| total <= policy.max_delivery_bytes)
        && policy
            .max_delivery_stu
            .is_none_or(|limit| stu.is_some_and(|stu| stu <= limit))
}

fn selection_trial_work(
    selected: &[PlannedContextItem],
    candidate: Option<&PlannedContextItem>,
) -> Option<u64> {
    let refs = selected
        .iter()
        .try_fold(0u64, |sum, item| sum.checked_add(item_references(item)?))?;
    let refs = if let Some(candidate) = candidate {
        refs.checked_add(item_references(candidate)?)?
    } else {
        refs
    };
    refs.checked_add(u64::try_from(selected.len()).ok()?)?
        .checked_add(u64::from(candidate.is_some()))?
        // inert_request performs bounded canonical measurement with at most
        // six convergence passes; charge the full deterministic allowance.
        .checked_add(MAX_INERT_REQUEST_SERIALIZATION_PASSES)
}

fn optional_dependency_group(
    items: &[PlannedContextItem],
    candidate_index: usize,
    chosen: &[PlannedContextItem],
    planning_work: &mut u64,
    max_work: u64,
) -> Result<(Option<Vec<usize>>, &'static str), ReactiveInputError> {
    let chosen_ids: BTreeSet<_> = chosen.iter().map(|item| item.item_id.as_str()).collect();
    let mut visited = BTreeSet::new();
    let mut group = Vec::new();
    let mut stack = vec![candidate_index];
    while let Some(index) = stack.pop() {
        let item = &items[index];
        if !visited.insert(item.item_id.clone()) {
            continue;
        }
        if !charge_planning_work(planning_work, 1, max_work)? {
            return Ok((None, "optional dependency closure exceeded planning work"));
        }
        if !chosen_ids.contains(item.item_id.as_str()) {
            match item.disposition {
                DeliveryDisposition::EventPlan
                | DeliveryDisposition::ToolOnlyAdvisory
                | DeliveryDisposition::StickyPendingResolution
                | DeliveryDisposition::ExplicitNotSelected
                | DeliveryDisposition::DeliveredDuplicate => {}
                DeliveryDisposition::WithheldPrivacy
                | DeliveryDisposition::WithheldProfile
                | DeliveryDisposition::AmbiguousUnknown
                | DeliveryDisposition::InFlight
                | DeliveryDisposition::UnsupportedCapability
                | DeliveryDisposition::BoundedOutFrontier => {
                    return Ok((
                        None,
                        "optional dependency closure contains a non-promotable item",
                    ));
                }
                _ => return Ok((None, "optional dependency closure is not selectable")),
            }
            group.push(index);
        }
        if let Some(rendered) = &item.rendered {
            for dependency in rendered.dependencies.iter().rev() {
                if !charge_planning_work(planning_work, 1, max_work)? {
                    return Ok((None, "optional dependency closure exceeded planning work"));
                }
                let dependency_id = dependency.to_string();
                if chosen_ids.contains(dependency_id.as_str()) || visited.contains(&dependency_id) {
                    continue;
                }
                let lookup_work =
                    u64::try_from(items.len()).map_err(|_| ReactiveInputError::InvalidField {
                        field: "planning.work",
                        reason: "dependency lookup work overflowed",
                    })?;
                if !charge_planning_work(planning_work, lookup_work, max_work)? {
                    return Ok((None, "optional dependency lookup exceeded planning work"));
                }
                let Some(dependency_index) =
                    items.iter().position(|item| item.item_id == dependency_id)
                else {
                    return Ok((None, "optional dependency closure has a missing item"));
                };
                stack.push(dependency_index);
            }
        }
    }
    Ok((Some(group), ""))
}

fn selection_group_work(
    selected: &[PlannedContextItem],
    additions: &[PlannedContextItem],
) -> Option<u64> {
    let refs = selected
        .iter()
        .chain(additions)
        .try_fold(0u64, |sum, item| sum.checked_add(item_references(item)?))?;
    refs.checked_add(u64::try_from(selected.len()).ok()?)?
        .checked_add(u64::try_from(additions.len()).ok()?)?
        .checked_add(MAX_INERT_REQUEST_SERIALIZATION_PASSES)
}

fn promote_dependency_clone(item: &mut PlannedContextItem, mode: ReactiveDeliveryMode) {
    if matches!(
        item.disposition,
        DeliveryDisposition::ExplicitNotSelected | DeliveryDisposition::DeliveredDuplicate
    ) {
        let original = std::mem::take(&mut item.reason);
        item.disposition = match mode {
            ReactiveDeliveryMode::EventIntegrated => DeliveryDisposition::EventPlan,
            _ => DeliveryDisposition::ToolOnlyAdvisory,
        };
        item.reason = format!("{original}; promoted as an exact dependency");
    }
}

fn selected_proof_ceiling(items: &[PlannedContextItem]) -> ProofCeiling {
    items
        .iter()
        .filter_map(|item| item.rendered.as_ref().map(|atom| atom.proof.ceiling))
        .max()
        .unwrap_or(ProofCeiling::Observation)
}

fn select_required_then_optional(
    items: &mut [PlannedContextItem],
    required_ids: &BTreeSet<String>,
    trigger: bool,
    mode: ReactiveDeliveryMode,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    planning_work: &mut u64,
) -> Result<Option<InertDeliveryRequest>, ReactiveInputError> {
    if !trigger {
        return Ok(None);
    }
    let Some(mut accumulator) =
        select_required_phase(items, required_ids, mode, session, policy, planning_work)?
    else {
        return Ok(None);
    };
    select_optional_groups(
        items,
        required_ids,
        mode,
        session,
        policy,
        planning_work,
        &mut accumulator,
    )?;
    finish_selection(items, &accumulator.chosen);
    Ok(accumulator.last_request)
}

#[derive(Default)]
struct SelectionAccumulator {
    chosen: Vec<PlannedContextItem>,
    last_request: Option<InertDeliveryRequest>,
}

fn selection_candidate(item: &PlannedContextItem) -> bool {
    matches!(
        item.disposition,
        DeliveryDisposition::EventPlan
            | DeliveryDisposition::ToolOnlyAdvisory
            | DeliveryDisposition::StickyPendingResolution
    )
}

fn select_required_phase(
    items: &[PlannedContextItem],
    required_ids: &BTreeSet<String>,
    mode: ReactiveDeliveryMode,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    planning_work: &mut u64,
) -> Result<Option<SelectionAccumulator>, ReactiveInputError> {
    let required: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            selection_candidate(item)
                && (required_ids.contains(&item.item_id) || item.kind == PlannedItemKind::Attention)
        })
        .map(|(index, _)| index)
        .collect();
    let mut accumulator = SelectionAccumulator::default();
    for index in required {
        let trial_work = selection_trial_work(&accumulator.chosen, Some(&items[index])).ok_or(
            ReactiveInputError::InvalidField {
                field: "planning.work",
                reason: "required selection work overflowed",
            },
        )?;
        if !charge_planning_work(planning_work, trial_work, policy.max_work)? {
            return Ok(None);
        }
        accumulator.chosen.push(items[index].clone());
        let request = inert_request(
            &accumulator.chosen,
            mode,
            session,
            policy,
            selected_proof_ceiling(&accumulator.chosen),
        )?;
        if !request_fits(&accumulator.chosen, &request, policy, *planning_work) {
            return Ok(None);
        }
        accumulator.last_request = Some(request);
    }
    if required_ids.iter().any(|required_id| {
        !accumulator
            .chosen
            .iter()
            .any(|item| item.item_id == *required_id)
    }) {
        return Ok(None);
    }
    Ok(Some(accumulator))
}

fn select_optional_groups(
    items: &mut [PlannedContextItem],
    required_ids: &BTreeSet<String>,
    mode: ReactiveDeliveryMode,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    planning_work: &mut u64,
    accumulator: &mut SelectionAccumulator,
) -> Result<(), ReactiveInputError> {
    let optional: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            selection_candidate(item)
                && !required_ids.contains(&item.item_id)
                && item.kind == PlannedItemKind::Context
        })
        .map(|(index, _)| index)
        .collect();
    for index in optional {
        if accumulator
            .chosen
            .iter()
            .any(|selected| selected.item_id == items[index].item_id)
        {
            continue;
        }
        let (group, group_reason) = optional_dependency_group(
            items,
            index,
            &accumulator.chosen,
            planning_work,
            policy.max_work,
        )?;
        let Some(group) = group else {
            let item = &mut items[index];
            let exhausted = group_reason.contains("work");
            item.disposition = if exhausted {
                DeliveryDisposition::WithheldBudget
            } else {
                DeliveryDisposition::WithheldProfile
            };
            let original = std::mem::take(&mut item.reason);
            item.reason = format!("{original}; {group_reason}");
            if exhausted {
                break;
            }
            continue;
        };
        let additions: Vec<_> = group
            .iter()
            .filter(|group_index| {
                !accumulator
                    .chosen
                    .iter()
                    .any(|selected| selected.item_id == items[**group_index].item_id)
            })
            .map(|group_index| {
                let mut item = items[*group_index].clone();
                promote_dependency_clone(&mut item, mode);
                (*group_index, item)
            })
            .collect();
        let addition_items: Vec<_> = additions.iter().map(|(_, item)| item.clone()).collect();
        let trial_work = selection_group_work(&accumulator.chosen, &addition_items).ok_or(
            ReactiveInputError::InvalidField {
                field: "planning.work",
                reason: "optional selection work overflowed",
            },
        )?;
        if !charge_planning_work(planning_work, trial_work, policy.max_work)? {
            items[index].disposition = DeliveryDisposition::WithheldBudget;
            "optional item withheld after planning work exhaustion"
                .clone_into(&mut items[index].reason);
            break;
        }
        let mut trial = accumulator.chosen.clone();
        trial.extend(addition_items);
        let request = inert_request(
            &trial,
            mode,
            session,
            policy,
            selected_proof_ceiling(&trial),
        )?;
        if request_fits(&trial, &request, policy, *planning_work) {
            accumulator.chosen = trial;
            accumulator.last_request = Some(request);
            for (group_index, promoted) in additions {
                items[group_index] = promoted;
            }
        } else {
            items[index].disposition = DeliveryDisposition::WithheldBudget;
            "optional item withheld after final request measurement"
                .clone_into(&mut items[index].reason);
        }
    }
    Ok(())
}

fn finish_selection(items: &mut [PlannedContextItem], chosen: &[PlannedContextItem]) {
    for item in items.iter_mut() {
        if selection_candidate(item)
            && !chosen
                .iter()
                .any(|selected| selected.item_id == item.item_id)
        {
            item.disposition = DeliveryDisposition::WithheldBudget;
            "required selection cannot fit final request".clone_into(&mut item.reason);
        }
    }
}

#[derive(Clone)]
struct OutputIdentity {
    request_id: RequestId,
    operation_id: OperationId,
    idempotency_key: String,
    plan_id: ArtifactId,
    input_digest: String,
    view_digest: String,
    admitted_set_digest: String,
    assembly_digest: String,
    activation_digest: String,
    activation_result: ActivationResult,
    session_snapshot_digest: String,
    attention_projection_digest: String,
    coverage_profile_digest: String,
    coverage_completeness: SnapshotCompleteness,
    coverage_gaps: Vec<String>,
    selected_event_evidence: Vec<eliot_context_contracts::CoverageEvidence>,
    session_completeness: SnapshotCompleteness,
    session_denominator: eliot_context_contracts::SnapshotDenominator,
    context_measurement: eliot_context_contracts::SerializedContextMeasurement,
    floor_capacity: eliot_context_contracts::CapacityLimits,
    floor_incomplete: Option<DecisionContextIncomplete>,
    policy_digest: String,
}

fn invalid<E: std::fmt::Display>(
    error: E,
    policy: &ReactiveDeliveryPolicy,
) -> ReactiveContextPlanningError {
    ReactiveContextPlanningError {
        disposition: PlanningErrorDisposition::InvalidRequest,
        kind: PlanningErrorKind::BindingMismatch,
        reason_code: "INVALID_INPUT_CONTRACT".to_owned(),
        operation_id: Some(policy.operation_id.clone()),
        request_id: Some(policy.request_id.clone()),
        input_digest: None,
        detail: bounded_detail(error.to_string()),
    }
}

fn internal<E: std::fmt::Display>(
    error: E,
    policy: &ReactiveDeliveryPolicy,
    input_digest: &str,
) -> ReactiveContextPlanningError {
    ReactiveContextPlanningError {
        disposition: PlanningErrorDisposition::Failed,
        kind: PlanningErrorKind::InternalContract,
        reason_code: "PLANNING_CONTRACT_FAILURE".to_owned(),
        operation_id: Some(policy.operation_id.clone()),
        request_id: Some(policy.request_id.clone()),
        input_digest: Some(input_digest.to_owned()),
        detail: bounded_detail(error.to_string()),
    }
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() > MAX_DIAGNOSTIC {
        let mut end = MAX_DIAGNOSTIC;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

fn validate_cross_bindings(
    view: &ContextPlanningView,
    session: &SessionDeliverySnapshot,
    attention: &CriticalAttentionProjection,
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Result<(), ReactiveContextPlanningError> {
    let binding = &view.view.binding;
    if session.task_id != binding.task_id
        || session.attempt_id.as_str() != binding.attempt_id.as_str()
        || session.scope_id != binding.scope_id
        || session.state_fence != binding.state_fence
        || attention.task_id != binding.task_id
        || attention.scope_id != binding.scope_id
        || attention.state_fence != binding.state_fence
        || coverage.state_fence != binding.state_fence
        || coverage.recipient_id != session.recipient_id
        || coverage.host_id != session.host_id
        || coverage.runtime_id != session.runtime_id
        || coverage.host_generation != session.host_generation
        || coverage.runtime_generation != session.runtime_generation
    {
        return Err(ReactiveContextPlanningError {
            disposition: PlanningErrorDisposition::StaleOrConflict,
            kind: PlanningErrorKind::BindingMismatch,
            reason_code: "STALE_OR_CONFLICTED_BINDING".to_owned(),
            operation_id: Some(policy.operation_id.clone()),
            request_id: Some(policy.request_id.clone()),
            input_digest: None,
            detail: "view, session, Attention, coverage, and operation identities disagree"
                .to_owned(),
        });
    }
    Ok(())
}

fn session_operation_conflict(
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    view: &ContextPlanningView,
    atom_handles: &BTreeMap<
        String,
        (
            Vec<ReactiveContextContentRef>,
            Vec<ReactiveContextContentRef>,
            u64,
        ),
    >,
) -> bool {
    session.records.iter().any(|record| {
        if !(record.operation_id == policy.operation_id
            || record.idempotency_key == policy.idempotency_key)
        {
            return false;
        }
        let refs_changed = atom_handles
            .get(&record.item_id)
            .is_none_or(|(content, source, _)| {
                content.len() != 1
                    || content.first() != Some(&record.content)
                    || source.len() != 1
                    || source.first() != Some(&record.source)
            });
        let known_view_changed = record
            .closure
            .as_ref()
            .is_some_and(|closure| closure.context_view != *view);
        record.operation_id != policy.operation_id
            || record.idempotency_key != policy.idempotency_key
            || record.request_id != policy.request_id
            || record.profile != policy.delivery_profile
            || record.session_id != session.session_id
            || record.runtime_id != session.runtime_id
            || record.runtime_generation != session.runtime_generation
            || record.host_generation != session.host_generation
            || record.task_id != session.task_id
            || record.attempt_id != session.attempt_id
            || record.scope_id != session.scope_id
            || record.state_fence != session.state_fence
            || refs_changed
            || known_view_changed
    })
}

fn choose_mode(
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
) -> Option<ReactiveDeliveryMode> {
    if policy
        .allowed_modes
        .contains(&ReactiveDeliveryMode::EventIntegrated)
        && coverage
            .supported_modes
            .contains(&ReactiveDeliveryMode::EventIntegrated)
        && coverage.events.iter().any(|event| {
            event.event == policy.target_event
                && event.contract == policy.delivery_contract
                && matches!(event.axis, eliot_context_contracts::CoverageAxis::Enforced)
                && matches!(event.completeness, SnapshotCompleteness::Complete)
                && !event.ordering.eq_ignore_ascii_case("unknown")
                && matches!(
                    event.freshness,
                    eliot_context_contracts::CoverageFreshness::Fresh
                )
        })
    {
        Some(ReactiveDeliveryMode::EventIntegrated)
    } else if policy
        .allowed_modes
        .contains(&ReactiveDeliveryMode::ToolOnly)
        && coverage
            .supported_modes
            .contains(&ReactiveDeliveryMode::ToolOnly)
        && coverage.events.iter().any(|event| {
            event.event == policy.target_event
                && event.contract == policy.delivery_contract
                && matches!(event.completeness, SnapshotCompleteness::Complete)
                && matches!(
                    event.freshness,
                    eliot_context_contracts::CoverageFreshness::Fresh
                )
                && !event.ordering.eq_ignore_ascii_case("unknown")
                && !matches!(
                    event.axis,
                    eliot_context_contracts::CoverageAxis::Unavailable
                )
        })
    {
        Some(ReactiveDeliveryMode::ToolOnly)
    } else {
        None
    }
}

fn effective_proof_ceiling(
    coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
    mode: ReactiveDeliveryMode,
) -> ProofCeiling {
    let event_ceiling = coverage
        .events
        .iter()
        .filter(|event| {
            event.event == policy.target_event
                && event.contract == policy.delivery_contract
                && matches!(event.completeness, SnapshotCompleteness::Complete)
                && matches!(
                    event.freshness,
                    eliot_context_contracts::CoverageFreshness::Fresh
                )
                && !event.ordering.eq_ignore_ascii_case("unknown")
                && match mode {
                    ReactiveDeliveryMode::EventIntegrated => {
                        matches!(event.axis, eliot_context_contracts::CoverageAxis::Enforced)
                    }
                    ReactiveDeliveryMode::ToolOnly => !matches!(
                        event.axis,
                        eliot_context_contracts::CoverageAxis::Unavailable
                    ),
                    _ => false,
                }
        })
        .map(|event| event.proof_ceiling)
        .min()
        .unwrap_or(ProofCeiling::Observation);
    coverage.proof_ceiling.min(event_ceiling)
}

fn attention_rule_allowed(
    member: &CriticalAttentionMember,
    policy: &ReactiveDeliveryPolicy,
    coverage: &IntegrationCoverageProfile,
) -> bool {
    policy
        .attention_disclosure
        .iter()
        .any(|rule: &AttentionDisclosureRule| {
            rule.attention_id == member.attention_id
                && rule.claim_digest == member.claim_digest
                && rule.minimum_privacy <= coverage.privacy_ceiling
        })
}

fn activation_targets(
    result: &ActivationResult,
    bindings: &[crate::input::ReactiveTargetBinding],
) -> BTreeMap<
    String,
    (
        ActivationEvidenceKind,
        eliot_cue_contracts::ActivationStrength,
        Vec<eliot_cue_contracts::TargetHandle>,
    ),
> {
    let mut targets: BTreeMap<
        String,
        (
            ActivationEvidenceKind,
            eliot_cue_contracts::ActivationStrength,
            Vec<eliot_cue_contracts::TargetHandle>,
        ),
    > = BTreeMap::new();
    let bound = |target: &eliot_cue_contracts::TargetHandle| {
        bindings
            .iter()
            .find(|binding| binding.target == *target)
            .map(|binding| (binding.item_id.as_str().to_owned(), target.clone()))
    };
    for direct in &result.direct {
        if let Some((item, target)) = bound(&direct.target) {
            match targets.get_mut(&item) {
                Some((kind, strength, handles)) => {
                    if matches!(*kind, ActivationEvidenceKind::Derived) {
                        *kind = ActivationEvidenceKind::DirectAndDerived;
                    }
                    *strength = (*strength).max(direct.strength);
                    handles.push(target);
                }
                None => {
                    targets.insert(
                        item,
                        (
                            ActivationEvidenceKind::Direct,
                            direct.strength,
                            vec![target],
                        ),
                    );
                }
            }
        }
    }
    for derived in &result.derived {
        if let Some((item, target)) = bound(&derived.target) {
            match targets.get_mut(&item) {
                Some((kind, strength, handles))
                    if matches!(*kind, ActivationEvidenceKind::Direct) =>
                {
                    *kind = ActivationEvidenceKind::DirectAndDerived;
                    *strength = (*strength).max(derived.strength);
                    handles.push(target);
                }
                Some((_, strength, handles)) => {
                    *strength = (*strength).max(derived.strength);
                    handles.push(target);
                }
                None => {
                    targets.insert(
                        item,
                        (
                            ActivationEvidenceKind::Derived,
                            derived.strength,
                            vec![target],
                        ),
                    );
                }
            }
        }
    }
    for (_, _, handles) in targets.values_mut() {
        handles.sort();
        handles.dedup();
    }
    targets
}

fn activation_frontier(result: &ActivationResult) -> Vec<String> {
    match &result.completeness {
        Completeness::Truncated { frontier, .. } | Completeness::Partial { frontier } => {
            frontier.iter().map(ToString::to_string).collect()
        }
        Completeness::Blocked { reason }
        | Completeness::Unavailable { reason }
        | Completeness::Unknown { reason }
        | Completeness::SourceUnavailable { reason } => vec![reason.clone()],
        Completeness::Complete | Completeness::Stale { .. } => Vec::new(),
        _ => vec!["activation:future-completeness".to_owned()],
    }
}

fn unmatched_activation_targets(
    result: &ActivationResult,
    bindings: &[crate::input::ReactiveTargetBinding],
) -> Vec<String> {
    let bound: BTreeSet<_> = bindings
        .iter()
        .map(|binding| binding.target.as_str())
        .collect();
    result
        .direct
        .iter()
        .map(|activation| activation.target.as_str())
        .chain(
            result
                .derived
                .iter()
                .map(|activation| activation.target.as_str()),
        )
        .filter(|target| !bound.contains(target))
        .map(|target| format!("activation:unmapped:{target}"))
        .collect()
}

fn required_floor_ids(
    view: &ContextPlanningView,
    max_work: u64,
) -> Option<(BTreeSet<String>, u64)> {
    let mut scan_work = 1u64;
    let mut ids = BTreeSet::new();
    for atom_id in &view.admitted.floor.mandatory_atoms {
        bounded_bump(&mut scan_work, 1, max_work)?;
        ids.insert(atom_id.to_string());
    }
    for atom_id in &view.admitted.floor.interpretation_dependencies {
        bounded_bump(&mut scan_work, 1, max_work)?;
        ids.insert(atom_id.to_string());
    }
    let mut changed = true;
    while changed {
        changed = false;
        for member in &view.admitted.floor.members {
            bounded_bump(&mut scan_work, 1, max_work)?;
            bounded_bump(&mut scan_work, member.required_dependencies.len(), max_work)?;
            if ids.contains(member.atom_id.as_str()) {
                let before = ids.len();
                ids.extend(member.required_dependencies.iter().map(ToString::to_string));
                changed |= ids.len() != before;
            }
        }
        for atom in &view.view.rendered {
            bounded_bump(&mut scan_work, 1, max_work)?;
            bounded_bump(&mut scan_work, atom.dependencies.len(), max_work)?;
            if ids.contains(atom.atom_id.as_str()) {
                let before = ids.len();
                ids.extend(atom.dependencies.iter().map(ToString::to_string));
                changed |= ids.len() != before;
            }
        }
    }
    Some((ids, scan_work))
}

#[allow(clippy::too_many_arguments)]
fn classify_normal(
    atom: &eliot_context_contracts::RenderedAtom,
    record: Option<&eliot_context_contracts::PriorDeliveryBinding>,
    activation_kind: Option<ActivationEvidenceKind>,
    mode: ReactiveDeliveryMode,
    content: &[ReactiveContextContentRef],
    source: &[ReactiveContextContentRef],
    profile: &ReactiveContextContentRef,
    coverage_proof_ceiling: ProofCeiling,
    completeness: SnapshotCompleteness,
    incomplete_activation: bool,
    required: bool,
    view: &ContextPlanningView,
    session: &SessionDeliverySnapshot,
) -> (DeliveryDisposition, String) {
    if let Some(disposition) = classify_privacy_and_proof(atom, coverage_proof_ceiling) {
        return disposition;
    }
    if let Some(disposition) =
        classify_prior_delivery(atom, record, content, source, profile, session, view)
    {
        return disposition;
    }
    if activation_kind.is_none() {
        return (
            if required {
                DeliveryDisposition::ExplicitNotSelected
            } else if incomplete_activation {
                DeliveryDisposition::BoundedOutFrontier
            } else {
                DeliveryDisposition::ExplicitNotSelected
            },
            if required {
                "required Safety Floor item retained for floor closure; activation absence is unresolved"
                    .to_owned()
            } else {
                "item is outside exact activation membership".to_owned()
            },
        );
    }
    (
        match mode {
            ReactiveDeliveryMode::EventIntegrated => DeliveryDisposition::EventPlan,
            _ => DeliveryDisposition::ToolOnlyAdvisory,
        },
        match completeness {
            SnapshotCompleteness::Complete => "exact activation target".to_owned(),
            _ => "activation is partial; absence is not inferred".to_owned(),
        },
    )
}

fn classify_privacy_and_proof(
    atom: &eliot_context_contracts::RenderedAtom,
    coverage_proof_ceiling: ProofCeiling,
) -> Option<(DeliveryDisposition, String)> {
    if atom.privacy != eliot_context_contracts::PrivacyClass::Public {
        return Some((
            DeliveryDisposition::WithheldPrivacy,
            "coverage privacy ceiling is below atom disclosure class".to_owned(),
        ));
    }
    if !atom.proof.ceiling.is_at_most(coverage_proof_ceiling) {
        return Some((
            DeliveryDisposition::WithheldProfile,
            "atom proof ceiling exceeds current integration coverage".to_owned(),
        ));
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn classify_prior_delivery(
    atom: &eliot_context_contracts::RenderedAtom,
    record: Option<&eliot_context_contracts::PriorDeliveryBinding>,
    content: &[ReactiveContextContentRef],
    source: &[ReactiveContextContentRef],
    profile: &ReactiveContextContentRef,
    session: &SessionDeliverySnapshot,
    view: &ContextPlanningView,
) -> Option<(DeliveryDisposition, String)> {
    let record = record?;
    let refs_match = content.len() == 1
        && content
            .first()
            .is_some_and(|current| current == &record.content)
        && source.len() == 1
        && source
            .first()
            .is_some_and(|current| current == &record.source)
        && record.profile == *profile;
    let current = record.validity == eliot_protocol::ReactiveContextValidity::Current
        && record.item_id == atom.atom_id.as_str()
        && refs_match
        && record.session_id == session.session_id
        && record.runtime_id == session.runtime_id
        && record.runtime_generation == session.runtime_generation
        && record.host_generation == session.host_generation
        && record.task_id == session.task_id
        && record.attempt_id == session.attempt_id
        && record.scope_id == session.scope_id
        && record.state_fence == session.state_fence
        && record
            .closure
            .as_ref()
            .is_none_or(|closure| closure.context_view == *view)
        && !matches!(
            record.stage,
            ReactiveContextStage::ValidatedNotEnqueued
                | ReactiveContextStage::CancelledRetracted
                | ReactiveContextStage::StaleSuperseded
                | ReactiveContextStage::UnavailableFenced
        );
    if !current {
        return None;
    }
    Some(match record.stage {
        ReactiveContextStage::DeliveredToExactEndpoint
        | ReactiveContextStage::RecipientReceived
        | ReactiveContextStage::RecipientDurable
        | ReactiveContextStage::NormalizedProjection
        | ReactiveContextStage::AppliedProjection => (
            if record
                .closure
                .as_ref()
                .is_some_and(|closure| closure.context_view == *view)
            {
                DeliveryDisposition::DeliveredDuplicate
            } else {
                DeliveryDisposition::AmbiguousUnknown
            },
            if record
                .closure
                .as_ref()
                .is_some_and(|closure| closure.context_view == *view)
            {
                "exact current owner delivery evidence"
            } else {
                "delivery stage lacks the retained view closure"
            }
            .to_owned(),
        ),
        ReactiveContextStage::EnqueuedPersisted | ReactiveContextStage::DeliveryAttempted => (
            DeliveryDisposition::InFlight,
            "enqueued or attempted state is not delivery".to_owned(),
        ),
        ReactiveContextStage::UnknownDelivery | ReactiveContextStage::AcknowledgementUnknown => (
            DeliveryDisposition::AmbiguousUnknown,
            "unknown delivery requires reconciliation".to_owned(),
        ),
        _ => (
            DeliveryDisposition::ExplicitNotSelected,
            "prior state does not qualify as current delivery".to_owned(),
        ),
    })
}

fn item_handles(
    atom: &eliot_context_contracts::RenderedAtom,
    _policy: &ReactiveDeliveryPolicy,
) -> Result<
    (
        Vec<ReactiveContextContentRef>,
        Vec<ReactiveContextContentRef>,
        u64,
    ),
    ReactiveInputError,
> {
    let contract =
        reactive_context_contract_identity().map_err(|_| ReactiveInputError::InvalidField {
            field: "delivery.contract",
            reason: "reactive context contract identity unavailable",
        })?;
    let bytes = canonical_json_bytes(&atom.representation).map_err(|_| {
        ReactiveInputError::InvalidField {
            field: "delivery.representation",
            reason: "canonical representation serialization failed",
        }
    })?;
    Ok((
        vec![ReactiveContextContentRef {
            contract: contract.clone(),
            source_revision: atom.source_revision.clone(),
            content_sha256: canonical_planning_digest(&atom.representation)?,
            byte_length: Some(bytes.len() as u64),
            artifact_id: Some(atom.atom_id.clone()),
        }],
        vec![ReactiveContextContentRef {
            contract,
            source_revision: atom.source_revision.clone(),
            content_sha256: atom.source_digest.clone(),
            byte_length: None,
            artifact_id: Some(atom.source_id.clone()),
        }],
        bytes.len() as u64,
    ))
}

fn profile_reference(policy: &ReactiveDeliveryPolicy) -> ReactiveContextContentRef {
    policy.delivery_profile.clone()
}

fn attention_item(
    member: &CriticalAttentionMember,
    profile: &ReactiveContextContentRef,
    mode: ReactiveDeliveryMode,
    projection_digest: &str,
) -> Result<PlannedContextItem, ReactiveInputError> {
    let unresolved = matches!(
        member.resolution,
        AttentionResolution::Open | AttentionResolution::Unknown
    );
    let resolution_owner = if matches!(member.resolution, AttentionResolution::Waived) {
        member
            .waiver_authority
            .clone()
            .ok_or(ReactiveInputError::InvalidField {
                field: "delivery.attention.waiver_authority",
                reason: "validated waiver is missing its terminal authority",
            })?
    } else {
        member.owner_id.clone()
    };
    let binding = PlannedAttentionBinding {
        attention_id: member.attention_id.clone(),
        claim_artifact_id: member.claim_artifact_id.clone(),
        claim_digest: member.claim_digest.clone(),
        source_revision: member.source_revision.clone(),
        projection_digest: projection_digest.to_owned(),
        member_owner_id: member.owner_id.clone(),
        resolution_owner,
        waiver_authority: member.waiver_authority.clone(),
        superseded_by: member.superseded_by.clone(),
        acknowledgement: member.acknowledgement,
        resolution: member.resolution,
        sticky: unresolved,
        // The planner observes the owner state; coverage capability is not
        // proof of an Attention claim.
        proof_ceiling: ProofCeiling::Observation,
    };
    let byte_cost = canonical_json_bytes(&(
        &binding,
        &member.kind,
        profile,
        &member.source,
        &member.evidence,
    ))
    .map_err(|_| ReactiveInputError::InvalidField {
        field: "delivery.attention",
        reason: "opaque Attention material serialization failed",
    })?;
    Ok(PlannedContextItem {
        item_id: member.attention_id.to_string(),
        kind: PlannedItemKind::Attention,
        rendered: None,
        content: member.source.clone(),
        source: member.evidence.clone(),
        profile: profile.clone(),
        activation_kind: None,
        activation_targets: Vec::new(),
        attention_kind: Some(member.kind.clone()),
        attention: Some(binding),
        omission: None,
        disposition: if unresolved {
            DeliveryDisposition::StickyPendingResolution
        } else {
            DeliveryDisposition::ExplicitNotSelected
        },
        // Only the bounded opaque handle set is selected.  Its canonical size
        // is known; any material behind these handles remains downstream work.
        byte_cost: u64::try_from(byte_cost.len()).map_err(|_| {
            ReactiveInputError::InvalidField {
                field: "delivery.attention",
                reason: "opaque Attention handle size overflowed",
            }
        })?,
        stu_cost: None,
        reason: if unresolved {
            format!("unresolved Attention retained for {mode:?} mode")
        } else {
            "owner-issued terminal resolution retained as history".to_owned()
        },
    })
}

fn force_complete_floor(
    items: &mut [PlannedContextItem],
    required: &BTreeSet<String>,
    mode: ReactiveDeliveryMode,
) {
    let disposition = match mode {
        ReactiveDeliveryMode::EventIntegrated => DeliveryDisposition::EventPlan,
        _ => DeliveryDisposition::ToolOnlyAdvisory,
    };
    for item in items {
        if required.contains(&item.item_id)
            && matches!(
                item.disposition,
                DeliveryDisposition::ExplicitNotSelected
                    | DeliveryDisposition::BoundedOutFrontier
                    | DeliveryDisposition::DeliveredDuplicate
            )
        {
            item.disposition = disposition;
            "required Safety Floor included with new injection".clone_into(&mut item.reason);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_accounting(
    items: &[PlannedContextItem],
    policy: &ReactiveDeliveryPolicy,
    required_ids: &BTreeSet<String>,
    required_attention: bool,
    input_bytes: u64,
    planning_work: u64,
    request: Option<&InertDeliveryRequest>,
    sticky_obligations: u64,
    input_references: u64,
) -> Result<PlanningAccounting, ReactiveContextPlanningError> {
    let totals = accounting_totals(items, policy, required_ids, required_attention)?;
    let reserves = reserve_bytes(policy)
        .ok_or_else(|| accounting_overflow(policy, "delivery reserve accounting overflowed"))?;
    let references = input_references;
    let work = planning_work;
    let delivery_bytes = request.map_or(totals.item_delivery_bytes, |request| {
        request.serialized_bytes
    });
    let selected_delivery_stu = match policy.max_delivery_stu {
        Some(_) => Some(
            delivery_bytes
                .checked_add(2)
                .ok_or_else(|| accounting_overflow(policy, "STU estimate overflowed"))?
                / 3,
        ),
        None => None,
    };
    let budget_fit = accounting_budget_fit(
        policy,
        input_bytes,
        items.len(),
        references,
        work,
        reserves,
        delivery_bytes,
        totals.required_floor_bytes,
        totals.required_attention_bytes,
        selected_delivery_stu,
    );
    Ok(PlanningAccounting {
        considered: items.len() as u64,
        planned: totals.selected.len() as u64,
        deduped: items
            .iter()
            .filter(|item| matches!(item.disposition, DeliveryDisposition::DeliveredDuplicate))
            .count() as u64,
        delayed: items
            .iter()
            .filter(|item| {
                matches!(
                    item.disposition,
                    DeliveryDisposition::DelayedBackpressure | DeliveryDisposition::InFlight
                )
            })
            .count() as u64,
        withheld: items
            .iter()
            .filter(|item| {
                matches!(
                    item.disposition,
                    DeliveryDisposition::WithheldBudget
                        | DeliveryDisposition::WithheldPrivacy
                        | DeliveryDisposition::WithheldProfile
                )
            })
            .count() as u64,
        sticky: sticky_obligations,
        unsupported: items
            .iter()
            .filter(|item| {
                matches!(
                    item.disposition,
                    DeliveryDisposition::UnsupportedCapability
                        | DeliveryDisposition::AmbiguousUnknown
                )
            })
            .count() as u64,
        frontier: items
            .iter()
            .filter(|item| matches!(item.disposition, DeliveryDisposition::BoundedOutFrontier))
            .count() as u64,
        input_bytes,
        references,
        work,
        selected_delivery_bytes: delivery_bytes,
        selected_delivery_stu,
        fixed_reserve: policy.fixed_reserve,
        protocol_reserve: policy.protocol_reserve,
        output_reserve: policy.output_reserve,
        review_reserve: policy.review_reserve,
        delivery_reserve: policy.delivery_reserve,
        required_floor_bytes: totals.required_floor_bytes,
        required_attention_bytes: totals.required_attention_bytes,
        budget_fit,
    })
}

struct AccountingTotals<'a> {
    selected: Vec<&'a PlannedContextItem>,
    item_delivery_bytes: u64,
    required_floor_bytes: u64,
    required_attention_bytes: u64,
}

fn accounting_totals<'a>(
    items: &'a [PlannedContextItem],
    policy: &ReactiveDeliveryPolicy,
    required_ids: &BTreeSet<String>,
    required_attention: bool,
) -> Result<AccountingTotals<'a>, ReactiveContextPlanningError> {
    let selected: Vec<_> = items
        .iter()
        .filter(|item| {
            matches!(
                item.disposition,
                DeliveryDisposition::EventPlan
                    | DeliveryDisposition::ToolOnlyAdvisory
                    | DeliveryDisposition::StickyPendingResolution
            )
        })
        .collect();
    let item_delivery_bytes = selected
        .iter()
        .try_fold(0u64, |total, item| {
            total.checked_add(item.byte_cost).ok_or(())
        })
        .map_err(|()| accounting_overflow(policy, "delivery byte accounting overflowed"))?;
    let required_floor_bytes = items
        .iter()
        .filter(|item| required_ids.contains(&item.item_id))
        .map(|item| item.byte_cost)
        .try_fold(0u64, u64::checked_add)
        .ok_or_else(|| accounting_overflow(policy, "required floor byte accounting overflowed"))?;
    let required_attention_bytes = if required_attention {
        items
            .iter()
            .filter(|item| {
                item.kind == PlannedItemKind::Attention
                    && item
                        .attention
                        .as_ref()
                        .is_some_and(|attention| attention.sticky)
            })
            .map(|item| item.byte_cost)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| accounting_overflow(policy, "Attention byte accounting overflowed"))?
    } else {
        0
    };
    Ok(AccountingTotals {
        selected,
        item_delivery_bytes,
        required_floor_bytes,
        required_attention_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn accounting_budget_fit(
    policy: &ReactiveDeliveryPolicy,
    input_bytes: u64,
    item_count: usize,
    references: u64,
    work: u64,
    reserves: u64,
    delivery_bytes: u64,
    required_floor_bytes: u64,
    required_attention_bytes: u64,
    selected_delivery_stu: Option<u64>,
) -> bool {
    let budget_fit = input_bytes <= policy.max_input_bytes
        && (item_count as u64) <= policy.max_items
        && references <= policy.max_references
        && work <= policy.max_work
        && reserves
            .checked_add(delivery_bytes)
            .is_some_and(|total| total <= policy.max_delivery_bytes)
        && required_floor_bytes
            .checked_add(required_attention_bytes)
            .and_then(|required| reserves.checked_add(required))
            .is_some_and(|required| required <= policy.max_delivery_bytes);
    budget_fit
        && selected_delivery_stu
            .is_none_or(|stu| policy.max_delivery_stu.is_some_and(|limit| stu <= limit))
}

fn inert_request(
    selected: &[PlannedContextItem],
    mode: ReactiveDeliveryMode,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    proof_ceiling: ProofCeiling,
) -> Result<InertDeliveryRequest, ReactiveInputError> {
    let mut request = inert_request_skeleton(selected, mode, session, policy, proof_ceiling);
    request.request_digest = inert_request_digest(&request)?;
    seal_inert_request_length(request)
}

fn inert_request_skeleton(
    selected: &[PlannedContextItem],
    mode: ReactiveDeliveryMode,
    session: &SessionDeliverySnapshot,
    policy: &ReactiveDeliveryPolicy,
    proof_ceiling: ProofCeiling,
) -> InertDeliveryRequest {
    let selected_attention_privacy = selected
        .iter()
        .filter(|item| item.kind == PlannedItemKind::Attention)
        .filter_map(|item| {
            policy
                .attention_disclosure
                .iter()
                .find(|rule| rule.attention_id.as_str() == item.item_id)
                .map(|rule| rule.minimum_privacy)
        })
        .max()
        .unwrap_or(ReactiveContextPrivacy::Public);
    InertDeliveryRequest {
        request_id: policy.request_id.clone(),
        operation_id: policy.operation_id.clone(),
        idempotency_key: policy.idempotency_key.clone(),
        plan_id: policy.plan_id.clone(),
        target_event_id: policy.target_event_id.clone(),
        target_event: policy.target_event.clone(),
        delivery_profile: policy.delivery_profile.clone(),
        delivery_contract: policy.delivery_contract.clone(),
        mode,
        session_id: session.session_id.clone(),
        principal_id: session.principal_id.clone(),
        recipient_id: session.recipient_id.clone(),
        runtime_id: session.runtime_id.clone(),
        host_id: session.host_id.clone(),
        runtime_generation: session.runtime_generation,
        host_generation: session.host_generation,
        task_id: session.task_id.clone(),
        attempt_id: session.attempt_id.clone(),
        scope_id: session.scope_id.clone(),
        state_fence: session.state_fence.clone(),
        observed_at: policy.observed_at,
        deadline_ms: policy.deadline_ms,
        privacy_ceiling: selected_attention_privacy,
        proof_ceiling,
        items: selected.to_vec(),
        request_digest: String::new(),
        serialized_bytes: 0,
    }
}

fn inert_request_digest(request: &InertDeliveryRequest) -> Result<String, ReactiveInputError> {
    let digest_preimage = canonical_json_bytes(&(
        (
            &request.request_id,
            &request.operation_id,
            &request.idempotency_key,
            &request.plan_id,
            &request.target_event_id,
            &request.target_event,
        ),
        (
            &request.delivery_profile,
            &request.delivery_contract,
            &request.mode,
            &request.session_id,
            &request.principal_id,
            &request.recipient_id,
        ),
        (
            &request.runtime_id,
            &request.host_id,
            &request.runtime_generation,
            &request.host_generation,
            &request.task_id,
            &request.attempt_id,
        ),
        (
            &request.scope_id,
            &request.state_fence,
            &request.observed_at,
            &request.deadline_ms,
            &request.privacy_ceiling,
            &request.proof_ceiling,
            &request.items,
        ),
    ))
    .map_err(|_| ReactiveInputError::InvalidField {
        field: "delivery.request",
        reason: "canonical inert request digest preimage failed",
    })?;
    Ok(eliot_contracts::sha256_hex(&digest_preimage))
}

fn seal_inert_request_length(
    mut request: InertDeliveryRequest,
) -> Result<InertDeliveryRequest, ReactiveInputError> {
    let mut previous = None;
    for _ in 0..4 {
        let bytes =
            canonical_json_bytes(&request).map_err(|_| ReactiveInputError::InvalidField {
                field: "delivery.request",
                reason: "canonical inert request serialization failed",
            })?;
        let length = u64::try_from(bytes.len()).map_err(|_| ReactiveInputError::InvalidField {
            field: "delivery.request",
            reason: "canonical inert request size overflowed",
        })?;
        request.serialized_bytes = length;
        if previous == Some(length) {
            return Ok(request);
        }
        previous = Some(length);
    }
    let bytes = canonical_json_bytes(&request).map_err(|_| ReactiveInputError::InvalidField {
        field: "delivery.request",
        reason: "canonical inert request serialization failed",
    })?;
    if u64::try_from(bytes.len()).ok() == Some(request.serialized_bytes) {
        return Ok(request);
    }
    Err(ReactiveInputError::InvalidField {
        field: "delivery.request",
        reason: "canonical inert request size did not converge",
    })
}

fn accounting_overflow(
    policy: &ReactiveDeliveryPolicy,
    detail: &str,
) -> ReactiveContextPlanningError {
    ReactiveContextPlanningError {
        disposition: PlanningErrorDisposition::Failed,
        kind: PlanningErrorKind::Overflow,
        reason_code: "ACCOUNTING_OVERFLOW".to_owned(),
        operation_id: Some(policy.operation_id.clone()),
        request_id: Some(policy.request_id.clone()),
        input_digest: None,
        detail: detail.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn output_digest(
    base: &OutputIdentity,
    outcome: &str,
    mode: Option<ReactiveDeliveryMode>,
    reason: Option<&str>,
    items: &[PlannedContextItem],
    accounting: &PlanningAccounting,
    frontier: &[String],
    invalidation: &[String],
    request: Option<&InertDeliveryRequest>,
) -> Result<String, ReactiveInputError> {
    canonical_planning_digest(&(
        (
            "eliot.reactive-context-plan.result.v1",
            outcome,
            &mode,
            &reason,
            &base.request_id,
            &base.operation_id,
            &base.idempotency_key,
            &base.plan_id,
            &base.input_digest,
            &base.policy_digest,
        ),
        (
            &base.view_digest,
            &base.admitted_set_digest,
            &base.assembly_digest,
            &base.activation_digest,
            &base.activation_result,
            &base.session_snapshot_digest,
            &base.attention_projection_digest,
            &base.coverage_profile_digest,
            &base.coverage_completeness,
            &base.coverage_gaps,
            &base.selected_event_evidence,
            &base.session_completeness,
            &base.session_denominator,
            &base.context_measurement,
            &base.floor_capacity,
            &base.floor_incomplete,
        ),
        (items, accounting, frontier, invalidation, request),
    ))
}

fn no_injection_with_items(
    base: &OutputIdentity,
    reason: &str,
    items: Vec<PlannedContextItem>,
    mut accounting: PlanningAccounting,
    frontier: Vec<String>,
) -> Result<ReactiveContextPlanResult, ReactiveContextPlanningError> {
    accounting.planned = 0;
    accounting.selected_delivery_bytes = 0;
    accounting.selected_delivery_stu = None;
    let result_digest = output_digest(
        base,
        "NO_INJECTION",
        None,
        Some(reason),
        &items,
        &accounting,
        &frontier,
        &[],
        None,
    )
    .map_err(|_| ReactiveContextPlanningError {
        disposition: PlanningErrorDisposition::Failed,
        kind: PlanningErrorKind::InternalContract,
        reason_code: "RESULT_DIGEST_FAILURE".to_owned(),
        operation_id: Some(base.operation_id.clone()),
        request_id: Some(base.request_id.clone()),
        input_digest: Some(base.input_digest.clone()),
        detail: "canonical no-injection result digest failed".to_owned(),
    })?;
    Ok(ReactiveContextPlanResult::NoInjection(
        NoInjectionDisposition {
            request_id: base.request_id.clone(),
            operation_id: base.operation_id.clone(),
            idempotency_key: base.idempotency_key.clone(),
            plan_id: base.plan_id.clone(),
            input_digest: base.input_digest.clone(),
            result_digest,
            view_digest: base.view_digest.clone(),
            admitted_set_digest: base.admitted_set_digest.clone(),
            assembly_digest: base.assembly_digest.clone(),
            activation_digest: base.activation_digest.clone(),
            activation_result: base.activation_result.clone(),
            session_snapshot_digest: base.session_snapshot_digest.clone(),
            attention_projection_digest: base.attention_projection_digest.clone(),
            coverage_profile_digest: base.coverage_profile_digest.clone(),
            coverage_completeness: base.coverage_completeness,
            coverage_gaps: base.coverage_gaps.clone(),
            selected_event_evidence: base.selected_event_evidence.clone(),
            session_completeness: base.session_completeness,
            session_denominator: base.session_denominator,
            context_measurement: base.context_measurement.clone(),
            floor_capacity: base.floor_capacity,
            floor_incomplete: base.floor_incomplete.clone(),
            policy_digest: base.policy_digest.clone(),
            reason: reason.to_owned(),
            items,
            accounting,
            frontier,
            invalidation: Vec::new(),
        },
    ))
}
