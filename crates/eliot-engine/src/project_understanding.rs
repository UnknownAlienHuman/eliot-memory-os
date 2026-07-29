use eliot_types::{
    CausalHopKind, CausalHopStatus, ContextPacketL3, ContinuityAcceptanceState,
    MaterialPacketFrame, PROJECT_UNDERSTANDING_SCHEMA_VERSION, ProjectCausalHop,
    ProjectCausalModel, ProjectUnderstandingEvidence, ProjectUnderstandingIntent,
    ProjectUnderstandingModel, ProjectUnderstandingSystem, TaskContract,
};
use std::collections::BTreeSet;

pub struct ProjectUnderstandingCompiler;

impl ProjectUnderstandingCompiler {
    #[must_use]
    pub fn compile(
        packet: &ContextPacketL3,
        frame: Option<&MaterialPacketFrame>,
        task: Option<&TaskContract>,
        evidence: &ProjectUnderstandingEvidence,
    ) -> ProjectUnderstandingModel {
        let restored_frame = frame_from_packet(packet);
        let frame = frame.unwrap_or(&restored_frame);
        let current_truth_refs = current_truth_refs(packet);
        let memory_refs_used = memory_refs_used(packet, evidence);
        let acceptance_refs = acceptance_state(packet, task)
            .iter()
            .map(|item| item.acceptance_ref.clone())
            .collect();
        let causal_model = causal_model(packet, frame, evidence);
        let files_to_inspect = packet.codecortex.as_ref().map_or_else(Vec::new, |view| {
            dedup(view.file_evidence.iter().map(|item| item.path.clone()))
        });
        let predicted_changed_paths = dedup(frame.predicted_changed_paths.iter().cloned());
        let predicted_failing_verifiers = dedup(frame.predicted_failing_verifiers.iter().cloned());
        let next_allowed_action = frame.next_allowed_action.clone();
        let expected_observable = frame.expected_observable.clone();
        let verifier_ref = frame.verifier.clone();

        ProjectUnderstandingModel {
            schema_version: PROJECT_UNDERSTANDING_SCHEMA_VERSION.to_owned(),
            project_id: packet.project_id,
            task_id: packet.task_id.clone(),
            revision_fence: packet.at_revision,
            intent: ProjectUnderstandingIntent {
                exact_user_goal_ref: format!(
                    "eliot/task/{}@{}",
                    packet.task_id,
                    packet.at_revision.value()
                ),
                normalized_goal: eliot_types::normalize_unicode_lowercase(&packet.goal),
                desired_state_transition: if next_allowed_action.trim().is_empty() {
                    packet.goal.clone()
                } else {
                    next_allowed_action.clone()
                },
                non_goals: dedup(evidence.non_goals.iter().cloned()),
                acceptance_refs,
            },
            system: ProjectUnderstandingSystem {
                project_purpose: evidence.project_purpose.clone(),
                subsystem_refs: dedup(evidence.subsystem_refs.iter().cloned()),
                owner_modules: dedup(evidence.owner_modules.iter().cloned()),
                entrypoint_refs: dedup(evidence.entrypoint_refs.iter().cloned()),
            },
            causal_model,
            invariants: dedup(
                frame
                    .invariant_refs
                    .iter()
                    .chain(&evidence.invariant_refs)
                    .cloned(),
            ),
            danger_and_negative_memory: danger_refs(packet, evidence),
            current_truth_refs: current_truth_refs.clone(),
            historical_or_stale_refs: historical_refs(packet),
            memory_refs_used: memory_refs_used.clone(),
            files_to_inspect,
            files_to_change: predicted_changed_paths.clone(),
            predicted_changed_paths,
            predicted_failing_verifiers,
            next_allowed_action: next_allowed_action.clone(),
            expected_observable: expected_observable.clone(),
            verifier_ref: verifier_ref.clone(),
            stop_condition: frame.stop_condition.clone(),
        }
    }
}

pub struct ProjectContinuityService;

impl ProjectContinuityService {
    pub fn restore(packet: &mut ContextPacketL3, previous: Option<&ContextPacketL3>) {
        let Some(previous) = previous.filter(|previous| {
            previous.project_id == packet.project_id && previous.task_id == packet.task_id
        }) else {
            normalize_active_plan(packet);
            return;
        };

        packet.completed_work = union(&previous.completed_work, &packet.completed_work);
        packet.killed_paths = union(&previous.killed_paths, &packet.killed_paths);
        restore_prediction_state(packet, previous);
        if packet.active_plan.is_empty() {
            packet.active_plan.clone_from(&previous.active_plan);
        }
        if packet.acceptance_items.is_empty() {
            packet
                .acceptance_items
                .clone_from(&previous.acceptance_items);
        }
        restore_locality(&mut packet.decision_locality_suffix, previous);
        normalize_active_plan(packet);
    }
}

fn restore_prediction_state(packet: &mut ContextPacketL3, previous: &ContextPacketL3) {
    let (Some(current), Some(previous)) = (
        packet.project_understanding.as_mut(),
        previous.project_understanding.as_ref(),
    ) else {
        return;
    };
    if current.predicted_changed_paths.is_empty() {
        current
            .predicted_changed_paths
            .clone_from(&previous.predicted_changed_paths);
        current
            .files_to_change
            .clone_from(&previous.files_to_change);
    }
    if current.predicted_failing_verifiers.is_empty() {
        current
            .predicted_failing_verifiers
            .clone_from(&previous.predicted_failing_verifiers);
    }
}

fn restore_locality(current: &mut eliot_types::DecisionLocalitySuffix, previous: &ContextPacketL3) {
    let previous = &previous.decision_locality_suffix;
    if current.next_allowed_action.trim().is_empty() {
        current
            .next_allowed_action
            .clone_from(&previous.next_allowed_action);
    }
    if current.expected_observable.trim().is_empty() {
        current
            .expected_observable
            .clone_from(&previous.expected_observable);
    }
    if current.verifier.trim().is_empty() {
        current.verifier.clone_from(&previous.verifier);
    }
    if current.stop_condition.trim().is_empty() {
        current.stop_condition.clone_from(&previous.stop_condition);
    }
    current.open_unknowns = union(&previous.open_unknowns, &current.open_unknowns);
    current.cheapest_discriminative_probes = union(
        &previous.cheapest_discriminative_probes,
        &current.cheapest_discriminative_probes,
    );
    current.responsibility_contour_route_refs = union(
        &previous.responsibility_contour_route_refs,
        &current.responsibility_contour_route_refs,
    );
}

fn normalize_active_plan(packet: &mut ContextPacketL3) {
    let terminal = packet
        .completed_work
        .iter()
        .chain(&packet.killed_paths)
        .map(|item| eliot_types::normalize_unicode_lowercase(item))
        .collect::<BTreeSet<_>>();
    packet
        .active_plan
        .retain(|item| !terminal.contains(&eliot_types::normalize_unicode_lowercase(item)));
    let next = eliot_types::normalize_unicode_lowercase(
        &packet.decision_locality_suffix.next_allowed_action,
    );
    if !next.is_empty() && terminal.contains(&next) {
        packet.decision_locality_suffix.next_allowed_action.clear();
        packet
            .decision_locality_suffix
            .open_unknowns
            .push("next action was already completed or killed; replan required".to_owned());
        packet.decision_locality_suffix.open_unknowns.sort();
        packet.decision_locality_suffix.open_unknowns.dedup();
    }
}

#[allow(clippy::too_many_lines)]
fn causal_model(
    packet: &ContextPacketL3,
    frame: &MaterialPacketFrame,
    evidence: &ProjectUnderstandingEvidence,
) -> ProjectCausalModel {
    let intent_ref = format!("intent:{}", packet.task_id);
    let concept_ref = evidence
        .subsystem_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown:concept".to_owned());
    let owner_ref = evidence
        .owner_modules
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown:owner".to_owned());
    let symbol_ref = evidence
        .entrypoint_refs
        .first()
        .cloned()
        .or_else(|| {
            packet.codecortex.as_ref().and_then(|view| {
                view.symbol_evidence
                    .first()
                    .map(|symbol| symbol.name.clone())
            })
        })
        .unwrap_or_else(|| "unknown:symbol".to_owned());
    let flow_ref = evidence
        .flow_evidence_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown:state-or-flow".to_owned());
    let observable_ref = nonempty_or(&frame.expected_observable, "unknown:observable");
    let verifier_ref = nonempty_or(&frame.verifier, "unknown:verifier");

    let definitions = [
        (
            CausalHopKind::IntentToConcept,
            intent_ref,
            "scoped_to",
            concept_ref.clone(),
            evidence.artifact_refs.clone(),
            CausalHopStatus::Supported,
        ),
        (
            CausalHopKind::ConceptToOwner,
            concept_ref,
            "owned_by",
            owner_ref.clone(),
            evidence.artifact_refs.clone(),
            CausalHopStatus::Supported,
        ),
        (
            CausalHopKind::OwnerToSymbol,
            owner_ref,
            "implemented_by",
            symbol_ref.clone(),
            codecortex_refs(packet),
            CausalHopStatus::Verified,
        ),
        (
            CausalHopKind::SymbolToStateOrFlow,
            symbol_ref,
            "participates_in",
            flow_ref.clone(),
            evidence.flow_evidence_refs.clone(),
            CausalHopStatus::Supported,
        ),
        (
            CausalHopKind::FlowToObservable,
            flow_ref,
            "predicts",
            observable_ref.clone(),
            Vec::new(),
            CausalHopStatus::Assumed,
        ),
        (
            CausalHopKind::ObservableToVerifier,
            observable_ref,
            "verified_by",
            verifier_ref,
            verifier_refs(packet),
            CausalHopStatus::Supported,
        ),
    ];

    let mut unknown_hops = Vec::new();
    let mut required_probes = frame.cheapest_discriminative_probes.clone();
    let hops = definitions
        .into_iter()
        .map(
            |(hop_kind, from, relation, to, evidence_refs, supported_status)| {
                let unknown = from.starts_with("unknown:") || to.starts_with("unknown:");
                if unknown {
                    unknown_hops.push(hop_kind);
                    required_probes.push(format!("resolve {hop_kind:?}"));
                }
                ProjectCausalHop {
                    hop_kind,
                    from,
                    relation: relation.to_owned(),
                    to,
                    evidence_refs: dedup(evidence_refs),
                    status: if unknown {
                        CausalHopStatus::Unknown
                    } else {
                        supported_status
                    },
                }
            },
        )
        .collect();
    required_probes.sort();
    required_probes.dedup();
    ProjectCausalModel {
        hops,
        unknown_hops,
        required_probes,
    }
}

fn acceptance_state(
    packet: &ContextPacketL3,
    task: Option<&TaskContract>,
) -> Vec<ContinuityAcceptanceState> {
    task.map_or_else(
        || {
            packet
                .acceptance_items
                .iter()
                .map(|item| ContinuityAcceptanceState {
                    acceptance_ref: item.clone(),
                    satisfied: packet.completed_work.contains(item),
                })
                .collect()
        },
        |task| {
            task.acceptance_items
                .iter()
                .map(|item| ContinuityAcceptanceState {
                    acceptance_ref: item.item_id.clone(),
                    satisfied: item.satisfied,
                })
                .collect()
        },
    )
}

fn current_truth_refs(packet: &ContextPacketL3) -> Vec<String> {
    dedup(
        packet
            .current_truth
            .iter()
            .map(|claim| format!("claim:{}", claim.claim_id)),
    )
}

fn historical_refs(packet: &ContextPacketL3) -> Vec<String> {
    dedup(
        packet
            .historical_memory
            .iter()
            .map(|claim| format!("claim:{}", claim.claim_id)),
    )
}

fn memory_refs_used(
    packet: &ContextPacketL3,
    evidence: &ProjectUnderstandingEvidence,
) -> Vec<String> {
    dedup(
        packet
            .exact_handles
            .iter()
            .chain(&evidence.artifact_refs)
            .cloned()
            .chain(
                packet
                    .memory_decisions
                    .iter()
                    .map(|decision| decision.memory_handle.clone()),
            ),
    )
}

fn danger_refs(packet: &ContextPacketL3, evidence: &ProjectUnderstandingEvidence) -> Vec<String> {
    dedup(
        evidence
            .danger_refs
            .iter()
            .cloned()
            .chain(
                packet
                    .negative_memory
                    .iter()
                    .map(|claim| format!("claim:{}", claim.claim_id)),
            )
            .chain(
                packet
                    .recent_failures
                    .iter()
                    .map(|failure| format!("failure:{}", failure.fingerprint)),
            ),
    )
}

fn codecortex_refs(packet: &ContextPacketL3) -> Vec<String> {
    packet
        .codecortex
        .as_ref()
        .map_or_else(Vec::new, |view| view.report_refs.clone())
}

fn verifier_refs(packet: &ContextPacketL3) -> Vec<String> {
    packet.codecortex.as_ref().map_or_else(Vec::new, |view| {
        dedup(
            view.verifier_map
                .iter()
                .map(|verifier| format!("verifier:{}", verifier.name)),
        )
    })
}

fn nonempty_or(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn frame_from_packet(packet: &ContextPacketL3) -> MaterialPacketFrame {
    let prediction = packet.project_understanding.as_ref();
    MaterialPacketFrame {
        acceptance_items: packet.acceptance_items.clone(),
        environment: packet
            .current_truth_snapshot
            .as_ref()
            .map_or_else(Vec::new, |snapshot| snapshot.environment.clone()),
        active_plan: packet.active_plan.clone(),
        completed_work: packet.completed_work.clone(),
        killed_paths: packet.killed_paths.clone(),
        causal_bridge: packet.causal_bridge.clone(),
        negative_memory_checked: !packet.negative_memory.is_empty()
            || packet
                .memory_decisions
                .iter()
                .any(|decision| decision.memory_handle.contains("failure")),
        exact_load_bearing_atoms: packet
            .decision_locality_suffix
            .exact_load_bearing_atoms
            .clone(),
        cheapest_discriminative_probes: packet
            .decision_locality_suffix
            .cheapest_discriminative_probes
            .clone(),
        responsibility_contour_route_refs: packet
            .decision_locality_suffix
            .responsibility_contour_route_refs
            .clone(),
        next_allowed_action: packet.decision_locality_suffix.next_allowed_action.clone(),
        expected_observable: packet.decision_locality_suffix.expected_observable.clone(),
        verifier: packet.decision_locality_suffix.verifier.clone(),
        stop_condition: packet.decision_locality_suffix.stop_condition.clone(),
        tool_schema_bytes_visible: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.tool_schema_bytes_visible),
        instruction_hotset_size: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.instruction_hotset_size),
        invariant_refs: prediction.map_or_else(Vec::new, |model| model.invariants.clone()),
        waived_invariants: Vec::new(),
        prediction_confidence: None,
        predicted_changed_paths: prediction
            .map_or_else(Vec::new, |model| model.predicted_changed_paths.clone()),
        predicted_failing_verifiers: prediction
            .map_or_else(Vec::new, |model| model.predicted_failing_verifiers.clone()),
    }
}

fn union(left: &[String], right: &[String]) -> Vec<String> {
    dedup(left.iter().chain(right).cloned())
}

fn dedup(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
