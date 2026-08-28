//! Packet-local continuity for project understanding.
//!
//! Architecture anchors: `A7.6` (Compaction and resume) and `ARCH-CORE-01`
//! (Understanding continuity first, `ELIOT_ARCHITECTURE.md` 4.5-draft
//! `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8`).
//! Implementation anchors: `I12.17` (Compaction and resume) and `I7.15`
//! (Route Continuation and transfer, `ELIOT_IMPLEMENTATION.md` 0.29-draft
//! `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B`).
//! Normative code: `crates/eliot-engine/src/project_understanding.rs`
//! (`ProjectUnderstandingCompiler` at `project_understanding.rs:9`, continuity
//! call sites at `context.rs:2939,2943,4552,4559`) and `crates/eliot-types`
//! `ContextPacketL3` / `DecisionLocalitySuffix`.
//!
//! Ownership: `crates/eliot-engine` owns this packet-local continuity seam
//! (restore/normalize + `union`); `crates/eliot-types` owns packet truth packet
//! types; `crates/eliot-engine/src/context.rs` owns the `ContextCompiler`
//! call site. This child is a pure helper with no provider, process, or
//! canonical-write authority and does not change `ProjectUnderstandingCompiler`
//! semantics.

use std::collections::BTreeSet;

use eliot_types::ContextPacketL3;

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

fn union(left: &[String], right: &[String]) -> Vec<String> {
    super::dedup(left.iter().chain(right).cloned())
}
