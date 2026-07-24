use eliot_engine::{MetacognitionService, UlLedgerAccumulator, UlLedgerService, UlToolMeasurement};
use eliot_types::{
    ConceptKind, ConceptNode, CoverageClass, CueBinding, CueKind, CueMatchMode, CueRecordSource,
    CueStrength, DependencyManifest, InjectionReceipt, ModuleCard, ProjectId, SessionId,
    SubsystemCapsule, TaskId, UlTaskLedger,
};
use serde_json::json;
use std::path::Path;

#[test]
fn t07_ledger_counts_bytes_and_injections() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let mut accumulator = UlLedgerAccumulator::default();
    let read = accumulator.record(&measurement(
        project_id,
        task_id,
        session_id,
        "eliot_current_state",
        json!({"project_id": project_id}),
        40,
        84,
        vec![
            receipt(session_id, task_id, "claim:one", 7),
            receipt(session_id, task_id, "claim:two", 9),
        ],
    ));
    let mutation = accumulator.record(&measurement(
        project_id,
        task_id,
        session_id,
        "eliot_agent_candidate_submit",
        json!({"statement": "material"}),
        100,
        120,
        vec![receipt(session_id, task_id, "claim:three", 3)],
    ));
    let after_mutation = accumulator.record(&measurement(
        project_id,
        task_id,
        session_id,
        "eliot_recall_l0",
        json!({"query": "ignored exploration"}),
        200,
        240,
        Vec::new(),
    ));
    let ledger = ledger_from_deltas(project_id, task_id, &[read, mutation, after_mutation]);
    let report = UlLedgerService::use_report(project_id, std::slice::from_ref(&ledger), 3);

    assert_eq!(ledger.read_tool_input_bytes, 40);
    assert_eq!(ledger.read_tool_output_bytes, 84);
    assert_eq!(ledger.injected_tokens, 19);
    assert!(ledger.first_mutation_seen);
    assert_eq!(report.exploration_tokens, 31);
    assert_eq!(report.injected_tokens, 19);
}

#[test]
fn t07_ack_and_expand_metrics_are_honest() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let mut accumulator = UlLedgerAccumulator::default();
    let handles = ["claim:one", "claim:two", "claim:three", "claim:four"];
    let mut deltas = vec![
        accumulator.record(&measurement(
            project_id,
            task_id,
            session_id,
            "eliot_current_state",
            json!({"project_id": project_id}),
            1,
            1,
            handles
                .iter()
                .map(|handle| receipt(session_id, task_id, handle, 5))
                .collect(),
        )),
    ];
    for (tool, arguments) in [
        (
            "eliot_memory_influence_trace",
            json!({
                "memory_handle": "claim:one",
                "influence_class": "used_and_changed_action",
                "downstream_outcome_ref": "verification:one"
            }),
        ),
        ("eliot_fetch_l2", json!({"handles": ["claim:two"]})),
        (
            "eliot_memory_influence_trace",
            json!({
                "memory_handle": "claim:three",
                "influence_class": "used_for_verification",
                "downstream_outcome_ref": "verification:three"
            }),
        ),
        (
            "eliot_memory_influence_trace",
            json!({
                "memory_handle": "claim:never-delivered",
                "influence_class": "seen_but_not_used"
            }),
        ),
        (
            "eliot_memory_influence_trace",
            json!({
                "memory_handle": "claim:one",
                "influence_class": "used_and_changed_action",
                "downstream_outcome_ref": "verification:repeated"
            }),
        ),
    ] {
        deltas.push(accumulator.record(&measurement(
            project_id,
            task_id,
            session_id,
            tool,
            arguments,
            0,
            0,
            Vec::new(),
        )));
    }
    let ledger = ledger_from_deltas(project_id, task_id, &deltas);

    assert_eq!(ledger.acknowledged_items, 2);
    assert_eq!(ledger.expanded_injected_handles, 1);
    assert_eq!(ledger.injected_tokens, 20);
}

#[test]
fn t07_coverage_classes_are_exact() {
    let project_id = ProjectId::new_v7();
    let concepts = vec![
        concept(project_id, "covered", "covered"),
        concept(project_id, "thin", "thin"),
        concept(project_id, "blind", "blind"),
    ];
    let capsules = vec![capsule(project_id, "covered"), capsule(project_id, "thin")];
    let cards = vec![card(project_id, "covered/src/lib.rs")];
    let cue_sources = vec![
        source("claim:covered", "claim", "covered/src/lib.rs", false),
        source("decision:covered", "decision", "covered/src/lib.rs", false),
        source(
            "failure:covered",
            "failure_fingerprint",
            "covered/src/lib.rs",
            true,
        ),
    ];
    let view = MetacognitionService::evaluate(
        Path::new("."),
        &concepts,
        &capsules,
        &cards,
        &[],
        &cue_sources,
        &[],
    );
    let classes = view
        .coverage
        .iter()
        .map(|coverage| (coverage.concept_id.as_str(), coverage.coverage))
        .collect::<std::collections::BTreeMap<_, _>>();

    assert_eq!(classes["covered"], CoverageClass::Covered);
    assert_eq!(classes["thin"], CoverageClass::Thin);
    assert_eq!(classes["blind"], CoverageClass::Blind);
    assert_eq!(
        view.coverage
            .iter()
            .find(|coverage| coverage.concept_id == "covered")
            .map(|coverage| (
                coverage.module_card_count,
                coverage.claim_count,
                coverage.decision_count,
                coverage.failure_count,
            )),
        Some((1, 1, 1, 1))
    );
}

#[test]
fn t07_blind_material_task_gets_advisory_probe() {
    let project_id = ProjectId::new_v7();
    let concepts = vec![concept(project_id, "known", "known")];
    let touched = vec!["known/src/lib.rs".to_owned(), "blind/src/lib.rs".to_owned()];
    let view =
        MetacognitionService::evaluate(Path::new("."), &concepts, &[], &[], &[], &[], &touched);
    let (coverage, target) = MetacognitionService::coverage_for_paths(&concepts, &view, &touched);
    let suggested_probe = MetacognitionService::recommended_probe(&[], &touched)
        .unwrap_or_else(|| "cargo test -p blind".to_owned());

    assert_eq!(coverage, CoverageClass::Blind);
    assert_eq!(target.as_deref(), Some("blind/src/lib.rs"));
    assert_eq!(suggested_probe, "cargo test -p blind");
    assert_eq!(view.novelty_percent, 50);
}

#[allow(clippy::too_many_arguments)]
fn measurement(
    project_id: ProjectId,
    task_id: TaskId,
    session_id: SessionId,
    tool_name: &str,
    arguments: serde_json::Value,
    input_bytes: u64,
    output_bytes: u64,
    injection_receipts: Vec<InjectionReceipt>,
) -> UlToolMeasurement {
    UlToolMeasurement {
        project_id,
        task_id,
        session_id,
        tool_name: tool_name.to_owned(),
        arguments,
        input_bytes,
        output_bytes,
        injection_receipts,
    }
}

fn receipt(
    session_id: SessionId,
    task_id: TaskId,
    item_ref: &str,
    token_cost: u32,
) -> InjectionReceipt {
    InjectionReceipt {
        injection_id: uuid::Uuid::new_v4().to_string(),
        session_id,
        task_id: Some(task_id),
        surface: "test".to_owned(),
        item_ref: item_ref.to_owned(),
        render_form: "payload".to_owned(),
        fired_cues: Vec::new(),
        token_cost,
        source_fingerprint: format!("fingerprint:{item_ref}"),
        outcome: "delivered".to_owned(),
    }
}

fn ledger_from_deltas(
    project_id: ProjectId,
    task_id: TaskId,
    deltas: &[eliot_types::UlLedgerDelta],
) -> UlTaskLedger {
    UlTaskLedger {
        project_id,
        task_id,
        injected_tokens: deltas.iter().map(|delta| delta.injected_tokens).sum(),
        read_tool_input_bytes: deltas.iter().map(|delta| delta.read_tool_input_bytes).sum(),
        read_tool_output_bytes: deltas
            .iter()
            .map(|delta| delta.read_tool_output_bytes)
            .sum(),
        expanded_injected_handles: deltas
            .iter()
            .map(|delta| delta.expanded_injected_handles)
            .sum(),
        acknowledged_items: deltas.iter().map(|delta| delta.acknowledged_items).sum(),
        first_mutation_seen: deltas.iter().any(|delta| delta.first_mutation_seen),
    }
}

fn concept(project_id: ProjectId, id: &str, boundary: &str) -> ConceptNode {
    ConceptNode {
        concept_id: id.to_owned(),
        project_id,
        name: id.to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: format!("Owns {id}."),
        boundary_paths: vec![boundary.to_owned()],
        invariant_refs: Vec::new(),
        hotspot_refs: Vec::new(),
        entrypoint_refs: Vec::new(),
        parent_concept_id: None,
        cue_bindings: Vec::new(),
        source_refs: Vec::new(),
    }
}

fn capsule(project_id: ProjectId, concept_id: &str) -> SubsystemCapsule {
    SubsystemCapsule {
        capsule_id: format!("capsule-{concept_id}"),
        project_id,
        concept_id: concept_id.to_owned(),
        body_md: "PURPOSE\nfixture".to_owned(),
        dependency_manifest: DependencyManifest::default(),
        build_id: format!("build-{concept_id}"),
        cue_bindings: Vec::new(),
        source_refs: Vec::new(),
    }
}

fn card(project_id: ProjectId, path: &str) -> ModuleCard {
    ModuleCard {
        card_id: "card-covered".to_owned(),
        project_id,
        path: path.to_owned(),
        body_md: "covered card".to_owned(),
        verifier: "cargo test -p covered".to_owned(),
        hotspot_ref: None,
        co_change_refs: Vec::new(),
        failure_refs: Vec::new(),
        source_refs: Vec::new(),
        cue_bindings: Vec::new(),
        build_fingerprint: "fixture".to_owned(),
    }
}

fn source(
    record_ref: &str,
    record_kind: &str,
    path: &str,
    negative_memory: bool,
) -> CueRecordSource {
    CueRecordSource {
        record_ref: record_ref.to_owned(),
        record_kind: record_kind.to_owned(),
        preview_text: record_ref.to_owned(),
        payload: None,
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: path.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "fixture".to_owned(),
        }],
        negative_memory,
        lifecycle: "active".to_owned(),
    }
}
