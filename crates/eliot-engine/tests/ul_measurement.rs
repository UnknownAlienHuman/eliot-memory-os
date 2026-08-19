use eliot_engine::{
    MetacognitionService, UlLedgerAccumulator, UlLedgerService, UlToolMeasurement,
    evaluate_task08_readiness, field_validation_manifest_path, load_field_validation_manifest,
    summarize_field_evidence,
};
use eliot_types::{
    ConceptKind, ConceptNode, CoverageClass, CueBinding, CueKind, CueMatchMode, CueRecordSource,
    CueStrength, DependencyManifest, InjectionReceipt, ModuleCard, ProjectId, SessionId,
    SubsystemCapsule, TaskId, UL_FIELD_VALIDATION_BASELINE_COMMIT,
    UL_FIELD_VALIDATION_SCHEMA_VERSION, UlExperimentArm, UlFieldTaskAnnotation,
    UlFieldValidationManifest, UlInjectionMode, UlReadinessInventory, UlReadinessState,
    UlTaskClass, UlTaskExperimentAssignment, UlTaskLedger,
};
use serde_json::json;
use std::fs;
use std::path::Path;

#[test]
fn u9_3_exploration_token_rounding_is_exact() {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let mut accumulator = UlLedgerAccumulator::default();
    let assignment = UlTaskExperimentAssignment {
        project_id,
        task_id,
        task_class: UlTaskClass {
            action_class: "read_only".to_owned(),
            subsystem: "concept:test".to_owned(),
            artifact_class: "code".to_owned(),
        },
        ordinal: 2,
        arm: UlExperimentArm::Treatment,
        injection_mode: UlInjectionMode::Payload,
        config_hash: "u9-3".to_owned(),
    };
    let delta = accumulator.record_with_assignment(
        &measurement(
            project_id,
            task_id,
            session_id,
            "eliot_current_state",
            json!({"project_id": project_id}),
            9,
            12,
            vec![receipt(session_id, task_id, "claim:u9-3", 9)],
        ),
        Some(&assignment),
    );

    assert_eq!(delta.read_tool_input_bytes, 9);
    assert_eq!(delta.read_tool_output_bytes, 12);
    assert_eq!(delta.exploration_tokens, 6);
    assert_eq!(delta.injected_tokens, 9);
    let baseline = UlLedgerService::matched_control_baseline(&[4, 6, 8]);
    assert_eq!(baseline, Some(6));
    assert_eq!(
        UlLedgerService::net_token_delta(delta.injected_tokens, baseline.unwrap_or_default()),
        3
    );
}

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
    let cards = vec![
        card(project_id, "covered/src/lib.rs"),
        card(project_id, "thin/src/lib.rs"),
    ];
    let cue_sources = vec![
        source("claim:covered", "claim", "covered/src/lib.rs", false),
        source("decision:covered", "decision", "covered/src/lib.rs", false),
        source(
            "failure:covered",
            "failure_fingerprint",
            "covered/src/lib.rs",
            true,
        ),
        source(
            "experience:covered",
            "experience_case",
            "covered/src/lib.rs",
            false,
        ),
        source("claim:thin", "claim", "thin/src/lib.rs", false),
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
        view.policy_version,
        MetacognitionService::COVERAGE_POLICY_VERSION
    );
    assert_eq!(
        view.coverage
            .iter()
            .find(|coverage| coverage.concept_id == "covered")
            .map(|coverage| (
                coverage.module_card_count,
                coverage.claim_count,
                coverage.decision_count,
                coverage.failure_count,
                coverage.experience_count,
            )),
        Some((1, 1, 1, 1, 1))
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

#[test]
fn fv1_c_readiness_thresholds_are_exact() {
    let mut inventory = UlReadinessInventory::default();
    inventory.graph.total_ul_edges = 499;
    inventory.artifacts.module_card_count = 10;
    inventory.artifacts.capsule_count = 3;
    inventory.artifacts.fresh_capsule_count = 3;
    inventory.tasks_with_injection = 20;
    let below_activation = evaluate_task08_readiness(&inventory, None);
    assert_eq!(
        below_activation.spreading_activation.state,
        UlReadinessState::NotEligible
    );
    assert_eq!(
        below_activation.spreading_activation.reasons,
        ["requires_at_least_500_live_edges"]
    );
    inventory.graph.total_ul_edges = 500;
    assert_eq!(
        evaluate_task08_readiness(&inventory, None)
            .spreading_activation
            .state,
        UlReadinessState::Eligible
    );

    inventory.ledger_tasks = 19;
    inventory.injection_receipts = 20;
    inventory.read_tool_input_bytes = 1;
    let below_token = evaluate_task08_readiness(&inventory, None);
    assert_eq!(
        below_token.token_ab_and_downgrade.reasons,
        ["requires_at_least_20_ledger_tasks"]
    );
    inventory.ledger_tasks = 20;
    assert_eq!(
        evaluate_task08_readiness(&inventory, None)
            .token_ab_and_downgrade
            .state,
        UlReadinessState::Eligible
    );

    inventory.artifacts.capsule_count = 5;
    inventory.artifacts.fresh_capsule_count = 4;
    inventory.artifacts.stale_capsule_count = 1;
    inventory.predictions.hit = 19;
    inventory.predictions.resolved_subsystem_count = 2;
    let below_exam = evaluate_task08_readiness(&inventory, None);
    assert_eq!(
        below_exam.weekly_understanding_exam.reasons,
        ["requires_at_least_20_resolved_predictions"]
    );
    inventory.predictions.hit = 20;
    assert_eq!(
        evaluate_task08_readiness(&inventory, None)
            .weekly_understanding_exam
            .state,
        UlReadinessState::Eligible
    );
}

#[test]
fn fv1_e_manifest_cannot_manufacture_eligibility() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let runtime_root = std::env::temp_dir().join(format!("eliot-ul-fv1-{}", TaskId::new_v7()));
    let manifest = UlFieldValidationManifest {
        schema_version: UL_FIELD_VALIDATION_SCHEMA_VERSION.to_owned(),
        project_id,
        project_root: env!("CARGO_MANIFEST_DIR").to_owned(),
        baseline_merge_commit: UL_FIELD_VALIDATION_BASELINE_COMMIT.to_owned(),
        second_repository: None,
        task_annotations: (0..20)
            .map(|index| UlFieldTaskAnnotation {
                task_id: TaskId::new_v7(),
                task_class: "fake-counter-only".to_owned(),
                real_task: true,
                verifier_ref: format!("missing:verification:{index}"),
                outcome: "claimed".to_owned(),
                notes: "has no canonical ledger or receipt".to_owned(),
            })
            .collect(),
        prose_failure_signals: Vec::new(),
        host_surface_incidents: Vec::new(),
    };
    let path = field_validation_manifest_path(&runtime_root, project_id);
    fs::create_dir_all(path.parent().ok_or("manifest parent missing")?)?;
    fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;

    let loaded = load_field_validation_manifest(&runtime_root, project_id);
    assert!(loaded.present);
    assert!(loaded.manifest.is_some());
    let mut warnings = loaded.warnings;
    let summary = summarize_field_evidence(true, loaded.manifest.as_ref(), &[], &[], &mut warnings);
    let readiness =
        evaluate_task08_readiness(&UlReadinessInventory::default(), loaded.manifest.as_ref());

    assert_eq!(summary.matched_real_tasks, 0);
    assert_eq!(summary.matched_real_injected_tasks, 0);
    assert_eq!(
        readiness.token_ab_and_downgrade.state,
        UlReadinessState::NotEligible
    );
    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning.contains("unmatched_task_annotation"))
            .count(),
        20
    );
    fs::remove_dir_all(&runtime_root)?;
    Ok(())
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
        policy_reason: None,
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
        task_class_key: String::new(),
        arm: None,
        injection_mode: None,
        injected_tokens: deltas.iter().map(|delta| delta.injected_tokens).sum(),
        read_tool_input_bytes: deltas.iter().map(|delta| delta.read_tool_input_bytes).sum(),
        read_tool_output_bytes: deltas
            .iter()
            .map(|delta| delta.read_tool_output_bytes)
            .sum(),
        exploration_tokens: deltas.iter().map(|delta| delta.exploration_tokens).sum(),
        matched_baseline_tokens: 0,
        net_token_delta: 0,
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
        dependency_manifest: eliot_types::DependencyManifest::default(),
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
            expected_reuse_note: Some("fixture".to_owned()),
        }],
        negative_memory,
        lifecycle: "active".to_owned(),
    }
}
