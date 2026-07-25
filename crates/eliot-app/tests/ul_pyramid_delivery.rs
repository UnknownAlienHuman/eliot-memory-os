#[path = "support/ul_t04.rs"]
mod support;

use eliot_engine::{
    CalibrationService, CapsuleEvidence, MetacognitionService, PyramidBuilder, resolve_prediction,
};
use eliot_types::{
    AgentId, CapsuleBuild, CommandContext, ConceptKind, ConceptNode, CoverageClass, CueBinding,
    CueKind, CueMatchMode, CueStrength, DependencyManifest, InjectionReceipt, LifecycleStatus,
    ModuleCard, ObservabilityKind, PredictionExpectation, PredictionRecord, PredictionResolution,
    ProjectCharter, ProjectId, PyramidBuildStatus, PyramidTargetKind, RelationInput, RelationType,
    SemanticCommand, SessionId, SubsystemCapsule, SystemMap, TaintClass, TaskId, UlArtifact,
    UlArtifactBatchRecordCommand, VerificationResult, Visibility, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn t06_boot_delivers_charter_map_once() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t06_boot_delivers_charter_map_once")? {
        return Ok(());
    }
    let command_source = include_str!("../src/commands/ul.rs");
    let ipc_source = include_str!("../src/named_pipe_ipc.rs");
    let dispatch_source = include_str!("../src/mcp_stdio/dispatch.rs");
    let onboard_boundary = command_source
        .split_once("pub async fn run_ul_onboard")
        .ok_or("UL onboarding command boundary missing")?
        .1;
    assert!(onboard_boundary.contains("host_governor_request"));
    assert!(!onboard_boundary.contains("ControlWal::open"));
    assert!(ipc_source.contains("\"ul/onboard\""));
    assert!(dispatch_source.contains("run_ul_onboard_from_daemon"));

    let mut harness = Harness::start("t06-boot")?;
    let project_id = ProjectId::new_v7();
    seed_pyramid(&harness, project_id)?;
    let first = current_state(&mut harness, 600, project_id, "src/a/lib.rs")?;
    let second = current_state(&mut harness, 601, project_id, "src/a/lib.rs")?;
    let control = harness.client.tool_call(
        602,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": eliot_types::TaskId::new_v7(),
            "goal": "memory-free control for src/a/lib.rs",
            "candidate_handles": ["file:src/a/lib.rs"],
            "max_tokens": 800,
            "memory_mode": "memory_free_control"
        }),
    )?;
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    let boot_receipts = receipts
        .iter()
        .filter(|receipt| receipt.surface == "mcp_auto_boot")
        .collect::<Vec<_>>();
    let boot_units = ul_token_estimate(&format!(
        "{}{}",
        first["ul_boot"]["charter"]["body_md"]
            .as_str()
            .unwrap_or_default(),
        first["ul_boot"]["system_map"]["body_md"]
            .as_str()
            .unwrap_or_default()
    ));

    assert_eq!(first["ul_boot"]["status"], "ready");
    assert!(boot_units <= 1_200);
    assert!(second.get("ul_boot").is_none());
    assert!(control.get("ul_boot").is_none());
    assert!(control.get("ul_understanding").is_none());
    assert_eq!(boot_receipts.len(), 2);
    assert!(boot_receipts.iter().any(|receipt| {
        receipt.item_ref.starts_with("charter:") && receipt.surface == "mcp_auto_boot"
    }));
    assert!(boot_receipts.iter().any(|receipt| {
        receipt.item_ref.starts_with("system-map:") && receipt.surface == "mcp_auto_boot"
    }));
    Ok(())
}

#[test]
fn t06_packet_delivers_relevant_capsule() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("t06_packet_delivers_relevant_capsule")? {
        return Ok(());
    }
    let mut harness = Harness::start("t06-packet")?;
    let project_id = ProjectId::new_v7();
    seed_pyramid(&harness, project_id)?;
    let response = harness.client.tool_call(
        610,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": eliot_types::TaskId::new_v7(),
            "goal": "change src/a/lib.rs without touching subsystem beta",
            "candidate_handles": ["file:src/a/lib.rs"],
            "max_tokens": 1200
        }),
    )?;
    let capsules = response["ul_understanding"]["capsules"]
        .as_array()
        .ok_or("ul_understanding.capsules missing")?;
    let serialized = serde_json::to_string(capsules)?;
    let bridge = response["frame_stub"]["causal_bridge"]
        .as_array()
        .ok_or("frame_stub.causal_bridge missing")?;

    assert_eq!(response["ul_understanding"]["coverage"], "covered");
    assert!(serialized.contains("CAPSULE_ALPHA_MARKER"));
    assert!(!serialized.contains("CAPSULE_BETA_MARKER"));
    assert!(bridge.iter().any(|hop| {
        hop["to"]
            .as_str()
            .is_some_and(|value| value.contains("concept-a"))
    }));
    assert!(bridge.iter().any(|hop| hop["to"] == "file:src/a/lib.rs"));
    Ok(())
}

#[test]
fn h1_boot_and_delivery_dedup_are_project_scoped() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h1_boot_and_delivery_dedup_are_project_scoped")? {
        return Ok(());
    }
    let mut harness = Harness::start("h1-project-boot")?;
    let project_a = ProjectId::new_v7();
    let project_b = ProjectId::new_v7();
    seed_pyramid(&harness, project_a)?;
    seed_pyramid(&harness, project_b)?;

    let first_a = current_state(&mut harness, 620, project_a, "src/a/lib.rs")?;
    let first_b = current_state(&mut harness, 621, project_b, "src/a/lib.rs")?;
    let second_a = current_state(&mut harness, 622, project_a, "src/a/lib.rs")?;
    let second_b = current_state(&mut harness, 623, project_b, "src/a/lib.rs")?;
    let receipts_a: Vec<InjectionReceipt> =
        harness.observability_records(project_a, None, ObservabilityKind::InjectionReceipt)?;
    let receipts_b: Vec<InjectionReceipt> =
        harness.observability_records(project_b, None, ObservabilityKind::InjectionReceipt)?;

    assert_eq!(first_a["ul_boot"]["status"], "ready");
    assert_eq!(first_b["ul_boot"]["status"], "ready");
    assert!(second_a.get("ul_boot").is_none());
    assert!(second_b.get("ul_boot").is_none());
    assert_eq!(
        receipts_a
            .iter()
            .filter(|receipt| receipt.surface == "mcp_auto_boot")
            .count(),
        2
    );
    assert_eq!(
        receipts_b
            .iter()
            .filter(|receipt| receipt.surface == "mcp_auto_boot")
            .count(),
        2
    );
    Ok(())
}

#[test]
fn h3_custom_root_freshness_and_dot_boundary_reach_runtime_packet() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h3_custom_root_freshness_and_dot_boundary_reach_runtime_packet")?
    {
        return Ok(());
    }
    let mut harness = Harness::start("h3-custom-root")?;
    let project_root = TempProjectRoot::new("h3-custom-root")?;
    let source_path = project_root.path().join("src").join("lib.rs");
    fs::create_dir_all(source_path.parent().ok_or("source parent missing")?)?;
    fs::write(&source_path, "pub fn before() {}\n")?;
    let project_id = ProjectId::new_v7();
    seed_pyramid(&harness, project_id)?;
    let root_concept = ConceptNode {
        entrypoint_refs: vec!["file:src/lib.rs".to_owned()],
        ..concept(project_id, "concept-root", "root", ".")
    };
    let module_card = ModuleCard {
        card_id: "card-root".to_owned(),
        project_id,
        path: "src/lib.rs".to_owned(),
        body_md: "PURPOSE: exercise a custom project root".to_owned(),
        verifier: "cargo test".to_owned(),
        hotspot_ref: None,
        co_change_refs: Vec::new(),
        failure_refs: Vec::new(),
        source_refs: vec!["file:src/lib.rs".to_owned()],
        cue_bindings: cue("root"),
        build_fingerprint: "h3-root-card".to_owned(),
        dependency_manifest: DependencyManifest::default(),
    };
    let promoted = PyramidBuilder.build_capsule(
        project_root.path(),
        &root_concept,
        &CapsuleEvidence {
            module_cards: vec![module_card.clone()],
            ..CapsuleEvidence::default()
        },
        None,
    )?;
    assert_fv1_root_boundary_consistency(
        project_root.path(),
        &root_concept,
        &module_card,
        &promoted.artifact,
    )?;
    harness.seed(&ul_command(
        project_id,
        vec![UlArtifact::ConceptNode(root_concept.clone())],
        vec![RelationInput {
            relation_type: RelationType::ConceptImplementedBy,
            from: format!("concept:{}", root_concept.concept_id),
            to: "file:.".to_owned(),
        }],
    ))?;
    let capsule_id = promoted.artifact.capsule_id.clone();
    harness.seed(&ul_command(
        project_id,
        vec![
            UlArtifact::SubsystemCapsule(promoted.artifact),
            UlArtifact::CapsuleBuild(promoted.build),
        ],
        vec![RelationInput {
            relation_type: RelationType::CapsuleCovers,
            from: format!("capsule:{capsule_id}"),
            to: format!("concept:{}", root_concept.concept_id),
        }],
    ))?;

    let fresh = compile_packet(&mut harness, 624, project_id, "src/lib.rs")?;
    let fresh_capsule = fresh["ul_understanding"]["capsules"]
        .as_array()
        .and_then(|capsules| {
            capsules
                .iter()
                .find(|capsule| capsule["ref"] == format!("capsule:{capsule_id}"))
        })
        .ok_or("custom-root capsule missing from runtime packet")?;
    assert_eq!(fresh_capsule["freshness"], "fresh");

    fs::write(&source_path, "pub fn after() {}\n")?;
    let stale = compile_packet(&mut harness, 625, project_id, "src/lib.rs")?;
    let stale_capsule = stale["ul_understanding"]["capsules"]
        .as_array()
        .and_then(|capsules| {
            capsules
                .iter()
                .find(|capsule| capsule["ref"] == format!("capsule:{capsule_id}"))
        })
        .ok_or("stale custom-root capsule missing from runtime packet")?;
    assert_eq!(stale_capsule["freshness"], "stale");
    assert!(
        stale_capsule["body_md"]
            .as_str()
            .is_some_and(|body| body.contains("[STALE:"))
    );
    Ok(())
}

#[test]
fn h7_inconclusive_predictions_and_handle_boot_receipts_are_truthful() -> TestResult {
    let project_id = ProjectId::new_v7();
    assert_eq!(
        resolve_prediction(
            PredictionExpectation::Pass,
            VerificationResult::Inconclusive
        ),
        PredictionResolution::Unresolvable
    );
    assert_eq!(
        resolve_prediction(
            PredictionExpectation::Fail,
            VerificationResult::Inconclusive
        ),
        PredictionResolution::Unresolvable
    );
    let scores = CalibrationService::scores(
        project_id,
        &[
            prediction(project_id, PredictionResolution::Hit),
            prediction(project_id, PredictionResolution::Miss),
            prediction(project_id, PredictionResolution::Unresolvable),
        ],
    );
    assert_eq!(scores.len(), 1);
    assert_eq!(
        (
            scores[0].resolved_predictions,
            scores[0].hits,
            scores[0].misses
        ),
        (2, 1, 1)
    );
    assert!((scores[0].hit_rate - 0.5).abs() <= f64::EPSILON);

    let _guard = test_guard();
    if rerun_with_credential_gate(
        "h7_inconclusive_predictions_and_handle_boot_receipts_are_truthful",
    )? {
        return Ok(());
    }
    let mut harness = Harness::start("h7-handle-boot")?;
    let project_id = ProjectId::new_v7();
    let charter_body = format!(
        "WHAT\n{}\n\nFOR WHOM\nagents\n\nTOP INVARIANTS\n- exact receipts\n\nNON-GOALS\n- payload boot\n\nVOCABULARY\n- handle",
        "charter ".repeat(1_400)
    );
    let map_body = format!(
        "SYSTEMS\n{}\n\nFLOWS\n- handle-only delivery",
        "system ".repeat(1_400)
    );
    seed_boot_artifacts(&harness, project_id, &charter_body, &map_body)?;
    let response = current_state(&mut harness, 626, project_id, "src/lib.rs")?;
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    let boot_receipts = receipts
        .iter()
        .filter(|receipt| receipt.surface == "mcp_auto_boot")
        .collect::<Vec<_>>();

    assert!(response["ul_boot"]["charter"].get("body_md").is_none());
    assert!(response["ul_boot"]["system_map"].get("body_md").is_none());
    assert_eq!(boot_receipts.len(), 2);
    for (field, full_body) in [("charter", &charter_body), ("system_map", &map_body)] {
        let delivery = response["ul_boot"][field].clone();
        let item_ref = delivery["ref"].as_str().ok_or("boot ref missing")?;
        let receipt = boot_receipts
            .iter()
            .find(|receipt| receipt.item_ref == item_ref)
            .ok_or("boot receipt missing")?;
        let rendered = serde_json::to_vec(&delivery)?;
        assert_eq!(receipt.render_form, "handle");
        assert_eq!(
            receipt.token_cost,
            ul_token_estimate(&String::from_utf8_lossy(&rendered))
        );
        assert_eq!(
            receipt.source_fingerprint,
            blake3::hash(&rendered).to_hex().to_string()
        );
        assert!(receipt.token_cost < ul_token_estimate(full_body));
    }
    Ok(())
}

fn current_state(
    harness: &mut Harness,
    id: u64,
    project_id: ProjectId,
    path: &str,
) -> TestResult<Value> {
    harness.client.tool_call(
        id,
        "eliot_current_state",
        &json!({
            "project_id": project_id,
            "file_path": path,
        }),
    )
}

fn compile_packet(
    harness: &mut Harness,
    id: u64,
    project_id: ProjectId,
    path: &str,
) -> TestResult<Value> {
    harness.client.tool_call(
        id,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": TaskId::new_v7(),
            "goal": format!("change {path}"),
            "candidate_handles": [format!("file:{path}")],
            "max_tokens": 1_200
        }),
    )
}

fn assert_fv1_root_boundary_consistency(
    project_root: &Path,
    root_concept: &ConceptNode,
    module_card: &ModuleCard,
    capsule: &SubsystemCapsule,
) -> TestResult {
    assert!(
        capsule
            .body_md
            .contains("PURPOSE: exercise a custom project root [file:src/lib.rs]")
    );
    let metacognition = MetacognitionService::evaluate(
        project_root,
        std::slice::from_ref(root_concept),
        std::slice::from_ref(capsule),
        std::slice::from_ref(module_card),
        &[],
        &[],
        &["src/lib.rs".to_owned()],
    );
    assert!(metacognition.novel_paths.is_empty());
    let (coverage, _) = MetacognitionService::coverage_for_paths(
        std::slice::from_ref(root_concept),
        &metacognition,
        &["src/lib.rs".to_owned()],
    );
    assert_ne!(coverage, CoverageClass::Blind);
    let expected_root = project_root
        .canonicalize()?
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(capsule.dependency_manifest.project_root, expected_root);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn seed_pyramid(harness: &Harness, project_id: ProjectId) -> TestResult {
    let project_suffix = project_id.to_string();
    let concepts = [
        concept(
            project_id,
            &format!("concept-a-{project_suffix}"),
            "alpha",
            "src/a",
        ),
        concept(
            project_id,
            &format!("concept-b-{project_suffix}"),
            "beta",
            "src/b",
        ),
    ];
    harness.seed(&ul_command(
        project_id,
        concepts
            .iter()
            .cloned()
            .map(UlArtifact::ConceptNode)
            .collect(),
        concepts
            .iter()
            .map(|concept| RelationInput {
                relation_type: RelationType::ConceptImplementedBy,
                from: format!("concept:{}", concept.concept_id),
                to: format!("file:{}", concept.boundary_paths[0]),
            })
            .collect(),
    ))?;
    for (concept, marker) in concepts
        .iter()
        .zip(["CAPSULE_ALPHA_MARKER", "CAPSULE_BETA_MARKER"])
    {
        let capsule_id = format!("capsule-{}", concept.name);
        let build_id = format!("build-{}-{project_suffix}", concept.name);
        let body_md = format!(
            "PURPOSE\n{marker}\n\nBOUNDARIES\n- {}\n\nKEY ENTRYPOINTS\n- {} [file:{}]\n\nINVARIANTS\n- none recorded\n\nDRAGONS\n- none recorded\n\nKEY DECISIONS\n- none recorded\n\nVERIFIERS\n- cargo test",
            concept.boundary_paths[0],
            concept.entrypoint_refs[0],
            concept.entrypoint_refs[0].trim_start_matches("file:")
        );
        let capsule = SubsystemCapsule {
            capsule_id: capsule_id.clone(),
            project_id,
            concept_id: concept.concept_id.clone(),
            body_md,
            dependency_manifest: DependencyManifest::default(),
            build_id: build_id.clone(),
            cue_bindings: concept.cue_bindings.clone(),
            source_refs: Vec::new(),
        };
        let build = build(
            project_id,
            build_id,
            PyramidTargetKind::SubsystemCapsule,
            capsule_id.clone(),
            500,
            ul_token_estimate(&capsule.body_md),
        );
        harness.seed(&ul_command(
            project_id,
            vec![
                UlArtifact::SubsystemCapsule(capsule),
                UlArtifact::CapsuleBuild(build),
            ],
            vec![RelationInput {
                relation_type: RelationType::CapsuleCovers,
                from: format!("capsule:{capsule_id}"),
                to: format!("concept:{}", concept.concept_id),
            }],
        ))?;
    }
    let map = SystemMap {
        map_id: format!("map-ready-{project_suffix}"),
        project_id,
        body_md: "SYSTEMS\n- alpha: owns a\n- beta: owns b\n\nFLOWS\n- none recorded".to_owned(),
        subsystem_concept_refs: concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect(),
        flow_edges: Vec::new(),
        dependency_manifest: DependencyManifest::default(),
        build_id: format!("build-map-{project_suffix}"),
        cue_bindings: cue("system map"),
    };
    let map_build = build(
        project_id,
        map.build_id.clone(),
        PyramidTargetKind::SystemMap,
        map.map_id.clone(),
        600,
        ul_token_estimate(&map.body_md),
    );
    harness.seed(&ul_command(
        project_id,
        vec![
            UlArtifact::SystemMap(map),
            UlArtifact::CapsuleBuild(map_build),
        ],
        Vec::new(),
    ))?;
    let charter = ProjectCharter {
        charter_id: format!("charter-ready-{project_suffix}"),
        project_id,
        body_md: "WHAT\nA governed test project.\n\nFOR WHOM\nAgents and operators changing this repository under verifier control.\n\nTOP INVARIANTS\n- preserve tests\n\nNON-GOALS\n- none\n\nVOCABULARY\n- alpha\n- beta".to_owned(),
        concept_refs: concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect(),
        dependency_manifest: DependencyManifest::default(),
        build_id: format!("build-charter-{project_suffix}"),
        cue_bindings: cue("test project"),
    };
    let charter_build = build(
        project_id,
        charter.build_id.clone(),
        PyramidTargetKind::ProjectCharter,
        charter.charter_id.clone(),
        200,
        ul_token_estimate(&charter.body_md),
    );
    harness.seed(&ul_command(
        project_id,
        vec![
            UlArtifact::ProjectCharter(charter),
            UlArtifact::CapsuleBuild(charter_build),
        ],
        Vec::new(),
    ))?;
    Ok(())
}

fn seed_boot_artifacts(
    harness: &Harness,
    project_id: ProjectId,
    charter_body: &str,
    map_body: &str,
) -> TestResult {
    let map = SystemMap {
        map_id: "map-over-budget".to_owned(),
        project_id,
        body_md: map_body.to_owned(),
        subsystem_concept_refs: Vec::new(),
        flow_edges: Vec::new(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build-map-over-budget".to_owned(),
        cue_bindings: cue("system map"),
    };
    let charter = ProjectCharter {
        charter_id: "charter-over-budget".to_owned(),
        project_id,
        body_md: charter_body.to_owned(),
        concept_refs: Vec::new(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build-charter-over-budget".to_owned(),
        cue_bindings: cue("test project"),
    };
    harness.seed(&ul_command(
        project_id,
        vec![
            UlArtifact::SystemMap(map.clone()),
            UlArtifact::CapsuleBuild(build(
                project_id,
                map.build_id.clone(),
                PyramidTargetKind::SystemMap,
                map.map_id,
                10_000,
                ul_token_estimate(map_body),
            )),
        ],
        Vec::new(),
    ))?;
    harness.seed(&ul_command(
        project_id,
        vec![
            UlArtifact::ProjectCharter(charter.clone()),
            UlArtifact::CapsuleBuild(build(
                project_id,
                charter.build_id.clone(),
                PyramidTargetKind::ProjectCharter,
                charter.charter_id,
                10_000,
                ul_token_estimate(charter_body),
            )),
        ],
        Vec::new(),
    ))?;
    Ok(())
}

fn prediction(project_id: ProjectId, resolution: PredictionResolution) -> PredictionRecord {
    PredictionRecord {
        prediction_id: uuid::Uuid::new_v4().to_string(),
        project_id,
        task_id: TaskId::new_v7(),
        session_id: SessionId::new_v7(),
        subsystem_concept_id: Some("h7".to_owned()),
        packet_id: uuid::Uuid::new_v4().to_string(),
        verifier: "h7-verifier".to_owned(),
        expected: PredictionExpectation::Pass,
        prediction: Some(eliot_types::UlPrediction::VerifierVerdict {
            verifier: "h7-verifier".to_owned(),
            expected: PredictionExpectation::Pass,
        }),
        confidence: None,
        resolution: Some(resolution),
        actual: Some(match resolution {
            PredictionResolution::Hit => VerificationResult::Passed,
            PredictionResolution::Miss => VerificationResult::Failed,
            PredictionResolution::Unresolvable => VerificationResult::Inconclusive,
        }),
        actual_detail: None,
        blast_score: None,
        verification_ref: Some("verification:h7".to_owned()),
        source_frame_hash: "h7-frame".to_owned(),
    }
}

fn concept(project_id: ProjectId, id: &str, name: &str, boundary: &str) -> ConceptNode {
    ConceptNode {
        concept_id: id.to_owned(),
        project_id,
        name: name.to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: format!("Owns subsystem {name}."),
        boundary_paths: vec![boundary.to_owned()],
        invariant_refs: Vec::new(),
        hotspot_refs: Vec::new(),
        entrypoint_refs: vec![format!("file:{boundary}/lib.rs")],
        parent_concept_id: None,
        cue_bindings: cue(name),
        source_refs: Vec::new(),
    }
}

fn cue(value: &str) -> Vec<CueBinding> {
    vec![CueBinding {
        cue_kind: CueKind::Subsystem,
        cue_value: value.to_owned(),
        match_mode: CueMatchMode::Exact,
        strength: CueStrength::Primary,
        expected_reuse_note: "when working in this subsystem or its boundary paths".to_owned(),
    }]
}

fn build(
    project_id: ProjectId,
    build_id: String,
    target_kind: PyramidTargetKind,
    target_id: String,
    budget_limit: u32,
    token_estimate: u32,
) -> CapsuleBuild {
    CapsuleBuild {
        build_id,
        project_id,
        target_kind,
        target_id,
        inputs_hash: "a".repeat(64),
        anchor_validation: vec!["test:ok".to_owned()],
        budget_limit,
        token_estimate,
        status: PyramidBuildStatus::Promoted,
        previous_build_id: None,
    }
}

fn ul_command(
    project_id: ProjectId,
    artifacts: Vec<UlArtifact>,
    relations: Vec<RelationInput>,
) -> SemanticCommand {
    SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: format!("project:{project_id}:ul-artifacts"),
            authority: "local-ul-builder".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalTool,
            lifecycle_status: LifecycleStatus::Active,
        },
        artifacts,
        relations,
    })
}

struct TempProjectRoot {
    root: PathBuf,
}

impl TempProjectRoot {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root =
            std::env::temp_dir().join(format!("eliot-ul-pr-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempProjectRoot {
    fn drop(&mut self) {
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-pr-"))
            && self.root.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
