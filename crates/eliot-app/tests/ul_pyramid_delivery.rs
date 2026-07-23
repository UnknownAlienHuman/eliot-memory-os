#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, CapsuleBuild, CommandContext, ConceptKind, ConceptNode, CueBinding, CueKind,
    CueMatchMode, CueStrength, DependencyManifest, InjectionReceipt, LifecycleStatus,
    ObservabilityKind, ProjectCharter, ProjectId, PyramidBuildStatus, PyramidTargetKind,
    RelationInput, RelationType, SemanticCommand, SubsystemCapsule, SystemMap, TaintClass,
    UlArtifact, UlArtifactBatchRecordCommand, Visibility, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
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

#[allow(clippy::too_many_lines)]
fn seed_pyramid(harness: &Harness, project_id: ProjectId) -> TestResult {
    let concepts = [
        concept(project_id, "concept-a", "alpha", "src/a"),
        concept(project_id, "concept-b", "beta", "src/b"),
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
        let build_id = format!("build-{}", concept.name);
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
        map_id: "map-ready".to_owned(),
        project_id,
        body_md: "SYSTEMS\n- alpha: owns a\n- beta: owns b\n\nFLOWS\n- none recorded".to_owned(),
        subsystem_concept_refs: concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect(),
        flow_edges: Vec::new(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build-map".to_owned(),
        cue_bindings: cue("system map"),
    };
    let map_build = build(
        project_id,
        "build-map".to_owned(),
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
        charter_id: "charter-ready".to_owned(),
        project_id,
        body_md: "WHAT\nA governed test project.\n\nFOR WHOM\nAgents and operators changing this repository under verifier control.\n\nTOP INVARIANTS\n- preserve tests\n\nNON-GOALS\n- none\n\nVOCABULARY\n- alpha\n- beta".to_owned(),
        concept_refs: concepts
            .iter()
            .map(|concept| concept.concept_id.clone())
            .collect(),
        dependency_manifest: DependencyManifest::default(),
        build_id: "build-charter".to_owned(),
        cue_bindings: cue("test project"),
    };
    let charter_build = build(
        project_id,
        "build-charter".to_owned(),
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
