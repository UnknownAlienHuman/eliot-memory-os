#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, CapsuleBuild, ClaimCardInput, ClaimId, CommandContext, ConceptKind, ConceptNode,
    CueBinding, CueKind, CueMatchMode, CueStrength, DependencyManifest, EpistemicStatus,
    InjectionReceipt, LifecycleStatus, ObservabilityKind, ProjectId, PyramidBuildStatus,
    PyramidTargetKind, RelationInput, RelationType, SemanticCommand, SubsystemCapsule, TaintClass,
    TaskId, UlArtifact, UlArtifactBatchRecordCommand, UlInjectionMode, UlTaskClassPolicy,
    Visibility, WriteId, ul_token_estimate,
};
use serde_json::{Value, json};
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn u9_2_control_assignment_forces_a_memory_free_compile() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("u9_2_control_assignment_forces_a_memory_free_compile")? {
        return Ok(());
    }
    let mut harness = Harness::start("u9-control")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(10, project_id, task_id)?;
    harness.seed(&failure_command(project_id))?;
    harness.seed(&claim_command(project_id, ClaimId::new_v7()))?;
    let before: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::InjectionReceipt,
    )?;

    let response = compile(
        &mut harness,
        11,
        project_id,
        task_id,
        None,
        "src/net/session.rs",
    )?;
    let after: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::InjectionReceipt,
    )?;

    assert_eq!(response["ul_experiment"]["arm"], "control");
    assert_eq!(
        response["ul_experiment"]["effective_memory_mode"],
        "memory_free_control"
    );
    assert!(response.get("ul_understanding").is_none());
    assert!(response.get("ul_boot").is_none());
    assert!(response.get("ul_fired").is_none());
    for memory_field in [
        "current_truth",
        "relevant_verified_claims",
        "relevant_supported_claims",
        "weak_claims_warning",
        "negative_memory",
        "recent_failures",
        "known_decisions",
        "open_questions",
        "exact_handles",
        "source_receipts",
        "memory_decisions",
        "experience_priors",
        "historical_memory",
    ] {
        assert_eq!(
            response[memory_field],
            json!([]),
            "{memory_field} leaked into the memory-free control"
        );
    }
    assert_eq!(after.len(), before.len());
    Ok(())
}

#[test]
fn u9_5_handles_only_policy_strips_negative_and_normal_payloads() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("u9_5_handles_only_policy_strips_negative_and_normal_payloads")? {
        return Ok(());
    }
    let mut harness = Harness::start("u9-handles")?;
    let project_id = ProjectId::new_v7();
    let control_task = TaskId::new_v7();
    let treatment_task = TaskId::new_v7();
    harness.create_task(20, project_id, control_task)?;
    harness.create_task(21, project_id, treatment_task)?;
    harness.seed(&failure_command(project_id))?;
    let claim_id = ClaimId::new_v7();
    harness.seed(&claim_command(project_id, claim_id))?;

    let control = compile(
        &mut harness,
        22,
        project_id,
        control_task,
        None,
        "src/net/session.rs",
    )?;
    assert_eq!(control["ul_experiment"]["arm"], "control");
    let task_class = control["ul_experiment"]["task_class"]
        .as_object()
        .ok_or("control task class missing")?;
    let class_key = format!(
        "{}|{}|{}",
        task_class["action_class"]
            .as_str()
            .ok_or("action_class missing")?,
        task_class["subsystem"]
            .as_str()
            .ok_or("subsystem missing")?,
        task_class["artifact_class"]
            .as_str()
            .ok_or("artifact_class missing")?
    );
    harness.upsert_ul_task_class_policy(&UlTaskClassPolicy {
        project_id,
        task_class_key: class_key,
        injection_mode: UlInjectionMode::HandlesOnly,
        treatment_tasks: 10,
        control_tasks: 5,
        control_median_exploration_tokens: 32,
        treatment_median_net_delta: 1,
        reason: "positive_median_net_token_delta".to_owned(),
        evidence_task_ids: Vec::new(),
    })?;

    let treatment = compile(
        &mut harness,
        23,
        project_id,
        treatment_task,
        None,
        "src/net/session.rs",
    )?;
    assert_eq!(treatment["ul_experiment"]["arm"], "treatment");
    let items = treatment["ul_fired"]["items"]
        .as_array()
        .ok_or("treatment ul_fired.items missing")?;
    for item_ref in [
        "failure:u9-handles-negative".to_owned(),
        format!("claim:{claim_id}"),
    ] {
        assert!(
            items
                .iter()
                .any(|item| item["item_ref"] == item_ref && item["payload"].is_null())
        );
    }
    let receipts: Vec<InjectionReceipt> = harness.observability_records(
        project_id,
        Some(treatment_task),
        ObservabilityKind::InjectionReceipt,
    )?;
    assert!(
        receipts.iter().any(|receipt| {
            receipt.item_ref == "failure:u9-handles-negative"
                && receipt.render_form == "handle"
                && receipt.policy_reason.as_deref() == Some("task_class_handles_only")
        }) && receipts.iter().any(|receipt| {
            receipt.item_ref == format!("claim:{claim_id}")
                && receipt.render_form == "handle"
                && receipt.policy_reason.as_deref() == Some("task_class_handles_only")
        }),
        "persisted injection receipts: {receipts:#?}"
    );
    Ok(())
}

#[test]
fn u9_6_invariant_gate_prefills_requires_and_accepts_an_explicit_waiver() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "u9_6_invariant_gate_prefills_requires_and_accepts_an_explicit_waiver",
    )? {
        return Ok(());
    }
    let mut harness = Harness::start("u9-invariant")?;
    let project_id = ProjectId::new_v7();
    seed_invariant_capsule(&harness, project_id)?;
    let control_task = TaskId::new_v7();
    let treatment_task = TaskId::new_v7();
    harness.create_task(30, project_id, control_task)?;
    harness.create_task(31, project_id, treatment_task)?;

    let control = compile(
        &mut harness,
        32,
        project_id,
        control_task,
        Some(material_frame(&[], &[])),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(control["ul_experiment"]["arm"], "control");

    let rejected = compile(
        &mut harness,
        33,
        project_id,
        treatment_task,
        Some(material_frame(&[], &[])),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(rejected["ul_experiment"]["arm"], "treatment");
    assert_eq!(rejected["ul_gate"]["status"], "require_packet_refresh");
    assert_eq!(
        rejected["ul_gate"]["missing_invariant_refs"],
        json!(["invariant:preserve-order"])
    );
    assert_eq!(
        rejected["frame_stub"]["invariant_refs"],
        json!(["invariant:preserve-order"])
    );

    let accepted = compile(
        &mut harness,
        34,
        project_id,
        treatment_task,
        Some(material_frame(
            &[],
            &[json!({
                "invariant_ref": "invariant:preserve-order",
                "reason": "verified by the focused deterministic fixture"
            })],
        )),
        "src/invariant/lib.rs",
    )?;
    assert_eq!(accepted["ul_gate"]["status"], "require_probe");
    assert_eq!(accepted["ul_gate"]["reason"], "blind_subsystem");
    assert!(
        accepted["ul_gate"].get("missing_invariant_refs").is_none(),
        "the explicit bounded waiver must clear only the invariant gate"
    );
    assert!(
        accepted["ul_gate"]["suggested_probe"]
            .as_str()
            .is_some_and(|probe| !probe.trim().is_empty()),
        "blind subsystem coverage still requires a discriminative probe"
    );

    let schema = harness.tool_schema(35, "eliot_compile_packet_l3")?;
    let serialized = serde_json::to_string(&schema)?;
    assert!(serialized.contains("invariant_refs"));
    assert!(serialized.contains("waived_invariants"));
    assert!(serialized.contains("prediction_confidence"));
    Ok(())
}

fn compile(
    harness: &mut Harness,
    request_id: u64,
    project_id: ProjectId,
    task_id: TaskId,
    material_frame: Option<Value>,
    path: &str,
) -> TestResult<Value> {
    let mut input = json!({
        "project_id": project_id,
        "task_id": task_id,
        "goal": format!("change {path}"),
        "candidate_handles": [format!("file:{path}")],
        "max_tokens": 1_200,
        "memory_mode": "include_case_candidates"
    });
    if let Some(frame) = material_frame {
        input["material_frame"] = frame;
    }
    harness
        .client
        .tool_call(request_id, "eliot_compile_packet_l3", &input)
}

fn material_frame(invariant_refs: &[String], waived_invariants: &[Value]) -> Value {
    json!({
        "acceptance_items": ["UL invariant gate is enforced"],
        "environment": ["windows-x64"],
        "active_plan": ["edit one governed file"],
        "completed_work": [],
        "killed_paths": [],
        "causal_bridge": [],
        "negative_memory_checked": true,
        "exact_load_bearing_atoms": ["file:src/invariant/lib.rs"],
        "cheapest_discriminative_probes": ["cargo test --test ul_control_treatment"],
        "responsibility_contour_route_refs": [],
        "next_allowed_action": "edit src/invariant/lib.rs",
        "expected_observable": "verifier:ul-invariant=pass",
        "verifier": "cargo test --test ul_control_treatment",
        "stop_condition": "stop on verifier failure",
        "tool_schema_bytes_visible": 1024,
        "instruction_hotset_size": 4,
        "invariant_refs": invariant_refs,
        "waived_invariants": waived_invariants,
        "prediction_confidence": "high"
    })
}

fn failure_command(project_id: ProjectId) -> SemanticCommand {
    SemanticCommand::FailureRecord(eliot_types::FailureRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-u9-test".to_owned(),
            authority: "test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        fingerprint: "u9-handles-negative".to_owned(),
        summary: "negative memory payload must become handle-only".to_owned(),
        payload: json!({
            "cue_bindings": [CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: "src/net/session.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: "reuse when this exact file is touched".to_owned(),
            }]
        }),
    })
}

fn claim_command(project_id: ProjectId, claim_id: ClaimId) -> SemanticCommand {
    SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-u9-test".to_owned(),
            authority: "test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        claim: ClaimCardInput {
            claim_id,
            statement: "The network session uses the governed reconnect path.".to_owned(),
            status: EpistemicStatus::Candidate,
            payload: json!({
                "cue_bindings": [CueBinding {
                    cue_kind: CueKind::FilePath,
                    cue_value: "src/net/session.rs".to_owned(),
                    match_mode: CueMatchMode::Exact,
                    strength: CueStrength::Primary,
                    expected_reuse_note: "reuse when this exact file is touched".to_owned(),
                }],
                "normal_claim_payload": "must be suppressed in handles-only mode"
            }),
        },
    })
}

fn seed_invariant_capsule(harness: &Harness, project_id: ProjectId) -> TestResult {
    let concept_id = format!("concept-invariant-{project_id}");
    let capsule_id = format!("capsule-invariant-{project_id}");
    let build_id = format!("build-invariant-{project_id}");
    let concept = ConceptNode {
        concept_id: concept_id.clone(),
        project_id,
        name: "invariant-subsystem".to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: "Own invariant-sensitive code.".to_owned(),
        boundary_paths: vec!["src/invariant".to_owned()],
        invariant_refs: vec!["invariant:preserve-order".to_owned()],
        hotspot_refs: Vec::new(),
        entrypoint_refs: vec!["file:src/invariant/lib.rs".to_owned()],
        parent_concept_id: None,
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::Subsystem,
            cue_value: "invariant-subsystem".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "reuse for invariant subsystem work".to_owned(),
        }],
        source_refs: Vec::new(),
    };
    let capsule = SubsystemCapsule {
        capsule_id: capsule_id.clone(),
        project_id,
        concept_id: concept_id.clone(),
        body_md: "PURPOSE\nOwn invariant-sensitive code.\n\nBOUNDARIES\n- src/invariant\n\nKEY ENTRYPOINTS\n- file:src/invariant/lib.rs\n\nINVARIANTS\n- preserve order [invariant:preserve-order]\n\nDRAGONS\n- none\n\nKEY DECISIONS\n- none\n\nVERIFIERS\n- cargo test"
            .to_owned(),
        dependency_manifest: DependencyManifest {
            project_root: std::env::current_dir()?.to_string_lossy().into_owned(),
            ..DependencyManifest::default()
        },
        build_id: build_id.clone(),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: "src/invariant/lib.rs".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "reuse for the invariant entrypoint".to_owned(),
        }],
        source_refs: Vec::new(),
    };
    let build = CapsuleBuild {
        build_id,
        project_id,
        target_kind: PyramidTargetKind::SubsystemCapsule,
        target_id: capsule_id.clone(),
        inputs_hash: "b".repeat(64),
        anchor_validation: vec!["test:ok".to_owned()],
        budget_limit: 1_200,
        token_estimate: ul_token_estimate(&capsule.body_md),
        status: PyramidBuildStatus::Promoted,
        previous_build_id: None,
    };
    harness.seed(&SemanticCommand::UlArtifactBatchRecord(
        UlArtifactBatchRecordCommand {
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
            artifacts: vec![
                UlArtifact::ConceptNode(concept),
                UlArtifact::SubsystemCapsule(capsule),
                UlArtifact::CapsuleBuild(build),
            ],
            relations: vec![
                RelationInput {
                    relation_type: RelationType::ConceptImplementedBy,
                    from: format!("concept:{concept_id}"),
                    to: "file:src/invariant".to_owned(),
                },
                RelationInput {
                    relation_type: RelationType::CapsuleCovers,
                    from: format!("capsule:{capsule_id}"),
                    to: format!("concept:{concept_id}"),
                },
            ],
        },
    ))?;
    Ok(())
}
