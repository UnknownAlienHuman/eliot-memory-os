#[path = "support/ul_t04.rs"]
mod support;

use eliot_engine::{GitMiningService, ModuleCardService};
use eliot_types::{
    AgentId, ClaimId, CommandContext, CueBinding, CueKind, CueMatchMode, CueStrength,
    InjectionReceipt, LifecycleStatus, MaterialPacketFrame, MemoryInfluenceTrace, ModuleCard,
    ObservabilityKind, PredictionRecord, PredictionResolution, ProjectCharter, ProjectId,
    RelationType, SemanticCommand, SubsystemCapsule, SystemMap, TaintClass, TaskId, Visibility,
    WriteId, compile_packet_input_schema,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};

#[test]
fn d01_packet_contains_memory_content() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d01_packet_contains_memory_content")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d01")?;
    let project_id = ProjectId::new_v7();
    let control_task_id = TaskId::new_v7();
    harness.create_task(0, project_id, control_task_id)?;
    harness.client.tool_call(
        1,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": control_task_id,
            "goal": "reserve the deterministic memory-free control arm",
            "candidate_handles": [],
            "max_tokens": 1200
        }),
    )?;
    let task_id = TaskId::new_v7();
    harness.create_task(2, project_id, task_id)?;
    let write_id = WriteId::new_v7();
    harness.client.tool_call(
        3,
        "eliot_agent_candidate_submit",
        &candidate_arguments(
            project_id,
            task_id,
            write_id,
            "QUARTZ pipeline reads its configuration from quartz.toml",
        ),
    )?;
    let packet = harness.client.tool_call(
        4,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "inspect the QUARTZ configuration pipeline",
            "candidate_handles": [format!("claim:{write_id}")],
            "max_tokens": 4_000,
            "memory_mode": "include_case_candidates"
        }),
    )?;
    let ledgers = harness.ul_metrics(project_id)?;
    let ledger = ledgers
        .iter()
        .find(|ledger| ledger.task_id == task_id)
        .ok_or("UL task ledger missing")?;

    assert!(serde_json::to_string(&packet)?.contains("quartz.toml"));
    assert!(ledger.first_mutation_seen);
    assert!(ledger.injected_tokens > 0);
    Ok(())
}

#[test]
fn d02_observability_replay_one_row_and_no_truth_revision() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d02_observability_replay_one_row_and_no_truth_revision")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d02")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(10, project_id, task_id)?;
    let candidate_write = WriteId::new_v7();
    let handle = format!("claim:{candidate_write}");
    harness.client.tool_call(
        11,
        "eliot_agent_candidate_submit",
        &candidate_arguments(
            project_id,
            task_id,
            candidate_write,
            "The packet content is used by the bounded verifier.",
        ),
    )?;
    harness.client.tool_call(
        12,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "load the candidate for observability replay",
            "candidate_handles": [handle],
            "max_tokens": 1_200,
            "memory_mode": "include_case_candidates"
        }),
    )?;
    let revision = harness.current_revision(project_id)?;
    let observation_write = WriteId::new_v7();
    let arguments = json!({
        "project_id": project_id,
        "write_id": observation_write,
        "memory_handle": handle,
        "influence_class": "used_and_changed_action",
        "downstream_outcome_ref": "verification:done-d02"
    });
    let first = harness
        .client
        .tool_call(13, "eliot_memory_influence_trace", &arguments)?;
    let replay = harness
        .client
        .tool_call(14, "eliot_memory_influence_trace", &arguments)?;
    let after = harness.current_revision(project_id)?;
    let records: Vec<MemoryInfluenceTrace> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::MemoryInfluenceTrace,
    )?;

    assert_eq!(first["observability_receipt"]["status"], "committed");
    assert_eq!(
        replay["observability_receipt"]["status"],
        "idempotent_replay"
    );
    assert_eq!(records.len(), 1);
    assert_eq!(revision, after);
    Ok(())
}

#[test]
fn h2_minimal_ack_uses_only_same_project_packet_context() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h2_minimal_ack_uses_only_same_project_packet_context")? {
        return Ok(());
    }
    let mut harness = Harness::start("h2-project-packet")?;
    let project_a = ProjectId::new_v7();
    let project_b = ProjectId::new_v7();
    let task_a = TaskId::new_v7();
    let task_b = TaskId::new_v7();
    harness.create_task(15, project_a, task_a)?;
    harness.create_task(16, project_b, task_b)?;
    let packet_a = harness.client.tool_call(
        17,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_a,
            "task_id": task_a,
            "goal": "compile project A packet context",
            "candidate_handles": ["file:src/a.rs"],
            "max_tokens": 1_200
        }),
    )?;
    let first_context_id = required_string(&packet_a, "/packet_id")?;
    let rejected = harness.client.tool_call_response(
        18,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_b,
            "write_id": WriteId::new_v7(),
            "memory_handle": "file:src/b.rs",
            "influence_class": "used_for_verification",
            "downstream_outcome_ref": "verification:h2-before-b"
        }),
    )?;
    assert!(
        rejected
            .to_string()
            .contains("MISSING_PROJECT_PACKET_CONTEXT")
    );

    let packet_b = harness.client.tool_call(
        19,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_b,
            "task_id": task_b,
            "goal": "compile project B packet context",
            "candidate_handles": ["file:src/b.rs"],
            "max_tokens": 1_200
        }),
    )?;
    let accepted_context_id = required_string(&packet_b, "/packet_id")?;
    harness.client.tool_call(
        20,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_b,
            "write_id": WriteId::new_v7(),
            "memory_handle": "file:src/b.rs",
            "influence_class": "used_for_verification",
            "downstream_outcome_ref": "verification:h2-after-b"
        }),
    )?;
    let traces: Vec<MemoryInfluenceTrace> = harness.observability_records(
        project_b,
        Some(task_b),
        ObservabilityKind::MemoryInfluenceTrace,
    )?;

    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].task_id, task_b);
    assert_eq!(traces[0].packet_id, accepted_context_id);
    assert_ne!(traces[0].task_id, task_a);
    assert_ne!(traces[0].packet_id, first_context_id);
    Ok(())
}

#[test]
fn h2_exact_fetch_context_supports_minimal_influence_ack() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("h2_exact_fetch_context_supports_minimal_influence_ack")? {
        return Ok(());
    }
    let mut harness = Harness::start("h2-exact-fetch-context")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let candidate_write = WriteId::new_v7();
    let handle = format!("claim:{candidate_write}");
    harness.create_task(21, project_id, task_id)?;
    harness.client.tool_call(
        22,
        "eliot_agent_candidate_submit",
        &candidate_arguments(
            project_id,
            task_id,
            candidate_write,
            "An exact L2 fetch can be acknowledged without compiling an unrelated L3 packet.",
        ),
    )?;
    let revision = harness.current_revision(project_id)?;
    let fetched = harness.client.tool_call(
        23,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [handle],
            "consistency": "latest"
        }),
    )?;
    assert!(
        fetched["returned_handles"]
            .as_array()
            .is_some_and(|handles| handles.iter().any(|candidate| candidate == &json!(handle)))
    );

    let mismatched = harness.client.tool_call_response(
        24,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_id,
            "write_id": WriteId::new_v7(),
            "memory_handle": "claim:019f0000-0000-7000-8000-000000000099",
            "influence_class": "seen_but_not_used"
        }),
    )?;
    assert!(
        mismatched
            .to_string()
            .contains("EXACT_FETCH_CONTEXT_MISMATCH")
    );

    let response = harness.client.tool_call(
        25,
        "eliot_memory_influence_trace",
        &json!({
            "project_id": project_id,
            "write_id": WriteId::new_v7(),
            "memory_handle": handle,
            "influence_class": "seen_but_not_used"
        }),
    )?;
    let after = harness.current_revision(project_id)?;
    let traces: Vec<MemoryInfluenceTrace> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::MemoryInfluenceTrace,
    )?;

    assert_eq!(response["observability_receipt"]["status"], "committed");
    assert_eq!(revision, after);
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].task_id, task_id);
    assert_eq!(traces[0].memory_handle, handle);
    assert!(traces[0].packet_id.starts_with("retrieval:"));
    assert!(traces[0].cited_in_understanding_proof);
    Ok(())
}

#[test]
fn d03_published_compile_schema_matches_serde() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d03_published_compile_schema_matches_serde")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d03")?;
    let published = harness.tool_schema(20, "eliot_compile_packet_l3")?;

    assert_eq!(published, compile_packet_input_schema());
    Ok(())
}

#[test]
fn d04_bad_encoding_rejected_before_write() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d04_bad_encoding_rejected_before_write")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d04")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(30, project_id, task_id)?;
    let before = harness.current_revision(project_id)?;
    let write_id = WriteId::new_v7();
    let response = harness.client.tool_call_response(
        31,
        "eliot_agent_candidate_submit",
        &candidate_arguments(project_id, task_id, write_id, "проверка ????? QUARTZ"),
    )?;
    let exact = harness.client.tool_call(
        32,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [format!("claim:{write_id}")]
        }),
    )?;
    let after = harness.current_revision(project_id)?;

    assert_eq!(response["error"]["data"]["code"], "ENCODING_REJECTED");
    assert_eq!(exact["claims"].as_array().map(Vec::len), Some(0));
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn d05_candidate_owns_one_belongs_to_edge() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d05_candidate_owns_one_belongs_to_edge")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d05")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    harness.create_task(40, project_id, task_id)?;
    let write_id = WriteId::new_v7();
    let claim_id = ClaimId::from_uuid(write_id.as_uuid());
    harness.client.tool_call(
        41,
        "eliot_agent_candidate_submit",
        &candidate_arguments(
            project_id,
            task_id,
            write_id,
            "QUARTZ parser belongs to this bounded task.",
        ),
    )?;
    let exact = harness.client.tool_call(
        42,
        "eliot_fetch_l2",
        &json!({
            "project_id": project_id,
            "handles": [format!("claim:{claim_id}")]
        }),
    )?;
    let belongs_to = exact["relations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|relation| {
            relation["relation_type"] == json!(RelationType::BelongsTo)
                && relation["from"] == claim_id.to_string()
                && relation["to"] == task_id.to_string()
        })
        .count();

    assert_eq!(belongs_to, 1);
    Ok(())
}

#[test]
fn d06_bound_path_pushes_memory_once_with_receipt() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d06_bound_path_pushes_memory_once_with_receipt")? {
        return Ok(());
    }
    let project_id = ProjectId::new_v7();
    let mut prepared = Harness::prepare("done-d06")?;
    prepared.seed(&failure_command(project_id, "done-d06"))?;
    let mut harness = prepared.launch()?;
    let first = harness.client.tool_call(
        50,
        "eliot_current_state",
        &json!({"project_id": project_id, "path": "src/net/session.rs"}),
    )?;
    let second = harness.client.tool_call(
        51,
        "eliot_current_state",
        &json!({"project_id": project_id, "path": "src/net/session.rs"}),
    )?;
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    let delivered = receipts
        .iter()
        .filter(|receipt| receipt.item_ref == "failure:done-d06")
        .count();

    assert_eq!(
        first["ul_fired"]["items"][0]["item_ref"],
        "failure:done-d06"
    );
    assert!(second.get("ul_fired").is_none());
    assert_eq!(delivered, 1);
    Ok(())
}

#[test]
fn d07_mining_builds_hidden_edge_and_module_card() -> TestResult {
    let repo = TempGitRepo::new("done-d07")?;
    for index in 0..8 {
        repo.commit(index, &["src/a.rs", "src/b.rs"], "feature hidden pair")?;
    }
    let project_id = ProjectId::new_v7();
    let mined = GitMiningService::default().mine(project_id, repo.path(), &BTreeMap::new())?;
    let edge = mined
        .edges
        .iter()
        .find(|edge| edge.path_a == "src/a.rs" && edge.path_b == "src/b.rs")
        .ok_or("hidden edge missing")?;
    let cards = ModuleCardService::build(
        project_id,
        repo.path(),
        &mined.hotspots,
        &mined.edges,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )?;

    assert!(edge.static_edge_exists.is_none() || edge.static_edge_exists == Some(false));
    assert!(
        cards
            .iter()
            .any(|card| card.co_change_refs.contains(&edge.edge_id))
    );
    Ok(())
}

#[test]
fn d08_onboarding_produces_charter_map_capsule_and_cold_boot_delivers_them() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "d08_onboarding_produces_charter_map_capsule_and_cold_boot_delivers_them",
    )? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d08")?;
    let repo = TempGitRepo::new("done-d08-repo")?;
    repo.write(
        "Cargo.toml",
        "[package]\nname='ul-done-fixture'\nversion='0.1.0'\nedition='2024'\n",
    )?;
    for index in 0..4 {
        repo.write(
            "src/lib.rs",
            &format!("//! Onboarding fixture.\npub fn marker() -> usize {{ {index} }}\n"),
        )?;
        repo.commit_all(index, "build onboarding fixture")?;
    }
    let project_id = ProjectId::new_v7();
    let report = harness.run_ul_onboard(project_id, repo.path())?;
    let concepts =
        harness.ul_artifacts::<eliot_types::ConceptNode>(project_id, &["concept_node"])?;
    let capsules = harness.ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"])?;
    let cards = harness.ul_artifacts::<ModuleCard>(project_id, &["module_card"])?;
    let charters = harness.ul_artifacts::<ProjectCharter>(project_id, &["project_charter"])?;
    let maps = harness.ul_artifacts::<SystemMap>(project_id, &["system_map"])?;
    let cold_boot = harness.client.tool_call(
        60,
        "eliot_current_state",
        &json!({"project_id": project_id, "path": "src/lib.rs"}),
    )?;

    assert!(
        report["concept_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(!concepts.is_empty());
    assert!(!capsules.is_empty());
    assert!(!cards.is_empty());
    assert_eq!(charters.len(), 1);
    assert_eq!(maps.len(), 1);
    assert_eq!(cold_boot["ul_boot"]["status"], "ready");
    assert!(cold_boot["ul_boot"]["charter"]["ref"].is_string());
    assert!(cold_boot["ul_boot"]["system_map"]["ref"].is_string());
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn d09_prediction_resolves_against_real_verifier() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate("d09_prediction_resolves_against_real_verifier")? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d09")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let created = harness.create_task(70, project_id, task_id)?;
    let created_revision = required_u64(&created, "/task_contract/memory_revision")?;
    let create_receipt = required_string(&created, "/write_receipt/receipt_id")?;
    let packet = harness.client.tool_call(
        71,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "resolve a machine-checkable UL prediction",
            "candidate_handles": [],
            "max_tokens": 2_000
        }),
    )?;
    let descriptor = packet["registered_verifiers"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["verifier_id"] == "daemon-receipt-resolution")
        })
        .ok_or("registered receipt verifier missing")?;
    let verifier_ref = required_string(descriptor, "/verifier_ref")?;
    let verifier_config_hash = required_string(descriptor, "/config_hash")?;
    let mut frame: MaterialPacketFrame = serde_json::from_value(packet["frame_stub"].clone())?;
    frame.expected_observable = "verifier:daemon-receipt-resolution=pass".to_owned();
    let material_packet = harness.client.tool_call(
        72,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "goal": "resolve a machine-checkable UL prediction",
            "candidate_handles": [],
            "max_tokens": 2_000,
            "material_frame": frame
        }),
    )?;
    assert!(material_packet["prediction_ref"].is_string());
    let action = harness.client.tool_call(
        73,
        "eliot_task_action_request",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "expected_revision": created_revision,
            "packet_id": required_string(&material_packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&material_packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&material_packet, "/task_contract_ref")?,
            "current_truth_refs": material_packet["current_truth_refs"].clone(),
            "provenance_handles": [create_receipt],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_string(
                &material_packet,
                "/negative_memory_check_ref"
            )?,
            "planned_action": "record one deterministic prediction observation",
            "planned_verifier_ref": verifier_ref
        }),
    )?;
    assert_eq!(action["status"], "allowed_bounded");
    let action_revision = required_u64(&action, "/task_contract/memory_revision")?;
    let action_lease_id = required_string(&action, "/action_lease/lease_id")?;
    let provenance_hash = required_string(&action, "/action_lease/provenance_set_hash")?;
    let action_receipt = required_string(&action, "/write_receipt/receipt_id")?;
    let stale_action = harness.client.tool_call(
        731,
        "eliot_task_action_request",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "expected_revision": action_revision,
            "packet_id": required_string(&material_packet, "/packet_id")?,
            "packet_revision_fence": required_u64(&material_packet, "/packet_revision_fence")?,
            "task_contract_ref": required_string(&material_packet, "/task_contract_ref")?,
            "current_truth_refs": material_packet["current_truth_refs"].clone(),
            "provenance_handles": [action_receipt.clone()],
            "negative_memory_checked": true,
            "negative_memory_check_ref": required_string(
                &material_packet,
                "/negative_memory_check_ref"
            )?,
            "planned_action": "attempt action from a superseded packet",
            "planned_verifier_ref": verifier_ref
        }),
    )?;
    assert_eq!(stale_action["status"], "denied_invalid_provenance");
    let observed = harness.client.tool_call(
        74,
        "eliot_task_observation_record",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "expected_revision": action_revision,
            "action_lease_id": action_lease_id,
            "item_id": "t04-observed",
            "tool_name": "ul_done_prediction_probe",
            "observation": "the daemon committed a bounded observation",
            "status": "passed",
            "scope": format!("eliot/task/{task_id}/acceptance/t04-observed"),
            "provenance_handles": [action_receipt],
            "provenance_set_hash": provenance_hash
        }),
    )?;
    let observation_revision = required_u64(&observed, "/task_contract/memory_revision")?;
    let observation_id = required_string(&observed, "/observation_id")?;
    let verified = harness.client.tool_call(
        75,
        "eliot_task_verification_run",
        &json!({
            "project_id": project_id,
            "task_id": task_id,
            "write_id": WriteId::new_v7(),
            "expected_revision": observation_revision,
            "item_id": "t04-verified",
            "observation_id": observation_id,
            "mode": "registered",
            "verifier_ref": verifier_ref,
            "verifier_config_hash": verifier_config_hash,
            "provenance_set_hash": provenance_hash,
            "acceptance_item_ids": ["t04-verified"],
            "artifact_paths": []
        }),
    )?;
    let predictions: Vec<PredictionRecord> = harness.observability_records(
        project_id,
        Some(task_id),
        ObservabilityKind::PredictionRecord,
    )?;

    assert_eq!(verified["status"], "passed");
    assert_eq!(verified["ul_prediction_resolution"]["status"], "resolved");
    let verifier_prediction = predictions
        .iter()
        .find(|record| {
            matches!(
                record.prediction,
                Some(eliot_types::UlPrediction::VerifierVerdict { .. })
            )
        })
        .ok_or("verifier prediction was not captured")?;
    assert_eq!(
        verifier_prediction.resolution,
        Some(PredictionResolution::Hit)
    );
    Ok(())
}

#[test]
fn d10_memory_free_control_has_zero_ul_fields_and_zero_injection_receipts() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "d10_memory_free_control_has_zero_ul_fields_and_zero_injection_receipts",
    )? {
        return Ok(());
    }
    let mut harness = Harness::start("done-d10")?;
    let project_id = ProjectId::new_v7();
    let response = harness.client.tool_call(
        80,
        "eliot_compile_packet_l3",
        &json!({
            "project_id": project_id,
            "task_id": TaskId::new_v7(),
            "goal": "compile the clean memory-free control",
            "candidate_handles": [],
            "max_tokens": 800,
            "memory_mode": "memory_free_control"
        }),
    )?;
    let receipts: Vec<InjectionReceipt> =
        harness.observability_records(project_id, None, ObservabilityKind::InjectionReceipt)?;
    let ul_fields = response
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .filter(|key| key.starts_with("ul_"))
        .collect::<Vec<_>>();

    assert_eq!(
        ul_fields,
        ["ul_experiment"],
        "control exposed memory-derived UL fields: {ul_fields:?}"
    );
    assert_eq!(response["ul_experiment"]["arm"], "control");
    assert_eq!(
        response["ul_experiment"]["effective_memory_mode"],
        "memory_free_control"
    );
    assert_eq!(
        response["compile_audit"]["source_reads"]["current_state_reads"],
        0
    );
    assert_eq!(response["compile_audit"]["source_reads"]["l0_reads"], 0);
    assert_eq!(response["compile_audit"]["source_reads"]["l2_reads"], 0);
    for counter in ["l0", "l2", "pyramid", "experience", "skill"] {
        assert_eq!(
            response["compile_audit"]["read_counters"][counter], 0,
            "control read counter {counter} was not zero"
        );
    }
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
    assert!(response.get("prediction_ref").is_none());
    assert!(receipts.is_empty());
    Ok(())
}

fn candidate_arguments(
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    statement: &str,
) -> Value {
    json!({
        "project_id": project_id,
        "task_id": task_id,
        "write_id": write_id,
        "topic": "ul-mvp-done",
        "statement": statement,
        "where_applicable": ["eliot-memory-os"],
        "where_not_applicable": [],
        "negative_constraints": [],
        "provenance_refs": ["test:UL-07"],
        "freshness_rule": "valid for this isolated integration fixture",
        "expected_reuse_note": "Reuse only in the matching isolated integration scope.",
        "cue_bindings": [{
            "cue_kind": "file_path",
            "cue_value": "crates/eliot-store/src/lib.rs",
            "match_mode": "exact",
            "strength": "primary",
            "expected_reuse_note": "Reuse only in the matching isolated integration scope."
        }]
    })
}

fn failure_command(project_id: ProjectId, fingerprint: &str) -> SemanticCommand {
    SemanticCommand::FailureRecord(eliot_types::FailureRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: None,
            scope: "ul-mvp-done".to_owned(),
            authority: "ul-mvp-done-test".to_owned(),
            visibility: Visibility::Project,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        fingerprint: fingerprint.to_owned(),
        summary: "network session repeatedly drops".to_owned(),
        payload: json!({
            "cue_bindings": [CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: "src/net/session.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: "Reuse when the network session path is touched.".to_owned(),
            }]
        }),
    })
}

fn required_string(value: &Value, pointer: &str) -> TestResult<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string at {pointer}: {value}").into())
}

fn required_u64(value: &Value, pointer: &str) -> TestResult<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 at {pointer}: {value}").into())
}

struct TempGitRepo {
    root: PathBuf,
}

impl TempGitRepo {
    fn new(name: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "eliot-ul-done-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        git(&root, &["init", "--quiet"])?;
        git(&root, &["config", "core.autocrlf", "false"])?;
        git(&root, &["config", "user.name", "UL Done Test"])?;
        git(&root, &["config", "user.email", "ul-done@example.invalid"])?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, path: &str, body: &str) -> TestResult {
        let target = self.root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, body)?;
        Ok(())
    }

    fn commit(&self, index: usize, paths: &[&str], subject: &str) -> TestResult {
        for path in paths {
            self.write(path, &format!("{subject}-{index}\n"))?;
        }
        self.commit_all(index, subject)
    }

    fn commit_all(&self, index: usize, subject: &str) -> TestResult {
        git(&self.root, &["add", "--all"])?;
        let timestamp = 1_760_000_000_i64.saturating_add(
            i64::try_from(index)
                .unwrap_or(i64::MAX)
                .saturating_mul(3_600),
        );
        let date = format!("@{timestamp} +0000");
        let status = Command::new("git")
            .args(["-C"])
            .arg(&self.root)
            .args(["commit", "--quiet", "-m", subject])
            .env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date)
            .status()?;
        if !status.success() {
            return Err(format!("git commit failed with {status}").into());
        }
        Ok(())
    }
}

impl Drop for TempGitRepo {
    fn drop(&mut self) {
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("eliot-ul-done-"))
            && self.root.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn git(root: &Path, args: &[&str]) -> TestResult {
    let status = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("git {args:?} failed with {status}").into());
    }
    Ok(())
}
