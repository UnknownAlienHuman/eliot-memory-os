#[path = "support/ul_t04.rs"]
mod support;

use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, EpistemicStatus, EvidenceAtomInput, EvidenceId,
    FailureFingerprintInput, IdempotencyOptions, LifecycleStatus, LifecycleWriteOptions,
    MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence, ReadConsistencyMode,
    RecallL0Request, SemanticCommandKind, TaintClass, TaskId, ToolObservationInput, VerificationId,
    VerificationResult, VerificationRunInput, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use support::{Harness, TestResult, rerun_with_credential_gate, test_guard};
use time::OffsetDateTime;

fn request(project_id: ProjectId, query: impl Into<String>) -> RecallL0Request {
    RecallL0Request {
        project_id,
        query: query.into(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
        task_id: None,
        task_class_cues: Vec::new(),
        scope_refs: Vec::new(),
        concept_refs: Vec::new(),
    }
}

fn envelope(
    project_id: ProjectId,
    task_id: TaskId,
    scope: &str,
    lifecycle: LifecycleStatus,
    sequence: u64,
    claims: Vec<ClaimCardInput>,
) -> MemoryWriteEnvelope {
    let write_id = WriteId::new_v7();
    MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash: blake3::hash(format!("{write_id}:{project_id}:{scope}").as_bytes())
            .to_hex()
            .to_string(),
        policy_snapshot_id: Some("policy:c3-unified-retrieval-v1".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(sequence)),
        created_at: OffsetDateTime::now_utc(),
        scope: scope.to_owned(),
        authority: "local-field-certification".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms: Vec::new(),
        tool_observations: Vec::new(),
        failures: Vec::new(),
        claims,
        verification_runs: Vec::new(),
        relations: Vec::new(),
        lifecycle: LifecycleWriteOptions {
            status: lifecycle,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn c3_unified_projection_pages_beyond_512_and_preserves_filters_and_dedup() -> TestResult {
    let _guard = test_guard();
    if rerun_with_credential_gate(
        "c3_unified_projection_pages_beyond_512_and_preserves_filters_and_dedup",
    )? {
        return Ok(());
    }
    let mut prepared = Harness::prepare("c3-unified-retrieval")?;
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let target_id = ClaimId::new_v7();
    let duplicate_a = ClaimId::new_v7();
    let duplicate_b = ClaimId::new_v7();
    let counterexample = ClaimId::new_v7();
    let harmful_id = ClaimId::new_v7();
    let evidence_id = EvidenceId::new_v7();
    let verification_id = VerificationId::new_v7();
    let observation_id = format!("c3-observation-{}", ClaimId::new_v7());
    let failure_id = format!("c3-failure-{}", ClaimId::new_v7());
    let mut claims = (0..520)
        .map(|index| ClaimCardInput {
            claim_id: ClaimId::new_v7(),
            statement: format!("обычный отвлекающий факт корпуса номер {index:03}"),
            status: EpistemicStatus::Supported,
            payload: json!({"topic": "large-corpus-distractor"}),
        })
        .collect::<Vec<_>>();
    claims.extend([
        ClaimCardInput {
            claim_id: target_id,
            statement: "редкая игла C3 находится после прежней границы пятисот двенадцати"
                .to_owned(),
            status: EpistemicStatus::Verified,
            payload: json!({
                "topic": "c3-paged-target",
                "path": "src/core/retrieval.rs",
                "symbol": "paged_projection",
                "task_class": "retrieval-certification",
                "concept_id": "concept:progressive-disclosure",
                "changed_outcome": true,
                "beneficial_use_count": 3
            }),
        },
        ClaimCardInput {
            claim_id: duplicate_a,
            statement: "точный семантический дубль применим только в src/core".to_owned(),
            status: EpistemicStatus::Supported,
            payload: json!({"topic": "dedup"}),
        },
        ClaimCardInput {
            claim_id: duplicate_b,
            statement: "точный семантический дубль применим только в src/core".to_owned(),
            status: EpistemicStatus::Supported,
            payload: json!({"topic": "dedup"}),
        },
        ClaimCardInput {
            claim_id: counterexample,
            statement: "точный семантический дубль применим только в src/core".to_owned(),
            status: EpistemicStatus::Contested,
            payload: json!({"topic": "dedup", "counterexample": true}),
        },
        ClaimCardInput {
            claim_id: harmful_id,
            statement: "опасная повторная отвлекающая рекомендация C3".to_owned(),
            status: EpistemicStatus::Supported,
            payload: json!({
                "topic": "penalty-probe",
                "harmful": true,
                "repeated": true,
                "distraction": true
            }),
        },
    ]);
    let mut active = envelope(
        project_id,
        task_id,
        "src/core",
        LifecycleStatus::Active,
        1,
        claims,
    );
    active.evidence_atoms = vec![EvidenceAtomInput {
        evidence_id,
        source_id: "source:c3-field".to_owned(),
        summary: "многоязычное свидетельство единой проекции".to_owned(),
        payload: json!({"concept_id": "concept:progressive-disclosure"}),
    }];
    active.verification_runs = vec![VerificationRunInput {
        verification_id,
        claim_id: Some(target_id),
        verifier: "c3-field-verifier".to_owned(),
        result: VerificationResult::Passed,
        summary: "проверка редкой иглы C3 пройдена".to_owned(),
        payload: json!({"path": "src/core/retrieval.rs"}),
    }];
    active.tool_observations = vec![ToolObservationInput {
        observation_id: observation_id.clone(),
        tool_name: "c3-field-tool".to_owned(),
        observation: "наблюдение многообразия текущей проекции".to_owned(),
        payload: json!({"task_class": "retrieval-certification"}),
    }];
    active.failures = vec![FailureFingerprintInput {
        fingerprint: failure_id.clone(),
        summary: "ошибка старого фиксированного лимита кандидатов".to_owned(),
        payload: json!({"error": "fixed-candidate-limit"}),
    }];
    assert_eq!(
        prepared.apply_memory_envelope(&active)?.status,
        WriteStatus::Committed
    );

    let hidden_id = ClaimId::new_v7();
    let hidden = envelope(
        project_id,
        task_id,
        "src/core",
        LifecycleStatus::Suppressed,
        2,
        vec![ClaimCardInput {
            claim_id: hidden_id,
            statement: "скрытая lifecycle память C3".to_owned(),
            status: EpistemicStatus::Supported,
            payload: json!({"topic": "lifecycle-audit"}),
        }],
    );
    assert_eq!(
        prepared.apply_memory_envelope(&hidden)?.status,
        WriteStatus::Committed
    );
    let archived_id = ClaimId::new_v7();
    let archived = envelope(
        project_id,
        task_id,
        "src/core",
        LifecycleStatus::Archived,
        3,
        vec![ClaimCardInput {
            claim_id: archived_id,
            statement: "архивная audit-only память C3".to_owned(),
            status: EpistemicStatus::Supported,
            payload: json!({"topic": "historical-audit"}),
        }],
    );
    assert_eq!(
        prepared.apply_memory_envelope(&archived)?.status,
        WriteStatus::Committed
    );
    let harness = prepared.launch()?;

    let mut paged = request(
        project_id,
        "редкая игла C3 находится после прежней границы пятисот двенадцати",
    );
    paged.task_id = Some(task_id);
    paged.task_class_cues = vec!["retrieval-certification".to_owned()];
    paged.scope_refs = vec!["src/core/retrieval.rs".to_owned()];
    paged.concept_refs = vec!["concept:progressive-disclosure".to_owned()];
    let recalled = harness.recall_l0(&paged)?;
    assert!(
        (1..=256).contains(&recalled.rank_trace.candidates_considered),
        "FTS admission exceeded the bounded L0 candidate contract: {:?}",
        recalled.rank_trace
    );
    assert_eq!(recalled.handles[0].handle, format!("claim:{target_id}"));
    let target_score = &recalled.rank_trace.feature_scores[0];
    assert!(target_score.exact_cue > 0);
    assert!(target_score.task_relation > 0);
    assert!(target_score.scope_fit > 0);
    assert!(target_score.concept_relation > 0);
    assert!(target_score.known_decision_delta > 0);
    assert!(target_score.prior_beneficial_use > 0);
    assert!(target_score.freshness_fit > 0);
    assert!(target_score.evidence_authority > 0);
    assert!(target_score.context_cost < 0);
    let evidence_recall = harness.recall_l0(&request(
        project_id,
        "многоязычное свидетельство единой проекции",
    ))?;
    assert_eq!(
        evidence_recall.handles[0].handle,
        format!("evidence:{evidence_id}")
    );
    assert!(evidence_recall.rank_trace.feature_scores[0].verification_value > 0);
    assert_eq!(
        harness
            .recall_l0(&request(project_id, "проверка редкой иглы C3 пройдена"))?
            .handles[0]
            .handle,
        format!("verification:{verification_id}")
    );
    assert_eq!(
        harness
            .recall_l0(&request(
                project_id,
                "наблюдение многообразия текущей проекции"
            ))?
            .handles[0]
            .handle,
        format!("observation:{observation_id}")
    );
    let failure_recall =
        harness.recall_l0(&request(project_id, "ошибка старого фиксированного лимита"))?;
    assert_eq!(
        failure_recall.handles[0].handle,
        format!("failure:{failure_id}")
    );
    assert!(failure_recall.rank_trace.feature_scores[0].negative_memory_value > 0);
    assert!(failure_recall.rank_trace.feature_scores[0].known_decision_delta > 0);
    let penalty_recall = harness.recall_l0(&request(
        project_id,
        "опасная повторная отвлекающая рекомендация C3",
    ))?;
    let penalty_score = penalty_recall
        .rank_trace
        .feature_scores
        .iter()
        .find(|score| score.handle == format!("claim:{harmful_id}"))
        .ok_or("penalty probe must remain inspectable after ranking")?;
    assert!(penalty_score.harm_penalty < 0);
    assert!(penalty_score.repetition_penalty < 0);
    assert!(penalty_score.distraction_penalty < 0);

    let duplicate_recall =
        harness.recall_l0(&request(project_id, "точный семантический дубль src/core"))?;
    assert_eq!(
        duplicate_recall
            .handles
            .iter()
            .filter(|handle| handle.preview.contains("точный семантический дубль"))
            .count(),
        2,
        "one supported duplicate and the contested counterexample must remain"
    );
    assert!(
        duplicate_recall
            .rank_trace
            .collapsed_duplicates
            .iter()
            .any(|trace| trace.reason == "semantic_duplicate")
    );

    let mut wrong_scope = request(project_id, "редкая игла C3");
    wrong_scope.scope_refs = vec!["src/unrelated".to_owned()];
    let scoped = harness.recall_l0(&wrong_scope)?;
    assert!(scoped.handles.is_empty());
    assert!(
        scoped
            .rank_trace
            .scope_suppressions
            .iter()
            .any(|trace| trace.handle == format!("claim:{target_id}"))
    );

    let normal_hidden = harness.recall_l0(&request(project_id, "скрытая lifecycle память C3"))?;
    assert!(
        normal_hidden
            .handles
            .iter()
            .all(|handle| handle.handle != format!("claim:{hidden_id}"))
    );
    let mut audit_request = request(project_id, "скрытая lifecycle память C3");
    audit_request.lifecycle_audit = true;
    let audited = harness.recall_l0(&audit_request)?;
    assert!(
        audited
            .handles
            .iter()
            .any(|handle| handle.handle == format!("claim:{hidden_id}"))
    );

    let default_archive =
        harness.recall_l0(&request(project_id, "архивная audit-only память C3"))?;
    assert!(
        default_archive
            .handles
            .iter()
            .all(|handle| handle.handle != format!("claim:{archived_id}"))
    );
    let mut archive_audit = request(project_id, "архивная audit-only память C3");
    archive_audit.lifecycle_audit = true;
    let archive_audited = harness.recall_l0(&archive_audit)?;
    assert!(
        archive_audited
            .handles
            .iter()
            .any(|handle| handle.handle == format!("claim:{archived_id}"))
    );
    Ok(())
}
