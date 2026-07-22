use eliot_store::CanonicalStore;
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, EpistemicStatus, EvidenceAtomInput, EvidenceId,
    FetchAtomsL2Request, GovernorConfig, IdempotencyOptions, LifecycleStatus,
    LifecycleWriteOptions, MemoryWriteEnvelope, OperationId, ProjectId, ProjectSequence,
    ReadConsistencyMode, RecallL0Request, RelationInput, RelationType, SemanticCommandKind,
    SurrealServerConfig, TaintClass, TaskId, Visibility, WriteId, WriteStatus,
};
use serde_json::json;
use std::error::Error;
use time::OffsetDateTime;

fn isolated_config() -> Option<SurrealServerConfig> {
    let endpoint = std::env::var("ELIOT_TEST_SURREAL_ENDPOINT").ok()?;
    let bind = std::env::var("ELIOT_TEST_SURREAL_BIND").ok()?;
    let password_file = std::env::var("ELIOT_TEST_SURREAL_PASSWORD_FILE").ok()?;
    let storage = std::env::var("ELIOT_TEST_SURREAL_STORAGE").ok()?;
    let mut config = GovernorConfig::default().db.surreal;
    config.endpoint = endpoint;
    config.bind = bind;
    config.password_file = password_file;
    config.storage = storage;
    Some(config)
}

fn retrieval_envelope(
    project_id: ProjectId,
    task_id: TaskId,
    claims: Vec<ClaimCardInput>,
    evidence_atoms: Vec<EvidenceAtomInput>,
    relations: Vec<RelationInput>,
) -> Result<MemoryWriteEnvelope, serde_json::Error> {
    let write_id = WriteId::new_v7();
    let input_hash = blake3::hash(&serde_json::to_vec(&json!({
        "project_id": project_id,
        "claims": claims,
        "evidence_atoms": evidence_atoms,
        "relations": relations,
    }))?)
    .to_hex()
    .to_string();
    Ok(MemoryWriteEnvelope {
        write_id,
        operation_id: OperationId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ClaimPropose,
        input_hash,
        policy_snapshot_id: Some("policy:l13-query-aware-retrieval".to_owned()),
        project_sequence_hint: Some(ProjectSequence::new(1)),
        created_at: OffsetDateTime::now_utc(),
        scope: "phase-l13-bounded-retrieval".to_owned(),
        authority: "isolated-local-verified".to_owned(),
        task_contracts: Vec::new(),
        source_snapshots: Vec::new(),
        evidence_atoms,
        tool_observations: Vec::new(),
        failures: Vec::new(),
        claims,
        verification_runs: Vec::new(),
        relations,
        lifecycle: LifecycleWriteOptions {
            status: LifecycleStatus::Active,
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
        },
        idempotency: IdempotencyOptions { allow_replay: true },
    })
}

fn claim(statement: String, topic: &str) -> ClaimCardInput {
    ClaimCardInput {
        claim_id: ClaimId::new_v7(),
        statement,
        status: EpistemicStatus::Verified,
        payload: json!({ "topic": topic }),
    }
}

fn recall_request(project_id: ProjectId, query: impl Into<String>) -> RecallL0Request {
    RecallL0Request {
        project_id,
        query: query.into(),
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
        lifecycle_audit: false,
    }
}

fn l2_request(project_id: ProjectId, handles: Vec<String>) -> FetchAtomsL2Request {
    FetchAtomsL2Request {
        project_id,
        handles,
        continuation: None,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn query_aware_l0_and_exact_l2_are_bounded_scoped_and_restart_deterministic()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut claims = (0..60)
        .map(|index| {
            claim(
                format!("omega needle distractor {index:02}"),
                "omega-needle-distractor",
            )
        })
        .collect::<Vec<_>>();
    let alpha = claim("alpha disjoint memory".to_owned(), "alpha-topic");
    let beta = claim("beta disjoint memory".to_owned(), "beta-topic");
    let exact = claim("omega needle".to_owned(), "omega-needle-target");
    let weak_causal_distractor = claim(
        "causal-probe-42 appears only as weak lexical text".to_owned(),
        "weak-lexical-distractor",
    );
    let mut causal = claim(
        "current task relation outranks weak text".to_owned(),
        "current-task-memory",
    );
    causal.payload = json!({ "task_id": "causal-probe-42" });
    let alpha_id = alpha.claim_id;
    let beta_id = beta.claim_id;
    let exact_id = exact.claim_id;
    let causal_id = causal.claim_id;
    claims.extend([alpha, beta, exact, weak_causal_distractor, causal]);

    let evidence_id = EvidenceId::new_v7();
    let envelope = retrieval_envelope(
        project_id,
        task_id,
        claims,
        vec![EvidenceAtomInput {
            evidence_id,
            source_id: "source:l13-retrieval".to_owned(),
            summary: "exact retrieval evidence".to_owned(),
            payload: json!({ "scope": "phase-l13" }),
        }],
        vec![RelationInput {
            relation_type: RelationType::Supports,
            from: exact_id.to_string(),
            to: evidence_id.to_string(),
        }],
    )?;
    let receipt = store.apply_write_envelope(&envelope).await?;
    assert_eq!(receipt.status, WriteStatus::Committed);

    let ranked = store
        .recall_l0(&recall_request(project_id, "omega needle"))
        .await?;
    assert_eq!(ranked.rank_trace.candidates_considered, 61);
    assert_eq!(ranked.rank_trace.candidates_returned, 50);
    assert!(ranked.truncation.truncated);
    assert_eq!(ranked.handles[0].handle, exact_id.to_string());
    assert_eq!(
        ranked.rank_trace.query_mode,
        "query_aware_semantic_lexical_relational_v2"
    );
    assert_eq!(ranked.rank_trace.feature_scores[0].lexical_overlap, 250);

    let alpha_ranked = store
        .recall_l0(&recall_request(project_id, "alpha disjoint memory"))
        .await?;
    assert_eq!(alpha_ranked.handles.len(), 1);
    assert_eq!(alpha_ranked.handles[0].handle, alpha_id.to_string());
    assert!(
        alpha_ranked
            .handles
            .iter()
            .all(|handle| handle.handle != beta_id.to_string())
    );

    let exact_ranked = store
        .recall_l0(&recall_request(project_id, format!("claim:{exact_id}")))
        .await?;
    assert!(
        !exact_ranked.handles.is_empty(),
        "exact-id recall returned no handles: {exact_ranked:?}"
    );
    assert_eq!(exact_ranked.handles[0].handle, exact_id.to_string());
    assert_eq!(
        exact_ranked.rank_trace.feature_scores[0].exact_identifier,
        1000
    );

    let empty = store
        .recall_l0(&recall_request(project_id, "memory-that-does-not-exist"))
        .await?;
    assert!(empty.handles.is_empty());
    assert!(empty.rank_trace.no_useful_memory);

    let causal_ranked = store
        .recall_l0(&recall_request(project_id, "causal-probe-42"))
        .await?;
    assert_eq!(causal_ranked.handles.len(), 2);
    assert_eq!(causal_ranked.handles[0].handle, causal_id.to_string());
    assert_eq!(
        causal_ranked.rank_trace.feature_scores[0].task_relation,
        120
    );
    assert!(
        causal_ranked.rank_trace.feature_scores[0].total
            > causal_ranked.rank_trace.feature_scores[1].total
    );

    let ordered = store
        .fetch_atoms_l2(&l2_request(
            project_id,
            vec![format!("claim:{beta_id}"), format!("claim:{alpha_id}")],
        ))
        .await?;
    assert_eq!(ordered.claims.len(), 2);
    assert_eq!(ordered.claims[0].claim_id, beta_id);
    assert_eq!(ordered.claims[1].claim_id, alpha_id);
    assert_eq!(
        ordered.returned_handles,
        vec![format!("claim:{beta_id}"), format!("claim:{alpha_id}")]
    );

    let deduplicated = store
        .fetch_atoms_l2(&l2_request(
            project_id,
            vec![
                format!("claim:{exact_id}"),
                format!("claim_card:{exact_id}"),
                exact_id.to_string(),
            ],
        ))
        .await?;
    assert_eq!(
        deduplicated.requested_handles,
        vec![format!("claim:{exact_id}")]
    );
    assert_eq!(deduplicated.claims.len(), 1);
    assert_eq!(deduplicated.evidence_atoms.len(), 1);
    assert_eq!(deduplicated.evidence_atoms[0].evidence_id, evidence_id);
    assert_eq!(deduplicated.relations.len(), 1);

    let bare_id = store
        .fetch_atoms_l2(&l2_request(project_id, vec![exact_id.to_string()]))
        .await?;
    assert_eq!(bare_id.claims.len(), 1);
    assert_eq!(bare_id.returned_handles, vec![exact_id.to_string()]);

    let relation = store
        .fetch_atoms_l2(&l2_request(
            project_id,
            vec![
                format!("claim:{exact_id}"),
                format!("evidence:{evidence_id}"),
            ],
        ))
        .await?;
    assert_eq!(relation.claims.len(), 1);
    assert_eq!(relation.evidence_atoms.len(), 1);
    assert_eq!(relation.relations.len(), 1);

    let missing = store
        .fetch_atoms_l2(&l2_request(
            project_id,
            vec![format!("claim:{}", ClaimId::new_v7())],
        ))
        .await?;
    assert_eq!(missing.missing_handles.len(), 1);
    assert!(missing.returned_handles.is_empty());

    let other_project_id = ProjectId::new_v7();
    let foreign = claim("foreign project claim".to_owned(), "foreign");
    let foreign_id = foreign.claim_id;
    let foreign_envelope = retrieval_envelope(
        other_project_id,
        TaskId::new_v7(),
        vec![foreign],
        Vec::new(),
        Vec::new(),
    )?;
    store.apply_write_envelope(&foreign_envelope).await?;
    let forbidden = store
        .fetch_atoms_l2(&l2_request(project_id, vec![format!("claim:{foreign_id}")]))
        .await?;
    assert_eq!(
        forbidden.forbidden_handles,
        vec![format!("claim:{foreign_id}")]
    );
    assert!(forbidden.claims.is_empty());
    let foreign_ranked = store
        .recall_l0(&recall_request(project_id, "foreign project claim"))
        .await?;
    assert!(foreign_ranked.handles.is_empty());
    assert!(foreign_ranked.rank_trace.no_useful_memory);

    let oversized = (0..65)
        .map(|_| format!("claim:{}", ClaimId::new_v7()))
        .collect::<Vec<_>>();
    let first_page = store
        .fetch_atoms_l2(&l2_request(project_id, oversized.clone()))
        .await?;
    assert_eq!(first_page.requested_handles.len(), 64);
    assert_eq!(first_page.missing_handles.len(), 64);
    assert!(first_page.truncation.truncated);
    let mut second_page_request = l2_request(project_id, oversized.clone());
    second_page_request.continuation = first_page.continuation.clone();
    let second_page = store.fetch_atoms_l2(&second_page_request).await?;
    assert_eq!(second_page.requested_handles.len(), 1);
    assert_eq!(second_page.missing_handles.len(), 1);
    assert!(second_page.continuation.is_none());
    let too_large = (0..513)
        .map(|_| format!("claim:{}", ClaimId::new_v7()))
        .collect::<Vec<_>>();
    assert!(
        store
            .fetch_atoms_l2(&l2_request(project_id, too_large))
            .await
            .is_err()
    );
    let mut invalid_continuation = l2_request(project_id, oversized);
    invalid_continuation.continuation = Some("l2:40:wrong-list-hash".to_owned());
    assert!(store.fetch_atoms_l2(&invalid_continuation).await.is_err());

    let restarted = CanonicalStore::new(config);
    let restarted_ranked = restarted
        .recall_l0(&recall_request(project_id, "omega needle"))
        .await?;
    assert_eq!(
        restarted_ranked
            .handles
            .iter()
            .map(|handle| &handle.handle)
            .collect::<Vec<_>>(),
        ranked
            .handles
            .iter()
            .map(|handle| &handle.handle)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        restarted_ranked
            .rank_trace
            .feature_scores
            .iter()
            .map(|score| (score.handle.as_str(), score.total))
            .collect::<Vec<_>>(),
        ranked
            .rank_trace
            .feature_scores
            .iter()
            .map(|score| (score.handle.as_str(), score.total))
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn neutral_l15_paraphrases_recall_the_right_admitted_memory_without_handles()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let mut ambient_root = claim(
        "On Windows, changing a process-wide ambient user data root can break both credential policy and user-installed host discovery; isolate only the owned test secret subtree and re-probe current paths before transfer."
            .to_owned(),
        "windows ambient root isolation boundary",
    );
    ambient_root.payload = json!({
        "topic": "windows ambient root isolation boundary",
        "where_applicable": [
            "Windows tests that need secret isolation while production code derives user paths from ambient roots"
        ],
        "where_not_applicable": [
            "fully hermetic processes that own every derived root"
        ],
        "negative_constraints": [
            "do not replace process-wide LOCALAPPDATA"
        ]
    });
    let mut opaque_bootstrap = claim(
        "For supervised CLI providers, application redaction cannot protect a complete task packet placed in argv; pass only an opaque identifier, fetch the packet after authenticated ELIOT connection, and verify the current CLI binding probe."
            .to_owned(),
        "opaque authenticated provider bootstrap",
    );
    opaque_bootstrap.payload = json!({
        "topic": "opaque authenticated provider bootstrap",
        "where_applicable": [
            "provider CLI accepts positional prompt text and can connect to an authenticated broker"
        ],
        "where_not_applicable": [
            "provider already has a confidential non-argv authenticated input channel"
        ],
        "negative_constraints": [
            "never place the complete role packet in process argv"
        ]
    });
    let ambient_root_id = ambient_root.claim_id;
    let opaque_bootstrap_id = opaque_bootstrap.claim_id;
    let receipt = store
        .apply_write_envelope(&retrieval_envelope(
            project_id,
            task_id,
            vec![ambient_root, opaque_bootstrap],
            Vec::new(),
            Vec::new(),
        )?)
        .await?;
    assert_eq!(receipt.status, WriteStatus::Committed);

    let cases = [
        (
            "A Windows test violates credential location policy and loses user installed host discovery. What common ambient root boundary should be repaired?",
            ambient_root_id,
        ),
        (
            "How should Windows secret isolation preserve provider discovery when production derives supported user paths from LOCALAPPDATA?",
            ambient_root_id,
        ),
        (
            "Explain why replacing the process wide user data root breaks both credential policy and installed host lookup.",
            ambient_root_id,
        ),
        (
            "Which owned test secrets subtree can be isolated without changing ambient Windows roots used for host discovery?",
            ambient_root_id,
        ),
        (
            "What should a Windows harness re-probe before transferring an ambient root isolation lesson to current paths?",
            ambient_root_id,
        ),
        (
            "A test needs local secret isolation while user installed providers depend on ambient roots. Recover the reusable boundary.",
            ambient_root_id,
        ),
        (
            "A supervised CLI agent needs a complete role packet but process inspection must not reveal it. What opaque bootstrap boundary applies?",
            opaque_bootstrap_id,
        ),
        (
            "Why can application redaction not protect task material passed in provider argv, and how should authenticated fetch replace it?",
            opaque_bootstrap_id,
        ),
        (
            "Describe the safe provider launch where argv carries an opaque identifier and ELIOT returns the task packet after authentication.",
            opaque_bootstrap_id,
        ),
        (
            "Which current CLI binding probe verifies that a supervised provider fetched its complete packet without exposing positional prompt text?",
            opaque_bootstrap_id,
        ),
        (
            "When a provider supports an authenticated broker connection, where should the role packet cross the delivery boundary instead of argv?",
            opaque_bootstrap_id,
        ),
        (
            "Recover the reusable lesson for hiding a substantial task packet from ordinary process metadata during supervised CLI launch.",
            opaque_bootstrap_id,
        ),
    ];
    for (query, expected_id) in cases {
        let recalled = store.recall_l0(&recall_request(project_id, query)).await?;
        let expected_handle = expected_id.to_string();
        assert!(
            !recalled.rank_trace.no_useful_memory,
            "neutral query admitted no memory: {query}"
        );
        assert_eq!(
            recalled
                .handles
                .first()
                .map(|handle| handle.handle.as_str()),
            Some(expected_handle.as_str()),
            "neutral query ranked the wrong memory: {query}; trace={:?}",
            recalled.rank_trace
        );
        assert_eq!(
            recalled.rank_trace.query_mode,
            "query_aware_semantic_lexical_relational_v2"
        );
    }

    let near_miss = store
        .recall_l0(&recall_request(
            project_id,
            "database sharding throughput benchmark",
        ))
        .await?;
    assert!(near_miss.handles.is_empty());
    assert!(near_miss.rank_trace.no_useful_memory);
    Ok(())
}
