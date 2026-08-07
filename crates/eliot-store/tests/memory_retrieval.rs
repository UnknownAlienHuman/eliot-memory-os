use eliot_store::{BlobStore, CanonicalStore};
use eliot_types::{
    AgentId, BlobStoreConfig, ClaimCardInput, ClaimId, CueBinding, CueKind, CueMatchMode,
    CueStrength, EpistemicStatus, EvidenceAtomInput, EvidenceId, FailureFingerprintInput,
    FetchAtomsL2Request, GovernorConfig, IdempotencyOptions, LifecycleStatus,
    LifecycleWriteOptions, MemoryConfidence, MemoryWriteEnvelope, OperationId, ProjectId,
    ProjectSequence, ReadConsistencyMode, RecallL0Request, RelationInput, RelationType,
    SemanticCommandKind, SurrealServerConfig, TaintClass, TaskId, ToolObservationInput, Visibility,
    WriteId, WriteStatus,
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
        scope: "bounded-retrieval".to_owned(),
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
        task_id: None,
        task_class_cues: Vec::new(),
        scope_refs: Vec::new(),
        concept_refs: Vec::new(),
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
async fn canonical_capacity_parent_and_tail_segment_are_reachable_through_normal_l2()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let blob_root = std::env::temp_dir().join(format!(
        "eliot-capacity-l2-{}",
        uuid::Uuid::new_v4().as_simple()
    ));
    let blob_store = BlobStore::open(&BlobStoreConfig {
        root: blob_root.display().to_string(),
    })?;
    let store = CanonicalStore::new(config).with_blob_store(blob_store.clone());
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let memory_handle = format!("memory:capacity-l2-{}", uuid::Uuid::new_v4().as_simple());
    let payload = (0..45_000)
        .map(|index| format!("capacity-token-{index:05}"))
        .collect::<Vec<_>>()
        .join(" ")
        .into_bytes();
    let plan = blob_store.stage_canonical_memory(
        &memory_handle,
        "synthetic_evidence",
        "text/plain; charset=utf-8",
        &payload,
        vec![CueBinding {
            cue_kind: CueKind::Concept,
            cue_value: "capacity-l2-tail".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "normal exact-L2 expansion".to_owned(),
        }],
        None,
    )?;
    assert!(plan.segments.len() > 32);

    for record in plan.records_in_commit_order() {
        let receipt_kind = record.receipt_kind();
        let record_id = record.record_id().to_owned();
        let receipt_body = record.receipt_body()?;
        let mut envelope =
            retrieval_envelope(project_id, task_id, Vec::new(), Vec::new(), Vec::new())?;
        envelope.command_kind = SemanticCommandKind::ToolObservationRecord;
        envelope.tool_observations = vec![ToolObservationInput {
            observation_id: record_id.clone(),
            tool_name: "eliot_canonical_memory_ingress".to_owned(),
            observation: format!("canonical memory {receipt_kind} {record_id}"),
            payload: json!({
                "receipt_kind": receipt_kind,
                "receipt_body": receipt_body,
            }),
        }];
        envelope.input_hash = blake3::hash(&serde_json::to_vec(&envelope.tool_observations)?)
            .to_hex()
            .to_string();
        assert_eq!(
            store.apply_write_envelope(&envelope).await?.status,
            WriteStatus::Committed
        );
    }

    let parent = store
        .fetch_atoms_l2(&l2_request(project_id, vec![memory_handle.clone()]))
        .await?;
    assert_eq!(parent.returned_handles, [memory_handle.clone()]);
    assert_eq!(parent.canonical_memory_pages.len(), 1);
    let first_page = &parent.canonical_memory_pages[0];
    assert_eq!(first_page.requested_handle, memory_handle);
    assert_eq!(
        first_page.resolved_parent_handle.as_deref(),
        Some(memory_handle.as_str())
    );
    assert_eq!(first_page.segments.len(), 32);
    assert!(first_page.truncated);
    assert!(first_page.continuation.is_some());
    assert!(!serde_json::to_string(first_page)?.contains("search_text"));

    let second_page = store
        .canonical_memory_l2(
            project_id,
            &memory_handle,
            first_page.continuation.as_deref(),
        )
        .await?;
    assert_eq!(second_page.segments[0].ordinal, 32);

    let tail_segment_id = plan
        .segments
        .last()
        .ok_or("capacity plan omitted its tail segment")?
        .segment_id
        .clone();
    let tail = store
        .fetch_atoms_l2(&l2_request(project_id, vec![tail_segment_id.clone()]))
        .await?;
    assert_eq!(tail.returned_handles, [tail_segment_id.clone()]);
    assert_eq!(tail.canonical_memory_pages.len(), 1);
    assert_eq!(
        tail.canonical_memory_pages[0]
            .requested_segment_id
            .as_deref(),
        Some(tail_segment_id.as_str())
    );
    assert_eq!(tail.canonical_memory_pages[0].segments.len(), 1);
    assert_eq!(
        tail.canonical_memory_pages[0].segments[0].segment_id,
        tail_segment_id
    );

    drop(store);
    std::fs::remove_dir_all(blob_root)?;
    Ok(())
}

#[tokio::test]
async fn file_selector_returns_incident_relation_and_is_restart_deterministic()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config.clone());
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let relation = RelationInput {
        relation_type: RelationType::CoChange,
        from: "file:src/a.rs".to_owned(),
        to: "file:src/b.rs".to_owned(),
    };
    let receipt = store
        .apply_write_envelope(&retrieval_envelope(
            project_id,
            TaskId::new_v7(),
            Vec::new(),
            Vec::new(),
            vec![relation.clone()],
        )?)
        .await?;
    assert_eq!(receipt.status, WriteStatus::Committed);
    assert!(
        receipt
            .created_relations
            .iter()
            .any(|kind| kind == "co_change")
    );
    let request = l2_request(project_id, vec!["file:src/a.rs".to_owned()]);
    let first = store.fetch_atoms_l2(&request).await?;
    assert_eq!(first.requested_handles, vec!["file:src/a.rs"]);
    assert_eq!(first.returned_handles, vec!["file:src/a.rs"]);
    assert!(first.missing_handles.is_empty());
    assert_eq!(first.relations.len(), 1);
    assert_eq!(first.relations[0].relation_type, relation.relation_type);
    assert_eq!(first.relations[0].from, relation.from);
    assert_eq!(first.relations[0].to, relation.to);

    let restarted = CanonicalStore::new(config);
    let after_restart = restarted.fetch_atoms_l2(&request).await?;
    assert_eq!(
        serde_json::to_value(after_restart)?,
        serde_json::to_value(first)?
    );
    Ok(())
}

#[tokio::test]
async fn fv1_d_readiness_graph_inventory_is_project_scoped() -> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;
    let project_a = ProjectId::new_v7();
    let project_b = ProjectId::new_v7();
    let relations_a = vec![
        RelationInput {
            relation_type: RelationType::CoChange,
            from: "file:a/src/lib.rs".to_owned(),
            to: "file:a/src/main.rs".to_owned(),
        },
        RelationInput {
            relation_type: RelationType::CardCovers,
            from: "card:a".to_owned(),
            to: "file:a/src/lib.rs".to_owned(),
        },
        RelationInput {
            relation_type: RelationType::ConceptImplementedBy,
            from: "concept:a".to_owned(),
            to: "file:a/src/lib.rs".to_owned(),
        },
        RelationInput {
            relation_type: RelationType::ConceptDependsOn,
            from: "concept:a".to_owned(),
            to: "concept:a-dependency".to_owned(),
        },
        RelationInput {
            relation_type: RelationType::CapsuleCovers,
            from: "capsule:a".to_owned(),
            to: "concept:a".to_owned(),
        },
    ];
    let relations_b = vec![
        RelationInput {
            relation_type: RelationType::CoChange,
            from: "file:b/src/lib.rs".to_owned(),
            to: "file:b/src/main.rs".to_owned(),
        },
        RelationInput {
            relation_type: RelationType::CoChange,
            from: "file:b/src/lib.rs".to_owned(),
            to: "file:b/src/other.rs".to_owned(),
        },
    ];
    for (project_id, relations) in [(project_a, relations_a), (project_b, relations_b)] {
        let receipt = store
            .apply_write_envelope(&retrieval_envelope(
                project_id,
                TaskId::new_v7(),
                Vec::new(),
                Vec::new(),
                relations,
            )?)
            .await?;
        assert_eq!(receipt.status, WriteStatus::Committed);
    }

    let a = store.load_ul_readiness_inventory(project_a).await?;
    let b = store.load_ul_readiness_inventory(project_b).await?;
    assert_eq!(a.co_change_edges, 1);
    assert_eq!(a.card_covers_edges, 1);
    assert_eq!(a.concept_implemented_by_edges, 1);
    assert_eq!(a.concept_depends_on_edges, 1);
    assert_eq!(a.capsule_covers_edges, 1);
    assert_eq!(a.total_ul_edges, 5);
    assert_eq!(b.co_change_edges, 2);
    assert_eq!(b.card_covers_edges, 0);
    assert_eq!(b.concept_implemented_by_edges, 0);
    assert_eq!(b.concept_depends_on_edges, 0);
    assert_eq!(b.capsule_covers_edges, 0);
    assert_eq!(b.total_ul_edges, 2);
    Ok(())
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
            payload: json!({ "scope": "bounded-retrieval" }),
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
    assert!((1..=256).contains(&ranked.rank_trace.candidates_considered));
    assert_eq!(ranked.rank_trace.candidates_returned, 12);
    assert!(ranked.truncation.truncated);
    assert_eq!(ranked.handles[0].handle, format!("claim:{exact_id}"));
    assert_eq!(
        ranked.rank_trace.query_mode,
        "unicode_multi_kind_lifecycle_aware_v4"
    );
    assert_eq!(ranked.rank_trace.feature_scores[0].lexical_overlap, 470);

    let alpha_ranked = store
        .recall_l0(&recall_request(project_id, "alpha disjoint memory"))
        .await?;
    assert_eq!(alpha_ranked.handles[0].handle, format!("claim:{alpha_id}"));

    let exact_ranked = store
        .recall_l0(&recall_request(project_id, format!("claim:{exact_id}")))
        .await?;
    assert!(
        !exact_ranked.handles.is_empty(),
        "exact-id recall returned no handles: {exact_ranked:?}"
    );
    assert_eq!(exact_ranked.handles[0].handle, format!("claim:{exact_id}"));
    assert_eq!(
        exact_ranked.rank_trace.feature_scores[0].exact_identifier,
        1000
    );

    let empty = store
        .recall_l0(&recall_request(project_id, "quasar telemetry absent"))
        .await?;
    assert!(empty.handles.is_empty());
    assert!(empty.rank_trace.no_useful_memory);

    let lexical_ranked = store
        .recall_l0(&recall_request(project_id, "causal-probe-42"))
        .await?;
    assert_ne!(
        lexical_ranked.handles[0].handle,
        format!("claim:{causal_id}")
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
    let query_plan = restarted
        .memory_search_query_plan(project_id, "omega needle")
        .await?;
    let query_plan_json = serde_json::to_string(&query_plan)?;
    assert!(
        query_plan_json.contains("idx_memory_search_token_posting"),
        "posting lookup did not use its composite index: {query_plan_json}"
    );
    let rebuilt_revision = restarted
        .rebuild_memory_search_projection(project_id)
        .await?;
    assert_eq!(rebuilt_revision, restarted_ranked.at_revision);
    let rebuilt_ranked = restarted
        .recall_l0(&recall_request(project_id, "omega needle"))
        .await?;
    assert_eq!(
        rebuilt_ranked
            .rank_trace
            .feature_scores
            .iter()
            .map(|score| (score.handle.as_str(), score.total))
            .collect::<Vec<_>>(),
        restarted_ranked
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
async fn unicode_multi_kind_recall_and_ul_expansion_are_truthful_and_scoped()
-> Result<(), Box<dyn Error>> {
    let Some(config) = isolated_config() else {
        return Ok(());
    };
    let store = CanonicalStore::new(config);
    store.migrate_schema().await?;

    let project_id = ProjectId::new_v7();
    let russian = claim(
        "Русская память находит границу подсистемы".to_owned(),
        "граница подсистемы",
    );
    let russian_id = russian.claim_id;
    let failure_id = format!("ul11r2-failure-{}", ClaimId::new_v7());
    let card_id = format!("ul11r2-card-{}", ClaimId::new_v7());
    let capsule_id = format!("ul11r2-capsule-{}", ClaimId::new_v7());
    let mut envelope = retrieval_envelope(
        project_id,
        TaskId::new_v7(),
        vec![russian],
        Vec::new(),
        Vec::new(),
    )?;
    envelope.failures = vec![FailureFingerprintInput {
        fingerprint: failure_id.clone(),
        summary: "редкий отказ синхронизации библиотекаря".to_owned(),
        payload: json!({"cause": "граница кодировки"}),
    }];
    envelope.tool_observations = vec![
        ToolObservationInput {
            observation_id: card_id.clone(),
            tool_name: "ul_artifact_writer_actor".to_owned(),
            observation: "recorded module_card artifact".to_owned(),
            payload: json!({
                "receipt_kind": "module_card",
                "receipt_body": {
                    "card_id": card_id,
                    "project_id": project_id,
                    "path": "src/библиотекарь.rs",
                    "body_md": "Карточка модуля описывает Юникод поиск библиотекаря.",
                    "source_refs": ["file:src/библиотекарь.rs"]
                }
            }),
        },
        ToolObservationInput {
            observation_id: capsule_id.clone(),
            tool_name: "ul_artifact_writer_actor".to_owned(),
            observation: "recorded subsystem_capsule artifact".to_owned(),
            payload: json!({
                "receipt_kind": "subsystem_capsule",
                "receipt_body": {
                    "capsule_id": capsule_id,
                    "project_id": project_id,
                    "concept_id": "concept:unicode-librarian",
                    "body_md": "Капсула подсистемы хранит причинную границу Юникод поиска.",
                    "source_refs": ["file:src/библиотекарь.rs"]
                }
            }),
        },
    ];
    envelope.input_hash =
        blake3::hash(format!("{project_id}:{failure_id}:{card_id}:{capsule_id}").as_bytes())
            .to_hex()
            .to_string();
    let receipt = store.apply_write_envelope(&envelope).await?;
    assert_eq!(receipt.status, WriteStatus::Committed);

    let russian_recall = store
        .recall_l0(&recall_request(project_id, "русская граница подсистемы"))
        .await?;
    assert_eq!(
        russian_recall.handles[0].handle,
        format!("claim:{russian_id}")
    );
    assert_eq!(russian_recall.memory_confidence, MemoryConfidence::Found);

    let failure_recall = store
        .recall_l0(&recall_request(project_id, "отказ синхронизации"))
        .await?;
    assert_eq!(
        failure_recall.handles[0].handle,
        format!("failure:{failure_id}")
    );
    let card_recall = store
        .recall_l0(&recall_request(project_id, "карточка модуля Юникод"))
        .await?;
    assert_eq!(card_recall.handles[0].handle, format!("card:{card_id}"));
    let capsule_recall = store
        .recall_l0(&recall_request(project_id, "капсула Юникод поиска"))
        .await?;
    assert_eq!(
        capsule_recall.handles[0].handle,
        format!("capsule:{capsule_id}")
    );

    let exact = store
        .recall_l0(&recall_request(project_id, format!("capsule:{capsule_id}")))
        .await?;
    assert_eq!(exact.handles[0].handle, format!("capsule:{capsule_id}"));
    assert_eq!(exact.rank_trace.feature_scores[0].exact_identifier, 1_000);

    let expanded = store
        .fetch_atoms_l2(&l2_request(
            project_id,
            vec![format!("card:{card_id}"), format!("capsule:{capsule_id}")],
        ))
        .await?;
    assert_eq!(expanded.ul_artifacts.len(), 2);
    assert_eq!(
        expanded.returned_handles,
        vec![format!("card:{card_id}"), format!("capsule:{capsule_id}")]
    );
    assert_eq!(expanded.ul_artifacts[0].record_type, "module_card");
    assert_eq!(expanded.ul_artifacts[1].record_type, "subsystem_capsule");
    assert!(expanded.tool_observations.is_empty());

    let unknown_card = format!("card:missing-{}", ClaimId::new_v7());
    let missing = store
        .fetch_atoms_l2(&l2_request(project_id, vec![unknown_card.clone()]))
        .await?;
    assert_eq!(missing.missing_handles, vec![unknown_card]);

    let other_project_id = ProjectId::new_v7();
    let foreign_claim = claim(
        "Русская память находит границу подсистемы".to_owned(),
        "граница подсистемы",
    );
    let foreign_claim_id = foreign_claim.claim_id;
    let foreign_card_id = format!("ul11r2-foreign-card-{}", ClaimId::new_v7());
    let mut foreign_envelope = retrieval_envelope(
        other_project_id,
        TaskId::new_v7(),
        vec![foreign_claim],
        Vec::new(),
        Vec::new(),
    )?;
    foreign_envelope.tool_observations = vec![ToolObservationInput {
        observation_id: foreign_card_id.clone(),
        tool_name: "ul_artifact_writer_actor".to_owned(),
        observation: "recorded module_card artifact".to_owned(),
        payload: json!({
            "receipt_kind": "module_card",
            "receipt_body": {
                "card_id": foreign_card_id,
                "project_id": other_project_id,
                "path": "src/библиотекарь.rs",
                "body_md": "Карточка модуля описывает Юникод поиск библиотекаря.",
                "source_refs": ["file:src/библиотекарь.rs"]
            }
        }),
    }];
    foreign_envelope.input_hash =
        blake3::hash(format!("{other_project_id}:{foreign_card_id}").as_bytes())
            .to_hex()
            .to_string();
    store.apply_write_envelope(&foreign_envelope).await?;

    let scoped = store
        .recall_l0(&recall_request(project_id, "русская граница подсистемы"))
        .await?;
    assert!(scoped.handles.iter().all(|handle| handle.handle
        != format!("claim:{foreign_claim_id}")
        && handle.handle != format!("card:{foreign_card_id}")));
    assert!((1..=256).contains(&scoped.rank_trace.candidates_considered));

    let absent = store
        .recall_l0(&recall_request(
            project_id,
            "квантовая телеметрия отсутствует",
        ))
        .await?;
    assert!(absent.handles.is_empty());
    assert!(absent.rank_trace.no_useful_memory);
    assert_eq!(absent.memory_confidence, MemoryConfidence::None);
    assert_eq!(absent.rank_trace.candidates_returned, 0);

    let store_source = include_str!("../src/canonical_store.rs");
    let query_source = include_str!("../src/surql/load_recall_candidates.surql");
    assert!(store_source.contains("eliot_types::normalize_query_tokens"));
    assert!(!query_source.contains("string::words"));
    assert!(!query_source.contains("string::slug"));
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
        let expected_handle = format!("claim:{expected_id}");
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
            "unicode_multi_kind_lifecycle_aware_v4"
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
