use eliot_engine::{
    ActivationProjection, CueIndexSnapshot, DEFAULT_PROJECT_SNAPSHOT_MAX_BYTES,
    DeliveredFingerprint, FreshArtifact, PacketUnderstandingRequest, PendingRestoreSource,
    ProjectProjectionFamily, ProjectProjectionHealth, ProjectRevisions, ProjectSnapshotBuilder,
    ProjectSnapshotInput, ProjectionFamilyHealth, RestoredSession, SnapshotFreshness,
    UnderstandingExecutionMode, UnderstandingRuntime, UnderstandingRuntimeConfig,
};
use eliot_types::{
    ActivationEdgeKind, CognitiveProjectionReadState, ConceptKind, ConceptNode, CoverageClass,
    CueBinding, CueKind, CueMatchMode, CueRecordSource, CueStrength, MemoryRevision, ObservedCue,
    ProjectId, SessionId, UlActivationGraphEdge, UlActivationGraphRows, UlInjectionMode,
    UlMetacognitionView,
};
use serde_json::json;

#[test]
fn direct_cues_fire_with_zero_activation_edges_and_without_io()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let source = negative_source("failure:borrow", "src/lib.rs");
    let snapshot = snapshot(project_id, vec![source])?;
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot)?;
    let session_id = SessionId::new_v7();
    let cues = vec![ObservedCue {
        kind: CueKind::FilePath,
        value: "src/lib.rs".to_owned(),
    }];

    runtime.record_observed_cues(project_id, session_id, &cues)?;
    let plan = runtime.plan_cues(project_id, session_id, None, &cues)?;

    assert_eq!(plan.direct_firing.fired.len(), 1);
    assert_eq!(plan.direct_firing.fired[0].record_ref, "failure:borrow");
    assert!(plan.activation_trace.is_none());
    runtime.enqueue_plan(project_id, session_id, &plan)?;
    let selected = runtime.select_pending(project_id, session_id, UlInjectionMode::Payload)?;
    assert_eq!(selected.items.len(), 1);
    assert_eq!(
        selected.items[0].payload,
        Some(json!({"avoid": "borrow across await"}))
    );
    Ok(())
}

#[test]
fn spread_stays_gated_below_five_hundred_edges_and_fires_at_the_threshold()
-> Result<(), Box<dyn std::error::Error>> {
    let records = vec![
        negative_source("failure:root", "src/root.rs"),
        concept_source("claim:target", "target"),
    ];
    let cues = [ObservedCue {
        kind: CueKind::FilePath,
        value: "src/root.rs".to_owned(),
    }];

    let below_project = ProjectId::new_v7();
    let below = UnderstandingRuntime::default();
    below.install_project(snapshot_with_graph(
        below_project,
        records.clone(),
        &activation_graph(499),
    )?)?;
    let below_plan = below.plan_cues(below_project, SessionId::new_v7(), None, &cues)?;
    assert!(below_plan.activation_trace.is_none());
    assert_eq!(below_plan.items.len(), 1);

    let threshold_project = ProjectId::new_v7();
    let threshold = UnderstandingRuntime::default();
    threshold.install_project(snapshot_with_graph(
        threshold_project,
        records,
        &activation_graph(500),
    )?)?;
    let threshold_plan =
        threshold.plan_cues(threshold_project, SessionId::new_v7(), None, &cues)?;
    assert_eq!(
        threshold_plan
            .activation_trace
            .as_ref()
            .map(|trace| trace.enabled_edge_count),
        Some(500)
    );
    assert!(
        threshold_plan
            .items
            .iter()
            .any(|item| item.item_ref == "claim:target")
    );
    Ok(())
}

#[test]
fn restore_not_durable_yet_rejects_fabricated_pending_and_atomically_restores_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let source = negative_source("failure:restore", "src/restore.rs");
    let snapshot = snapshot(project_id, vec![source.clone()])?;
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot)?;
    let plan = runtime.plan_cues(
        project_id,
        session_id,
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/restore.rs".to_owned(),
        }],
    )?;
    let fabricated = runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::NotDurableYet,
        touched_cues: Vec::new(),
        pending: plan.items.clone(),
        delivered: Vec::new(),
        active_concepts: Vec::new(),
        packet_revision: Some(MemoryRevision::new(7)),
        execution_mode: UnderstandingExecutionMode::Treatment,
        boot_sent: false,
    });
    assert!(fabricated.is_err());

    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::NotDurableYet,
        touched_cues: Vec::new(),
        pending: Vec::new(),
        delivered: vec![DeliveredFingerprint {
            item_ref: plan.items[0].item_ref.clone(),
            source_fingerprint: plan.items[0].source_fingerprint.clone(),
        }],
        active_concepts: Vec::new(),
        packet_revision: Some(MemoryRevision::new(7)),
        execution_mode: UnderstandingExecutionMode::Treatment,
        boot_sent: true,
    })?;

    let restored = runtime
        .session_snapshot(project_id, session_id)?
        .ok_or("session was not restored")?;
    assert_eq!(
        restored.execution_mode,
        UnderstandingExecutionMode::Treatment
    );
    assert_eq!(restored.packet_revision, Some(MemoryRevision::new(7)));
    assert_eq!(restored.restore_source, PendingRestoreSource::NotDurableYet);
    assert!(restored.pending.is_empty());
    assert_eq!(restored.delivered.len(), 1);
    assert!(restored.boot_sent);
    assert!(
        runtime
            .select_pending(project_id, session_id, UlInjectionMode::Payload)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn project_revisions_are_monotonic_and_staleness_is_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot(
        project_id,
        vec![negative_source("failure:revision", "src/revision.rs")],
    )?)?;
    let replay = snapshot(
        project_id,
        vec![negative_source("failure:revision", "src/revision.rs")],
    )?;
    assert!(runtime.install_project(replay).is_err());

    runtime.mark_project_stale(
        project_id,
        ProjectProjectionFamily::Cue,
        MemoryRevision::new(2),
        Some("coordinator target advanced".to_owned()),
    )?;
    let current = runtime
        .project_snapshot(project_id)?
        .ok_or("project snapshot missing")?;
    assert_eq!(
        current.health().cue.state,
        CognitiveProjectionReadState::Stale
    );
    assert_eq!(
        current.cue_projection().projection_state(),
        CognitiveProjectionReadState::Stale
    );
    let stale_plan = runtime.plan_cues(
        project_id,
        SessionId::new_v7(),
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/revision.rs".to_owned(),
        }],
    )?;
    assert!(stale_plan.items.is_empty());
    assert!(stale_plan.activation_trace.is_none());
    Ok(())
}

#[test]
fn equal_canonical_revision_can_only_recover_explicitly_stale_family_health()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot(project_id, Vec::new())?)?;
    runtime.mark_project_stale(
        project_id,
        ProjectProjectionFamily::Dependency,
        MemoryRevision::new(1),
        Some("same-head dirty projection".to_owned()),
    )?;

    let recovered = snapshot_with_health(
        project_id,
        Vec::new(),
        ProjectProjectionHealth {
            cue: published_health(1),
            pyramid: published_health(1),
            activation: published_health(1),
            dependency: published_health(1),
        },
        1,
    )?;
    runtime.install_project(recovered)?;
    assert!(
        runtime
            .project_snapshot(project_id)?
            .ok_or("recovered project snapshot missing")?
            .health()
            .dependency
            .state
            .is_published()
    );
    assert!(
        runtime
            .install_project(snapshot(project_id, Vec::new())?)
            .is_err()
    );
    Ok(())
}

#[test]
fn refreshed_snapshot_suppresses_obsolete_pending_fingerprint_and_allows_changed_memory()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let runtime = UnderstandingRuntime::default();
    let cues = [ObservedCue {
        kind: CueKind::FilePath,
        value: "src/changed.rs".to_owned(),
    }];
    runtime.install_project(snapshot_at_revision(
        project_id,
        vec![negative_source("failure:changed", "src/changed.rs")],
        1,
    )?)?;
    let first = runtime.plan_cues(project_id, session_id, None, &cues)?;
    let old_fingerprint = first.items[0].source_fingerprint.clone();
    runtime.enqueue_plan(project_id, session_id, &first)?;

    runtime.mark_project_stale(
        project_id,
        ProjectProjectionFamily::Cue,
        MemoryRevision::new(2),
        None,
    )?;
    let mut changed = negative_source("failure:changed", "src/changed.rs");
    changed.preview_text = "Changed canonical lesson".to_owned();
    changed.payload = Some(json!({"avoid": "changed lesson"}));
    runtime.install_project(snapshot_at_revision(project_id, vec![changed], 2)?)?;

    assert!(
        runtime
            .select_pending(project_id, session_id, UlInjectionMode::Payload)?
            .items
            .is_empty()
    );
    let second = runtime.plan_cues(project_id, session_id, None, &cues)?;
    assert_ne!(second.items[0].source_fingerprint, old_fingerprint);
    runtime.enqueue_plan(project_id, session_id, &second)?;
    assert_eq!(
        runtime
            .session_snapshot(project_id, session_id)?
            .ok_or("session disappeared after fingerprint replacement")?
            .pending
            .len(),
        1
    );
    let selected = runtime.select_pending(project_id, session_id, UlInjectionMode::Payload)?;
    assert_eq!(selected.items.len(), 1);
    assert_eq!(selected.items[0].preview, "Changed canonical lesson");
    Ok(())
}

#[test]
fn packet_metacognition_scopes_novelty_without_mutating_the_project_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let revision = MemoryRevision::new(1);
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        revision,
        CognitiveProjectionReadState::Published,
        &[],
    )?;
    let snapshot = ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(revision),
            cue: Some(revision),
            pyramid: Some(revision),
            activation: Some(revision),
            dependency: Some(revision),
        },
        health: ProjectProjectionHealth {
            cue: published_health(1),
            pyramid: published_health(1),
            activation: published_health(1),
            dependency: published_health(1),
        },
        cue_projection,
        records: Vec::new(),
        charter: None,
        system_map: None,
        concepts: vec![test_concept(project_id, "known", "src/known")],
        capsules: Vec::new(),
        cards: Vec::new(),
        activation_projection: ActivationProjection::default(),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    })?;

    let mixed = snapshot.plan_packet_understanding(&PacketUnderstandingRequest {
        task_id: "novelty-mixed".to_owned(),
        touched_paths: vec![
            "src/known/lib.rs".to_owned(),
            "src/novel/lib.rs".to_owned(),
            "src/novel/lib.rs".to_owned(),
        ],
        fallback_text: String::new(),
    });
    assert_eq!(mixed.meta.novelty_percent, 50);
    assert_eq!(mixed.meta.novel_paths, vec!["src/novel/lib.rs"]);
    assert_eq!(mixed.coverage, CoverageClass::Blind);

    let known_only = snapshot.plan_packet_understanding(&PacketUnderstandingRequest {
        task_id: "novelty-known".to_owned(),
        touched_paths: vec!["src/known/lib.rs".to_owned()],
        fallback_text: String::new(),
    });
    assert_eq!(known_only.meta.novelty_percent, 0);
    assert!(known_only.meta.novel_paths.is_empty());
    Ok(())
}

#[test]
fn rejected_mandatory_pending_overflow_preserves_the_existing_queue()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let runtime = UnderstandingRuntime::new(UnderstandingRuntimeConfig {
        max_pending_per_session: 1,
        ..UnderstandingRuntimeConfig::default()
    });
    runtime.install_project(snapshot(
        project_id,
        vec![
            negative_source("failure:first", "src/first.rs"),
            negative_source("failure:second", "src/second.rs"),
        ],
    )?)?;
    let first = runtime.plan_cues(
        project_id,
        session_id,
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/first.rs".to_owned(),
        }],
    )?;
    runtime.enqueue_plan(project_id, session_id, &first)?;
    let second = runtime.plan_cues(
        project_id,
        session_id,
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/second.rs".to_owned(),
        }],
    )?;

    assert!(
        runtime
            .enqueue_plan(project_id, session_id, &second)
            .is_err()
    );
    let restored = runtime
        .session_snapshot(project_id, session_id)?
        .ok_or("session disappeared after rejected pending overflow")?;
    assert_eq!(restored.pending.len(), 1);
    assert_eq!(restored.pending[0].item_ref, "failure:first");
    Ok(())
}

#[test]
fn delivered_receipt_horizon_above_legacy_cap_preserves_effects_once()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot(
        project_id,
        vec![negative_source("failure:0000", "src/dedup.rs")],
    )?)?;
    let source_fingerprint = runtime
        .project_snapshot(project_id)?
        .and_then(|snapshot| {
            snapshot
                .record("failure:0000")
                .map(|record| record.source_fingerprint.clone())
        })
        .ok_or("target compact record was not installed")?;
    let mut delivered = vec![DeliveredFingerprint {
        item_ref: "failure:0000".to_owned(),
        source_fingerprint,
    }];
    delivered.extend((1..1_500).map(|index| DeliveredFingerprint {
        item_ref: format!("zz:{index:04}"),
        source_fingerprint: format!("fingerprint-{index:04}"),
    }));
    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::NotDurableYet,
        touched_cues: Vec::new(),
        pending: Vec::new(),
        delivered,
        active_concepts: Vec::new(),
        packet_revision: None,
        execution_mode: UnderstandingExecutionMode::Production,
        boot_sent: false,
    })?;
    let plan = runtime.plan_cues(
        project_id,
        session_id,
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/dedup.rs".to_owned(),
        }],
    )?;
    runtime.enqueue_plan(project_id, session_id, &plan)?;

    assert!(
        runtime
            .select_pending(project_id, session_id, UlInjectionMode::Payload)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn observed_packet_revision_updates_the_session_mirror() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = UnderstandingRuntime::default();
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();

    runtime.observe_result(
        project_id,
        session_id,
        "eliot_compile_packet_l3",
        &json!({"packet_id": "packet:revision", "at_revision": 9}),
    )?;

    assert_eq!(
        runtime
            .session_snapshot(project_id, session_id)?
            .ok_or("packet observation did not create the session mirror")?
            .packet_revision,
        Some(MemoryRevision::new(9))
    );
    Ok(())
}

#[test]
fn snapshot_budget_elides_only_optional_payloads_and_preserves_handles_and_fingerprints()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(DEFAULT_PROJECT_SNAPSHOT_MAX_BYTES, 64 * 1024 * 1024);
    let project_id = ProjectId::new_v7();
    let revision = MemoryRevision::new(1);
    let mut optional = concept_source("claim:large", "large");
    optional.payload = Some(json!({"body": "x".repeat(256 * 1024)}));
    let optional_fingerprint = blake3::hash(&serde_json::to_vec(&optional)?)
        .to_hex()
        .to_string();
    let negative = negative_source("failure:mandatory", "src/mandatory.rs");
    let mut invariant = concept_source("invariant:mandatory", "invariant");
    invariant.record_kind = "invariant".to_owned();
    invariant.payload = Some(json!({"rule": "preserve every invariant payload"}));
    let records = vec![optional, negative, invariant];
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        revision,
        CognitiveProjectionReadState::Published,
        &records,
    )?;
    let snapshot = ProjectSnapshotBuilder {
        max_bytes: 64 * 1024,
        ..ProjectSnapshotBuilder::default()
    }
    .build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(revision),
            cue: Some(revision),
            pyramid: Some(revision),
            activation: Some(revision),
            dependency: Some(revision),
        },
        health: ProjectProjectionHealth {
            cue: published_health(1),
            pyramid: published_health(1),
            activation: published_health(1),
            dependency: published_health(1),
        },
        cue_projection,
        records,
        charter: None,
        system_map: None,
        concepts: Vec::new(),
        capsules: Vec::new(),
        cards: Vec::new(),
        activation_projection: ActivationProjection::default(),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    })?;

    assert_eq!(snapshot.record_handles().count(), 3);
    assert!(snapshot.estimated_bytes() <= 64 * 1024);
    let optional = snapshot
        .record("claim:large")
        .ok_or("optional handle lost")?;
    assert!(optional.payload.is_none());
    assert_eq!(optional.source_fingerprint, optional_fingerprint);
    assert!(
        snapshot
            .record("failure:mandatory")
            .and_then(|record| record.payload.as_ref())
            .is_some()
    );
    assert!(
        snapshot
            .record("invariant:mandatory")
            .and_then(|record| record.payload.as_ref())
            .is_some()
    );
    Ok(())
}

#[test]
fn mandatory_hot_minimum_rejects_one_byte_below_without_dropping_durable_knowledge()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let revision = MemoryRevision::new(1);
    let records = vec![negative_source("failure:minimum", "src/minimum.rs")];
    let admitted = snapshot_at_revision(project_id, records.clone(), 1)?;
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        revision,
        CognitiveProjectionReadState::Published,
        &records,
    )?;
    let result = ProjectSnapshotBuilder {
        max_bytes: admitted.estimated_bytes().saturating_sub(1),
        ..ProjectSnapshotBuilder::default()
    }
    .build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(revision),
            cue: Some(revision),
            pyramid: Some(revision),
            activation: Some(revision),
            dependency: Some(revision),
        },
        health: ProjectProjectionHealth {
            cue: published_health(1),
            pyramid: published_health(1),
            activation: published_health(1),
            dependency: published_health(1),
        },
        cue_projection,
        records,
        charter: None,
        system_map: None,
        concepts: Vec::new(),
        capsules: Vec::new(),
        cards: Vec::new(),
        activation_projection: ActivationProjection::default(),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    });

    let Err(error) = result else {
        return Err("mandatory minimum unexpectedly fit below its exact charge".into());
    };
    assert!(
        error
            .to_string()
            .contains("no handles or mandatory payloads were dropped")
    );
    Ok(())
}

#[test]
fn durable_restore_filters_exact_delivered_pairs_before_pending_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let runtime = UnderstandingRuntime::default();
    let delivered = eliot_types::PendingInjectionItem {
        item_ref: "failure:delivered".to_owned(),
        record_kind: "failure_fingerprint".to_owned(),
        preview: "already delivered".to_owned(),
        payload: Some(json!({"rule": "once"})),
        source_fingerprint: "fingerprint-delivered".to_owned(),
        fired_cues: Vec::new(),
        negative_memory: true,
        invariant: false,
        token_estimate: 4,
        activation_trace_ref: None,
        activation_score_milli: None,
    };
    let mut remaining = delivered.clone();
    remaining.item_ref = "failure:remaining".to_owned();
    remaining.source_fingerprint = "fingerprint-remaining".to_owned();

    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::PendingInjectionAndReceipts,
        touched_cues: Vec::new(),
        pending: vec![delivered.clone(), remaining.clone()],
        delivered: vec![DeliveredFingerprint {
            item_ref: delivered.item_ref,
            source_fingerprint: delivered.source_fingerprint,
        }],
        active_concepts: Vec::new(),
        packet_revision: None,
        execution_mode: UnderstandingExecutionMode::Production,
        boot_sent: false,
    })?;

    let restored = runtime
        .session_snapshot(project_id, session_id)?
        .ok_or("durable session was not restored")?;
    assert_eq!(restored.pending.len(), 1);
    assert_eq!(restored.pending[0].item_ref, remaining.item_ref);
    Ok(())
}

#[test]
fn evicted_session_rehydrates_durable_pending_and_receipt_dedup_exactly_once()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let evicting_session = SessionId::new_v7();
    let runtime = UnderstandingRuntime::new(UnderstandingRuntimeConfig {
        max_sessions: 1,
        ..UnderstandingRuntimeConfig::default()
    });
    runtime.install_project(snapshot(
        project_id,
        vec![negative_source("failure:eviction", "src/eviction.rs")],
    )?)?;
    let plan = runtime.plan_cues(
        project_id,
        session_id,
        None,
        &[ObservedCue {
            kind: CueKind::FilePath,
            value: "src/eviction.rs".to_owned(),
        }],
    )?;
    let pending = plan.items.clone();
    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::PendingInjectionAndReceipts,
        touched_cues: Vec::new(),
        pending: pending.clone(),
        delivered: Vec::new(),
        active_concepts: Vec::new(),
        packet_revision: None,
        execution_mode: UnderstandingExecutionMode::Production,
        boot_sent: false,
    })?;
    runtime.observe_arguments(
        project_id,
        evicting_session,
        "eliot_current_state",
        &json!({}),
    )?;
    assert!(runtime.session_snapshot(project_id, session_id)?.is_none());

    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::PendingInjectionAndReceipts,
        touched_cues: Vec::new(),
        pending: pending.clone(),
        delivered: Vec::new(),
        active_concepts: Vec::new(),
        packet_revision: None,
        execution_mode: UnderstandingExecutionMode::Production,
        boot_sent: false,
    })?;
    let selected = runtime.select_pending(project_id, session_id, UlInjectionMode::Payload)?;
    assert_eq!(selected.items.len(), 1);
    let delivered = DeliveredFingerprint {
        item_ref: pending[0].item_ref.clone(),
        source_fingerprint: pending[0].source_fingerprint.clone(),
    };
    runtime.acknowledge_delivered(project_id, session_id, std::slice::from_ref(&delivered))?;
    runtime.observe_arguments(
        project_id,
        evicting_session,
        "eliot_current_state",
        &json!({}),
    )?;
    runtime.restore_session(RestoredSession {
        project_id,
        session_id,
        source: PendingRestoreSource::PendingInjectionAndReceipts,
        touched_cues: Vec::new(),
        pending,
        delivered: vec![delivered],
        active_concepts: Vec::new(),
        packet_revision: None,
        execution_mode: UnderstandingExecutionMode::Production,
        boot_sent: false,
    })?;
    assert!(
        runtime
            .select_pending(project_id, session_id, UlInjectionMode::Payload)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn snapshot_rejects_missing_mandatory_payload_without_dropping_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let mut source = negative_source("failure:missing", "src/missing.rs");
    source.payload = None;
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        MemoryRevision::new(1),
        CognitiveProjectionReadState::Published,
        &[source.clone()],
    )?;
    let result = ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            cue: Some(MemoryRevision::new(1)),
            ..ProjectRevisions::default()
        },
        health: ProjectProjectionHealth {
            cue: published_health(1),
            ..ProjectProjectionHealth::default()
        },
        cue_projection,
        records: vec![source],
        charter: None,
        system_map: None,
        concepts: Vec::new(),
        capsules: Vec::<FreshArtifact<_>>::new(),
        cards: Vec::<FreshArtifact<_>>::new(),
        activation_projection: ActivationProjection::from_graph(&UlActivationGraphRows::default()),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    });
    let Err(error) = result else {
        return Err("mandatory negative payload was accepted".into());
    };
    assert!(error.to_string().contains("failure:missing"));
    Ok(())
}

fn published_health(revision: u64) -> ProjectionFamilyHealth {
    ProjectionFamilyHealth {
        state: CognitiveProjectionReadState::Published,
        revision: Some(MemoryRevision::new(revision)),
        detail: None,
    }
}

fn snapshot(
    project_id: ProjectId,
    records: Vec<CueRecordSource>,
) -> Result<eliot_engine::ProjectSnapshot, eliot_engine::EngineError> {
    snapshot_at_revision(project_id, records, 1)
}

fn snapshot_at_revision(
    project_id: ProjectId,
    records: Vec<CueRecordSource>,
    revision: u64,
) -> Result<eliot_engine::ProjectSnapshot, eliot_engine::EngineError> {
    snapshot_with_health(
        project_id,
        records,
        ProjectProjectionHealth {
            cue: published_health(revision),
            pyramid: published_health(revision),
            activation: published_health(revision),
            dependency: published_health(revision),
        },
        revision,
    )
}

fn snapshot_with_health(
    project_id: ProjectId,
    records: Vec<CueRecordSource>,
    health: ProjectProjectionHealth,
    revision: u64,
) -> Result<eliot_engine::ProjectSnapshot, eliot_engine::EngineError> {
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        MemoryRevision::new(revision),
        CognitiveProjectionReadState::Published,
        &records,
    )?;
    ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(MemoryRevision::new(revision)),
            cue: Some(MemoryRevision::new(revision)),
            pyramid: Some(MemoryRevision::new(revision)),
            activation: Some(MemoryRevision::new(revision)),
            dependency: Some(MemoryRevision::new(revision)),
        },
        health,
        cue_projection,
        records,
        charter: None,
        system_map: None,
        concepts: Vec::new(),
        capsules: Vec::new(),
        cards: Vec::new(),
        activation_projection: ActivationProjection::default(),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    })
}

fn snapshot_with_graph(
    project_id: ProjectId,
    records: Vec<CueRecordSource>,
    graph: &UlActivationGraphRows,
) -> Result<eliot_engine::ProjectSnapshot, eliot_engine::EngineError> {
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        MemoryRevision::new(1),
        CognitiveProjectionReadState::Published,
        &records,
    )?;
    ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(MemoryRevision::new(1)),
            cue: Some(MemoryRevision::new(1)),
            pyramid: Some(MemoryRevision::new(1)),
            activation: Some(MemoryRevision::new(1)),
            dependency: Some(MemoryRevision::new(1)),
        },
        health: ProjectProjectionHealth {
            cue: published_health(1),
            pyramid: published_health(1),
            activation: published_health(1),
            dependency: published_health(1),
        },
        cue_projection,
        records,
        charter: None,
        system_map: None,
        concepts: Vec::new(),
        capsules: Vec::new(),
        cards: Vec::new(),
        activation_projection: ActivationProjection::from_graph(graph),
        dirty: Vec::new(),
        dependencies: Vec::new(),
        metacognition: empty_meta(),
    })
}

fn activation_graph(edge_count: usize) -> UlActivationGraphRows {
    let relations = (0..edge_count)
        .map(|index| {
            let (from_ref, to_ref) = if index == 0 {
                ("failure:root".to_owned(), "concept:target".to_owned())
            } else {
                (format!("noise:{index}"), format!("noise-next:{index}"))
            };
            UlActivationGraphEdge {
                from_ref,
                to_ref,
                kind: ActivationEdgeKind::Supports,
            }
        })
        .collect();
    UlActivationGraphRows {
        co_change: Vec::new(),
        relations,
    }
}

fn negative_source(record_ref: &str, path: &str) -> CueRecordSource {
    CueRecordSource {
        record_ref: record_ref.to_owned(),
        record_kind: "failure_fingerprint".to_owned(),
        preview_text: "Do not hold this borrow across await".to_owned(),
        payload: Some(json!({"avoid": "borrow across await"})),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: path.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "same source path".to_owned(),
        }],
        negative_memory: true,
        lifecycle: "active".to_owned(),
    }
}

fn concept_source(record_ref: &str, concept: &str) -> CueRecordSource {
    CueRecordSource {
        record_ref: record_ref.to_owned(),
        record_kind: "claim".to_owned(),
        preview_text: "Target concept claim".to_owned(),
        payload: Some(json!({"claim": "target"})),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::Concept,
            cue_value: concept.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "activation target".to_owned(),
        }],
        negative_memory: false,
        lifecycle: "active".to_owned(),
    }
}

fn test_concept(project_id: ProjectId, concept_id: &str, boundary: &str) -> ConceptNode {
    ConceptNode {
        concept_id: concept_id.to_owned(),
        project_id,
        name: concept_id.to_owned(),
        kind: ConceptKind::Subsystem,
        purpose: format!("Owns {concept_id}."),
        boundary_paths: vec![boundary.to_owned()],
        invariant_refs: Vec::new(),
        hotspot_refs: Vec::new(),
        entrypoint_refs: Vec::new(),
        parent_concept_id: None,
        cue_bindings: Vec::new(),
        source_refs: Vec::new(),
    }
}

fn empty_meta() -> UlMetacognitionView {
    UlMetacognitionView {
        policy_version: "test".to_owned(),
        coverage: Vec::new(),
        novelty_percent: 0,
        novel_paths: Vec::new(),
        danger_paths: Vec::new(),
    }
}

#[allow(dead_code)]
fn _fresh<T>(artifact: T) -> FreshArtifact<T> {
    FreshArtifact {
        artifact,
        freshness: SnapshotFreshness::Fresh,
    }
}
