use eliot_engine::{MEMORY_DISTILLATION_RULESET_VERSION, MemoryDistillationService};
use eliot_types::{
    CanonicalMemoryUtilityLedger, ForgettingOperator, MemoryCompressionArtifact,
    MemoryDistillationAction, MemoryDistillationCorpusItem, MemoryDistillationFinding,
    MemoryDistillationInput, MemoryDistillationScheduleRequest, MemoryDistillationTrigger,
    MemoryLifecycleState, MemoryRevision, MemoryTier, MemoryUtilitySourceRecord, ProjectId,
};
use serde_json::json;

fn item(target_ref: impl Into<String>) -> MemoryDistillationCorpusItem {
    let target_ref = target_ref.into();
    MemoryDistillationCorpusItem {
        record_ref: format!("record:{target_ref}"),
        target_ref,
        record_kind: "claim_card".to_owned(),
        task_id: None,
        scope: "project:alpha".to_owned(),
        content_hash: String::new(),
        normalized_proposition: String::new(),
        mechanism: String::new(),
        applies_when: Vec::new(),
        does_not_apply_when: Vec::new(),
        counterexamples: Vec::new(),
        evidence_refs: vec!["receipt:verified".to_owned()],
        verifier_refs: vec!["verifier:test".to_owned()],
        lifecycle: MemoryLifecycleState::Active,
        status: "candidate".to_owned(),
        token_units: 64,
        current_truth: false,
        negative_memory: false,
        protected: false,
        superseded_by: None,
        exact_scope_contradiction: None,
        obsolete_replacement: None,
        certification_noise: false,
    }
}

fn empty_ledger(
    project_id: ProjectId,
    snapshot_revision: MemoryRevision,
    complete: bool,
) -> CanonicalMemoryUtilityLedger {
    CanonicalMemoryUtilityLedger {
        project_id,
        snapshot_revision,
        complete,
        source_record_count: 0,
        entries: Vec::new(),
    }
}

fn plan(
    project_id: ProjectId,
    snapshot_revision: MemoryRevision,
    complete: bool,
    items: Vec<MemoryDistillationCorpusItem>,
    utility_ledger: CanonicalMemoryUtilityLedger,
) -> Result<eliot_types::MemoryDistillationPlan, eliot_engine::EngineError> {
    MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision,
        ruleset_version: MEMORY_DISTILLATION_RULESET_VERSION.to_owned(),
        complete,
        items,
        utility_ledger,
    })
}

#[test]
fn utility_ledger_uses_canonical_signals_and_ignores_writer_score() {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(7);
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[MemoryUtilitySourceRecord {
            record_ref: "injection_receipt:1".to_owned(),
            record_kind: "injection_receipt".to_owned(),
            target_refs: vec!["claim:useful".to_owned()],
            evidence_ref: "receipt:1".to_owned(),
            payload: json!({
                "utility_score": 999_999,
                "estimated_tokens": 50_000,
                "false_activation": false
            }),
            memory_revision: Some(snapshot_revision),
            project_sequence: None,
            serialized_bytes: 1_500,
        }],
        true,
    );

    assert_eq!(ledger.source_record_count, 1);
    assert!(ledger.complete);
    let entry = &ledger.entries[0];
    assert_eq!(entry.target_ref, "claim:useful");
    assert_eq!(entry.beneficial_use_count, 2);
    assert_eq!(entry.context_cost_tokens, 0);
    assert_eq!(entry.false_activation_count, 0);
    assert_eq!(entry.maintenance_cost_units, 2);
    assert_eq!(entry.evidence_refs, ["receipt:1"]);
}

#[test]
fn exact_duplicate_is_the_only_automatic_merge_and_apply_is_reversible()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(8);
    let mut first = item("claim:a");
    first.content_hash = "same-content".to_owned();
    let mut second = item("claim:b");
    second.content_hash = "same-content".to_owned();
    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        vec![first, second],
        empty_ledger(project_id, snapshot_revision, true),
    )?;

    let candidate = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::ExactDuplicate)
        .ok_or("missing exact duplicate candidate")?;
    assert_eq!(candidate.proposed_action, MemoryDistillationAction::Archive);
    assert!(candidate.automatic_apply_allowed);
    assert!(candidate.reversible);
    assert_eq!(candidate.confidence, 100);

    let receipt = MemoryDistillationService::select_reversible_actions(
        &plan,
        std::slice::from_ref(&candidate.candidate_id),
    )?;
    assert_eq!(receipt.selected.len(), 1);
    assert_eq!(receipt.selected[0].operator, ForgettingOperator::Archive);
    assert!(!receipt.selected[0].restore_conditions.is_empty());
    assert!(receipt.rejected_candidate_ids.is_empty());
    Ok(())
}

#[test]
fn semantic_duplicates_and_near_misses_remain_candidate_only()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);
    let mut semantic_a = item("claim:semantic-a");
    semantic_a.normalized_proposition = "Use bounded replay".to_owned();
    semantic_a.mechanism = "receipt replay".to_owned();
    semantic_a.applies_when = vec!["same project".to_owned()];
    let mut semantic_b = item("claim:semantic-b");
    semantic_b.normalized_proposition = "use bounded replay".to_owned();
    semantic_b.mechanism = "receipt replay".to_owned();
    semantic_b.applies_when = vec!["same project".to_owned()];

    let mut near_a = item("claim:near-a");
    near_a.normalized_proposition = "Prefer cached context".to_owned();
    near_a.mechanism = "latency reduction".to_owned();
    near_a.applies_when = vec!["repository is unchanged".to_owned()];
    let mut near_b = item("claim:near-b");
    near_b.normalized_proposition = "Prefer cached context".to_owned();
    near_b.mechanism = "latency reduction".to_owned();
    near_b.applies_when = vec!["repository changed".to_owned()];
    near_b.counterexamples = vec!["stale graph".to_owned()];

    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        vec![semantic_a, semantic_b, near_a, near_b],
        empty_ledger(project_id, snapshot_revision, true),
    )?;

    let semantic = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::SemanticDuplicate)
        .ok_or("missing semantic duplicate candidate")?;
    assert_eq!(
        semantic.proposed_action,
        MemoryDistillationAction::Supersede
    );
    assert!(!semantic.automatic_apply_allowed);

    let near_miss = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::NearMiss)
        .ok_or("missing near-miss candidate")?;
    assert!(!near_miss.automatic_apply_allowed);
    assert_eq!(near_miss.counterevidence_refs, ["stale graph"]);
    assert!(
        plan.unresolved_items
            .iter()
            .any(|item| item.starts_with("near_miss_requires_bounded_reasoning:"))
    );
    Ok(())
}

#[test]
fn incomplete_large_projection_cannot_claim_or_apply_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(10);
    let mut items = (0..1_001)
        .map(|index| {
            let mut value = item(format!("claim:{index:04}"));
            value.content_hash = format!("hash:{index:04}");
            value
        })
        .collect::<Vec<_>>();
    items[999].content_hash = items[1_000].content_hash.clone();
    let plan = plan(
        project_id,
        snapshot_revision,
        false,
        items,
        empty_ledger(project_id, snapshot_revision, false),
    )?;

    assert_eq!(plan.corpus_profile_before.physical_records, 1_001);
    assert!(!plan.complete);
    assert!(
        plan.candidates
            .iter()
            .all(|candidate| !candidate.automatic_apply_allowed)
    );
    let exact = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::ExactDuplicate)
        .ok_or("missing exact duplicate candidate")?;
    let receipt = MemoryDistillationService::select_reversible_actions(
        &plan,
        std::slice::from_ref(&exact.candidate_id),
    )?;
    assert!(receipt.selected.is_empty());
    assert_eq!(
        receipt.rejected_candidate_ids.as_slice(),
        std::slice::from_ref(&exact.candidate_id)
    );
    Ok(())
}

#[test]
fn compression_must_preserve_boundaries_counterexamples_and_verifier() {
    let artifact = MemoryCompressionArtifact {
        compression_id: "compression:1".to_owned(),
        source_refs: vec!["episode:1".to_owned(), "episode:2".to_owned()],
        output_ref: "pattern:1".to_owned(),
        invariant_core: vec!["receipt replay".to_owned()],
        preserved_exact_atoms: vec!["unknown stays unknown".to_owned()],
        applicability_boundary: vec!["same project only".to_owned()],
        counterexamples: vec!["stale graph".to_owned()],
        required_probe: "run reconstruction replay".to_owned(),
        verifier_refs: vec!["verifier:replay".to_owned()],
        input_token_units: 900,
        output_token_units: 180,
        known_information_loss: Vec::new(),
        replay_requirement: "exact receipt reconstruction".to_owned(),
        candidate_only: true,
    };
    let protected = [
        "receipt replay".to_owned(),
        "unknown stays unknown".to_owned(),
        "same project only".to_owned(),
        "stale graph".to_owned(),
        "verifier:replay".to_owned(),
    ];
    assert!(MemoryDistillationService::validate_compression(&artifact, &protected).is_ok());

    let mut lossy = artifact;
    lossy.counterexamples.clear();
    assert!(MemoryDistillationService::validate_compression(&lossy, &protected).is_err());
}

#[test]
fn scheduler_pauses_for_interactive_load_and_tiers_are_explicit() {
    let project_id = ProjectId::new_v7();
    let paused = MemoryDistillationService::schedule(&MemoryDistillationScheduleRequest {
        project_id,
        trigger: MemoryDistillationTrigger::Nightly,
        new_evidence_count: 50,
        minimum_evidence_count: 10,
        interactive_load_active: true,
        cursor: Some("cursor:1000".to_owned()),
        batch_size: 100,
    });
    assert!(paused.paused);
    assert_eq!(paused.reason, "paused_under_interactive_load");
    assert_eq!(paused.cursor.as_deref(), Some("cursor:1000"));

    let ready = MemoryDistillationService::schedule(&MemoryDistillationScheduleRequest {
        interactive_load_active: false,
        ..MemoryDistillationScheduleRequest {
            project_id,
            trigger: MemoryDistillationTrigger::Manual,
            new_evidence_count: 50,
            minimum_evidence_count: 10,
            interactive_load_active: true,
            cursor: None,
            batch_size: 100,
        }
    });
    assert!(!ready.paused);
    assert_eq!(ready.reason, "bounded_distillation_ready");

    let mut cold = item("claim:cold");
    cold.evidence_refs.clear();
    assert_eq!(
        MemoryDistillationService::tier(&cold, None),
        MemoryTier::Cold
    );
    cold.lifecycle = MemoryLifecycleState::Archived;
    assert_eq!(
        MemoryDistillationService::tier(&cold, None),
        MemoryTier::ArchivedAudit
    );
    cold.lifecycle = MemoryLifecycleState::Suppressed;
    assert_eq!(
        MemoryDistillationService::tier(&cold, None),
        MemoryTier::SuppressedQuarantined
    );
}

#[test]
fn verified_episode_groups_only_propose_a_pattern() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(11);
    let mut first = item("episode:1");
    first.record_kind = "verified_episode".to_owned();
    first.mechanism = "same causal mechanism".to_owned();
    first.status = "verified".to_owned();
    let mut second = item("episode:2");
    second.record_kind = "experience_case".to_owned();
    second.mechanism = "same causal mechanism".to_owned();
    second.status = "verified".to_owned();
    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        vec![first, second],
        empty_ledger(project_id, snapshot_revision, true),
    )?;
    let pattern = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::CompressibleEpisodeGroup)
        .ok_or("missing pattern proposal")?;
    assert_eq!(
        pattern.proposed_action,
        MemoryDistillationAction::ProposePattern
    );
    assert!(!pattern.automatic_apply_allowed);
    Ok(())
}

#[test]
fn exact_distillation_reduces_active_bytes_without_losing_current_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(12);
    let mut items = (0..10)
        .map(|index| {
            let mut value = item(format!("claim:duplicate-{index}"));
            value.content_hash = "one-exact-body".to_owned();
            value.status = "supported".to_owned();
            value
        })
        .collect::<Vec<_>>();
    items[0].current_truth = true;
    items[0].protected = true;
    items[0].status = "verified".to_owned();
    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        items,
        empty_ledger(project_id, snapshot_revision, true),
    )?;

    let before = plan.corpus_profile_before.active_bytes;
    let after = i64::try_from(before)? + plan.expected_active_bytes_delta;
    assert!(before > 0);
    assert!(after >= 0);
    assert!(after * 100 <= i64::try_from(before)? * 60);
    assert_eq!(plan.expected_reconstruction_delta, 0);
    assert_eq!(plan.protected_refs, ["claim:duplicate-0"]);
    assert_eq!(
        plan.candidates
            .iter()
            .filter(|candidate| {
                candidate.finding == MemoryDistillationFinding::ExactDuplicate
                    && candidate.automatic_apply_allowed
            })
            .count(),
        9
    );
    Ok(())
}
