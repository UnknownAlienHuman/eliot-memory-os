use eliot_context_contracts::ContextError;
use eliot_engine::{EngineError, MEMORY_DISTILLATION_RULESET_VERSION, MemoryDistillationService};
use eliot_types::{
    CanonicalMemoryUtilityLedger, ForgettingOperator, MemoryCompressionArtifact,
    MemoryDistillationAction, MemoryDistillationCorpusItem, MemoryDistillationFinding,
    MemoryDistillationInput, MemoryDistillationScheduleRequest, MemoryDistillationTrigger,
    MemoryLifecycleState, MemoryRevision, MemoryTier, MemoryUtilityLedgerEntry,
    MemoryUtilitySourceRecord, ProjectId,
};
use serde_json::{Value, json};

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

/// A ledger whose single entry has an explicit Context cost and NO beneficial use.
///
/// The `HighCostLowValue` arm requires `beneficial_use_count == 0`
/// (`memory_distillation.rs:741`), and `derive_utility_ledger` cannot produce
/// that for a Context-cost record: `utility_signals` pushes `PacketInclusion`
/// alongside `ContextTokenCost` for every `context_packet` kind
/// (`memory_distillation.rs:492-495`), and `PacketInclusion` counts as a
/// beneficial use. `plan` takes the ledger from its caller, so the two tests
/// that need the arm to actually fire build the entry directly. This mirrors
/// the real route too: `CanonicalMemoryUtilityLedger` is a deserializable wire
/// type, so a ledger arriving over the wire is exactly this shape.
fn ledger_with_cost(
    project_id: ProjectId,
    snapshot_revision: MemoryRevision,
    target_ref: &str,
    context_cost_tokens: u64,
) -> CanonicalMemoryUtilityLedger {
    CanonicalMemoryUtilityLedger {
        project_id,
        snapshot_revision,
        complete: true,
        source_record_count: 1,
        entries: vec![MemoryUtilityLedgerEntry {
            target_ref: target_ref.to_owned(),
            context_cost_tokens,
            evidence_refs: vec!["receipt:context".to_owned()],
            ..MemoryUtilityLedgerEntry::default()
        }],
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
fn utility_ledger_uses_canonical_signals_and_ignores_writer_score()
-> Result<(), Box<dyn std::error::Error>> {
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
    )?;

    assert_eq!(ledger.source_record_count, 1);
    assert!(ledger.complete);
    let entry = &ledger.entries[0];
    assert_eq!(entry.target_ref, "claim:useful");
    assert_eq!(entry.beneficial_use_count, 2);
    assert_eq!(entry.context_cost_tokens, 0);
    assert_eq!(entry.false_activation_count, 0);
    assert_eq!(entry.maintenance_cost_units, 2);
    assert_eq!(entry.evidence_refs, ["receipt:1"]);
    Ok(())
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
fn exact_distillation_reduces_the_covering_active_estimate_without_losing_current_truth()
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

    let before = plan.corpus_profile_before.estimated_covering_active_bytes;
    let after = i64::try_from(before)? + plan.expected_estimated_covering_active_bytes_delta;
    assert!(before > 0);
    assert!(after >= 0);
    assert!(after * 100 <= i64::try_from(before)? * 60);
    // The figures above are a covering ESTIMATE over `token_units`, not
    // observed storage bytes, so the field NAME is part of what this test pins:
    // ten items of 64 units cover 10 * bytes_for_stu(64) == 1920, which is the
    // whole-multiple covering length and NOT the smallest covering length 190
    // per item, and never an observed byte count.
    assert_eq!(
        plan.corpus_profile_before.estimated_covering_total_bytes,
        1_920
    );
    assert_eq!(
        plan.corpus_profile_before.estimated_covering_active_bytes,
        1_920
    );
    assert_eq!(
        plan.expected_estimated_covering_active_bytes_delta,
        -9 * 192
    );

    // Serialised-plan pinning: the honest keys must appear on the wire and the
    // misnamed byte keys must not. A ratio-only assertion stays green under any
    // renaming and under either bytes-per-unit ratio, so it could never catch
    // this defect class; these assertions fail if the rename is reverted.
    let encoded = serde_json::to_value(&plan)?;
    // `estimated_covering_*` fields live inside `corpus_profile_before`; the
    // delta lives at the top level of the plan.
    let profile = &encoded["corpus_profile_before"];
    for key in [
        "estimated_covering_total_bytes",
        "estimated_covering_active_bytes",
    ] {
        assert!(
            profile.get(key).is_some(),
            "missing honest covering-estimate key {key} in the serialised plan"
        );
    }
    assert_eq!(
        encoded.get("expected_estimated_covering_active_bytes_delta"),
        Some(&json!(-9 * 192)),
        "the serialised plan must publish the covering ESTIMATE delta under its honest name"
    );
    assert!(
        profile.get("total_bytes").is_none() && profile.get("active_bytes").is_none(),
        "the serialised plan still advertises observed-byte keys it cannot honour"
    );
    assert!(
        encoded.get("expected_active_bytes_delta").is_none(),
        "the serialised plan still advertises the misnamed byte delta"
    );

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

/// A well-formed `eliot-context-cost/v1` measurement payload carrying a
/// CONSERVATIVE STU estimate.
///
/// This is the unvalidated form: `measurement_status` is the owner's
/// `MeasurementStatus::ConservativeStu` under its `SCREAMING_SNAKE_CASE`
/// spelling (it is `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`,
/// `crates/smart/eliot-context-contracts/src/measurement.rs:10-18`), `actual_tokens`
/// is explicitly `null` because an actual-token count needs its own
/// route/model/tokenizer binding over these bytes, and `stu_estimate` is exactly
/// the owner's `StuEstimate` member set (`value`, `empirical`,
/// `crates/smart/eliot-context-contracts/src/measurement.rs:96-99`).
///
/// HONEST NOTE ON THE PRODUCER: no in-repo producer emits this object. The only
/// in-repo memory measurement wire form is `measurement_wire` at
/// `crates/eliot-app/src/mcp_stdio.rs:371-377`, which emits
/// `{unit, status, actual_tokens: null}` and no `adapter_revision`,
/// `serializer_id` or `stu_estimate`. So this fixture is the contract's own
/// admissible form, not a transcription of something an existing producer
/// writes today. That gap predates this change (the five probes it replaces
/// required the same keys) and emitting the contract is an `eliot-app` owner
/// change outside this work unit; see the corrected-evidence note in
/// `crates/eliot-engine/src/context_cost_measurement.rs`.
fn context_cost_record(stu: u64) -> MemoryUtilitySourceRecord {
    MemoryUtilitySourceRecord {
        record_ref: "context_packet:1".to_owned(),
        record_kind: "context_packet".to_owned(),
        target_refs: vec!["claim:measured".to_owned()],
        evidence_ref: "receipt:context".to_owned(),
        payload: json!({
            "measurement": {
                "adapter_revision": "eliot-context-cost/v1",
                "serializer_id": "serde_json",
                "measurement_status": "CONSERVATIVE_STU",
                "actual_tokens": Value::Null,
                "stu_estimate": {
                    "value": stu,
                    "empirical": false,
                },
            },
        }),
        memory_revision: None,
        project_sequence: None,
        serialized_bytes: 190,
    }
}

/// A bound measurement payload: the owner's `MeasurementStatus::ExactTokenizer`
/// with a real observed `actual_tokens` count.
///
/// This is the only form that is a capacity-deciding observation, and it is the
/// only form `apply_utility_signal` admits into `context_cost_tokens`. The
/// `stu_estimate` beside it is deliberately far larger than the observed count so
/// a test can prove the admitted figure is the TOKENIZER count and not the STU
/// beside it - the two-unit confusion the audit named.
fn bound_context_cost_record(actual_tokens: u64, stu: u64) -> MemoryUtilitySourceRecord {
    MemoryUtilitySourceRecord {
        record_ref: "context_packet:bound".to_owned(),
        record_kind: "context_packet".to_owned(),
        target_refs: vec!["claim:measured".to_owned()],
        evidence_ref: "receipt:bound".to_owned(),
        payload: json!({
            "measurement": {
                "adapter_revision": "eliot-context-cost/v1",
                "serializer_id": "serde_json",
                "measurement_status": "EXACT_TOKENIZER",
                "actual_tokens": actual_tokens,
                "stu_estimate": {
                    "value": stu,
                    "empirical": false,
                },
            },
        }),
        memory_revision: None,
        project_sequence: None,
        serialized_bytes: 190,
    }
}

#[test]
fn closed_context_cost_adapter_admits_a_well_formed_bound_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[
            bound_context_cost_record(64, 900),
            bound_context_cost_record(24, 900),
            MemoryUtilitySourceRecord {
                record_ref: "injection_receipt:1".to_owned(),
                record_kind: "injection_receipt".to_owned(),
                target_refs: vec!["claim:measured".to_owned()],
                evidence_ref: "receipt:other".to_owned(),
                payload: json!({}),
                memory_revision: None,
                project_sequence: None,
                serialized_bytes: 1_500,
            },
        ],
        true,
    )?;

    let entry = ledger
        .entries
        .iter()
        .find(|entry| entry.target_ref == "claim:measured")
        .expect("the measured target must have a ledger entry");
    // 64 + 24 = 88 OBSERVED TOKENS. The admitted figure is the tokenizer count,
    // not the 900-unit STU carried beside it in each payload: 88, not 1_800 and
    // not 1_764. That distinction is the unit honesty the audit's repair 5
    // demands, and it is why the fixtures pass a distinct STU per record.
    assert_eq!(entry.context_cost_tokens, 88);
    // 190 bytes over two context-packet records plus 1_500 over the injection
    // receipt, each rounded up to whole KiB and kept in its own storage unit.
    assert_eq!(entry.maintenance_cost_units, 2);
    assert_eq!(
        entry.evidence_refs,
        ["receipt:bound", "receipt:other"],
        "evidence refs stay sorted and deduplicated"
    );
    Ok(())
}

/// The closed-schema limb: a payload carrying an extra, mutated or unexpected
/// fragment is refused instead of admitted on the strength of the few fragments
/// the old probes looked for.
///
/// Every assertion is on a real `derive_utility_ledger` return value, so a
/// source-text change cannot make this green. The mutated-`value` case is the
/// audit's exact counterexample: a forged STU carried beside unrelated and
/// mutated bytes used to be accepted.
#[test]
fn closed_context_cost_adapter_refuses_unknown_and_malformed_fragments()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);
    // Five admitted OBSERVED TOKENS on the same target: anything that leaks in
    // from a refused payload has to move this number off 5.
    let records = [
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:0".to_owned(),
            record_kind: "injection_receipt".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:0".to_owned(),
            payload: json!({}),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        bound_context_cost_record(5, 900),
        // An unknown sibling fragment on the measurement object. The old
        // `adapter_revision`/`serializer_id`/`measurement_status`/
        // `actual_tokens`/`stu_estimate.value` probes never looked at this key,
        // so this payload was admitted before and is refused now.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:unknown".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:unknown".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "EXACT_TOKENIZER",
                    "actual_tokens": 9_000,
                    "stu_estimate": { "value": 9_000, "empirical": false },
                    "total_bytes": 190,
                    "content_digest": "0000000000000000000000000000000000000000000000000000000000000000",
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        // A forged STU carried beside an unreviewed sibling inside the estimate
        // object itself. `stu_estimate.value` alone used to be read.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:stu_sibling".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:stu-sibling".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "EXACT_TOKENIZER",
                    "actual_tokens": 9_000,
                    "stu_estimate": { "value": 9_000, "estimator_id": "forged" },
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        // A conservative-STU payload that also claims a non-null actual-token
        // count with no route/model/tokenizer binding behind it.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:actual".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:actual".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "CONSERVATIVE_STU",
                    "actual_tokens": 9_000,
                    "stu_estimate": { "value": 9_000, "empirical": false },
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        // The legacy bare integer and the pre-existing lowercase status spelling.
        // Neither is decoded as a current measurement.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:legacy".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:legacy".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "exact_tokenizer",
                    "actual_tokens": 9_000,
                    "stu_estimate": { "value": 9_000, "empirical": false },
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:bare".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:bare".to_owned(),
            payload: json!({ "estimated_tokens": 9_000 }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
    ];
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &records,
        true,
    )?;

    let entry = &ledger.entries[0];
    assert_eq!(
        entry.context_cost_tokens, 5,
        "only the one well-formed bound payload may contribute; every refused \
         fragment above must leave the total at the single admitted 5 tokens"
    );
    Ok(())
}

/// A required measurement fragment that is missing is refused as unknown
/// evidence, NOT admitted as zero.
///
/// `actual_tokens` is the sharpest case: it is required by the closed schema in
/// both admitted forms, so omission is a deserialization error rather than an
/// absent-optional. Omitting `value` from the STU object is refused for the same
/// reason. Neither may read as a cheap zero, and neither may let a refused
/// payload's number leak into the scalar the demotion threshold reads.
#[test]
fn closed_context_cost_adapter_refuses_a_missing_required_fragment()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);
    let records = [
        MemoryUtilitySourceRecord {
            record_ref: "injection_receipt:0".to_owned(),
            record_kind: "injection_receipt".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:0".to_owned(),
            payload: json!({}),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        bound_context_cost_record(5, 900),
        // `actual_tokens` omitted entirely rather than explicitly null.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:no_actual".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:no-actual".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "CONSERVATIVE_STU",
                    "stu_estimate": { "value": 9_000, "empirical": false },
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        // The required `value` member missing from the STU object.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:no_value".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:no-value".to_owned(),
            payload: json!({
                "measurement": {
                    "adapter_revision": "eliot-context-cost/v1",
                    "serializer_id": "serde_json",
                    "measurement_status": "CONSERVATIVE_STU",
                    "actual_tokens": Value::Null,
                    "stu_estimate": { "empirical": false },
                },
            }),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
        // The whole measurement object absent.
        MemoryUtilitySourceRecord {
            record_ref: "context_packet:no_measurement".to_owned(),
            record_kind: "context_packet".to_owned(),
            target_refs: vec!["claim:measured".to_owned()],
            evidence_ref: "receipt:no-measurement".to_owned(),
            payload: json!({}),
            memory_revision: None,
            project_sequence: None,
            serialized_bytes: 0,
        },
    ];
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &records,
        true,
    )?;

    assert_eq!(
        ledger.entries[0].context_cost_tokens, 5,
        "a missing required fragment must stay unknown evidence, never a zero \
         that would read as a cheap memory"
    );
    Ok(())
}

/// An addition that would overflow is a typed error, not `u64::MAX`.
///
/// The admitted observation is a real `u64` a payload can name, so `u64::MAX`
/// plus one more measured unit is reachable through the ordinary public entry
/// point. The old `saturating_add` returned `u64::MAX` here, which is exactly the
/// figure `deterministic_item_finding` reads as `context_cost_tokens > 512` when
/// it proposes `MemoryDistillationAction::Demote` - so an arithmetic overflow
/// could become a lifecycle action. It is now the typed
/// `EngineError::ContextMeasurement(ContextError::Overflow)` refusal that this
/// file's byte path already returns, propagated out of `derive_utility_ledger`.
#[test]
fn context_cost_accumulation_overflow_is_a_typed_error_not_u64_max()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);

    // Exactly at the boundary: `u64::MAX` alone is representable and admitted.
    let at_limit = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[bound_context_cost_record(u64::MAX, 900)],
        true,
    )?;
    assert_eq!(at_limit.entries[0].context_cost_tokens, u64::MAX);

    // One more measured unit past the boundary is the typed refusal.
    let overflowed = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[
            bound_context_cost_record(u64::MAX, 900),
            bound_context_cost_record(1, 900),
            bound_context_cost_record(1, 900),
        ],
        true,
    );
    let error = overflowed
        .expect_err("an overflowing measured accumulation must be refused, not saturated");
    assert_eq!(
        error,
        EngineError::ContextMeasurement(ContextError::Overflow),
        "the refusal must be the typed measurement overflow, not a saturated value"
    );

    // The saturated figure this used to produce is the one the demotion
    // threshold fires on. Pin that a refused ledger yields no plan at all, so
    // the overflow cannot reach `deterministic_item_finding` as a cost.
    let refused = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[
            bound_context_cost_record(u64::MAX, 900),
            bound_context_cost_record(1, 900),
        ],
        true,
    )
    .err()
    .expect("the second ledger must also refuse");
    assert_eq!(
        refused,
        EngineError::ContextMeasurement(ContextError::Overflow)
    );
    Ok(())
}

/// AUD4 repair 5, negative limb: a `stu_estimate` that alone crosses `512` does
/// NOT reach `Demote`.
///
/// This is the audit's exact counterexample. `stu_estimate.value = 9_000` is a
/// self-reported number with no binding to bytes, content, digest or identity,
/// and the audit states it "is admitted, exceeds 512, and reaches `Demote`".
/// Before the fix, `derive_utility_ledger` wrote that STU straight into
/// `context_cost_tokens`, so `deterministic_item_finding`'s
/// `entry.context_cost_tokens > 512` arm saw a scalar above the threshold with
/// no beneficial use and returned `MemoryDistillationFinding::HighCostLowValue`
/// with `MemoryDistillationAction::Demote`.
///
/// Two steps, both pinned:
/// 1. `derive_utility_ledger` must NOT admit the STU into the scalar at all, so
///    the threshold has nothing unbound to read.
/// 2. Even when a ledger DOES carry a cost above 512 with no beneficial use -
///    the exact shape the arm fires on - the STU payload that produced it never
///    got there, so the value cannot have come from an unvalidated estimate.
///
/// The corpus item is deliberately inert so that the cost arm is the ONLY thing
/// that could produce a candidate: an empty `content_hash` means no
/// exact-duplicate arm, and empty proposition/mechanism means no semantic arm.
#[test]
fn an_unvalidated_stu_crossing_the_threshold_never_reaches_demote()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(20);
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[context_cost_record(9_000)],
        true,
    )?;
    let entry = ledger
        .entries
        .iter()
        .find(|entry| entry.target_ref == "claim:measured")
        .expect("the measured target must have a ledger entry");

    // The STU is still real evidence - it is not invented away - but it is not
    // admitted into the scalar the policy threshold reads.
    assert_eq!(
        entry.context_cost_tokens, 0,
        "an unvalidated STU must not enter the scalar the demotion threshold reads"
    );

    // Pre-fix this scalar would have been 9_000, which is above the 512
    // threshold. Build the ledger the arm needs (cost above 512, no beneficial
    // use) from exactly the scalar the admission step produced and prove no
    // HighCostLowValue/Demote candidate is derived. Pre-fix, feeding the real
    // 9_000 here would make the arm fire and this assertion fail - so this is a
    // discriminator, not a tautology. `ledger_with_cost` supplies the
    // `beneficial_use_count == 0` the arm requires, which `derive_utility_ledger`
    // cannot produce for a Context-cost record because it always pairs
    // `ContextTokenCost` with a `PacketInclusion` beneficial use.
    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        vec![item("claim:measured")],
        ledger_with_cost(
            project_id,
            snapshot_revision,
            "claim:measured",
            entry.context_cost_tokens,
        ),
    )?;
    assert!(
        plan.candidates
            .iter()
            .all(|candidate| candidate.finding != MemoryDistillationFinding::HighCostLowValue),
        "an unvalidated STU of 9_000 must not reach HighCostLowValue/Demote; got {:?}",
        plan.candidates
            .iter()
            .map(|candidate| candidate.finding)
            .collect::<Vec<_>>()
    );
    assert!(
        plan.candidates
            .iter()
            .all(|candidate| candidate.proposed_action != MemoryDistillationAction::Demote),
        "no candidate may propose Demote from an unvalidated measurement"
    );
    Ok(())
}

/// AUD4 repair 5, positive limb: a genuinely BOUND measurement that crosses
/// `512` DOES reach `Demote`.
///
/// This is the guard against "fixing" the audit finding by simply disabling the
/// policy. The same inert corpus item and the same `plan` call shape as the
/// negative limb are used; the ONLY difference is that the payload is a bound
/// tokenizer observation rather than a bare STU, so its count is admitted and
/// the threshold must fire. If this test fails, the fix has removed the policy
/// instead of constraining it.
#[test]
fn a_bound_measurement_crossing_the_threshold_still_reaches_demote()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(20);
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[bound_context_cost_record(9_000, 900)],
        true,
    )?;
    let entry = ledger
        .entries
        .iter()
        .find(|entry| entry.target_ref == "claim:measured")
        .expect("the measured target must have a ledger entry");
    assert_eq!(
        entry.context_cost_tokens, 9_000,
        "a bound observation is admitted, and its observed count is used, not the \
         900-unit STU beside it"
    );

    // Feed the arm exactly the scalar the bound measurement produced. The
    // `beneficial_use_count == 0` condition is supplied by `ledger_with_cost`,
    // which is the shape a wire-supplied ledger has.
    let plan = plan(
        project_id,
        snapshot_revision,
        true,
        vec![item("claim:measured")],
        ledger_with_cost(
            project_id,
            snapshot_revision,
            "claim:measured",
            entry.context_cost_tokens,
        ),
    )?;
    let candidate = plan
        .candidates
        .iter()
        .find(|candidate| candidate.finding == MemoryDistillationFinding::HighCostLowValue)
        .ok_or("a bound measurement above the threshold must reach HighCostLowValue")?;
    assert_eq!(candidate.proposed_action, MemoryDistillationAction::Demote);
    Ok(())
}

/// `empirical: true` is refused, so it cannot present an unvalidated estimate as
/// the bound observation that drives `Demote`.
///
/// The audit named this: `empirical: true` was accepted by the reader despite a
/// doc comment saying "Always false", and no test covered that case. An STU that
/// claims to be empirically observed is claiming an observation this seam does
/// not have, so `claims_unproven_empirical_stu` refuses the payload. Without this
/// refusal an `empirical: true` STU is exactly the shape that would slip past a
/// status gate pretending to be a proof gate.
#[test]
fn an_empirical_stu_is_refused_rather_than_treated_as_bound_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let snapshot_revision = MemoryRevision::new(9);
    let empirical = MemoryUtilitySourceRecord {
        record_ref: "context_packet:empirical".to_owned(),
        record_kind: "context_packet".to_owned(),
        target_refs: vec!["claim:measured".to_owned()],
        evidence_ref: "receipt:empirical".to_owned(),
        payload: json!({
            "measurement": {
                "adapter_revision": "eliot-context-cost/v1",
                "serializer_id": "serde_json",
                "measurement_status": "CONSERVATIVE_STU",
                "actual_tokens": Value::Null,
                "stu_estimate": { "value": 9_000, "empirical": true },
            },
        }),
        memory_revision: None,
        project_sequence: None,
        serialized_bytes: 0,
    };
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &[empirical],
        true,
    )?;
    assert_eq!(
        ledger.entries[0].context_cost_tokens, 0,
        "an STU that claims to be empirical must be refused, not admitted as a \
         proven cost"
    );
    Ok(())
}
