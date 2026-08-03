use eliot_engine::{
    ActivationProjection, CueIndexSnapshot, InjectionSelection, InjectionSelectionPolicy,
    ProjectProjectionHealth, ProjectRevisions, ProjectSnapshotBuilder, ProjectSnapshotInput,
    ProjectionFamilyHealth, UnderstandingRuntime,
};
use eliot_types::{
    CognitiveProjectionReadState, CueBinding, CueKind, CueMatchMode, CueRecordSource, CueStrength,
    MemoryRevision, ObservedCue, ProjectId, SessionId, UlInjectionMode, UlMetacognitionView,
    ul_token_estimate,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TEST_PATH: &str = "src/injection.rs";

#[test]
fn payload_mode_preserves_non_negative_payloads_in_shipped_order() -> TestResult {
    let decision_payload = json!({"decision": "keep the pure selector"});
    let card_payload = json!({"module": "injection"});
    let claim_payload = json!({"claim": "snapshot ownership is pure"});
    let selection = select(
        vec![
            source(
                "card:injection",
                "module_card",
                "Module card",
                card_payload.clone(),
                false,
            ),
            source(
                "claim:snapshot",
                "claim",
                "Snapshot claim",
                claim_payload.clone(),
                false,
            ),
            source(
                "decision:pure",
                "decision",
                "Pure selector decision",
                decision_payload.clone(),
                false,
            ),
        ],
        UlInjectionMode::Payload,
        InjectionSelectionPolicy::default(),
    )?;

    assert_eq!(
        selection
            .items
            .iter()
            .map(|item| item.item_ref.as_str())
            .collect::<Vec<_>>(),
        vec!["decision:pure", "card:injection", "claim:snapshot"]
    );
    assert_eq!(selection.items[0].payload, Some(decision_payload));
    assert_eq!(selection.items[1].payload, Some(card_payload));
    assert_eq!(selection.items[2].payload, Some(claim_payload));
    assert_eq!(selection.overflow, 0);
    Ok(())
}

#[test]
fn default_policy_preserves_shipped_three_item_and_four_hundred_unit_bounds() -> TestResult {
    let policy = InjectionSelectionPolicy::default();
    assert_eq!(policy.max_items, 3);
    assert_eq!(policy.max_token_units, 400);

    let item_bounded = select(
        vec![
            source("decision:a", "decision", "a", json!({"v": "a"}), false),
            source("card:b", "module_card", "b", json!({"v": "b"}), false),
            source("claim:c", "claim", "c", json!({"v": "c"}), false),
            source(
                "experience:d",
                "experience_case",
                "d",
                json!({"v": "d"}),
                false,
            ),
        ],
        UlInjectionMode::Payload,
        policy,
    )?;
    assert_eq!(item_bounded.items.len(), 3);
    assert_eq!(item_bounded.overflow, 1);

    let preview = "p".repeat(160);
    let payload_body = "x".repeat(650);
    let first_cost = ul_token_estimate(&preview)
        + ul_token_estimate(&serde_json::to_string(&json!({"body": payload_body}))?);
    assert!(first_cost < 400);
    assert!(first_cost.saturating_mul(2) > 400);
    let token_bounded = select(
        vec![
            source(
                "decision:budget",
                "decision",
                &preview,
                json!({"body": "x".repeat(650)}),
                false,
            ),
            source(
                "claim:budget",
                "claim",
                &preview,
                json!({"body": "x".repeat(650)}),
                false,
            ),
        ],
        UlInjectionMode::Payload,
        policy,
    )?;
    assert_eq!(token_bounded.items.len(), 1);
    assert_eq!(token_bounded.overflow, 1);
    assert!(token_bounded.token_units <= 400);
    Ok(())
}

#[test]
fn b1_selector_has_no_kind_specific_negative_payload_suppression() -> TestResult {
    let selection = select(
        vec![
            source(
                "failure:a",
                "failure_fingerprint",
                "Avoid failure A",
                json!({"avoid": "a"}),
                true,
            ),
            source(
                "failure:b",
                "failure_fingerprint",
                "Avoid failure B",
                json!({"avoid": "b"}),
                true,
            ),
        ],
        UlInjectionMode::Payload,
        InjectionSelectionPolicy {
            max_items: 3,
            max_token_units: 400,
            // Retained for API compatibility; B1 does not apply this B2 policy.
            max_negative_payloads: 0,
        },
    )?;

    assert_eq!(selection.items.len(), 2);
    assert!(selection.items.iter().all(|item| item.payload.is_some()));
    assert_eq!(selection.overflow, 0);
    Ok(())
}

#[test]
fn oversized_payload_falls_back_to_handle_without_dropping_the_item() -> TestResult {
    let selection = select(
        vec![source(
            "decision:large",
            "decision",
            "Large decision",
            json!({"body": "x".repeat(1_300)}),
            false,
        )],
        UlInjectionMode::Payload,
        InjectionSelectionPolicy::default(),
    )?;

    assert_eq!(selection.items.len(), 1);
    assert_eq!(selection.items[0].item_ref, "decision:large");
    assert!(selection.items[0].payload.is_none());
    assert_eq!(selection.overflow, 0);
    Ok(())
}

fn select(
    sources: Vec<CueRecordSource>,
    mode: UlInjectionMode,
    policy: InjectionSelectionPolicy,
) -> Result<InjectionSelection, Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let session_id = SessionId::new_v7();
    let runtime = UnderstandingRuntime::default();
    runtime.install_project(snapshot(project_id, sources)?)?;
    let cues = [ObservedCue {
        kind: CueKind::FilePath,
        value: TEST_PATH.to_owned(),
    }];
    let plan = runtime.plan_cues(project_id, session_id, None, &cues)?;
    runtime.enqueue_plan(project_id, session_id, &plan)?;
    Ok(runtime.select_pending_with_policy(project_id, session_id, mode, policy)?)
}

fn source(
    record_ref: &str,
    record_kind: &str,
    preview: &str,
    payload: Value,
    negative_memory: bool,
) -> CueRecordSource {
    CueRecordSource {
        record_ref: record_ref.to_owned(),
        record_kind: record_kind.to_owned(),
        preview_text: preview.to_owned(),
        payload: Some(payload),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: TEST_PATH.to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "focused injection selection".to_owned(),
        }],
        negative_memory,
        lifecycle: "active".to_owned(),
    }
}

fn snapshot(
    project_id: ProjectId,
    records: Vec<CueRecordSource>,
) -> Result<eliot_engine::ProjectSnapshot, eliot_engine::EngineError> {
    let revision = MemoryRevision::new(1);
    let cue_projection = CueIndexSnapshot::from_sources(
        project_id,
        revision,
        CognitiveProjectionReadState::Published,
        &records,
    )?;
    ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
        project_id,
        revisions: ProjectRevisions {
            canonical: Some(revision),
            cue: Some(revision),
            pyramid: Some(revision),
            activation: Some(revision),
            dependency: Some(revision),
        },
        health: ProjectProjectionHealth {
            cue: published_health(revision),
            pyramid: published_health(revision),
            activation: published_health(revision),
            dependency: published_health(revision),
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
    })
}

fn published_health(revision: MemoryRevision) -> ProjectionFamilyHealth {
    ProjectionFamilyHealth {
        state: CognitiveProjectionReadState::Published,
        revision: Some(revision),
        detail: None,
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
