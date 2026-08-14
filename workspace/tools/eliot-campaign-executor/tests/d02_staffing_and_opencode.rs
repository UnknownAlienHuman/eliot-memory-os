#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_campaign_executor::{
    CampaignExecutor, CampaignLedger, CapabilityProbe, CodexRole, OpenCodeActualRouteReceipt,
    OpenCodeActualRouteState, OpenCodeEvidence, OpenCodeHttpSseResult, OpenCodeLane,
    OpenCodeRoutePolicy, OpenCodeRouteState, PRIMARY_OPENCODE_MODEL,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn fixture_ledger() -> CampaignLedger {
    let seed = json!({"campaign_id": "synthetic-d02", "controller_epoch": 0});
    let seed_digest = sha256(b"{\"campaign_id\":\"synthetic-d02\",\"controller_epoch\":0}");
    let receipt = json!({"seed_digest": seed_digest, "sequence": 0});
    CampaignLedger::from_seed_and_suffix(seed, receipt, Vec::new()).expect("genesis")
}

#[test]
fn capability_probe_preserves_input_role_capacities_and_typed_roles() {
    let mut executor = CampaignExecutor::new(fixture_ledger());
    let slot_ids = vec![
        "codex-a".to_owned(),
        "codex-b".to_owned(),
        "codex-c".to_owned(),
    ];
    let mut probe = CapabilityProbe::post_adoption_with_codex_slots(1, 1, 1, 1, 1, slot_ids, 3);
    probe.codex_slots_used = 3;
    probe
        .validate_before_staffing()
        .expect("complete route probe");
    assert!(executor.record_capability_probe(probe.clone()).is_err());
    assert!(executor.capability_probe().is_none());
    assert!(executor.staff_codex_slots().is_err());
    assert_eq!(
        [
            CodexRole::Mutating,
            CodexRole::Reviewer,
            CodexRole::ReadOnly,
            CodexRole::Assembly,
            CodexRole::BuildExclusive,
        ]
        .len(),
        5
    );
}

#[test]
fn unavailable_route_is_typed_and_never_opens_another_model() {
    let mut lane = OpenCodeLane::new();
    lane.disable("quota unavailable").expect("disable route");
    assert!(matches!(lane.state, OpenCodeRouteState::Unavailable { .. }));
    assert!(lane.admit_primary().is_err());
    assert!(lane.primary.is_none());
}

#[test]
fn a04_result_and_actual_route_receipt_are_candidate_only_and_dynamic() {
    let root = PathBuf::from(r"C:\Scratch\d02");
    let route = OpenCodeActualRouteReceipt {
        requested: eliot_campaign_executor::OpenCodeModelIdentity {
            provider_id: "opencode-go".into(),
            model_id: "deepseek-v4-flash".into(),
        },
        observed: Some(eliot_campaign_executor::OpenCodeModelIdentity {
            provider_id: "opencode-go".into(),
            model_id: "deepseek-v4-flash".into(),
        }),
        provider: Some("opencode-go".into()),
        endpoint: Some("http://127.0.0.1:4096".into()),
        route_fingerprint: Some("sha256:observed".into()),
        session_id: Some("ses_d02".into()),
        directory: Some(root.display().to_string()),
        server_version: Some("1.4.3".into()),
        workspace_id: None,
        state: OpenCodeActualRouteState::Observed,
    };
    let result = OpenCodeHttpSseResult {
        status: "succeeded".into(),
        candidate_only: true,
        authority: "candidate_only".into(),
        actual_route: route,
        session_id: Some("ses_d02".into()),
        output: Some(json!({"status": "ready"})),
        events: Vec::new(),
        diff: Vec::new(),
    };
    let evidence = OpenCodeEvidence::from_result(result);
    evidence
        .verify_with_policy(&OpenCodeRoutePolicy {
            model: PRIMARY_OPENCODE_MODEL.into(),
        })
        .expect("A-04 result contract");
}

#[test]
fn a04_no_authority_wire_shape_uses_separate_provider_and_model_ids() {
    let wire = json!({
        "status": "succeeded",
        "candidate_only": true,
        "authority": "candidate_only",
        "actual_route": {
            "requested": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "observed": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "provider": "opencode-go",
            "endpoint": "http://127.0.0.1:4096",
            "route_fingerprint": "sha256:a04-fixture",
            "session_id": "ses_a04",
            "directory": "C:\\Scratch\\d02",
            "server_version": "1.4.3",
            "workspace_id": null,
            "state": "observed"
        },
        "usage": {"state": "known"},
        "quota": {"state": "known"},
        "session_id": "ses_a04",
        "output": {"status": "ready"},
        "events": [],
        "diff": []
    });
    let result: OpenCodeHttpSseResult = serde_json::from_value(wire.clone()).expect("A-04 wire");
    OpenCodeEvidence::from_result(result)
        .verify()
        .expect("separate provider/model IDs are accepted");

    let mut wrong_provider = wire;
    wrong_provider["actual_route"]["observed"]["providerID"] = json!("opencode");
    let result: OpenCodeHttpSseResult = serde_json::from_value(wrong_provider).expect("wire");
    assert!(OpenCodeEvidence::from_result(result).verify().is_err());

    let wrong_model = json!({
        "status": "succeeded",
        "candidate_only": true,
        "authority": "candidate_only",
        "actual_route": {
            "requested": {"providerID": "opencode-go", "modelID": "wrong-model"},
            "observed": {"providerID": "opencode-go", "modelID": "wrong-model"},
            "provider": "opencode-go",
            "endpoint": "http://127.0.0.1:4096",
            "route_fingerprint": "sha256:a04-fixture",
            "session_id": "ses_a04",
            "directory": "C:\\Scratch\\d02",
            "server_version": "1.4.3",
            "workspace_id": null,
            "state": "observed"
        },
        "session_id": "ses_a04",
        "output": null,
        "events": [],
        "diff": []
    });
    let result: OpenCodeHttpSseResult = serde_json::from_value(wrong_model).expect("wire");
    assert!(OpenCodeEvidence::from_result(result).verify().is_err());
}
