#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_campaign_executor::{
    CampaignExecutor, CampaignLedger, CapabilityProbe, CodexRole, FallbackAdmission,
    FallbackTerminalClass, OPENCODE_RECEIPT_SHA256, OPENCODE_STDERR_SHA256, OPENCODE_STDOUT_SHA256,
    OpenCodeEvidence, OpenCodeLane, OpenCodeRoutePolicy, PRIMARY_OPENCODE_MODEL,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-d02-{label}-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create synthetic fixture root");
    root
}

fn fixture_ledger() -> CampaignLedger {
    let seed = json!({"campaign_id": "synthetic-d02", "controller_epoch": 0});
    let seed_digest = sha256(b"{\"campaign_id\":\"synthetic-d02\",\"controller_epoch\":0}");
    let receipt = json!({"seed_digest": seed_digest, "sequence": 0});
    CampaignLedger::from_seed_and_suffix(seed, receipt, Vec::new()).expect("genesis")
}

fn fixture_executor() -> CampaignExecutor {
    CampaignExecutor::new(fixture_ledger())
}

fn write_fixed_bytes(
    root: &Path,
    name: &str,
    bytes: &[u8],
    expected_sha256: &str,
) -> eliot_campaign_executor::EvidenceFile {
    let path = root.join(name);
    fs::write(&path, bytes).expect("write synthetic artifact");
    eliot_campaign_executor::EvidenceFile {
        path,
        expected_sha256: expected_sha256.to_owned(),
    }
}

#[test]
fn capability_probe_preserves_input_role_capacities_and_typed_roles() {
    let mut executor = fixture_executor();
    let slot_ids = vec![
        "codex-a".to_owned(),
        "codex-b".to_owned(),
        "codex-c".to_owned(),
    ];
    let mut probe = CapabilityProbe::post_adoption_with_codex_slots(1, 1, 1, 1, 1, slot_ids, 3);
    probe.codex_slots_used = 3;
    assert_eq!(
        probe.codex_slots_admitted as usize,
        probe.codex_slot_ids.len()
    );
    for role in [
        "mutating",
        "reviewer",
        "read_only",
        "assembly",
        "build_exclusive",
    ] {
        assert_eq!(probe.role_capacities[role], 1);
    }
    probe
        .validate_before_staffing()
        .expect("complete route probe");
    assert!(executor.record_capability_probe(probe.clone()).is_err());
    assert!(
        executor.capability_probe().is_none(),
        "capability recording requires verified recovery adoption"
    );
    let typed_roles = [
        CodexRole::Mutating,
        CodexRole::Reviewer,
        CodexRole::ReadOnly,
        CodexRole::Assembly,
        CodexRole::BuildExclusive,
    ];
    assert_eq!(typed_roles.len(), 5);
    assert!(
        executor.staff_codex_slots().is_err(),
        "staffing cannot bypass recovery adoption"
    );
}

#[test]
fn capability_probe_rejects_unfit_route_and_slot_count_tampering() {
    let mut unfit = CapabilityProbe::post_adoption(0, 1, 1, 1, 1);
    assert!(unfit.validate_before_staffing().is_err());
    unfit.codex_slots_admitted = 3;
    assert!(
        unfit.validate_before_staffing().is_err(),
        "admission count must match identities"
    );
    unfit.codex_slots_admitted = 4;

    let executor = fixture_executor();
    assert!(executor.capability_probe().is_none());
    assert!(unfit.validate_shape().is_ok());
}

#[test]
fn opencode_primary_and_fallback_are_explicit_candidate_only_attempts() {
    let mut executor = fixture_executor();
    assert!(
        executor.admit_opencode_primary().is_err(),
        "probe is required before admission"
    );
    let mut lane = OpenCodeLane::with_policy(OpenCodeRoutePolicy {
        primary_model: PRIMARY_OPENCODE_MODEL.to_owned(),
        fallback_model: eliot_campaign_executor::FALLBACK_OPENCODE_MODEL.to_owned(),
        primary_receipt_sha256: eliot_campaign_executor::OPENCODE_RECEIPT_SHA256.to_owned(),
        event9_head_sha256: eliot_campaign_executor::EVENT9_HEAD_SHA256.to_owned(),
    });
    let primary = lane.admit_primary().expect("primary attempt");
    assert_eq!(primary.launch.model, PRIMARY_OPENCODE_MODEL);
    assert!(primary.launch.headless);
    assert!(primary.launch.supervised);
    assert!(primary.launch.candidate_only);
    assert!(
        serde_json::to_value(&primary.launch)
            .expect("launch JSON")
            .get("timeout")
            .is_none()
    );

    let admission = FallbackAdmission {
        terminal_class: FallbackTerminalClass::Readiness,
        route_admitted: true,
        privacy_admitted: true,
        budget_admitted: true,
    };
    admission.verify().expect("fallback readiness admission");
    let fallback = lane
        .admit_fallback("controller-selected fallback")
        .expect("explicit fallback");
    assert!(fallback.explicit_admission);
    assert!(!fallback.automatic_retry);
    assert!(lane.admit_fallback("duplicate").is_err());
}

#[test]
fn candidate_result_is_bound_to_attempt_and_never_becomes_a_verdict() {
    let mut lane = OpenCodeLane::with_policy(OpenCodeRoutePolicy {
        primary_model: PRIMARY_OPENCODE_MODEL.to_owned(),
        fallback_model: eliot_campaign_executor::FALLBACK_OPENCODE_MODEL.to_owned(),
        primary_receipt_sha256: eliot_campaign_executor::OPENCODE_RECEIPT_SHA256.to_owned(),
        event9_head_sha256: eliot_campaign_executor::EVENT9_HEAD_SHA256.to_owned(),
    });
    let attempt = lane.admit_primary().expect("primary");
    let mut executor = fixture_executor();
    assert!(
        executor
            .record_candidate(&attempt, b"synthetic-candidate")
            .is_err()
    );
}

#[test]
fn opencode_evidence_requires_exact_contract_and_reaped_process_facts() {
    let root = temp_root("opencode-evidence");
    let result = b"synthetic-result";
    let stdout = b"synthetic-stdout\n";
    let stderr = b"";
    let evidence = OpenCodeEvidence {
        contract_model: PRIMARY_OPENCODE_MODEL.to_owned(),
        contract_argv: vec![
            "run".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--agent".to_owned(),
            "plan".to_owned(),
            "--dir".to_owned(),
            root.display().to_string(),
            "--model".to_owned(),
            PRIMARY_OPENCODE_MODEL.to_owned(),
        ],
        contract_unscoped_supervised_plan: true,
        contract_authority_refs_null: true,
        result: write_fixed_bytes(&root, "result.json", result, OPENCODE_RECEIPT_SHA256),
        stdout: write_fixed_bytes(&root, "stdout.jsonl", stdout, OPENCODE_STDOUT_SHA256),
        stderr: write_fixed_bytes(&root, "stderr.log", stderr, OPENCODE_STDERR_SHA256),
        expected_exit_code: 0,
        expected_session_events: 3,
        expected_tool_events: 0,
        reap_complete: true,
    };
    let error = evidence
        .verify()
        .expect_err("synthetic bytes cannot satisfy immutable OpenCode proof");
    assert!(error.to_string().contains("hash mismatch"));

    let mut unreaped = evidence.clone();
    unreaped.reap_complete = false;
    assert!(
        unreaped.verify().is_err(),
        "unreaped process is not admissible evidence"
    );

    let mut wrong_model = evidence.clone();
    wrong_model.contract_model = "opencode/other-model".to_owned();
    assert!(
        wrong_model.verify().is_err(),
        "model drift must fail closed"
    );
    let mut wrong_outcome = evidence;
    wrong_outcome.expected_session_events = 2;
    assert!(
        wrong_outcome.verify().is_err(),
        "weaker live outcome must fail closed"
    );
    let _ = fs::remove_dir_all(root);
}
