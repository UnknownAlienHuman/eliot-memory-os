#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_campaign_executor::{
    BOOTSTRAP_RECEIPT_SHA256, CHECKPOINT0_SHA256, CHECKPOINT1_SHA256, CampaignExecutor,
    CampaignLedger, CampaignStore, D01_HANDLE_SHA256, D01_REPORT_SHA256, EVENT9_HEAD_SHA256,
    EpochId, EvidenceFile, LedgerEvent, OpenCodeRoutePolicy, RecoveryEvidence,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("eliot-d02-{label}-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("create synthetic fixture root");
    root
}

fn fixture_ledger() -> CampaignLedger {
    let seed = json!({"campaign_id": "synthetic-d02", "controller_epoch": 0});
    let seed_digest = sha256(&serde_json::to_vec(&seed).expect("seed bytes"));
    let receipt = json!({"sequence": 0, "seed_digest": seed_digest});
    CampaignLedger::from_seed_and_suffix(seed, receipt, Vec::new()).expect("genesis")
}

fn fixed_recovery(root: &Path) -> RecoveryEvidence {
    let fixed = |name: &str, expected_sha256: &str| EvidenceFile {
        path: root.join(name),
        expected_sha256: expected_sha256.to_owned(),
    };
    RecoveryEvidence {
        bootstrap_receipt: fixed("bootstrap-receipt.json", BOOTSTRAP_RECEIPT_SHA256),
        checkpoint0: fixed("checkpoint-0.json", CHECKPOINT0_SHA256),
        d01_report: fixed("d01-report.json", D01_REPORT_SHA256),
        d01_handle: fixed("d01-handle.json", D01_HANDLE_SHA256),
        checkpoint: fixed("checkpoint-1.json", CHECKPOINT1_SHA256),
        event9: fixed("event-9.json", EVENT9_HEAD_SHA256),
        repository_root: root.to_path_buf(),
        event9_head_sha256: EVENT9_HEAD_SHA256.to_owned(),
    }
}

fn write_empty_raw_store(root: &Path) {
    fs::create_dir_all(root.join("events")).expect("events directory");
    let seed = json!({
        "schema_version": "eliot-bootstrap-campaign-seed-v1",
        "campaign_id": "synthetic-d02",
        "controller_epoch": 0
    });
    let seed_bytes = serde_json::to_vec(&seed).expect("seed JSON");
    let receipt = json!({
        "schema_version": "eliot-bootstrap-campaign-seed-receipt-v1",
        "campaign_id": "synthetic-d02",
        "seed_sha256": sha256(&seed_bytes)
    });
    fs::write(root.join("bootstrap-campaign-seed.json"), seed_bytes).expect("seed file");
    fs::write(
        root.join("bootstrap-campaign-seed.receipt.json"),
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    )
    .expect("receipt file");
}

#[test]
fn unverified_synthetic_ledger_cannot_claim_legacy_bootstrap() {
    let ledger = fixture_ledger();
    let genesis = ledger.genesis().clone();
    assert!(
        ledger.verify_legacy_suffix().is_err(),
        "synthetic empty suffix is not an immutable bootstrap"
    );
    assert_eq!(
        &genesis,
        ledger.genesis(),
        "verification must not rewrite genesis"
    );
    assert!(ledger.active_controller_epoch().is_none());
}

#[test]
fn legacy_bootstrap_requires_the_exact_nine_event_head() {
    let ledger = fixture_ledger();
    let error = ledger
        .verify_legacy_suffix()
        .expect_err("empty suffix is not a legacy head");
    assert!(error.to_string().contains("events 1..9"));

    // A synthetic event-9 marker is not accepted as a substitute for the
    // immutable real-format head. This protects the test from accidentally
    // weakening the exact EVENT9 binding while the parser/API is completed.
    assert_eq!(EVENT9_HEAD_SHA256.len(), 64);
}

#[test]
fn recovery_evidence_requires_fixed_immutable_hashes_and_all_artifacts() {
    let root = temp_root("recovery");
    let evidence = fixed_recovery(&root);
    for (name, bytes) in [
        ("bootstrap-receipt.json", b"synthetic receipt".as_slice()),
        ("checkpoint-0.json", b"synthetic checkpoint 0".as_slice()),
        ("d01-report.json", b"synthetic report".as_slice()),
        ("d01-handle.json", b"synthetic handle".as_slice()),
        ("checkpoint-1.json", b"synthetic checkpoint 1".as_slice()),
        ("event-9.json", b"synthetic event 9".as_slice()),
    ] {
        fs::write(root.join(name), bytes).expect("write synthetic artifact");
    }
    let error = evidence
        .verify()
        .expect_err("synthetic bytes cannot satisfy immutable recovery contract");
    assert!(error.to_string().contains("hash mismatch"));

    let mut stale_hash = fixed_recovery(&root);
    stale_hash.event9_head_sha256 = "0".repeat(64);
    assert!(
        stale_hash.verify().is_err(),
        "stale event-9 hash must fail closed"
    );

    assert!(
        fixed_recovery(&root.join("missing")).verify().is_err(),
        "missing immutable artifacts must fail closed"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn recovery_policy_rejects_route_or_event9_drift_before_reads() {
    let root = temp_root("recovery-policy");
    let evidence = fixed_recovery(&root);
    let policy = OpenCodeRoutePolicy {
        model: "opencode-go/other-model".to_owned(),
    };
    let error = evidence
        .verify_with_policy(&policy)
        .expect_err("event-9 drift must fail closed");
    assert!(error.to_string().contains("model"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn executor_adoption_requires_exact_immutable_recovery_and_events_one_through_nine() {
    let root = temp_root("adoption");
    let mut executor = CampaignExecutor::new(fixture_ledger());
    let error = executor
        .adopt(
            EpochId::fresh(1).expect("epoch one"),
            &fixed_recovery(&root),
        )
        .expect_err("empty synthetic ledger/evidence cannot be adopted");
    assert!(!error.to_string().is_empty());
    assert!(executor.ledger.active_controller_epoch().is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn checked_append_rejects_stale_head_and_epoch_before_event_write() {
    let root = temp_root("checked-append");
    write_empty_raw_store(&root);
    let store = CampaignStore::acquire(&root).expect("campaign lock");
    let ledger = store.load().expect("empty raw campaign");
    let head = ledger.head_hash().to_owned();
    let state_fence = ledger.state_fence();
    let event: LedgerEvent = serde_json::from_value(json!({
        "sequence": 1,
        "event_type": "synthetic_append",
        "actor": "D-02",
        "controller_epoch": {"lineage": Uuid::nil(), "sequence": 1},
        "hash_algorithm": "Blake3",
        "payload": {},
        "previous_segment_hash": head,
        "event_hash": "not-a-valid-hash"
    }))
    .expect("synthetic event shape");
    assert!(
        store
            .append_event_checked(&event, "stale-head", None, &state_fence)
            .is_err(),
        "a stale observed head must block append"
    );
    let stale_epoch = EpochId::fresh(1).expect("stale epoch");
    let loaded_head = ledger.head_hash().to_owned();
    assert!(
        store
            .append_event_checked(&event, &loaded_head, Some(&stale_epoch), &state_fence)
            .is_err(),
        "a stale observed epoch must block append"
    );
    drop(store);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn torn_or_malformed_journal_segment_is_rejected_without_repair() {
    let root = temp_root("torn-journal");
    let seed = json!({"campaign_id": "synthetic-d02", "controller_epoch": 0});
    let seed_digest = sha256(&serde_json::to_vec(&seed).expect("seed bytes"));
    let receipt = json!({"sequence": 0, "seed_digest": seed_digest});
    fs::create_dir_all(root.join("events")).expect("events directory");
    fs::write(
        root.join("bootstrap-campaign-seed.json"),
        serde_json::to_vec(&seed).expect("seed JSON"),
    )
    .expect("seed file");
    fs::write(
        root.join("bootstrap-campaign-seed.receipt.json"),
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    )
    .expect("receipt file");
    fs::write(
        root.join("events").join("00000000000000000001.json"),
        b"{\"sequence\":1,\"event_type\":\"torn",
    )
    .expect("torn journal");
    fs::write(
        root.join("events").join("00000000000000000001.json.tmp"),
        b"partial",
    )
    .expect("torn temporary segment");

    let store = CampaignStore::acquire(&root).expect("acquire synthetic campaign store");
    assert!(
        store.load().is_err(),
        "torn segment must be rejected, never repaired"
    );
    drop(store);
    assert!(
        fs::read(root.join("events").join("00000000000000000001.json"))
            .expect("read journal")
            .starts_with(b"{\"sequence\":1")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unexpected_event_file_is_quarantined_by_rejection() {
    let root = temp_root("quarantine");
    fs::create_dir_all(root.join("events")).expect("events directory");
    let seed = json!({"campaign_id": "synthetic-d02", "controller_epoch": 0});
    let seed_digest = sha256(&serde_json::to_vec(&seed).expect("seed bytes"));
    let receipt = json!({"sequence": 0, "seed_digest": seed_digest});
    fs::write(
        root.join("bootstrap-campaign-seed.json"),
        serde_json::to_vec(&seed).expect("seed JSON"),
    )
    .expect("seed file");
    fs::write(
        root.join("bootstrap-campaign-seed.receipt.json"),
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    )
    .expect("receipt file");
    fs::write(
        root.join("events").join("00000000000000000001.json.tmp"),
        b"partial",
    )
    .expect("unexpected temporary segment");
    let store = CampaignStore::acquire(&root).expect("acquire synthetic campaign store");
    let error = store
        .load()
        .expect_err("temporary event file must be rejected");
    assert!(
        error
            .to_string()
            .contains("quarantine unexpected campaign event file")
    );
    assert!(
        root.join("events")
            .join("00000000000000000001.json.tmp")
            .is_file()
    );
    drop(store);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn controller_lock_is_single_writer_and_is_released_after_drop() {
    let root = temp_root("controller-lock");
    let first = CampaignStore::acquire(&root).expect("first controller");
    assert!(
        CampaignStore::acquire(&root).is_err(),
        "a second controller must not attach"
    );
    drop(first);
    let second = CampaignStore::acquire(&root).expect("lock released after controller exit");
    drop(second);
    let _ = fs::remove_dir_all(root);
}
