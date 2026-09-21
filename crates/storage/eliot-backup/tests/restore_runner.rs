//! Actual isolated restore runner proofs (issue #1873 product lane).
//!
//! Temporary-only proof: real restored bytes plus receipt through the governed
//! journaled executor, durable resume across runner instances from the
//! temp-file journal, tampered-blob refusal, degraded canonical-only ceiling,
//! and key-coverage gating. No production data is touched: every root lives
//! under the system temp dir and purge guards stay enforced.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput,
    CanonicalRecord, EventRange, ExportFence, IsolatedRoot, OrsSnapshotFence, RestoreContext,
    WatchdogSpoolFence, WrappedKeyEntry, WrappedKeyManifest, execute_isolated_restore,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use serde_json::json;

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const KEY_LINEAGE: &str = "key-lineage-1873x";

fn epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(LINEAGE_A).expect("valid lineage"),
        NonZeroU64::new(sequence).expect("nonzero sequence"),
    )
    .expect("valid epoch")
}

fn fence() -> StateFence {
    StateFence::new(epoch(1), ResourceGeneration::genesis())
}

fn locator_for(label: &str) -> BlobLocator {
    let digest_hex = sha256_hex(label.as_bytes());
    BlobLocator {
        hash: BlobHash::new(digest_hex.clone()).expect("valid blob hash"),
        residency: ObjectResidencyKey {
            scope_domain_id: BlobId::new("scope-1873x").expect("scope domain"),
            access_domain_id: BlobId::new("access-1873x").expect("access domain"),
            confidentiality_domain_id: BlobId::new("confidentiality-1873x")
                .expect("confidentiality domain"),
            encryption_key_domain_id: BlobId::new("keydomain-1873x").expect("key domain"),
            retention_domain_id: BlobId::new("retention-1873x").expect("retention domain"),
            erasure_domain_id: BlobId::new("erasure-1873x").expect("erasure domain"),
            content_digest: VersionedContentDigest {
                algorithm: BlobId::new("blake3").expect("valid algorithm"),
                version: 1,
                digest: BlobHash::new(digest_hex).expect("valid digest"),
            },
        },
        root_generation: 1,
        path_generation: 1,
    }
}

fn blob_for(label: &str) -> BackupBlob {
    let sealed_bytes = format!("sealed-envelope-{label}").into_bytes();
    BackupBlob {
        locator: locator_for(label),
        sealed_sha256: sha256_hex(&sealed_bytes),
        plaintext_sha256: sha256_hex(format!("plaintext-{label}").as_bytes()),
        sealed_bytes,
        key_lineage: BlobId::new(KEY_LINEAGE).expect("key lineage"),
        format: BlobId::new("backup-format").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: CryptoDescriptor {
            algorithm: BlobId::new("aead-test").expect("crypto"),
            version: 1,
            key_lineage: BlobId::new(KEY_LINEAGE).expect("crypto lineage"),
            key_generation: 1,
        },
    }
}

fn artifact(kind: &str) -> BackupArtifact {
    let bytes = format!("{kind}-manifest-bytes").into_bytes();
    let sha256 = sha256_hex(&bytes);
    BackupArtifact {
        kind: kind.to_owned(),
        artifact_id: format!("{kind}-1"),
        bytes,
        sha256,
    }
}

fn purge_entry(id: &str) -> PurgeLedgerEntry {
    PurgeLedgerEntry {
        purge_id: id.to_owned(),
        subject_ref: format!("subject-{id}"),
        scope: "scope-1".to_owned(),
        purged_locations: vec![PurgeLocation::CanonicalPayload],
        tombstone_digest: sha256_hex(format!("tombstone-{id}").as_bytes()),
        state: PurgeState::Purged,
        state_fence: fence(),
        revision: 1,
    }
}

fn receipt_for(operation: &str) -> eliot_store_api::WriteReceipt {
    eliot_store_api::WriteReceipt {
        operation_id: eliot_store_api::OperationId::new(operation).expect("operation"),
        idempotency_key: format!("idem-{operation}"),
        canonical_request_hash: "a".repeat(64),
        transition_class: eliot_store_api::TransitionClass::CaptureCandidate,
        status: eliot_store_api::WriteReceiptStatus::Committed,
        commit_id: Some(
            eliot_store_api::CommitId::new(format!("commit-{operation}")).expect("commit"),
        ),
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("cmd-{operation}")],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: eliot_store_api::OperationManifestDigest::new(
            "manifest-runner-1873x",
        )
        .expect("manifest"),
        error_code: None,
        resubmission: eliot_store_api::Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    }
}

fn full_input() -> BackupInput {
    let source_fence = fence();
    let blob = blob_for("runner-1873x");
    let blob_hash = blob.locator.hash.to_string();
    let event = CanonicalRecord::new(
        "task_state",
        "event-1873x-1",
        json!({"subject": "subject-1873x-1"}),
    )
    .expect("event builds");
    let projection =
        CanonicalRecord::new("task_state", "event-1873x-1", json!({"projected": true}))
            .expect("projection builds");
    BackupInput {
        backup_id: "backup-1873x-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-1873x".to_owned(),
            store_generation: "store-1873x".to_owned(),
            state_fence: source_fence.clone(),
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: Some(1),
                last_sequence: Some(1),
                count: 1,
            },
            blob_reachability_manifest: vec![BlobHash::new(blob_hash).expect("reachability")],
            consistent: true,
        },
        canonical_events: vec![event],
        projections: vec![projection],
        receipts: vec![receipt_for("op-1873x-1")],
        blobs: vec![blob],
        purge_ledger: vec![purge_entry("purge-1873x-1")],
        ors_snapshot: Some(OrsSnapshotFence {
            snapshot_id: "ors-1873x".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 1,
            last_outbox_cursor: 0,
            pending_operation_ids: vec!["op-1873x-b".to_owned(), "op-1873x-a".to_owned()],
            job_checkpoint_ids: Vec::new(),
            generation_cutover_ids: Vec::new(),
            state_fence: source_fence.clone(),
            active_authority_restored: false,
        }),
        artifacts: ["config", "policy", "module", "host_dependency_build"]
            .iter()
            .map(|kind| artifact(kind))
            .collect(),
        watchdog_spool: Some(WatchdogSpoolFence {
            fence_id: "watchdog-1873x".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-1873x")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn key_manifest() -> WrappedKeyManifest {
    let wrapped = b"wrapped-key-1873x".to_vec();
    WrappedKeyManifest {
        manifest_id: "key-manifest-1873x".to_owned(),
        backup_id: "backup-1873x-full".to_owned(),
        entries: vec![WrappedKeyEntry {
            key_lineage: KEY_LINEAGE.to_owned(),
            wrapping_key_id: "wrapping-key-1873x".to_owned(),
            algorithm: "aead-wrap-test".to_owned(),
            wrapped_key_sha256: sha256_hex(&wrapped),
            wrapped_key_bytes: wrapped,
        }],
    }
}

fn target_context() -> RestoreContext {
    RestoreContext {
        target_id: "target-1873x".to_owned(),
        target_authority_epoch: epoch(2),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    }
}

// WORK_UNIT_CASE: 1873x/real-bytes-receipt
#[test]
fn runner_restores_real_bytes_with_receipt_in_temp_only() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let manifest = key_manifest();
    let root = IsolatedRoot::create("run-1873x").expect("isolated root creates");
    let outcome = execute_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
        Some(&manifest),
    )
    .expect("isolated run completes");
    // Receipt: exact plan binding, never operational-ready, never cut over.
    assert_eq!(outcome.receipt.target_id, "target-1873x");
    assert_eq!(
        outcome.receipt.bundle_sha256,
        bundle.bundle_sha256().expect("digest")
    );
    assert!(!outcome.receipt.canonical_only);
    assert!(!outcome.receipt.operational_recovery_ready);
    assert!(!outcome.receipt.cutover_performed);
    assert_eq!(outcome.receipt.restored_fence.authority_epoch, epoch(2));
    // Real bytes: the restored blob file carries the exact sealed envelope.
    let blob_path = outcome
        .root
        .join("blobs")
        .join(bundle.blobs[0].locator.hash.to_string());
    let restored = std::fs::read(&blob_path).expect("restored blob reads");
    assert_eq!(restored, bundle.blobs[0].sealed_bytes);
    // Real bytes: the restored event payload round-trips exactly.
    let event_path = outcome.root.join("events").join("event-1873x-1.json");
    let event_bytes = std::fs::read(&event_path).expect("restored event reads");
    let event_value: serde_json::Value =
        serde_json::from_slice(&event_bytes).expect("event parses");
    assert_eq!(event_value, json!({"subject": "subject-1873x-1"}));
    // Purge ledger persisted before any import ran.
    assert!(outcome.root.join("purge_ledger.json").exists());
    assert!(outcome.phase_log.len() >= 2);
    assert_eq!(outcome.phase_log[0], "prepare");
    assert_eq!(outcome.phase_log[1], "purge");
    assert!(outcome.phase_log.contains(&"suspend-ors".to_owned()));
    // Suspended ORS evidence is deterministic and never active authority.
    assert_eq!(outcome.suspended_entries.len(), 2);
    for entry in &outcome.suspended_entries {
        assert!(entry.suspended);
    }
    assert_eq!(outcome.suspended_entries[0].historical_ref, "op-1873x-a");
    // Journal file proves durable (temp-file) execution, not a mock run.
    assert!(outcome.journal_path.exists());
    // Everything observed lives under the temp dir.
    assert!(outcome.root.starts_with(std::env::temp_dir()));
}

// WORK_UNIT_CASE: 1873x/durable-resume
#[test]
fn runner_resumes_from_the_durable_journal_without_reapplying() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let manifest = key_manifest();
    let root = IsolatedRoot::create("resume-1873x").expect("isolated root creates");
    let first = execute_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
        Some(&manifest),
    )
    .expect("first run completes");
    assert!(!first.phase_log.is_empty(), "first run applies phases");
    // A second runner instance against the same root resumes from the
    // durable journal file instead of re-applying effects.
    let reopened = IsolatedRoot::open_existing(root.path().to_path_buf()).expect("root reopens");
    let second = execute_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &reopened,
        Some(&manifest),
    )
    .expect("resumed run completes");
    assert_eq!(
        second.receipt, first.receipt,
        "resume returns the same receipt"
    );
    assert_eq!(
        second.evidence, first.evidence,
        "resumed evidence rebuilds deterministically from plan and bundle"
    );
    assert!(
        second.phase_log.is_empty(),
        "resumed run applies no phases: {:?}",
        second.phase_log
    );
}

// WORK_UNIT_CASE: 1873x/tampered-blob
#[test]
fn runner_refuses_tampered_blob_bytes() {
    let mut bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    bundle.blobs[0].sealed_bytes = b"tampered-bytes".to_vec();
    let manifest = key_manifest();
    let root = IsolatedRoot::create("tamper-1873x").expect("isolated root creates");
    let result = execute_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
        Some(&manifest),
    );
    assert!(
        matches!(result, Err(BackupError::IntegrityMismatch { .. })),
        "tampered sealed bytes must be an integrity mismatch, got {result:?}"
    );
    // Refusal lands at plan validation, before any effect: no phase ran and
    // the tampered blob never lands in the isolated root.
    assert!(
        !root.path().join("phase-receipts").exists(),
        "no phase may execute for a tampered archive"
    );
    assert!(
        !root
            .path()
            .join("blobs")
            .join(bundle.blobs[0].locator.hash.to_string(),)
            .exists(),
        "tampered blob must never land in the isolated root"
    );
}

// WORK_UNIT_CASE: 1873x/degraded-run
#[test]
fn runner_degraded_run_stays_canonical_only() {
    let mut input = full_input();
    input.backup_id = "backup-1873x-degraded".to_owned();
    input.class = BackupClass::CanonicalOnlyDegraded;
    input.ors_snapshot = None;
    input.blobs = Vec::new();
    input.export_fence.blob_reachability_manifest = Vec::new();
    input.canonical_events = Vec::new();
    input.projections = Vec::new();
    input.receipts = Vec::new();
    input.export_fence.event_range = EventRange {
        first_sequence: None,
        last_sequence: None,
        count: 0,
    };
    let bundle = BackupBundle::build(input).expect("degraded bundle builds");
    let root = IsolatedRoot::create("degraded-1873x").expect("isolated root creates");
    let outcome = execute_isolated_restore(
        &bundle,
        target_context(),
        epoch(2),
        ResourceGeneration::new(2).expect("generation"),
        &root,
        None,
    )
    .expect("degraded run completes");
    assert!(outcome.receipt.canonical_only);
    assert!(!outcome.receipt.operational_recovery_ready);
    assert!(!outcome.receipt.cutover_performed);
    assert!(outcome.suspended_entries.is_empty());
    assert!(!outcome.phase_log.contains(&"suspend-ors".to_owned()));
    assert_eq!(outcome.phase_log[0], "prepare");
    assert_eq!(outcome.phase_log[1], "purge");
}

// WORK_UNIT_CASE: 1873x/key-gate
#[test]
fn runner_requires_key_coverage_for_blob_archives() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let root = IsolatedRoot::create("keygate-1873x").expect("isolated root creates");
    assert!(
        matches!(
            execute_isolated_restore(
                &bundle,
                target_context(),
                epoch(2),
                ResourceGeneration::new(2).expect("generation"),
                &root,
                None,
            ),
            Err(BackupError::MissingRecoveryComponent("blob_key_material"))
        ),
        "blob archives without key coverage must fail"
    );
}

// WORK_UNIT_CASE: 1873x/stale-lineage
#[test]
fn runner_refuses_stale_lineage_before_any_effect() {
    let bundle = BackupBundle::build(full_input()).expect("full bundle builds");
    let stale = RestoreContext {
        target_id: "target-1873x".to_owned(),
        target_authority_epoch: epoch(1),
        target_resource_generation: ResourceGeneration::new(2).expect("generation"),
    };
    let root = IsolatedRoot::create("stale-1873x").expect("isolated root creates");
    let manifest = key_manifest();
    assert!(
        matches!(
            execute_isolated_restore(
                &bundle,
                stale,
                epoch(1),
                ResourceGeneration::new(2).expect("generation"),
                &root,
                Some(&manifest),
            ),
            Err(BackupError::StaleRestoreLineage)
        ),
        "stale lineage must be refused"
    );
    // No phase ran: the journal has no completed record and no phase receipts.
    assert!(!root.path().join("phase-receipts").exists());
}
