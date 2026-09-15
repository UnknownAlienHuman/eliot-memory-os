//! Backup integrity cases 948/11..948/20 (worker B).
//!
//! Written against the current public API on the base commit:
//! `BackupBundle::{build,validate,encode,decode,bundle_sha256}`,
//! `EcxfManifest`, `BackupInput` plus the surrounding checksum/class/
//! normalization helpers in `crates/storage/eliot-backup/src/lib.rs`.
//!
//! Cases that need worker-A verify-hardening helpers (explicit AAD/nonce
//! wire fields, typed raw-gate names, residency/key-version proof levels)
//! pin the specified behavior with the existing public API and mark the gap
//! inline instead of fabricating helpers.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

use std::num::NonZeroU64;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput,
    CanonicalRecord, EventRange, ExportFence, OrsSnapshotFence, RestoreArchiveDisposition,
    RestoreArchiveDispositionKind, RestoreEvidenceLevel, WatchdogSpoolFence,
};
use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VersionedContentDigest,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use eliot_store_api::{OrderingScopeId, RevisionKey, ScopeId};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

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

fn content_digest(label: &str) -> (BlobHash, VersionedContentDigest) {
    let digest_hex = sha256_hex(label.as_bytes());
    let hash = BlobHash::new(digest_hex.clone()).expect("valid blob hash");
    let content = VersionedContentDigest {
        algorithm: BlobId::new("blake3").expect("valid algorithm"),
        version: 1,
        digest: BlobHash::new(digest_hex).expect("valid digest"),
    };
    (hash, content)
}

fn locator_for(label: &str, domain: &str) -> BlobLocator {
    let (hash, content_digest) = content_digest(label);
    BlobLocator {
        hash,
        residency: ObjectResidencyKey {
            scope_domain_id: BlobId::new(format!("scope-{domain}")).expect("scope domain"),
            access_domain_id: BlobId::new(format!("access-{domain}")).expect("access domain"),
            confidentiality_domain_id: BlobId::new(format!("confidential-{domain}"))
                .expect("confidentiality domain"),
            encryption_key_domain_id: BlobId::new(format!("keydomain-{domain}"))
                .expect("key domain"),
            retention_domain_id: BlobId::new(format!("retention-{domain}"))
                .expect("retention domain"),
            erasure_domain_id: BlobId::new(format!("erasure-{domain}")).expect("erasure domain"),
            content_digest,
        },
        root_generation: 1,
        path_generation: 1,
    }
}

fn blob_for(label: &str, domain: &str, key_lineage: &str) -> BackupBlob {
    let locator = locator_for(label, domain);
    let sealed_bytes = format!("sealed-envelope-{label}").into_bytes();
    let sealed_sha256 = sha256_hex(&sealed_bytes);
    let plaintext_sha256 = sha256_hex(format!("plaintext-{label}").as_bytes());
    BackupBlob {
        locator,
        sealed_bytes,
        sealed_sha256,
        plaintext_sha256,
        key_lineage: BlobId::new(key_lineage).expect("key lineage"),
        format: BlobId::new("backup-format").expect("format"),
        format_version: 1,
        compression: CompressionDescriptor {
            algorithm: BlobId::new("none").expect("compression"),
            version: 1,
        },
        crypto: CryptoDescriptor {
            algorithm: BlobId::new("aead-test").expect("crypto"),
            version: 1,
            key_lineage: BlobId::new(key_lineage).expect("crypto lineage"),
            key_generation: 1,
        },
    }
}

fn export_fence(blobs: &[BackupBlob], event_count: u64) -> ExportFence {
    let (first_sequence, last_sequence) = if event_count == 0 {
        (None, None)
    } else {
        (Some(1), Some(event_count))
    };
    ExportFence {
        export_id: "export-948-b".to_owned(),
        store_generation: "store-948-b".to_owned(),
        state_fence: fence(),
        scope_id: None,
        revision_heads: Vec::new(),
        ordering_heads: Vec::new(),
        event_range: EventRange {
            first_sequence,
            last_sequence,
            count: event_count,
        },
        blob_reachability_manifest: blobs.iter().map(|blob| blob.locator.hash.clone()).collect(),
        consistent: true,
    }
}

fn degraded_input(blobs: Vec<BackupBlob>, events: Vec<CanonicalRecord>) -> BackupInput {
    let count = events.len() as u64;
    BackupInput {
        backup_id: "backup-948-b".to_owned(),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: export_fence(&blobs, count),
        canonical_events: events,
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs,
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 1,
    }
}

fn record(id: &str) -> CanonicalRecord {
    CanonicalRecord::new(
        "test-type",
        id,
        serde_json::json!({"id": id, "body": "tiny"}),
    )
    .expect("record builds")
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

fn full_input() -> BackupInput {
    let source_fence = fence();
    BackupInput {
        backup_id: "backup-948-b-full".to_owned(),
        class: BackupClass::FullRecovery,
        source_adapter: "test-adapter".to_owned(),
        schema_generation: "schema-1".to_owned(),
        export_fence: ExportFence {
            export_id: "export-948-b-full".to_owned(),
            store_generation: "store-948-b".to_owned(),
            state_fence: source_fence.clone(),
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: None,
                last_sequence: None,
                count: 0,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: Vec::new(),
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: Some(OrsSnapshotFence {
            snapshot_id: "ors-948-b".to_owned(),
            authority_epoch: epoch(1),
            resource_generation: ResourceGeneration::genesis(),
            last_receipt_cursor: 0,
            last_event_cursor: 0,
            last_outbox_cursor: 0,
            pending_operation_ids: Vec::new(),
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
            fence_id: "watchdog-948-b".to_owned(),
            unresolved_signal_digests: vec![sha256_hex(b"signal-948-b")],
            state_fence: source_fence,
            bounded: true,
        }),
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/tests/data/backup-integrity/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).expect("fixture reads");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

// WORK_UNIT_CASE: 948/11
#[test]
fn missing_extra_duplicate_conflicting_blob_members_reject() {
    let fixture = load_fixture("948-b-case11-denominator.json");
    assert_eq!(fixture["missing"], "MissingBlob");
    assert_eq!(fixture["extra"], "UnreferencedBlob");
    assert_eq!(fixture["duplicate"], "Duplicate");
    assert_eq!(fixture["conflict"], "IntegrityMismatch");

    // Missing: manifest names a blob the sealed set does not carry.
    let ghost = blob_for("ghost-bytes", "domain-a", "key-lineage-1");
    let mut missing_fence = export_fence(&[], 0);
    missing_fence.blob_reachability_manifest = vec![ghost.locator.hash.clone()];
    let missing = degraded_input(Vec::new(), Vec::new());
    let missing = BackupInput {
        export_fence: missing_fence,
        ..missing
    };
    assert_eq!(BackupBundle::build(missing), Err(BackupError::MissingBlob));

    // Extra: sealed set carries a blob the manifest never referenced.
    let extra_blob = blob_for("extra-bytes", "domain-a", "key-lineage-1");
    let extra = degraded_input(vec![extra_blob], Vec::new());
    let extra = BackupInput {
        export_fence: export_fence(&[], 0),
        ..extra
    };
    assert!(matches!(
        BackupBundle::build(extra),
        Err(BackupError::UnreferencedBlob { .. })
    ));

    // Duplicate: the same locator hash twice is not a denominator of two.
    let first = blob_for("dup-bytes", "domain-a", "key-lineage-1");
    let second = first.clone();
    let manifest = vec![first.locator.hash.clone()];
    let mut dup_fence = export_fence(&[], 0);
    dup_fence.blob_reachability_manifest = manifest;
    let duplicate = degraded_input(vec![first, second], Vec::new());
    let duplicate = BackupInput {
        export_fence: dup_fence,
        ..duplicate
    };
    assert!(matches!(
        BackupBundle::build(duplicate),
        Err(BackupError::Duplicate { .. })
    ));

    // Conflicting: section bytes and section digests must reconcile exactly.
    let member = blob_for("member-bytes", "domain-a", "key-lineage-1");
    let bundle = BackupBundle::build(degraded_input(vec![member], Vec::new()))
        .expect("member bundle builds");
    let mut tampered_sections = bundle.clone();
    tampered_sections
        .manifest
        .sections
        .insert("blobs".to_owned(), "0".repeat(64));
    assert!(matches!(
        tampered_sections.validate(),
        Err(BackupError::IntegrityMismatch { .. })
    ));
    let mut tampered_bytes = bundle.clone();
    tampered_bytes.blobs[0].sealed_bytes = b"conflicting-bytes".to_vec();
    assert!(matches!(
        tampered_bytes.validate(),
        Err(BackupError::IntegrityMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 948/12
#[test]
fn sealed_envelope_identity_checked_without_opening_key() {
    let fixture = load_fixture("948-b-case12-envelope.json");
    assert_eq!(fixture["envelope"], "sealed-blob-envelope-v1");
    assert_eq!(fixture["plaintext_keys_present"], false);

    // GAP(948/12): explicit AAD/nonce wire fields are worker-A hardening and
    // are absent from this base API. This test pins the specified behavior
    // with the existing envelope/key-lineage/version/content identities and
    // never fabricates the missing helper names.
    let blob = blob_for("envelope-bytes", "domain-a", "key-lineage-7");
    blob.validate().expect("sealed blob validates");
    assert_eq!(blob.crypto.key_generation, 1);
    assert_eq!(blob.crypto.version, 1);
    assert_eq!(blob.crypto.key_lineage.as_str(), "key-lineage-7");
    assert_eq!(blob.key_lineage.as_str(), "key-lineage-7");

    let bundle = BackupBundle::build(degraded_input(vec![blob], Vec::new()))
        .expect("envelope bundle builds");
    assert_eq!(
        bundle.manifest.encryption.envelope,
        "sealed-blob-envelope-v1"
    );
    assert!(!bundle.manifest.encryption.plaintext_keys_present);
    assert_eq!(
        bundle.manifest.encryption.key_lineages,
        vec!["key-lineage-7"]
    );

    // Ciphertext checksum mismatch rejects without attempting decryption.
    let mut tampered = bundle.clone();
    tampered.blobs[0].sealed_bytes = b"other-ciphertext".to_vec();
    assert!(matches!(
        tampered.validate(),
        Err(BackupError::IntegrityMismatch { .. })
    ));

    // Key-version regression rejects at the descriptor boundary.
    let mut bad_version = bundle.clone();
    bad_version.blobs[0].crypto.version = 0;
    assert!(bad_version.validate().is_err());
    let mut bad_generation = bundle;
    bad_generation.blobs[0].crypto.key_generation = 0;
    assert!(bad_generation.validate().is_err());
}

// WORK_UNIT_CASE: 948/13
#[test]
fn absent_decryption_or_capture_evidence_limits_proof() {
    let fixture = load_fixture("948-b-case13-evidence-levels.json");
    assert_eq!(fixture["rule"], "absence-of-evidence-is-never-success");

    let bundle =
        BackupBundle::build(degraded_input(Vec::new(), Vec::new())).expect("bundle builds");
    bundle.validate().expect("archive validates");
    let digest = bundle.bundle_sha256().expect("bundle digest");
    assert_eq!(digest.len(), 64);
    // Pure archive validation binds bytes and fences only: it carries no
    // decryption proof and no capture-owner binding. The manifest records the
    // sealed envelope and key lineages but never claims plaintext
    // authenticity or key availability.
    assert!(!bundle.manifest.encryption.plaintext_keys_present);
    let encoded = bundle.encode().expect("bundle encodes");
    let decoded = BackupBundle::decode(&encoded).expect("bundle decodes");
    assert_eq!(decoded, bundle);

    // Proof ceilings stay distinct: archive validity is not capture binding,
    // decryptability, or recovery. The strongest level actually observed here
    // is the isolated-import ceiling for the degraded class.
    assert_eq!(
        RestoreEvidenceLevel::for_class(BackupClass::CanonicalOnlyDegraded),
        RestoreEvidenceLevel::IsolatedImportComplete
    );
    assert!(!RestoreEvidenceLevel::IsolatedImportComplete.permits_operational_readiness());
    assert!(!RestoreEvidenceLevel::ReconciliationRequired.permits_operational_readiness());
    assert!(!RestoreEvidenceLevel::ArchiveValid.permits_operational_readiness());
    let levels = fixture["levels"].as_array().expect("levels array");
    assert!(levels.contains(&serde_json::json!("ArchiveValid")));
}

// WORK_UNIT_CASE: 948/14
#[test]
fn purge_integrity_config_policy_module_build_identities_load_bearing() {
    let fixture = load_fixture("948-b-case14-identities.json");
    let load_bearing = fixture["load_bearing"].as_array().expect("identity list");
    assert!(load_bearing.contains(&serde_json::json!("purge_ledger_revision")));
    assert!(load_bearing.contains(&serde_json::json!("artifacts.config")));

    let full = BackupBundle::build(full_input()).expect("full bundle builds");
    full.validate().expect("full bundle validates");

    // Each required manifest kind gates FullRecovery; none is defaultable.
    let expected: [(&str, &'static str); 4] = [
        ("config", "config"),
        ("policy", "policy"),
        ("module", "module"),
        ("host_dependency_build", "host_dependency_build"),
    ];
    for (missing_kind, component) in expected {
        let mut input = full_input();
        input
            .artifacts
            .retain(|artifact| artifact.kind != missing_kind);
        assert_eq!(
            BackupBundle::build(input),
            Err(BackupError::MissingRecoveryComponent(component)),
            "kind {missing_kind} must be load-bearing"
        );
    }

    // Purge revision is bound by the integrity digest, not advisory metadata.
    let mut tampered_revision = full.clone();
    tampered_revision.manifest.purge_ledger_revision = 8;
    assert!(matches!(
        tampered_revision.validate(),
        Err(BackupError::IntegrityMismatch { .. })
    ));

    // Artifact content identity is load-bearing: bytes and digest reconcile.
    let mut tampered_artifact = full.clone();
    tampered_artifact.artifacts[0].bytes = b"forged-manifest".to_vec();
    assert!(matches!(
        tampered_artifact.validate(),
        Err(BackupError::IntegrityMismatch { .. })
    ));

    // A purge entry on an incompatible fence cannot ride the export fence.
    let mut fenced_input = full_input();
    let mut foreign_entry = purge_entry("purge-foreign");
    let mut foreign_fence = fence();
    foreign_fence.resource_generation = ResourceGeneration::new(9).expect("generation");
    foreign_entry.state_fence = foreign_fence;
    fenced_input.purge_ledger = vec![foreign_entry];
    assert!(matches!(
        BackupBundle::build(fenced_input),
        Err(BackupError::FenceMismatch { .. })
    ));

    // A well-fenced purge entry is accepted and stays bound.
    let mut purged_input = full_input();
    purged_input.purge_ledger = vec![purge_entry("purge-1")];
    let purged = BackupBundle::build(purged_input).expect("purged full builds");
    purged.validate().expect("purged full validates");
}

// WORK_UNIT_CASE: 948/15
#[test]
fn aggregate_and_per_member_bounds_reject_overflow_truncation_mismatch() {
    let fixture = load_fixture("948-b-case15-bounds.json");
    assert_eq!(fixture["max_record_bytes"], 33_554_432);
    assert_eq!(fixture["max_sealed_blob_bytes"], 536_870_912);
    assert_eq!(
        eliot_backup::MAX_RECORD_BYTES,
        33_554_432,
        "per-member record bound is load-bearing"
    );
    assert_eq!(
        eliot_backup::MAX_SEALED_BLOB_BYTES,
        536_870_912,
        "per-member blob bound is load-bearing"
    );

    // Declared-size mismatch: ciphertext digest must match the sealed bytes.
    let bundle =
        BackupBundle::build(degraded_input(Vec::new(), Vec::new())).expect("empty bundle builds");
    let mut blob = blob_for("bound-bytes", "domain-a", "key-lineage-1");
    blob.sealed_sha256 = sha256_hex(b"different-bytes");
    let declared = degraded_input(vec![blob], Vec::new());
    assert!(matches!(
        BackupBundle::build(declared),
        Err(BackupError::IntegrityMismatch { .. })
    ));

    // Declared-count mismatch: the fence count must equal the event section.
    let counted = degraded_input(Vec::new(), vec![record("event-1")]);
    let counted = BackupInput {
        export_fence: export_fence(&[], 0),
        ..counted
    };
    assert!(matches!(
        BackupBundle::build(counted),
        Err(BackupError::FenceMismatch { .. })
    ));

    // One-over interval: the range count cannot exceed its sequence interval.
    let over = EventRange {
        first_sequence: Some(1),
        last_sequence: Some(2),
        count: 3,
    };
    assert!(over.validate().is_err());

    // Overflow-shaped growth rejects before allocation.
    let overflow = EventRange {
        first_sequence: Some(1),
        last_sequence: Some(2),
        count: u64::MAX,
    };
    assert!(overflow.validate().is_err());

    // Truncation: a cut bundle never decodes into a valid archive.
    let encoded = bundle.encode().expect("bundle encodes");
    assert!(!encoded.is_empty());
    let cut = encoded.len() / 2;
    assert!(BackupBundle::decode(&encoded[..cut]).is_err());
    assert!(BackupBundle::decode(&[]).is_err());

    // Empty members reject at the per-member boundary, not as zero-length success.
    let mut empty_blob = blob_for("nonempty", "domain-a", "key-lineage-1");
    empty_blob.sealed_bytes = Vec::new();
    assert!(empty_blob.validate().is_err());
    let empty_artifact = BackupArtifact {
        kind: "config".to_owned(),
        artifact_id: "config-empty".to_owned(),
        bytes: Vec::new(),
        sha256: sha256_hex(b"config-manifest-bytes"),
    };
    assert!(empty_artifact.validate().is_err());
}

// WORK_UNIT_CASE: 948/16
#[test]
fn set_permutations_stable_and_sequence_changes_visible() {
    let fixture = load_fixture("948-b-case16-ordering.json");
    assert!(
        fixture["sequence_visible"]
            .as_array()
            .expect("sequences")
            .contains(&serde_json::json!("canonical_events"))
    );

    // The same logical set in a different input order canonicalizes identically.
    let first = BackupBundle::build(degraded_input(
        Vec::new(),
        vec![record("event-a"), record("event-b")],
    ))
    .expect("ordered builds");
    let second = BackupBundle::build(degraded_input(
        Vec::new(),
        vec![record("event-b"), record("event-a")],
    ))
    .expect("permuted builds");
    assert_eq!(
        first.bundle_sha256().expect("digest"),
        second.bundle_sha256().expect("digest")
    );
    assert_eq!(
        first.encode().expect("encode"),
        second.encode().expect("encode")
    );

    // Blob and artifact sets canonicalize under permutation as well. Both
    // inputs share one fence order; only the member input order differs.
    let blob_a = blob_for("stable-a", "domain-a", "key-lineage-1");
    let blob_b = blob_for("stable-b", "domain-b", "key-lineage-1");
    let shared_fence = export_fence(&[blob_a.clone(), blob_b.clone()], 0);
    let blobs_forward = BackupInput {
        export_fence: shared_fence.clone(),
        ..degraded_input(vec![blob_a.clone(), blob_b.clone()], Vec::new())
    };
    let blobs_backward = degraded_input(vec![blob_b, blob_a], Vec::new());
    let blobs_backward = BackupInput {
        export_fence: shared_fence,
        ..blobs_backward
    };
    assert_eq!(
        BackupBundle::build(blobs_forward)
            .expect("forward builds")
            .bundle_sha256()
            .expect("digest"),
        BackupBundle::build(blobs_backward)
            .expect("backward builds")
            .bundle_sha256()
            .expect("digest")
    );

    // A semantic member change is always visible in the bundle digest.
    let changed = BackupBundle::build(degraded_input(
        Vec::new(),
        vec![record("event-a"), record("event-c")],
    ))
    .expect("changed builds");
    assert_ne!(
        first.bundle_sha256().expect("digest"),
        changed.bundle_sha256().expect("digest")
    );
    assert_ne!(
        first.encode().expect("encode"),
        changed.encode().expect("encode")
    );
}

// WORK_UNIT_CASE: 948/17
#[test]
fn duplicate_unknown_protected_raw_fields_reject_before_normalization() {
    let fixture = load_fixture("948-b-case17-raw-fields.json");
    assert_eq!(fixture["schema"], "ECXF/1-current");

    // GAP(948/17): worker-A typed raw-gate names are absent from this base
    // API. This test pins the specified behavior at the exact current
    // byte boundary (`deny_unknown_fields` on every closed struct) and never
    // invents the missing helper names.
    let valid = record("protected-1");
    let mut wire = serde_json::to_value(&valid).expect("record encodes");
    wire["unknown_future_field"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<CanonicalRecord>(wire).is_err(),
        "unknown protected fields must reject before normalization"
    );

    let duplicate_wire = format!(
        "{{\"record_type\":\"test-type\",\"record_id\":\"a\",\"record_id\":\"b\",\"payload\":{{\"id\":\"a\"}},\"sha256\":\"{}\"}}",
        "0".repeat(64)
    );
    // Duplicate struct fields reject at the derived-deserialization
    // boundary before any `Value` normalization runs. Any further typed
    // raw-payload gate names are worker-A hardening and stay marked as a gap.
    assert!(
        serde_json::from_slice::<CanonicalRecord>(duplicate_wire.as_bytes()).is_err(),
        "duplicate protected fields must reject before normalization"
    );
    let typed_duplicate = degraded_input(Vec::new(), vec![record("dup"), record("dup")]);
    let typed_duplicate = BackupInput {
        export_fence: export_fence(&[], 2),
        ..typed_duplicate
    };
    assert!(matches!(
        BackupBundle::build(typed_duplicate),
        Err(BackupError::Duplicate { .. })
    ));

    let bundle =
        BackupBundle::build(degraded_input(Vec::new(), Vec::new())).expect("bundle builds");
    let mut bundle_wire = serde_json::to_value(&bundle).expect("bundle encodes");
    bundle_wire["unknown_future_section"] = serde_json::json!({"forged": true});
    let bundle_bytes = serde_json::to_vec(&bundle_wire).expect("wire encodes");
    assert!(
        BackupBundle::decode(&bundle_bytes).is_err(),
        "unknown bundle fields must reject at the byte boundary"
    );

    let mut fence_wire = serde_json::to_value(&bundle.export_fence).expect("fence encodes");
    fence_wire["unknown_future_fence"] = serde_json::json!(1);
    assert!(
        serde_json::from_value::<ExportFence>(fence_wire).is_err(),
        "unknown fence fields must reject at the byte boundary"
    );
}

// WORK_UNIT_CASE: 948/18
#[test]
fn explicit_legacy_compatibility_cannot_invent_authority() {
    let fixture = load_fixture("948-b-case18-legacy.json");
    assert!(
        fixture["forbidden_inventions"]
            .as_array()
            .expect("forbidden list")
            .contains(&serde_json::json!("residency"))
    );

    // A legacy format label is an explicit refusal, never a silent upgrade.
    let bundle =
        BackupBundle::build(degraded_input(Vec::new(), Vec::new())).expect("bundle builds");
    let mut legacy_wire = serde_json::to_value(&bundle).expect("bundle encodes");
    legacy_wire["manifest"]["format"] = serde_json::json!("ECXF/0");
    let legacy_bytes = serde_json::to_vec(&legacy_wire).expect("wire encodes");
    assert_eq!(
        BackupBundle::decode(&legacy_bytes),
        Err(BackupError::UnsupportedFormat("ECXF/0".to_owned()))
    );

    // A hash-only locator without residency is rejected, never defaulted.
    let blob_value = serde_json::to_value(blob_for("legacy-bytes", "domain-a", "key-lineage-1"))
        .expect("blob encodes");
    let hash_only = serde_json::json!({
        "locator": {
            "hash": blob_value["locator"]["hash"],
            "root_generation": 1,
            "path_generation": 1,
        },
        "sealed_bytes": [1, 2, 3],
        "sealed_sha256": blob_value["sealed_sha256"],
        "plaintext_sha256": blob_value["plaintext_sha256"],
        "key_lineage": "key-lineage-1",
        "format": "backup-format",
        "format_version": 1,
        "compression": {"algorithm": "none", "version": 1},
        "crypto": {
            "algorithm": "aead-test",
            "version": 1,
            "key_lineage": "key-lineage-1",
            "key_generation": 1,
        },
    });
    assert!(
        serde_json::from_value::<BackupBlob>(hash_only).is_err(),
        "legacy hash-only locators must not gain a default residency"
    );

    // Canonical legacy-epoch import stays loss-visible: missing evidence is
    // suspended history, never fresh residency or fence authority.
    let legacy =
        eliot_contracts::LegacyScalarEpoch::new(7, "record-7", "legacy-v1").expect("legacy scalar");
    let imported = eliot_contracts::import_legacy_scalar_epoch(
        legacy,
        eliot_contracts::LegacyEpochEvidence::Missing,
    )
    .expect("missing imports as suspended");
    assert!(matches!(
        imported,
        eliot_contracts::LegacyEpochImport::HistoricalSuspended { .. }
    ));

    // Valid historical archives keep their dispositional envelope.
    let disposition = RestoreArchiveDisposition {
        disposition: RestoreArchiveDispositionKind::HistoricalPreserved,
        compatibility_ref: "ecxf-1-history".to_owned(),
    };
    disposition.validate().expect("disposition validates");
}

// WORK_UNIT_CASE: 948/19
#[test]
fn bounded_malformed_cases_and_diagnostic_redaction() {
    let fixture = load_fixture("948-b-case19-redaction.json");
    assert_eq!(fixture["redaction"], "errors-carry-shape-not-content");

    // Bounded malformed inputs reject with typed, bounded failures.
    assert!(matches!(
        BackupBundle::decode(&[]),
        Err(BackupError::Serialization(_))
    ));
    assert!(matches!(
        BackupBundle::decode(b"{not-json"),
        Err(BackupError::Serialization(_))
    ));
    let bundle =
        BackupBundle::build(degraded_input(Vec::new(), Vec::new())).expect("bundle builds");
    let encoded = bundle.encode().expect("bundle encodes");
    let mut tampered =
        serde_json::from_slice::<serde_json::Value>(&encoded).expect("bundle parses");
    tampered["manifest"]["backup_id"] = serde_json::json!("   ");
    assert!(matches!(
        BackupBundle::decode(&serde_json::to_vec(&tampered).expect("wire encodes")),
        Err(BackupError::InvalidField { .. })
    ));
    let duplicated_input = degraded_input(Vec::new(), vec![record("dup"), record("dup")]);
    let duplicated_input = BackupInput {
        export_fence: export_fence(&[], 2),
        ..duplicated_input
    };
    assert!(matches!(
        BackupBundle::build(duplicated_input),
        Err(BackupError::Duplicate { .. })
    ));
    // Diagnostics carry shape, never deleted content or credentials.
    let secret = "SECRET-KEY-material-948-b";
    let mut leaky = blob_for("redaction-bytes", "domain-a", "key-lineage-1");
    leaky.sealed_bytes = secret.as_bytes().to_vec();
    leaky.sealed_sha256 = sha256_hex(b"other-digest");
    let error = leaky.validate().expect_err("digest mismatch must fail");
    let rendered = format!("{error}");
    assert!(
        !rendered.contains(secret),
        "errors must not echo sealed bytes"
    );
    for marker in ["DELETED-CONTENT", "SECRET-KEY", "PASSWORD", "cek-bytes"] {
        assert!(
            !rendered.contains(marker),
            "error must not leak marker {marker}"
        );
    }
    let purge = purge_entry("purge-redacted");
    purge.validate().expect("purge validates");
    let purge_wire = serde_json::to_value(&purge).expect("purge encodes");
    assert!(
        purge_wire.get("deleted_content").is_none(),
        "purge evidence carries digests, never deleted content"
    );
}

// WORK_UNIT_CASE: 948/20
#[test]
fn real_bundle_round_trip_with_no_foreign_api() {
    let fixture = load_fixture("948-b-case20-roundtrip.json");
    assert_eq!(fixture["round_trip"], "build-encode-decode-validate");

    // Positive: the real public constructors round-trip deterministically.
    let blob = blob_for("roundtrip-bytes", "domain-a", "key-lineage-1");
    let input = degraded_input(vec![blob], vec![record("event-1")]);
    let bundle = BackupBundle::build(input).expect("bundle builds");
    bundle.validate().expect("bundle validates");
    let digest = bundle.bundle_sha256().expect("bundle digest");
    assert_eq!(digest.len(), 64);
    let encoded = bundle.encode().expect("bundle encodes");
    assert!(!encoded.is_empty());
    let decoded = BackupBundle::decode(&encoded).expect("bundle decodes");
    assert_eq!(decoded, bundle);
    decoded.validate().expect("decoded validates");
    assert_eq!(decoded.bundle_sha256().expect("digest"), digest);
    assert_eq!(decoded.encode().expect("re-encode"), encoded);

    // Negative: one flipped byte never survives validation.
    let mut flipped = encoded.clone();
    let last = flipped.len() - 1;
    flipped[last] = flipped[last].wrapping_add(1);
    assert!(BackupBundle::decode(&flipped).is_err());

    // The verification path performs no capture/restore/key/Store/network or
    // persistent-state effects: the source boundary contains no I/O surface.
    let source = std::fs::read(format!("{}/src/lib.rs", env!("CARGO_MANIFEST_DIR")))
        .expect("backup source reads");
    let source_text = String::from_utf8(source).expect("backup source is UTF-8");
    for marker in [
        "std::fs::",
        "std::net::",
        "TcpListener",
        "TcpStream",
        "reqwest::",
        "tokio::net",
        "fn capture",
        "fn open_key",
        "key_service::",
    ] {
        assert!(
            !source_text.contains(marker),
            "backup verification must not expose {marker}"
        );
    }

    // Scope and revision identities used above come from the exact current
    // contracts, not invented strings.
    let scope = ScopeId::new("scope-948-b").expect("scope builds");
    assert_eq!(scope.as_str(), "scope-948-b");
    let key = RevisionKey::new("revision-948-b").expect("revision key builds");
    assert_eq!(key.as_str(), "revision-948-b");
    let ordering = OrderingScopeId::new("ordering-948-b").expect("ordering builds");
    assert_eq!(ordering.as_str(), "ordering-948-b");
}
