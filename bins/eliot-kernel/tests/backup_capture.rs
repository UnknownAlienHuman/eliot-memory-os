//! Kernel cross-owner backup capture tests (issue #959).
//!
//! Every case below drives the REAL coordinator (`KernelBackupCapture` in
//! `bins/eliot-kernel/src/backup_capture.rs`, over the admission / frozen-plan
//! / snapshot-relation / budget / publication vocabulary in
//! `backup_capture_ports.rs`, re-exported through `eliot_kernel::lib.rs`).
//! Owner evidence uses the real `eliot_backup` API (`BackupBundle::build` /
//! `validate` / `encode` / `decode` / `bundle_sha256`) with deterministic
//! finite fixtures under `tests/data/backup-capture/`; publication runs
//! through a test-local in-memory `PublicationPort`.
//!
//! Coordinator bindings under test (see `assemble_input` and `capture`):
//! the archive identity binds the canonical export identity (`backup_id` is
//! the export fence `export_id`, never the caller-supplied input id); the
//! purge revision binds the carried ledger length; class, source adapter, and
//! schema generation cross from the frozen plan; generations bind through the
//! cross-owner fence relation, not string equality. A lost publication
//! response reconciles the SAME operation by identity, never by second
//! publish.

use std::num::NonZeroU64;
use std::path::PathBuf;

use eliot_backup::{
    BackupArtifact, BackupBlob, BackupBundle, BackupClass, BackupError, BackupInput,
    CanonicalRecord, EventRange, ExportFence, HostStateAuditFence, OrsSnapshotFence,
    WatchdogSpoolFence,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence, sha256_hex};
use eliot_kernel::{
    CaptureBudgets, CaptureCallerAuth, CaptureRequest, CaptureState, FrozenCapturePlan,
    KernelBackupCapture, KernelCaptureError, PublicationPort, PublicationReceipt, SnapshotRelation,
    require_capture_admitted,
};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation, PurgeState};
use eliot_store_api::{
    CommitId, EventId, OperationId, OperationManifestDigest, Resubmission, ScopeId,
    TransitionClass, WriteReceipt, WriteReceiptStatus,
};
use serde::Deserialize;
use serde_json::json;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_epoch(sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("nonzero test sequence"),
    )
    .expect("valid test epoch")
}

fn base_fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

// ---------------------------------------------------------------------------
// Deterministic fixtures (tests/data/backup-capture/; filenames frozen).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCursors {
    receipt: u64,
    event: u64,
    outbox: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBudgets {
    max_events: usize,
    max_bytes: usize,
    max_blobs: usize,
    max_artifacts: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureFixture {
    backup_id: String,
    class: String,
    source_adapter: String,
    schema_generation: String,
    scope_id: Option<String>,
    installation_id: String,
    store_generation: String,
    lineage: String,
    capture_times_match: bool,
    cursors: FixtureCursors,
    pending_ops: Vec<String>,
    budgets: FixtureBudgets,
    cancel_requested: bool,
    control_reserve_preserved: bool,
    drift: String,
    expected_state: String,
}

fn read_fixture(name: &str) -> CaptureFixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/backup-capture")
        .join(name);
    let bytes = std::fs::read(&path).expect("fixture file");
    serde_json::from_slice(&bytes).expect("fixture parses")
}

fn fixture_class(fixture: &CaptureFixture) -> BackupClass {
    match fixture.class.as_str() {
        "full_recovery" => BackupClass::FullRecovery,
        "canonical_only_degraded" => BackupClass::CanonicalOnlyDegraded,
        "scope_export" => BackupClass::ScopeExport,
        other => panic!("unknown fixture class {other}"),
    }
}

// ---------------------------------------------------------------------------
// Owner-evidence builders (real `eliot_backup` input shapes).
// ---------------------------------------------------------------------------

fn canonical_event(id: &str) -> CanonicalRecord {
    CanonicalRecord::new("test-event-959", id, json!({"id": id})).expect("canonical event")
}

fn projection_for(id: &str) -> CanonicalRecord {
    CanonicalRecord::new("test-event-959", id, json!({"projection": id}))
        .expect("projection record")
}

fn receipt_for(event_id: &str, operation: &str, fence: &StateFence) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).expect("operation id"),
        idempotency_key: format!("idem-959-{operation}"),
        canonical_request_hash: "a".repeat(64),
        transition_class: TransitionClass::CaptureCandidate,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new(format!("commit-959-{operation}")).expect("commit id")),
        state_fence: fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("cmd-959-{operation}")],
        emitted_event_ids: vec![EventId::new(event_id).expect("event id")],
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new(format!(
            "manifest-959-{operation}"
        ))
        .expect("manifest digest"),
        admission_digest: "e".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        semantic_source_revisions: Vec::new(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    }
}

fn test_blob(suffix: &str, sealed: &[u8]) -> BackupBlob {
    let digest = sha256_hex(sealed);
    serde_json::from_value(json!({
        "locator": {
            "hash": digest,
            "residency": {
                "scope_domain_id": format!("scope-959-{suffix}"),
                "access_domain_id": format!("access-959-{suffix}"),
                "confidentiality_domain_id": format!("conf-959-{suffix}"),
                "encryption_key_domain_id": "key-lineage-959",
                "retention_domain_id": format!("retention-959-{suffix}"),
                "erasure_domain_id": format!("erasure-959-{suffix}"),
                "content_digest": {
                    "algorithm": "blake3",
                    "version": 1,
                    "digest": digest
                }
            },
            "root_generation": 1,
            "path_generation": 1
        },
        "sealed_bytes": sealed.to_vec(),
        "sealed_sha256": sha256_hex(sealed),
        "plaintext_sha256": sha256_hex(b"plaintext-959"),
        "key_lineage": "key-lineage-959",
        "format": "test-format-959",
        "format_version": 1,
        "compression": {"algorithm": "none", "version": 1},
        "crypto": {
            "algorithm": "aead-test-959",
            "version": 1,
            "key_lineage": "key-lineage-959",
            "key_generation": 1
        }
    }))
    .expect("test blob deserializes")
}

fn artifact(kind: &str) -> BackupArtifact {
    let bytes = format!("{kind}-manifest-bytes-959").into_bytes();
    BackupArtifact {
        kind: kind.to_owned(),
        artifact_id: format!("{kind}-959-1"),
        sha256: sha256_hex(&bytes),
        bytes,
    }
}

fn full_artifacts() -> Vec<BackupArtifact> {
    ["config", "policy", "module", "host_dependency_build"]
        .iter()
        .map(|kind| artifact(kind))
        .collect()
}

fn ors_fence(fence: &StateFence, pending: Vec<String>) -> OrsSnapshotFence {
    OrsSnapshotFence {
        snapshot_id: "ors-959".to_owned(),
        authority_epoch: fence.authority_epoch.clone(),
        resource_generation: fence.resource_generation,
        last_receipt_cursor: 1,
        last_event_cursor: 2,
        last_outbox_cursor: 0,
        pending_operation_ids: pending,
        job_checkpoint_ids: vec!["checkpoint-959-1".to_owned()],
        generation_cutover_ids: Vec::new(),
        state_fence: fence.clone(),
        active_authority_restored: false,
    }
}

fn watchdog_fence(fence: &StateFence) -> WatchdogSpoolFence {
    WatchdogSpoolFence {
        fence_id: "watchdog-959".to_owned(),
        unresolved_signal_digests: vec![sha256_hex(b"signal-959")],
        state_fence: fence.clone(),
        bounded: true,
    }
}

fn audit_fence() -> HostStateAuditFence {
    HostStateAuditFence {
        audit_id: "audit-959".to_owned(),
        lineage_digest: "b".repeat(64),
        observed_dispositions: vec!["observed-959".to_owned()],
        active_authority_restored: false,
    }
}

fn purge_entry(fence: &StateFence) -> PurgeLedgerEntry {
    PurgeLedgerEntry {
        purge_id: "purge-959-1".to_owned(),
        subject_ref: "subject-959-1".to_owned(),
        scope: "scope-959".to_owned(),
        purged_locations: vec![PurgeLocation::Blob],
        tombstone_digest: "c".repeat(64),
        state: PurgeState::Purged,
        state_fence: fence.clone(),
        revision: 7,
    }
}

/// FullRecovery denominator per `validate_class_requirements`: coherent
/// canonical export + sealed blobs + coherent ORS snapshot + bounded Watchdog
/// spool + config/policy/module/build manifests + purge revision, gapless.
fn valid_full_input() -> BackupInput {
    let fixture = read_fixture("full-recovery-capture.json");
    assert_eq!(fixture.expected_state, "complete_full_recovery");
    assert_eq!(fixture_class(&fixture), BackupClass::FullRecovery);
    let fence = base_fence();
    let blob = test_blob("a", b"sealed-envelope-959-1");
    let blob_hash = blob.locator.hash.clone();
    BackupInput {
        backup_id: fixture.backup_id.clone(),
        class: BackupClass::FullRecovery,
        source_adapter: fixture.source_adapter.clone(),
        schema_generation: fixture.schema_generation.clone(),
        export_fence: ExportFence {
            export_id: "export-959-full".to_owned(),
            installation_id: fixture.installation_id.clone(),
            schema_generation: fixture.schema_generation.clone(),
            store_generation: fixture.store_generation.clone(),
            state_fence: fence.clone(),
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: Some(1),
                last_sequence: Some(2),
                count: 2,
            },
            blob_reachability_manifest: vec![blob_hash],
            consistent: true,
        },
        canonical_events: vec![
            canonical_event("event-959-1"),
            canonical_event("event-959-2"),
        ],
        projections: vec![projection_for("event-959-1")],
        receipts: vec![receipt_for("event-959-1", "op-959-1", &fence)],
        blobs: vec![blob],
        purge_ledger: vec![purge_entry(&fence)],
        ors_snapshot: Some(ors_fence(&fence, fixture.pending_ops.clone())),
        artifacts: full_artifacts(),
        watchdog_spool: Some(watchdog_fence(&fence)),
        host_audit: Some(audit_fence()),
        missing_features: Vec::new(),
        purge_ledger_revision: 7,
    }
}

fn degraded_input() -> BackupInput {
    let fixture = read_fixture("canonical-only-degraded.json");
    assert_eq!(fixture.expected_state, "complete_canonical_only_degraded");
    let fence = base_fence();
    BackupInput {
        backup_id: fixture.backup_id.clone(),
        class: BackupClass::CanonicalOnlyDegraded,
        source_adapter: fixture.source_adapter.clone(),
        schema_generation: fixture.schema_generation.clone(),
        export_fence: ExportFence {
            export_id: "export-959-degraded".to_owned(),
            installation_id: fixture.installation_id.clone(),
            schema_generation: fixture.schema_generation.clone(),
            store_generation: fixture.store_generation.clone(),
            state_fence: fence.clone(),
            scope_id: None,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: Some(1),
                last_sequence: Some(1),
                count: 1,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: vec![canonical_event("event-959-1")],
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 0,
    }
}

fn scope_input() -> BackupInput {
    let fixture = read_fixture("scope-export.json");
    assert_eq!(fixture.expected_state, "complete_scope_export");
    let fence = base_fence();
    BackupInput {
        backup_id: fixture.backup_id.clone(),
        class: BackupClass::ScopeExport,
        source_adapter: fixture.source_adapter.clone(),
        schema_generation: fixture.schema_generation.clone(),
        export_fence: ExportFence {
            export_id: "export-959-scope".to_owned(),
            installation_id: fixture.installation_id.clone(),
            schema_generation: fixture.schema_generation.clone(),
            store_generation: fixture.store_generation.clone(),
            state_fence: fence.clone(),
            scope_id: Some(
                ScopeId::new(fixture.scope_id.clone().expect("scope fixture")).expect("scope"),
            ),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            event_range: EventRange {
                first_sequence: Some(1),
                last_sequence: Some(1),
                count: 1,
            },
            blob_reachability_manifest: Vec::new(),
            consistent: true,
        },
        canonical_events: vec![canonical_event("event-959-1")],
        projections: Vec::new(),
        receipts: Vec::new(),
        blobs: Vec::new(),
        purge_ledger: Vec::new(),
        ors_snapshot: None,
        artifacts: Vec::new(),
        watchdog_spool: None,
        host_audit: None,
        missing_features: Vec::new(),
        purge_ledger_revision: 0,
    }
}

// ---------------------------------------------------------------------------
// Real-coordinator shared doubles: admitted caller, frozen plan, request,
// in-memory publication port.
// ---------------------------------------------------------------------------

fn admitted_caller() -> CaptureCallerAuth {
    CaptureCallerAuth {
        principal: "test-principal-959".to_owned(),
        capability: "backup-capture".to_owned(),
        admitted: true,
    }
}

fn generous_budgets() -> CaptureBudgets {
    CaptureBudgets {
        max_pages_per_owner: 1000,
        max_bytes_per_owner: 1_000_000,
        max_bytes_total: 10_000_000,
        max_work_items: 10_000,
        max_duration_ms: 60_000,
    }
}

/// Builds the real `CaptureRequest` from accepted owner evidence: the frozen
/// plan carries the input class/source/schema (scope only for `ScopeExport`,
/// bound from the export fence), and every evidence section crosses cloned.
fn to_request(input: &BackupInput, suspended: u64) -> CaptureRequest {
    let scope_id = match input.class {
        BackupClass::ScopeExport => input
            .export_fence
            .scope_id
            .as_ref()
            .map(|scope| scope.as_str().to_owned()),
        _ => None,
    };
    CaptureRequest {
        caller: admitted_caller(),
        plan: FrozenCapturePlan {
            class: input.class,
            scope_id,
            source_adapter: input.source_adapter.clone(),
            schema_generation: input.schema_generation.clone(),
            build_digest: "a".repeat(64),
            policy_digest: "b".repeat(64),
            budgets: generous_budgets(),
        },
        export_fence: input.export_fence.clone(),
        canonical_events: input.canonical_events.clone(),
        projections: input.projections.clone(),
        receipts: input.receipts.clone(),
        blobs: input.blobs.clone(),
        purge_ledger: input.purge_ledger.clone(),
        ors_snapshot: input.ors_snapshot.clone(),
        suspended_count: suspended,
        artifacts: input.artifacts.clone(),
        watchdog_spool: input.watchdog_spool.clone(),
        host_audit: input.host_audit.clone(),
    }
}

fn coordinator() -> KernelBackupCapture {
    KernelBackupCapture::bind(std::env::temp_dir().join("eliot-959-capture"))
}

/// Mirrors the coordinator's `assemble_input` binding for independent digest
/// recomputation: archive identity from the export fence, class/source/schema
/// from the frozen plan, purge revision from the carried ledger length.
fn coordinator_input(request: &CaptureRequest) -> BackupInput {
    BackupInput {
        backup_id: request.export_fence.export_id.clone(),
        class: request.plan.class,
        source_adapter: request.plan.source_adapter.clone(),
        schema_generation: request.plan.schema_generation.clone(),
        export_fence: request.export_fence.clone(),
        canonical_events: request.canonical_events.clone(),
        projections: request.projections.clone(),
        receipts: request.receipts.clone(),
        blobs: request.blobs.clone(),
        purge_ledger: request.purge_ledger.clone(),
        ors_snapshot: request.ors_snapshot.clone(),
        artifacts: request.artifacts.clone(),
        watchdog_spool: request.watchdog_spool.clone(),
        host_audit: request.host_audit.clone(),
        missing_features: Vec::new(),
        purge_ledger_revision: if request.purge_ledger.is_empty() {
            0
        } else {
            request.purge_ledger.len() as u64
        },
    }
}

/// In-memory `PublicationPort`: records every publish attempt with its exact
/// bytes; `drop_first` simulates one lost publication response so the
/// coordinator must reconcile the SAME operation by identity.
#[derive(Debug, Default)]
struct MemPublisher {
    publishes: Vec<(String, String, Vec<u8>)>,
    reconciles: Vec<String>,
    drop_first: bool,
    dropped: bool,
}

impl PublicationPort for MemPublisher {
    fn publish_once(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, KernelCaptureError> {
        self.publishes.push((
            operation_id.to_owned(),
            idempotency_key.to_owned(),
            bytes.to_vec(),
        ));
        if self.drop_first && !self.dropped {
            self.dropped = true;
            return Err(KernelCaptureError::PublicationUnknown(
                operation_id.to_owned(),
            ));
        }
        Ok(PublicationReceipt {
            operation_id: operation_id.to_owned(),
            archive_sha256: sha256_hex(bytes),
            durable: true,
        })
    }

    fn reconcile(&mut self, operation_id: &str) -> Result<PublicationReceipt, KernelCaptureError> {
        self.reconciles.push(operation_id.to_owned());
        self.publishes
            .iter()
            .rev()
            .find(|(operation, _, _)| operation == operation_id)
            .map(|(operation, _, bytes)| PublicationReceipt {
                operation_id: operation.clone(),
                archive_sha256: sha256_hex(bytes),
                durable: true,
            })
            .ok_or_else(|| KernelCaptureError::PublicationUnknown(operation_id.to_owned()))
    }
}

/// Expected member-disposition keys in the coordinator's domain-prefixed
/// shape (`canonical:` / `projection:` / `receipt:` / `blob:` / `purge:` /
/// `artifact:`), sorted for bijection comparison against the report.
fn expected_disposition_keys(input: &BackupInput) -> Vec<String> {
    let mut keys = Vec::new();
    for event in &input.canonical_events {
        keys.push(format!("canonical:{}", event.record_id));
    }
    for projection in &input.projections {
        keys.push(format!("projection:{}", projection.record_id));
    }
    for receipt in &input.receipts {
        keys.push(format!("receipt:{}", receipt.operation_id));
    }
    for blob in &input.blobs {
        keys.push(format!("blob:{}", blob.locator.hash.as_str()));
    }
    for entry in &input.purge_ledger {
        keys.push(format!("purge:{}", entry.purge_id));
    }
    for artifact in &input.artifacts {
        keys.push(format!("artifact:{}", artifact.artifact_id));
    }
    keys.sort();
    keys
}

fn report_disposition_keys(report_keys: &[(String, String)]) -> Vec<String> {
    let mut keys: Vec<String> = report_keys.iter().map(|(key, _)| key.clone()).collect();
    keys.sort();
    keys
}

const CAPTURE_COORDINATOR_SRC: &str = include_str!("../src/backup_capture.rs");
const CAPTURE_PORTS_SRC: &str = include_str!("../src/backup_capture_ports.rs");
const KERNEL_MANIFEST: &str = include_str!("../Cargo.toml");

// WORK_UNIT_CASE: 959/1
#[test]
fn admitted_full_recovery_capture_completes_and_binds_archive() {
    let input = valid_full_input();
    let request = to_request(&input, 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("admitted FullRecovery capture completes");
    assert_eq!(report.state, CaptureState::Complete);
    assert_eq!(report.class, BackupClass::FullRecovery);
    assert!(report.class.is_full_recovery());
    assert_eq!(report.verification_level, "build-validate-publish");
    // The archive identity binds the canonical export identity, never the
    // caller-supplied input id.
    assert_eq!(report.backup_id, "export-959-full");
    assert_eq!(report.operation_id, "capture-publish-export-959-full");
    // Independent recomputation through the real bundle API binds the digest:
    // same export-bound input rebuilds to the same archive sha.
    let rebuilt = BackupBundle::build(coordinator_input(&request)).expect("bundle rebuilds");
    assert_eq!(
        report.archive_sha256,
        rebuilt.bundle_sha256().expect("rebuilt digest")
    );
    // The published bytes decode to the same digest.
    assert_eq!(publisher.publishes.len(), 1, "exactly one publish");
    assert!(publisher.reconciles.is_empty(), "no reconcile needed");
    let published = BackupBundle::decode(&publisher.publishes[0].2).expect("published decodes");
    assert_eq!(
        published.bundle_sha256().expect("published digest"),
        report.archive_sha256
    );
    // No suspended frontier: the receipt identity is the operation itself.
    assert_eq!(report.receipt_identity, Some(report.operation_id.clone()));
    // One `captured` disposition per expected member across every domain.
    assert_eq!(
        report_disposition_keys(&report.member_dispositions),
        expected_disposition_keys(&input)
    );
    assert_eq!(report.member_dispositions.len(), 10);
    assert!(
        report
            .member_dispositions
            .iter()
            .all(|(_, disposition)| disposition == "captured")
    );
    for prefix in [
        "canonical:",
        "projection:",
        "receipt:",
        "blob:",
        "purge:",
        "artifact:",
    ] {
        assert!(
            report
                .member_dispositions
                .iter()
                .any(|(key, _)| key.starts_with(prefix)),
            "dispositions cover {prefix} members"
        );
    }
}

// WORK_UNIT_CASE: 959/2
#[test]
fn explicit_canonical_only_degraded_capture() {
    let input = degraded_input();
    let request = to_request(&input, 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("degraded capture completes explicitly");
    assert_eq!(report.state, CaptureState::Complete);
    assert_eq!(report.class, BackupClass::CanonicalOnlyDegraded);
    assert!(
        !report.class.is_full_recovery(),
        "never advertised as recovery"
    );
    assert_eq!(publisher.publishes.len(), 1);
    // The contrast with verification-only is explicit: the same published
    // archive verifies as degraded (Incomplete), while the capture that
    // produced it is Complete.
    let verified = coordinator()
        .verify_only(&publisher.publishes[0].2, &admitted_caller(), &base_fence())
        .expect("degraded archive verifies");
    assert_eq!(verified.class, BackupClass::CanonicalOnlyDegraded);
    assert_eq!(verified.verification_level, "decode-validate-relation");
    assert!(matches!(verified.state, CaptureState::Incomplete { .. }));
}

// WORK_UNIT_CASE: 959/3
#[test]
fn bounded_scope_export_distinct_from_installation_backup() {
    let input = scope_input();
    let request = to_request(&input, 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("scope export completes");
    assert_eq!(report.state, CaptureState::Complete);
    assert_eq!(report.class, BackupClass::ScopeExport);
    assert_eq!(report.backup_id, "export-959-scope");
    // An installation ORS snapshot inside a scope transfer refuses: a scope
    // export is never an installation backup.
    let mut widened = scope_input();
    widened.ors_snapshot = Some(ors_fence(&base_fence(), Vec::new()));
    assert_eq!(
        BackupBundle::build(widened).unwrap_err(),
        BackupError::UnexpectedRecoveryComponent("ors_snapshot")
    );
}

// WORK_UNIT_CASE: 959/4
#[test]
fn missing_class_capability_refuses_without_downgrade() {
    let mut input = valid_full_input();
    input.ors_snapshot = None;
    let request = to_request(&input, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator().capture(&request, &mut publisher);
    assert_eq!(
        refused.unwrap_err(),
        KernelCaptureError::ClassCapabilityUnsupported {
            class: "full_recovery",
            capability: "ors_snapshot",
        }
    );
    assert!(
        publisher.publishes.is_empty(),
        "no publication on refusal, and no weaker-class report is produced"
    );
}

// WORK_UNIT_CASE: 959/5
#[test]
fn unadmitted_caller_and_bad_scope_refuse_before_publication() {
    // Unadmitted caller: the admission gate refuses first.
    let mut request = to_request(&valid_full_input(), 0);
    request.caller.admitted = false;
    let mut publisher = MemPublisher::default();
    assert_eq!(
        coordinator().capture(&request, &mut publisher).unwrap_err(),
        KernelCaptureError::NotAdmitted
    );
    assert!(publisher.publishes.is_empty(), "zero publishes on refusal");
    // The admission helper agrees directly.
    assert_eq!(
        require_capture_admitted(&request.caller).unwrap_err(),
        KernelCaptureError::NotAdmitted
    );
    assert!(require_capture_admitted(&admitted_caller()).is_ok());
    // Bad scope: a ScopeExport plan without a declared scope is invalid input.
    let mut scoped = to_request(&scope_input(), 0);
    scoped.plan.scope_id = None;
    let mut publisher = MemPublisher::default();
    let refused = coordinator().capture(&scoped, &mut publisher).unwrap_err();
    assert!(
        matches!(
            refused,
            KernelCaptureError::InvalidInput {
                field: "capture.scope_id",
                ..
            }
        ),
        "bad scope refuses as invalid input, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty(), "zero publishes on refusal");
}

// WORK_UNIT_CASE: 959/6
#[test]
fn timestamps_alone_fail_and_no_global_transaction_assumed() {
    let fixture = read_fixture("relation-timestamps-only-fail.json");
    assert_eq!(fixture.expected_state, "refused_relation_incoherent");
    assert!(
        fixture.capture_times_match,
        "capture times match yet the relation must still fail"
    );
    assert_eq!(fixture.cursors.receipt, 9);
    assert_eq!(fixture.cursors.event, 9);
    assert_eq!(fixture.cursors.outbox, 3);
    // A timestamps-only relation built on the fixture cursors refuses even
    // though every carried value is otherwise well-formed.
    let timestamps_only = SnapshotRelation {
        installation_id: "export-959-relation".to_owned(),
        store_generation: fixture.store_generation.clone(),
        authority_lineage: fixture.lineage.clone(),
        receipt_cursor: fixture.cursors.receipt,
        event_cursor: fixture.cursors.event,
        outbox_cursor: fixture.cursors.outbox,
        pending_operation_ids: fixture.pending_ops.clone(),
        pending_operation_hashes: Vec::new(),
        checkpoint_ids: vec!["checkpoint-959-1".to_owned()],
        cutover_ids: Vec::new(),
        spool_signal_digests: Vec::new(),
        spool_gaps: Vec::new(),
        capture_time_ms_per_owner: vec![("canonical-959".to_owned(), 7)],
        fence_compatible: true,
        timestamps_only: true,
    };
    assert!(matches!(
        KernelBackupCapture::validate_snapshot_relation(&timestamps_only).unwrap_err(),
        KernelCaptureError::RelationIncoherent(_)
    ));
    // An all-zero-cursor relation refuses as well: empty cursors prove
    // nothing even with compatible fences and real lineage.
    let zero_cursors = SnapshotRelation {
        timestamps_only: false,
        receipt_cursor: 0,
        event_cursor: 0,
        outbox_cursor: 0,
        ..timestamps_only.clone()
    };
    assert!(matches!(
        KernelBackupCapture::validate_snapshot_relation(&zero_cursors).unwrap_err(),
        KernelCaptureError::RelationIncoherent(_)
    ));
    // A relation with real cursors, lineage, and compatible fences passes.
    let coherent = SnapshotRelation {
        installation_id: "export-959-full".to_owned(),
        store_generation: "store-959".to_owned(),
        authority_lineage: TEST_LINEAGE.to_owned(),
        receipt_cursor: 1,
        event_cursor: 2,
        outbox_cursor: 0,
        timestamps_only: false,
        ..timestamps_only.clone()
    };
    KernelBackupCapture::validate_snapshot_relation(&coherent).expect("coherent relation passes");
    // No global cross-store transaction, barrier, or snapshot service in the
    // coordinator or its ports.
    for src in [CAPTURE_COORDINATOR_SRC, CAPTURE_PORTS_SRC] {
        for banned in [
            "GlobalTransaction",
            "CrossStoreTransaction",
            "stop_the_world",
            "global_quiet",
        ] {
            assert!(!src.contains(banned), "banned {banned} in capture src");
        }
    }
}

// WORK_UNIT_CASE: 959/7
#[test]
fn controlled_concurrent_mutation_excluded_or_represented() {
    // Immutable handle: no pending frontier, capture passes clean with the
    // receipt identity bound to the operation itself.
    let mut clean_input = valid_full_input();
    clean_input.ors_snapshot = Some(ors_fence(&base_fence(), Vec::new()));
    let clean_request = to_request(&clean_input, 0);
    let mut publisher = MemPublisher::default();
    let clean = coordinator()
        .capture(&clean_request, &mut publisher)
        .expect("immutable snapshot capture passes");
    assert_eq!(clean.state, CaptureState::Complete);
    assert_eq!(clean.class, BackupClass::FullRecovery);
    assert_eq!(clean.receipt_identity, Some(clean.operation_id.clone()));
    // Represented frontier: two bounded pending operations recorded exactly;
    // the capture still completes as FullRecovery and the receipt identity
    // carries the suspended marker with the declared count.
    let mut frontier_input = valid_full_input();
    frontier_input.ors_snapshot = Some(ors_fence(
        &base_fence(),
        vec!["op-pending-959-1".to_owned(), "op-pending-959-2".to_owned()],
    ));
    let frontier_request = to_request(&frontier_input, 2);
    let mut publisher = MemPublisher::default();
    let frontier = coordinator()
        .capture(&frontier_request, &mut publisher)
        .expect("frontier-recorded capture passes");
    assert_eq!(frontier.state, CaptureState::Complete);
    assert_eq!(frontier.class, BackupClass::FullRecovery);
    assert_eq!(frontier.receipt_identity, Some("suspended:2".to_owned()));
}

// WORK_UNIT_CASE: 959/8
#[test]
fn generation_schema_continuation_drift_blocks_complete() {
    let drifted = read_fixture("drift-generation.json");
    assert_eq!(drifted.expected_state, "refused_denominator_incomplete");
    assert!(
        !drifted.drift.is_empty(),
        "drift fixture names its drift axis"
    );
    assert_ne!(drifted.store_generation, "store-959");
    // The coordinator binds generations through the cross-owner fence
    // relation, not string equality: a self-consistent generation string
    // alone still captures, but once the export fence advances past the owner
    // snapshots the relation refuses. Both drift axes below carry the fixture
    // values and advance the export epoch while ORS/Watchdog stay behind.
    let advanced = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
    // Generation drift: drifted store generation plus an advanced export
    // fence the owner snapshots no longer share.
    let mut generation_input = valid_full_input();
    generation_input.export_fence.store_generation = drifted.store_generation.clone();
    generation_input.export_fence.state_fence = advanced.clone();
    let generation_request = to_request(&generation_input, 0);
    let mut publisher = MemPublisher::default();
    let generation_blocked = coordinator()
        .capture(&generation_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(
            generation_blocked,
            KernelCaptureError::RelationIncoherent(_)
                | KernelCaptureError::DenominatorIncomplete(_)
                | KernelCaptureError::ArchiveInvalid(_)
                | KernelCaptureError::OwnerEvidenceInvalid(_)
        ),
        "generation drift blocks, got {generation_blocked:?}"
    );
    assert!(publisher.publishes.is_empty());
    // Schema drift similarly: the drifted schema generation rides the same
    // incoherent fence relation and blocks the same way.
    let schema_input = generation_input;
    let mut schema_request = to_request(&schema_input, 0);
    schema_request.plan.schema_generation = drifted.schema_generation.clone();
    let mut publisher = MemPublisher::default();
    let schema_blocked = coordinator()
        .capture(&schema_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(
            schema_blocked,
            KernelCaptureError::RelationIncoherent(_)
                | KernelCaptureError::DenominatorIncomplete(_)
                | KernelCaptureError::ArchiveInvalid(_)
                | KernelCaptureError::OwnerEvidenceInvalid(_)
        ),
        "schema drift blocks, got {schema_blocked:?}"
    );
    assert!(publisher.publishes.is_empty());
}

// WORK_UNIT_CASE: 959/9
#[test]
fn every_member_has_one_disposition() {
    let input = valid_full_input();
    let request = to_request(&input, 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("capture completes");
    // Bijection: exactly one disposition per expected member, no more.
    assert_eq!(
        report_disposition_keys(&report.member_dispositions),
        expected_disposition_keys(&input)
    );
    // A duplicated member identity cannot capture: the denominator refuses
    // the second disposition for the same member.
    let mut duplicated = valid_full_input();
    duplicated
        .canonical_events
        .push(canonical_event("event-959-1"));
    duplicated.export_fence.event_range.count = 3;
    let duplicated_request = to_request(&duplicated, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&duplicated_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(
            refused,
            KernelCaptureError::DenominatorIncomplete(_) | KernelCaptureError::ArchiveInvalid(_)
        ),
        "duplicate member refuses, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty());
}

// WORK_UNIT_CASE: 959/10
#[test]
fn incoherent_boundary_and_count_gap_never_capture() {
    // An exporter that did not prove one coherent boundary cannot capture.
    let mut incoherent = valid_full_input();
    incoherent.export_fence.consistent = false;
    let incoherent_request = to_request(&incoherent, 0);
    let mut publisher = MemPublisher::default();
    assert_eq!(
        coordinator()
            .capture(&incoherent_request, &mut publisher)
            .unwrap_err(),
        KernelCaptureError::RelationIncoherent("export fence is not consistent".to_owned())
    );
    assert!(publisher.publishes.is_empty());
    // An event range claiming more members than carried cannot capture.
    let mut gapped = valid_full_input();
    gapped.export_fence.event_range.count = 5;
    let gapped_request = to_request(&gapped, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&gapped_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(refused, KernelCaptureError::DenominatorIncomplete(_)),
        "count gap refuses, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty());
}

// WORK_UNIT_CASE: 959/11
#[test]
fn references_and_residency_closure_preserved() {
    // Dangling projection reference: a projection without its canonical
    // member fails archive closure.
    let mut dangling = valid_full_input();
    dangling.projections = vec![projection_for("event-missing-959")];
    let dangling_request = to_request(&dangling, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&dangling_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(refused, KernelCaptureError::ArchiveInvalid(_)),
        "dangling projection refuses, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty());
    // Two identical envelopes under one obligation domain never coalesce
    // silently: the denominator gate trips first, before bundle build.
    let mut doubled = valid_full_input();
    let second = test_blob("a", b"sealed-envelope-959-1");
    doubled.blobs.push(second);
    let doubled_request = to_request(&doubled, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&doubled_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(
            refused,
            KernelCaptureError::DenominatorIncomplete(_) | KernelCaptureError::ArchiveInvalid(_)
        ),
        "doubled residency refuses, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty());
    // A duplicated reachability entry for one residency passes the
    // per-member denominator but fails bundle validation as a duplicate.
    let mut duplicated_manifest = valid_full_input();
    let hash = duplicated_manifest.export_fence.blob_reachability_manifest[0].clone();
    duplicated_manifest
        .export_fence
        .blob_reachability_manifest
        .push(hash);
    let duplicated_request = to_request(&duplicated_manifest, 0);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&duplicated_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(refused, KernelCaptureError::ArchiveInvalid(_)),
        "duplicated manifest residency refuses, got {refused:?}"
    );
    assert!(publisher.publishes.is_empty());
    // The valid closure captures: distinct residency domains stay distinct.
    let mut publisher = MemPublisher::default();
    coordinator()
        .capture(&to_request(&valid_full_input(), 0), &mut publisher)
        .expect("closed bundle captures");
    assert_eq!(publisher.publishes.len(), 1);
}

// WORK_UNIT_CASE: 959/12
#[test]
fn suspended_unresolved_distinguished_from_incoherent() {
    // Bounded unresolved operations with coherent evidence still complete as
    // FullRecovery and record the suspended marker; unresolved operations are
    // not archive corruption.
    let request = to_request(&valid_full_input(), 1);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("bounded unresolved with full evidence completes");
    assert_eq!(report.state, CaptureState::Complete);
    assert_eq!(report.class, BackupClass::FullRecovery);
    assert_eq!(report.receipt_identity, Some("suspended:1".to_owned()));
    // Incoherent ORS material blocks through the fence relation, never as
    // corruption: the error vocabulary carries no corruption flavor.
    let mut incoherent = valid_full_input();
    let foreign = StateFence::new(test_epoch(2), ResourceGeneration::genesis());
    incoherent.ors_snapshot = Some(ors_fence(&foreign, vec!["op-pending-959-1".to_owned()]));
    let incoherent_request = to_request(&incoherent, 1);
    let mut publisher = MemPublisher::default();
    let refused = coordinator()
        .capture(&incoherent_request, &mut publisher)
        .unwrap_err();
    assert!(
        matches!(
            refused,
            KernelCaptureError::RelationIncoherent(_) | KernelCaptureError::ArchiveInvalid(_)
        ),
        "incoherent ORS blocks, got {refused:?}"
    );
    assert!(
        !format!("{refused}").contains("corrupt"),
        "unresolved operations are never reported as corruption"
    );
    assert!(publisher.publishes.is_empty());
}

// WORK_UNIT_CASE: 959/13
#[test]
fn config_purge_build_and_forensic_audit_ceilings_retained() {
    let request = to_request(&valid_full_input(), 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("full capture completes");
    assert_eq!(report.class, BackupClass::FullRecovery);
    let bundle =
        BackupBundle::decode(&publisher.publishes[0].2).expect("published archive decodes");
    assert_eq!(bundle.manifest.class, BackupClass::FullRecovery);
    let mut kinds: Vec<&str> = bundle
        .artifacts
        .iter()
        .map(|artifact| artifact.kind.as_str())
        .collect();
    kinds.sort_unstable();
    assert_eq!(
        kinds,
        vec!["config", "host_dependency_build", "module", "policy"]
    );
    for kept in &bundle.artifacts {
        kept.validate().expect("artifact digest binds bytes");
    }
    // The purge revision binds the carried ledger length: the coordinator
    // rebinds it from evidence instead of trusting caller arithmetic.
    assert_eq!(bundle.purge_ledger.len(), 1);
    assert_eq!(bundle.manifest.purge_ledger_revision, 1);
    assert!(!bundle.purge_ledger.is_empty(), "purge ledger retained");
    // Host audit is present but forensic: never active authority, never part
    // of the recovery denominator, and the class stays FullRecovery.
    let audit = bundle.host_audit.as_ref().expect("host audit carried");
    assert!(!audit.active_authority_restored);
    audit.validate().expect("audit shape validates");
}

// WORK_UNIT_CASE: 959/14
#[test]
fn no_plaintext_keys_or_live_database_exported() {
    let request = to_request(&valid_full_input(), 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("full capture completes");
    let bytes = &publisher.publishes[0].2;
    let text = String::from_utf8_lossy(bytes);
    // `"plaintext_key"` is gated in its exact quoted key form: the manifest
    // legitimately serializes the `plaintext_keys_present: false` declaration,
    // which contains `plaintext_key` as a field-name prefix.
    assert!(
        !text.contains("\"plaintext_key\""),
        "no plaintext key material in the encoded archive"
    );
    assert!(
        !text.contains(".redb"),
        "no live database file path in the encoded archive"
    );
    let bundle = BackupBundle::decode(bytes).expect("published archive decodes");
    assert_eq!(
        bundle.bundle_sha256().expect("digest"),
        report.archive_sha256
    );
    assert!(
        !bundle.manifest.encryption.plaintext_keys_present,
        "manifest declares no plaintext keys"
    );
    assert_eq!(
        bundle.manifest.encryption.envelope, "sealed-blob-envelope-v1",
        "sealed envelopes only"
    );
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("archive is JSON");
    assert_eq!(
        value["manifest"]["encryption"]["plaintext_keys_present"],
        serde_json::Value::Bool(false)
    );
    let lineage = bundle.blobs[0].key_lineage.as_str();
    assert!(!lineage.trim().is_empty(), "key lineage retained");
    let debug = format!("{bundle:?}");
    assert!(
        !debug.contains(".redb"),
        "no live database file path in the logical bundle"
    );
    let ors = bundle.ors_snapshot.as_ref().expect("ORS snapshot");
    assert!(!ors.active_authority_restored);
}

// WORK_UNIT_CASE: 959/15
#[test]
fn real_bundle_api_with_allowed_revalidation() {
    let bundle = BackupBundle::build(valid_full_input()).expect("bundle builds");
    bundle.validate().expect("first validation passes");
    bundle.validate().expect("revalidation is allowed");
    let bytes = bundle.encode().expect("bundle encodes");
    let round_tripped = BackupBundle::decode(&bytes).expect("bundle decodes");
    assert_eq!(round_tripped, bundle);
    round_tripped.validate().expect("decoded bundle validates");
    assert_eq!(
        round_tripped.bundle_sha256().expect("digest"),
        bundle.bundle_sha256().expect("digest")
    );
    // No fictional once-only restriction on internal validation calls.
    for src in [CAPTURE_COORDINATOR_SRC, CAPTURE_PORTS_SRC] {
        for banned in ["once_only", "single_validation"] {
            assert!(!src.contains(banned), "banned {banned} in capture src");
        }
    }
}

// WORK_UNIT_CASE: 959/16
#[test]
fn one_publication_binds_archive_and_receipt() {
    let request = to_request(&valid_full_input(), 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("capture completes");
    assert_eq!(
        publisher.publishes.len(),
        1,
        "publisher called exactly once"
    );
    assert!(
        publisher.reconciles.is_empty(),
        "no reconcile on the happy path"
    );
    let (operation_id, idempotency_key, bytes) = &publisher.publishes[0];
    // The operation identity and idempotency key bind backup id and digest.
    assert_eq!(operation_id, "capture-publish-export-959-full");
    assert_eq!(operation_id, &report.operation_id);
    assert_eq!(
        idempotency_key,
        &format!("export-959-full:{}", report.archive_sha256)
    );
    assert_eq!(sha256_hex(bytes), report.archive_sha256);
}

// WORK_UNIT_CASE: 959/17
#[test]
fn lost_publication_response_reconciles_same_operation() {
    let request = to_request(&valid_full_input(), 0);
    let mut publisher = MemPublisher {
        drop_first: true,
        ..MemPublisher::default()
    };
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("lost response still captures via reconcile");
    assert_eq!(publisher.publishes.len(), 1, "publish count stays 1");
    assert_eq!(publisher.reconciles.len(), 1, "one reconcile by identity");
    assert_eq!(
        publisher.reconciles[0], report.operation_id,
        "reconcile adopts the same operation, never a second publish"
    );
    assert_eq!(report.operation_id, "capture-publish-export-959-full");
    assert_eq!(report.state, CaptureState::Complete);
    assert_eq!(report.receipt_identity, Some(report.operation_id.clone()));
    assert_eq!(sha256_hex(&publisher.publishes[0].2), report.archive_sha256);
}

// WORK_UNIT_CASE: 959/18
#[test]
fn bounds_refuse_before_publication_and_zero_budgets_are_invalid() {
    let tiny = read_fixture("bounds-cancel.json");
    assert_eq!(tiny.expected_state, "cancelled");
    assert!(tiny.cancel_requested, "cancel requested");
    assert!(tiny.control_reserve_preserved, "Control Reserve preserved");
    assert_eq!(tiny.budgets.max_events, 1);
    assert_eq!(tiny.budgets.max_bytes, 64);
    assert_eq!(tiny.budgets.max_blobs, 0);
    assert_eq!(tiny.budgets.max_artifacts, 1);
    // The fixture's tiny bounds (one page per owner, 64 bytes per owner and
    // total) refuse the full capture before any publication.
    let mut request = to_request(&valid_full_input(), 0);
    request.plan.budgets = CaptureBudgets {
        max_pages_per_owner: tiny.budgets.max_events as u64,
        max_bytes_per_owner: tiny.budgets.max_bytes as u64,
        max_bytes_total: tiny.budgets.max_bytes as u64,
        max_work_items: 10_000,
        max_duration_ms: 60_000,
    };
    let mut publisher = MemPublisher::default();
    let refused = coordinator().capture(&request, &mut publisher).unwrap_err();
    assert!(
        matches!(refused, KernelCaptureError::BudgetExceeded { .. }),
        "tiny bounds-cancel budgets refuse the full capture, got {refused:?}"
    );
    assert!(
        publisher.publishes.is_empty(),
        "failed capture performs no publish"
    );
    // Zero budgets are invalid at plan validation, before any reads.
    let mut request = to_request(&valid_full_input(), 0);
    request.plan.budgets = CaptureBudgets {
        max_pages_per_owner: 0,
        max_bytes_per_owner: 0,
        max_bytes_total: 0,
        max_work_items: 0,
        max_duration_ms: 0,
    };
    let mut publisher = MemPublisher::default();
    let refused = coordinator().capture(&request, &mut publisher).unwrap_err();
    assert!(
        matches!(refused, KernelCaptureError::InvalidInput { .. }),
        "zero budgets refuse at plan validation, got {refused:?}"
    );
    assert!(
        publisher.publishes.is_empty(),
        "failed capture performs no publish"
    );
}

// WORK_UNIT_CASE: 959/19
#[test]
fn verify_only_never_restores_or_mutates() {
    let request = to_request(&valid_full_input(), 0);
    let mut publisher = MemPublisher::default();
    let report = coordinator()
        .capture(&request, &mut publisher)
        .expect("capture completes");
    // Verification-only takes no publisher at all: no publication is
    // representable here, and the report carries the verify-only identity.
    let verified = coordinator()
        .verify_only(&publisher.publishes[0].2, &admitted_caller(), &base_fence())
        .expect("verify-only passes");
    assert_eq!(verified.class, BackupClass::FullRecovery);
    assert_eq!(verified.state, CaptureState::Complete);
    assert_eq!(verified.verification_level, "decode-validate-relation");
    assert_eq!(verified.archive_sha256, report.archive_sha256);
    assert!(
        verified.operation_id.starts_with("verify-only-"),
        "verify-only identity, got {}",
        verified.operation_id
    );
    assert_eq!(
        verified.operation_id,
        format!("verify-only-{}", verified.backup_id)
    );
    assert!(verified.receipt_identity.is_none());
    // Static boundary: no restore/mutation/cutover vocabulary in the capture
    // coordinator. `cut_over`/`Finished` are matched case-sensitively so prose
    // about cutover policy cannot trip the gate; code calls would.
    for banned in [
        "restore_canonical_batch",
        "RestoreTarget",
        "import_to_store",
        "cut_over",
        "Finished",
    ] {
        assert!(
            !CAPTURE_COORDINATOR_SRC.contains(banned),
            "banned {banned} in coordinator"
        );
    }
}

// WORK_UNIT_CASE: 959/20
#[test]
fn no_forbidden_imports_or_overclaims() {
    for (name, src) in [
        ("backup_capture.rs", CAPTURE_COORDINATOR_SRC),
        ("backup_capture_ports.rs", CAPTURE_PORTS_SRC),
    ] {
        for banned in [
            "surreal",
            "redb",
            "mint_epoch",
            "activate_installation",
            "cloud_upload",
            "arbitrary destination",
            "Finished",
        ] {
            assert!(!src.contains(banned), "banned {banned} in {name}");
        }
        // `recovered` occurs only inside explicit denial prose ("never claims
        // recovered ...", "no recovered ... claims"): the coordinator's own
        // capability cell forbids recovered/activated/finished claims, so
        // every occurrence must sit in a sentence that denies the claim.
        for (index, line) in src.lines().enumerate() {
            if line.contains("recovered") {
                assert!(
                    line.contains("never") || line.contains("no recovered"),
                    "unexpected 'recovered' claim at {name}:{}: {line}",
                    index + 1
                );
            }
        }
    }
    // `Cargo.toml` is read-only here: no new binary/store dependency edges.
    assert!(!KERNEL_MANIFEST.is_empty());
    for banned in ["surrealdb", "watchdog-binary"] {
        assert!(
            !KERNEL_MANIFEST.contains(banned),
            "banned dependency {banned}"
        );
    }
}
