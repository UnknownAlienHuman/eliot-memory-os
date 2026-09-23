//! Backup-I/O structural contract tests (issue #950).
//!
//! Eighteen cases (`950/1` .. `950/18`) pin the owner-neutral coherent
//! snapshot and isolated-restore surface in `backup_io.rs`: the exact closed
//! capture/restore port vocabulary, snapshot binding under one owner-issued
//! consistency point, page/cursor continuation closure, complete versus
//! partial/expired/unavailable receipts, the exact record/type/reference and
//! blob-residency denominator, residency-domain identity separation, the
//! timestamp-is-not-authority rule, isolated-destination separation,
//! admission-shape versus admission-authority, purge/reference closure with
//! fail-closed port defaults, same-operation replay identity, unknown or
//! possible-mutation receipts, conflict-kind mapping, the known-zero
//! completeness rule, closed fields/versions/bounds/redaction, the unchanged
//! `CanonicalStoreClient`, single-owner consumer compilation, and the
//! no-archive-format/SQL/credential/wire/runtime source guard.
//!
//! Typed inputs freeze in `data/backup-io/`: `snapshot-manifest-v1.json` is
//! the exact valid begin request, `snapshot-page-v1.json` one bounded page,
//! `validation-receipt-v1.json` the proven-success receipt,
//! `restore-member-v1.json` the valid canonical restore batch,
//! `isolated-destination-v1.json` the admitted isolated destination,
//! `reconciliation-v1.json` the replay-identity record, `bounds-v1.json` the
//! frozen denominator/bounds envelope, and `redaction-v1.json` the
//! digests-only redaction probe.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, ContractVersion, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_store_api::{
    ALL_BACKUP_IO_CAPABILITIES, BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT,
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION,
    BACKUP_IO_CAPABILITY_PURGE_VALIDATION, BACKUP_IO_CAPABILITY_REBUILD_VALIDATION,
    BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION, BACKUP_IO_CONTRACT_NAME,
    BACKUP_IO_RESTORE_SCHEMA_V1, BACKUP_IO_SNAPSHOT_SCHEMA_V1, BackupIoCapability,
    BackupOperationReconciliation, BlobResidency, BlobResidencyDomain, CONTRACT_VERSION,
    CanonicalRestoreBatch, CanonicalSnapshotPort, CanonicalStoreClient,
    CanonicalValidationSnapshot, DestinationClass, EventInterval, IsolatedDestination,
    IsolatedRestorePort, IsolationEvidence, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_MEMBERS,
    NamedReadRequest, NamedReadResponse, OperationIdentity, OperationManifestDigest, OrderingHead,
    OrderingHeadExpectation, OrderingScopeId, PreparedTransition, ReconciliationOutcome,
    RequestMeta, RestoreConflictKind, RestoreValidationReceipt, Resubmission, RevisionHead,
    RevisionHeadExpectation, RevisionKey, ScopeId, ScopeRevisionView, SnapshotBeginRequest,
    SnapshotBounds, SnapshotCompleteness, SnapshotCursor, SnapshotDenominator, SnapshotEndReceipt,
    SnapshotHandle, SnapshotMember, SnapshotMemberType, SnapshotPage, SnapshotSourceIdentity,
    SnapshotValidationReceipt, StoreError, StoreHealth, StoreMutationDisposition, TransitionClass,
    WriteReceipt, WriteReceiptStatus, classify_restore_conflict, is_backup_io_capability,
    reconcile_same_operation,
};
use serde_json::{Value, json};

const LINEAGE_950: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_950).unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn fence_seq2() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_950).unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(2).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-950-1").unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-950").unwrap(),
        source_id: SourceId::new("source-950").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn operation(id: &str, key: &str, hash: &str) -> OperationIdentity {
    OperationIdentity {
        operation_id: OperationId::new(id).unwrap(),
        idempotency_key: key.to_owned(),
        canonical_request_hash: hash.to_owned(),
    }
}

fn hex(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn source() -> SnapshotSourceIdentity {
    SnapshotSourceIdentity {
        installation_id: "install-950-1".to_owned(),
        store_id: "store-950-1".to_owned(),
        schema: "eliot.storage.snapshot.v1".to_owned(),
        generation: ResourceGeneration::new(7).expect("non-zero test generation"),
    }
}

fn scope(fence: &StateFence) -> ScopeRevisionView {
    ScopeRevisionView {
        scope_id: ScopeId::new("scope-950-1").unwrap(),
        revision_heads: vec![RevisionHead {
            key: RevisionKey::new("scope-950-1").unwrap(),
            revision: 9,
            state_fence: fence.clone(),
        }],
        ordering_heads: vec![OrderingHead {
            scope: OrderingScopeId::new("order-950-1").unwrap(),
            sequence: 4,
            state_fence: fence.clone(),
        }],
        state_fence: fence.clone(),
    }
}

fn record_member() -> SnapshotMember {
    SnapshotMember {
        member_id: "member-950-1".to_owned(),
        member_type: SnapshotMemberType::Record,
        content_digest: hex('c'),
        residency: BlobResidency {
            domain: BlobResidencyDomain::InlineCanonical,
            residency_digest: hex('d'),
            byte_count: 1024,
        },
        reference_digest: None,
    }
}

fn blob_member() -> SnapshotMember {
    SnapshotMember {
        member_id: "member-950-2".to_owned(),
        member_type: SnapshotMemberType::Blob,
        content_digest: hex('e'),
        residency: BlobResidency {
            domain: BlobResidencyDomain::ContentBlob,
            residency_digest: hex('f'),
            byte_count: 2048,
        },
        reference_digest: None,
    }
}

fn reference_member() -> SnapshotMember {
    SnapshotMember {
        member_id: "member-950-3".to_owned(),
        member_type: SnapshotMemberType::Reference,
        content_digest: hex('0'),
        residency: BlobResidency {
            domain: BlobResidencyDomain::ExternalReference,
            residency_digest: hex('1'),
            byte_count: 64,
        },
        reference_digest: Some(hex('2')),
    }
}

fn denominator() -> SnapshotDenominator {
    SnapshotDenominator {
        members: vec![record_member(), blob_member(), reference_member()],
        is_complete: true,
    }
}

fn bounds() -> SnapshotBounds {
    SnapshotBounds {
        max_members: 512,
        max_bytes: 8_388_608,
        max_pages: 64,
        max_work: 100_000,
        max_duration_ms: 60_000,
    }
}

fn begin_request() -> SnapshotBeginRequest {
    SnapshotBeginRequest {
        contract_version: CONTRACT_VERSION,
        operation: operation("op-950-1", "idem-950-1", &hex('a')),
        source: source(),
        scope: scope(&fence()),
        event_interval: EventInterval {
            first_sequence: 101,
            last_sequence: 140,
        },
        denominator: denominator(),
        bounds: bounds(),
        expires_at_unix_ms: 1_893_456_000_000,
        privacy_proof_refs: vec!["proof-950-1".to_owned()],
    }
}

fn handle_for(begin: &SnapshotBeginRequest) -> SnapshotHandle {
    SnapshotHandle {
        consistency_point: "consistency-950-1".to_owned(),
        snapshot_digest: begin.compute_digest().unwrap(),
        operation_id: OperationId::new("op-950-1").unwrap(),
        idempotency_key: "idem-950-1".to_owned(),
    }
}

fn page_for(begin: &SnapshotBeginRequest) -> SnapshotPage {
    let handle = handle_for(begin);
    SnapshotPage {
        cursor: SnapshotCursor {
            handle_digest: handle.snapshot_digest.clone(),
            page_index: 0,
            cumulative_members: 2,
            cumulative_bytes: 3072,
        },
        members: vec![record_member(), blob_member()],
        cumulative_bytes: 3072,
        cumulative_work: 50,
        is_last: false,
        predecessor_digest: hex('6'),
        next_cursor: Some(SnapshotCursor {
            handle_digest: handle.snapshot_digest.clone(),
            page_index: 1,
            cumulative_members: 3,
            cumulative_bytes: 3136,
        }),
        handle,
    }
}

fn end_receipt(completeness: SnapshotCompleteness) -> SnapshotEndReceipt {
    SnapshotEndReceipt {
        handle: handle_for(&begin_request()),
        operation: operation("op-950-1", "idem-950-1", &hex('a')),
        member_count: 3,
        byte_count: 3136,
        completeness,
        validation_revision: 1,
    }
}

fn validation_receipt(
    completeness: SnapshotCompleteness,
    disposition: StoreMutationDisposition,
    resolved: u64,
    unresolved: u64,
    denominator: SnapshotDenominator,
) -> SnapshotValidationReceipt {
    SnapshotValidationReceipt {
        operation: operation("op-950-1", "idem-950-1", &hex('a')),
        handle: handle_for(&begin_request()),
        denominator,
        resolved_members: resolved,
        unresolved_members: unresolved,
        completeness,
        disposition,
    }
}

fn restore_receipt(
    completeness: SnapshotCompleteness,
    disposition: StoreMutationDisposition,
) -> RestoreValidationReceipt {
    RestoreValidationReceipt {
        operation: operation("op-950-2", "idem-950-2", &hex('b')),
        destination: destination(),
        archive_member_digest: hex('7'),
        resolved_members: 3,
        unresolved_members: 0,
        denominator_members: 3,
        completeness,
        disposition,
    }
}

fn destination() -> IsolatedDestination {
    IsolatedDestination {
        destination_id: "restore-950-1".to_owned(),
        destination_class: DestinationClass::IsolatedRestore,
        source_store_id: "store-950-1".to_owned(),
        source_installation_id: "install-950-1".to_owned(),
        evidence: IsolationEvidence {
            admission_handle: "admit-950-1".to_owned(),
            admitted_at_unix_ms: 1_758_672_000_000,
            purge_policy_revision: 3,
        },
        target_schema: "eliot.storage.snapshot.v1".to_owned(),
    }
}

fn batch() -> CanonicalRestoreBatch {
    CanonicalRestoreBatch {
        contract_version: CONTRACT_VERSION,
        operation: operation("op-950-2", "idem-950-2", &hex('b')),
        source: source(),
        destination: destination(),
        archive_member_digest: hex('7'),
        target_schema: "eliot.storage.snapshot.v1".to_owned(),
        purge_policy_revision: 3,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope-950-1").unwrap(),
            expected_revision: 9,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("order-950-1").unwrap(),
            expected_sequence: 4,
            state_fence: fence(),
        }],
        member_count: 3,
    }
}

fn collect_keys(value: &Value, keys: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                keys.push(key.clone());
                collect_keys(nested, keys);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_keys(item, keys);
            }
        }
        _ => {}
    }
}

/// Pre-950 client surface with fail-closed bodies and no new-port success
/// defaults: proves `CanonicalStoreClient` is unchanged by #950.
struct LegacyStore;

impl CanonicalStoreClient for LegacyStore {
    async fn apply_prepared(
        &self,
        _ctx: &RequestMeta,
        _transition: PreparedTransition,
        _expected_revision_heads: Vec<RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn receipt(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        Ok(None)
    }

    async fn revision_heads(
        &self,
        _keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn scope_revision_view(
        &self,
        _scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn ordering_heads(
        &self,
        _scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn execute_named(
        &self,
        _query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        Err(StoreError::Unavailable)
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        Err(StoreError::Unavailable)
    }
}

fn assert_legacy_compiles(_: &impl CanonicalStoreClient) {}

fn assert_no_new_required(store: &LegacyStore) {
    assert_legacy_compiles(store);
}

fn consume_client_defaults<C: CanonicalStoreClient>() {
    let _ = C::apply_reserved_write;
    let _ = C::recovery;
    let _ = C::initialize_genesis;
    let _ = C::dreamer_job;
}

/// Restore-port stub with zero fields and no overrides: every method keeps
/// its fail-closed default body.
struct StubRestorePort;

impl IsolatedRestorePort for StubRestorePort {}

fn consume_restore_defaults(
    port: &impl IsolatedRestorePort,
    ctx: &RequestMeta,
    batch: CanonicalRestoreBatch,
    dest: IsolatedDestination,
    first: OperationIdentity,
    second: OperationIdentity,
) {
    std::mem::drop(port.prepare_isolated_destination(ctx, dest));
    std::mem::drop(port.restore_canonical_batch(ctx, batch.clone()));
    std::mem::drop(port.validate_restore(ctx, batch));
    std::mem::drop(port.reconcile_operation(first, second));
}

/// Capture/restore consumer with zero fields and no backend: proves one
/// owner compiles through both ports on defaults alone.
struct FakePorts;

impl CanonicalSnapshotPort for FakePorts {}

impl IsolatedRestorePort for FakePorts {}

fn consume_ports<C: CanonicalSnapshotPort + IsolatedRestorePort>(_ports: &C) {
    let _ = C::begin_snapshot;
    let _ = C::read_snapshot_page;
    let _ = C::end_snapshot;
    let _ = C::prepare_isolated_destination;
    let _ = C::restore_canonical_batch;
    let _ = C::validate_restore;
    let _ = C::reconcile_operation;
}

// WORK_UNIT_CASE: 950/1
#[test]
fn backup_io_closed_capability_vocabulary_is_exact() {
    // Every helper below produces valid values; the frozen begin/batch/page
    // fixtures decode to the same shapes.
    assert!(context().validate().is_ok());
    assert!(begin_request().validate().is_ok());
    assert!(denominator().validate().is_ok());
    assert!(bounds().validate().is_ok());
    assert!(destination().validate().is_ok());
    assert!(batch().validate().is_ok());
    let begin = begin_request();
    assert!(page_for(&begin).validate().is_ok());
    assert!(page_for(&begin).validate_for_begin(&begin).is_ok());
    let manifest: SnapshotBeginRequest =
        serde_json::from_str(include_str!("data/backup-io/snapshot-manifest-v1.json")).unwrap();
    assert!(manifest.validate().is_ok());
    // The closed vocabulary is exactly six frozen names.
    assert_eq!(
        ALL_BACKUP_IO_CAPABILITIES,
        &[
            "coherent_snapshot",
            "isolated_restore",
            "reference_validation",
            "purge_validation",
            "rebuild_validation",
            "operation_reconciliation",
        ]
    );
    assert_eq!(BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT, "coherent_snapshot");
    assert_eq!(BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, "isolated_restore");
    assert_eq!(
        BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION,
        "reference_validation"
    );
    assert_eq!(BACKUP_IO_CAPABILITY_PURGE_VALIDATION, "purge_validation");
    assert_eq!(
        BACKUP_IO_CAPABILITY_REBUILD_VALIDATION,
        "rebuild_validation"
    );
    assert_eq!(
        BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION,
        "operation_reconciliation"
    );
    for capability in ALL_BACKUP_IO_CAPABILITIES {
        assert!(is_backup_io_capability(capability));
    }
    for unknown in ["sql", "arbitrary_query", ""] {
        assert!(!is_backup_io_capability(unknown));
    }
    assert_eq!(
        BackupIoCapability::CoherentSnapshot.capability_name(),
        BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT
    );
    assert_eq!(
        BackupIoCapability::IsolatedRestore.capability_name(),
        BACKUP_IO_CAPABILITY_ISOLATED_RESTORE
    );
    assert_eq!(
        BackupIoCapability::ReferenceValidation.capability_name(),
        BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION
    );
    assert_eq!(
        BackupIoCapability::PurgeValidation.capability_name(),
        BACKUP_IO_CAPABILITY_PURGE_VALIDATION
    );
    assert_eq!(
        BackupIoCapability::RebuildValidation.capability_name(),
        BACKUP_IO_CAPABILITY_REBUILD_VALIDATION
    );
    assert_eq!(
        BackupIoCapability::OperationReconciliation.capability_name(),
        BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION
    );
    // Serde rejects unknown variants; the closed request rejects unknown fields.
    assert!(serde_json::from_value::<BackupIoCapability>(json!("SqlQuery")).is_err());
    assert!(serde_json::from_value::<BackupIoCapability>(json!("COHERENT_SNAPSHOT")).is_ok());
    assert!(serde_json::from_value::<DestinationClass>(json!("SOURCE_ACTIVE")).is_err());
    let mut extended = serde_json::to_value(begin_request()).unwrap();
    extended
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<SnapshotBeginRequest>(extended).is_err());
}

// WORK_UNIT_CASE: 950/2
#[test]
fn snapshot_begin_binds_source_generation_heads_and_fence() {
    let begin = begin_request();
    assert!(begin.validate().is_ok());
    // A head on a different fence breaks coherence.
    let mut wrong_fence = begin.clone();
    wrong_fence.scope.revision_heads[0].state_fence = fence_seq2();
    assert_eq!(wrong_fence.validate(), Err(StoreError::FenceMismatch));
    // Generation is bound through the immutable digest: changing it rebinds
    // the capture, so a handle issued for the original no longer matches.
    let mut regen = begin.clone();
    regen.source.generation = ResourceGeneration::new(8).expect("non-zero test generation");
    assert_ne!(
        regen.compute_digest().unwrap(),
        begin.compute_digest().unwrap()
    );
    let page = page_for(&begin);
    assert!(page.validate_for_begin(&regen).is_err());
    // A zero generation is not representable through the closed JSON shape.
    let mut zero = serde_json::to_value(&begin).unwrap();
    zero["source"]["generation"] = json!(0);
    assert!(serde_json::from_value::<SnapshotBeginRequest>(zero).is_err());
    // A snapshot with no revision heads is not coherent.
    let mut empty = begin.clone();
    empty.scope.revision_heads = Vec::new();
    assert_eq!(
        empty.validate(),
        Err(StoreError::Empty {
            field: "snapshot.revision_heads"
        })
    );
    // The contract version is exact.
    let mut versioned = begin.clone();
    versioned.contract_version = ContractVersion::new(0, 9, 9);
    assert!(versioned.validate().is_err());
}

// WORK_UNIT_CASE: 950/3
#[test]
fn snapshot_pages_and_cursors_cannot_cross_snapshot_or_reset_bounds() {
    let begin = begin_request();
    let page = page_for(&begin);
    assert!(page.validate().is_ok());
    assert!(page.validate_for_begin(&begin).is_ok());
    let fixture: SnapshotPage =
        serde_json::from_str(include_str!("data/backup-io/snapshot-page-v1.json")).unwrap();
    assert!(fixture.validate().is_ok());
    // A cursor from a foreign handle does not belong to this page.
    let mut foreign = page.clone();
    foreign.cursor.handle_digest = hex('9');
    assert!(foreign.validate().is_err());
    // Continuation cannot cross to a different snapshot handle.
    let mut crossed = page.clone();
    crossed.handle.snapshot_digest = hex('8');
    crossed.cursor.handle_digest = hex('8');
    crossed.cursor.page_index = 1;
    assert!(crossed.validate().is_ok());
    assert!(crossed.validate_continuation(&page).is_err());
    // Cumulative bytes must never reset along a continuation.
    let mut rewound_bytes = page.clone();
    rewound_bytes.members = vec![reference_member()];
    rewound_bytes.cumulative_bytes = 100;
    rewound_bytes.cursor.page_index = 1;
    rewound_bytes.cursor.cumulative_members = 3;
    assert!(rewound_bytes.validate().is_ok());
    assert!(rewound_bytes.validate_continuation(&page).is_err());
    // Cumulative members must never reset along a continuation.
    let mut rewound_members = page.clone();
    rewound_members.members = vec![record_member(), blob_member(), reference_member()];
    rewound_members.cumulative_bytes = 3136;
    rewound_members.cursor.page_index = 1;
    rewound_members.cursor.cumulative_members = 1;
    assert!(rewound_members.validate().is_ok());
    assert!(rewound_members.validate_continuation(&page).is_err());
    // The page index must advance by exactly one.
    let mut skipped = page.clone();
    skipped.cursor.page_index = 5;
    assert!(skipped.validate_continuation(&page).is_err());
    // A page handle that does not match the begin-request digest is refused.
    assert!(crossed.validate_for_begin(&begin).is_err());
    // Cumulative work past the declared bounds is refused as too large.
    let mut over_bytes = page.clone();
    over_bytes.cumulative_bytes = begin.bounds.max_bytes + 1;
    assert_eq!(
        over_bytes.validate_for_begin(&begin),
        Err(StoreError::PayloadTooLarge)
    );
    let mut over_members = page.clone();
    over_members.cursor.cumulative_members = begin.bounds.max_members + 1;
    assert_eq!(
        over_members.validate_for_begin(&begin),
        Err(StoreError::PayloadTooLarge)
    );
}

// WORK_UNIT_CASE: 950/4
#[test]
fn end_and_validation_receipts_keep_partial_expired_unsupported_distinct() {
    // Every completeness state validates shape-wise, but only Complete closes.
    for completeness in [
        SnapshotCompleteness::Complete,
        SnapshotCompleteness::Partial,
        SnapshotCompleteness::Expired,
        SnapshotCompleteness::Unsupported,
    ] {
        let receipt = end_receipt(completeness);
        assert!(receipt.validate().is_ok());
        assert_eq!(
            receipt.is_complete(),
            completeness == SnapshotCompleteness::Complete
        );
    }
    assert!(!SnapshotCompleteness::Expired.is_complete());
    // Partial, expired, and unsupported captures with outstanding members
    // validate structurally but never prove success.
    for completeness in [
        SnapshotCompleteness::Partial,
        SnapshotCompleteness::Expired,
        SnapshotCompleteness::Unsupported,
    ] {
        let receipt = validation_receipt(
            completeness,
            StoreMutationDisposition::Committed,
            2,
            1,
            denominator(),
        );
        assert!(receipt.validate().is_ok());
        assert!(!receipt.is_proven_success());
    }
}

// WORK_UNIT_CASE: 950/5
#[test]
fn denominator_binds_member_type_reference_and_residency() {
    let full = denominator();
    assert!(full.validate().is_ok());
    assert_eq!(full.member_count(), 3);
    assert_eq!(full.total_bytes(), 3136);
    // Duplicate member identities are refused.
    let mut duplicated = full.clone();
    duplicated.members.push(record_member());
    assert_eq!(
        duplicated.validate(),
        Err(StoreError::Duplicate {
            field: "snapshot.members"
        })
    );
    // A reference member without its reference digest is open.
    let mut missing = full.clone();
    missing.members[2].reference_digest = None;
    assert!(missing.validate().is_err());
    // A non-reference member must not carry a reference digest.
    let mut stray = full.clone();
    stray.members[0].reference_digest = Some(hex('2'));
    assert!(stray.validate().is_err());
    // A tampered residency digest breaks residency closure.
    let mut tampered = full.clone();
    tampered.members[1].residency.residency_digest = "not-a-digest".to_owned();
    assert!(tampered.validate().is_err());
    // A denominator missing a member no longer matches the frozen envelope.
    let frozen: Value =
        serde_json::from_str(include_str!("data/backup-io/bounds-v1.json")).unwrap();
    assert_eq!(frozen["denominator_members"], json!(3));
    assert_eq!(frozen["denominator_bytes"], json!(3136));
    let mut short = full.clone();
    short.members.pop();
    assert_eq!(short.member_count(), 2);
    assert_eq!(short.total_bytes(), 3072);
    assert_ne!(
        short.member_count(),
        frozen["denominator_members"].as_u64().unwrap()
    );
    assert_ne!(
        short.total_bytes(),
        frozen["denominator_bytes"].as_u64().unwrap()
    );
}

// WORK_UNIT_CASE: 950/6
#[test]
fn same_content_across_residency_domains_stays_distinct() {
    let content = hex('c');
    let inline = SnapshotMember {
        member_id: "member-950-inline".to_owned(),
        member_type: SnapshotMemberType::Record,
        content_digest: content.clone(),
        residency: BlobResidency {
            domain: BlobResidencyDomain::InlineCanonical,
            residency_digest: hex('d'),
            byte_count: 1024,
        },
        reference_digest: None,
    };
    let blob = SnapshotMember {
        member_id: "member-950-blob".to_owned(),
        member_type: SnapshotMemberType::Blob,
        content_digest: content.clone(),
        residency: BlobResidency {
            domain: BlobResidencyDomain::ContentBlob,
            residency_digest: hex('f'),
            byte_count: 1024,
        },
        reference_digest: None,
    };
    // The domain is part of the logical identity: equal bytes stay distinct.
    assert_ne!(inline.logical_identity(), blob.logical_identity());
    // The denominator keeps both members: no digest-only coalescing.
    let both = SnapshotDenominator {
        members: vec![inline, blob],
        is_complete: true,
    };
    assert!(both.validate().is_ok());
    assert_eq!(both.member_count(), 2);
}

// WORK_UNIT_CASE: 950/7
#[test]
fn timestamp_alone_cannot_bind_a_snapshot() {
    // A bare timestamp never decodes as an owner-issued handle.
    assert!(serde_json::from_value::<SnapshotHandle>(json!(1_758_672_000_000_i64)).is_err());
    // There is no timestamp constructor: an empty consistency point fails.
    let empty = SnapshotHandle {
        consistency_point: String::new(),
        snapshot_digest: hex('5'),
        operation_id: OperationId::new("op-950-1").unwrap(),
        idempotency_key: "idem-950-1".to_owned(),
    };
    assert!(empty.validate().is_err());
    // A page requires a bound handle: an empty handle digest fails.
    let mut unbound = page_for(&begin_request());
    unbound.handle.snapshot_digest = String::new();
    assert!(unbound.validate().is_err());
    // The existing validation snapshot carries only an observation timestamp:
    // it has no snapshot digest or consistency point fields.
    let observed = CanonicalValidationSnapshot {
        state_fence: fence(),
        revision_heads: vec![RevisionHead {
            key: RevisionKey::new("scope-950-1").unwrap(),
            revision: 9,
            state_fence: fence(),
        }],
        validation_revision: 1,
        observed_at_unix_ms: 1_758_672_000_000,
    };
    assert!(observed.validate().is_ok());
    let value = serde_json::to_value(&observed).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(!keys.contains(&"snapshot_digest"));
    assert!(!keys.contains(&"consistency_point"));
}

// WORK_UNIT_CASE: 950/8
#[test]
fn isolated_destination_differs_from_source_and_active() {
    assert!(destination().validate().is_ok());
    let fixture: IsolatedDestination =
        serde_json::from_str(include_str!("data/backup-io/isolated-destination-v1.json")).unwrap();
    assert!(fixture.validate().is_ok());
    // The destination must differ from the source store identity.
    let mut same_store = destination();
    same_store.destination_id = same_store.source_store_id.clone();
    assert!(same_store.validate().is_err());
    // The destination must differ from the source installation identity.
    let mut same_install = destination();
    same_install.destination_id = same_install.source_installation_id.clone();
    assert!(same_install.validate().is_err());
    // Only the isolated class can ever validate.
    for class in [
        DestinationClass::Active,
        DestinationClass::Source,
        DestinationClass::Foreign,
    ] {
        let mut wrong = destination();
        wrong.destination_class = class;
        assert!(wrong.validate().is_err());
    }
}

// WORK_UNIT_CASE: 950/9
#[test]
fn admission_shape_alone_is_not_restore_authority() {
    assert!(batch().validate().is_ok());
    let fixture: CanonicalRestoreBatch =
        serde_json::from_str(include_str!("data/backup-io/restore-member-v1.json")).unwrap();
    assert!(fixture.validate().is_ok());
    // Destination admission is checked first: an empty handle fails.
    let mut no_handle = batch();
    no_handle.destination.evidence.admission_handle = String::new();
    assert!(no_handle.validate().is_err());
    // A zero admission timestamp fails.
    let mut zero_time = batch();
    zero_time.destination.evidence.admitted_at_unix_ms = 0;
    assert!(zero_time.validate().is_err());
    // The batch purge revision must match the admitted evidence revision.
    let mut mismatch = batch();
    mismatch.purge_policy_revision = 9;
    assert!(mismatch.validate().is_err());
    // A well-formed batch over stale (zero-revision) evidence still fails.
    let mut stale = batch();
    stale.destination.evidence.purge_policy_revision = 0;
    assert!(stale.validate().is_err());
    // Admission is an opaque string handle, never a boolean flag.
    let mut boolean = serde_json::to_value(destination()).unwrap();
    boolean["evidence"]["admission_handle"] = json!(true);
    assert!(serde_json::from_value::<IsolatedDestination>(boolean).is_err());
}

// WORK_UNIT_CASE: 950/10
#[test]
fn purge_and_reference_closure_with_fail_closed_restore_defaults() {
    // A stale (zero) purge revision is refused before any restore.
    let mut stale = batch();
    stale.purge_policy_revision = 0;
    assert!(stale.validate().is_err());
    // A known-zero restore receipt requires a complete validation receipt.
    let proven = restore_receipt(
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Committed,
    );
    assert!(proven.validate().is_ok());
    assert!(proven.is_proven_success());
    let partial = restore_receipt(
        SnapshotCompleteness::Partial,
        StoreMutationDisposition::Committed,
    );
    assert!(partial.validate().is_err());
    // Reference closure is required on the restore path too.
    let mut open = denominator();
    open.members[2].reference_digest = None;
    assert!(open.validate().is_err());
    // The default port bodies exist and are invocable without a backend.
    // Futures are constructed but never polled: no async runtime is needed
    // (this crate has no dev-dependency runtime) and no backend I/O happens.
    // `provider_unknown_outcome.rs` likewise covers sync refusal contours
    // only; execution refusal lives with the accepted concrete backend.
    consume_restore_defaults(
        &StubRestorePort,
        &context(),
        batch(),
        destination(),
        operation("op-950-1", "idem-950-1", &hex('a')),
        operation("op-950-1", "idem-950-1", &hex('a')),
    );
}

// WORK_UNIT_CASE: 950/11
#[test]
fn same_operation_replay_identity_versus_changed_input_conflict() {
    let first = operation("op-950-1", "idem-950-1", &hex('a'));
    // Identical inputs reconcile as replay identity.
    assert_eq!(
        reconcile_same_operation(&first, &first).unwrap(),
        ReconciliationOutcome::ReplayIdentity
    );
    // The same operation id with a changed hash is an identity conflict.
    let changed = operation("op-950-1", "idem-950-1", &hex('b'));
    assert_eq!(
        reconcile_same_operation(&first, &changed).unwrap(),
        ReconciliationOutcome::IdentityConflict
    );
    // Reconciliation across different operation ids is refused.
    let other = operation("op-950-9", "idem-950-1", &hex('a'));
    assert!(reconcile_same_operation(&first, &other).is_err());
    // Equal digests with a replay outcome validate.
    let record = BackupOperationReconciliation {
        operation: first.clone(),
        first_digest: hex('a'),
        second_digest: hex('a'),
        outcome: ReconciliationOutcome::ReplayIdentity,
    };
    assert!(record.validate().is_ok());
    let fixture: BackupOperationReconciliation =
        serde_json::from_str(include_str!("data/backup-io/reconciliation-v1.json")).unwrap();
    assert!(fixture.validate().is_ok());
    // Equal digests with a conflict outcome fail: the outcome must match.
    let mut mismatched = record;
    mismatched.outcome = ReconciliationOutcome::IdentityConflict;
    assert!(mismatched.validate().is_err());
}

// WORK_UNIT_CASE: 950/12
#[test]
fn possible_mutation_or_unknown_receipt_is_neither_no_write_nor_pass() {
    // An unknown disposition never validates as a complete success.
    let unknown = validation_receipt(
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Unknown,
        3,
        0,
        denominator(),
    );
    assert_eq!(unknown.validate(), Err(StoreError::InvalidReceipt));
    // A possible-mutation (partial) disposition never validates as success.
    let partial = validation_receipt(
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Partial,
        3,
        0,
        denominator(),
    );
    assert_eq!(partial.validate(), Err(StoreError::InvalidReceipt));
    assert!(!unknown.is_proven_success());
    // A transport receipt without its reconciliation envelope is explicitly
    // unknown and must never be reported as a successful write.
    let envelope_less = WriteReceipt {
        operation_id: OperationId::new("op-950-1").unwrap(),
        idempotency_key: "idem-950-1".to_owned(),
        canonical_request_hash: hex('a'),
        transition_class: TransitionClass::CaptureCandidate,
        status: WriteReceiptStatus::Rejected,
        commit_id: None,
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: Vec::new(),
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new("manifest-950-1").unwrap(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: None,
        envelope: None,
    };
    assert_eq!(
        envelope_less.require_reconciliation_envelope(),
        Err(StoreError::MissingReceiptEnvelope)
    );
}

// WORK_UNIT_CASE: 950/13
#[test]
fn restore_conflict_kinds_map_to_distinct_outcomes() {
    assert_eq!(
        classify_restore_conflict(RestoreConflictKind::ExpectedState),
        ReconciliationOutcome::RevisionConflict
    );
    assert_eq!(
        classify_restore_conflict(RestoreConflictKind::Ordering),
        ReconciliationOutcome::OrderingConflict
    );
    assert_eq!(
        classify_restore_conflict(RestoreConflictKind::Schema),
        ReconciliationOutcome::SchemaConflict
    );
    let outcomes = [
        classify_restore_conflict(RestoreConflictKind::ExpectedState),
        classify_restore_conflict(RestoreConflictKind::Ordering),
        classify_restore_conflict(RestoreConflictKind::Schema),
    ];
    assert_ne!(outcomes[0], outcomes[1]);
    assert_ne!(outcomes[0], outcomes[2]);
    assert_ne!(outcomes[1], outcomes[2]);
    assert_ne!(StoreError::RevisionConflict, StoreError::OrderingConflict);
    assert_ne!(
        StoreError::RevisionConflict,
        StoreError::InvalidField {
            field: "restore.expected_revision_heads",
            reason: "mismatch"
        }
    );
    assert_ne!(
        StoreError::OrderingConflict,
        StoreError::InvalidField {
            field: "restore.expected_ordering_heads",
            reason: "mismatch"
        }
    );
    // Expectations validate shape-wise: a zero expected revision fails.
    let mut wrong = batch();
    wrong.expected_revision_heads[0].expected_revision = 0;
    assert!(wrong.validate().is_err());
}

// WORK_UNIT_CASE: 950/14
#[test]
fn known_zero_unresolved_requires_complete_receipt() {
    // A known-zero count over an empty but complete authoritative
    // denominator validates and proves success.
    let empty = SnapshotDenominator {
        members: Vec::new(),
        is_complete: true,
    };
    assert!(empty.validate().is_ok());
    let fixture: SnapshotValidationReceipt =
        serde_json::from_str(include_str!("data/backup-io/validation-receipt-v1.json")).unwrap();
    assert!(fixture.validate().is_ok());
    assert!(fixture.is_proven_success());
    let proven = validation_receipt(
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Committed,
        0,
        0,
        empty.clone(),
    );
    assert!(proven.validate().is_ok());
    assert!(proven.is_proven_success());
    // The same counts over a non-authoritative denominator fail.
    let open = validation_receipt(
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Committed,
        0,
        0,
        SnapshotDenominator {
            members: Vec::new(),
            is_complete: false,
        },
    );
    assert!(open.validate().is_err());
    // The same counts with a partial completeness fail.
    let partial = validation_receipt(
        SnapshotCompleteness::Partial,
        StoreMutationDisposition::Committed,
        0,
        0,
        empty,
    );
    assert!(partial.validate().is_err());
}

// WORK_UNIT_CASE: 950/15
#[test]
fn closed_fields_versions_bounds_and_redaction() {
    // Unknown fields fail closed on every backup-I/O document.
    let mut begin_value = serde_json::to_value(begin_request()).unwrap();
    begin_value
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<SnapshotBeginRequest>(begin_value).is_err());
    let mut page_value = serde_json::to_value(page_for(&begin_request())).unwrap();
    page_value
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<SnapshotPage>(page_value).is_err());
    let mut batch_value = serde_json::to_value(batch()).unwrap();
    batch_value
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<CanonicalRestoreBatch>(batch_value).is_err());
    let mut dest_value = serde_json::to_value(destination()).unwrap();
    dest_value
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<IsolatedDestination>(dest_value).is_err());
    // Contract versions are exact on both capture and restore documents.
    for version in [ContractVersion::new(0, 9, 9), ContractVersion::new(2, 0, 0)] {
        let mut old = begin_request();
        old.contract_version = version;
        assert!(old.validate().is_err());
        let mut future = batch();
        future.contract_version = version;
        assert!(future.validate().is_err());
    }
    // Every bound must be non-zero.
    let mut zero_members = bounds();
    zero_members.max_members = 0;
    assert!(zero_members.validate().is_err());
    let mut zero_bytes = bounds();
    zero_bytes.max_bytes = 0;
    assert!(zero_bytes.validate().is_err());
    let mut zero_pages = bounds();
    zero_pages.max_pages = 0;
    assert!(zero_pages.validate().is_err());
    let mut zero_work = bounds();
    zero_work.max_work = 0;
    assert!(zero_work.validate().is_err());
    let mut zero_duration = bounds();
    zero_duration.max_duration_ms = 0;
    assert!(zero_duration.validate().is_err());
    // Bounds past the frozen ceilings are refused as too large.
    let mut over_members = bounds();
    over_members.max_members = MAX_SNAPSHOT_MEMBERS as u64 + 1;
    assert_eq!(over_members.validate(), Err(StoreError::PayloadTooLarge));
    let mut over_bytes = bounds();
    over_bytes.max_bytes = MAX_SNAPSHOT_BYTES + 1;
    assert_eq!(over_bytes.validate(), Err(StoreError::PayloadTooLarge));
    // The redaction probe carries digests only: no key names a secret.
    let probe: Value =
        serde_json::from_str(include_str!("data/backup-io/redaction-v1.json")).unwrap();
    let mut keys = Vec::new();
    collect_keys(&probe, &mut keys);
    assert!(!keys.is_empty());
    for key in &keys {
        for forbidden in ["password", "secret", "credential", "private_key"] {
            assert!(
                !key.contains(forbidden),
                "redaction probe key must not name a secret: {key}"
            );
        }
    }
    // The batch debug rendering carries digests but no secret material.
    let debug = format!("{:?}", batch());
    assert!(debug.contains(&hex('b')));
    for forbidden in ["password", "secret", "credential", "private_key"] {
        assert!(
            !debug.contains(forbidden),
            "debug rendering must not leak secret material: {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 950/16
#[test]
fn existing_client_implementation_compiles_without_new_success_defaults() {
    // The pre-950 client surface still compiles with fail-closed bodies and
    // no new-port implementation: `CanonicalStoreClient` is unchanged.
    assert_legacy_compiles(&LegacyStore);
    assert_no_new_required(&LegacyStore);
    // The untouched default entry points still exist with their refusal
    // bodies; futures are constructed but never polled, so no async runtime
    // or backend is required (same compile-only technique as 950/10).
    consume_client_defaults::<LegacyStore>();
}

// WORK_UNIT_CASE: 950/17
#[test]
fn independent_consumer_compiles_through_single_owner_without_backends() {
    // One owner with zero fields compiles through both ports on defaults
    // alone: no adapter or backend types are referenced anywhere in this
    // suite, and no runtime backend is required.
    consume_ports(&FakePorts);
}

// WORK_UNIT_CASE: 950/18
#[test]
fn no_archive_format_sql_credential_wire_or_runtime_surface() {
    const SOURCE: &str = include_str!("../src/backup_io.rs");
    // No second archive format, query language, credential material,
    // filesystem/clock runtime, or Store wire coupling.
    for forbidden in [
        "eliot-backup",
        "eliot_backup",
        "StoreRequest",
        "StoreResponse",
        "SELECT",
        "CREATE TABLE",
        "password",
        "std::fs",
        "SystemTime",
        "wire::",
        "CAPABILITY_APPLY",
        "token",
        "scheduler",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "backup-I/O surface must not grow an unowned surface: {forbidden}"
        );
    }
    // `credential` occurs exactly once, in the module denial prose ("no
    // database, filesystem, credential, backup-library ..."); no credential
    // field, parameter, or surface exists.
    assert_eq!(SOURCE.matches("credential").count(), 1);
    assert!(SOURCE.contains("credential, backup-library"));
    // `CAPABILITIES` occurs exactly twice: the closed vocabulary declaration
    // and its membership check. No Store wire catalogue is referenced.
    assert_eq!(SOURCE.matches("CAPABILITIES").count(), 2);
    assert!(SOURCE.contains("deny_unknown_fields"));
    assert!(SOURCE.contains("grants no"));
    // The frozen capability and contract names.
    assert_eq!(BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT, "coherent_snapshot");
    assert_eq!(BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, "isolated_restore");
    assert_eq!(
        BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION,
        "reference_validation"
    );
    assert_eq!(BACKUP_IO_CAPABILITY_PURGE_VALIDATION, "purge_validation");
    assert_eq!(
        BACKUP_IO_CAPABILITY_REBUILD_VALIDATION,
        "rebuild_validation"
    );
    assert_eq!(
        BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION,
        "operation_reconciliation"
    );
    assert_eq!(BACKUP_IO_CONTRACT_NAME, "eliot.storage.backup-io.v1");
    assert_eq!(
        BACKUP_IO_SNAPSHOT_SCHEMA_V1,
        "eliot.storage.backup-io.snapshot.v1"
    );
    assert_eq!(
        BACKUP_IO_RESTORE_SCHEMA_V1,
        "eliot.storage.backup-io.restore.v1"
    );
}
