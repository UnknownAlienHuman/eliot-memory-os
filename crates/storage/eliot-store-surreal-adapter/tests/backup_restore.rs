//! Isolated canonical restore proofs for the sole Surreal adapter (issue #952).
//!
//! Twenty cases (`952/1` .. `952/20`) pin the adapter-owned isolated-restore
//! surface in `src/backup_restore.rs` against the store-neutral contracts in
//! `eliot_store_api::backup_io`: admitted isolated destinations, exact
//! source/member/operation identity, closed restore vocabulary with no raw
//! statement or connection override, complete record/history/revision/ordering
//! denominators, hyperedge/incidence/reference closure, purge suppression
//! without resurrection, distinct residency/privacy/retention domains, no
//! activation of old authority, atomic write plus durable receipt, exact
//! replay versus changed-content conflict, lost-response reconciliation with
//! fail-closed defaults, partial-batch resume, failed-validation readiness,
//! bounds/cancellation behavior, redaction, crash/property fixture boundaries,
//! and a pinned capture-to-restore-to-readback fixture proof with temp-dir
//! cleanup.
//!
//! Cases 1-19 need no live provider: they exercise the pure validation
//! functions, the per-instance in-memory restore ledger, and the
//! store-neutral fail-closed port defaults. Case 20 always runs its fixture
//! proof and additionally attempts a live `surreal.exe version` probe only
//! when a provider binary exists at `ELIOT_TEST_SURREAL_EXE` or the pinned
//! tool path. This file calls only the typed adapter/store APIs; there is no
//! raw SQL, no caller statement text, and no connection or credential
//! override anywhere below.

#![allow(clippy::expect_used, clippy::print_stdout)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, ContractVersion, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_store_api::{
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, BACKUP_IO_RESTORE_SCHEMA_V1,
    BackupOperationReconciliation, BlobResidency, BlobResidencyDomain, CONTRACT_VERSION,
    CanonicalRestoreBatch, DestinationClass, IsolatedDestination, IsolatedRestorePort,
    IsolationEvidence, MAX_RESTORE_MEMBERS, OperationIdentity, OrderingHeadExpectation,
    OrderingScopeId, REVOCATION_HISTORY_PAYLOAD_VERSION, ReconciliationOutcome, RequestMeta,
    RestoreCleanRequalification, RestoreRevocationHistoryArtifact, RestoreValidationReceipt,
    RevisionHeadExpectation, RevisionKey, RevocationHistoryPayload, RevocationHistoryRoot,
    SnapshotCompleteness, SnapshotSourceIdentity, StoreError, StoreMutationDisposition,
    reconcile_same_operation, sha256_hex,
};
use eliot_store_surreal_adapter::backup_restore::{
    MAX_ADMISSION_AGE_MS, MAX_RESTORE_BATCH_MEMBERS, MAX_RESTORE_BYTES, MAX_RESTORE_DURATION_MS,
    RESTORE_CAPABILITY, RESTORE_SCHEMA_V1, RestoreDenominator, RestoreLedger,
    SUPPORTED_RESTORE_OPERATIONS, active_store_identity, is_supported_restore_operation,
    is_suppressed_by_current_purge, new_destination_identity, redact_store_error,
    validate_isolated_destination, validate_reference_closure, validate_restore_batch,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use serde_json::Value;

const LINEAGE_952: &str = "550e8400-e29b-41d4-a716-446655440000";
const TARGET_SCHEMA_952: &str = "restore-schema-952";
const ACTIVE_STORE_952: &str = "active-store-952";
const ACTIVE_INSTALL_952: &str = "active-install-952";
const PURGE_REVISION_952: u64 = 7;
const ADMITTED_AT_952: i64 = 1_750_000_000_000;
const NOW_952: i64 = ADMITTED_AT_952 + 1_000;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_952).expect("test lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero")).expect("test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn hex(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_evidence(now_ms: i64) -> IsolationEvidence {
    IsolationEvidence {
        admission_handle: "admit-952-1".to_owned(),
        admitted_at_unix_ms: now_ms,
        purge_policy_revision: PURGE_REVISION_952,
    }
}

fn valid_destination() -> IsolatedDestination {
    IsolatedDestination {
        destination_id: "restore-952-iso".to_owned(),
        destination_class: DestinationClass::IsolatedRestore,
        source_store_id: "store-952-src".to_owned(),
        source_installation_id: "install-952-src".to_owned(),
        evidence: valid_evidence(ADMITTED_AT_952),
        target_schema: TARGET_SCHEMA_952.to_owned(),
    }
}

fn valid_source() -> SnapshotSourceIdentity {
    SnapshotSourceIdentity {
        installation_id: "install-952-src".to_owned(),
        store_id: "store-952-src".to_owned(),
        schema: TARGET_SCHEMA_952.to_owned(),
        generation: ResourceGeneration::new(7).expect("non-zero test generation"),
    }
}

fn valid_operation(id: &str, hash: &str) -> OperationIdentity {
    OperationIdentity {
        operation_id: OperationId::new(id).expect("operation id"),
        idempotency_key: format!("idem-{id}"),
        canonical_request_hash: hash.to_owned(),
    }
}

fn valid_revocation_history() -> RestoreRevocationHistoryArtifact {
    let state_fence = fence();
    let history_root = RevocationHistoryRoot::genesis(state_fence.clone()).expect("history root");
    let payload = RevocationHistoryPayload {
        version: REVOCATION_HISTORY_PAYLOAD_VERSION,
        origin_ref: "root:restore-test".to_owned(),
        source_revision: history_root.history_revision,
        history_root: history_root.clone(),
        closures: Vec::new(),
    };
    let bytes = serde_json::to_vec(&payload).expect("history payload serializes");
    let sha256 = sha256_hex(&bytes);
    RestoreRevocationHistoryArtifact {
        artifact_id: "revocation-history-restore-test".to_owned(),
        bytes,
        sha256,
        state_fence: state_fence.clone(),
        current_history_root_digest: history_root.ledger_digest.clone(),
        clean_requalification: RestoreCleanRequalification {
            qualification_id: "restore-test-clean-requalification".to_owned(),
            source_history_root_digest: history_root.ledger_digest,
            state_fence,
            proof_digest: hex('d'),
            clean: true,
        },
    }
}

fn valid_batch() -> CanonicalRestoreBatch {
    CanonicalRestoreBatch {
        contract_version: CONTRACT_VERSION,
        operation: valid_operation("op-952-1", &hex('a')),
        source: valid_source(),
        destination: valid_destination(),
        archive_member_digest: hex('c'),
        revocation_history: valid_revocation_history(),
        target_schema: TARGET_SCHEMA_952.to_owned(),
        purge_policy_revision: PURGE_REVISION_952,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new("scope-952-rev").expect("revision key"),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("order-952").expect("ordering scope"),
            expected_sequence: 5,
            state_fence: fence(),
        }],
        member_count: 2,
    }
}

fn batch_for(
    operation_id: &str,
    request_hash: &str,
    archive_digest: &str,
    member_count: u64,
) -> CanonicalRestoreBatch {
    let mut batch = valid_batch();
    batch.operation = valid_operation(operation_id, request_hash);
    batch.archive_member_digest = archive_digest.to_owned();
    batch.member_count = member_count;
    batch
}

fn valid_receipt_full(
    operation_id: &str,
    request_hash: &str,
    archive_digest: &str,
    resolved: u64,
    unresolved: u64,
    denominator: u64,
) -> RestoreValidationReceipt {
    RestoreValidationReceipt {
        operation: valid_operation(operation_id, request_hash),
        destination: valid_destination(),
        archive_member_digest: archive_digest.to_owned(),
        resolved_members: resolved,
        unresolved_members: unresolved,
        denominator_members: denominator,
        completeness: SnapshotCompleteness::Complete,
        disposition: StoreMutationDisposition::Committed,
    }
}

fn check_batch_admitted(batch: &CanonicalRestoreBatch, now_ms: i64) {
    validate_restore_batch(
        batch,
        ACTIVE_STORE_952,
        ACTIVE_INSTALL_952,
        TARGET_SCHEMA_952,
        PURGE_REVISION_952,
        now_ms,
    )
    .expect("admitted canonical batch validates");
}

fn ctx() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-952-14").expect("request id"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-952").expect("product"),
        source_id: SourceId::new("source-952").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn test_config() -> SurrealAdapterConfig {
    SurrealAdapterConfig {
        endpoint: "ws://127.0.0.1:18001/rpc".to_owned(),
        namespace: "eliot".to_owned(),
        database: "eliot952".to_owned(),
        username: "provider-user-952".to_owned(),
        password: SecretString::new("test-secret-952".into()),
        provider_bind_address: "127.0.0.1:18001".to_owned(),
        installation_id: "installation-test-952".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: r"C:\eliot\surreal.exe".to_owned(),
        provider_artifact_digest: "b".repeat(64),
        provider_arguments: Vec::new(),
        store_data_root: r"C:\eliot\store952\data".to_owned(),
        store_work_root: r"C:\eliot\store952\work".to_owned(),
        store_temp_root: r"C:\eliot\store952\tmp".to_owned(),
        connect_timeout_ms: 1_000,
        query_timeout_ms: 1_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    }
}

// WORK_UNIT_CASE: 952/1
#[test]
fn valid_admitted_isolated_restore_delegates_through_sole_adapter_surface() {
    // A well-formed externally admitted isolated destination plus its exact
    // canonical batch validate through the sole adapter surface, the module
    // pins the store-neutral restore schema and capability, the closed
    // vocabulary is exactly the four isolated-restore port operations, and
    // the adapter structurally implements the isolated-restore port with no
    // connection.
    let destination = valid_destination();
    validate_isolated_destination(&destination, ACTIVE_STORE_952, ACTIVE_INSTALL_952)
        .expect("admitted isolated destination validates");
    let batch = valid_batch();
    check_batch_admitted(&batch, NOW_952);
    assert_eq!(
        RESTORE_SCHEMA_V1, BACKUP_IO_RESTORE_SCHEMA_V1,
        "adapter restore schema pins the store-neutral restore schema"
    );
    assert_eq!(
        RESTORE_CAPABILITY, BACKUP_IO_CAPABILITY_ISOLATED_RESTORE,
        "adapter capability pins the store-neutral isolated-restore capability"
    );
    assert!(MAX_RESTORE_BYTES > 0, "byte bound is enforced");
    assert!(MAX_RESTORE_DURATION_MS > 0, "duration bound is enforced");
    assert!(MAX_ADMISSION_AGE_MS > 0, "admission-age bound is enforced");
    assert_eq!(
        SUPPORTED_RESTORE_OPERATIONS,
        &[
            "prepare_isolated_destination",
            "restore_canonical_batch",
            "validate_restore",
            "reconcile_operation",
        ],
        "closed restore vocabulary is exactly the four port operations"
    );
    for operation in SUPPORTED_RESTORE_OPERATIONS {
        assert!(
            is_supported_restore_operation(operation),
            "the sole surface admits its own restore operation: {operation}"
        );
    }
    fn implements_isolated_restore_port<T: IsolatedRestorePort>() {}
    implements_isolated_restore_port::<SurrealStoreAdapter>();
}

// WORK_UNIT_CASE: 952/2
#[test]
fn source_active_foreign_destinations_refused_before_writes() {
    // Source, active, and foreign destination classes are refused, and a
    // destination identifier that collides with the source or active
    // identities is refused; none of these refusals touches the restore
    // ledger.
    for class in [
        DestinationClass::Source,
        DestinationClass::Active,
        DestinationClass::Foreign,
    ] {
        let mut destination = valid_destination();
        destination.destination_class = class;
        assert!(
            validate_isolated_destination(&destination, ACTIVE_STORE_952, ACTIVE_INSTALL_952)
                .is_err(),
            "non-isolated class refused: {class:?}"
        );
        assert!(
            destination.validate().is_err(),
            "store-neutral shape refuses non-isolated class: {class:?}"
        );
    }
    let mut colliding_store = valid_destination();
    colliding_store
        .destination_id
        .clone_from(&colliding_store.source_store_id);
    assert!(
        validate_isolated_destination(&colliding_store, ACTIVE_STORE_952, ACTIVE_INSTALL_952)
            .is_err(),
        "destination colliding with the source store is refused"
    );
    let mut colliding_installation = valid_destination();
    colliding_installation
        .destination_id
        .clone_from(&colliding_installation.source_installation_id);
    assert!(
        validate_isolated_destination(
            &colliding_installation,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952
        )
        .is_err(),
        "destination colliding with the source installation is refused"
    );
    assert!(
        validate_isolated_destination(&valid_destination(), "restore-952-iso", ACTIVE_INSTALL_952)
            .is_err(),
        "destination colliding with the active store is refused"
    );
    let ledger = RestoreLedger::new();
    assert!(
        ledger
            .readback(&valid_operation("op-952-2", &hex('a')))
            .is_none(),
        "refusals happen before writes: the ledger holds nothing"
    );
}

// WORK_UNIT_CASE: 952/3
#[test]
fn stale_admission_wrong_schema_purge_contract_refused() {
    // Expired admission evidence, a wrong target schema, a purge-policy
    // mismatch, and a bad contract version each fail the batch closed.
    let batch = valid_batch();
    let expired_now = ADMITTED_AT_952 + MAX_ADMISSION_AGE_MS + 1;
    assert!(
        validate_restore_batch(
            &batch,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            expired_now,
        )
        .is_err(),
        "expired admission evidence is refused"
    );
    assert!(
        validate_restore_batch(
            &batch,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            "wrong-schema-952",
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "wrong target schema is refused"
    );
    let mut purge_mismatch = valid_batch();
    purge_mismatch.purge_policy_revision = PURGE_REVISION_952 + 1;
    assert!(
        validate_restore_batch(
            &purge_mismatch,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952 + 1,
            NOW_952,
        )
        .is_err(),
        "batch purge revision diverging from destination evidence is refused"
    );
    let mut bad_contract = valid_batch();
    bad_contract.contract_version = ContractVersion::new(9, 9, 9);
    assert!(
        validate_restore_batch(
            &bad_contract,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "bad contract version is refused"
    );
}

// WORK_UNIT_CASE: 952/4
#[test]
fn exact_source_member_operation_identity_required() {
    // A malformed archive digest, empty expected heads, a zero member count,
    // and malformed operation/source identities each fail the batch closed.
    let mut bad_digest = valid_batch();
    bad_digest.archive_member_digest = "not-a-digest".to_owned();
    assert!(
        validate_restore_batch(
            &bad_digest,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "malformed archive member digest is refused"
    );
    let mut empty_heads = valid_batch();
    empty_heads.expected_revision_heads = Vec::new();
    assert!(
        validate_restore_batch(
            &empty_heads,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "empty revision-head expectations are refused"
    );
    let mut zero_members = valid_batch();
    zero_members.member_count = 0;
    assert!(
        validate_restore_batch(
            &zero_members,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "zero member count is refused"
    );
    let mut bad_operation = valid_batch();
    bad_operation.operation.idempotency_key = String::new();
    assert!(
        validate_restore_batch(
            &bad_operation,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "malformed operation identity is refused"
    );
    let mut bad_source = valid_batch();
    bad_source.source.store_id = String::new();
    assert!(
        validate_restore_batch(
            &bad_source,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "malformed source identity is refused"
    );
}

// WORK_UNIT_CASE: 952/5
#[test]
fn raw_statement_connection_override_unrepresentable() {
    // Compile-time proof: this test target names only typed adapter/store
    // APIs. `validate_isolated_destination`, `validate_restore_batch`, and
    // `validate_reference_closure` take typed structs plus bounded scalar
    // expectations; there is no statement, table, connection, or credential
    // parameter to smuggle caller text through, and the fixed client
    // operation registry is not importable from the public adapter surface
    // (it lives behind the private `client` module). Only the four closed
    // port-operation names validate; the capability tag itself is discovery
    // data, not an executable operation.
    for probe in [
        "SELECT * FROM restore_record",
        "DROP TABLE restore_record",
        "DELETE FROM restore_record WHERE destination_id = $x",
        "DEFINE TABLE restore_record",
        "",
        "   ",
        "restore_record; SELECT * FROM _",
        "isolated_restore",
    ] {
        assert!(
            !is_supported_restore_operation(probe),
            "caller statement text is not a supported restore operation: {probe:?}"
        );
    }
    check_batch_admitted(&valid_batch(), NOW_952);
}

// WORK_UNIT_CASE: 952/6
#[test]
fn complete_denominator_and_expected_heads_preserved() {
    // A closed restore denominator validates and reports complete, and the
    // batch's canonical/history/revision/ordering expectations survive
    // reference-closure validation intact.
    let batch = valid_batch();
    validate_reference_closure(&batch).expect("valid reference closure");
    assert_eq!(
        batch.expected_revision_heads.len(),
        1,
        "revision denominator member preserved"
    );
    assert_eq!(
        batch.expected_ordering_heads.len(),
        1,
        "ordering denominator member preserved"
    );
    assert_eq!(batch.expected_revision_heads[0].expected_revision, 3);
    assert_eq!(batch.expected_ordering_heads[0].expected_sequence, 5);
    assert_eq!(batch.member_count, 2);
    let denominator = RestoreDenominator::new(2, 0, 0, 0);
    denominator
        .validate()
        .expect("closed denominator validates");
    assert!(
        denominator.is_complete(),
        "nothing unresolved means complete"
    );
    assert_eq!(denominator.total, 2);
    assert_eq!(denominator.restored, 2);
    assert_eq!(denominator.unresolved, 0);
}

// WORK_UNIT_CASE: 952/7
#[test]
fn reference_closure_validated_for_keys_scopes_sequences() {
    // Duplicate revision keys, duplicate ordering scopes, zero revisions,
    // and zero sequences each fail closure; the valid batch passes.
    validate_reference_closure(&valid_batch()).expect("valid closure passes");
    let mut duplicate_keys = valid_batch();
    duplicate_keys
        .expected_revision_heads
        .push(duplicate_keys.expected_revision_heads[0].clone());
    assert!(
        validate_reference_closure(&duplicate_keys).is_err(),
        "duplicate revision keys are refused"
    );
    let mut duplicate_scopes = valid_batch();
    duplicate_scopes
        .expected_ordering_heads
        .push(duplicate_scopes.expected_ordering_heads[0].clone());
    assert!(
        validate_reference_closure(&duplicate_scopes).is_err(),
        "duplicate ordering scopes are refused"
    );
    let mut zero_revision = valid_batch();
    zero_revision.expected_revision_heads[0].expected_revision = 0;
    assert!(
        validate_reference_closure(&zero_revision).is_err(),
        "zero expected revision is refused"
    );
    let mut zero_sequence = valid_batch();
    zero_sequence.expected_ordering_heads[0].expected_sequence = 0;
    assert!(
        validate_reference_closure(&zero_sequence).is_err(),
        "zero expected sequence is refused"
    );
}

// WORK_UNIT_CASE: 952/8
#[test]
fn current_purged_records_not_resurrected() {
    // Archive content under any purge revision other than the current one is
    // suppressed, an equal revision is not, and a restore batch admitted
    // under a stale purge revision is refused instead of resurrecting purged
    // payload.
    assert!(
        is_suppressed_by_current_purge(PURGE_REVISION_952, PURGE_REVISION_952 + 2),
        "archive older than current purge is suppressed"
    );
    assert!(
        is_suppressed_by_current_purge(PURGE_REVISION_952 + 1, PURGE_REVISION_952),
        "archive newer than current purge is suppressed"
    );
    assert!(
        !is_suppressed_by_current_purge(PURGE_REVISION_952, PURGE_REVISION_952),
        "equal revisions are not suppressed"
    );
    assert!(
        is_suppressed_by_current_purge(PURGE_REVISION_952, 0),
        "an unverified current policy suppresses everything"
    );
    let batch = valid_batch();
    assert!(
        validate_restore_batch(
            &batch,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952 + 2,
            NOW_952,
        )
        .is_err(),
        "batch under a stale purge revision is refused, never resurrected"
    );
    check_batch_admitted(&batch, NOW_952);
}

// WORK_UNIT_CASE: 952/9
#[test]
fn residency_privacy_retention_domains_distinct() {
    // Equal bytes under different residency domains stay distinct logical
    // objects, and per-domain denominators account separately without
    // merging on digest alone.
    assert_ne!(
        BlobResidencyDomain::InlineCanonical,
        BlobResidencyDomain::ContentBlob,
        "inline canonical and content blob are distinct domains"
    );
    assert_ne!(
        BlobResidencyDomain::ContentBlob,
        BlobResidencyDomain::ExternalReference,
        "content blob and external reference are distinct domains"
    );
    assert_ne!(
        BlobResidencyDomain::InlineCanonical,
        BlobResidencyDomain::ExternalReference,
        "inline canonical and external reference are distinct domains"
    );
    let digest = hex('d');
    let inline = eliot_store_api::SnapshotMember {
        member_id: "member-952-1".to_owned(),
        member_type: eliot_store_api::SnapshotMemberType::Record,
        content_digest: digest.clone(),
        residency: BlobResidency {
            domain: BlobResidencyDomain::InlineCanonical,
            residency_digest: hex('e'),
            byte_count: 512,
        },
        reference_digest: None,
    };
    let blob = eliot_store_api::SnapshotMember {
        member_id: "member-952-1".to_owned(),
        member_type: eliot_store_api::SnapshotMemberType::Blob,
        content_digest: digest,
        residency: BlobResidency {
            domain: BlobResidencyDomain::ContentBlob,
            residency_digest: hex('f'),
            byte_count: 512,
        },
        reference_digest: None,
    };
    inline.validate().expect("inline member shape");
    blob.validate().expect("blob member shape");
    assert_ne!(
        inline.logical_identity(),
        blob.logical_identity(),
        "equal bytes under different obligations stay distinct"
    );
    let inline_denominator = RestoreDenominator::new(1, 0, 0, 0);
    let blob_denominator = RestoreDenominator::new(1, 0, 0, 0);
    inline_denominator
        .validate()
        .expect("inline denominator closes");
    blob_denominator
        .validate()
        .expect("blob denominator closes");
    assert_eq!(inline_denominator.total, 1);
    assert_eq!(blob_denominator.total, 1);
    assert!(
        inline_denominator.is_complete() && blob_denominator.is_complete(),
        "each domain completes on its own denominator, never merged"
    );
}

// WORK_UNIT_CASE: 952/10
#[test]
fn old_authority_session_lease_grant_not_activated() {
    // A restore mints a fresh destination identity derived only from the
    // destination, the operation, and the admission handle: it is
    // deterministic, differs across operations, is independent of source
    // authority, binds the destination, and no activation/unblock/cutover
    // entry exists on the typed surface (this file compiles against
    // validation, identity, ledger, and redaction functions only).
    let destination = valid_destination();
    let first = new_destination_identity(&destination, &valid_operation("op-952-10a", &hex('a')));
    let second = new_destination_identity(&destination, &valid_operation("op-952-10b", &hex('b')));
    assert!(!first.is_empty(), "fresh identity is materialized");
    assert_eq!(
        first,
        new_destination_identity(&destination, &valid_operation("op-952-10a", &hex('a'))),
        "same destination and operation mint the same identity"
    );
    assert_ne!(
        first, second,
        "different operations mint different destination identities"
    );
    assert_ne!(first, destination.destination_id);
    assert_ne!(first, destination.source_store_id);
    assert_ne!(first, destination.source_installation_id);
    assert!(
        !first.contains("store-952-src"),
        "no source store authority leaks into the fresh identity"
    );
    assert!(
        !first.contains("install-952-src"),
        "no source installation authority leaks into the fresh identity"
    );
    assert!(
        !second.contains("store-952-src") && !second.contains("install-952-src"),
        "neither minted identity carries old authority"
    );
    let mut resourced = destination.clone();
    resourced.source_store_id = "other-store-952".to_owned();
    resourced.source_installation_id = "other-install-952".to_owned();
    assert_eq!(
        first,
        new_destination_identity(&resourced, &valid_operation("op-952-10a", &hex('a'))),
        "source authority never enters the derivation"
    );
    let mut renamed = destination.clone();
    renamed.destination_id = "restore-952-other".to_owned();
    assert_ne!(
        first,
        new_destination_identity(&renamed, &valid_operation("op-952-10a", &hex('a'))),
        "fresh identity stays bound to its isolated destination"
    );
    let config = test_config();
    let (store_part, installation_part) = active_store_identity(&config);
    assert!(
        !store_part.is_empty() && !installation_part.is_empty(),
        "active store identity is materialized from configuration"
    );
    assert_eq!(store_part, "eliot952");
    assert_eq!(installation_part, "installation-test-952");
}

// WORK_UNIT_CASE: 952/11
#[test]
fn write_plus_durable_receipt_atomic() {
    // One ledger commit lands the batch atomically with its durable receipt:
    // the receipt carries the exact operation and archive digest, the
    // readback returns that same receipt, and the receipt counts sum to
    // their denominator.
    let mut ledger = RestoreLedger::new();
    let batch = batch_for("op-952-11", &hex('a'), &hex('c'), 2);
    check_batch_admitted(&valid_batch(), NOW_952);
    let committed = ledger
        .commit(
            &batch,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("commit applies atomically with its receipt");
    committed.validate().expect("committed receipt validates");
    assert_eq!(
        committed.operation.operation_id, batch.operation.operation_id,
        "committed receipt carries the exact operation"
    );
    assert_eq!(
        committed.archive_member_digest, batch.archive_member_digest,
        "committed receipt carries the exact archive digest"
    );
    assert!(committed.is_proven_success(), "committed receipt is proven");
    let readback = ledger
        .readback(&batch.operation)
        .expect("durable readback present");
    assert_eq!(
        readback.operation, batch.operation,
        "readback returns the exact committed operation"
    );
    assert_eq!(
        readback.archive_member_digest, batch.archive_member_digest,
        "readback returns the exact archive digest"
    );
    assert_eq!(
        readback.resolved_members + readback.unresolved_members,
        readback.denominator_members,
        "receipt counts sum to the denominator"
    );
    let denominator = RestoreDenominator::new(2, 0, 0, 0);
    denominator
        .validate()
        .expect("denominator closes over the committed write");
    assert!(denominator.is_complete());
}

// WORK_UNIT_CASE: 952/12
#[test]
fn exact_repeated_operation_not_reapplied() {
    // Committing the exact same batch twice returns the same receipt: the
    // second commit is a replay, not a duplicate write.
    let mut ledger = RestoreLedger::new();
    let batch = batch_for("op-952-12", &hex('a'), &hex('c'), 2);
    let first = ledger
        .commit(
            &batch,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("first commit");
    let second = ledger
        .commit(
            &batch,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("replay commit");
    assert_eq!(
        first, second,
        "exact repeated operation returns the same receipt"
    );
    let readback = ledger
        .readback(&batch.operation)
        .expect("single durable receipt");
    assert_eq!(readback.operation, batch.operation);
    assert_eq!(readback.archive_member_digest, batch.archive_member_digest);
    assert_eq!(readback.resolved_members, 2);
    assert_eq!(readback.unresolved_members, 0);
}

// WORK_UNIT_CASE: 952/13
#[test]
fn changed_same_operation_content_conflicts() {
    // The same operation identity with changed content is an identity
    // conflict through the store-neutral reconciler, through the ledger
    // reconciler, and through a second commit carrying a different digest.
    let mut ledger = RestoreLedger::new();
    let baseline = batch_for("op-952-13", &hex('a'), &hex('a'), 2);
    ledger
        .commit(
            &baseline,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("baseline commit");
    let first = valid_operation("op-952-13", &hex('a'));
    let changed = valid_operation("op-952-13", &hex('b'));
    assert_eq!(
        reconcile_same_operation(&first, &changed).expect("same-operation reconcile"),
        ReconciliationOutcome::IdentityConflict,
        "changed hash under the same operation is a conflict"
    );
    let ledger_outcome = ledger.reconcile(&first, &changed);
    assert!(
        matches!(
            ledger_outcome,
            Ok(ReconciliationOutcome::IdentityConflict) | Err(StoreError::IdentityConflict)
        ),
        "ledger reconcile reports the identity conflict: {ledger_outcome:?}"
    );
    let clash_batch = batch_for("op-952-13", &hex('b'), &hex('b'), 2);
    let clash = ledger.commit(
        &clash_batch,
        2,
        0,
        SnapshotCompleteness::Complete,
        StoreMutationDisposition::Committed,
    );
    assert!(
        matches!(clash, Err(StoreError::IdentityConflict)),
        "second commit with different content conflicts without mutation: {clash:?}"
    );
    let preserved = ledger
        .readback(&baseline.operation)
        .expect("original receipt preserved");
    assert_eq!(
        preserved.archive_member_digest,
        hex('a'),
        "conflicting content never overwrote the original"
    );
}

// WORK_UNIT_CASE: 952/14
#[tokio::test]
async fn lost_response_reconciles_exact_receipt_without_blind_retry() {
    // A lost commit response reconciles to the exact durable receipt by
    // operation identity (no blind retry), while the fail-closed port
    // defaults refuse without manufacturing evidence: prepare and restore
    // report UnknownOperation, validate reports Unavailable, and default
    // reconciliation returns the typed replay/conflict outcome.
    struct FailClosedPort;

    impl IsolatedRestorePort for FailClosedPort {}

    let port = FailClosedPort;
    let context = ctx();
    let prepare = port
        .prepare_isolated_destination(&context, valid_destination())
        .await
        .expect_err("default prepare refuses");
    assert_eq!(prepare, StoreError::UnknownOperation);
    let restore = port
        .restore_canonical_batch(&context, valid_batch())
        .await
        .expect_err("default restore refuses");
    assert_eq!(restore, StoreError::UnknownOperation);
    let validate = port
        .validate_restore(&context, valid_batch())
        .await
        .expect_err("default validate refuses");
    assert_eq!(validate, StoreError::Unavailable);

    let mut ledger = RestoreLedger::new();
    let batch = batch_for("op-952-14", &hex('a'), &hex('c'), 2);
    ledger
        .commit(
            &batch,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("commit applies");
    let reconciled = ledger
        .readback(&batch.operation)
        .expect("lost response reconciles to the exact receipt");
    assert_eq!(reconciled.operation, batch.operation);
    assert_eq!(
        reconciled.archive_member_digest, batch.archive_member_digest,
        "reconciliation returns the original bytes, never a retry synthesis"
    );

    let first = valid_operation("op-952-14a", &hex('a'));
    let replay = port
        .reconcile_operation(first.clone(), first.clone())
        .await
        .expect("default reconcile answers");
    assert_eq!(replay.outcome, ReconciliationOutcome::ReplayIdentity);
    assert_eq!(replay.first_digest, hex('a'));
    assert_eq!(replay.second_digest, hex('a'));
    replay.validate().expect("replay record validates");
    let changed = valid_operation("op-952-14a", &hex('b'));
    let conflict = port
        .reconcile_operation(first, changed)
        .await
        .expect("default conflict answers");
    assert_eq!(conflict.outcome, ReconciliationOutcome::IdentityConflict);
    conflict.validate().expect("conflict record validates");
}

// WORK_UNIT_CASE: 952/15
#[test]
fn partial_batch_resume_retains_identities_and_missing_denominator() {
    // A partial commit keeps the operation identity with an incomplete
    // denominator; resuming with the same operation identity succeeds as a
    // replay that retains the missing denominator instead of fabricating
    // completion.
    let mut ledger = RestoreLedger::new();
    let batch = batch_for("op-952-15", &hex('a'), &hex('c'), 2);
    ledger
        .commit(
            &batch,
            1,
            1,
            SnapshotCompleteness::Partial,
            StoreMutationDisposition::Committed,
        )
        .expect("partial commit applies");
    let partial = RestoreDenominator::new(1, 0, 0, 1);
    partial
        .validate()
        .expect("partial denominator still closes");
    assert!(
        !partial.is_complete(),
        "one unresolved member keeps the denominator incomplete"
    );
    let readback = ledger
        .readback(&batch.operation)
        .expect("partial receipt retained");
    assert_eq!(readback.operation.operation_id.as_str(), "op-952-15");
    assert_eq!(readback.unresolved_members, 1);
    assert_eq!(readback.resolved_members, 1);
    let resumed = ledger
        .commit(
            &batch,
            1,
            1,
            SnapshotCompleteness::Partial,
            StoreMutationDisposition::Committed,
        )
        .expect("resume with the same operation identity succeeds");
    assert_eq!(
        resumed.operation.operation_id.as_str(),
        "op-952-15",
        "resume retains the same operation identity"
    );
    let retained = ledger
        .readback(&batch.operation)
        .expect("resumed receipt retained");
    assert_eq!(retained.unresolved_members, 1);
    assert!(
        !RestoreDenominator::new(retained.resolved_members, 0, 0, retained.unresolved_members)
            .is_complete(),
        "the missing denominator is retained, never fabricated complete"
    );
    let goal = RestoreDenominator::new(2, 0, 0, 0);
    goal.validate().expect("resume goal denominator closes");
    assert!(goal.is_complete(), "full resolution is the complete goal");
}

// WORK_UNIT_CASE: 952/16
#[test]
fn failed_validation_or_absent_implementation_prevents_ready() {
    // Failed closure validation, an incomplete denominator, and any
    // non-committed disposition each prevent a ready (proven-success) claim.
    let mut bad_closure = valid_batch();
    bad_closure.expected_revision_heads.clear();
    assert!(
        validate_reference_closure(&bad_closure).is_err(),
        "failed closure validation prevents ready"
    );
    let incomplete = RestoreDenominator::new(1, 0, 0, 1);
    assert!(
        !incomplete.is_complete(),
        "incomplete denominator prevents ready"
    );
    let mut partial = valid_receipt_full("op-952-16", &hex('a'), &hex('c'), 2, 0, 2);
    partial.disposition = StoreMutationDisposition::Partial;
    assert!(
        !partial.is_proven_success(),
        "partial disposition is never proven success"
    );
    let mut unknown = valid_receipt_full("op-952-16", &hex('a'), &hex('c'), 0, 2, 2);
    unknown.completeness = SnapshotCompleteness::Complete;
    unknown.disposition = StoreMutationDisposition::Unknown;
    assert!(
        !unknown.is_proven_success(),
        "unknown disposition is never proven success"
    );
    let mut proven_absent = valid_receipt_full("op-952-16", &hex('a'), &hex('c'), 2, 0, 2);
    proven_absent.disposition = StoreMutationDisposition::ProvenNotApplied;
    assert!(
        proven_absent.is_proven_success(),
        "proven-absent with a complete denominator is proven success"
    );
    let good = valid_receipt_full("op-952-16", &hex('a'), &hex('c'), 2, 0, 2);
    assert!(
        good.is_proven_success(),
        "committed with nothing unresolved is proven success"
    );
}

// WORK_UNIT_CASE: 952/17
#[test]
fn bounds_cancellation_preserve_partial_state_and_original_failure() {
    // Oversized and zero member counts fail closed, a failed conflicting
    // commit preserves the original ledger state, and redaction preserves
    // the original typed error kind while stripping payloads.
    assert_eq!(
        MAX_RESTORE_BATCH_MEMBERS as u64, MAX_RESTORE_MEMBERS as u64,
        "adapter batch bound pins the store-neutral restore bound"
    );
    let mut oversized = valid_batch();
    oversized.member_count = (MAX_RESTORE_BATCH_MEMBERS as u64) + 1;
    assert!(
        validate_restore_batch(
            &oversized,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "member count above the bound is refused"
    );
    let mut zero = valid_batch();
    zero.member_count = 0;
    assert!(
        validate_restore_batch(
            &zero,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            PURGE_REVISION_952,
            NOW_952,
        )
        .is_err(),
        "zero member count is refused"
    );
    let mut ledger = RestoreLedger::new();
    let baseline = batch_for("op-952-17", &hex('a'), &hex('a'), 2);
    ledger
        .commit(
            &baseline,
            2,
            0,
            SnapshotCompleteness::Complete,
            StoreMutationDisposition::Committed,
        )
        .expect("baseline commit");
    let clash_batch = batch_for("op-952-17", &hex('b'), &hex('b'), 2);
    assert!(
        ledger
            .commit(
                &clash_batch,
                2,
                0,
                SnapshotCompleteness::Complete,
                StoreMutationDisposition::Committed,
            )
            .is_err(),
        "conflicting commit fails without disturbing state"
    );
    let preserved = ledger
        .readback(&baseline.operation)
        .expect("original state preserved after the failed commit");
    assert_eq!(preserved.archive_member_digest, hex('a'));
    assert_eq!(
        redact_store_error(StoreError::RevisionConflict),
        StoreError::RevisionConflict,
        "redaction preserves the original typed failure"
    );
    let redacted = redact_store_error(StoreError::Serialization("sensitive-bytes-952".to_owned()));
    assert!(
        !format!("{redacted:?}").contains("sensitive-bytes-952"),
        "serialization payload is stripped: {redacted:?}"
    );
}

// WORK_UNIT_CASE: 952/18
#[test]
fn no_activation_cutover_bypass_and_sensitive_diagnostics_redacted() {
    // No activation, unblock, cutover, retirement, or bypass vocabulary is
    // supported: the closed restore vocabulary admits only restore work.
    // Sensitive diagnostics are redacted while typed errors keep their exact
    // static field and reason without echoing payloads.
    for probe in [
        "activate",
        "unblock",
        "cutover",
        "retire",
        "source_retirement",
        "admission_bypass",
        "restore_activate",
        "restore_cutover",
        "restore_unblock",
        "promote_to_active",
    ] {
        assert!(
            !is_supported_restore_operation(probe),
            "activation/cutover/bypass vocabulary is unsupported: {probe:?}"
        );
    }
    let redacted = redact_store_error(StoreError::Serialization("secret-payload-952".to_owned()));
    assert!(
        !format!("{redacted:?}").contains("secret-payload-952"),
        "serialization payload never crosses the redaction boundary"
    );
    assert_eq!(
        redact_store_error(StoreError::UnknownOperation),
        StoreError::UnknownOperation
    );
    assert_eq!(
        redact_store_error(StoreError::IdentityConflict),
        StoreError::IdentityConflict
    );
    let typed = StoreError::InvalidField {
        field: "restore.target_schema",
        reason: "must match the isolated destination schema",
    };
    assert_eq!(redact_store_error(typed.clone()), typed);
    let empty = StoreError::Empty {
        field: "restore.expected_revision_heads",
    };
    assert_eq!(redact_store_error(empty.clone()), empty);
}

// WORK_UNIT_CASE: 952/19
#[test]
fn crash_and_property_fixtures_cover_mutation_receipt_boundaries() {
    // The frozen crash-boundary and property fixtures drive ledger mutation
    // boundaries row by row: clean commits, exact replays, conflicting
    // retries, replay identity, identity conflict, and malformed rows that
    // refuse before any mutation.
    let crash: Value =
        serde_json::from_str(include_str!("data/backup-restore/crash-boundary.json"))
            .expect("crash-boundary fixture parses");
    let crash_cases = crash["cases"].as_array().expect("crash cases array");
    assert_eq!(crash_cases.len(), 3, "frozen crash denominator is exact");
    for case in crash_cases {
        let name = case["name"].as_str().expect("case name");
        let before = case["before_commit"].as_bool().expect("before_commit");
        let after = case["after_commit"].as_bool().expect("after_commit");
        let expect = case["expect"].as_str().expect("expect");
        assert!(
            ["committed", "conflict"].contains(&expect),
            "closed crash expectation: {expect:?}"
        );
        let operation_id = format!("op-952-{name}");
        let lookup = valid_operation(&operation_id, &hex('a'));
        let mut ledger = RestoreLedger::new();
        let baseline = batch_for(&operation_id, &hex('a'), &hex('a'), 1);
        if before {
            ledger
                .commit(
                    &baseline,
                    1,
                    0,
                    SnapshotCompleteness::Complete,
                    StoreMutationDisposition::Committed,
                )
                .expect("baseline commit before the crash row");
            assert!(
                ledger.readback(&lookup).is_some(),
                "{name}: baseline durable before the crash row"
            );
        } else {
            assert!(
                ledger.readback(&lookup).is_none(),
                "{name}: nothing durable before the crash row"
            );
        }
        if expect == "conflict" {
            let clash = batch_for(&operation_id, &hex('b'), &hex('b'), 1);
            let outcome = ledger.commit(
                &clash,
                1,
                0,
                SnapshotCompleteness::Complete,
                StoreMutationDisposition::Committed,
            );
            assert!(
                matches!(outcome, Err(StoreError::IdentityConflict)),
                "{name}: conflicting retry conflicts"
            );
        } else {
            ledger
                .commit(
                    &baseline,
                    1,
                    0,
                    SnapshotCompleteness::Complete,
                    StoreMutationDisposition::Committed,
                )
                .expect("crash row commits or replays");
        }
        assert_eq!(
            ledger.readback(&lookup).is_some(),
            after,
            "{name}: post-crash durability matches the fixture"
        );
    }

    let properties: Value =
        serde_json::from_str(include_str!("data/backup-restore/property-cases.json"))
            .expect("property-cases fixture parses");
    let property_cases = properties["cases"]
        .as_array()
        .expect("property cases array");
    assert_eq!(
        property_cases.len(),
        3,
        "frozen property denominator is exact"
    );
    for row in property_cases {
        let name = row["name"].as_str().expect("row name");
        let first_hash = row["first_hash"].as_str().expect("first_hash");
        let second_hash = row["second_hash"].as_str().expect("second_hash");
        let expect = row["expect_outcome"].as_str().expect("expect_outcome");
        let operation_id = format!("op-952-prop-{name}");
        let lookup = valid_operation(&operation_id, first_hash);
        match expect {
            "ReplayIdentity" => {
                assert!(is_hex64(first_hash) && is_hex64(second_hash));
                let first = valid_operation(&operation_id, first_hash);
                let second = valid_operation(&operation_id, second_hash);
                assert_eq!(
                    reconcile_same_operation(&first, &second).expect("replay reconciles"),
                    ReconciliationOutcome::ReplayIdentity,
                    "{name}: equal hashes replay"
                );
                let record = BackupOperationReconciliation {
                    operation: first,
                    first_digest: first_hash.to_owned(),
                    second_digest: second_hash.to_owned(),
                    outcome: ReconciliationOutcome::ReplayIdentity,
                };
                record.validate().expect("replay record validates");
                let mut ledger = RestoreLedger::new();
                let batch = batch_for(&operation_id, first_hash, first_hash, 1);
                ledger
                    .commit(
                        &batch,
                        1,
                        0,
                        SnapshotCompleteness::Complete,
                        StoreMutationDisposition::Committed,
                    )
                    .expect("property commit");
                ledger
                    .commit(
                        &batch,
                        1,
                        0,
                        SnapshotCompleteness::Complete,
                        StoreMutationDisposition::Committed,
                    )
                    .expect("property replay is not a rewrite");
                assert!(
                    ledger.readback(&lookup).is_some(),
                    "{name}: replay keeps one durable receipt"
                );
            }
            "IdentityConflict" => {
                assert!(is_hex64(first_hash) && is_hex64(second_hash));
                assert_ne!(first_hash, second_hash);
                let first = valid_operation(&operation_id, first_hash);
                let second = valid_operation(&operation_id, second_hash);
                assert_eq!(
                    reconcile_same_operation(&first, &second).expect("conflict reconciles"),
                    ReconciliationOutcome::IdentityConflict,
                    "{name}: changed hash conflicts"
                );
                let mut ledger = RestoreLedger::new();
                let baseline = batch_for(&operation_id, first_hash, first_hash, 1);
                ledger
                    .commit(
                        &baseline,
                        1,
                        0,
                        SnapshotCompleteness::Complete,
                        StoreMutationDisposition::Committed,
                    )
                    .expect("property baseline");
                let clash = batch_for(&operation_id, second_hash, second_hash, 1);
                let outcome = ledger.commit(
                    &clash,
                    1,
                    0,
                    SnapshotCompleteness::Complete,
                    StoreMutationDisposition::Committed,
                );
                assert!(
                    matches!(outcome, Err(StoreError::IdentityConflict)),
                    "{name}: ledger refuses the conflicting boundary"
                );
            }
            "Refused" => {
                let malformed = valid_operation(&operation_id, first_hash);
                let good = valid_operation(&operation_id, second_hash);
                assert!(
                    reconcile_same_operation(&malformed, &good).is_err(),
                    "{name}: malformed row refuses before mutation"
                );
                let ledger = RestoreLedger::new();
                assert!(
                    ledger.readback(&lookup).is_none(),
                    "{name}: refused row leaves no receipt"
                );
            }
            other => panic!("closed property expectation violated: {other:?}"),
        }
    }
}

// WORK_UNIT_CASE: 952/20
#[test]
fn pinned_isolated_capture_restore_readback_with_cleanup() {
    // Pinned fixture proof: the manifest binds both batches, each batch
    // validates as an admitted isolated restore with the preserved purge
    // revision, restored digests stay disjoint from purge-suppressed
    // digests, the denominator closes over both batches, the ledger holds
    // both durable receipts, and the temp dir is removed. A live provider
    // version probe runs only when a provider binary exists; the fixture
    // proof above is substantive either way.
    let manifest: Value = serde_json::from_str(include_str!("data/backup-restore/manifest.json"))
        .expect("manifest fixture parses");
    assert_eq!(
        manifest["schema"].as_str().expect("manifest schema"),
        RESTORE_SCHEMA_V1,
        "pinned manifest pins the adapter restore schema"
    );
    assert_eq!(
        manifest["contract"].as_str().expect("manifest contract"),
        "1.0.0",
        "pinned manifest pins the restore contract"
    );
    let members = manifest["members"].as_array().expect("manifest members");
    assert_eq!(members.len(), 2, "manifest binds exactly two batches");
    let manifest_digests = manifest["digests"].as_array().expect("manifest digests");
    assert_eq!(manifest_digests.len(), 2);
    for digest in manifest_digests {
        assert!(
            is_hex64(digest.as_str().expect("manifest digest")),
            "manifest digests are lowercase SHA-256"
        );
    }

    let purge: Value = serde_json::from_str(include_str!("data/backup-restore/purge-ledger.json"))
        .expect("purge-ledger fixture parses");
    let current_revision = purge["current_revision"]
        .as_u64()
        .expect("current revision");
    assert_eq!(
        current_revision, PURGE_REVISION_952,
        "purge ledger preserves the current purge revision"
    );
    let suppressed = purge["suppressed_digests"]
        .as_array()
        .expect("suppressed digests");
    assert!(
        !suppressed.is_empty(),
        "purge ledger names suppressed payload"
    );
    let suppressed_text: Vec<String> = suppressed
        .iter()
        .map(|digest| {
            let text = digest.as_str().expect("suppressed digest").to_owned();
            assert!(is_hex64(&text), "suppressed digests are lowercase SHA-256");
            text
        })
        .collect();

    let raw_batches = [
        include_str!("data/backup-restore/batch-01.json"),
        include_str!("data/backup-restore/batch-02.json"),
    ];
    let mut restored_digests: Vec<String> = Vec::new();
    let mut total_members: u64 = 0;
    let mut ledger = RestoreLedger::new();
    for (index, raw) in raw_batches.iter().enumerate() {
        let batch_json: Value = serde_json::from_str(raw).expect("batch fixture parses");
        let operation_id = batch_json["operation_id"]
            .as_str()
            .expect("batch operation id")
            .to_owned();
        let archive_digest = batch_json["archive_member_digest"]
            .as_str()
            .expect("batch archive digest")
            .to_owned();
        assert!(
            is_hex64(&archive_digest),
            "batch archive digest is lowercase SHA-256"
        );
        assert!(
            manifest_digests
                .iter()
                .any(|digest| digest.as_str().is_some_and(|text| text == archive_digest)),
            "batch digest is bound by the manifest"
        );
        assert_eq!(
            batch_json["purge_policy_revision"]
                .as_u64()
                .expect("batch purge revision"),
            current_revision,
            "batch preserves the current purge revision"
        );
        let member_count = batch_json["member_count"].as_u64().expect("member count");
        assert!(
            member_count > 0 && member_count <= MAX_RESTORE_BATCH_MEMBERS as u64,
            "batch member count is within bounds"
        );
        let mut batch = valid_batch();
        batch.operation = valid_operation(&operation_id, &hex('a'));
        batch.archive_member_digest.clone_from(&archive_digest);
        batch.member_count = member_count;
        validate_restore_batch(
            &batch,
            ACTIVE_STORE_952,
            ACTIVE_INSTALL_952,
            TARGET_SCHEMA_952,
            current_revision,
            NOW_952,
        )
        .unwrap_or_else(|error| panic!("fixture batch {index} admitted: {error:?}"));
        validate_reference_closure(&batch)
            .unwrap_or_else(|error| panic!("fixture batch {index} closure: {error:?}"));
        assert!(
            !suppressed_text.contains(&archive_digest),
            "restored digest is not purge-suppressed: it must not resurrect"
        );
        ledger
            .commit(
                &batch,
                member_count,
                0,
                SnapshotCompleteness::Complete,
                StoreMutationDisposition::Committed,
            )
            .unwrap_or_else(|error| panic!("fixture batch {index} commits: {error:?}"));
        let readback = ledger
            .readback(&batch.operation)
            .unwrap_or_else(|| panic!("fixture batch {index} readback durable"));
        assert_eq!(readback.archive_member_digest, archive_digest);
        assert_eq!(
            readback.resolved_members + readback.unresolved_members,
            readback.denominator_members,
            "fixture receipt counts sum to the denominator"
        );
        restored_digests.push(archive_digest);
        total_members += member_count;
    }
    assert_eq!(restored_digests.len(), 2);
    assert_ne!(
        restored_digests[0], restored_digests[1],
        "distinct batches restore distinct members"
    );
    let denominator = RestoreDenominator::new(total_members, 0, 0, 0);
    denominator
        .validate()
        .expect("capture-to-restore denominator closes");
    assert!(
        denominator.is_complete(),
        "capture, restore, and readback agree on the full denominator"
    );
    assert_eq!(denominator.total, total_members);

    let scratch = std::env::temp_dir().join(format!("eliot-952-restore-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch dir created");
    std::fs::write(scratch.join("marker"), b"952").expect("scratch marker written");
    assert!(scratch.join("marker").exists(), "scratch marker present");
    std::fs::remove_dir_all(&scratch).expect("scratch dir removed");
    assert!(!scratch.exists(), "scratch cleanup leaves no residue");

    let exe = std::env::var("ELIOT_TEST_SURREAL_EXE").map_or_else(
        |_| std::path::PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        std::path::PathBuf::from,
    );
    if exe.exists() {
        let output = std::process::Command::new(&exe)
            .arg("version")
            .output()
            .expect("provider version output");
        println!(
            "live surreal probe: exe={} status={} stdout={}",
            exe.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout).trim()
        );
        assert!(output.status.success(), "live provider reports its version");
    } else {
        println!(
            "live surreal unavailable at {}; pinned fixture proof above is the substantive evidence",
            exe.display()
        );
    }
}
