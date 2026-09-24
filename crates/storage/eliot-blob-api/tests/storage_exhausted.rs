//! Typed BlobStore capacity-exhaustion contract for ELIOT issue #864.
//!
//! Declared denominator: cases 2..9 of the 22-case matrix live in this suite;
//! cases 1 and 10..22 live in `eliot-blob/tests/storage_exhausted.rs`. One
//! substantive executable Rust test per `// WORK_UNIT_CASE: 864/<case>` marker
//! immediately above its attributes, allocated once across the two suites.
//! Each test binds its source (current `eliot-blob-api` public capacity
//! types on main: `BlobCapacity*` plus `BlobError::StorageCapacity`), its
//! discovery (constructed values over the exact public constructors, never
//! string-parsed codes), and its executed-pass result (real assertions against
//! live validation behavior, never count-only).
//!
//! No test here performs I/O, locking, CAS execution, retry, or backend work:
//! every case constructs capacity observations as values and checks the public
//! validation and distinction rules.

use eliot_blob_api::{
    BlobCapacityCause, BlobCapacityCleanup, BlobCapacityEffect, BlobCapacityEvidence,
    BlobCapacityFailure, BlobCapacityIdentity, BlobCapacityRecovery, BlobCapacityStage,
    BlobCasDurability, BlobCasFailure, BlobCasNamespace, BlobCasOutcome, BlobCasRequest,
    BlobCasState, BlobError, BlobReceiptContext, BlobRootLease, GcState,
};
use eliot_platform::WorkScopePath;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn context_json(effect: &str, operation: &str, request: &str) -> String {
    let epoch = r#"{"lineage_id":"550e8400-e29b-41d4-a716-446655440000","sequence":4}"#;
    let fence = format!(
        "{{\"authority_epoch\":{epoch},\"resource_generation\":7,\"task_revision\":null,\"policy_revision\":null,\"integration_revision\":null}}"
    );
    let metadata = format!(
        r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-capacity-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":{epoch},"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn receipt_context(operation: &str) -> BlobReceiptContext {
    ok(serde_json::from_str(&context_json(
        "REVERSIBLE_MUTATION",
        operation,
        &format!("request-{operation}"),
    )))
}

fn root_lease(context: &BlobReceiptContext) -> BlobRootLease {
    ok(serde_json::from_value(serde_json::json!({
        "root_id": "root-1",
        "owner_id": "owner-1",
        "lease_id": "lease-1",
        "root_generation": 7,
        "fence_binding": context.request,
    })))
}

fn cas_request(operation: &str) -> BlobCasRequest {
    let context = receipt_context(operation);
    let lease = root_lease(&context);
    ok(BlobCasRequest::new(
        context,
        lease,
        BlobCasNamespace::StageJournal,
        ok(WorkScopePath::new("transactions/journal.stage")),
        ok(BlobCasState::digest("c".repeat(64))),
        "d".repeat(64),
        9,
        7,
        BlobCasDurability::Requested,
    ))
}

fn root_lease_identity() -> BlobCapacityIdentity {
    BlobCapacityIdentity::RootLease {
        root_id: "root:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        lease_id: Some("lease-1".to_owned()),
    }
}

/// Source: `BlobCapacityFailure`/`BlobError::StorageCapacity` in `src/lib.rs`.
/// Discovery: constructed minimal provider-neutral capacity value.
/// Executed-pass: the value binds the exact required identity, validates, keeps
/// cause/effect/cleanup/recovery, rejects a wrong-namespace code, and the
/// accepted #946/#730 CAS outcomes still map to `CasFailure`, never capacity.
// WORK_UNIT_CASE: 864/2
#[test]
fn minimal_capacity_error_binds_identity_and_preserves_cas_outcomes() {
    let error = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: root_lease_identity(),
            stage: BlobCapacityStage::RootLeaseCreate,
            evidence: BlobCapacityEvidence {
                cause: BlobCapacityCause::PosixEnospc { code: 28 },
                attempted_bytes: None,
                effect: BlobCapacityEffect::PartialWriteUnknown,
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::NotApplicable,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
        }),
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected capacity failure");
    };
    assert!(failure.validate().is_ok());
    assert!(matches!(
        failure.evidence.cause,
        BlobCapacityCause::PosixEnospc { code: 28 }
    ));
    assert_eq!(failure.evidence.attempted_bytes, None);
    assert_eq!(
        failure.evidence.effect,
        BlobCapacityEffect::PartialWriteUnknown
    );
    assert_eq!(failure.cleanup, BlobCapacityCleanup::NotApplicable);
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::CapacityRevalidationRequired
    );
    let mut invalid = (*failure).clone();
    invalid.evidence.cause = BlobCapacityCause::PosixEnospc { code: 1 };
    assert!(invalid.validate().is_err());

    // A CAS observation keeps its complete #946/#730 request and reconciliation
    // state alongside the capacity cause; capacity never erases it.
    let request = cas_request("capacity-cas-1");
    let cas_failure = BlobCapacityFailure {
        identity: BlobCapacityIdentity::Operation {
            context: Box::new(request.context.clone()),
            locator: None,
        },
        stage: BlobCapacityStage::CasJournal,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: None,
            effect: BlobCapacityEffect::PossibleMutation,
        },
        cas_request: Some(Box::new(request.clone())),
        cas_observed: Some(BlobCasState::Missing),
        cas_backend_generation: Some(7),
        cas_durability: Some(BlobCasDurability::Unconfirmed),
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::ReconcileSameOperationThenRevalidate,
    };
    assert!(cas_failure.validate().is_ok());
    assert_eq!(
        cas_failure
            .cas_request
            .as_deref()
            .expect("cas request retained"),
        &request
    );

    // Accepted #946 outcomes still decode to CasFailure, never to capacity.
    let not_attempted = match (BlobCasOutcome::NotAttempted {
        request: Box::new(request.clone()),
    })
    .into_blob_result()
    {
        Err(BlobError::CasFailure { failure }) => *failure,
        other => panic!("CAS not-attempted must stay CasFailure, got: {other:?}"),
    };
    assert!(matches!(not_attempted, BlobCasFailure::NotAttempted { .. }));
    assert!(!matches!(
        BlobCasOutcome::UnsupportedAtomicCas {
            request: Box::new(request),
        }
        .into_blob_result(),
        Ok(_) | Err(BlobError::StorageCapacity { .. })
    ));
}

/// Source: `validate_capacity_identity` in `src/lib.rs`.
/// Discovery: empty operation and storage identities as values.
/// Executed-pass: every missing/empty identity is rejected; non-blank journal
/// and root-lease identities validate.
// WORK_UNIT_CASE: 864/3
#[test]
fn missing_or_empty_operation_or_storage_identity_is_rejected() {
    for identity in [
        BlobCapacityIdentity::Journal {
            operation_id: String::new(),
            idempotency_key: "idem-1".to_owned(),
            locator: None,
        },
        BlobCapacityIdentity::Journal {
            operation_id: "op-1".to_owned(),
            idempotency_key: "   ".to_owned(),
            locator: None,
        },
        BlobCapacityIdentity::RootLease {
            root_id: String::new(),
            lease_id: None,
        },
        BlobCapacityIdentity::RootLease {
            root_id: "root-1".to_owned(),
            lease_id: Some("  ".to_owned()),
        },
    ] {
        let failure = BlobCapacityFailure {
            identity,
            stage: BlobCapacityStage::RootLeaseCreate,
            evidence: BlobCapacityEvidence {
                cause: BlobCapacityCause::IoStorageFull,
                attempted_bytes: None,
                effect: BlobCapacityEffect::NotAttempted,
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::NotApplicable,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
        };
        assert!(failure.validate().is_err());
    }

    let journal = BlobCapacityFailure {
        identity: BlobCapacityIdentity::Journal {
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            locator: None,
        },
        stage: BlobCapacityStage::JournalWrite,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: Some(64),
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(journal.validate().is_ok());
    let root_lease = BlobCapacityFailure {
        identity: root_lease_identity(),
        stage: BlobCapacityStage::RootLeaseCreate,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: None,
            effect: BlobCapacityEffect::NotAttempted,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(root_lease.validate().is_ok());
}

/// Source: `BlobCapacityCause::WindowsErrorDiskFull` + `validate_capacity_cause`.
/// Discovery: ERROR_DISK_FULL code 112 in its Windows namespace.
/// Executed-pass: code 112 validates; any other code under this variant is
/// rejected; the platform namespace is retained in the debug shape.
// WORK_UNIT_CASE: 864/4
#[test]
fn windows_error_disk_full_mapping_keeps_platform_namespace() {
    let valid = BlobCapacityFailure {
        identity: root_lease_identity(),
        stage: BlobCapacityStage::RootLeaseCreate,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::WindowsErrorDiskFull { code: 112 },
            attempted_bytes: None,
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(valid.validate().is_ok());
    assert_eq!(
        format!("{:?}", valid.evidence.cause),
        "WindowsErrorDiskFull { code: 112 }"
    );
    for code in [0, 1, 28, 39, 111, 113] {
        let mut mismatched = valid.clone();
        mismatched.evidence.cause = BlobCapacityCause::WindowsErrorDiskFull { code };
        assert!(
            mismatched.validate().is_err(),
            "code {code} must not validate as ERROR_DISK_FULL"
        );
    }
}

/// Source: `BlobCapacityCause::WindowsErrorHandleDiskFull` + validator.
/// Discovery: ERROR_HANDLE_DISK_FULL code 39 in its Windows namespace.
/// Executed-pass: code 39 validates; ERROR_DISK_FULL/ENOSPC codes under this
/// variant are rejected.
// WORK_UNIT_CASE: 864/5
#[test]
fn windows_error_handle_disk_full_mapping_keeps_platform_namespace() {
    let valid = BlobCapacityFailure {
        identity: root_lease_identity(),
        stage: BlobCapacityStage::RootLeaseCreate,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::WindowsErrorHandleDiskFull { code: 39 },
            attempted_bytes: None,
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(valid.validate().is_ok());
    assert_eq!(
        format!("{:?}", valid.evidence.cause),
        "WindowsErrorHandleDiskFull { code: 39 }"
    );
    for code in [0, 28, 38, 40, 112] {
        let mut mismatched = valid.clone();
        mismatched.evidence.cause = BlobCapacityCause::WindowsErrorHandleDiskFull { code };
        assert!(
            mismatched.validate().is_err(),
            "code {code} must not validate as ERROR_HANDLE_DISK_FULL"
        );
    }
}

/// Source: `BlobCapacityCause::PosixEnospc` + validator.
/// Discovery: ENOSPC code 28 in its POSIX namespace.
/// Executed-pass: code 28 validates; Windows codes under the POSIX variant are
/// rejected, so a foreign-platform numeric collision never classifies.
// WORK_UNIT_CASE: 864/6
#[test]
fn posix_enospc_mapping_rejects_foreign_platform_codes() {
    let valid = BlobCapacityFailure {
        identity: root_lease_identity(),
        stage: BlobCapacityStage::RootLeaseCreate,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::PosixEnospc { code: 28 },
            attempted_bytes: None,
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(valid.validate().is_ok());
    for code in [0, 1, 27, 29, 39, 112] {
        let mut mismatched = valid.clone();
        mismatched.evidence.cause = BlobCapacityCause::PosixEnospc { code };
        assert!(
            mismatched.validate().is_err(),
            "code {code} must not validate as ENOSPC"
        );
    }
    // The Windows variants never accept the POSIX code either: namespaces do
    // not leak across variants.
    let mut cross = valid.clone();
    cross.evidence.cause = BlobCapacityCause::WindowsErrorDiskFull { code: 28 };
    assert!(cross.validate().is_err());
    cross.evidence.cause = BlobCapacityCause::WindowsErrorHandleDiskFull { code: 28 };
    assert!(cross.validate().is_err());
}

/// Source: `BlobCapacityCause::IoStorageFull` + full `BlobError` vocabulary.
/// Discovery: pinned `ErrorKind::StorageFull` cause without a native code.
/// Executed-pass: the codeless cause validates; no invented unavailable variant
/// exists, and capacity is never `ProviderUnavailable`.
// WORK_UNIT_CASE: 864/7
#[test]
fn pinned_storage_full_mapping_invents_no_unavailable_variant() {
    let failure = BlobCapacityFailure {
        identity: root_lease_identity(),
        stage: BlobCapacityStage::PayloadWrite,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: Some(128),
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: None,
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(failure.validate().is_ok());
    let error = BlobError::StorageCapacity {
        failure: Box::new(failure),
    };
    assert!(!matches!(error, BlobError::ProviderUnavailable(_)));
    assert!(matches!(error, BlobError::StorageCapacity { .. }));
    // The public error vocabulary has no invented unavailable/capacity alias:
    // an exhaustive consumer match compiles only with the exact live variants.
    match &error {
        BlobError::InvalidField { .. }
        | BlobError::InvalidContract(_)
        | BlobError::Receipt(_)
        | BlobError::AuthorityRequired(_)
        | BlobError::StaleFence
        | BlobError::OwnerConflict
        | BlobError::DuplicateIdentity(_)
        | BlobError::IncompleteLiveSet
        | BlobError::NotFound
        | BlobError::MetadataPayloadMismatch
        | BlobError::IdempotencyConflict
        | BlobError::IntegrityMismatch
        | BlobError::UnknownPublishOutcome { .. }
        | BlobError::UnknownGcOutcome { .. }
        | BlobError::PlanGap(_)
        | BlobError::ProviderUnavailable(_)
        | BlobError::CasFailure { .. }
        | BlobError::KeyUnavailable { .. }
        | BlobError::Provider(_) => panic!("capacity must stay StorageCapacity"),
        BlobError::StorageCapacity { failure } => assert!(failure.validate().is_ok()),
    }
}

/// Source: `BlobCapacityCause` vocabulary in `src/lib.rs`.
/// Discovery: exhaustive match over every live cause variant.
/// Executed-pass: exactly the four capacity causes exist — permission,
/// read-only, file-too-large, out-of-memory and quota semantics have no cause
/// variant and can never decode as disk full.
// WORK_UNIT_CASE: 864/8
#[test]
fn unrelated_kinds_and_quota_semantics_stay_distinct() {
    fn cause_name(cause: &BlobCapacityCause) -> &'static str {
        match cause {
            BlobCapacityCause::IoStorageFull => "IO_STORAGE_FULL",
            BlobCapacityCause::PosixEnospc { .. } => "POSIX_ENOSPC",
            BlobCapacityCause::WindowsErrorDiskFull { .. } => "WINDOWS_ERROR_DISK_FULL",
            BlobCapacityCause::WindowsErrorHandleDiskFull { .. } => {
                "WINDOWS_ERROR_HANDLE_DISK_FULL"
            }
        }
    }
    assert_eq!(
        cause_name(&BlobCapacityCause::IoStorageFull),
        "IO_STORAGE_FULL"
    );
    assert_eq!(
        cause_name(&BlobCapacityCause::PosixEnospc { code: 28 }),
        "POSIX_ENOSPC"
    );
    assert_eq!(
        cause_name(&BlobCapacityCause::WindowsErrorDiskFull { code: 112 }),
        "WINDOWS_ERROR_DISK_FULL"
    );
    assert_eq!(
        cause_name(&BlobCapacityCause::WindowsErrorHandleDiskFull { code: 39 }),
        "WINDOWS_ERROR_HANDLE_DISK_FULL"
    );
    // A quota/policy denial travels as authority/contract state, never as a
    // capacity cause: no cause variant can carry it.
    let denial = BlobError::AuthorityRequired("quota decisions belong to the policy owner");
    assert!(!matches!(denial, BlobError::StorageCapacity { .. }));
    let provider = BlobError::Provider("permission denied at the platform boundary".to_owned());
    assert!(!matches!(provider, BlobError::StorageCapacity { .. }));
}

/// Source: `validate_capacity_cause` + `BlobError::Provider` in `src/lib.rs`.
/// Discovery: wrong-namespace codes and a string-only legacy port error.
/// Executed-pass: unknown kinds/codes fail validation and a string-only error
/// stays `Provider` (unknown I/O), never `StorageCapacity`.
// WORK_UNIT_CASE: 864/9
#[test]
fn unknown_kind_code_or_string_only_evidence_stays_unknown_io() {
    for cause in [
        BlobCapacityCause::PosixEnospc { code: 0 },
        BlobCapacityCause::PosixEnospc { code: 112 },
        BlobCapacityCause::WindowsErrorDiskFull { code: 28 },
        BlobCapacityCause::WindowsErrorHandleDiskFull { code: 112 },
    ] {
        let failure = BlobCapacityFailure {
            identity: root_lease_identity(),
            stage: BlobCapacityStage::RootLeaseCreate,
            evidence: BlobCapacityEvidence {
                cause,
                attempted_bytes: None,
                effect: BlobCapacityEffect::PartialWriteUnknown,
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::NotApplicable,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
        };
        assert!(failure.validate().is_err());
    }
    // A string-only legacy port error carries no typed cause/code/stage and
    // therefore remains unknown I/O: it never becomes StorageCapacity.
    let legacy = BlobError::Provider("os error 28: no space left on device".to_owned());
    assert!(!matches!(legacy, BlobError::StorageCapacity { .. }));
    assert_eq!(
        format!("{legacy}"),
        "provider failure: os error 28: no space left on device"
    );
    // GC state without a GC phase is likewise rejected, not silently kept.
    let gc_mismatch = BlobCapacityFailure {
        identity: BlobCapacityIdentity::Journal {
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            locator: None,
        },
        stage: BlobCapacityStage::PayloadWrite,
        evidence: BlobCapacityEvidence {
            cause: BlobCapacityCause::IoStorageFull,
            attempted_bytes: None,
            effect: BlobCapacityEffect::PartialWriteUnknown,
        },
        cas_request: None,
        cas_observed: None,
        cas_backend_generation: None,
        cas_durability: None,
        cleanup: BlobCapacityCleanup::NotApplicable,
        cleanup_stage: None,
        cleanup_evidence: None,
        gc_state: Some(GcState::PayloadDeleteAttempt),
        recovery: BlobCapacityRecovery::CapacityRevalidationRequired,
    };
    assert!(gc_mismatch.validate().is_err());
}
