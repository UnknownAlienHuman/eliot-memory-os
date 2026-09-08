use eliot_blob_api::{
    BlobCapacityCause, BlobCapacityCleanup, BlobCapacityEffect, BlobCapacityEvidence,
    BlobCapacityFailure, BlobCapacityIdentity, BlobCapacityRecovery, BlobCapacityStage, BlobError,
    PublishState,
};

#[test]
fn storage_capacity_preserves_cause_effect_and_root_identity() {
    let error = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: BlobCapacityIdentity::RootLease {
                root_id: "root:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                lease_id: Some("lease-1".to_owned()),
            },
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
}

#[test]
fn storage_capacity_keeps_possible_publication_and_cas_reconciliation() {
    let error = BlobError::StorageCapacity {
        failure: Box::new(BlobCapacityFailure {
            identity: BlobCapacityIdentity::Journal {
                operation_id: "op-1".to_owned(),
                idempotency_key: "idem-1".to_owned(),
                locator: None,
            },
            stage: BlobCapacityStage::CommitWrite,
            evidence: BlobCapacityEvidence {
                cause: BlobCapacityCause::IoStorageFull,
                attempted_bytes: Some(128),
                effect: BlobCapacityEffect::PossiblePublication {
                    state: PublishState::MetadataDurable,
                },
            },
            cas_request: None,
            cas_observed: None,
            cas_backend_generation: None,
            cas_durability: None,
            cleanup: BlobCapacityCleanup::Failed,
            cleanup_stage: None,
            cleanup_evidence: None,
            gc_state: None,
            recovery: BlobCapacityRecovery::ReconcileSameOperationThenRevalidate,
        }),
    };
    let BlobError::StorageCapacity { failure } = error else {
        panic!("expected capacity failure");
    };
    assert!(failure.validate().is_ok());
    assert!(matches!(
        failure.evidence.effect,
        BlobCapacityEffect::PossiblePublication {
            state: PublishState::MetadataDurable
        }
    ));
    assert_eq!(failure.cleanup, BlobCapacityCleanup::Failed);
    assert_eq!(
        failure.recovery,
        BlobCapacityRecovery::ReconcileSameOperationThenRevalidate
    );
}
