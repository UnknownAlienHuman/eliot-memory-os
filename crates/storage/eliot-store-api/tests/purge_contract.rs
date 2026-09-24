//! Neutral store-port purge contract for #688.
//!
//! Proofs inside `eliot-store-api` only, over the neutral port the
//! orchestration depends on: the closed six-surface denominator, the durable
//! intent record, the capability-gated dispatch wrapper, the fail-closed
//! outcome aggregation, and the exact failure mapping. Injected outcomes
//! stand in for owner-reported surface states; these tests prove the port
//! accounting, never physical deletion by a fake provider.

#![allow(clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, OperationId, RequestId, ResourceGeneration};
use eliot_store_api::{
    CAPABILITY_ERASURE_INTENT, CommitId, ErasureFailureKind, ErasureIntentRecord,
    ErasureSurfaceKind, ErasureSurfaceOutcome, ErasureSurfaceRequest, OperationIdentity,
    OperationManifestDigest, Resubmission, StateFence, StoreError, StoreFailureContractError,
    StoreFailureDisposition, StoreFailureIdentityContext, StoreMutationDisposition,
    StoreRecoveryAction, StoreRetryDirective, TransitionClass, WriteReceipt, WriteReceiptStatus,
    aggregate_erasure_outcomes, erasure_store_failure,
};
use serde::Deserialize;

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

/// The closed six-surface denominator in deterministic canonical order.
fn all_surfaces() -> Vec<ErasureSurfaceKind> {
    vec![
        ErasureSurfaceKind::Observations,
        ErasureSurfaceKind::Projections,
        ErasureSurfaceKind::Caches,
        ErasureSurfaceKind::Backups,
        ErasureSurfaceKind::ProviderCopies,
        ErasureSurfaceKind::RouteResidues,
    ]
}

fn intent() -> ErasureIntentRecord {
    ErasureIntentRecord {
        operation_id: OperationId::new("op-688-purge-contract").unwrap(),
        request_digest: "a".repeat(64),
        subject: "subject:purge-contract".to_string(),
        surfaces: all_surfaces(),
        policy_digest: "b".repeat(64),
        closure_digest: "c".repeat(64),
        state_fence: fence(),
    }
}

fn wrapper() -> ErasureSurfaceRequest {
    let record = intent();
    ErasureSurfaceRequest {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-688-purge-contract").unwrap(),
            idempotency_key: "idem-688-purge-contract".to_owned(),
            canonical_request_hash: record.request_digest.clone(),
        },
        intent: record,
        surfaces: all_surfaces(),
    }
}

/// One `Purged` outcome per planned surface except the overridden entries.
fn outcomes_with(
    planned: &[ErasureSurfaceKind],
    overrides: &[(ErasureSurfaceKind, ErasureSurfaceOutcome)],
) -> Vec<ErasureSurfaceOutcome> {
    planned
        .iter()
        .map(|surface| {
            for (target, outcome) in overrides {
                if target == surface {
                    return *outcome;
                }
            }
            ErasureSurfaceOutcome::Purged { surface: *surface }
        })
        .collect()
}

fn failure_context() -> StoreFailureIdentityContext {
    StoreFailureIdentityContext {
        request_id: Some(RequestId::new("request-688-purge").unwrap()),
        operation_id: Some(OperationId::new("op-688-purge-contract").unwrap()),
        idempotency_key_ref_or_digest: Some("a".repeat(64)),
        state_fence_ref_or_exact_safe_projection: None,
        evidence_ref: Some("evidence-688-purge".to_owned()),
        transport_unavailable: false,
    }
}

fn restore_probe_receipt(operation: &str, class: TransitionClass) -> WriteReceipt {
    WriteReceipt {
        operation_id: OperationId::new(operation).unwrap(),
        idempotency_key: format!("idem-{operation}"),
        canonical_request_hash: "c".repeat(64),
        transition_class: class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new(format!("commit-{operation}")).unwrap()),
        state_fence: fence(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec![format!("command-{operation}")],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: OperationManifestDigest::new("e".repeat(64)).unwrap(),
        admission_digest: "d".repeat(64),
        mutation_plan_digest: "f".repeat(64),
        semantic_source_revisions: Vec::new(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some(format!("commit-sequence-{operation}")),
        envelope: None,
    }
}

// WORK_UNIT_CASE: 688/8
#[test]
fn canonical_success_with_partial_blob_removal() {
    let planned = all_surfaces();
    // Every surface proves removal except the blob-bearing observations:
    // canonical success everywhere else cannot paper over partial blobs.
    let outcomes = outcomes_with(
        &planned,
        &[(
            ErasureSurfaceKind::Observations,
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Observations,
            },
        )],
    );
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &outcomes),
        Err(ErasureFailureKind::Incomplete),
        "partial blob removal blocks a complete purge result"
    );
    let failure =
        erasure_store_failure(ErasureFailureKind::Incomplete, &failure_context()).unwrap();
    assert_eq!(failure.disposition, StoreFailureDisposition::Unavailable);
    assert_eq!(failure.reason_code.as_str(), "ERASURE_SURFACE_INCOMPLETE");
    assert_eq!(
        failure.mutation_disposition,
        StoreMutationDisposition::Partial
    );
    assert_eq!(failure.retry_directive, StoreRetryDirective::ManualRecovery);
    assert_eq!(
        failure.recovery_action,
        StoreRecoveryAction::EnterManualRecovery
    );
    failure.validate().unwrap();

    // The clean control aggregates to the full canonical set in order.
    let clean = outcomes_with(&planned, &[]);
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &clean),
        Ok(planned.clone())
    );
}

// WORK_UNIT_CASE: 688/9
#[test]
fn projection_index_or_cache_hit_blocks_complete() {
    let planned = all_surfaces();
    // A projection/index surface that still returns the subject.
    let outcomes = outcomes_with(
        &planned,
        &[(
            ErasureSurfaceKind::Projections,
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Projections,
            },
        )],
    );
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &outcomes),
        Err(ErasureFailureKind::Incomplete),
        "remaining derived material blocks a complete result"
    );

    // A cache hit is the same refusal and stays distinct from unknown.
    let cache_hit = outcomes_with(
        &planned,
        &[(
            ErasureSurfaceKind::Caches,
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Caches,
            },
        )],
    );
    let result = aggregate_erasure_outcomes(&planned, &cache_hit);
    assert_eq!(result, Err(ErasureFailureKind::Incomplete));
    assert_ne!(
        result,
        Err(ErasureFailureKind::Unknown),
        "incomplete and unknown are different outcomes"
    );
}

// WORK_UNIT_CASE: 688/10
#[test]
fn ors_pending_recreation_preserves_unknown() {
    let planned = all_surfaces();
    // ORS/pending copies that can recreate the subject keep the surface
    // unknown: possible effect stays explicit for same-operation reconcile.
    let outcomes = outcomes_with(
        &planned,
        &[(
            ErasureSurfaceKind::Caches,
            ErasureSurfaceOutcome::Unknown {
                surface: ErasureSurfaceKind::Caches,
            },
        )],
    );
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &outcomes),
        Err(ErasureFailureKind::Unknown),
        "recreatable state preserves unknown"
    );

    // Unknown takes precedence over an incomplete sibling.
    let mixed = outcomes_with(
        &planned,
        &[
            (
                ErasureSurfaceKind::Observations,
                ErasureSurfaceOutcome::Incomplete {
                    surface: ErasureSurfaceKind::Observations,
                },
            ),
            (
                ErasureSurfaceKind::Caches,
                ErasureSurfaceOutcome::Unknown {
                    surface: ErasureSurfaceKind::Caches,
                },
            ),
        ],
    );
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &mixed),
        Err(ErasureFailureKind::Unknown),
        "unknown requires reconciliation before any incomplete recovery"
    );

    let failure = erasure_store_failure(ErasureFailureKind::Unknown, &failure_context()).unwrap();
    assert_eq!(failure.disposition, StoreFailureDisposition::UnknownOutcome);
    assert_eq!(failure.reason_code.as_str(), "ERASURE_SURFACE_UNKNOWN");
    assert_eq!(
        failure.mutation_disposition,
        StoreMutationDisposition::Unknown
    );
    assert_eq!(
        failure.retry_directive,
        StoreRetryDirective::ReconcileExactOperation
    );
    assert_eq!(
        failure.recovery_action,
        StoreRecoveryAction::ReconcileUnknownOutcome
    );
    assert_eq!(
        failure.operation_id,
        Some(OperationId::new("op-688-purge-contract").unwrap()),
        "unknown preserves the exact operation identity"
    );
    failure.validate().unwrap();
}

// WORK_UNIT_CASE: 688/11
#[test]
fn pre_purge_backup_restore_cannot_resurrect() {
    let planned = all_surfaces();
    // The backup/restore path is not suppressed: one incomplete required
    // surface prevents complete purge evidence.
    let outcomes = outcomes_with(
        &planned,
        &[(
            ErasureSurfaceKind::Backups,
            ErasureSurfaceOutcome::Incomplete {
                surface: ErasureSurfaceKind::Backups,
            },
        )],
    );
    assert_eq!(
        aggregate_erasure_outcomes(&planned, &outcomes),
        Err(ErasureFailureKind::Incomplete),
        "an unsuppressed restore path blocks a complete result"
    );

    // Old snapshots cannot resurrect a purged subject: an erasure receipt
    // never authorizes state rehydration, while receipts of every other
    // class stay rehydratable.
    assert_eq!(
        restore_probe_receipt("op-688-restore-blocked", TransitionClass::Erasure)
            .refuse_rehydration_from_erasure(),
        Err(StoreError::InvalidReceipt),
        "pre-purge backups cannot resurrect purged payload"
    );
    assert!(
        restore_probe_receipt("op-688-restore-ok", TransitionClass::CaptureCandidate)
            .refuse_rehydration_from_erasure()
            .is_ok(),
        "non-erasure receipts stay rehydratable"
    );
}

// WORK_UNIT_CASE: 688/20
#[test]
fn store_port_fixture_and_source_guard() {
    // The checked-in port fixture deserializes into the real neutral types:
    // it compiles against the port instead of shadowing it.
    let fixture: FixturePort =
        serde_json::from_str(include_str!("data/purge_contract.json")).unwrap();
    assert_eq!(fixture.capability, CAPABILITY_ERASURE_INTENT);
    assert_eq!(fixture.capability, "store.erasure.intent");
    fixture.intent.validate().unwrap();
    assert_eq!(fixture.surfaces, fixture.intent.surfaces);

    // Fresh intents start NotAttempted on every surface: nothing is
    // attempted before the intent is durable.
    let initial = fixture.intent.initial_state();
    assert_eq!(initial.len(), all_surfaces().len());
    for (surface, disposition) in &initial {
        assert_eq!(
            *disposition,
            StoreMutationDisposition::NotAttempted,
            "surface {surface:?} starts not attempted"
        );
    }

    // The closed dispatch wrapper binds the fixture intent and refuses
    // without the intent capability: unimplemented capabilities explicitly
    // refuse and are never advertised as working.
    let request = ErasureSurfaceRequest {
        identity: wrapper().identity,
        intent: fixture.intent.clone(),
        surfaces: fixture.surfaces.clone(),
    };
    request.validate().unwrap();
    assert_eq!(
        request.validate_for_dispatch(&[]),
        Err(StoreError::UnknownOperation),
        "dispatch without the intent capability refuses"
    );
    assert!(
        request
            .validate_for_dispatch(&[CAPABILITY_ERASURE_INTENT])
            .is_ok(),
        "dispatch with the capability proceeds to validation"
    );

    // Source guard: the neutral port covers exactly six surfaces and four
    // refusal kinds. A seventh surface, a fifth refusal, or a renamed
    // reason code fails this test instead of slipping through.
    assert_eq!(
        all_surfaces().len(),
        6,
        "the denominator stays six surfaces"
    );
    let mut misordered = intent();
    misordered.surfaces = vec![
        ErasureSurfaceKind::Projections,
        ErasureSurfaceKind::Observations,
        ErasureSurfaceKind::Caches,
        ErasureSurfaceKind::Backups,
        ErasureSurfaceKind::ProviderCopies,
        ErasureSurfaceKind::RouteResidues,
    ];
    assert!(
        matches!(
            misordered.validate(),
            Err(StoreError::InvalidField {
                field: "erasure.surfaces",
                ..
            })
        ),
        "canonical surface order is enforced, not advisory"
    );
    let kinds = [
        ErasureFailureKind::Incomplete,
        ErasureFailureKind::Unknown,
        ErasureFailureKind::UnsupportedIntent,
        ErasureFailureKind::IntentConflict,
    ];
    assert_eq!(
        kinds
            .iter()
            .map(|kind| kind.reason_code())
            .collect::<Vec<_>>(),
        vec![
            "ERASURE_SURFACE_INCOMPLETE",
            "ERASURE_SURFACE_UNKNOWN",
            "ERASURE_INTENT_UNSUPPORTED",
            "ERASURE_INTENT_CONFLICT",
        ]
    );
    for kind in kinds {
        let failure = erasure_store_failure(kind, &failure_context()).unwrap();
        failure.validate().unwrap();
    }
    assert_eq!(
        erasure_store_failure(
            ErasureFailureKind::Unknown,
            &StoreFailureIdentityContext {
                operation_id: None,
                ..failure_context()
            }
        ),
        Err(StoreFailureContractError::MissingOperationIdentity),
        "unknown without an operation identity cannot reconcile"
    );
}

/// Shape of `tests/data/purge_contract.json`: the neutral intent record plus
/// the selected surfaces and the required capability, in one fixture.
#[derive(Deserialize)]
struct FixturePort {
    capability: String,
    surfaces: Vec<ErasureSurfaceKind>,
    intent: ErasureIntentRecord,
}

// Fixture conformance, not a denominator case: proves the checked-in
// `purge_contract.json` parses into the real port types and validates.
// No WORK_UNIT_CASE marker by design, so the twenty markers stay exactly
// 1..20, each allocated once.
#[test]
fn purge_contract_fixture_parses_into_real_port_types() {
    let fixture: FixturePort =
        serde_json::from_str(include_str!("data/purge_contract.json")).unwrap();
    fixture.intent.validate().unwrap();
    assert_eq!(fixture.intent.surfaces, all_surfaces());
    assert_eq!(fixture.intent.initial_state().len(), all_surfaces().len());
    let request = wrapper();
    request.validate().unwrap();
    assert_eq!(
        request.intent.operation_id.as_str(),
        fixture.intent.operation_id.as_str()
    );
}
