//! Contract tests for the named canonical erasure transaction (issue #1712).
//!
//! Pure in-crate proofs only: explicit user-request admission builds a
//! deterministic `ApplyErasure` plan under `TransitionClass::Erasure` that the
//! generated catalogue admits, while missing approvals, out-of-manifest
//! class/effect, and undeclared parameters fail closed pre-execution.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_contracts::{EpochId, EpochLineageId, OperationId, ResourceGeneration};
use eliot_store_api::{
    EffectClass, ErasureAdmissionRequest, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, OperationIdentity, OrderingScopeId, ScopeId, SecurityContext, StoreError,
    TransitionClass, admit_erasure_transition, decode_erasure_surfaces, encode_erasure_surfaces,
    generated_operation_manifests, operation_manifest_set_digest,
};
use serde_json::json;
use std::num::NonZeroU64;

fn fence() -> eliot_store_api::StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis())
}

fn admission_request() -> ErasureAdmissionRequest {
    let entries = generated_operation_manifests().unwrap();
    let set_digest = operation_manifest_set_digest(&entries).unwrap();
    ErasureAdmissionRequest {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-erasure-1").unwrap(),
            idempotency_key: "idem-erasure-1".to_owned(),
            canonical_request_hash: "c".repeat(64),
        },
        scope_id: ScopeId::new("scope-erasure").unwrap(),
        ordering_scope: OrderingScopeId::new("scope-erasure").unwrap(),
        state_fence: fence(),
        subject: "subject-erasure".to_owned(),
        surfaces: vec!["CanonicalPayload".to_owned(), "Index".to_owned()],
        reason: "user requested deletion".to_owned(),
        requester: "user:alice".to_owned(),
        approval_refs: vec!["approval-user-1".to_owned()],
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest,
        security: SecurityContext::default(),
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
    }
}

#[test]
fn admitted_erasure_plan_passes_catalogue_and_is_deterministic() {
    let entries = generated_operation_manifests().unwrap();
    let first = admit_erasure_transition(&admission_request()).unwrap();
    assert_eq!(
        first.transition_class,
        TransitionClass::Erasure,
        "erasure owns its transition class"
    );
    assert_eq!(
        first.requested_effect_ceiling,
        EffectClass::ReversibleMutation,
        "erasure ceiling is the maximum store-allowed effect"
    );
    assert_eq!(first.named_operations.len(), 1);
    assert_eq!(
        first.named_operations[0].operation,
        NamedMutationOperation::ApplyErasure
    );
    assert!(
        first.validate_against_catalogue(&entries).is_ok(),
        "declared erasure class admits pre-execution"
    );
    // Deterministic: the same explicit request always yields the same bytes,
    // including canonical surface order regardless of input order.
    let mut reordered = admission_request();
    reordered.surfaces = vec!["Index".to_owned(), "CanonicalPayload".to_owned()];
    let second = admit_erasure_transition(&reordered).unwrap();
    assert_eq!(
        eliot_store_api::canonical_json_bytes(&first).unwrap(),
        eliot_store_api::canonical_json_bytes(&second).unwrap()
    );
    assert_eq!(
        second.named_operations[0].parameters["surfaces"],
        json!("CanonicalPayload,Index")
    );
}

#[test]
fn erasure_without_explicit_approval_is_rejected_pre_execution() {
    let mut request = admission_request();
    request.approval_refs.clear();
    assert!(
        matches!(
            admit_erasure_transition(&request),
            Err(StoreError::InvalidField {
                field: "proof_or_approval_ref",
                ..
            })
        ),
        "automatic paths furnish no approval and must fail"
    );
}

#[test]
fn erasure_out_of_manifest_class_or_effect_is_rejected() {
    let entries = generated_operation_manifests().unwrap();
    let set_digest = operation_manifest_set_digest(&entries).unwrap();

    // Wrong transition class for the named erasure operation.
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.transition_class = TransitionClass::CaptureCandidate;
    assert_eq!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::TransitionClassExceeded)
    );

    // Effect above the declared erasure ceiling.
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.requested_effect_ceiling = EffectClass::ExternalEffect;
    assert_eq!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::TransitionClassExceeded)
    );

    // Stale manifest digest never reaches the store.
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.operation_manifest_digest =
        eliot_store_api::OperationManifestDigest::new("0".repeat(64)).unwrap();
    assert_eq!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::ManifestMismatch)
    );
    let _ = set_digest;
}

#[test]
fn erasure_typed_parameters_are_closed() {
    let entries = generated_operation_manifests().unwrap();
    let set_digest = operation_manifest_set_digest(&entries).unwrap();
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.operation_manifest_digest = set_digest;

    // Missing explicit reason fails as a typed parameter error.
    plan.named_operations[0].parameters.remove("reason");
    assert!(matches!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    // Unknown parameters fail closed the same way.
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.operation_manifest_digest = operation_manifest_set_digest(&entries).unwrap();
    plan.named_operations[0]
        .parameters
        .insert("maintenance_window".to_owned(), json!("nightly"));
    assert!(matches!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField { .. })
    ));

    // A second command bundled with the deletion breaks the single-identity rule.
    let mut plan = admit_erasure_transition(&admission_request()).unwrap();
    plan.named_operations.push(NamedMutationRequest {
        operation: NamedMutationOperation::ApplyErasure,
        parameters: BTreeMap::new(),
    });
    assert_eq!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::TransitionClassExceeded)
    );
}

#[test]
fn erasure_surface_denominator_is_canonical_and_checked() {
    assert_eq!(
        encode_erasure_surfaces(&["Index", "CanonicalPayload"]).unwrap(),
        "CanonicalPayload,Index"
    );
    assert_eq!(
        decode_erasure_surfaces("CanonicalPayload,Index").unwrap(),
        vec!["CanonicalPayload".to_owned(), "Index".to_owned()]
    );
    assert!(encode_erasure_surfaces(&[]).is_err(), "empty scope refuses");
    assert!(
        encode_erasure_surfaces(&["Index", "Index"]).is_err(),
        "duplicates refuse"
    );
    assert!(
        decode_erasure_surfaces("Index,,Projection").is_err(),
        "blank entries refuse"
    );
}
