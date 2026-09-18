//! Wire integration tests for the reserved-write operation (issue #991).
//!
//! Seven cases (`991/1`, `991/2`, `991/3`, `991/11`, `991/16`, `991/17`,
//! `991/18`) carry #990's sealed admission projection through the closed
//! Store wire: request validation, capability declaration, frame mapping,
//! legacy compatibility, correlation/identity separation, rejection families,
//! and the closed-shape guard. Client serialization, dispatch, and the
//! session capability gate live in the sibling `reserved_write_client` and
//! `reserved_write_dispatch` suites; markers are allocated once across the
//! three files.
//!
//! Typed inputs freeze in `data/reserved-write/`: `reserved-write-request.json`
//! is the exact valid request under test, `legacy-apply.json` the frozen
//! ordinary-`Apply` encoding that must keep decoding as `Apply`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_protocol::{ProtocolVersion, RequestIdentity};
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    CAPABILITIES, CAPABILITY_APPLY, CAPABILITY_RESERVED_WRITE, CommitId, EFFECTS, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OperationManifestDigest, OrderingHead, OrderingHeadExpectation,
    OrderingScopeId, PreparedTransition, RequestMeta, ReservedScopeBinding, ReservedWriteRequest,
    Resubmission, RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext, StoreError,
    StoreRequest, StoreResponse, TransitionClass, WriteAdmissionParams, WriteAdmissionProjection,
    WriteReceipt, WriteReceiptStatus, WriterEpochBinding, decode_request_frame,
    decode_response_frame, issue_store_receipt_envelope, request_frame, response_frame,
};
use serde_json::{Value, json};

const LINEAGE_991: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    let lineage = EpochLineageId::new(LINEAGE_991).unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-991-1").unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-991").unwrap(),
        source_id: SourceId::new("source-991").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition() -> PreparedTransition {
    PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-991-1").unwrap(),
            idempotency_key: "idem-991-1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-991-1").unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-991-1").unwrap()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new("manifest-991-1").unwrap(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-991-1"))]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    }
}

fn scope_binding() -> ReservedScopeBinding {
    ReservedScopeBinding {
        scope: OrderingScopeId::new("scope-991-1").unwrap(),
        reserved_sequence: 7,
        expected_sequence: 6,
        expected_head_digest: "c".repeat(64),
    }
}

fn epoch_binding() -> WriterEpochBinding {
    WriterEpochBinding {
        lineage_id: "epoch-lineage-991".to_owned(),
        epoch: 5,
        predecessor_lineage_id: None,
        predecessor_epoch: None,
    }
}

fn admission_for(transition: &PreparedTransition) -> WriteAdmissionProjection {
    let params = WriteAdmissionParams {
        reservation_id: "reservation-991-1".to_owned(),
        reservation_order: 42,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes: vec![scope_binding()],
        writer_epoch: epoch_binding(),
        state_fence: fence(),
        source_id: "source-991".to_owned(),
        created_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        recovery_owner: "recovery-owner-991".to_owned(),
    };
    WriteAdmissionProjection::bind(transition, params).unwrap()
}

fn valid_request() -> ReservedWriteRequest {
    let transition = transition();
    let admission = admission_for(&transition);
    ReservedWriteRequest {
        context: context(),
        transition,
        admission,
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new("rev-991-1").unwrap(),
            expected_revision: 3,
            state_fence: fence(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope-991-1").unwrap(),
            expected_sequence: 6,
            state_fence: fence(),
        }],
    }
}

fn legacy_apply_request() -> StoreRequest {
    let request = valid_request();
    StoreRequest::Apply {
        context: request.context,
        transition: request.transition,
        expected_revision_heads: request.expected_revision_heads,
        expected_ordering_heads: request.expected_ordering_heads,
    }
}

fn test_identity(context: &RequestMeta, idempotency_key: &str) -> RequestIdentity {
    RequestIdentity {
        request: RequestBinding {
            metadata: context.clone(),
            state_fence: context.state_fence.clone(),
        },
        idempotency_key: idempotency_key.to_owned(),
        deadline_unix_ms: 1,
        cancellation_id: "cancel-991".to_owned(),
    }
}

fn receipt_for(request: &ReservedWriteRequest) -> WriteReceipt {
    let transition = &request.transition;
    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: transition.transition_class,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-991-1").unwrap()),
        state_fence: request.context.state_fence.clone(),
        ordering_sequences: vec![OrderingHead {
            scope: OrderingScopeId::new("scope-991-1").unwrap(),
            sequence: 7,
            state_fence: fence(),
        }],
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["capture-observation".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        error_code: None,
        resubmission: Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    receipt.envelope =
        Some(issue_store_receipt_envelope(&request.context, transition, &receipt, 1).unwrap());
    receipt.validate().unwrap();
    receipt
}

fn fixture_request_value() -> Value {
    let text = include_str!("data/reserved-write/reserved-write-request.json");
    serde_json::from_str(text).unwrap()
}

fn fixture_request() -> ReservedWriteRequest {
    serde_json::from_value(fixture_request_value()).unwrap()
}

// WORK_UNIT_CASE: 991/1
#[test]
fn complete_request_to_frame_to_response_map_preserves_exact_identity() {
    // The coordinated wire integration on the wire segment: sealed request
    // validation, capability declaration, authenticated request-frame
    // mapping, and the correlated response frame. Client serialization and
    // dispatch are covered in the sibling suites with the same frozen shape.
    let request = fixture_request();
    assert!(request.validate().is_ok(), "frozen fixture validates");
    assert_eq!(
        request,
        valid_request(),
        "fixture matches the sealed builder"
    );
    let wire = StoreRequest::ReservedWrite {
        request: request.clone(),
    };
    assert!(wire.validate().is_ok());
    assert_eq!(wire.capability(), CAPABILITY_RESERVED_WRITE);
    let identity = test_identity(
        &request.context,
        &request.transition.identity.idempotency_key,
    );
    let frame = request_frame(
        "connection-991",
        ProtocolVersion::CURRENT,
        request.context.request_id.clone(),
        identity,
        wire.clone(),
    )
    .unwrap();
    let (request_id, _, decoded) = decode_request_frame(&frame).unwrap();
    assert_eq!(request_id, request.context.request_id);
    assert_eq!(decoded, wire);
    assert!(decoded.validate().is_ok());
    let receipt = receipt_for(&request);
    let response_frame = response_frame(
        "connection-991",
        ProtocolVersion::CURRENT,
        Some(request.context.request_id.clone()),
        StoreResponse::Transaction {
            receipt: receipt.clone(),
        },
    )
    .unwrap();
    let (response_id, response) =
        decode_response_frame(&response_frame, "connection-991", ProtocolVersion::CURRENT).unwrap();
    assert_eq!(response_id, request.context.request_id);
    let StoreResponse::Transaction { receipt: observed } = response else {
        panic!("reserved-write answer must be the Transaction receipt");
    };
    assert_eq!(observed, receipt);
    assert_eq!(
        observed.operation_id,
        request.transition.identity.operation_id
    );
}

// WORK_UNIT_CASE: 991/2
#[test]
fn exact_reserved_request_round_trip_is_codec_stable() {
    // Exact round trip across the actual JSON codec: value, string, and frame
    // payload forms all decode to the identical request, and re-encoding is
    // byte-deterministic.
    let request = fixture_request();
    let value = serde_json::to_value(&request).unwrap();
    let from_value: ReservedWriteRequest = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(from_value, request);
    let text = serde_json::to_string(&request).unwrap();
    let from_text: ReservedWriteRequest = serde_json::from_str(&text).unwrap();
    assert_eq!(from_text, request);
    let wire = StoreRequest::ReservedWrite {
        request: request.clone(),
    };
    let wire_text = serde_json::to_string(&wire).unwrap();
    let wire_replay: StoreRequest = serde_json::from_str(&wire_text).unwrap();
    assert_eq!(wire_replay, wire);
    assert_eq!(
        serde_json::to_vec(&wire).unwrap(),
        serde_json::to_vec(&wire_replay).unwrap(),
        "re-encoding is byte-deterministic"
    );
    assert_eq!(
        serde_json::to_value(&wire).unwrap().get("op"),
        Some(&json!("reserved_write"))
    );
}

// WORK_UNIT_CASE: 991/3
#[test]
fn legacy_request_compatibility_without_fabricated_reservation() {
    // A legacy serial profile is not the new concurrency profile: the frozen
    // ordinary `Apply` keeps decoding as `Apply` (never `ReservedWrite`),
    // and the bare reservation projection still selects no wire operation.
    let text = include_str!("data/reserved-write/legacy-apply.json");
    let legacy_value: Value = serde_json::from_str(text).unwrap();
    assert_eq!(legacy_value.get("op"), Some(&json!("apply")));
    let legacy: StoreRequest = serde_json::from_value(legacy_value).unwrap();
    assert!(matches!(legacy, StoreRequest::Apply { .. }));
    assert!(legacy.validate().is_ok());
    assert_eq!(legacy, legacy_apply_request());
    assert!(
        serde_json::from_value::<ReservedWriteRequest>(serde_json::to_value(&legacy).unwrap())
            .is_err()
    );
    let bare = fixture_request_value();
    assert!(bare.get("op").is_none());
    assert!(serde_json::from_value::<StoreRequest>(bare).is_err());
    // The legacy frame path is untouched by the new variant.
    let StoreRequest::Apply {
        context,
        transition,
        ..
    } = legacy
    else {
        panic!("frozen legacy request must stay an Apply");
    };
    let identity = test_identity(&context, &transition.identity.idempotency_key);
    let frame = request_frame(
        "connection-991",
        ProtocolVersion::CURRENT,
        context.request_id.clone(),
        identity,
        legacy_apply_request(),
    )
    .unwrap();
    let (_, _, decoded) = decode_request_frame(&frame).unwrap();
    assert!(matches!(decoded, StoreRequest::Apply { .. }));
}

// WORK_UNIT_CASE: 991/11
#[test]
fn response_correlation_is_separate_from_operation_identity() {
    // Fresh transport correlation per frame; stable operation identity per
    // write. The same receipt answers under two correlations without
    // changing identity, and a correlation is never adopted as identity.
    let request = fixture_request();
    let receipt = receipt_for(&request);
    let first_id = RequestId::new("correlation-991-first").unwrap();
    let second_id = RequestId::new("correlation-991-second").unwrap();
    let first = response_frame(
        "connection-991",
        ProtocolVersion::CURRENT,
        Some(first_id.clone()),
        StoreResponse::Transaction {
            receipt: receipt.clone(),
        },
    )
    .unwrap();
    let second = response_frame(
        "connection-991",
        ProtocolVersion::CURRENT,
        Some(second_id.clone()),
        StoreResponse::Transaction {
            receipt: receipt.clone(),
        },
    )
    .unwrap();
    let (first_out, first_response) =
        decode_response_frame(&first, "connection-991", ProtocolVersion::CURRENT).unwrap();
    let (second_out, second_response) =
        decode_response_frame(&second, "connection-991", ProtocolVersion::CURRENT).unwrap();
    assert_eq!(first_out, first_id);
    assert_eq!(second_out, second_id);
    assert_ne!(first_out, second_out);
    for response in [first_response, second_response] {
        let StoreResponse::Transaction { receipt: observed } = response else {
            panic!("both correlations must carry the Transaction receipt");
        };
        assert_eq!(
            observed.operation_id,
            request.transition.identity.operation_id
        );
        assert_eq!(observed, receipt);
    }
}

// WORK_UNIT_CASE: 991/16
#[test]
fn unknown_duplicate_oversize_and_sensitive_diagnostic_canaries() {
    // Unknown fields fail closed at every level of the new variant.
    let mut unknown_variant = serde_json::to_value(StoreRequest::ReservedWrite {
        request: valid_request(),
    })
    .unwrap();
    unknown_variant
        .as_object_mut()
        .unwrap()
        .insert("future_field".to_owned(), json!(1));
    assert!(serde_json::from_value::<StoreRequest>(unknown_variant).is_err());
    let mut unknown_inner = fixture_request_value();
    unknown_inner
        .as_object_mut()
        .unwrap()
        .insert("reservation_ticket".to_owned(), json!("ticket-991"));
    assert!(serde_json::from_value::<ReservedWriteRequest>(unknown_inner).is_err());
    let mut unknown_admission = fixture_request_value();
    unknown_admission
        .get_mut("admission")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("authority_grant".to_owned(), json!(true));
    assert!(serde_json::from_value::<ReservedWriteRequest>(unknown_admission).is_err());
    // Duplicate scopes fail closed.
    let mut duplicated = valid_request();
    duplicated.admission.scopes.push(scope_binding());
    assert!(matches!(
        duplicated.validate(),
        Err(StoreError::Duplicate { .. })
    ));
    // Oversize scope sets and labels fail closed at the exact bounds.
    let wide: Vec<_> = (0..257u64)
        .map(|index| ReservedScopeBinding {
            scope: OrderingScopeId::new(format!("scope-991-wide-{index}")).unwrap(),
            reserved_sequence: 7,
            expected_sequence: 6,
            expected_head_digest: "c".repeat(64),
        })
        .collect();
    let mut oversize = valid_request();
    oversize.admission.scopes = wide;
    assert_eq!(oversize.validate(), Err(StoreError::PayloadTooLarge));
    // Refusal diagnostics echo no field values: no raw token, credential,
    // command, transition body, or query payload leaks into error text.
    let mut tampered = valid_request();
    tampered.transition.identity.idempotency_key = "idem-991-tampered".to_owned();
    let refusal = tampered.validate().unwrap_err().to_string();
    for secret in [
        "idem-991-tampered",
        "idem-991-1",
        "reservation-991-1",
        "observation-991-1",
    ] {
        assert!(
            !refusal.contains(secret),
            "refusal diagnostic must not echo field values: {refusal}"
        );
    }
    let wire_refusal = StoreRequest::ReservedWrite { request: tampered }
        .validate_for_identity(
            &RequestId::new("request-991-1").unwrap(),
            &test_identity(&context(), "idem-991-tampered"),
        )
        .unwrap_err()
        .to_string();
    assert!(!wire_refusal.contains("idem-991-tampered"));
    assert!(!wire_refusal.contains("observation-991-1"));
}

// WORK_UNIT_CASE: 991/17
#[test]
fn all_existing_unrelated_mappings_are_unchanged() {
    // Every legacy request/capability/failure mapping keeps its exact
    // behavior under the extended catalogue.
    assert!(
        !CAPABILITIES.contains(&CAPABILITY_RESERVED_WRITE),
        "reserved-write stays a declared but unadvertised capability"
    );
    assert_eq!(EFFECTS, &["read", "canonical_write"]);
    assert_eq!(CAPABILITY_APPLY, "store.apply");
    assert_eq!(CAPABILITY_RESERVED_WRITE, "store.reserved_write");
    let legacy = legacy_apply_request();
    assert_eq!(legacy.capability(), CAPABILITY_APPLY);
    assert!(CAPABILITIES.contains(&legacy.capability()));
    let health = StoreRequest::Health;
    assert!(health.validate().is_ok());
    assert!(CAPABILITIES.contains(&health.capability()));
    let failing = StoreRequest::Receipt {
        operation_id: OperationId::new("op-991-absent").unwrap(),
    };
    assert!(failing.validate().is_ok());
    let ok = StoreRequest::ValidationSnapshot;
    assert!(ok.validate().is_ok());
}

// WORK_UNIT_CASE: 991/18
#[test]
fn closed_shape_guard_rejects_new_authority_or_unowned_changes() {
    // Production-call-chain shape freeze: the new variant carries exactly the
    // admitted fields — no scheduler, authority grant, credential, token, or
    // query surface — and the capability declaration is exact.
    let value = serde_json::to_value(StoreRequest::ReservedWrite {
        request: valid_request(),
    })
    .unwrap();
    let mut top_keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    top_keys.sort_unstable();
    assert_eq!(top_keys, vec!["op", "request"]);
    let request_value = value.get("request").unwrap();
    let mut request_keys: Vec<&str> = request_value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    request_keys.sort_unstable();
    assert_eq!(
        request_keys,
        vec![
            "admission",
            "context",
            "expected_ordering_heads",
            "expected_revision_heads",
            "transition"
        ]
    );
    let text = serde_json::to_string(&value).unwrap();
    for forbidden in [
        "scheduler",
        "authority_grant",
        "credential",
        "password",
        "secret",
        "token_raw",
        "query",
        "effect_authority",
    ] {
        assert!(
            !text.contains(forbidden),
            "wire shape must not grow an unowned surface: {forbidden}"
        );
    }
    // A caller cannot smuggle an authority claim through the variant: any
    // extra key at any level fails the closed decode.
    let mut smuggled = value.clone();
    smuggled
        .get_mut("request")
        .unwrap()
        .get_mut("transition")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("reservation_approved".to_owned(), json!(true));
    assert!(serde_json::from_value::<StoreRequest>(smuggled).is_err());
}
