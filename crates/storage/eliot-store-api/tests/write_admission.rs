//! Contract tests for the Store-owned write-admission projection (issue #990).
//!
//! Pure in-crate proofs only: a closed versioned projection carries mapped
//! ORS reservation evidence across the Kernel-to-Store boundary as shape
//! only, bound by two recomputed canonical digests. Exactly sixteen cases
//! (`990/1` through `990/16`) cover the owner mapping, round trip, every
//! rejection family, the unsupported client default, legacy compatibility,
//! and the source/API guard. No reservation, wire, commit, or concurrent
//! execution is established by these types.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroU64;
use std::task::{Context, Poll, Waker};

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_store_api::{
    CAPABILITIES, CONTRACT_VERSION, CanonicalStoreClient, CanonicalValidationSnapshot, EffectClass,
    ErrorCode, EventProjectionRelationIntents, MAX_WRITE_ADMISSION_LABEL_BYTES,
    MAX_WRITE_ADMISSION_SCOPES, NamedMutationOperation, NamedMutationRequest, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, RequestMeta, ReservedScopeBinding, ReservedWriteRequest, Resubmission,
    RevisionHeadExpectation, RevisionKey, ScopeId, ScopeRevisionView, SecurityContext, StoreError,
    StoreHealth, StoreHealthStatus, StoreRequest, TransitionClass,
    WRITE_ADMISSION_CONTRACT_VERSION, WriteAdmissionParams, WriteAdmissionProjection, WriteReceipt,
    WriteReceiptStatus, WriterEpochBinding,
};
use serde_json::{Value, json};

fn fence() -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).unwrap()).unwrap();
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn context() -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new("request-admit-1").unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-admit").unwrap(),
        source_id: SourceId::new("source-admit").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn transition_with_scopes(scopes: &[&str]) -> eliot_store_api::PreparedTransition {
    eliot_store_api::PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("op-admit-1").unwrap(),
            idempotency_key: "idem-admit-1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-admit-1").unwrap(),
        task_id: None,
        ordering_scopes: scopes
            .iter()
            .map(|scope| OrderingScopeId::new(*scope).unwrap())
            .collect(),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: OperationManifestDigest::new("manifest-admit-1").unwrap(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::from([("subject".to_owned(), json!("observation-admit-1"))]),
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

fn transition() -> eliot_store_api::PreparedTransition {
    transition_with_scopes(&["scope-admit-1"])
}

fn scope_binding(scope: &str, reserved: u64, expected: u64) -> ReservedScopeBinding {
    ReservedScopeBinding {
        scope: OrderingScopeId::new(scope).unwrap(),
        reserved_sequence: reserved,
        expected_sequence: expected,
        expected_head_digest: "c".repeat(64),
    }
}

fn epoch_binding() -> WriterEpochBinding {
    WriterEpochBinding {
        lineage_id: "epoch-lineage-admit".to_owned(),
        epoch: 5,
        predecessor_lineage_id: None,
        predecessor_epoch: None,
    }
}

fn params_for(transition: &eliot_store_api::PreparedTransition) -> WriteAdmissionParams {
    WriteAdmissionParams {
        reservation_id: "reservation-admit-1".to_owned(),
        reservation_order: 42,
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        scopes: transition
            .ordering_scopes
            .iter()
            .enumerate()
            .map(|(index, scope)| {
                #[allow(clippy::cast_possible_truncation)]
                let reserved = 7 + index as u64;
                #[allow(clippy::cast_possible_truncation)]
                let expected = 6 + index as u64;
                scope_binding(scope.as_str(), reserved, expected)
            })
            .collect(),
        writer_epoch: epoch_binding(),
        state_fence: fence(),
        source_id: "source-admit".to_owned(),
        created_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        recovery_owner: "recovery-owner-admit".to_owned(),
    }
}

fn admission_for(transition: &eliot_store_api::PreparedTransition) -> WriteAdmissionProjection {
    WriteAdmissionProjection::bind(transition, params_for(transition)).unwrap()
}

fn bind_with_label(
    transition: &eliot_store_api::PreparedTransition,
    field: &str,
    label: String,
) -> Result<WriteAdmissionProjection, StoreError> {
    let mut params = params_for(transition);
    match field {
        "reservation_id" => params.reservation_id = label,
        "recovery_owner" => params.recovery_owner = label,
        "source_id" => params.source_id = label,
        _ => params.writer_epoch.lineage_id = label,
    }
    WriteAdmissionProjection::bind(transition, params)
}

fn assert_label_bound(field: &str) {
    let transition = transition();
    let label = "l".repeat(MAX_WRITE_ADMISSION_LABEL_BYTES);
    assert!(
        bind_with_label(&transition, field, label).is_ok(),
        "{field} at exactly the byte bound seals"
    );
    let long = "l".repeat(MAX_WRITE_ADMISSION_LABEL_BYTES + 1);
    assert_eq!(
        bind_with_label(&transition, field, long),
        Err(StoreError::PayloadTooLarge),
        "{field} one byte over the bound fails closed"
    );
}

fn revision_heads() -> Vec<RevisionHeadExpectation> {
    vec![RevisionHeadExpectation {
        key: RevisionKey::new("rev-admit-1").unwrap(),
        expected_revision: 3,
        state_fence: fence(),
    }]
}

fn ordering_heads_for(scopes: &[(String, u64)]) -> Vec<OrderingHeadExpectation> {
    scopes
        .iter()
        .map(|(scope, sequence)| OrderingHeadExpectation {
            scope: OrderingScopeId::new(scope.clone()).unwrap(),
            expected_sequence: *sequence,
            state_fence: fence(),
        })
        .collect()
}

fn valid_request() -> ReservedWriteRequest {
    let transition = transition();
    let admission = admission_for(&transition);
    ReservedWriteRequest {
        context: context(),
        transition,
        admission,
        expected_revision_heads: revision_heads(),
        expected_ordering_heads: ordering_heads_for(&[("scope-admit-1".to_owned(), 6)]),
    }
}

fn valid_request_two_scopes() -> ReservedWriteRequest {
    let transition = transition_with_scopes(&["scope-admit-1", "scope-admit-2"]);
    let admission = admission_for(&transition);
    ReservedWriteRequest {
        context: context(),
        transition,
        admission,
        expected_revision_heads: revision_heads(),
        expected_ordering_heads: ordering_heads_for(&[
            ("scope-admit-1".to_owned(), 6),
            ("scope-admit-2".to_owned(), 7),
        ]),
    }
}

// WORK_UNIT_CASE: 990/1
#[test]
fn field_to_owner_mapping_is_complete_and_deterministic() {
    let transition = transition();
    let request = valid_request();
    assert_eq!(
        request.admission.contract_version,
        WRITE_ADMISSION_CONTRACT_VERSION
    );
    assert_eq!(request.admission.reservation_id, "reservation-admit-1");
    assert_eq!(request.admission.reservation_order, 42);
    assert_eq!(
        request.admission.operation_id,
        transition.identity.operation_id
    );
    assert_eq!(
        request.admission.idempotency_key,
        transition.identity.idempotency_key
    );
    assert_eq!(
        request.admission.canonical_request_hash,
        transition.identity.canonical_request_hash
    );
    assert_eq!(request.admission.scopes.len(), 1);
    assert_eq!(request.admission.scopes[0].scope.as_str(), "scope-admit-1");
    assert_eq!(request.admission.scopes[0].reserved_sequence, 7);
    assert_eq!(request.admission.scopes[0].expected_sequence, 6);
    assert_eq!(
        request.admission.writer_epoch.lineage_id,
        "epoch-lineage-admit"
    );
    assert_eq!(request.admission.writer_epoch.epoch, 5);
    assert_eq!(request.admission.state_fence, fence());
    assert_eq!(request.admission.source_id, context().source_id.as_str());
    assert_eq!(request.admission.recovery_owner, "recovery-owner-admit");
    assert_eq!(request.transition, transition);
    assert_eq!(request.context, context());
    assert!(request.validate().is_ok());
    let replay = admission_for(&transition);
    assert_eq!(
        replay, request.admission,
        "same owner evidence seals identically"
    );
    let encoded = serde_json::to_value(&request.admission).unwrap();
    let decoded: WriteAdmissionProjection = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, request.admission);
}

// WORK_UNIT_CASE: 990/2
#[test]
fn valid_bounded_projection_and_request_round_trip() {
    let request = valid_request();
    assert!(request.validate().is_ok());
    let encoded = serde_json::to_value(&request).unwrap();
    let decoded: ReservedWriteRequest = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, request);
    assert!(decoded.validate().is_ok());
    let reencoded = serde_json::to_value(&decoded).unwrap();
    assert_eq!(reencoded, encoded, "canonical raw bytes are stable");
    let fixture = include_str!("data/write_admission.json");
    let from_fixture: ReservedWriteRequest = serde_json::from_str(fixture).unwrap();
    assert!(from_fixture.validate().is_ok());
    assert_eq!(
        from_fixture, request,
        "fixture matches the sealed builder output"
    );
}

// WORK_UNIT_CASE: 990/3
#[test]
fn empty_duplicate_unsorted_or_incomplete_scope_sets_are_rejected() {
    let transition = transition();
    let mut empty = params_for(&transition);
    empty.scopes.clear();
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, empty),
        Err(StoreError::Empty {
            field: "admission.scopes"
        })
    ));
    let mut duplicate = params_for(&transition);
    duplicate.scopes.push(scope_binding("scope-admit-1", 9, 8));
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, duplicate),
        Err(StoreError::Duplicate {
            field: "admission.scopes"
        })
    ));
    let unsorted = transition_with_scopes(&["scope-admit-1", "scope-admit-2"]);
    let mut params = params_for(&unsorted);
    params.scopes.reverse();
    assert!(matches!(
        WriteAdmissionProjection::bind(&unsorted, params),
        Err(StoreError::InvalidField {
            field: "admission.scopes",
            ..
        })
    ));
    let wide = transition_with_scopes(&["scope-admit-1", "scope-admit-2"]);
    let narrow_params = params_for(&transition);
    let narrow = WriteAdmissionProjection::bind(&wide, narrow_params).unwrap();
    let incomplete = ReservedWriteRequest {
        context: context(),
        transition: wide,
        admission: narrow,
        expected_revision_heads: revision_heads(),
        expected_ordering_heads: ordering_heads_for(&[("scope-admit-1".to_owned(), 6)]),
    };
    assert!(matches!(
        incomplete.validate(),
        Err(StoreError::InvalidField {
            field: "admission.scopes",
            ..
        })
    ));
}

// WORK_UNIT_CASE: 990/4
#[test]
fn operation_and_transition_binding_mismatches_are_rejected() {
    let mut operation = valid_request();
    operation.admission.operation_id = OperationId::new("op-other").unwrap();
    assert_eq!(operation.validate(), Err(StoreError::IdentityConflict));
    let mut idempotency = valid_request();
    idempotency.admission.idempotency_key = "idem-other".to_owned();
    assert_eq!(idempotency.validate(), Err(StoreError::IdentityConflict));
    let mut hash = valid_request();
    hash.admission.canonical_request_hash = "d".repeat(64);
    assert_eq!(hash.validate(), Err(StoreError::IdentityConflict));
    let mut digest = valid_request();
    digest.admission.prepared_transition_digest = "d".repeat(64);
    assert!(matches!(
        digest.validate(),
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
}

// WORK_UNIT_CASE: 990/5
#[test]
fn expected_and_reserved_scope_or_head_mismatches_are_rejected() {
    let mut scope = valid_request();
    scope.expected_ordering_heads[0].scope = OrderingScopeId::new("scope-other").unwrap();
    assert!(matches!(
        scope.validate(),
        Err(StoreError::InvalidField {
            field: "admission.expected_ordering_heads",
            ..
        })
    ));
    let mut sequence = valid_request();
    sequence.expected_ordering_heads[0].expected_sequence = 99;
    assert!(matches!(
        sequence.validate(),
        Err(StoreError::InvalidField {
            field: "admission.expected_ordering_heads",
            ..
        })
    ));
    let mut fence = valid_request();
    fence.expected_revision_heads[0].state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::genesis(),
    );
    assert_eq!(fence.validate(), Err(StoreError::FenceMismatch));
    let mut duplicate = valid_request();
    duplicate
        .expected_revision_heads
        .push(revision_heads()[0].clone());
    assert!(matches!(
        duplicate.validate(),
        Err(StoreError::Duplicate {
            field: "admission.expected_revision_heads"
        })
    ));
}

// WORK_UNIT_CASE: 990/6
#[test]
fn writer_epoch_fence_and_generation_mismatches_are_rejected() {
    let mut fence = valid_request();
    fence.context.state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::genesis(),
    );
    assert_eq!(fence.validate(), Err(StoreError::FenceMismatch));
    let mut epoch = valid_request();
    epoch.admission.writer_epoch.epoch = 6;
    assert!(matches!(
        epoch.validate(),
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
    let transition = transition();
    let mut params = params_for(&transition);
    params.writer_epoch.epoch = 0;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, params),
        Err(StoreError::InvalidField {
            field: "admission.writer_epoch",
            ..
        })
    ));
    let mut broken_edge = params_for(&transition);
    broken_edge.writer_epoch.predecessor_lineage_id = Some("epoch-lineage-admit".to_owned());
    broken_edge.writer_epoch.predecessor_epoch = Some(3);
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, broken_edge),
        Err(StoreError::InvalidField {
            field: "admission.writer_epoch",
            ..
        })
    ));
}

// WORK_UNIT_CASE: 990/7
#[test]
fn missing_or_invalid_expiry_and_recovery_owner_are_rejected() {
    let transition = transition();
    let mut equal = params_for(&transition);
    equal.expires_at_ms = equal.created_at_ms;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, equal),
        Err(StoreError::InvalidField {
            field: "admission.expires_at_ms",
            ..
        })
    ));
    let mut backward = params_for(&transition);
    backward.expires_at_ms = backward.created_at_ms - 1;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, backward),
        Err(StoreError::InvalidField {
            field: "admission.expires_at_ms",
            ..
        })
    ));
    let mut epoch_zero = params_for(&transition);
    epoch_zero.created_at_ms = 0;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, epoch_zero),
        Err(StoreError::InvalidField {
            field: "admission.created_at_ms",
            ..
        })
    ));
    let mut blank_owner = params_for(&transition);
    blank_owner.recovery_owner = "   ".to_owned();
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, blank_owner),
        Err(StoreError::InvalidField {
            field: "admission.recovery_owner",
            ..
        })
    ));
    let mut long_owner = params_for(&transition);
    long_owner.recovery_owner = "r".repeat(MAX_WRITE_ADMISSION_LABEL_BYTES + 1);
    assert_eq!(
        WriteAdmissionProjection::bind(&transition, long_owner),
        Err(StoreError::PayloadTooLarge)
    );
}

// WORK_UNIT_CASE: 990/8
#[test]
fn every_item_string_and_byte_bound_holds_at_max_and_one_over() {
    assert_eq!(MAX_WRITE_ADMISSION_SCOPES, 256);
    let transition = transition();
    let params = params_for(&transition);
    assert!(WriteAdmissionProjection::bind(&transition, params).is_ok());
    let mut full = params_for(&transition);
    full.scopes = (0..MAX_WRITE_ADMISSION_SCOPES)
        .map(|index| {
            scope_binding(
                &format!("scope-{index:04}"),
                1 + index as u64,
                1 + index as u64,
            )
        })
        .collect();
    full.scopes
        .sort_by(|left, right| left.scope.cmp(&right.scope));
    let wide_transition = transition_with_scopes(
        &full
            .scopes
            .iter()
            .map(|scope| scope.scope.as_str())
            .collect::<Vec<_>>(),
    );
    let mut wide_params = params_for(&wide_transition);
    wide_params.scopes = full.scopes;
    assert!(WriteAdmissionProjection::bind(&wide_transition, wide_params.clone()).is_ok());
    wide_params
        .scopes
        .push(scope_binding("scope-overflow", 1, 1));
    wide_params
        .scopes
        .sort_by(|left, right| left.scope.cmp(&right.scope));
    assert_eq!(
        WriteAdmissionProjection::bind(&wide_transition, wide_params),
        Err(StoreError::PayloadTooLarge)
    );
    for field in [
        "reservation_id",
        "recovery_owner",
        "source_id",
        "lineage_id",
    ] {
        assert_label_bound(field);
    }
    let mut zero_order = params_for(&transition);
    zero_order.reservation_order = 0;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, zero_order),
        Err(StoreError::InvalidField {
            field: "admission.reservation_order",
            ..
        })
    ));
    let mut zero_reserved = params_for(&transition);
    zero_reserved.scopes[0].reserved_sequence = 0;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, zero_reserved),
        Err(StoreError::InvalidField {
            field: "admission.reserved_sequence",
            ..
        })
    ));
    let mut zero_expected = params_for(&transition);
    zero_expected.scopes[0].expected_sequence = 0;
    assert!(matches!(
        WriteAdmissionProjection::bind(&transition, zero_expected),
        Err(StoreError::InvalidField {
            field: "admission.expected_sequence",
            ..
        })
    ));
    let mut short_digest = valid_request();
    short_digest.admission.canonical_request_hash = "d".repeat(63);
    assert!(matches!(
        short_digest.validate(),
        Err(StoreError::InvalidField {
            field: "admission.canonical_request_hash",
            ..
        })
    ));
}

// WORK_UNIT_CASE: 990/9
#[test]
fn unknown_version_field_variant_and_duplicate_raw_keys_are_rejected() {
    let mut version = valid_request();
    version.admission.contract_version = 999;
    assert!(matches!(
        version.validate(),
        Err(StoreError::InvalidField {
            field: "admission.contract_version",
            ..
        })
    ));
    let mut unknown = serde_json::to_value(valid_request()).unwrap();
    unknown["admission"]["unknown_field"] = json!(true);
    assert!(serde_json::from_value::<ReservedWriteRequest>(unknown).is_err());
    let mut variant = serde_json::to_value(valid_request()).unwrap();
    variant["transition"]["transition_class"] = json!("Future");
    assert!(serde_json::from_value::<ReservedWriteRequest>(variant).is_err());
    let mut duplicate = serde_json::to_value(valid_request_two_scopes()).unwrap();
    let scopes = duplicate["admission"]["scopes"].as_array().unwrap().clone();
    duplicate["admission"]["scopes"] = Value::Array(vec![scopes[0].clone(), scopes[0].clone()]);
    let decoded: ReservedWriteRequest = serde_json::from_value(duplicate).unwrap();
    assert!(matches!(
        decoded.validate(),
        Err(StoreError::Duplicate {
            field: "admission.scopes"
        })
    ));
}

// WORK_UNIT_CASE: 990/10
#[test]
fn missing_reservation_cannot_decode_through_a_legacy_fallback() {
    let mut missing = serde_json::to_value(valid_request()).unwrap();
    missing.as_object_mut().unwrap().remove("admission");
    assert!(serde_json::from_value::<ReservedWriteRequest>(missing).is_err());
    let legacy = StoreRequest::Apply {
        context: context(),
        transition: transition(),
        expected_revision_heads: revision_heads(),
        expected_ordering_heads: ordering_heads_for(&[("scope-admit-1".to_owned(), 6)]),
    };
    let legacy_json = serde_json::to_value(&legacy).unwrap();
    assert!(serde_json::from_value::<ReservedWriteRequest>(legacy_json).is_err());
    let reserved_json = serde_json::to_value(valid_request()).unwrap();
    assert!(serde_json::from_value::<StoreRequest>(reserved_json).is_err());
}

// WORK_UNIT_CASE: 990/11
#[test]
fn caller_created_projection_proves_shape_only_never_current_authority() {
    let fabricated = valid_request();
    assert!(
        fabricated.validate().is_ok(),
        "shape check passes on copied evidence"
    );
    let encoded = serde_json::to_value(&fabricated).unwrap();
    let mut keys = Vec::new();
    collect_keys(&encoded, &mut keys);
    for forbidden in [
        "eligible",
        "verified",
        "valid",
        "authority",
        "grant",
        "issuer",
    ] {
        assert!(
            !keys.iter().any(|key| *key == forbidden),
            "no worker-controlled authority key {forbidden:?} in {keys:?}"
        );
    }
    let replay = valid_request();
    assert_eq!(
        replay.admission.reservation_token_digest,
        fabricated.admission.reservation_token_digest
    );
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

// WORK_UNIT_CASE: 990/12
#[test]
fn transport_principal_and_payload_issuer_are_noninterchangeable() {
    let mut payload = valid_request();
    payload.admission.source_id = "source-impostor".to_owned();
    assert_eq!(payload.validate(), Err(StoreError::IdentityConflict));
    let mut transport = valid_request();
    transport.context.source_id = SourceId::new("source-impostor").unwrap();
    assert_eq!(transport.validate(), Err(StoreError::IdentityConflict));
    let request = valid_request();
    assert_eq!(
        request.admission.source_id,
        request.context.source_id.as_str()
    );
}

// WORK_UNIT_CASE: 990/13
#[test]
fn canonical_token_or_transition_mutation_invalidates_the_binding() {
    let request = valid_request();
    assert!(request.validate().is_ok());
    let mut transition = valid_request();
    transition.transition.named_operations[0]
        .parameters
        .insert("subject".to_owned(), json!("observation-mutated"));
    assert!(matches!(
        transition.validate(),
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
    let mut sequence = valid_request();
    sequence.admission.scopes[0].reserved_sequence = 99;
    assert!(matches!(
        sequence.validate(),
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
    let mut head = valid_request();
    head.admission.scopes[0].expected_head_digest = "d".repeat(64);
    assert!(matches!(
        head.validate(),
        Err(StoreError::TransitionDigestMismatch { .. })
    ));
}

struct StubClient {
    apply_calls: std::sync::Mutex<usize>,
}

impl StubClient {
    fn new() -> Self {
        Self {
            apply_calls: std::sync::Mutex::new(0),
        }
    }

    fn apply_call_count(&self) -> usize {
        *self.apply_calls.lock().unwrap()
    }

    fn rejected_receipt(operation: &OperationId) -> WriteReceipt {
        WriteReceipt {
            operation_id: operation.clone(),
            idempotency_key: "idem-stub".to_owned(),
            canonical_request_hash: "e".repeat(64),
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
            operation_manifest_digest: OperationManifestDigest::new("manifest-stub").unwrap(),
            error_code: Some(ErrorCode::Conflict),
            resubmission: Resubmission::None,
            committed_at: None,
            envelope: None,
        }
    }
}

impl CanonicalStoreClient for StubClient {
    async fn apply_prepared(
        &self,
        _ctx: &RequestMeta,
        transition: eliot_store_api::PreparedTransition,
        _expected_revision_heads: Vec<RevisionHeadExpectation>,
        _expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        *self.apply_calls.lock().unwrap() += 1;
        Ok(Self::rejected_receipt(&transition.identity.operation_id))
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
    ) -> Result<Vec<eliot_store_api::RevisionHead>, StoreError> {
        Ok(Vec::new())
    }

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        Ok(CanonicalValidationSnapshot {
            state_fence: fence(),
            revision_heads: Vec::new(),
            validation_revision: 1,
            observed_at_unix_ms: 1,
        })
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        Ok(ScopeRevisionView {
            scope_id,
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence(),
        })
    }

    async fn ordering_heads(
        &self,
        _scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<eliot_store_api::OrderingHead>, StoreError> {
        Ok(Vec::new())
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        Ok(NamedReadResponse {
            operation: query.operation,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: json!([]),
        })
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        Ok(StoreHealth {
            status: StoreHealthStatus::Ready,
            contract_version: CONTRACT_VERSION,
            manifest_digest: OperationManifestDigest::new("manifest-stub").unwrap(),
        })
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker: &Waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut pinned = std::pin::pin!(future);
    match pinned.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future pended without a runtime"),
    }
}

// WORK_UNIT_CASE: 990/14
#[test]
fn unsupported_client_default_refuses_without_unreserved_fallback() {
    let client = StubClient::new();
    let outcome = block_on(client.apply_reserved_write(valid_request()));
    assert_eq!(outcome, Err(StoreError::Unavailable));
    assert_eq!(client.apply_call_count(), 0, "no unreserved fallback ran");
    let mut broken = valid_request();
    broken.admission.reservation_order = 0;
    let refused = block_on(client.apply_reserved_write(broken));
    assert!(refused.is_err());
    assert_eq!(
        client.apply_call_count(),
        0,
        "invalid input still causes no effects"
    );
}

// WORK_UNIT_CASE: 990/15
#[test]
fn existing_client_implementations_keep_ordinary_apply_behavior() {
    let client = StubClient::new();
    let plan = transition();
    let operation = plan.identity.operation_id.clone();
    let receipt = block_on(client.apply_prepared(
        &context(),
        plan,
        revision_heads(),
        ordering_heads_for(&[("scope-admit-1".to_owned(), 6)]),
    ))
    .unwrap();
    assert_eq!(receipt.operation_id, operation);
    assert!(receipt.validate().is_ok());
    assert_eq!(client.apply_call_count(), 1);
    let legacy = StoreRequest::Apply {
        context: context(),
        transition: transition(),
        expected_revision_heads: revision_heads(),
        expected_ordering_heads: ordering_heads_for(&[("scope-admit-1".to_owned(), 6)]),
    };
    let encoded = serde_json::to_value(&legacy).unwrap();
    let decoded: StoreRequest = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, legacy);
    assert!(decoded.validate().is_ok());
}

// WORK_UNIT_CASE: 990/16
#[test]
fn source_and_api_guard_excludes_hidden_authority_io_and_activation() {
    let source = include_str!("../src/write_admission.rs");
    for forbidden in [
        "eliot_ors",
        "eliot-ors",
        "ors::",
        "SystemTime",
        "UNIX_EPOCH",
        "std::time",
        "std::fs",
        "std::net",
        "std::process",
        "std::env",
        "tokio",
        "async_std",
        "apply_prepared",
        "WriteReceipt {",
        "ReceiptEnvelope",
        "schedul",
        "eligible",
        "verified",
        "Atomic",
        "Mutex",
        "RwLock",
        "RefCell",
        "OnceLock",
        "thread_local",
        "CAPABILITY",
    ] {
        assert!(
            !source.contains(forbidden),
            "write_admission.rs must not contain {forbidden:?}"
        );
    }
    assert!(
        source.contains("deny_unknown_fields"),
        "closed shape is enforced"
    );
    assert!(
        CAPABILITIES
            .iter()
            .all(|capability| !capability.contains("reserv") && !capability.contains("admission")),
        "no hidden capability activation: {CAPABILITIES:?}"
    );
}
