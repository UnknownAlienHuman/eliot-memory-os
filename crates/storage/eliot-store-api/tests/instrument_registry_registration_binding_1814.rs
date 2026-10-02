//! Receipt-bound instrument registry registration readback proof for #1814.
//!
//! Documentation route receipt: `sha256:e85010591b0a5b8e9ec9fdea3dbab28fedb53a7fd3c8c69fba2e23614862f823`;
//! read receipt: `sha256:7d591a41a340d2c0c5e4b5459c0e591bd4db914ffdfba608624076c70a9df6ec`;
//! verified bundle SHA-256: `6a3d460d68bfcf6e891258bd97b078d59b0fbbec271998da13e95a53a6427d34`.
//! Matched routes: `generic-source`, `host-kernel`, `canonical-storage`,
//! `agent-swarm`, `instrument-verification`, `human-surfaces`,
//! `security-privacy`, `workspace-governance`, `repository-root`. Required
//! handles: `I10.8.3`, `I10.8.4`; relevant fragment identities are
//! `crates/storage/AGENTS.md` (`c77891d466c7622e5061430192459d8099304d57b27815b63776f023ae5b59f9`),
//! `docs/architecture/I10-08-03-ip1-typed-extensible-instrument-contracts.md`
//! (`c82b346cb4b6d7e313c4790c8f5496d8ae9bb50a7166eead8fa83e71ffe26f16`),
//! `docs/architecture/I10-08-04-ip2-instrumentrunner.md`
//! (`b9a020dd270e278e5834a775186c0100c52ab85c35dd1e5e102bedb1e115b638`),
//! and `docs/architecture/READING_PROTOCOL.md`
//! (`253cca0f078acd49545baed814c9319d72659ef1e2428edf1ead789beaa4e1c3`).
//! I attest that I opened and read the canonical merged #1814 bundle before
//! editing. These pure API proofs validate a readback against an
//! originally sealed canonical request and committed Store receipt. They do
//! not establish authenticated Kernel IPC or a live platform launch.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence,
};
use eliot_store_api::{
    CanonicalRequestView, CommitId, EffectClass, EventProjectionRelationIntents,
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadResponse,
    OperationIdentity, OrderingScopeId, PreparedTransition, RequestMeta, ScopeId, SecurityContext,
    TransitionClass, WriteReceipt, WriteReceiptStatus, bind_issue18_digests, bind_issue18_receipt,
    bind_policy_config_schema_versions, canonical_request_hash, generated_operation_manifests,
    issue_store_receipt_envelope, operation_manifest_set_digest,
    validate_instrument_registry_registration_readback,
};
use serde_json::{Value, json};

const SCOPE: &str = "scope:instrument-registry-registration-1814";
const SNAPSHOT: &str = "{\"schema\":\"eliot.instrument.registry\",\"version\":1}";
const AUTHORITY: &str = concat!(
    "{\"schema\":\"eliot.governor.registration-authority-ledger\",",
    "\"version\":1,\"grant_uses\":[],\"leases\":[]}"
);

struct OriginalRegistration {
    receipt: WriteReceipt,
    readback: NamedReadResponse,
}

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::genesis(),
    )
}

fn original_registration() -> OriginalRegistration {
    let state_fence = fence();
    let context = RequestMeta {
        request_id: RequestId::new("request:instrument-registry-registration-1814").unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("instrument-registry-registration-1814").unwrap(),
        source_id: SourceId::new("instrument-registry-store-owner-1814").unwrap(),
        state_fence: state_fence.clone(),
        clock: ClockReading::default(),
    };
    let manifests = generated_operation_manifests().unwrap();
    let command = NamedMutationRequest {
        operation: NamedMutationOperation::ApplyInstrumentRegistryState,
        parameters: BTreeMap::from([
            (
                "snapshot_json".to_owned(),
                Value::String(SNAPSHOT.to_owned()),
            ),
            (
                "registration_authority_json".to_owned(),
                Value::String(AUTHORITY.to_owned()),
            ),
            ("expected_registry_revision".to_owned(), json!(0)),
        ]),
    };
    let mut transition = PreparedTransition {
        contract_version: eliot_store_api::CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: OperationId::new("operation:instrument-registry-registration-1814")
                .unwrap(),
            idempotency_key: "instrument-registry-registration-1814".to_owned(),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: state_fence.clone(),
        scope_id: ScopeId::new(SCOPE).unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new(SCOPE).unwrap()],
        transition_class: TransitionClass::InstrumentRegistry,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: eliot_store_api::supported_admission_contract_set_digest()
            .unwrap(),
        operation_manifest_digest: operation_manifest_set_digest(&manifests).unwrap(),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).unwrap();
    let request = CanonicalRequestView::from_apply(&context, &transition, &[], &[]);
    transition.identity.canonical_request_hash = canonical_request_hash(&request).unwrap();

    let mut receipt = WriteReceipt {
        operation_id: transition.identity.operation_id.clone(),
        idempotency_key: transition.identity.idempotency_key.clone(),
        canonical_request_hash: transition.identity.canonical_request_hash.clone(),
        transition_class: TransitionClass::InstrumentRegistry,
        status: WriteReceiptStatus::Committed,
        commit_id: Some(CommitId::new("commit-instrument-registry-registration-1814").unwrap()),
        state_fence: state_fence.clone(),
        ordering_sequences: Vec::new(),
        revision_before_after: Vec::new(),
        applied_command_ids: vec!["ApplyInstrumentRegistryState".to_owned()],
        emitted_event_ids: Vec::new(),
        projection_refs: Vec::new(),
        outbox_refs: Vec::new(),
        operation_manifest_digest: transition.operation_manifest_digest.clone(),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions::bound_to(
            &transition,
        ),
        error_code: None,
        resubmission: eliot_store_api::Resubmission::None,
        committed_at: Some("commit-sequence-0000000000000001".to_owned()),
        envelope: None,
    };
    bind_issue18_receipt(&transition, &mut receipt, &[]);
    bind_policy_config_schema_versions(&transition, &mut receipt);
    receipt.envelope =
        Some(issue_store_receipt_envelope(&context, &transition, &receipt, 1).unwrap());
    receipt.validate().unwrap();

    let readback = NamedReadResponse {
        operation: NamedReadOperation::GetInstrumentRegistryState,
        state_fence: state_fence.clone(),
        revision_heads: Vec::new(),
        payload: json!({
            "snapshot_json": SNAPSHOT,
            "registration_authority_json": AUTHORITY,
            "registration_request_json": serde_json::to_string(&request).unwrap(),
            "revision": 1,
            "state_fence": state_fence,
            "scope_id": SCOPE,
            "task_id": null,
            "operation_id": receipt.operation_id.as_str(),
            "canonical_request_hash": receipt.canonical_request_hash.as_str(),
        }),
    };
    OriginalRegistration { receipt, readback }
}

#[test]
fn exact_original_registration_row_is_bound_to_its_committed_receipt() {
    let original = original_registration();
    validate_instrument_registry_registration_readback(&original.readback, &original.receipt)
        .expect("the unchanged original row is supported by its original receipt");
}

#[test]
fn changed_snapshot_with_original_request_and_receipt_is_refused() {
    let original = original_registration();
    let mut foreign = original.readback.clone();
    foreign.payload["snapshot_json"] = json!("{\"foreign\":true}");
    assert!(
        validate_instrument_registry_registration_readback(&foreign, &original.receipt).is_err()
    );
}

#[test]
fn rewritten_self_consistent_request_and_snapshot_cannot_reuse_original_receipt() {
    let original = original_registration();
    let mut foreign = original.readback.clone();
    let mut rewritten: CanonicalRequestView = serde_json::from_str(
        foreign.payload["registration_request_json"]
            .as_str()
            .expect("original request JSON"),
    )
    .unwrap();
    rewritten.semantic_commands[0]
        .parameters
        .insert("snapshot_json".to_owned(), json!("{\"foreign\":true}"));
    // The changed view is serialized and hashed as a valid, newly computed
    // request; the original immutable receipt remains untouched.
    let recomputed = canonical_request_hash(&rewritten).unwrap();
    assert_ne!(recomputed, original.receipt.canonical_request_hash);
    foreign.payload["snapshot_json"] = json!("{\"foreign\":true}");
    foreign.payload["registration_request_json"] =
        json!(serde_json::to_string(&rewritten).unwrap());
    assert!(
        validate_instrument_registry_registration_readback(&foreign, &original.receipt).is_err()
    );
}

#[test]
fn foreign_operation_and_scope_cannot_reuse_original_receipt() {
    let original = original_registration();
    let mut foreign_operation = original.readback.clone();
    foreign_operation.payload["operation_id"] = json!("operation:foreign");
    assert!(
        validate_instrument_registry_registration_readback(&foreign_operation, &original.receipt)
            .is_err()
    );

    let mut foreign_scope = original.readback.clone();
    foreign_scope.payload["scope_id"] = json!("scope:foreign");
    assert!(
        validate_instrument_registry_registration_readback(&foreign_scope, &original.receipt)
            .is_err()
    );
}

#[test]
fn wrong_read_fence_and_empty_or_missing_historical_request_fail_closed() {
    let original = original_registration();
    let mut foreign_fence = original.readback.clone();
    let other_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap(),
        ResourceGeneration::genesis(),
    );
    foreign_fence.state_fence = other_fence.clone();
    foreign_fence.payload["state_fence"] = serde_json::to_value(other_fence).unwrap();
    assert!(
        validate_instrument_registry_registration_readback(&foreign_fence, &original.receipt)
            .is_err()
    );

    let mut empty_request = original.readback.clone();
    empty_request.payload["registration_request_json"] = json!("");
    assert!(
        validate_instrument_registry_registration_readback(&empty_request, &original.receipt)
            .is_err()
    );

    let mut historical_row = original.readback.clone();
    historical_row
        .payload
        .as_object_mut()
        .expect("registry payload object")
        .remove("registration_request_json");
    assert!(
        validate_instrument_registry_registration_readback(&historical_row, &original.receipt)
            .is_err()
    );
}
