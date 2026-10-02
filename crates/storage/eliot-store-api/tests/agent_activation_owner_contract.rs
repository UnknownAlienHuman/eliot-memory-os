//! Provider-independent contract proof for Governor's closed four-owner
//! activation write. The payloads below are opaque canonical owner snapshots;
//! this test proves only the storage wire and validation contract.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId,
};
use eliot_receipts::EffectClass;
use eliot_store_api::{
    AgentActivationOwnerBundle, AgentActivationOwnerFrame, CanonicalRequestView,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, PreparedTransition, RecoveryRecord, RequestMeta, ScopeId, SecurityContext,
    StateFence, StoreError, TransitionClass, OWNER_SNAPSHOT_SCHEMA, bind_issue18_digests,
    canonical_json_bytes, canonical_request_hash, generated_operation_manifests,
    operation_manifest_set_digest, sha256_hex, supported_admission_contract_set_digest,
};
use serde_json::json;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const OWNER_KEYS: [&str; 4] = ["task", "session", "coordination", "work_scope"];

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(LINEAGE).expect("lineage"),
        NonZeroU64::new(1).expect("epoch sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
}

fn owner_frame(owner_key: &str, expected_revision: u64, fixture: &str) -> AgentActivationOwnerFrame {
    let next_revision = expected_revision + 1;
    let payload = canonical_json_bytes(&json!({
        "fixture": fixture,
        "owner": owner_key,
        "snapshot_revision": next_revision,
    }))
    .expect("canonical owner payload");
    AgentActivationOwnerFrame {
        expected_revision,
        record: RecoveryRecord {
            namespace: "owner".to_owned(),
            key: owner_key.to_owned(),
            state_fence: fence(),
            revision: next_revision,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        },
    }
}

fn supplier_snapshot_fixture(fixture: &str) -> AgentActivationOwnerBundle {
    AgentActivationOwnerBundle {
        task: owner_frame("task", 0, fixture),
        session: owner_frame("session", 0, fixture),
        coordination: owner_frame("coordination", 0, fixture),
        work_scope: owner_frame("work_scope", 0, fixture),
    }
}

fn context(tag: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(format!("request-agent-activation-{tag}")).expect("request"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-agent-activation").expect("product"),
        source_id: SourceId::new("governor-owner-fixture").expect("source"),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn prepared_transition(
    tag: &str,
    owners: &AgentActivationOwnerBundle,
) -> (RequestMeta, PreparedTransition) {
    let ctx = context(tag);
    let catalogue = generated_operation_manifests().expect("generated catalogue");
    let mut transition = PreparedTransition {
        contract_version: eliot_store_api::CONTRACT_VERSION,
        identity: OperationIdentity {
            operation_id: OperationId::new(format!("operation-agent-activation-{tag}"))
                .expect("operation"),
            idempotency_key: format!("idempotency-agent-activation-{tag}"),
            canonical_request_hash: "0".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("agent-activation-owner-contract").expect("scope"),
        task_id: None,
        ordering_scopes: vec![
            eliot_store_api::OrderingScopeId::new("agent-activation-owner-contract")
                .expect("ordering scope"),
        ],
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: supported_admission_contract_set_digest()
            .expect("admission contract digest"),
        operation_manifest_digest: operation_manifest_set_digest(&catalogue)
            .expect("operation manifest digest"),
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyAgentActivationOwners,
            parameters: BTreeMap::from([(
                "owner_records".to_owned(),
                serde_json::to_value(owners).expect("owner bundle JSON"),
            )]),
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    bind_issue18_digests(&mut transition).expect("prepared-transition digests");
    let request_view = CanonicalRequestView::from_apply(&ctx, &transition, &[], &[]);
    transition.identity.canonical_request_hash =
        canonical_request_hash(&request_view).expect("canonical request hash");
    (ctx, transition)
}

#[test]
fn closed_owner_bundle_passes_catalogue_and_digest_validation_and_rejects_foreign_key() {
    let catalogue = generated_operation_manifests().expect("generated catalogue");
    let owners = supplier_snapshot_fixture("supplier-shaped-contract-image");

    let keys = [
        owners.task.record.key.as_str(),
        owners.session.record.key.as_str(),
        owners.coordination.record.key.as_str(),
        owners.work_scope.record.key.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(keys, OWNER_KEYS.into_iter().collect());
    owners
        .validate_for_fence(&fence())
        .expect("complete bundle uses the admitted fence");

    for frame in [
        &owners.task,
        &owners.session,
        &owners.coordination,
        &owners.work_scope,
    ] {
        assert_eq!(frame.record.namespace, "owner");
        assert_eq!(frame.record.schema, OWNER_SNAPSHOT_SCHEMA);
        assert_eq!(frame.record.state_fence, fence());
        assert_eq!(frame.record.revision, frame.expected_revision + 1);
        assert_eq!(
            frame.record.value_digest,
            sha256_hex(&frame.record.payload),
            "the carried digest names the exact opaque payload bytes"
        );
    }

    let (ctx, accepted) = prepared_transition("accepted", &owners);
    let catalogue_digest = operation_manifest_set_digest(&catalogue).expect("catalogue digest");
    assert_eq!(accepted.operation_manifest_digest, catalogue_digest);
    assert_eq!(
        accepted.identity.canonical_request_hash,
        canonical_request_hash(&CanonicalRequestView::from_apply(&ctx, &accepted, &[], &[]))
            .expect("recomputed canonical request hash")
    );
    accepted
        .validate_against_catalogue(&catalogue)
        .expect("registered operation and typed owner parameter validate");

    let mut foreign = supplier_snapshot_fixture("foreign-fixed-key");
    foreign.session.record.key = "session-shadow".to_owned();
    let (_, refused) = prepared_transition("foreign-key", &foreign);
    assert!(matches!(
        refused.validate_against_catalogue(&catalogue),
        Err(StoreError::InvalidField {
            field: "agent_activation_owner.record",
            ..
        })
    ));
}
