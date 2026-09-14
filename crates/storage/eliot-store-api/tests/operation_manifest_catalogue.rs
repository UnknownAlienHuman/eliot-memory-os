//! Contract tests for the generated per-operation store manifest (slice C1).
//!
//! Pure in-crate proofs only: no Surreal/Blob edge, no authority issuance.
//! Deferred cases are listed in the owning work report: the global catalogue
//! beyond the four activated reads, a universal parameter-schema framework,
//! new adapter defaults, C2 enforcement (scope/role/fence/expiry), and the
//! null/absent/false/zero matrix beyond the activated operations.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use eliot_contracts::{
    ClockReading, EpochId, OperationId, ProductId, RequestId, ResourceGeneration, SourceId,
};
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, GENESIS_MANIFEST_NAME,
    NamedMutationOperation, NamedMutationRequest, NamedOperationManifest, NamedReadOperation,
    NamedReadRequest, OperationIdentity, OperationManifestDigest, OperationManifestSpec,
    OrderingScopeId, ReadConsistency, ScopeId, SecurityContext, StateFence, StoreError,
    StoreGenesisRequest, TransitionClass, canonical_json_bytes, generated_operation_manifests,
    genesis_manifest, genesis_transition, named_read_operation_name, operation_manifest_set_digest,
    sha256_hex,
};
use serde_json::{Value, json};

fn test_epoch(sequence: u64) -> EpochId {
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage-A");
    EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn read_request(
    operation: NamedReadOperation,
    scope: Option<&str>,
    parameters: BTreeMap<String, Value>,
) -> NamedReadRequest {
    NamedReadRequest {
        operation,
        scope_id: scope.map(|value| ScopeId::new(value.to_owned()).unwrap()),
        consistency: ReadConsistency::Eventual,
        state_fence: fence(),
        parameters,
    }
}

fn receipt_params() -> BTreeMap<String, Value> {
    let mut parameters = BTreeMap::new();
    parameters.insert("operation_id".to_owned(), json!("operation-1"));
    parameters
}

#[test]
fn activated_typed_reads_pass_catalogue_validation() {
    let entries = generated_operation_manifests().unwrap();
    assert_eq!(entries.len(), 5);

    // The closed name mapping is the single owner for code, manifests, wire.
    for operation in [
        NamedReadOperation::GetRevisionHeads,
        NamedReadOperation::GetOrderingHeads,
        NamedReadOperation::GetScopeRevisionView,
        NamedReadOperation::ResolveWriteReceipt,
    ] {
        let wire = serde_json::to_value(operation).unwrap();
        assert_eq!(
            wire,
            Value::String(named_read_operation_name(operation).to_owned())
        );
    }

    let heads = read_request(NamedReadOperation::GetRevisionHeads, None, BTreeMap::new());
    assert!(heads.validate_against_catalogue(&entries).is_ok());

    let ordering = read_request(NamedReadOperation::GetOrderingHeads, None, BTreeMap::new());
    assert!(ordering.validate_against_catalogue(&entries).is_ok());

    let view = read_request(
        NamedReadOperation::GetScopeRevisionView,
        Some("scope-one"),
        BTreeMap::new(),
    );
    assert!(view.validate_against_catalogue(&entries).is_ok());

    let receipt = read_request(
        NamedReadOperation::ResolveWriteReceipt,
        None,
        receipt_params(),
    );
    assert!(receipt.validate_against_catalogue(&entries).is_ok());
}

#[test]
fn unknown_extra_and_control_params_fail_closed() {
    let entries = generated_operation_manifests().unwrap();

    // Extra undeclared parameter on an otherwise accepted request.
    let mut extra = receipt_params();
    extra.insert("limit".to_owned(), json!(1));
    let request = read_request(NamedReadOperation::ResolveWriteReceipt, None, extra);
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    // Control substitution through an undeclared control name.
    let mut control = receipt_params();
    control.insert("state_fence".to_owned(), json!("smuggled"));
    let request = read_request(NamedReadOperation::ResolveWriteReceipt, None, control);
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "payload.control_field",
            ..
        })
    ));

    // Missing required parameter.
    let request = read_request(
        NamedReadOperation::ResolveWriteReceipt,
        None,
        BTreeMap::new(),
    );
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    // Malformed operation identity shape.
    let mut malformed = BTreeMap::new();
    malformed.insert("operation_id".to_owned(), json!(""));
    let request = read_request(NamedReadOperation::ResolveWriteReceipt, None, malformed);
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    // Known-but-unsupported operation stays unadvertised.
    let request = read_request(NamedReadOperation::GetMailbox, None, BTreeMap::new());
    assert_eq!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::UnknownOperation)
    );

    // Scope-required read without a scope.
    let request = read_request(
        NamedReadOperation::GetScopeRevisionView,
        None,
        BTreeMap::new(),
    );
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "scope_id",
            ..
        })
    ));

    // Scope-free read carrying a scope.
    let request = read_request(
        NamedReadOperation::GetRevisionHeads,
        Some("scope-one"),
        BTreeMap::new(),
    );
    assert!(matches!(
        request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "scope_id",
            ..
        })
    ));
}

fn respec_with(
    entry: &NamedOperationManifest,
    mutate: impl FnOnce(&mut OperationManifestSpec),
) -> NamedOperationManifest {
    let mut spec = OperationManifestSpec {
        name: entry.name.clone(),
        version: entry.version,
        operation_kind: entry.operation_kind,
        owning_section: entry.owning_section.clone(),
        schema_revision: entry.schema_revision,
        parameter_schema: entry.parameter_schema.clone(),
        requires_scope_id: entry.requires_scope_id,
        scope_kind: entry.scope_kind.clone(),
        minimum_compatible_version: entry.minimum_compatible_version,
        transition_classes: entry.transition_classes.clone(),
        maximum_effect: entry.maximum_effect,
        max_input_bytes: entry.max_input_bytes,
        max_output_bytes: entry.max_output_bytes,
        timeout_ms: entry.timeout_ms,
    };
    mutate(&mut spec);
    NamedOperationManifest::from_spec(spec).unwrap()
}

#[test]
fn entry_binding_change_moves_set_digest() {
    let entries = generated_operation_manifests().unwrap();
    let baseline = operation_manifest_set_digest(&entries).unwrap();

    // Widening any entry bound changes the entry digest and the set digest.
    let mut widened = entries.clone();
    widened[0] = respec_with(&entries[0], |spec| {
        spec.max_input_bytes = spec.max_input_bytes.saturating_add(1);
    });
    let widened_digest = operation_manifest_set_digest(&widened).unwrap();
    assert_ne!(widened[0].digest, entries[0].digest);
    assert_ne!(widened_digest, baseline);

    // Bumping any entry schema revision moves the set digest as well.
    let mut rebased = entries.clone();
    rebased[3] = respec_with(&entries[3], |spec| {
        spec.schema_revision = eliot_contracts::ContractVersion::new(
            spec.schema_revision.major,
            spec.schema_revision.minor,
            spec.schema_revision.patch.saturating_add(1),
        );
    });
    let rebased_digest = operation_manifest_set_digest(&rebased).unwrap();
    assert_ne!(rebased[3].digest, entries[3].digest);
    assert_ne!(rebased_digest, baseline);
    assert_ne!(rebased_digest, widened_digest);
}

fn mutation_plan(set_digest: &OperationManifestDigest) -> eliot_store_api::PreparedTransition {
    eliot_store_api::PreparedTransition {
        identity: OperationIdentity {
            operation_id: OperationId::new("operation-1").unwrap(),
            idempotency_key: "retry-1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: fence(),
        scope_id: ScopeId::new("scope-one").unwrap(),
        task_id: None,
        ordering_scopes: vec![OrderingScopeId::new("scope-one").unwrap()],
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest.clone(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters: BTreeMap::new(),
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

#[test]
fn stale_digest_plan_fails_manifest_mismatch() {
    let entries = generated_operation_manifests().unwrap();
    let set_digest = operation_manifest_set_digest(&entries).unwrap();

    // C1 advertises no mutation: the set digest binds, but the command
    // resolves to no entry.
    let plan = mutation_plan(&set_digest);
    assert_eq!(
        plan.validate_against_catalogue(&entries),
        Err(StoreError::UnknownOperation)
    );

    // A stale digest fails before command resolution.
    let mut stale = plan.clone();
    stale.operation_manifest_digest = OperationManifestDigest::new("0".repeat(64)).unwrap();
    assert_eq!(
        stale.validate_against_catalogue(&entries),
        Err(StoreError::ManifestMismatch)
    );
}

fn genesis_context() -> eliot_store_api::RequestMeta {
    eliot_store_api::RequestMeta {
        request_id: RequestId::new("request-1").unwrap(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product").unwrap(),
        source_id: SourceId::new("source").unwrap(),
        state_fence: fence(),
        clock: ClockReading::default(),
    }
}

fn genesis_request() -> Result<StoreGenesisRequest, StoreError> {
    let payload = br#"{"seed":true}"#.to_vec();
    let record = eliot_store_api::RecoveryRecord {
        namespace: "owner".to_owned(),
        key: "seed".to_owned(),
        state_fence: fence(),
        revision: 1,
        schema: "opaque-owner-v1".to_owned(),
        payload: payload.clone(),
        value_digest: sha256_hex(&payload),
    };
    StoreGenesisRequest {
        contract_version: CONTRACT_VERSION,
        operation_id: OperationId::new("genesis-op-1").map_err(StoreError::Foundation)?,
        idempotency_key: "genesis-retry-1".to_owned(),
        canonical_request_hash: String::new(),
        state_fence: fence(),
        owner_records: vec![record],
    }
    .with_computed_digest()
}

#[test]
fn generated_set_regenerates_byte_identical_and_genesis_binds() {
    let first = generated_operation_manifests().unwrap();
    let second = generated_operation_manifests().unwrap();
    assert_eq!(
        canonical_json_bytes(&first).unwrap(),
        canonical_json_bytes(&second).unwrap()
    );
    assert_eq!(
        operation_manifest_set_digest(&first).unwrap(),
        operation_manifest_set_digest(&second).unwrap()
    );

    // The genesis path is sourced from the same generated table.
    let genesis = genesis_manifest().unwrap();
    assert!(genesis.validate().is_ok());
    assert_eq!(genesis.name, GENESIS_MANIFEST_NAME);
    let table_genesis = first
        .iter()
        .find(|entry| entry.name == GENESIS_MANIFEST_NAME)
        .unwrap();
    assert_eq!(&genesis, table_genesis);

    let transition = genesis_transition(&genesis_context(), &genesis_request().unwrap()).unwrap();
    assert!(transition.validate_against_catalogue(&first).is_ok());

    let mut stale = transition.clone();
    stale.operation_manifest_digest = OperationManifestDigest::new("0".repeat(64)).unwrap();
    assert_eq!(
        stale.validate_against_catalogue(&first),
        Err(StoreError::ManifestMismatch)
    );
}
