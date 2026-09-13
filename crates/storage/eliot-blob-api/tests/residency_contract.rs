use eliot_blob_api::{
    BlobHash, BlobId, BlobLocator, BlobPolicyBinding, BlobReceiptContext, BlobRootLease,
    BlobStageRequest, ObjectResidencyKey, VersionedContentDigest, metadata_path, payload_path,
    receipt_binding_sha256,
};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn residency_for_scope(scope: &str) -> ObjectResidencyKey {
    let digest = ok(BlobHash::new("a".repeat(64)));
    ObjectResidencyKey {
        scope_domain_id: ok(BlobId::new(scope)),
        access_domain_id: ok(BlobId::new("access-a")),
        confidentiality_domain_id: ok(BlobId::new("conf-a")),
        encryption_key_domain_id: ok(BlobId::new("key-lineage-a")),
        retention_domain_id: ok(BlobId::new("retention-a")),
        erasure_domain_id: ok(BlobId::new("erasure-a")),
        content_digest: VersionedContentDigest {
            algorithm: ok(BlobId::new("blake3")),
            version: 1,
            digest,
        },
    }
}

fn locator_for_scope(scope: &str) -> BlobLocator {
    let residency = residency_for_scope(scope);
    let hash = residency.content_digest.digest.clone();
    let locator = BlobLocator {
        hash,
        residency,
        root_generation: 7,
        path_generation: 1,
    };
    ok(locator.validate().map(|()| locator))
}

fn context_json(effect: &str, operation: &str, request: &str) -> String {
    let fence = r#"{"authority_epoch":4,"resource_generation":7,"task_revision":null,"policy_revision":null,"integration_revision":null}"#;
    let metadata = format!(
        r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-stage-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":4,"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn make_stage_request(operation: &str, scope: &str) -> BlobStageRequest {
    let context: BlobReceiptContext = ok(serde_json::from_str(&context_json(
        "REVERSIBLE_MUTATION",
        operation,
        &format!("request-{operation}"),
    )));
    let root_lease: BlobRootLease = ok(serde_json::from_value(serde_json::json!({
        "root_id": "root-1",
        "owner_id": "owner-1",
        "lease_id": "lease-1",
        "root_generation": 7,
        "fence_binding": context.request,
    })));
    let policy: BlobPolicyBinding = ok(serde_json::from_str(
        r#"{"privacy_class":"PRIVATE","retention_class":"TASK","policy_ref":"policy-1","instruction_taint":"DATA_ONLY","effect_ceiling":"CANDIDATE_ONLY"}"#,
    ));
    let residency = residency_for_scope(scope);
    let request = BlobStageRequest {
        context,
        root_lease,
        bytes: b"hello residency".to_vec(),
        policy,
        residency,
    };
    ok(request.validate().map(|()| request))
}

#[test]
fn residency_scoped_stage_request_is_accepted() {
    let request = make_stage_request("stage-residency-1", "scope-a");
    assert_eq!(request.residency.scope_domain_id.as_str(), "scope-a");
    assert!(request.policy.validate_for_residency(&request.residency).is_ok());
    assert!(request.validate().is_ok());
    // Wire round-trip preserves the full residency identity.
    let wire = ok(serde_json::to_string(&request));
    let decoded: BlobStageRequest = ok(serde_json::from_str(&wire));
    assert_eq!(decoded, request);
}

#[test]
fn equal_bytes_in_different_domains_never_co_reside() {
    let left = locator_for_scope("scope-a");
    let right = locator_for_scope("scope-b");
    assert_ne!(left, right);
    assert_ne!(left.residency_key_digest(), right.residency_key_digest());

    let left_payload = ok(payload_path(&left));
    let right_payload = ok(payload_path(&right));
    assert_ne!(
        left_payload.normalized_identity(),
        right_payload.normalized_identity()
    );

    let left_metadata = ok(metadata_path(&left));
    let right_metadata = ok(metadata_path(&right));
    assert_ne!(
        left_metadata.normalized_identity(),
        right_metadata.normalized_identity()
    );
    assert_ne!(
        left_payload.normalized_identity(),
        left_metadata.normalized_identity()
    );

    let policy: BlobPolicyBinding = ok(serde_json::from_str(
        r#"{"privacy_class":"PRIVATE","retention_class":"TASK","policy_ref":"policy-1","instruction_taint":"DATA_ONLY","effect_ceiling":"CANDIDATE_ONLY"}"#,
    ));
    let format = ok(BlobId::new("blob-format"));
    let compression = eliot_blob_api::CompressionDescriptor {
        algorithm: ok(BlobId::new("zstd")),
        version: 1,
    };
    let crypto = eliot_blob_api::CryptoDescriptor {
        algorithm: ok(BlobId::new("aes-gcm")),
        version: 1,
        key_lineage: ok(BlobId::new("key-lineage-a")),
        key_generation: 1,
    };
    let left_binding = ok(receipt_binding_sha256(
        &format,
        1,
        &left,
        5,
        64,
        &"c".repeat(64),
        &"d".repeat(64),
        &compression,
        &crypto,
        &policy,
    ));
    let right_binding = ok(receipt_binding_sha256(
        &format,
        1,
        &right,
        5,
        64,
        &"c".repeat(64),
        &"d".repeat(64),
        &compression,
        &crypto,
        &policy,
    ));
    assert_ne!(left_binding, right_binding);
}

#[test]
fn legacy_locator_and_digest_mismatch_are_rejected_without_silent_upgrade() {
    // s-04-v1 3-field shape without residency: rejected, never defaulted.
    let legacy = r#"{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","root_generation":7,"path_generation":1}"#;
    let legacy_error = match serde_json::from_str::<BlobLocator>(legacy) {
        Ok(_) => panic!("legacy locator without residency must be rejected"),
        Err(error) => format!("{error:?}"),
    };
    assert!(legacy_error.contains("residency"));

    // Hash that does not equal the residency content digest: rejected.
    let mut locator = locator_for_scope("scope-a");
    locator.hash = ok(BlobHash::new("b".repeat(64)));
    assert!(locator.validate().is_err());
    assert!(serde_json::to_string(&locator).is_ok_and(|_| locator.validate().is_err()));

    // Zero digest version: rejected at the content-digest layer.
    let mut residency = residency_for_scope("scope-a");
    residency.content_digest.version = 0;
    assert!(residency.validate().is_err());

    // Digest rotation is a different residency identity with a different
    // binding, not a relabel of the same object.
    let mut rotated = residency_for_scope("scope-a");
    rotated.content_digest.digest = ok(BlobHash::new("b".repeat(64)));
    let base = residency_for_scope("scope-a");
    assert_ne!(ok(base.key_digest()), ok(rotated.key_digest()));
}
