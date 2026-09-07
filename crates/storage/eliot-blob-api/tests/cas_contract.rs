use eliot_blob_api::{
    BlobCasCapability, BlobCasDurability, BlobCasFailure, BlobCasNamespace, BlobCasOutcome,
    BlobCasReceipt, BlobCasRequest, BlobCasState, BlobCasSuccessKind, BlobError,
    BlobIssuerTrustAnchor, BlobReceiptBinding, BlobReceiptContext, BlobRootLease,
    VerifiedBlobReceipt, verify_receipt,
};
use eliot_platform::WorkScopePath;
use eliot_receipts::{
    ArtifactBinding, ProofCeiling, Receipt, ReceiptCore, ReceiptDisposition, ReceiptKind,
    contract_identity,
};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected success: {value:?}"),
        Err(error) => error,
    }
}

fn context_json(effect: &str, operation: &str, request: &str) -> String {
    let fence = r#"{"authority_epoch":4,"resource_generation":7,"task_revision":null,"policy_revision":null,"integration_revision":null}"#;
    let metadata = format!(
        r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-cas-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":4,"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn make_request(operation: &str, target: &str) -> BlobCasRequest {
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
    ok(BlobCasRequest::new(
        context,
        root_lease,
        BlobCasNamespace::StageJournal,
        ok(WorkScopePath::new(target)),
        BlobCasState::Digest("a".repeat(64)),
        "b".repeat(64),
        7,
        9,
        BlobCasDurability::Requested,
    ))
}

#[test]
fn cas_state_is_tagged_and_rejects_unknown_or_noncanonical_digests() {
    let missing = ok(serde_json::to_string(&BlobCasState::Missing));
    assert_eq!(missing, r#"{"kind":"MISSING"}"#);
    let digest = ok(serde_json::to_string(&BlobCasState::Digest("a".repeat(64))));
    assert!(digest.contains(r#""kind":"DIGEST""#));
    assert!(serde_json::from_str::<BlobCasState>(r#"{"kind":"UNKNOWN"}"#).is_err());
    assert!(
        serde_json::from_str::<BlobCasState>(&format!(
            r#"{{"kind":"DIGEST","sha256":"{}"}}"#,
            "A".repeat(64)
        ))
        .is_err()
    );
}

#[test]
fn request_commitment_uses_normalized_target_and_rejects_reuse_changes() {
    let slash = make_request("cas-1", "transactions/journal.stage");
    let backslash = make_request("cas-1", r"transactions\journal.stage");
    assert_eq!(
        ok(slash.request_commitment_sha256()),
        ok(backslash.request_commitment_sha256())
    );
    ok(slash.validate_exact_replay(&backslash));

    let mut changed = slash.clone();
    changed.expected = BlobCasState::Digest("c".repeat(64));
    let error = err(slash.validate_exact_replay(&changed));
    assert!(matches!(
        error,
        BlobError::CasFailure { ref failure } if matches!(**failure, BlobCasFailure::IdentityConflict { .. })
    ));

    let different_step = make_request("cas-2", "transactions/journal.stage");
    assert!(slash.validate_exact_replay(&different_step).is_err());
    assert_ne!(
        ok(slash.request_commitment_sha256()),
        ok(different_step.request_commitment_sha256())
    );
}

#[test]
fn journal_namespace_and_provider_generation_are_explicitly_fenced() {
    let mut invalid = make_request("cas-3", "transactions/journal.stage");
    invalid.namespace = BlobCasNamespace::Tombstone;
    assert!(invalid.validate().is_err());

    let mut stale = make_request("cas-4", "transactions/journal.stage");
    stale.expected_backend_generation = 0;
    assert!(stale.validate().is_err());

    let request = make_request("cas-5", "transactions/journal.stage");
    let applied = ok(request.effect_commitment_sha256(
        9,
        BlobCasDurability::Confirmed,
        eliot_blob_api::BlobCasSuccessKind::Applied,
    ));
    let no_op = err(request.effect_commitment_sha256(
        9,
        BlobCasDurability::Confirmed,
        eliot_blob_api::BlobCasSuccessKind::NoOp,
    ));
    assert!(matches!(no_op, BlobError::MetadataPayloadMismatch));
    assert_ne!(applied, ok(request.request_commitment_sha256()));

    let mut equal = request.clone();
    equal.expected = BlobCasState::Digest("b".repeat(64));
    assert!(
        equal
            .effect_commitment_sha256(
                9,
                BlobCasDurability::Confirmed,
                eliot_blob_api::BlobCasSuccessKind::Applied,
            )
            .is_err()
    );
    assert!(
        equal
            .effect_commitment_sha256(
                9,
                BlobCasDurability::Confirmed,
                eliot_blob_api::BlobCasSuccessKind::NoOp,
            )
            .is_ok()
    );
}

#[test]
fn unknown_failure_preserves_request_and_distinguishes_no_observation() {
    let request = Box::new(make_request("cas-6", "transactions/journal.stage"));
    let outcome = BlobCasOutcome::UnknownOutcome {
        request,
        observed: None,
        observed_backend_generation: Some(8),
        observed_durability: BlobCasDurability::Unconfirmed,
    };
    let error = err(outcome.into_blob_result());
    match error {
        BlobError::CasFailure { failure } => match *failure {
            BlobCasFailure::UnknownOutcome {
                request,
                observed,
                observed_backend_generation,
                observed_durability,
            } => {
                assert_eq!(
                    request.target.normalized_identity(),
                    "transactions/journal.stage"
                );
                assert!(observed.is_none());
                assert_eq!(observed_backend_generation, Some(8));
                assert_eq!(observed_durability, BlobCasDurability::Unconfirmed);
            }
            other => panic!("unexpected failure: {other:?}"),
        },
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn capability_and_failure_surface_keep_unsupported_distinct() {
    assert_eq!(
        ok(serde_json::to_string(
            &BlobCasCapability::UnsupportedAtomicCas
        )),
        "\"UNSUPPORTED_ATOMIC_CAS\""
    );
    let request = Box::new(make_request("cas-7", "transactions/journal.stage"));
    let error = err(BlobCasOutcome::UnsupportedAtomicCas { request }.into_blob_result());
    assert!(matches!(
        error,
        BlobError::CasFailure { ref failure }
            if matches!(**failure, BlobCasFailure::UnsupportedAtomicCas { .. })
    ));
}

fn verified_receipt(request: &BlobCasRequest) -> (BlobIssuerTrustAnchor, VerifiedBlobReceipt) {
    let request_sha = ok(request.request_commitment_sha256());
    let effect_sha = ok(request.effect_commitment_sha256(
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    let request_artifact = ok(ok(request.request_artifact_id()).parse());
    let effect_artifact = ok(ok(request.effect_artifact_id(
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ))
    .parse());
    let context = &request.context;
    let receipt = ok(Receipt::issue(ReceiptCore {
        contract: ok(contract_identity()),
        kind: ReceiptKind::Operation,
        work_scope: context.work_scope.clone(),
        task: context.task.clone(),
        session: context.session.clone(),
        causal: context.causal.clone(),
        request: context.request.clone(),
        operation: context.operation.clone(),
        authority: context.authority.clone(),
        artifacts: vec![
            ArtifactBinding {
                artifact_id: request_artifact,
                sha256: request_sha,
                role: ReceiptKind::Artifact,
                source_revision: None,
            },
            ArtifactBinding {
                artifact_id: effect_artifact,
                sha256: effect_sha,
                role: ReceiptKind::Artifact,
                source_revision: None,
            },
        ],
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::ObservedExternalEffect,
        },
    }));
    let anchor = ok(BlobIssuerTrustAnchor::new(
        "cas-issuer",
        "cas-key",
        vec![7; 32],
    ));
    let bytes = ok(anchor.sign_receipt(&receipt));
    let proof_id = ok(request.receipt_proof_id());
    let binding = ok(BlobReceiptBinding::for_operation(
        context,
        request.root_lease.root_generation,
        Some(1),
        Some(&proof_id),
    ));
    let verified = ok(verify_receipt(&anchor, &bytes, binding));
    (anchor, verified)
}

#[test]
fn verified_receipt_requires_exact_signed_cas_artifacts() {
    let request = make_request("cas-8", "transactions/journal.stage");
    let (anchor, verified) = verified_receipt(&request);
    let cas = ok(BlobCasReceipt::from_verified(
        &verified,
        &anchor,
        &request,
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    assert_eq!(cas.request(), &request);
    assert_eq!(cas.success(), BlobCasSuccessKind::Applied);

    let wrong_request = make_request("cas-9", "transactions/journal.stage");
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &wrong_request,
            9,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
    let other_anchor = ok(BlobIssuerTrustAnchor::new(
        "cas-issuer",
        "other-key",
        vec![8; 32],
    ));
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &other_anchor,
            &request,
            9,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
    assert!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &request,
            9,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::NoOp,
        )
        .is_err()
    );
}
