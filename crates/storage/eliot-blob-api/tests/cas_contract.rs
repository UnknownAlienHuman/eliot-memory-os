//! Lossless public CAS dispositions contract for ELIOT issue #946.
//!
//! Declared denominator: exactly 16 substantive tests, one per
//! `// WORK_UNIT_CASE: 946/<case>` marker immediately above its attributes,
//! cases 1..16 as listed in the issue. Each test binds its source (current
//! `eliot-blob-api` public types on main: `BlobCas*` plus
//! `BlobError::CasFailure`), its discovery (the frozen fixture under
//! `tests/data/cas-contract/` it decodes), and its executed-pass result (real
//! assertions against live behavior, never count-only).
//!
//! No test here performs I/O, locking, CAS execution, retry, or backend work:
//! every case constructs requests/outcomes/failures as values and checks the
//! public mapping into the existing `BlobError` surface.

use eliot_blob_api::{
    BlobCasCapability, BlobCasDurability, BlobCasFailure, BlobCasInternalReason, BlobCasNamespace,
    BlobCasOutcome, BlobCasReceipt, BlobCasRequest, BlobCasState, BlobCasSuccessKind, BlobError,
    BlobHash, BlobId, BlobIssuerTrustAnchor, BlobLocator, BlobReceiptBinding, BlobReceiptContext,
    BlobRootLease, CompressionDescriptor, CryptoDescriptor, ObjectResidencyKey,
    VerifiedBlobReceipt, VersionedContentDigest, verify_receipt,
};
use eliot_blob_api::{
    BlobPolicyBinding, CONTRACT_VERSION, metadata_path, payload_path, receipt_binding_sha256,
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

/// Canonical test lineage-A epoch (matches every other EpochId-only fixture).
const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn context_json(effect: &str, operation: &str, request: &str) -> String {
    let epoch = format!(r#"{{"lineage_id":"{TEST_LINEAGE}","sequence":4}}"#);
    let fence = format!(
        r#"{{"authority_epoch":{epoch},"resource_generation":7,"task_revision":null,"policy_revision":null,"integration_revision":null}}"#
    );
    let metadata = format!(
        r#"{{"request_id":"{request}","session_id":null,"task_id":null,"product_id":"product-1","source_id":"source-1","state_fence":{fence},"clock":{{"valid_time_ms":1,"known_time_ms":1,"transaction_sequence":null,"monotonic_ns":1}}}}"#
    );
    format!(
        r#"{{"work_scope":{{"scope_id":"scope-1","product_id":"product-1","resource_generation":7,"state_fence":{fence}}},"task":null,"session":null,"causal":{{"state_fence":{fence},"transaction_sequence":1,"parent_receipt_id":null,"predecessor_receipt_ids":[]}},"request":{{"metadata":{metadata},"state_fence":{fence}}},"operation":{{"operation_id":"{operation}","request_id":"{request}","idempotency_key":"idem-1","operation_kind":"blob-cas-test","effect":"{effect}","state_fence":{fence}}},"authority":{{"authority_id":"authority-1","authority_owner":"test-owner","authority_epoch":{epoch},"state_fence":{fence},"allowed_effect":"{effect}","proof_ceiling":"OBSERVED_EXTERNAL_EFFECT"}}}}"#
    )
}

fn make_request(operation: &str, target: &str) -> BlobCasRequest {
    make_request_with_backend(operation, target, 7)
}

fn make_request_with_backend(
    operation: &str,
    target: &str,
    expected_backend_generation: u64,
) -> BlobCasRequest {
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
        expected_backend_generation,
        9,
        BlobCasDurability::Requested,
    ))
}

fn verified_receipt(request: &BlobCasRequest) -> (BlobIssuerTrustAnchor, VerifiedBlobReceipt) {
    verified_receipt_for(request, BlobCasSuccessKind::Applied)
}

fn verified_receipt_for(
    request: &BlobCasRequest,
    success: BlobCasSuccessKind,
) -> (BlobIssuerTrustAnchor, VerifiedBlobReceipt) {
    let request_sha = ok(request.request_commitment_sha256());
    let effect_sha = ok(request.effect_commitment_sha256(
        request.expected_backend_generation,
        BlobCasDurability::Confirmed,
        success,
    ));
    let request_artifact = ok(ok(request.request_artifact_id()).parse());
    let effect_artifact = ok(ok(request.effect_artifact_id(
        request.expected_backend_generation,
        BlobCasDurability::Confirmed,
        success,
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

fn verified_noop_receipt(request: &BlobCasRequest) -> (BlobIssuerTrustAnchor, VerifiedBlobReceipt) {
    verified_receipt_for(request, BlobCasSuccessKind::NoOp)
}

/// A no-op request names the already-present state as both expected and
/// replacement, so the exact supported no-op path stays constructible.
fn make_noop_request(operation: &str) -> BlobCasRequest {
    let mut request = make_request(operation, "transactions/journal.stage");
    request.expected = BlobCasState::Digest("b".repeat(64));
    ok(request.validate().map(|()| request))
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

fn receipt_parts() -> (
    BlobId,
    CompressionDescriptor,
    CryptoDescriptor,
    BlobPolicyBinding,
) {
    let format = ok(BlobId::new("blob-format"));
    let compression = CompressionDescriptor {
        algorithm: ok(BlobId::new("zstd")),
        version: 1,
    };
    let crypto = CryptoDescriptor {
        algorithm: ok(BlobId::new("aes-gcm")),
        version: 1,
        key_lineage: ok(BlobId::new("lineage-a")),
        key_generation: 3,
    };
    let policy: BlobPolicyBinding = ok(serde_json::from_str(
        r#"{"privacy_class":"PRIVATE","retention_class":"TASK","policy_ref":"policy-1","instruction_taint":"DATA_ONLY","effect_ceiling":"CANDIDATE_ONLY"}"#,
    ));
    (format, compression, crypto, policy)
}

/// Source: `BlobCasCapability`, `BlobCasNamespace`, `BlobCasState`,
/// `BlobCasDurability`, `BlobCasSuccessKind` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/capability-vocabulary.json`.
/// Executed-pass: every wire spelling round-trips through the live enums.
// WORK_UNIT_CASE: 946/1
#[test]
fn cas_capability_and_outcome_vocabulary_is_exact() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/capability-vocabulary.json"
    )));
    assert_eq!(
        fixture["capabilities"],
        serde_json::json!(["ATOMIC_COMPARE_AND_REPLACE", "UNSUPPORTED_ATOMIC_CAS"])
    );
    assert_eq!(
        fixture["namespaces"],
        serde_json::json!(["STAGE_JOURNAL", "TOMBSTONE"])
    );
    assert_eq!(
        fixture["state_kinds"],
        serde_json::json!(["DIGEST", "MISSING"])
    );
    assert_eq!(
        fixture["durabilities"],
        serde_json::json!(["NOT_REQUESTED", "REQUESTED", "CONFIRMED", "UNCONFIRMED"])
    );
    assert_eq!(
        fixture["success_kinds"],
        serde_json::json!(["APPLIED", "NO_OP"])
    );

    let capability_wire = |capability: BlobCasCapability| match capability {
        BlobCasCapability::AtomicCompareAndReplace => "ATOMIC_COMPARE_AND_REPLACE",
        BlobCasCapability::UnsupportedAtomicCas => "UNSUPPORTED_ATOMIC_CAS",
    };
    assert_eq!(
        ok(serde_json::to_string(
            &BlobCasCapability::AtomicCompareAndReplace
        )),
        format!(
            "\"{}\"",
            capability_wire(BlobCasCapability::AtomicCompareAndReplace)
        )
    );
    assert_eq!(
        ok(serde_json::to_string(
            &BlobCasCapability::UnsupportedAtomicCas
        )),
        format!(
            "\"{}\"",
            capability_wire(BlobCasCapability::UnsupportedAtomicCas)
        )
    );
    assert_eq!(
        ok(serde_json::from_str::<BlobCasCapability>(
            "\"UNSUPPORTED_ATOMIC_CAS\""
        )),
        BlobCasCapability::UnsupportedAtomicCas
    );
    assert!(serde_json::from_str::<BlobCasCapability>("\"ATOMIC\"").is_err());

    let namespace_wire = |namespace: BlobCasNamespace| match namespace {
        BlobCasNamespace::StageJournal => "STAGE_JOURNAL",
        BlobCasNamespace::Tombstone => "TOMBSTONE",
    };
    for namespace in [BlobCasNamespace::StageJournal, BlobCasNamespace::Tombstone] {
        assert_eq!(
            ok(serde_json::to_string(&namespace)),
            format!("\"{}\"", namespace_wire(namespace))
        );
        assert_eq!(
            ok(serde_json::from_str::<BlobCasNamespace>(&format!(
                "\"{}\"",
                namespace_wire(namespace)
            ))),
            namespace
        );
    }

    let durability_wire = |durability: BlobCasDurability| match durability {
        BlobCasDurability::NotRequested => "NOT_REQUESTED",
        BlobCasDurability::Requested => "REQUESTED",
        BlobCasDurability::Confirmed => "CONFIRMED",
        BlobCasDurability::Unconfirmed => "UNCONFIRMED",
    };
    for durability in [
        BlobCasDurability::NotRequested,
        BlobCasDurability::Requested,
        BlobCasDurability::Confirmed,
        BlobCasDurability::Unconfirmed,
    ] {
        assert_eq!(
            ok(serde_json::to_string(&durability)),
            format!("\"{}\"", durability_wire(durability))
        );
    }

    let success_wire = |success: BlobCasSuccessKind| match success {
        BlobCasSuccessKind::Applied => "APPLIED",
        BlobCasSuccessKind::NoOp => "NO_OP",
    };
    for success in [BlobCasSuccessKind::Applied, BlobCasSuccessKind::NoOp] {
        assert_eq!(
            ok(serde_json::to_string(&success)),
            format!("\"{}\"", success_wire(success))
        );
    }

    assert_eq!(
        ok(serde_json::to_string(&BlobCasState::Missing)),
        r#"{"kind":"MISSING"}"#
    );
    let digest = ok(serde_json::to_string(&BlobCasState::Digest("a".repeat(64))));
    assert!(digest.contains(r#""kind":"DIGEST""#));
    assert!(digest.contains(&"a".repeat(64)));
}

/// Source: `BlobCasOutcome::UnsupportedAtomicCas` and
/// `BlobCasFailure::UnsupportedAtomicCas` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/unsupported-premutation.json`.
/// Executed-pass: the unsupported path preserves the exact request with no
/// receipt, observation, or mutation evidence attached.
// WORK_UNIT_CASE: 946/2
#[test]
fn unsupported_atomic_cas_is_a_typed_pre_mutation_state() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/unsupported-premutation.json"
    )));
    assert_eq!(
        fixture["capability"],
        serde_json::json!("UNSUPPORTED_ATOMIC_CAS")
    );
    assert_eq!(fixture["attempted"], serde_json::json!(false));
    assert_eq!(fixture["retryable"], serde_json::json!(false));

    let request = make_request("cas-unsupported-1", "transactions/journal.stage");
    let expected_commitment = ok(request.request_commitment_sha256());
    let outcome = BlobCasOutcome::UnsupportedAtomicCas {
        request: Box::new(request.clone()),
    };
    let error = err(outcome.into_blob_result());
    match error {
        BlobError::CasFailure { failure } => match *failure {
            BlobCasFailure::UnsupportedAtomicCas { request: kept } => {
                assert_eq!(*kept, request);
                assert_eq!(ok(kept.request_commitment_sha256()), expected_commitment);
                assert_eq!(
                    kept.target.normalized_identity(),
                    "transactions/journal.stage"
                );
            }
            other => panic!("unsupported must stay typed, got: {other:?}"),
        },
        other => panic!("unsupported must map to CasFailure, got: {other:?}"),
    }
    assert_eq!(
        ok(serde_json::to_string(
            &BlobCasCapability::UnsupportedAtomicCas
        )),
        "\"UNSUPPORTED_ATOMIC_CAS\""
    );
}

/// Source: `BlobCasOutcome::into_blob_result` and every `BlobError` variant in
/// `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/unsupported-premutation.json`.
/// Executed-pass: the unsupported failure is a `CasFailure`, never a
/// transient-availability error eligible for blind retry.
// WORK_UNIT_CASE: 946/3
#[test]
fn public_mapping_never_flattens_unsupported_into_unavailability() {
    fn is_transient_unavailability(error: &BlobError) -> bool {
        match error {
            BlobError::InvalidField { .. } => false,
            BlobError::InvalidContract(_) => false,
            BlobError::Receipt(_) => false,
            BlobError::AuthorityRequired(_) => false,
            BlobError::StaleFence => false,
            BlobError::OwnerConflict => false,
            BlobError::DuplicateIdentity(_) => false,
            BlobError::IncompleteLiveSet => false,
            BlobError::NotFound => false,
            BlobError::MetadataPayloadMismatch => false,
            BlobError::IdempotencyConflict => false,
            BlobError::IntegrityMismatch => false,
            BlobError::UnknownPublishOutcome { .. } => false,
            BlobError::UnknownGcOutcome { .. } => false,
            BlobError::PlanGap(_) => false,
            BlobError::ProviderUnavailable(_) => true,
            BlobError::CasFailure { .. } => false,
            BlobError::StorageCapacity { .. } => true,
            BlobError::KeyUnavailable { .. } => false,
            BlobError::Provider(_) => true,
        }
    }

    let request = make_request("cas-unsupported-2", "transactions/journal.stage");
    let error = err(BlobCasOutcome::UnsupportedAtomicCas {
        request: Box::new(request),
    }
    .into_blob_result());
    assert!(matches!(
        error,
        BlobError::CasFailure { ref failure }
            if matches!(**failure, BlobCasFailure::UnsupportedAtomicCas { .. })
    ));
    assert!(!is_transient_unavailability(&error));
    assert!(!matches!(error, BlobError::ProviderUnavailable(_)));
    assert!(!matches!(error, BlobError::Provider(_)));
    assert!(!matches!(error, BlobError::StorageCapacity { .. }));
    assert!(!matches!(error, BlobError::NotFound));
    let display = format!("{error}");
    assert_eq!(display, "CAS failure: atomic CAS is unsupported");
    assert!(!display.contains("unavailable"));
}

/// Source: `BlobCasFailure::ExpectedStateConflict` versus
/// `BlobCasFailure::IdentityConflict` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/conflict-vocabulary.json`.
/// Executed-pass: the two conflicts carry different payloads, messages, and
/// discriminants on live values.
// WORK_UNIT_CASE: 946/4
#[test]
fn expected_state_conflict_and_identity_conflict_stay_distinct() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/conflict-vocabulary.json"
    )));
    assert_eq!(fixture["distinct"], serde_json::json!(true));
    assert!(
        fixture["expected_state_preserves_observed"]
            .as_bool()
            .unwrap_or(false)
    );

    let request = make_request("cas-conflict-1", "transactions/journal.stage");
    let observed = BlobCasState::Digest("c".repeat(64));
    let state_error = err(BlobCasOutcome::ExpectedStateConflict {
        request: Box::new(request.clone()),
        observed: observed.clone(),
    }
    .into_blob_result());
    let identity_error = err(BlobCasOutcome::IdentityConflict {
        request: Box::new(request.clone()),
    }
    .into_blob_result());

    match &state_error {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::ExpectedStateConflict {
                request: kept,
                observed: seen,
            } => {
                assert_eq!(*kept.clone(), request);
                assert_eq!(*seen, observed);
                let digest_c = "c".repeat(64);
                assert_eq!(seen.sha256(), Some(digest_c.as_str()));
            }
            other => panic!("expected ExpectedStateConflict, got: {other:?}"),
        },
        other => panic!("expected CasFailure, got: {other:?}"),
    }
    match &identity_error {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::IdentityConflict { request: kept } => {
                assert_eq!(**kept, request);
            }
            other => panic!("expected IdentityConflict, got: {other:?}"),
        },
        other => panic!("expected CasFailure, got: {other:?}"),
    }
    assert_ne!(format!("{state_error}"), format!("{identity_error}"));
    assert_eq!(
        format!("{state_error}"),
        "CAS failure: CAS expected state conflict"
    );
    assert_eq!(
        format!("{identity_error}"),
        "CAS failure: CAS operation identity conflict"
    );
}

/// Source: `BlobCasReceipt::from_verified` plus the request/effect commitment
/// owners in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/applied-receipt.json`.
/// Executed-pass: a live signed receipt binds the exact operation, request,
/// fence generation, and confirmed durability.
// WORK_UNIT_CASE: 946/5
#[test]
fn applied_receipt_is_bound_to_the_exact_operation() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/applied-receipt.json"
    )));
    assert_eq!(fixture["success"], serde_json::json!("APPLIED"));
    assert_eq!(
        fixture["observed_durability"],
        serde_json::json!("CONFIRMED")
    );
    assert!(
        fixture["requires_operation_binding"]
            .as_bool()
            .unwrap_or(false)
    );
    assert!(
        fixture["requires_effect_commitment"]
            .as_bool()
            .unwrap_or(false)
    );

    let request = make_request_with_backend("cas-applied-1", "transactions/journal.stage", 9);
    let (anchor, verified) = verified_receipt(&request);
    let cas: BlobCasReceipt = ok(BlobCasReceipt::from_verified(
        &verified,
        &anchor,
        &request,
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    assert_eq!(cas.request(), &request);
    assert_eq!(cas.success(), BlobCasSuccessKind::Applied);
    assert_eq!(cas.backend_generation(), 9);
    assert_eq!(cas.expected_backend_generation(), 9);
    assert_eq!(cas.observed_durability(), BlobCasDurability::Confirmed);
    assert_eq!(
        cas.request_commitment_sha256(),
        ok(request.request_commitment_sha256()).as_str()
    );
    assert_eq!(
        cas.effect_commitment_sha256(),
        ok(request.effect_commitment_sha256(
            9,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied
        ))
        .as_str()
    );
    assert_eq!(
        cas.target().normalized_identity(),
        "transactions/journal.stage"
    );
    assert_eq!(cas.expected(), &request.expected);
    assert_eq!(
        cas.replacement_sha256(),
        request.replacement_sha256.as_str()
    );
    assert_eq!(cas.replacement_length(), 9);
    assert_eq!(
        verified.binding().operation_id(),
        request.context.operation.operation_id.as_str()
    );
    assert_eq!(
        verified.binding().request_id(),
        request.context.request.metadata.request_id.as_str()
    );
    assert_eq!(
        verified.binding().idempotency_key(),
        request.context.operation.idempotency_key.as_str()
    );
    match ok(BlobCasOutcome::Applied {
        receipt: cas.clone(),
    }
    .into_blob_result())
    {
        BlobCasOutcome::Applied { receipt } => assert_eq!(receipt, cas),
        other => panic!("applied must stay applied, got: {other:?}"),
    }

    let wrong_request = make_request("cas-applied-2", "transactions/journal.stage");
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
}

/// Source: `BlobCasOutcome::UnknownOutcome` and
/// `BlobCasFailure::UnknownOutcome` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/unknown-outcome.json`.
/// Executed-pass: a possible write keeps its unknown outcome with the exact
/// observation (`None` stays `None`), never decoding as not-attempted or
/// applied.
// WORK_UNIT_CASE: 946/6
#[test]
fn unknown_possible_write_never_becomes_not_attempted() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/unknown-outcome.json"
    )));
    assert_eq!(fixture["outcome"], serde_json::json!("UnknownOutcome"));
    assert_eq!(
        fixture["decodes_as_not_attempted"],
        serde_json::json!(false)
    );
    assert_eq!(fixture["decodes_as_applied"], serde_json::json!(false));

    let request = make_request("cas-unknown-1", "transactions/journal.stage");
    let unobserved = BlobCasOutcome::UnknownOutcome {
        request: Box::new(request.clone()),
        observed: None,
        observed_backend_generation: Some(8),
        observed_durability: BlobCasDurability::Unconfirmed,
    };
    let error = err(unobserved.into_blob_result());
    match &error {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::UnknownOutcome {
                request: kept,
                observed,
                observed_backend_generation,
                observed_durability,
            } => {
                assert_eq!(
                    kept.target.normalized_identity(),
                    "transactions/journal.stage"
                );
                assert!(observed.is_none());
                assert_eq!(*observed_backend_generation, Some(8));
                assert_eq!(*observed_durability, BlobCasDurability::Unconfirmed);
            }
            other => panic!("unknown outcome must stay typed, got: {other:?}"),
        },
        other => panic!("unknown outcome must map to CasFailure, got: {other:?}"),
    }

    let absence = BlobCasState::Missing;
    let observed_absence = BlobCasOutcome::UnknownOutcome {
        request: Box::new(request.clone()),
        observed: Some(absence.clone()),
        observed_backend_generation: None,
        observed_durability: BlobCasDurability::Unconfirmed,
    };
    let absence_error = err(observed_absence.into_blob_result());
    match &absence_error {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::UnknownOutcome { observed, .. } => {
                assert_eq!(*observed, Some(absence));
            }
            other => panic!("observed absence must be preserved, got: {other:?}"),
        },
        other => panic!("expected CasFailure, got: {other:?}"),
    }

    assert!(!matches!(
        &error,
        BlobError::CasFailure { failure }
            if matches!(
                failure.as_ref(),
                BlobCasFailure::NotAttempted { .. }
            )
    ));
    assert!(format!("{error}").contains("unknown"));
}

/// Source: `BlobCasOutcome::DurabilityUnconfirmed`,
/// `BlobCasFailure::DurabilityUnconfirmed`, and the confirmed-durability gates
/// in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/durability-unconfirmed.json`.
/// Executed-pass: unconfirmed durability keeps its observation and can never
/// satisfy the confirmed-durability effect or receipt gates.
// WORK_UNIT_CASE: 946/7
#[test]
fn durability_unconfirmed_never_becomes_durable_applied() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/durability-unconfirmed.json"
    )));
    assert_eq!(
        fixture["outcome"],
        serde_json::json!("DurabilityUnconfirmed")
    );
    assert_eq!(
        fixture["decodes_as_durable_applied"],
        serde_json::json!(false)
    );

    let request = make_request("cas-durability-1", "transactions/journal.stage");
    let observed = BlobCasState::Digest("c".repeat(64));
    let pending = BlobCasOutcome::DurabilityUnconfirmed {
        request: Box::new(request.clone()),
        observed: Some(observed.clone()),
        observed_backend_generation: Some(8),
    };
    let error = err(pending.into_blob_result());
    match &error {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::DurabilityUnconfirmed {
                request: kept,
                observed: seen,
                observed_backend_generation,
            } => {
                assert_eq!(**kept, request);
                assert_eq!(*seen, Some(observed.clone()));
                assert_eq!(*observed_backend_generation, Some(8));
            }
            other => panic!("durability state must stay typed, got: {other:?}"),
        },
        other => panic!("expected CasFailure, got: {other:?}"),
    }

    assert!(
        request
            .effect_commitment_sha256(
                7,
                BlobCasDurability::Unconfirmed,
                BlobCasSuccessKind::Applied
            )
            .is_err()
    );
    assert!(
        request
            .effect_commitment_sha256(7, BlobCasDurability::Requested, BlobCasSuccessKind::Applied)
            .is_err()
    );
    let (anchor, verified) = verified_receipt(&request);
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &request,
            7,
            BlobCasDurability::Unconfirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
}

/// Source: `request_commitment_sha256`, `validate_exact_replay`, and
/// `BlobCasReceipt::from_verified` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/operation-identity.json`.
/// Executed-pass: two operation IDs over identical bytes hold different
/// commitments and neither accepts the other's signed evidence.
// WORK_UNIT_CASE: 946/8
#[test]
fn same_bytes_with_different_operation_ids_share_no_evidence() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/operation-identity.json"
    )));
    assert_eq!(fixture["same_replacement_bytes"], serde_json::json!(true));
    assert_eq!(fixture["share_apply_evidence"], serde_json::json!(false));

    let first = make_request("cas-op-a", "transactions/journal.stage");
    let second = make_request("cas-op-b", "transactions/journal.stage");
    assert_eq!(first.replacement_sha256, second.replacement_sha256);
    assert_eq!(first.expected, second.expected);
    assert_ne!(
        ok(first.request_commitment_sha256()),
        ok(second.request_commitment_sha256())
    );
    let replay_error = err(first.validate_exact_replay(&second));
    assert!(matches!(
        &replay_error,
        BlobError::CasFailure { failure }
            if matches!(
                failure.as_ref(),
                BlobCasFailure::IdentityConflict { .. }
            )
    ));
    assert!(second.validate_exact_replay(&first).is_err());

    let (anchor, verified) = verified_receipt(&first);
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &second,
            9,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
    let first_effect = ok(first.effect_commitment_sha256(
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    let second_effect = ok(second.effect_commitment_sha256(
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    assert_ne!(first_effect, second_effect);
}

/// Source: `validate_exact_replay` and the commitment owners in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/operation-identity.json`.
/// Executed-pass: reusing one operation ID with a changed expected state or
/// replacement is an identity conflict with divergent commitments.
// WORK_UNIT_CASE: 946/9
#[test]
fn same_operation_with_changed_payload_conflicts() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/operation-identity.json"
    )));
    assert_eq!(
        fixture["changed_payload_conflicts"],
        serde_json::json!(true)
    );

    let request = make_request("cas-op-c", "transactions/journal.stage");
    let baseline = ok(request.request_commitment_sha256());

    let mut changed_expected = request.clone();
    changed_expected.expected = BlobCasState::Digest("c".repeat(64));
    assert_ne!(baseline, ok(changed_expected.request_commitment_sha256()));
    assert!(matches!(
        err(request.validate_exact_replay(&changed_expected)),
        BlobError::CasFailure { ref failure }
            if matches!(**failure, BlobCasFailure::IdentityConflict { .. })
    ));

    let mut changed_replacement = request.clone();
    changed_replacement.replacement_sha256 = "c".repeat(64);
    assert_ne!(
        baseline,
        ok(changed_replacement.request_commitment_sha256())
    );
    assert!(matches!(
        err(request.validate_exact_replay(&changed_replacement)),
        BlobError::CasFailure { ref failure }
            if matches!(**failure, BlobCasFailure::IdentityConflict { .. })
    ));

    ok(request.validate_exact_replay(&request.clone()));
}

/// Source: `ObjectResidencyKey`, `payload_path`, `metadata_path`, and
/// `receipt_binding_sha256` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/residency-domains.json`.
/// Executed-pass: equal content digests under different domains hold different
/// residency digests, paths, and receipt bindings on live values.
// WORK_UNIT_CASE: 946/10
#[test]
fn residency_identity_never_aliases_by_content_digest() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/residency-domains.json"
    )));
    assert_eq!(fixture["same_content_digest"], serde_json::json!(true));
    assert_eq!(fixture["alias_permitted"], serde_json::json!(false));

    let left = locator_for_scope("scope-a");
    let right = locator_for_scope("scope-b");
    assert_eq!(
        left.residency.content_digest.digest,
        right.residency.content_digest.digest
    );
    assert_ne!(left, right);
    assert_ne!(
        ok(left.residency.key_digest()),
        ok(right.residency.key_digest())
    );

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

    let (format, compression, crypto, policy) = receipt_parts();
    let left_binding = ok(receipt_binding_sha256(
        &format,
        1,
        &left,
        9,
        11,
        &"a".repeat(64),
        &"b".repeat(64),
        &compression,
        &crypto,
        &policy,
    ));
    let right_binding = ok(receipt_binding_sha256(
        &format,
        1,
        &right,
        9,
        11,
        &"a".repeat(64),
        &"b".repeat(64),
        &compression,
        &crypto,
        &policy,
    ));
    assert_ne!(left_binding, right_binding);

    let mut incoherent = left.clone();
    incoherent.hash = ok(BlobHash::new("b".repeat(64)));
    assert!(incoherent.validate().is_err());
}

/// Source: `BlobCasSuccessKind::NoOp`, `BlobCasOutcome::NoOp`, and
/// `BlobCasFailure::NotFound` in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/noop-notfound.json`.
/// Executed-pass: a live no-op receipt verifies only for expected-equals-
/// replacement, and not-found preserves its request without effect evidence.
// WORK_UNIT_CASE: 946/11
#[test]
fn supported_noop_and_not_found_semantics_are_preserved() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/noop-notfound.json"
    )));
    assert_eq!(fixture["success"], serde_json::json!("NO_OP"));
    assert!(
        fixture["not_found_preserves_request"]
            .as_bool()
            .unwrap_or(false)
    );

    let request = make_noop_request("cas-noop-1");
    assert_eq!(
        request.expected.sha256(),
        Some(request.replacement_sha256.as_str())
    );
    let (anchor, verified) = verified_noop_receipt(&request);
    let cas: BlobCasReceipt = ok(BlobCasReceipt::from_verified(
        &verified,
        &anchor,
        &request,
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::NoOp,
    ));
    assert_eq!(cas.success(), BlobCasSuccessKind::NoOp);
    match ok(BlobCasOutcome::NoOp { receipt: cas }.into_blob_result()) {
        BlobCasOutcome::NoOp { receipt } => {
            assert_eq!(receipt.success(), BlobCasSuccessKind::NoOp);
        }
        other => panic!("no-op must stay a no-op, got: {other:?}"),
    }

    let applied_request = make_request("cas-noop-2", "transactions/journal.stage");
    assert!(
        applied_request
            .effect_commitment_sha256(7, BlobCasDurability::Confirmed, BlobCasSuccessKind::NoOp)
            .is_err()
    );
    assert!(
        request
            .effect_commitment_sha256(7, BlobCasDurability::Confirmed, BlobCasSuccessKind::Applied)
            .is_err()
    );

    let missing = make_request("cas-missing-1", "transactions/journal.stage");
    let not_found = err(BlobCasOutcome::NotFound {
        request: Box::new(missing.clone()),
    }
    .into_blob_result());
    match &not_found {
        BlobError::CasFailure { failure } => match failure.as_ref() {
            BlobCasFailure::NotFound { request: kept } => {
                assert_eq!(**kept, missing);
            }
            other => panic!("not-found must stay typed, got: {other:?}"),
        },
        other => panic!("expected CasFailure, got: {other:?}"),
    }
}

/// Source: the `deny_unknown_fields` wire types and intrinsic constructors in
/// `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/wire-rejection.json`.
/// Executed-pass: unknown wire shapes fail closed and protected request fields
/// reject every defaulted or out-of-range value through live decoding.
// WORK_UNIT_CASE: 946/12
#[test]
fn unknown_wire_and_protected_defaults_are_rejected() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/wire-rejection.json"
    )));
    assert_eq!(fixture["unknown_field_rejected"], serde_json::json!(true));
    assert_eq!(fixture["unknown_variant_rejected"], serde_json::json!(true));
    assert_eq!(
        fixture["protected_defaults_rejected"],
        serde_json::json!(true)
    );

    assert!(serde_json::from_str::<BlobCasState>(r#"{"kind":"UNKNOWN"}"#).is_err());
    assert!(serde_json::from_str::<BlobCasNamespace>("\"JOURNAL\"").is_err());
    assert!(serde_json::from_str::<BlobCasDurability>("\"DURABLE\"").is_err());
    assert!(serde_json::from_str::<BlobCasSuccessKind>("\"SUCCESS\"").is_err());
    assert!(
        serde_json::from_str::<BlobCasState>(&format!(
            r#"{{"kind":"DIGEST","sha256":"{}"}}"#,
            "A".repeat(64)
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<BlobCasState>(&format!(
            r#"{{"kind":"DIGEST","sha256":"{}","extra":1}}"#,
            "a".repeat(64)
        ))
        .is_err()
    );

    let request = make_request("cas-wire-1", "transactions/journal.stage");
    let mut wire = ok(serde_json::to_value(&request));
    let object = ok::<_, &str>(wire.as_object_mut().ok_or("request wire must be an object"));
    object.insert("unknown_field".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<BlobCasRequest>(wire).is_err());

    let mut zero_length = request.clone();
    zero_length.replacement_length = 0;
    assert!(zero_length.validate().is_err());
    let mut zero_generation = request.clone();
    zero_generation.expected_backend_generation = 0;
    assert!(zero_generation.validate().is_err());
    let mut confirmed_request = request.clone();
    confirmed_request.requested_durability = BlobCasDurability::Confirmed;
    assert!(confirmed_request.validate().is_err());
    let mut unconfirmed_request = request;
    unconfirmed_request.requested_durability = BlobCasDurability::Unconfirmed;
    assert!(unconfirmed_request.validate().is_err());
}

/// Source: `CONTRACT_VERSION`, the `s-04-v1` rejection path, and the
/// generation-fenced effect gates in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/legacy-mapping.json`.
/// Executed-pass: legacy locator bytes decode as rejected and no legacy or
/// generation-shifted mapping can mint effect evidence.
// WORK_UNIT_CASE: 946/13
#[test]
fn versioned_legacy_mapping_fabricates_no_evidence() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/legacy-mapping.json"
    )));
    assert_eq!(fixture["contract_version"], serde_json::json!("s-04-v2"));
    assert_eq!(fixture["effect_domain"], serde_json::json!("s-04-cas-v1"));
    assert_eq!(fixture["fabricates_evidence"], serde_json::json!(false));
    assert_eq!(CONTRACT_VERSION, "s-04-v2");

    let legacy = format!(
        r#"{{"hash":"{}","root_generation":7,"path_generation":1}}"#,
        "a".repeat(64)
    );
    let legacy_error = match serde_json::from_str::<BlobLocator>(&legacy) {
        Ok(_) => panic!("legacy locator without residency must be rejected"),
        Err(error) => format!("{error}"),
    };
    assert!(legacy_error.contains("residency"));

    let request = make_request("cas-legacy-1", "transactions/journal.stage");
    let shifted_generation = request.expected_backend_generation + 1;
    assert!(
        request
            .effect_commitment_sha256(
                shifted_generation,
                BlobCasDurability::Confirmed,
                BlobCasSuccessKind::Applied
            )
            .is_err()
    );
    let baseline_effect = ok(request.effect_commitment_sha256(
        request.expected_backend_generation,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    let tweaked_effect = format!("{baseline_effect}#");
    assert_ne!(baseline_effect, tweaked_effect);
    assert_eq!(tweaked_effect.len(), baseline_effect.len() + 1);
    let (anchor, verified) = verified_receipt(&request);
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &request,
            shifted_generation,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
    assert!(matches!(
        BlobCasReceipt::from_verified(
            &verified,
            &anchor,
            &request,
            0,
            BlobCasDurability::Confirmed,
            BlobCasSuccessKind::Applied,
        ),
        Err(BlobError::MetadataPayloadMismatch)
    ));
}

/// Source: the validated constructors and `Display` impls in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/redacted-errors.json`.
/// Executed-pass: malformed inputs fail closed over a bounded table and every
/// surfaced error string is typed without protected bytes.
// WORK_UNIT_CASE: 946/14
#[test]
fn malformed_inputs_fail_closed_and_errors_stay_redacted() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/redacted-errors.json"
    )));
    assert_eq!(fixture["malformed_rejected"], serde_json::json!(true));
    assert_eq!(fixture["redacted"], serde_json::json!(true));
    assert_eq!(
        fixture["error_carries_protected_bytes"],
        serde_json::json!(false)
    );

    for length in [0, 1, 63, 65, 128] {
        assert!(BlobCasState::digest("a".repeat(length)).is_err());
        assert!(BlobHash::new("a".repeat(length)).is_err());
    }
    assert!(BlobCasState::digest("A".repeat(64)).is_err());
    assert!(BlobCasState::digest("zz".repeat(32)).is_err());
    assert!(BlobHash::new("A".repeat(64)).is_err());
    assert!(BlobId::new("../owner").is_err());
    assert!(BlobId::new("owner/blob").is_err());
    assert!(BlobId::new("").is_err());
    assert!(BlobId::new("owner-1").is_ok());
    assert!(serde_json::from_str::<BlobId>("\"../owner\"").is_err());

    let digest_a = "a".repeat(64);
    let digest_c = "c".repeat(64);
    let request = make_request("cas-redacted-1", "transactions/journal.stage");
    let conflict = err(BlobCasOutcome::ExpectedStateConflict {
        request: Box::new(request.clone()),
        observed: BlobCasState::Digest(digest_c.clone()),
    }
    .into_blob_result());
    let conflict_display = format!("{conflict}");
    assert_eq!(conflict_display, "CAS failure: CAS expected state conflict");
    assert!(!conflict_display.contains(&digest_a));
    assert!(!conflict_display.contains(&digest_c));

    let unknown = err(BlobCasOutcome::UnknownOutcome {
        request: Box::new(request.clone()),
        observed: Some(BlobCasState::Digest(digest_c.clone())),
        observed_backend_generation: Some(8),
        observed_durability: BlobCasDurability::Unconfirmed,
    }
    .into_blob_result());
    let unknown_display = format!("{unknown}");
    assert_eq!(unknown_display, "CAS failure: CAS outcome is unknown");
    assert!(!unknown_display.contains(&digest_c));

    let invalid = err(BlobCasState::digest("A".repeat(64)));
    let invalid_display = format!("{invalid}");
    assert!(invalid_display.contains("cas.sha256"));
    assert!(!invalid_display.contains(&"A".repeat(64)));
}

/// Minimal backend and caller fixtures over the same public owner.
/// Source: the public `BlobCas*`/`BlobError` owners in `src/lib.rs`.
/// Discovery: `tests/data/cas-contract/backend-caller.json`.
/// Executed-pass: exhaustive matches with no generic fallback classify every
/// live capability, outcome, failure, durability, and retry disposition.
struct FixtureBackend {
    capability: BlobCasCapability,
}

impl FixtureBackend {
    fn capability_wire(&self) -> &'static str {
        match self.capability {
            BlobCasCapability::AtomicCompareAndReplace => "ATOMIC_COMPARE_AND_REPLACE",
            BlobCasCapability::UnsupportedAtomicCas => "UNSUPPORTED_ATOMIC_CAS",
        }
    }

    /// The fixture performs no mutation: an atomic-capable backend reports the
    /// untouched request as not attempted, while an incapable backend reports
    /// the typed unsupported state before any mutation.
    fn attempt(&self, request: BlobCasRequest) -> BlobCasOutcome {
        match self.capability {
            BlobCasCapability::AtomicCompareAndReplace => BlobCasOutcome::NotAttempted {
                request: Box::new(request),
            },
            BlobCasCapability::UnsupportedAtomicCas => BlobCasOutcome::UnsupportedAtomicCas {
                request: Box::new(request),
            },
        }
    }
}

struct FixtureCaller;

impl FixtureCaller {
    fn disposition(outcome: &BlobCasOutcome) -> &'static str {
        match outcome {
            BlobCasOutcome::Applied { .. } => "APPLIED",
            BlobCasOutcome::NoOp { .. } => "NO_OP",
            BlobCasOutcome::ExpectedStateConflict { .. } => "EXPECTED_STATE_CONFLICT",
            BlobCasOutcome::IdentityConflict { .. } => "IDENTITY_CONFLICT",
            BlobCasOutcome::NotFound { .. } => "NOT_FOUND",
            BlobCasOutcome::NotAttempted { .. } => "NOT_ATTEMPTED",
            BlobCasOutcome::UnsupportedAtomicCas { .. } => "UNSUPPORTED_ATOMIC_CAS",
            BlobCasOutcome::UnknownOutcome { .. } => "UNKNOWN_OUTCOME",
            BlobCasOutcome::DurabilityUnconfirmed { .. } => "DURABILITY_UNCONFIRMED",
            BlobCasOutcome::Internal { .. } => "INTERNAL",
        }
    }

    fn failure_wire(failure: &BlobCasFailure) -> &'static str {
        match failure {
            BlobCasFailure::ExpectedStateConflict { .. } => "EXPECTED_STATE_CONFLICT",
            BlobCasFailure::IdentityConflict { .. } => "IDENTITY_CONFLICT",
            BlobCasFailure::NotFound { .. } => "NOT_FOUND",
            BlobCasFailure::NotAttempted { .. } => "NOT_ATTEMPTED",
            BlobCasFailure::UnsupportedAtomicCas { .. } => "UNSUPPORTED_ATOMIC_CAS",
            BlobCasFailure::UnknownOutcome { .. } => "UNKNOWN_OUTCOME",
            BlobCasFailure::DurabilityUnconfirmed { .. } => "DURABILITY_UNCONFIRMED",
            BlobCasFailure::Internal { .. } => "INTERNAL",
            BlobCasFailure::SuccessKindMismatch { .. } => "SUCCESS_KIND_MISMATCH",
        }
    }

    /// Blind retry is never safe: unsupported is not transient, unknown and
    /// unconfirmed outcomes must reconcile under the same operation first, and
    /// conflicts require a fresh read and a new operation. Only a request that
    /// was never attempted may be attempted.
    fn is_retryable(failure: &BlobCasFailure) -> bool {
        match failure {
            BlobCasFailure::ExpectedStateConflict { .. } => false,
            BlobCasFailure::IdentityConflict { .. } => false,
            BlobCasFailure::NotFound { .. } => false,
            BlobCasFailure::NotAttempted { .. } => true,
            BlobCasFailure::UnsupportedAtomicCas { .. } => false,
            BlobCasFailure::UnknownOutcome { .. } => false,
            BlobCasFailure::DurabilityUnconfirmed { .. } => false,
            BlobCasFailure::Internal { .. } => false,
            BlobCasFailure::SuccessKindMismatch { .. } => false,
        }
    }

    fn internal_reason_wire(reason: BlobCasInternalReason) -> &'static str {
        match reason {
            BlobCasInternalReason::InvalidRequest => "INVALID_REQUEST",
            BlobCasInternalReason::ReceiptMismatch => "RECEIPT_MISMATCH",
            BlobCasInternalReason::ArtifactMismatch => "ARTIFACT_MISMATCH",
            BlobCasInternalReason::SuccessKindMismatch => "SUCCESS_KIND_MISMATCH",
            BlobCasInternalReason::CommitmentMismatch => "COMMITMENT_MISMATCH",
            BlobCasInternalReason::BackendGenerationMismatch => "BACKEND_GENERATION_MISMATCH",
            BlobCasInternalReason::Protocol => "PROTOCOL",
        }
    }
}

// WORK_UNIT_CASE: 946/15
#[test]
fn backend_and_caller_fixtures_use_the_public_owner_exhaustively() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/backend-caller.json"
    )));
    assert_eq!(fixture["owner"], serde_json::json!("eliot.storage.blob"));
    assert_eq!(fixture["exhaustive_match"], serde_json::json!(true));
    assert_eq!(fixture["generic_fallback"], serde_json::json!(false));

    let atomic = FixtureBackend {
        capability: BlobCasCapability::AtomicCompareAndReplace,
    };
    let incapable = FixtureBackend {
        capability: BlobCasCapability::UnsupportedAtomicCas,
    };
    assert_eq!(atomic.capability_wire(), "ATOMIC_COMPARE_AND_REPLACE");
    assert_eq!(incapable.capability_wire(), "UNSUPPORTED_ATOMIC_CAS");

    let request = make_request("cas-fixture-1", "transactions/journal.stage");
    match atomic.attempt(request.clone()) {
        BlobCasOutcome::NotAttempted { request: kept } => assert_eq!(*kept, request),
        other => panic!("atomic fixture must not attempt, got: {other:?}"),
    }
    let unsupported = incapable.attempt(request.clone());
    assert_eq!(
        FixtureCaller::disposition(&unsupported),
        "UNSUPPORTED_ATOMIC_CAS"
    );
    let unsupported_error = err(unsupported.into_blob_result());
    match &unsupported_error {
        BlobError::CasFailure { failure } => {
            assert_eq!(
                FixtureCaller::failure_wire(failure),
                "UNSUPPORTED_ATOMIC_CAS"
            );
            assert!(!FixtureCaller::is_retryable(failure));
        }
        other => panic!("expected CasFailure, got: {other:?}"),
    }

    let (anchor, verified) = verified_receipt(&request);
    let applied: BlobCasReceipt = ok(BlobCasReceipt::from_verified(
        &verified,
        &anchor,
        &request,
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::Applied,
    ));
    assert_eq!(
        FixtureCaller::disposition(&BlobCasOutcome::Applied {
            receipt: applied.clone()
        }),
        "APPLIED"
    );
    let mismatch = err(BlobCasOutcome::NoOp { receipt: applied }.into_blob_result());
    match &mismatch {
        BlobError::CasFailure { failure } => {
            assert_eq!(
                FixtureCaller::failure_wire(failure),
                "SUCCESS_KIND_MISMATCH"
            );
            assert!(!FixtureCaller::is_retryable(failure));
        }
        other => panic!("expected CasFailure, got: {other:?}"),
    }

    let noop_request = make_noop_request("cas-fixture-2");
    let (noop_anchor, noop_verified) = verified_noop_receipt(&noop_request);
    let noop: BlobCasReceipt = ok(BlobCasReceipt::from_verified(
        &noop_verified,
        &noop_anchor,
        &noop_request,
        9,
        BlobCasDurability::Confirmed,
        BlobCasSuccessKind::NoOp,
    ));
    assert_eq!(
        FixtureCaller::disposition(&BlobCasOutcome::NoOp { receipt: noop }),
        "NO_OP"
    );

    let outcomes: Vec<BlobCasOutcome> = vec![
        BlobCasOutcome::ExpectedStateConflict {
            request: Box::new(request.clone()),
            observed: BlobCasState::Digest("c".repeat(64)),
        },
        BlobCasOutcome::IdentityConflict {
            request: Box::new(request.clone()),
        },
        BlobCasOutcome::NotFound {
            request: Box::new(request.clone()),
        },
        BlobCasOutcome::NotAttempted {
            request: Box::new(request.clone()),
        },
        BlobCasOutcome::UnsupportedAtomicCas {
            request: Box::new(request.clone()),
        },
        BlobCasOutcome::UnknownOutcome {
            request: Box::new(request.clone()),
            observed: None,
            observed_backend_generation: Some(8),
            observed_durability: BlobCasDurability::Unconfirmed,
        },
        BlobCasOutcome::DurabilityUnconfirmed {
            request: Box::new(request.clone()),
            observed: None,
            observed_backend_generation: Some(8),
        },
        BlobCasOutcome::Internal {
            request: Box::new(request.clone()),
            reason: BlobCasInternalReason::Protocol,
        },
    ];
    let expected = [
        "EXPECTED_STATE_CONFLICT",
        "IDENTITY_CONFLICT",
        "NOT_FOUND",
        "NOT_ATTEMPTED",
        "UNSUPPORTED_ATOMIC_CAS",
        "UNKNOWN_OUTCOME",
        "DURABILITY_UNCONFIRMED",
        "INTERNAL",
    ];
    for (outcome, wire) in outcomes.iter().zip(expected.iter()) {
        assert_eq!(FixtureCaller::disposition(outcome), *wire);
    }
    for outcome in outcomes {
        let error = err(outcome.into_blob_result());
        match &error {
            BlobError::CasFailure { failure } => {
                let reconstructed = match failure.as_ref() {
                    BlobCasFailure::ExpectedStateConflict { request, observed } => {
                        BlobCasOutcome::ExpectedStateConflict {
                            request: request.clone(),
                            observed: observed.clone(),
                        }
                    }
                    BlobCasFailure::IdentityConflict { request } => {
                        BlobCasOutcome::IdentityConflict {
                            request: request.clone(),
                        }
                    }
                    BlobCasFailure::NotFound { request } => BlobCasOutcome::NotFound {
                        request: request.clone(),
                    },
                    BlobCasFailure::NotAttempted { request } => BlobCasOutcome::NotAttempted {
                        request: request.clone(),
                    },
                    BlobCasFailure::UnsupportedAtomicCas { request } => {
                        BlobCasOutcome::UnsupportedAtomicCas {
                            request: request.clone(),
                        }
                    }
                    BlobCasFailure::UnknownOutcome {
                        request,
                        observed,
                        observed_backend_generation,
                        observed_durability,
                    } => BlobCasOutcome::UnknownOutcome {
                        request: request.clone(),
                        observed: observed.clone(),
                        observed_backend_generation: *observed_backend_generation,
                        observed_durability: *observed_durability,
                    },
                    BlobCasFailure::DurabilityUnconfirmed {
                        request,
                        observed,
                        observed_backend_generation,
                    } => BlobCasOutcome::DurabilityUnconfirmed {
                        request: request.clone(),
                        observed: observed.clone(),
                        observed_backend_generation: *observed_backend_generation,
                    },
                    BlobCasFailure::Internal { request, reason } => BlobCasOutcome::Internal {
                        request: request.clone(),
                        reason: *reason,
                    },
                    BlobCasFailure::SuccessKindMismatch { .. } => {
                        panic!("fixture outcomes never carry success-kind mismatch")
                    }
                };
                assert_eq!(
                    FixtureCaller::failure_wire(failure),
                    FixtureCaller::disposition(&reconstructed)
                );
                if matches!(failure.as_ref(), BlobCasFailure::NotAttempted { .. }) {
                    assert!(FixtureCaller::is_retryable(failure));
                } else {
                    assert!(!FixtureCaller::is_retryable(failure));
                }
            }
            other => panic!("expected CasFailure, got: {other:?}"),
        }
    }

    for (reason, wire) in [
        (BlobCasInternalReason::InvalidRequest, "INVALID_REQUEST"),
        (BlobCasInternalReason::ReceiptMismatch, "RECEIPT_MISMATCH"),
        (BlobCasInternalReason::ArtifactMismatch, "ARTIFACT_MISMATCH"),
        (
            BlobCasInternalReason::SuccessKindMismatch,
            "SUCCESS_KIND_MISMATCH",
        ),
        (
            BlobCasInternalReason::CommitmentMismatch,
            "COMMITMENT_MISMATCH",
        ),
        (
            BlobCasInternalReason::BackendGenerationMismatch,
            "BACKEND_GENERATION_MISMATCH",
        ),
        (BlobCasInternalReason::Protocol, "PROTOCOL"),
    ] {
        assert_eq!(FixtureCaller::internal_reason_wire(reason), wire);
        assert_eq!(format!("{reason}").len() > 0, true);
    }
}

/// Source: `crates/storage/eliot-blob-api/src/lib.rs` and its manifest,
/// embedded at compile time.
/// Discovery: `tests/data/cas-contract/source-proof.json`.
/// Executed-pass: structural assertions over the embedded source prove the
/// contract surface carries no I/O, lock, CAS-execution, retry, store,
/// state-machine, or authority implementation.
const LIB_RS: &str = include_str!("../src/lib.rs");
const API_CARGO_TOML: &str = include_str!("../Cargo.toml");

// WORK_UNIT_CASE: 946/16
#[test]
fn contract_source_carries_no_implementation_authority() {
    let fixture: serde_json::Value = ok(serde_json::from_str(include_str!(
        "data/cas-contract/source-proof.json"
    )));
    assert_eq!(
        fixture["source_file"],
        serde_json::json!("crates/storage/eliot-blob-api/src/lib.rs")
    );
    let forbidden: Vec<String> = ok(serde_json::from_value(fixture["forbidden_markers"].clone()));
    assert!(forbidden.contains(&"std::fs".to_owned()));
    assert!(forbidden.contains(&"tokio".to_owned()));
    for marker in &forbidden {
        assert!(
            !LIB_RS.contains(marker.as_str()),
            "forbidden implementation marker in contract source: {marker}"
        );
    }

    assert!(LIB_RS.contains("#![forbid(unsafe_code)]"));
    assert!(LIB_RS.contains("pub enum BlobCasOutcome"));
    assert!(LIB_RS.contains("pub enum BlobCasFailure"));
    assert!(LIB_RS.contains("pub struct BlobCasRequest"));
    assert!(LIB_RS.contains("pub struct BlobCasReceipt"));
    assert!(LIB_RS.contains("into_blob_result"));
    assert!(!LIB_RS.contains("BlobPlatformPort"));
    assert!(!LIB_RS.contains("StorageUnavailable"));
    assert!(!LIB_RS.contains("fn cas("));
    assert!(LIB_RS.contains("fn stage("));
    assert!(LIB_RS.contains("fn health("));
    assert!(!LIB_RS.contains("process::exit"));

    assert!(!API_CARGO_TOML.contains("tokio"));
    assert!(!API_CARGO_TOML.contains("redb"));
    assert!(API_CARGO_TOML.contains("eliot-platform"));
    assert!(API_CARGO_TOML.contains("eliot-receipts"));
}
