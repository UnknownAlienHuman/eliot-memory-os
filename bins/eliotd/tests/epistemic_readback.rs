//! T11.2 daemon closed integration surface for epistemic readback.
//!
//! This file proves the daemon's view of the Governor -> Kernel -> Store
//! epistemic path with real catalogue, validation, and failure logic — no
//! stubs, mocks, or canned Store values.
//!
//! Store execution (identical replay returns the same receipt/revision; a
//! stale predecessor fails with `RevisionConflict`; a changed same-ID payload
//! fails with `IdentityConflict`; no second revision is created; the exact
//! current-epistemic-position readback matches the commit) is proven against
//! the real provider by
//! `crates/storage/eliot-store-surreal-adapter/tests/epistemic_revision.rs::real_position_cas_exact_replay_and_receipt_readback`
//! (re-run on this base as the real-Surreal proof) and against the reference
//! handler by `crates/storage/eliot-store-memory/src/epistemic_tests.rs`.
//! This file proves the daemon half with the same closed types: the 35-entry
//! catalogue (18 reads + 16 mutations + genesis), the CEP `position` selector,
//! the `ApplyEpistemicRevision` closed payload requirement, the activated
//! `RecordAuthorityRevocation` schema, the `IdentityConflict` without-second-
//! revision disposition, and the exact daemon wiring types
//! (`KernelContextReadClient: CanonicalReadClient`,
//! `DaemonComposition::epistemic_composition` borrowing canonical +
//! activation + `DaemonKernelClient` + reads + readiness).

use std::collections::BTreeMap;

use eliot_store_api::{
    NamedMutationOperation, NamedReadOperation, StoreError, StoreFailure, StoreFailureDisposition,
    StoreFailureIdentityContext, StoreMutationDisposition, generated_operation_manifests,
    operation_manifest_set_digest,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn scope_request(
    operation: NamedReadOperation,
    scope: Option<&str>,
    parameters: BTreeMap<String, Value>,
) -> TestResult<eliot_store_api::NamedReadRequest> {
    use eliot_store_api::{ReadConsistency, ScopeId};
    let fence = test_fence()?;
    let scope_id = scope
        .map(ScopeId::new)
        .transpose()
        .map_err(|error| format!("scope names: {error}"))?;
    Ok(eliot_store_api::NamedReadRequest {
        operation,
        scope_id,
        consistency: ReadConsistency::ExactFence,
        state_fence: fence,
        parameters,
    })
}

fn test_fence() -> TestResult<eliot_store_api::StateFence> {
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .map_err(|error| format!("test lineage: {error}"))?;
    let sequence = NonZeroU64::new(1).ok_or("nonzero test sequence")?;
    let epoch = EpochId::new(lineage, sequence).map_err(|error| format!("test epoch: {error}"))?;
    Ok(eliot_store_api::StateFence::new(
        epoch,
        ResourceGeneration::genesis(),
    ))
}

#[test]
fn catalogue_activates_position_read_and_revision_write() -> TestResult {
    let entries = generated_operation_manifests().map_err(|error| format!("catalogue: {error}"))?;
    // Denominator bound to the producer declaration table: 18 activated reads
    // + 16 activated mutations + the genesis bootstrap entry. Exact equality
    // prevents a silent add or drop from passing on a bound.
    assert_eq!(entries.len(), 35, "18 reads + 16 mutations + genesis");
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert!(names.contains(&"GetCurrentEpistemicPosition"));
    assert!(names.contains(&"ApplyEpistemicRevision"));
    assert!(names.contains(&"UpdateTaskState"));
    assert!(names.contains(&"GetEvidencePack"));
    assert!(names.contains(&"GetAuthorityRevocationHistory"));
    assert!(names.contains(&"RecordAuthorityRevocation"));
    // The admitted catalogue growth since the 18-entry bound is exactly the
    // #1780 notification pair — bound here so a different silent add still
    // fails on the count above.
    assert!(names.contains(&"GetNotificationState"));
    assert!(names.contains(&"ApplyNotificationState"));
    let set_digest =
        operation_manifest_set_digest(&entries).map_err(|error| format!("digest: {error}"))?;
    let regenerated =
        generated_operation_manifests().map_err(|error| format!("regenerate: {error}"))?;
    let again =
        operation_manifest_set_digest(&regenerated).map_err(|error| format!("digest: {error}"))?;
    assert_eq!(
        set_digest, again,
        "identical catalogue binds the same digest"
    );
    Ok(())
}

#[test]
fn position_read_requires_its_closed_selector() -> TestResult {
    let entries = generated_operation_manifests().map_err(|error| format!("catalogue: {error}"))?;
    let valid = scope_request(
        NamedReadOperation::GetCurrentEpistemicPosition,
        Some("scope-one"),
        BTreeMap::from([("position".to_owned(), json!("position-one"))]),
    )?;
    assert!(valid.validate_against_catalogue(&entries).is_ok());

    let missing = scope_request(
        NamedReadOperation::GetCurrentEpistemicPosition,
        Some("scope-one"),
        BTreeMap::new(),
    )?;
    assert!(matches!(
        missing.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    let mut blank = BTreeMap::new();
    blank.insert("position".to_owned(), json!("   "));
    let blank_request = scope_request(
        NamedReadOperation::GetCurrentEpistemicPosition,
        Some("scope-one"),
        blank,
    )?;
    assert!(matches!(
        blank_request.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "operation.parameter",
            ..
        })
    ));

    let unscoped = scope_request(
        NamedReadOperation::GetCurrentEpistemicPosition,
        None,
        BTreeMap::from([("position".to_owned(), json!("position-one"))]),
    )?;
    assert!(matches!(
        unscoped.validate_against_catalogue(&entries),
        Err(StoreError::InvalidField {
            field: "scope_id",
            ..
        })
    ));
    Ok(())
}

#[test]
fn revision_and_revocation_writes_are_admitted_with_closed_payloads() -> TestResult {
    let entries = generated_operation_manifests().map_err(|error| format!("catalogue: {error}"))?;
    let set_digest =
        operation_manifest_set_digest(&entries).map_err(|error| format!("digest: {error}"))?;
    let operation_id = eliot_store_api::OperationId::new("operation-1")
        .map_err(|error| format!("operation: {error}"))?;
    let scope_id =
        eliot_store_api::ScopeId::new("scope-one").map_err(|error| format!("scope: {error}"))?;
    let ordering = eliot_store_api::OrderingScopeId::new("scope-one")
        .map_err(|error| format!("ordering: {error}"))?;

    let mut empty_revision = eliot_store_api::PreparedTransition {
        identity: eliot_store_api::OperationIdentity {
            operation_id,
            idempotency_key: "retry-1".to_owned(),
            canonical_request_hash: "a".repeat(64),
        },
        state_fence: test_fence()?,
        scope_id,
        task_id: None,
        ordering_scopes: vec![ordering],
        transition_class: eliot_store_api::TransitionClass::Epistemic,
        requested_effect_ceiling: eliot_store_api::EffectClass::Candidate,
        admission_contract_set_digest: "b".repeat(64),
        operation_manifest_digest: set_digest.clone(),
        // Issue-#18 digests are derived below via `bind_issue18_digests`,
        // never defaulted; no semantic source is bound here (`[]`).
        admission_digest: String::new(),
        mutation_plan_digest: String::new(),
        semantic_source_revisions: Vec::new(),
        named_operations: vec![eliot_store_api::NamedMutationRequest {
            operation: NamedMutationOperation::ApplyEpistemicRevision,
            parameters: BTreeMap::new(),
        }],
        event_projection_relation_intents: eliot_store_api::EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: eliot_store_api::SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    eliot_store_api::bind_issue18_digests(&mut empty_revision)
        .map_err(|error| format!("issue-18 digests: {error}"))?;
    assert!(
        matches!(
            empty_revision.validate_against_catalogue(&entries),
            Err(StoreError::InvalidField {
                field: "operation.parameter",
                ..
            })
        ),
        "admitted revision without its closed payload fails as a typed parameter error, never UnknownOperation"
    );

    let mut revocation = empty_revision.clone();
    revocation.transition_class = eliot_store_api::TransitionClass::RecoverySchema;
    revocation.requested_effect_ceiling = eliot_store_api::EffectClass::ReversibleMutation;
    revocation.named_operations = vec![eliot_store_api::NamedMutationRequest {
        operation: NamedMutationOperation::RecordAuthorityRevocation,
        parameters: BTreeMap::from([
            ("origin_ref".to_owned(), json!("root:alpha")),
            ("closure_id".to_owned(), json!("closure:one")),
            ("closure_revision".to_owned(), json!("1")),
            ("affected_digest".to_owned(), json!("a".repeat(64))),
            ("affected_count".to_owned(), json!("1")),
            ("invalidation_reason".to_owned(), json!("SOURCE_REVOKED")),
            ("fence_digest".to_owned(), json!("b".repeat(64))),
        ]),
    }];
    eliot_store_api::bind_issue18_digests(&mut revocation)
        .map_err(|error| format!("issue-18 digests: {error}"))?;
    revocation
        .validate_against_catalogue(&entries)
        .map_err(|error| format!("activated revocation catalogue: {error}"))?;
    Ok(())
}

#[test]
fn changed_same_id_rejection_creates_no_second_revision() -> TestResult {
    let failure = StoreFailure::from_store_error(
        StoreError::IdentityConflict,
        StoreFailureIdentityContext::default(),
    )
    .map_err(|error| format!("identity conflict maps: {error}"))?;
    assert_eq!(failure.disposition, StoreFailureDisposition::Conflict);
    assert_eq!(
        failure.mutation_disposition,
        StoreMutationDisposition::NotAttempted,
        "a changed same-ID payload is refused before any mutation is attempted"
    );
    Ok(())
}

fn assert_reads_implements_canonical<T: eliot_store_api::CanonicalReadClient>() {}

#[test]
fn kernel_context_read_client_is_the_canonical_read_client() {
    assert_reads_implements_canonical::<eliotd::KernelContextReadClient>();
}

type EpistemicBorrow<'a> = eliot_governor::GovernorEpistemicComposition<
    'a,
    eliotd::DaemonKernelClient,
    eliotd::KernelContextReadClient,
>;

type EpistemicWiringFn = for<'a> fn(
    &'a eliotd::DaemonComposition,
    &'a std::sync::Arc<eliotd::DaemonKernelClient>,
    &'a eliotd::KernelContextReadClient,
    u64,
) -> Result<EpistemicBorrow<'a>, eliotd::DaemonError>;

#[test]
fn daemon_exposes_the_epistemic_borrow_without_composition_churn() {
    fn wiring(f: EpistemicWiringFn) {
        let _ = f;
    }
    wiring(eliotd::DaemonComposition::epistemic_composition);
}
