//! Governor-owned authority-revocation recording and history decoding.
//!
//! Transitive influence revocation (issue #686) is enforced in the shipped
//! authority graph without a second graph, ledger, or authority machine:
//!
//! * recording: the Governor emits the canonical `RecordAuthorityRevocation`
//!   transition through [`authority_revocation_envelope`], following the
//!   `AppendAuditEvent` / `ReconcileRecovery` envelope pattern (closed
//!   owner-approved parameters, `RecoverySchema` / `ReversibleMutation`,
//!   Governor scope, generated-catalogue manifest digest). `eliot-authority`
//!   stays the pure decision owner and never emits transitions.
//! * reading: the Governor reads CURRENT revocation history through the
//!   `GetAuthorityRevocationHistory` named read built by
//!   [`revocation_history_read_request`] and decodes the store reply into
//!   typed evidence with [`decode_revocation_history_evidence`]. Only
//!   actually recorded revocations under the exact response fence are
//!   returned; unknown or partial outcomes can never appear in the decoded
//!   evidence.
//! * restoring: [`AuthorityOwner::from_snapshot_with_revocation_history`]
//!   (in `authority_recovery.rs`) applies that evidence before any grant
//!   becomes effective; missing, stale, or unknown evidence refuses.
//!
//! Validation order (fail-closed): admitted [`RequestIdentity`] shape and
//! exact fence agreement first, then non-blank revocation binding fields
//! with nonzero revision/count, then the closed typed parameters. Failure
//! mapping reuses the existing [`CompositionError`] variants (no new
//! variant is introduced so the closed matches elsewhere in this crate keep
//! compiling): identity/fence/response-binding mismatches are
//! [`CompositionError::Provider`]; every other deterministic admission
//! refusal is [`CompositionError::Owner`].
//!
//! Honest gaps: `RecordAuthorityRevocation` and
//! `GetAuthorityRevocationHistory` are known-but-unsupported at the store
//! catalogue gate until a store-owned slice activates their rows with
//! proven handlers (see `operation_catalogue`). The envelope therefore
//! binds the generated catalogue set digest so it passes that gate
//! unchanged once the row exists; until then commits fail closed with
//! `UnknownOperation`, never as silent success. The `scope:governor`
//! ordering-head expectation mirrors the operator/recovery precedent (the
//! store enforces the live sequence).

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, InfluenceDependencyClosure,
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId,
    ReadConsistency, ScopeId, SecurityContext, TransitionClass, generated_operation_manifests,
    operation_manifest_set_digest, parse_revocation_history_payload,
};

use crate::CompositionError;
use eliot_authority::RevocationHistoryEvidence;

/// Governor scope reused from the observation/operator precedent; no new
/// scope is introduced for revocation recording.
const GOVERNOR_SCOPE_ID: &str = "governor";
/// Ordering scope reused from the observation/operator precedent.
const GOVERNOR_ORDERING_SCOPE: &str = "scope:governor";

fn owner_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn identity_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Provider(detail.into())
}

/// Canonical digest helper for the revocation binding record.
fn canonical_digest(value: &impl serde::Serialize) -> Result<String, CompositionError> {
    let bytes = canonical_json_bytes(value).map_err(|error| {
        CompositionError::Owner(format!("cannot canonicalize revocation binding: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// Binds the generated catalogue set digest into the revocation envelope.
///
/// The digest covers the closed activated-operation table, so the envelope
/// passes the store pre-dispatch gate unchanged once the
/// `RecordAuthorityRevocation` row is activated by its owning slice.
fn catalogue_set_digest() -> Result<OperationManifestDigest, CompositionError> {
    let entries =
        generated_operation_manifests().map_err(|error| owner_refused(error.to_string()))?;
    operation_manifest_set_digest(&entries).map_err(|error| owner_refused(error.to_string()))
}

/// Builds the canonical authority-revocation envelope binding one exact
/// committed influence revocation.
///
/// The envelope reuses the exact identity types the store already keys on
/// (`operation_id`, the request metadata fence, and the idempotency key
/// from the admitted identity), so a later retry resolves through the
/// receipt route instead of re-admitting. The `RecordAuthorityRevocation`
/// parameters record the seven owner-approved revocation fields; ceilings
/// stay fixed at `RecoverySchema` / `ReversibleMutation` by construction.
/// `invalidation_reason` carries the terminal reason in its
/// `SCREAMING_SNAKE_CASE` wire spelling; `closure_revision` and
/// `affected_count` travel as decimal strings, mirroring how
/// `AppendAuditEvent` carries `expected_revision`.
#[allow(
    clippy::too_many_arguments,
    reason = "the envelope binds every recorded revocation identity explicitly; grouping them would hide a binding"
)]
pub fn authority_revocation_envelope(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    origin_ref: &str,
    closure_id: &str,
    closure_revision: u64,
    affected_digest: &str,
    affected_count: u64,
    invalidation_reason: &str,
    fence_digest: &str,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    identity
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    let fence = &identity.request.metadata.state_fence;
    if identity.request.state_fence != *fence {
        return Err(identity_refused(
            "admitted request fence does not match the request binding fence".to_owned(),
        ));
    }
    for (value, field) in [
        (origin_ref, "origin_ref"),
        (closure_id, "closure_id"),
        (affected_digest, "affected_digest"),
        (invalidation_reason, "invalidation_reason"),
        (fence_digest, "fence_digest"),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(owner_refused(format!(
                "revocation {field} is blank or contains control characters"
            )));
        }
    }
    if closure_revision == 0 {
        return Err(owner_refused(
            "revocation closure revision must be non-zero".to_owned(),
        ));
    }
    if affected_count == 0 {
        return Err(owner_refused(
            "revocation affected count must be non-zero: the origin itself is always affected"
                .to_owned(),
        ));
    }
    let manifest_digest = catalogue_set_digest()?;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("origin_ref", origin_ref.to_owned()),
        ("closure_id", closure_id.to_owned()),
        ("closure_revision", closure_revision.to_string()),
        ("affected_digest", affected_digest.to_owned()),
        ("affected_count", affected_count.to_string()),
        ("invalidation_reason", invalidation_reason.to_owned()),
        ("fence_digest", fence_digest.to_owned()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(GOVERNOR_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: canonical_digest(&(
            origin_ref,
            closure_id,
            closure_revision,
            affected_digest,
            affected_count,
            invalidation_reason,
            fence_digest,
            operation_id.as_str(),
            identity.idempotency_key.clone(),
        ))?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordAuthorityRevocation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Builds the typed `GetAuthorityRevocationHistory` named read for one
/// exact revoked origin.
///
/// The request carries the exact `origin_ref` selector and the explicit
/// `max_records` bound; scope is the Governor scope, mirroring the
/// `GetEvidencePack` scope declaration the future catalogue row follows.
/// The reply must be decoded with
/// [`decode_revocation_history_evidence`]; the request alone proves
/// nothing.
pub fn revocation_history_read_request(
    state_fence: &eliot_contracts::StateFence,
    origin_ref: &str,
    max_records: u32,
) -> Result<NamedReadRequest, CompositionError> {
    state_fence
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    if origin_ref.trim().is_empty() || origin_ref.chars().any(char::is_control) {
        return Err(owner_refused(
            "revocation history origin_ref is blank or contains control characters".to_owned(),
        ));
    }
    if max_records == 0 {
        return Err(owner_refused(
            "revocation history max_records must be a positive decimal bound".to_owned(),
        ));
    }
    if max_records > eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS {
        return Err(owner_refused(
            "revocation history max_records exceeds the advertised bound".to_owned(),
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "origin_ref".to_owned(),
        serde_json::Value::String(origin_ref.to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(max_records.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetAuthorityRevocationHistory,
        scope_id: Some(
            ScopeId::new(GOVERNOR_SCOPE_ID).map_err(|error| owner_refused(error.to_string()))?,
        ),
        consistency: ReadConsistency::Eventual,
        state_fence: state_fence.clone(),
        parameters,
    };
    request
        .validate()
        .map_err(|error| owner_refused(error.to_string()))?;
    Ok(request)
}

/// Decodes one `GetAuthorityRevocationHistory` reply into typed
/// revocation-history evidence.
///
/// The reply must name the history operation and the exact expected fence;
/// its payload must be a well-formed [`parse_revocation_history_payload`]
/// view. Every recorded row decodes to a terminal `Revoked` closure stamped
/// with the response fence: only committed revocations are recorded, so
/// unknown or partial outcomes can never appear here. Currency
/// (CURRENT vs stale/unknown) is enforced at restore by
/// [`AuthorityOwner::from_snapshot_with_revocation_history`](crate::AuthorityOwner::from_snapshot_with_revocation_history),
/// not here.
pub fn decode_revocation_history_evidence(
    response: &NamedReadResponse,
    expected_fence: &eliot_contracts::StateFence,
) -> Result<RevocationHistoryEvidence, CompositionError> {
    if response.operation != NamedReadOperation::GetAuthorityRevocationHistory {
        return Err(owner_refused(
            "revocation history response names a different operation".to_owned(),
        ));
    }
    response
        .validate()
        .map_err(|error| identity_refused(error.to_string()))?;
    if response.state_fence != *expected_fence {
        return Err(identity_refused(
            "revocation history response is not bound to the expected fence".to_owned(),
        ));
    }
    let payload = parse_revocation_history_payload(&response.payload).map_err(|error| {
        owner_refused(format!("revocation history payload is malformed: {error}"))
    })?;
    let closures = payload
        .closures
        .into_iter()
        .map(|row| InfluenceDependencyClosure {
            closure_id: row.closure_id,
            root_ref: row.root_ref,
            dependent_refs: row.dependent_refs,
            invalidation_reason: Some(row.invalidation_reason),
            current_influence: eliot_store_api::InfluenceState::Revoked,
            state_fence: response.state_fence.clone(),
            revision: row.revision,
        })
        .collect();
    Ok(RevocationHistoryEvidence {
        state_fence: response.state_fence.clone(),
        source_revision: payload.source_revision,
        closures,
    })
}

#[cfg(test)]
mod authority_revocation_tests {
    #![allow(clippy::expect_used)]
    use std::num::NonZeroU64;

    use super::*;
    use eliot_authority::{
        AuthoritySet, CapabilityGrant, EffectAuthorizer, GrantGraph, GrantId, GrantStatus,
        LogicalTime, PrincipalRef,
    };
    use eliot_contracts::{
        ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
    use eliot_store_api::{
        REVOCATION_HISTORY_PAYLOAD_VERSION, RecordedRevocation, RevocationHistoryPayload,
    };

    use crate::{AuthorityOwner, AuthorityOwnerSnapshot};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-revoke-1").expect("request id"),
            session_id: Some(SessionId::new("session-revoke-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-revoke-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-revoke-1".to_owned(),
        }
    }

    fn operation_id() -> OperationId {
        OperationId::new("op-revoke-1").expect("operation id")
    }

    fn grant_snapshot(fence: &StateFence) -> eliot_authority::GrantGraphRecoverySnapshot {
        let binding = AuthorityBinding {
            authority_id: ContractId::new("authority:test").expect("contract"),
            authority_owner: "G-01".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        };
        let origin = CapabilityGrant {
            grant_id: GrantId::new("grant:origin").expect("id"),
            parent_grant_id: None,
            authority_root_ref: "root:alpha".to_owned(),
            issuer: PrincipalRef::new("principal:root").expect("issuer"),
            holder: PrincipalRef::new("principal:child").expect("holder"),
            authority: AuthoritySet::new(
                ["read".to_owned(), "write".to_owned()],
                ["resource:a".to_owned(), "resource:b".to_owned()],
                EffectClass::ExternalEffect,
            )
            .expect("authority"),
            inherited_source_ceiling: None,
            binding: binding.clone(),
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        };
        let child = CapabilityGrant {
            grant_id: GrantId::new("grant:child").expect("id"),
            parent_grant_id: Some(GrantId::new("grant:origin").expect("parent")),
            authority_root_ref: "root:alpha".to_owned(),
            issuer: PrincipalRef::new("principal:child").expect("issuer"),
            holder: PrincipalRef::new("principal:leaf").expect("holder"),
            authority: AuthoritySet::new(
                ["read".to_owned()],
                ["resource:a".to_owned()],
                EffectClass::Read,
            )
            .expect("authority"),
            inherited_source_ceiling: None,
            binding,
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        };
        GrantGraph::from_grants([origin, child], 7)
            .expect("graph")
            .recovery_snapshot()
            .expect("snapshot")
    }

    fn owner_snapshot(fence: &StateFence) -> AuthorityOwnerSnapshot {
        let effect_authorizer = EffectAuthorizer::default().snapshot().expect("authorizer");
        AuthorityOwnerSnapshot::new(fence.clone(), grant_snapshot(fence), effect_authorizer)
            .expect("owner snapshot")
    }

    fn param(envelope: &CanonicalWriteEnvelope, name: &str) -> Option<String> {
        envelope
            .semantic_commands
            .first()
            .and_then(|command| command.parameters.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    #[test]
    fn revocation_envelope_carries_the_closed_seven_field_command() {
        let fence = fence();
        let envelope = authority_revocation_envelope(
            &identity(&fence),
            &operation_id(),
            "root:alpha",
            "revocation-686-01",
            9,
            &"a".repeat(64),
            3,
            "SOURCE_REVOKED",
            &"b".repeat(64),
        )
        .expect("envelope builds");
        assert_eq!(envelope.transition_class, TransitionClass::RecoverySchema);
        assert_eq!(
            envelope.requested_effect_ceiling,
            EffectClass::ReversibleMutation
        );
        assert_eq!(envelope.semantic_commands.len(), 1);
        assert_eq!(
            envelope.semantic_commands[0].operation,
            NamedMutationOperation::RecordAuthorityRevocation
        );
        assert_eq!(
            param(&envelope, "origin_ref").as_deref(),
            Some("root:alpha")
        );
        assert_eq!(
            param(&envelope, "closure_id").as_deref(),
            Some("revocation-686-01")
        );
        assert_eq!(param(&envelope, "closure_revision").as_deref(), Some("9"));
        assert_eq!(
            param(&envelope, "affected_digest").as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(param(&envelope, "affected_count").as_deref(), Some("3"));
        assert_eq!(
            param(&envelope, "invalidation_reason").as_deref(),
            Some("SOURCE_REVOKED")
        );
        assert_eq!(
            param(&envelope, "fence_digest").as_deref(),
            Some("b".repeat(64).as_str())
        );
        let entries = generated_operation_manifests().expect("catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest");
        assert_eq!(envelope.operation_manifest_digest, set_digest);
    }

    #[test]
    fn revocation_envelope_refuses_blank_zero_and_drifted_bindings() {
        let fence = fence();
        let identity = identity(&fence);
        let operation = operation_id();
        for (origin, closure, revision, count) in [
            ("", "revocation-686-01", 9, 3),
            ("root:alpha", "", 9, 3),
            ("root:alpha", "revocation-686-01", 0, 3),
            ("root:alpha", "revocation-686-01", 9, 0),
        ] {
            assert!(
                authority_revocation_envelope(
                    &identity,
                    &operation,
                    origin,
                    closure,
                    revision,
                    &"a".repeat(64),
                    count,
                    "SOURCE_REVOKED",
                    &"b".repeat(64),
                )
                .is_err(),
                "blank origin/closure, zero revision, or zero count must refuse"
            );
        }
        let mut drifted = identity.clone();
        drifted.request.state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            authority_revocation_envelope(
                &drifted,
                &operation,
                "root:alpha",
                "revocation-686-01",
                9,
                &"a".repeat(64),
                3,
                "SOURCE_REVOKED",
                &"b".repeat(64),
            )
            .is_err(),
            "fence drift between binding and metadata must refuse"
        );
    }

    #[test]
    fn history_read_request_carries_exact_selectors() {
        let fence = fence();
        let request = revocation_history_read_request(&fence, "root:alpha", 8).expect("request");
        assert_eq!(
            request.operation,
            NamedReadOperation::GetAuthorityRevocationHistory
        );
        assert_eq!(
            request
                .parameters
                .get("origin_ref")
                .and_then(serde_json::Value::as_str),
            Some("root:alpha")
        );
        assert_eq!(
            request
                .parameters
                .get("max_records")
                .and_then(serde_json::Value::as_str),
            Some("8")
        );
        assert!(request.scope_id.is_some());
        assert!(revocation_history_read_request(&fence, "", 8).is_err());
        assert!(revocation_history_read_request(&fence, "root:alpha", 0).is_err());
        assert!(
            revocation_history_read_request(
                &fence,
                "root:alpha",
                eliot_store_api::REVOCATION_HISTORY_MAX_RECORDS + 1
            )
            .is_err()
        );
    }

    fn history_response(fence: &StateFence) -> NamedReadResponse {
        let payload = RevocationHistoryPayload {
            version: REVOCATION_HISTORY_PAYLOAD_VERSION,
            origin_ref: "root:alpha".to_owned(),
            source_revision: 9,
            closures: vec![RecordedRevocation {
                closure_id: "revocation-686-01".to_owned(),
                root_ref: "root:alpha".to_owned(),
                dependent_refs: vec!["grant:child".to_owned(), "grant:origin".to_owned()],
                invalidation_reason: eliot_store_api::RevocationReason::SourceRevoked,
                revision: 9,
            }],
        };
        NamedReadResponse {
            operation: NamedReadOperation::GetAuthorityRevocationHistory,
            state_fence: fence.clone(),
            revision_heads: Vec::new(),
            payload: serde_json::to_value(&payload).expect("payload"),
        }
    }

    #[test]
    fn decode_history_then_restore_suppresses_origin_and_child() {
        let fence = fence();
        let evidence =
            decode_revocation_history_evidence(&history_response(&fence), &fence).expect("decode");
        assert_eq!(evidence.source_revision, 9);
        assert_eq!(evidence.closures.len(), 1);
        let snapshot = owner_snapshot(&fence);
        let outcome = AuthorityOwner::from_snapshot_with_revocation_history(
            &snapshot,
            &fence,
            Some(&evidence),
        )
        .expect("current evidence restores");
        let suppressed: Vec<&str> = outcome
            .suppressed
            .iter()
            .map(|entry| entry.grant_id.as_str())
            .collect();
        assert_eq!(suppressed, ["grant:child", "grant:origin"]);
        let restored = outcome.owner.snapshot().expect("re-emit");
        assert_eq!(
            restored.grant_graph.revoked,
            ["grant:child".to_owned(), "grant:origin".to_owned()]
        );
    }

    #[test]
    fn decode_rejects_wrong_operation_fence_and_version() {
        let fence = fence();
        let mut wrong_operation = history_response(&fence);
        wrong_operation.operation = NamedReadOperation::GetEvidencePack;
        assert!(decode_revocation_history_evidence(&wrong_operation, &fence).is_err());
        let other_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            decode_revocation_history_evidence(&history_response(&fence), &other_fence).is_err()
        );
        let mut bad_version = history_response(&fence);
        bad_version.payload["version"] = serde_json::json!(999);
        assert!(decode_revocation_history_evidence(&bad_version, &fence).is_err());
    }

    #[test]
    fn history_bound_restore_refuses_missing_and_stale_evidence() {
        let fence = fence();
        let snapshot = owner_snapshot(&fence);
        assert!(
            AuthorityOwner::from_snapshot_with_revocation_history(&snapshot, &fence, None).is_err(),
            "missing history blocks restoration"
        );
        let evidence =
            decode_revocation_history_evidence(&history_response(&fence), &fence).expect("decode");
        let other_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(2).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        );
        assert!(
            AuthorityOwner::from_snapshot_with_revocation_history(
                &snapshot,
                &other_fence,
                Some(&evidence)
            )
            .is_err(),
            "stale fence blocks restoration"
        );
    }
}
