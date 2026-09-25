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
//! The store catalogue now admits both operations. The envelope binds the
//! generated catalogue set digest; the store handler preserves the typed
//! record in the durable recovery-owner ledger, and the history read serves
//! that ledger to the production owner-feed restore gate. The
//! `scope:governor` ordering-head expectation mirrors the operator/recovery
//! precedent (the store enforces the live sequence).

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_security_contracts::RevocationReason;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, InfluenceDependencyClosure,
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationManifestDigest, OrderingHeadExpectation, OrderingScopeId,
    REVOCATION_HISTORY_ROOT_SELECTOR, ReadConsistency, RevocationHistoryRoot, ScopeId,
    SecurityContext, TransitionClass, affected_reference_digest, generated_operation_manifests,
    operation_manifest_set_digest, parse_revocation_history_payload, revocation_fence_digest,
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

/// Authenticated, exact ingress for one authority-revocation record.
///
/// The identity and operation id are supplied by the admitted front-door
/// ingress; this type never manufactures either one.  The affected vector,
/// digest/count, state-fence digest, independent history revision, per-root
/// revision, and prior history-root digest are all checked before a canonical
/// transition is built.  The prior root digest is the Store CAS witness: a
/// caller cannot append a row to a stale or forked history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationIngress {
    /// Identity admitted by the authenticated Kernel frame.
    pub identity: RequestIdentity,
    /// Stable canonical operation identity.
    pub operation_id: OperationId,
    /// Revoked origin.
    pub origin_ref: String,
    /// Stable closure identity.
    pub closure_id: String,
    /// Authority/graph revision carried by the closure.
    pub closure_revision: u64,
    /// Exact affected-reference denominator, including the origin.
    pub affected_refs: Vec<String>,
    /// Canonical digest of `affected_refs`.
    pub affected_digest: String,
    /// Exact affected-reference count.
    pub affected_count: u64,
    /// Closed terminal invalidation reason.
    pub invalidation_reason: RevocationReason,
    /// Canonical digest of the admitted state fence.
    pub fence_digest: String,
    /// Independent Store history revision to append.
    pub history_revision: u64,
    /// Independent per-origin root revision to append.
    pub root_revision: u64,
    /// Current complete Store history-root digest observed by ingress.
    pub history_root_digest: String,
    /// Current canonical ordering-head sequence observed by ingress.
    pub expected_ordering_sequence: u64,
}

impl AuthorityRevocationIngress {
    /// Validates the complete authenticated ingress without touching a Store.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.identity
            .validate()
            .map_err(|error| identity_refused(error.to_string()))?;
        if self.identity.request.state_fence != self.identity.request.metadata.state_fence {
            return Err(identity_refused(
                "authenticated request fence does not match its request metadata".to_owned(),
            ));
        }
        if self.affected_refs.is_empty()
            || self.affected_refs.windows(2).any(|pair| pair[0] >= pair[1])
            || !self
                .affected_refs
                .iter()
                .any(|value| value == &self.origin_ref)
        {
            return Err(owner_refused(
                "revocation affected references must be sorted, unique, and include the origin"
                    .to_owned(),
            ));
        }
        if self.affected_count != self.affected_refs.len() as u64 {
            return Err(owner_refused(
                "revocation affected count does not match the exact reference vector".to_owned(),
            ));
        }
        if affected_reference_digest(&self.affected_refs)
            .map_err(|error| owner_refused(error.to_string()))?
            != self.affected_digest
        {
            return Err(owner_refused(
                "revocation affected digest does not match the exact reference vector".to_owned(),
            ));
        }
        for (value, field) in [
            (&self.origin_ref, "origin_ref"),
            (&self.closure_id, "closure_id"),
            (&self.fence_digest, "fence_digest"),
            (&self.affected_digest, "affected_digest"),
            (&self.history_root_digest, "history_root_digest"),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(owner_refused(format!(
                    "revocation {field} is blank or contains controls"
                )));
            }
        }
        if self.origin_ref == REVOCATION_HISTORY_ROOT_SELECTOR {
            return Err(owner_refused(
                "the Store history root selector is reserved and cannot be a semantic origin"
                    .to_owned(),
            ));
        }
        if self.closure_revision == 0
            || self.history_revision == 0
            || self.root_revision == 0
            || self.expected_ordering_sequence == 0
        {
            return Err(owner_refused(
                "revocation revisions must all be non-zero".to_owned(),
            ));
        }
        let fence = &self.identity.request.state_fence;
        if revocation_fence_digest(fence).map_err(|error| owner_refused(error.to_string()))?
            != self.fence_digest
        {
            return Err(identity_refused(
                "revocation fence digest does not match the authenticated identity".to_owned(),
            ));
        }
        if !is_digest(&self.affected_digest) || !is_digest(&self.history_root_digest) {
            return Err(owner_refused(
                "revocation digest fields must be lowercase SHA-256 values".to_owned(),
            ));
        }
        Ok(())
    }

    fn parameter_reason(&self) -> Result<String, CompositionError> {
        serde_json::to_value(self.invalidation_reason)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| owner_refused("revocation reason is not encodable".to_owned()))
    }
}

/// Builds the canonical authority-revocation envelope from one authenticated
/// ingress.  The operation id, request identity, exact affected denominator,
/// fence, and independent history CAS witness all cross this single boundary.
pub fn authority_revocation_envelope(
    ingress: &AuthorityRevocationIngress,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    ingress.validate()?;
    let identity = &ingress.identity;
    let operation_id = &ingress.operation_id;
    let fence = &identity.request.metadata.state_fence;
    let reason = ingress.parameter_reason()?;
    let manifest_digest = catalogue_set_digest()?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "origin_ref".to_owned(),
        serde_json::Value::String(ingress.origin_ref.clone()),
    );
    parameters.insert(
        "closure_id".to_owned(),
        serde_json::Value::String(ingress.clone().closure_id),
    );
    parameters.insert(
        "closure_revision".to_owned(),
        serde_json::Value::String(ingress.closure_revision.to_string()),
    );
    parameters.insert(
        "affected_refs".to_owned(),
        serde_json::to_value(ingress.affected_refs.clone())
            .map_err(|error| owner_refused(error.to_string()))?,
    );
    parameters.insert(
        "affected_digest".to_owned(),
        serde_json::Value::String(ingress.affected_digest.clone()),
    );
    parameters.insert(
        "affected_count".to_owned(),
        serde_json::Value::String(ingress.affected_count.to_string()),
    );
    parameters.insert(
        "invalidation_reason".to_owned(),
        serde_json::Value::String(reason),
    );
    parameters.insert(
        "fence_digest".to_owned(),
        serde_json::Value::String(ingress.fence_digest.clone()),
    );
    parameters.insert(
        "history_revision".to_owned(),
        serde_json::Value::String(ingress.history_revision.to_string()),
    );
    parameters.insert(
        "root_revision".to_owned(),
        serde_json::Value::String(ingress.root_revision.to_string()),
    );
    parameters.insert(
        "history_root_digest".to_owned(),
        serde_json::Value::String(ingress.history_root_digest.clone()),
    );
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
            &ingress.origin_ref,
            &ingress.closure_id,
            ingress.closure_revision,
            &ingress.affected_refs,
            &ingress.affected_digest,
            ingress.affected_count,
            ingress.invalidation_reason,
            &ingress.fence_digest,
            ingress.history_revision,
            ingress.root_revision,
            &ingress.history_root_digest,
            operation_id.as_str(),
            identity.idempotency_key.as_str(),
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
            expected_sequence: ingress.expected_ordering_sequence,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
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
pub fn decode_revocation_history_with_root(
    response: &NamedReadResponse,
    expected_fence: &eliot_contracts::StateFence,
) -> Result<(RevocationHistoryRoot, RevocationHistoryEvidence), CompositionError> {
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
    payload
        .validate_for_fence(&response.state_fence)
        .map_err(|error| {
            owner_refused(format!(
                "revocation history payload fence/root is invalid: {error}"
            ))
        })?;
    let history_root = payload.history_root.clone();
    let closures = payload
        .closures
        .into_iter()
        .map(|row| InfluenceDependencyClosure {
            closure_id: row.closure_id,
            root_ref: row.root_ref,
            dependent_refs: row.dependent_refs,
            invalidation_reason: Some(row.invalidation_reason),
            current_influence: eliot_store_api::InfluenceState::Revoked,
            state_fence: row.state_fence,
            revision: row.revision,
        })
        .collect();
    Ok((
        history_root,
        RevocationHistoryEvidence {
            state_fence: response.state_fence.clone(),
            source_revision: payload.source_revision,
            closures,
        },
    ))
}

/// Decodes one `GetAuthorityRevocationHistory` reply into typed
/// revocation-history evidence.
pub fn decode_revocation_history_evidence(
    response: &NamedReadResponse,
    expected_fence: &eliot_contracts::StateFence,
) -> Result<RevocationHistoryEvidence, CompositionError> {
    decode_revocation_history_with_root(response, expected_fence).map(|(_, history)| history)
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
        RevocationHistoryRoot, advance_revocation_history_digest, recorded_revocation_digest,
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

    fn ingress_for(
        identity: &RequestIdentity,
        operation_id: &OperationId,
        origin_ref: &str,
        closure_id: &str,
        closure_revision: u64,
        affected_refs: Vec<String>,
        invalidation_reason: RevocationReason,
        history_revision: u64,
        root_revision: u64,
    ) -> AuthorityRevocationIngress {
        let fence = &identity.request.state_fence;
        let affected_digest = affected_reference_digest(&affected_refs).expect("affected digest");
        let fence_digest = revocation_fence_digest(fence).expect("fence digest");
        let affected_count = affected_refs.len() as u64;
        AuthorityRevocationIngress {
            identity: identity.clone(),
            operation_id: operation_id.clone(),
            origin_ref: origin_ref.to_owned(),
            closure_id: closure_id.to_owned(),
            closure_revision,
            affected_refs,
            affected_digest,
            affected_count,
            invalidation_reason,
            fence_digest,
            history_revision,
            root_revision,
            history_root_digest: "c".repeat(64),
            expected_ordering_sequence: 1,
        }
    }

    #[test]
    fn revocation_envelope_carries_the_closed_ingress_fields() {
        let fence = fence();
        let identity = identity(&fence);
        let operation = operation_id();
        let affected_refs = vec![
            "grant:child".to_owned(),
            "grant:origin".to_owned(),
            "root:alpha".to_owned(),
        ];
        let mut ingress = ingress_for(
            &identity,
            &operation,
            "root:alpha",
            "revocation-686-01",
            9,
            affected_refs,
            RevocationReason::SourceRevoked,
            2,
            1,
        );
        ingress.affected_count = 3;
        ingress.history_root_digest = "c".repeat(64);
        let envelope = authority_revocation_envelope(&ingress).expect("envelope builds");
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
            Some(ingress.affected_digest.as_str())
        );
        assert_eq!(param(&envelope, "affected_count").as_deref(), Some("3"));
        assert_eq!(
            param(&envelope, "invalidation_reason").as_deref(),
            Some("SOURCE_REVOKED")
        );
        assert_eq!(
            param(&envelope, "fence_digest").as_deref(),
            Some(ingress.fence_digest.as_str())
        );
        assert_eq!(param(&envelope, "history_revision").as_deref(), Some("2"));
        assert_eq!(param(&envelope, "root_revision").as_deref(), Some("1"));
        let entries = generated_operation_manifests().expect("catalogue generates");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest");
        assert_eq!(envelope.operation_manifest_digest, set_digest);
    }

    #[test]
    fn revocation_envelope_refuses_blank_zero_and_drifted_bindings() {
        let fence = fence();
        let identity = identity(&fence);
        let operation = operation_id();
        let affected_refs = vec!["grant:child".to_owned(), "root:alpha".to_owned()];
        for (origin, closure, revision, count) in [
            ("", "revocation-686-01", 9_u64, 2_u64),
            ("root:alpha", "", 9, 2),
            ("root:alpha", "revocation-686-01", 0, 2),
            ("root:alpha", "revocation-686-01", 9, 0),
        ] {
            let mut ingress = ingress_for(
                &identity,
                &operation,
                origin,
                closure,
                revision,
                affected_refs.clone(),
                RevocationReason::SourceRevoked,
                2,
                1,
            );
            ingress.affected_count = count;
            assert!(
                authority_revocation_envelope(&ingress).is_err(),
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
        let ingress = ingress_for(
            &drifted,
            &operation,
            "root:alpha",
            "revocation-686-01",
            9,
            affected_refs,
            RevocationReason::SourceRevoked,
            2,
            1,
        );
        assert!(
            authority_revocation_envelope(&ingress).is_err(),
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
        let dependent_refs = vec!["grant:child".to_owned(), "grant:origin".to_owned()];
        let affected_digest = affected_reference_digest(&dependent_refs).expect("affected digest");
        let record = RecordedRevocation {
            closure_id: "revocation-686-01".to_owned(),
            root_ref: "root:alpha".to_owned(),
            dependent_refs: dependent_refs.clone(),
            affected_count: dependent_refs.len() as u64,
            affected_digest,
            invalidation_reason: RevocationReason::SourceRevoked,
            state_fence: fence.clone(),
            fence_digest: revocation_fence_digest(fence).expect("fence digest"),
            revision: 9,
            history_revision: 2,
            root_revision: 1,
        };
        let mut history_root = RevocationHistoryRoot::genesis(fence.clone()).expect("genesis root");
        history_root.history_revision = 2;
        history_root.record_count = 1;
        history_root.root_refs = vec!["root:alpha".to_owned()];
        history_root
            .root_revisions
            .insert("root:alpha".to_owned(), 1);
        history_root.ledger_digest = advance_revocation_history_digest(
            &history_root.ledger_digest,
            &recorded_revocation_digest(&record).expect("record digest"),
        )
        .expect("advance root");
        history_root
            .validate_against_records(std::slice::from_ref(&record))
            .expect("root validates");
        let payload = RevocationHistoryPayload {
            version: REVOCATION_HISTORY_PAYLOAD_VERSION,
            origin_ref: "root:alpha".to_owned(),
            source_revision: history_root.history_revision,
            history_root,
            closures: vec![record],
        };
        payload
            .validate_for_fence(fence)
            .expect("history payload validates");
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
        assert_eq!(evidence.source_revision, 2);
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
