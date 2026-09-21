//! Canonical failure-history port adapter over the existing canonical
//! Store (issue #1779).
//!
//! This module is the Store-owned adapter Beauvoir's
//! [`UserAutomationRuntimeComposition`](super::UserAutomationRuntimeComposition)
//! binds as its `H` port. It translates one validated
//! [`UserAutomationFailureRecord`] into exactly one admitted
//! `ApplyUserAutomationState` failure leg through the existing
//! [`CanonicalStoreClient`] path, reads back the canonical failure row,
//! and projects the typed [`UserAutomationFailureHistory`]. It owns no
//! revisions, scheduler, notification state, or dedup policy:
//! durability, row convergence, and receipts stay with the canonical
//! Store; failure content validity stays Kernel-owned; response
//! validation stays with the execution owner.
//!
//! Row identity is the canonical failure key
//! `(automation_id, revision, fingerprint)`; repeats of one failure
//! class converge on the existing row while the last-failure pointer
//! moves to it. The history reference is deterministic over the row
//! key, so replays and converged repeats resolve the identical
//! reference. The occurrence in the response is always the presented
//! occurrence; the row retains the first occurrence as history context.

use eliot_store_api::{
    AutomationFailureDocument, CanonicalStoreClient, OrderingScopeId, PreparedTransition, ScopeId,
    SecurityContext, StoreError, TransitionClass, USER_AUTOMATION_SCOPE, WriteReceiptStatus,
    automation_failure_history_ref, automation_failure_params, automation_mutation_request,
    automation_read_request, canonical_json_bytes, generated_operation_manifests,
    operation_manifest_set_digest, sha256_hex,
};
use serde_json::Value;

use super::user_automation_execution::{
    UserAutomationFailureHistory, UserAutomationFailureHistoryPort, UserAutomationFailureRecord,
    UserAutomationRuntimeError,
};

/// Canonical Store adapter implementing the failure-history port.
///
/// Generic over any [`CanonicalStoreClient`] so production backends and
/// the reference contour share the exact translation path.
#[derive(Clone, Debug)]
pub struct StoreUserAutomationFailureHistory<C> {
    client: C,
}

impl<C> StoreUserAutomationFailureHistory<C> {
    /// Binds the port to the composed canonical Store client.
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

impl<C: CanonicalStoreClient> StoreUserAutomationFailureHistory<C> {
    /// Reads the canonical failure row and projects the typed history.
    async fn read_history(
        &self,
        request: &UserAutomationFailureRecord,
        occurrence_id: &str,
    ) -> Result<UserAutomationFailureHistory, UserAutomationRuntimeError> {
        let query = automation_read_request(
            eliot_store_api::AUTOMATION_QUERY_FAILURE.to_owned(),
            Some(request.revision.automation_id.clone()),
            false,
            1,
            request.context.state_fence.clone(),
        )
        .map_err(map_store_error)?;
        let response = self
            .client
            .execute_named(query)
            .await
            .map_err(map_store_error)?;
        history_from_row(&response.payload, request, occurrence_id)
    }
}

/// Maps a closed store error onto the port error set without inventing
/// authority: identity collisions stay conflicts, unavailability stays
/// unavailable, unknown outcomes stay unknown, and every
/// request/content/binding fault is a rejection.
fn map_store_error(error: StoreError) -> UserAutomationRuntimeError {
    match error {
        StoreError::IdentityConflict => UserAutomationRuntimeError::IdentityConflict,
        StoreError::Unavailable => {
            UserAutomationRuntimeError::Unavailable("canonical store unavailable".to_owned())
        }
        StoreError::MissingReceiptEnvelope => UserAutomationRuntimeError::UnknownOutcome(
            "receipt envelope is missing; write outcome is unknown".to_owned(),
        ),
        other => UserAutomationRuntimeError::Rejected(other.to_string()),
    }
}

/// Builds the canonical failure document from the owner-admitted
/// projection. Fingerprint and dedup key travel verbatim; the typed
/// reason travels as its canonical JSON wire value.
fn failure_document(
    request: &UserAutomationFailureRecord,
) -> Result<AutomationFailureDocument, StoreError> {
    let reason_bytes = canonical_json_bytes(&request.failure.reason)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let reason = String::from_utf8(reason_bytes)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(AutomationFailureDocument {
        fingerprint: request.failure.failure_fingerprint.clone(),
        reason,
        notification_dedup_key: request.failure.notification.canonical.dedup_key.clone(),
    })
}

/// Builds the one admitted failure transition for a validated record.
///
/// The transition binds the parent operation identity verbatim: the
/// record identity is the execution-request identity sealed upstream
/// over the parent request bytes, and the failure leg is that
/// operation's effect. Replay resolves by (operation, idempotency,
/// hash) triple; a divergent triple conflicts before any write. The
/// builder is deterministic over the record, so rebuilds verify
/// byte-identical.
pub fn build_failure_transition(
    request: &UserAutomationFailureRecord,
) -> Result<(PreparedTransition, eliot_store_api::OperationManifestDigest), StoreError> {
    let document = failure_document(request)?;
    let occurrence_id = request
        .invocation
        .occurrence_identity()
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let failure_json = serde_json::to_string(&document)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    eliot_store_api::parse_automation_failure_document(&failure_json)?;
    let parameters = automation_failure_params(
        request.revision.automation_id.clone(),
        request.revision.revision.clone(),
        occurrence_id,
        failure_json,
    );
    let operation = automation_mutation_request(parameters);
    let manifest_digest = operation_manifest_set_digest(&generated_operation_manifests()?)?;
    // The admission digest binds the admitted record with the
    // identity-hash field cleared: the hash itself is bound separately
    // by the transition view, so clearing keeps admission deterministic
    // across sealing (which fills the hash after building) and dispatch
    // (which rebuilds from the sealed request). A caller-supplied
    // admission digest is never trusted.
    let mut admission_view = request.clone();
    admission_view.identity.canonical_request_hash = String::new();
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&admission_view)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    let automation_id = request.revision.automation_id.clone();
    let transition = PreparedTransition {
        identity: request.identity.clone(),
        state_fence: request.context.state_fence.clone(),
        scope_id: ScopeId::new(USER_AUTOMATION_SCOPE)?,
        task_id: request.context.task_id.clone().map(|task| task.to_string()),
        ordering_scopes: vec![OrderingScopeId::new(format!("automation:{automation_id}"))?],
        transition_class: TransitionClass::UserAutomation,
        requested_effect_ceiling: TransitionClass::UserAutomation.maximum_effect(),
        admission_contract_set_digest: admission_digest,
        operation_manifest_digest: manifest_digest.clone(),
        named_operations: vec![operation],
        event_projection_relation_intents: eliot_store_api::EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
    };
    transition.validate()?;
    Ok((transition, manifest_digest))
}

/// Reads the canonical failure row for one automation and projects the
/// typed history response. Fails closed when no row exists, the row
/// names another failure class or revision, or the row carries no
/// source operation. Deduplication is decided by first-writer
/// provenance: a row created by another operation means this record
/// converged.
fn history_from_row(
    payload: &Value,
    request: &UserAutomationFailureRecord,
    occurrence_id: &str,
) -> Result<UserAutomationFailureHistory, UserAutomationRuntimeError> {
    let rejected = |reason: &'static str| UserAutomationRuntimeError::Rejected(reason.to_owned());
    let row = payload
        .get("failure")
        .ok_or_else(|| rejected("failure row is missing from the canonical read"))?;
    if row.is_null() {
        return Err(rejected("no failure row is recorded for this automation"));
    }
    let text_of = |name: &str| -> Result<String, UserAutomationRuntimeError> {
        row.get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| rejected("failure row is missing a text field"))
    };
    let fingerprint = text_of("fingerprint")?;
    let revision = text_of("revision")?;
    let automation_id = text_of("automation_id")?;
    let source_operation_id = text_of("source_operation_id")?;
    if fingerprint != request.failure.failure_fingerprint
        || revision != request.revision.revision
        || automation_id != request.revision.automation_id
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    Ok(UserAutomationFailureHistory {
        operation_id: request.identity.operation_id.clone(),
        idempotency_key: request.identity.idempotency_key.clone(),
        canonical_request_hash: request.identity.canonical_request_hash.clone(),
        state_fence: request.context.state_fence.clone(),
        automation_id: request.revision.automation_id.clone(),
        automation_revision: request.revision.revision.clone(),
        failure_fingerprint: fingerprint.clone(),
        occurrence_id: occurrence_id.to_owned(),
        history_ref: automation_failure_history_ref(&automation_id, &revision, &fingerprint),
        dedup_key: request.failure.notification.canonical.dedup_key.clone(),
        deduplicated: source_operation_id != request.identity.operation_id.to_string(),
    })
}

#[allow(async_fn_in_trait)]
impl<C: CanonicalStoreClient> UserAutomationFailureHistoryPort
    for StoreUserAutomationFailureHistory<C>
{
    async fn record_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationFailureHistory, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let occurrence_id = request
            .invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        // Sealed identities resolve their receipt without remutation; a
        // divergent seal conflicts before any write.
        if let Some(existing) = self
            .client
            .receipt(request.identity.operation_id.clone())
            .await
            .map_err(map_store_error)?
        {
            if existing.canonical_request_hash != request.identity.canonical_request_hash
                || existing.idempotency_key != request.identity.idempotency_key
            {
                return Err(UserAutomationRuntimeError::IdentityConflict);
            }
            return self.read_history(&request, &occurrence_id).await;
        }
        let (transition, _) = build_failure_transition(&request).map_err(map_store_error)?;
        // The record must arrive sealed over the exact failure
        // transition: the sealed upstream identity alone cannot prove
        // these bytes. An unsealed or divergent record fails here
        // before any write; resuming re-issues the sealed record.
        let check = eliot_store_api::CanonicalRequestView::from_apply(
            &request.context,
            &transition,
            &[],
            &[],
        );
        eliot_store_api::verify_canonical_request_hash(
            &check,
            &request.identity.canonical_request_hash,
        )
        .map_err(|_| {
            UserAutomationRuntimeError::Rejected("failure transition digest mismatch".to_owned())
        })?;
        let receipt = self
            .client
            .apply_prepared(&request.context, transition, Vec::new(), Vec::new())
            .await
            .map_err(map_store_error)?;
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(UserAutomationRuntimeError::UnknownOutcome(format!(
                "failure write ended with status {:?}; effect is unknown",
                receipt.status
            )));
        }
        receipt.validate().map_err(map_store_error)?;
        if receipt.state_fence != request.context.state_fence {
            return Err(UserAutomationRuntimeError::Rejected(
                "failure receipt fence mismatch".to_owned(),
            ));
        }
        self.read_history(&request, &occurrence_id).await
    }
}
