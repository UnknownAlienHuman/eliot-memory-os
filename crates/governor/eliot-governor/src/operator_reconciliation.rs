//! Private Governor-owned reconciliation of operator command admissions.
//!
//! The single [`GovernorOperatorReconciliation`] addresses one serialized
//! Governor owner pair (the [`CanonicalAdmissionOwner`] plus the retained
//! neutral [`KernelTransitionPort`]). It never creates an independent ledger,
//! map, or canonical owner per caller: the durable operator identity lives in
//! Kernel ORS behind the receipt route, and persistence flows only through the
//! existing canonical path.
//!
//! Validation order (fail-closed):
//! - admitted [`RequestIdentity`] shape, composition readiness, and exact
//!   fence agreement: the request binding fence, the envelope metadata fence,
//!   and the canonical owner fence must coincide;
//! - the admitted session must equal the session bound in the request
//!   metadata, mirroring the sync adapter check, so a substituted session
//!   fails closed here;
//! - the operator binding fields (session, access digest, action digest,
//!   expected revision) must be non-blank with a non-zero revision; byte-shape
//!   validation stays with the surface owner and is not redefined here.
//!
//! Canonical persistence is one commit through
//! [`CanonicalAdmissionOwner::commit`]:
//! - `AppendAuditEvent` / `CaptureCandidate` / `Candidate` carrying
//!   `{operation_id, idempotency_key, session_id, access_digest,
//!   action_digest, expected_revision}` over the Governor scope with the
//!   production adapter manifest digest (reconstructed exactly like the
//!   observation/skill precedent; no new manifest, scope, or authority
//!   vocabulary is introduced).
//!
//! Only the Kernel-issued [`WriteReceipt`](eliot_store_api::WriteReceipt) is
//! returned, exactly as issued so the caller observes the true store verdict.
//! A lost acknowledgement reconciles the same operation's receipt through the
//! neutral port (the T1.2 exact-receipt pattern), never a second execution: a
//! proactive same-operation receipt check precedes any commit, an `Unknown`
//! commit outcome falls back to the same receipt lookup, and the store-level
//! `(operation_id, canonical_request_hash)` identity makes a retried commit
//! with identical bytes idempotent while the same operation with different
//! bytes fails closed. The conflict rule reuses
//! `reconcile_existing_receipt` exactly: same identity returns the stored
//! receipt, changed bytes under the same id are an identity conflict that
//! mutates nothing.
//!
//! Failure mapping reuses the existing [`CompositionError`] variants (no new
//! variant is introduced so the closed matches elsewhere in this crate keep
//! compiling): request-identity, fence, session, and operation-identity
//! mismatches are [`CompositionError::Provider`]; every other deterministic
//! admission refusal — blank binding fields, malformed store receipt — is
//! [`CompositionError::Owner`]. Detail strings name the refused property; they
//! are diagnostics, never control flow.
//!
//! Honest gaps: the `scope:governor` ordering-head expectation mirrors the
//! observation/skill precedent (the store enforces the live sequence); the
//! sync candidate adapter keeps its volatile fast path and resolves durable
//! identity through this borrow after recovery.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{OperationId, SessionId, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, ScopeId, SecurityContext, TransitionClass, WriteReceipt,
};

use crate::{
    CanonicalAdmissionOwner, CompositionError, CompositionReadiness, KernelPortError,
    KernelTransitionPort,
};

/// Production adapter manifest name from the Surreal adapter. Reuses the exact
/// observation/skill precedent value; no new adapter identity is introduced.
const PRODUCTION_MANIFEST_NAME: &str = "eliot.storage.store-surreal-adapter";

/// Governor-owned operator-command reconciliation over one serialized owner
/// pair plus the retained neutral Kernel port.
pub struct GovernorOperatorReconciliation<'a, P: ?Sized> {
    canonical: &'a CanonicalAdmissionOwner,
    kernel: &'a P,
    readiness: CompositionReadiness,
}

impl<'a, P: ?Sized> GovernorOperatorReconciliation<'a, P> {
    /// Borrows the single Governor owner pair. No per-caller ledger is
    /// created; the readiness value is exact for the returned borrow because
    /// the composition can only leave `Ready` through `&mut` methods excluded
    /// by this borrow.
    pub(crate) fn new(
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
        readiness: CompositionReadiness,
    ) -> Self {
        Self {
            canonical,
            kernel,
            readiness,
        }
    }
}

/// Reconstructs the production adapter manifest digest.
///
/// The shape mirrors `default_manifest` exactly like the observation/skill
/// precedent (same adapter name, contract version, admitted transition
/// classes, reversible-mutation ceiling, and byte/timeout bounds) so the
/// digest equals the digest enforced by the store adapter.
fn production_manifest_digest() -> Result<OperationManifestDigest, CompositionError> {
    let manifest = NamedOperationManifest::new(
        PRODUCTION_MANIFEST_NAME,
        CONTRACT_VERSION,
        vec![
            TransitionClass::CaptureCandidate,
            TransitionClass::Epistemic,
            TransitionClass::TaskControl,
            TransitionClass::LifecyclePolicy,
            TransitionClass::RecoverySchema,
        ],
        EffectClass::ReversibleMutation,
        1024 * 1024,
        1024 * 1024,
        30_000,
    )
    .map_err(|error| CompositionError::Owner(error.to_string()))?;
    Ok(manifest.digest)
}

/// Canonical digest helper for the operator binding record.
fn canonical_digest(value: &impl serde::Serialize) -> Result<String, CompositionError> {
    let bytes = canonical_json_bytes(value).map_err(|error| {
        CompositionError::Owner(format!("cannot canonicalize operator binding: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

fn owner_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn identity_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Provider(detail.into())
}

/// Builds the canonical operator envelope binding one exact admission.
///
/// The envelope reuses the exact identity types the store already keys on
/// (`operation_id`, the request metadata fence, and the idempotency key from
/// the admitted identity), so Kernel ORS actually stores the operation and a
/// later retry resolves through `kernel.receipt` instead of re-admitting. The
/// `AppendAuditEvent` parameters record the receipt-bound operator fields;
/// ceilings stay fixed at candidate-only by construction.
pub fn operator_command_envelope(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    session_id: &str,
    access_digest: &str,
    action_digest: &str,
    expected_revision: u64,
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
    let identity_session = identity
        .request
        .metadata
        .session_id
        .as_ref()
        .map(SessionId::as_str)
        .unwrap_or_default();
    if identity_session != session_id {
        return Err(identity_refused(
            "operator session does not match the admitted request session".to_owned(),
        ));
    }
    if session_id.trim().is_empty() || session_id.chars().any(char::is_control) {
        return Err(owner_refused(
            "operator session binding is blank or contains control characters".to_owned(),
        ));
    }
    if access_digest.trim().is_empty() || action_digest.trim().is_empty() {
        return Err(owner_refused(
            "operator binding digests must not be blank".to_owned(),
        ));
    }
    if expected_revision == 0 {
        return Err(owner_refused(
            "operator expected revision must be non-zero".to_owned(),
        ));
    }
    let manifest_digest = production_manifest_digest()?;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("operation_id", operation_id.as_str().to_owned()),
        ("idempotency_key", identity.idempotency_key.clone()),
        ("session_id", session_id.to_owned()),
        ("access_digest", access_digest.to_owned()),
        ("action_digest", action_digest.to_owned()),
        ("expected_revision", expected_revision.to_string()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        // Reuses the Governor scope vocabulary from the observation/skill
        // precedent; no new scope is introduced.
        scope_id: ScopeId::new("governor").map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: canonical_digest(&(
            session_id,
            access_digest,
            action_digest,
            expected_revision,
            operation_id.as_str(),
            identity.idempotency_key.clone(),
        ))?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::AppendAuditEvent,
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
            scope: OrderingScopeId::new("scope:governor")
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Validates that a receipt is well-formed and bound to the expected
/// canonical identity. The canonical request hash comparison is what makes a
/// same-operation retry return the identical receipt instead of executing a
/// second transition.
fn check_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    identity: &RequestIdentity,
    expected_hash: &str,
    expected_class: TransitionClass,
    expected_manifest: &OperationManifestDigest,
) -> Result<(), CompositionError> {
    receipt
        .validate()
        .map_err(|error| owner_refused(format!("canonical receipt is malformed: {error}")))?;
    if receipt.operation_id != *operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != expected_hash
        || receipt.state_fence != identity.request.metadata.state_fence
    {
        return Err(identity_refused(
            "canonical receipt is not bound to the admitted operation identity".to_owned(),
        ));
    }
    if receipt.transition_class != expected_class
        || receipt.operation_manifest_digest != *expected_manifest
    {
        return Err(owner_refused(
            "canonical receipt does not match the admitted transition".to_owned(),
        ));
    }
    Ok(())
}

impl<P: KernelTransitionPort + ?Sized> GovernorOperatorReconciliation<'_, P> {
    /// Validates readiness, request identity shape, and exact fence agreement
    /// against the canonical owner.
    fn validate_identity_fence(&self, identity: &RequestIdentity) -> Result<(), CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        identity
            .validate()
            .map_err(|error| identity_refused(error.to_string()))?;
        let fence = &identity.request.metadata.state_fence;
        if identity.request.state_fence != *fence {
            return Err(identity_refused(
                "admitted request fence does not match the request binding fence".to_owned(),
            ));
        }
        if self.canonical.state_fence() != fence {
            return Err(identity_refused(
                "admitted request fence does not match the active canonical fence".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the already-committed receipt for an identical retry, or fails
    /// closed when the same operation carries different bytes. This is the
    /// `reconcile_existing_receipt` rule reused exactly: same identity returns
    /// the stored receipt, changed bytes under the same id conflict without
    /// mutating anything.
    async fn reconcile_existing_receipt(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        expected_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<Option<WriteReceipt>, CompositionError> {
        if let Some(receipt) = self.kernel.receipt(operation_id.clone()).await? {
            if receipt.idempotency_key == identity.idempotency_key
                && receipt.canonical_request_hash == expected_hash
            {
                check_receipt(
                    &receipt,
                    operation_id,
                    identity,
                    expected_hash,
                    TransitionClass::CaptureCandidate,
                    manifest_digest,
                )?;
                return Ok(Some(receipt));
            }
            return Err(identity_refused(format!(
                "operation {operation_id} is already committed with different canonical bytes"
            )));
        }
        Ok(None)
    }

    /// Commits the operator leg, reconciling an unknown outcome through the
    /// neutral receipt route instead of a second execution.
    async fn commit_operator_leg(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        envelope: CanonicalWriteEnvelope,
        expected_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<WriteReceipt, CompositionError> {
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                match self.kernel.receipt(operation_id.clone()).await? {
                    Some(receipt) => receipt,
                    None => {
                        return Err(CompositionError::Kernel(KernelPortError::Unknown(
                            "operator commit outcome is unknown and no receipt reconciled"
                                .to_owned(),
                        )));
                    }
                }
            }
            Err(other) => return Err(other),
        };
        check_receipt(
            &receipt,
            operation_id,
            identity,
            expected_hash,
            TransitionClass::CaptureCandidate,
            manifest_digest,
        )?;
        Ok(receipt)
    }

    /// Admits one operator command through the canonical path and returns only
    /// the exact issued receipt.
    ///
    /// The caller supplies the envelope built by
    /// [`operator_command_envelope`] for the exact receipt-bound operator
    /// fields; the envelope operation must equal the admitted operation id. A
    /// proactive same-operation receipt check precedes any commit, and an
    /// `Unknown` commit outcome falls back to the same receipt lookup, so a
    /// newly created board resolves the original operation identity instead
    /// of re-admitting it.
    pub async fn admit_operator_command(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        envelope: CanonicalWriteEnvelope,
    ) -> Result<WriteReceipt, CompositionError> {
        self.validate_identity_fence(identity)?;
        if envelope.operation_id != *operation_id {
            return Err(identity_refused(
                "operator envelope operation does not match the admitted operation identity"
                    .to_owned(),
            ));
        }
        let manifest_digest = production_manifest_digest()?;
        let expected_hash = envelope
            .canonical_request_hash()
            .map_err(CompositionError::Canonical)?;
        if let Some(receipt) = self
            .reconcile_existing_receipt(identity, operation_id, &expected_hash, &manifest_digest)
            .await?
        {
            return Ok(receipt);
        }
        let receipt = self
            .commit_operator_leg(
                identity,
                operation_id,
                envelope,
                &expected_hash,
                &manifest_digest,
            )
            .await?;
        Ok(receipt)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        CommitId, OrderingHeadExpectation, PreparedTransition, Resubmission,
        RevisionHeadExpectation, ScopeRevisionView, StoreHealth, WriteReceiptStatus,
        issue_store_receipt_envelope, validate_store_receipt_envelope,
    };

    use crate::{CanonicalAdmissionSnapshot, KernelPortFuture};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    /// Test Kernel measuring exact executions. Mirrors the observation test
    /// harness: the same binding/fence/idempotency checks, the same real
    /// receipt-envelope issuance, and idempotent replay of identical bytes
    /// with a conflict on changed bytes. `lose_next_acknowledgement` stages
    /// one commit that executes and stores the receipt but reports `Unknown`,
    /// so the fallback resolves through the receipt route.
    struct TestKernel {
        committed: Mutex<BTreeMap<String, (String, String, WriteReceipt)>>,
        apply_calls: Mutex<u64>,
        lose_acknowledgement: Mutex<bool>,
    }

    impl TestKernel {
        fn new() -> Self {
            Self {
                committed: Mutex::new(BTreeMap::new()),
                apply_calls: Mutex::new(0),
                lose_acknowledgement: Mutex::new(false),
            }
        }

        fn apply_count(&self) -> u64 {
            *self.apply_calls.lock().expect("apply lock")
        }

        fn lose_next_acknowledgement(&self) {
            *self.lose_acknowledgement.lock().expect("ack lock") = true;
        }
    }

    /// Validates identity/transition binding plus revision/ordering fences.
    fn check_test_transition_bindings(
        identity: &RequestIdentity,
        transition: &PreparedTransition,
        expected_revision_heads: &[RevisionHeadExpectation],
        expected_ordering_heads: &[OrderingHeadExpectation],
    ) -> Result<(), KernelPortError> {
        identity
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        transition
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if identity.request.metadata.state_fence != transition.state_fence {
            return Err(KernelPortError::Contract(
                "test gateway: identity fence does not match transition".to_owned(),
            ));
        }
        if identity.idempotency_key != transition.identity.idempotency_key {
            return Err(KernelPortError::Contract(
                "test gateway: idempotency does not match transition".to_owned(),
            ));
        }
        for head in expected_revision_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: revision head fence mismatch".to_owned(),
                ));
            }
        }
        for head in expected_ordering_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: ordering head fence mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Builds the committed test receipt plus its store envelope.
    fn build_test_receipt(
        identity: &RequestIdentity,
        transition: &PreparedTransition,
        hash: &str,
        sequence: u64,
    ) -> Result<WriteReceipt, KernelPortError> {
        let operation_id = transition.identity.operation_id.clone();
        let candidate = WriteReceipt {
            operation_id: operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: hash.to_owned(),
            transition_class: transition.transition_class,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(
                CommitId::new(format!("commit-{operation_id}"))
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?,
            ),
            state_fence: transition.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["cmd-1".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some(format!("commit-sequence-{sequence:016}")),
            envelope: None,
        };
        candidate
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let envelope = issue_store_receipt_envelope(
            &identity.request.metadata,
            transition,
            &candidate,
            sequence,
        )
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let mut receipt = candidate;
        receipt.envelope = Some(envelope);
        validate_store_receipt_envelope(&identity.request.metadata, transition, &receipt)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(receipt)
    }

    impl KernelTransitionPort for TestKernel {
        fn apply_prepared<'a>(
            &'a self,
            identity: &RequestIdentity,
            transition: PreparedTransition,
            expected_revision_heads: Vec<RevisionHeadExpectation>,
            expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            let identity = identity.clone();
            Box::pin(async move {
                check_test_transition_bindings(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                )?;
                let key = transition.identity.operation_id.as_str().to_owned();
                let hash = transition.identity.canonical_request_hash.clone();
                let mut committed = self.committed.lock().expect("committed lock");
                if let Some((_, stored_hash, receipt)) = committed.get(&key) {
                    if *stored_hash == hash {
                        return Ok(receipt.clone());
                    }
                    return Err(KernelPortError::Contract(
                        "test gateway: committed operation identity conflict".to_owned(),
                    ));
                }
                let sequence = u64::try_from(committed.len())
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                    + 1;
                let receipt = build_test_receipt(&identity, &transition, &hash, sequence)?;
                *self.apply_calls.lock().expect("apply lock") += 1;
                committed.insert(
                    key,
                    (
                        transition.identity.idempotency_key.clone(),
                        hash,
                        receipt.clone(),
                    ),
                );
                if std::mem::replace(
                    &mut *self.lose_acknowledgement.lock().expect("ack lock"),
                    false,
                ) {
                    return Err(KernelPortError::Unknown(
                        "test gateway: acknowledgement lost after commit".to_owned(),
                    ));
                }
                Ok(receipt)
            })
        }

        fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async move {
                Ok(self
                    .committed
                    .lock()
                    .expect("committed lock")
                    .get(operation_id.as_str())
                    .map(|(_, _, receipt)| receipt.clone()))
            })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async move { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn identity(fence_value: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-operator-1").expect("request id"),
            session_id: Some(SessionId::new("session-operator-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence_value.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence_value.clone(),
            },
            idempotency_key: "idem-operator-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-operator-1".to_owned(),
        }
    }

    fn canonical_owner(fence_value: &StateFence) -> CanonicalAdmissionOwner {
        let scope = ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence_value.clone(),
        };
        let snapshot =
            CanonicalAdmissionSnapshot::new(fence_value.clone(), 1, None).expect("snapshot");
        CanonicalAdmissionOwner::new(fence_value.clone(), scope, snapshot).expect("canonical owner")
    }

    fn adapter<'a>(
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a TestKernel,
    ) -> GovernorOperatorReconciliation<'a, TestKernel> {
        GovernorOperatorReconciliation::new(canonical, kernel, CompositionReadiness::Ready)
    }

    fn envelope_for(
        identity_value: &RequestIdentity,
        operation_id: &OperationId,
        action_digest: &str,
    ) -> CanonicalWriteEnvelope {
        operator_command_envelope(
            identity_value,
            operation_id,
            "session-operator-1",
            &"a".repeat(64),
            action_digest,
            7,
        )
        .expect("envelope builds")
    }

    #[test]
    fn unknown_outcome_reconciles_by_original_id_while_changed_bytes_conflict() {
        let fence_value = fence();
        let canonical = canonical_owner(&fence_value);
        let kernel = TestKernel::new();
        let owner = adapter(&canonical, &kernel);
        let identity_value = identity(&fence_value);
        let operation_id = OperationId::new("op-operator-replay").expect("operation id");
        let envelope = envelope_for(&identity_value, &operation_id, &"b".repeat(64));
        let expected_hash = envelope.canonical_request_hash().expect("request hash");
        // First admission commits the canonical operator envelope into Kernel
        // ORS through the existing canonical path.
        let receipt = block_on(owner.admit_operator_command(
            &identity_value,
            &operation_id,
            envelope.clone(),
        ))
        .expect("operator admission commits");
        assert_eq!(receipt.operation_id, operation_id);
        assert_eq!(receipt.idempotency_key, identity_value.idempotency_key);
        assert_eq!(receipt.canonical_request_hash, expected_hash);
        assert_eq!(receipt.transition_class, TransitionClass::CaptureCandidate);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.state_fence, fence_value);
        assert_eq!(kernel.apply_count(), 1);
        // A fresh board after recovery resolves the same receipt by the
        // original operation id through the receipt route.
        let stored = block_on(kernel.receipt(operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(stored, receipt);
        // A lost acknowledgement reconciles through the receipt route instead
        // of a second execution.
        kernel.lose_next_acknowledgement();
        let unknown_id = OperationId::new("op-operator-unknown").expect("operation id");
        let unknown_envelope = envelope_for(&identity_value, &unknown_id, &"b".repeat(64));
        let reconciled = block_on(owner.admit_operator_command(
            &identity_value,
            &unknown_id,
            unknown_envelope.clone(),
        ))
        .expect("unknown outcome reconciles");
        assert_eq!(reconciled.operation_id, unknown_id);
        assert_eq!(reconciled.status, WriteReceiptStatus::Committed);
        assert_eq!(
            kernel.apply_count(),
            2,
            "the lost-acknowledgement commit executed exactly once"
        );
        let replayed =
            block_on(owner.admit_operator_command(&identity_value, &unknown_id, unknown_envelope))
                .expect("identical bytes replay the stored receipt");
        assert_eq!(replayed, reconciled);
        assert_eq!(
            kernel.apply_count(),
            2,
            "an identical retry must not execute a second transition"
        );
        // Changed bytes under the same operation id conflict and mutate
        // nothing: the original receipt still replays afterwards.
        let changed = envelope_for(&identity_value, &unknown_id, &"c".repeat(64));
        let conflicted =
            block_on(owner.admit_operator_command(&identity_value, &unknown_id, changed));
        assert!(
            matches!(conflicted, Err(CompositionError::Provider(_))),
            "changed bytes under the same id must conflict: {conflicted:?}"
        );
        assert_eq!(kernel.apply_count(), 2, "a conflict must not commit");
        let still = block_on(kernel.receipt(unknown_id.clone()))
            .expect("receipt route")
            .expect("original receipt");
        assert_eq!(still, reconciled);
    }
}
