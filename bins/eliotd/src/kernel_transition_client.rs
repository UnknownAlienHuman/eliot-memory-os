//! Neutral authenticated Kernel transition client for the daemon.
//!
//! This module owns only the `KernelTransitionPort` transport adapter: caller
//! metadata, transition/head validation, explicit request identity construction,
//! and exact write-receipt decoding. Store owns canonical persistence and
//! Kernel owns route/fence admission; Governor retains semantic transition
//! planning. Architecture: A2.3, A12.3, A13.2, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I1.8, I2.23, P.3, I14.21, I14.26.
//! Forbidden authority: no Store/provider SDK, canonical ownership, semantic
//! Governor reconstruction, retry/default synthesis, or alternate transport.

use eliot_contracts::OperationId;
use eliot_governor::{KernelPortError, KernelPortFuture, KernelTransitionPort};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CanonicalRequestView, OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation,
    StoreHealth, WriteReceipt, generated_operation_manifests, validate_store_receipt_envelope,
    verify_canonical_request_hash,
};
use tracing::Instrument as _;

use super::{DaemonKernelClient, kernel_port_error, kind_value};

/// Checks the admitted identity against the immutable transition before any
/// transport is touched.
///
/// The identity carries the original caller/fence binding plus the admitted
/// idempotency terms and is forwarded unchanged: no deadline/cancellation
/// default is synthesized here. The authenticated daemon transport peer stays
/// distinct from the initiating principal/session, so this check never
/// requires the request source to be the daemon identity and never rewrites
/// it.
#[cfg(test)]
fn check_identity_binding(
    identity: &RequestIdentity,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), KernelPortError> {
    check_identity_binding_with_mode(
        identity,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        false,
    )
}

fn check_identity_binding_with_mode(
    identity: &RequestIdentity,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
    allow_learning: bool,
) -> Result<(), KernelPortError> {
    identity
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    transition
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    if transition.state_fence != identity.request.metadata.state_fence {
        return Err(KernelPortError::Contract(
            "daemon transition fence does not match the admitted identity".to_owned(),
        ));
    }
    if !allow_learning
        && transition.named_operations.iter().any(|command| {
            command.operation == eliot_store_api::NamedMutationOperation::RecordLearningRecord
        })
    {
        return Err(KernelPortError::Contract(
            "generic daemon transition cannot carry learning records".to_owned(),
        ));
    }
    if transition.identity.idempotency_key != identity.idempotency_key {
        return Err(KernelPortError::Contract(
            "daemon transition idempotency does not match the admitted identity".to_owned(),
        ));
    }
    for head in expected_revision_heads {
        head.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if head.state_fence != identity.request.metadata.state_fence {
            return Err(KernelPortError::Contract(
                "daemon revision head fence does not match the admitted identity".to_owned(),
            ));
        }
    }
    for head in expected_ordering_heads {
        head.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if head.state_fence != identity.request.metadata.state_fence {
            return Err(KernelPortError::Contract(
                "daemon ordering head fence does not match the admitted identity".to_owned(),
            ));
        }
    }
    // 1927: deterministic PreparedTransition admission before transport.
    // Recompute the canonical request hash over the exact executable bytes
    // about to be sent (context + transition + expected heads). A plan whose
    // contents, effect ceiling, scope task binding, named operation
    // parameters, or admission digest changed after staging fails here rather
    // than reaching Kernel/store execution.
    let view = CanonicalRequestView::from_apply(
        &identity.request.metadata,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    // 1927: the transported plan must be supported by the currently admitted
    // operation catalogue. An unsupported recorded plan is refused here as
    // visible recovery work; it is never reinterpreted or widened for send.
    let entries = generated_operation_manifests()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    transition
        .validate_against_catalogue(&entries)
        .map_err(|error| {
            KernelPortError::Contract(format!(
                "unsupported prepared transition; preserve as recovery, do not reinterpret: {error}"
            ))
        })?;
    Ok(())
}

impl KernelTransitionPort for DaemonKernelClient {
    fn apply_prepared<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        let identity = identity.clone();
        // #740: handoff/commitment span over the neutral transition
        // boundary. Identity binding agreement marks the prepared handoff;
        // the validated receipt envelope marks the commitment. The two
        // are never the same record. The span instruments the future
        // (`Send`-safe) instead of an entered guard, which cannot cross
        // an await.
        let span = tracing::info_span!(
            "eliotd.transition_handoff",
            operation = %super::diagnostics::sanitize_identity(&identity.idempotency_key)
        );
        Box::pin(
            async move {
                check_identity_binding_with_mode(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                    false,
                )?;
                let _ = super::diagnostics::emit_handoff(
                    super::diagnostics::HandoffKind::Prepared,
                    identity.idempotency_key.as_str(),
                    identity.request.metadata.request_id.as_str(),
                );
                let expected_transition = transition.clone();
                let value = self
                    .transact_async_with_identity(
                        "apply_prepared",
                        serde_json::json!({
                            "context": identity.request.metadata.clone(),
                            "transition": transition,
                            "expected_revision_heads": expected_revision_heads,
                            "expected_ordering_heads": expected_ordering_heads,
                        }),
                        identity.clone(),
                    )
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "write_receipt")?;
                let receipt: WriteReceipt = serde_json::from_value(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                validate_store_receipt_envelope(
                    &identity.request.metadata,
                    &expected_transition,
                    &receipt,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let _ = super::diagnostics::emit_handoff(
                    super::diagnostics::HandoffKind::Committed,
                    identity.idempotency_key.as_str(),
                    receipt.operation_id.as_str(),
                );
                Ok(receipt)
            }
            .instrument(span),
        )
    }

    fn record_learning_record<'a>(
        &'a self,
        identity: &'a RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        let identity = identity.clone();
        let span = tracing::info_span!(
            "eliotd.learning_record_handoff",
            operation = %super::diagnostics::sanitize_identity(&identity.idempotency_key)
        );
        Box::pin(
            async move {
                check_identity_binding_with_mode(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                    true,
                )?;
                if transition.named_operations.len() != 1
                    || transition.named_operations[0].operation
                        != eliot_store_api::NamedMutationOperation::RecordLearningRecord
                {
                    return Err(KernelPortError::Contract(
                        "dedicated learning route requires exactly one learning operation"
                            .to_owned(),
                    ));
                }
                let expected_transition = transition.clone();
                let value = self
                    .transact_async_with_identity(
                        "record_learning_record",
                        serde_json::json!({
                            "context": identity.request.metadata.clone(),
                            "transition": transition,
                            "expected_revision_heads": expected_revision_heads,
                            "expected_ordering_heads": expected_ordering_heads,
                        }),
                        identity.clone(),
                    )
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "write_receipt")?;
                let receipt: WriteReceipt = serde_json::from_value(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                validate_store_receipt_envelope(
                    &identity.request.metadata,
                    &expected_transition,
                    &receipt,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                Ok(receipt)
            }
            .instrument(span),
        )
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        let state_fence = self.kernel_binding.state_fence.clone();
        // #740: receipt-boundary span over the owning read path
        // (`Send`-safe instrumentation; no entered guard crosses an await).
        let span = tracing::info_span!("eliotd.transition_receipt");
        Box::pin(
            async move {
                let value = self
                    .transact_async(
                        "receipt",
                        serde_json::json!({
                            "operation_id": operation_id.clone(),
                            "state_fence": state_fence.clone(),
                        }),
                    )
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "receipt")?;
                let Some(receipt) = serde_json::from_value::<Option<WriteReceipt>>(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                else {
                    return Ok(None);
                };
                receipt
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if receipt.operation_id != operation_id || receipt.state_fence != state_fence {
                    return Err(KernelPortError::Contract(
                    "daemon receipt does not match the requested operation and active state fence"
                        .to_owned(),
                ));
                }
                Ok(Some(receipt))
            }
            .instrument(span),
        )
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        // #740: health-boundary span over the owning read path
        // (`Send`-safe instrumentation; no entered guard crosses an await).
        let span = tracing::info_span!("eliotd.transition_health");
        Box::pin(
            async move {
                let value = self
                    .transact_async("health", serde_json::json!({}))
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "health")?;
                serde_json::from_value(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))
            }
            .instrument(span),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        CanonicalRequestView, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
        NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId,
        SecurityContext, TransitionClass, canonical_request_hash, generated_operation_manifests,
        operation_manifest_set_digest,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence(generation: u64) -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(generation).expect("resource generation"),
        )
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-daemon-1").expect("request id"),
            session_id: Some(SessionId::new("session-daemon-1").expect("session id")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product id"),
            source_id: SourceId::new("agent-bridge").expect("source id"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-daemon-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-daemon-1".to_owned(),
        }
    }

    fn transition(fence: &StateFence) -> PreparedTransition {
        let entries = generated_operation_manifests().expect("catalogue");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest");
        let mut transition = PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new("op-daemon-1").expect("operation id"),
                idempotency_key: "idem-daemon-1".to_owned(),
                canonical_request_hash: "c".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("governor").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope:governor").expect("ordering scope")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: set_digest,
            // Issue-#18 digests are derived below via `bind_issue18_digests`,
            // never defaulted; this fixture leg binds no semantic source (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-daemon-1"),
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
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn ordering_head(fence: &StateFence) -> OrderingHeadExpectation {
        OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope:governor").expect("ordering scope"),
            expected_sequence: 1,
            state_fence: fence.clone(),
        }
    }

    #[test]
    fn transition_identity_binding_is_exact_before_transport() {
        let fence = test_fence(1);
        let identity = identity(&fence);
        let mut transition = transition(&fence);
        // Bind the deterministic admission digest over the exact executable
        // bytes used below (1927): the transported hash must equal the
        // recomputed canonical request hash, or admission fails closed.
        let heads = vec![ordering_head(&fence)];
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&identity.request.metadata, &transition, &[], &heads),
        )
        .expect("admission hash");
        // Exact admitted terms pass with the initiating source preserved:
        // the adapter never rewrites it to the daemon transport peer.
        check_identity_binding(&identity, &transition, &[], &heads).expect("exact binding");
        assert_eq!(identity.request.metadata.source_id.as_str(), "agent-bridge");
        // A substituted fence binding fails closed before any transport,
        // even though the substituted identity is internally consistent.
        let other = test_fence(2);
        let mut substituted = identity.clone();
        substituted.request.metadata.state_fence = other.clone();
        substituted.request.state_fence = other.clone();
        assert!(matches!(
            check_identity_binding(&substituted, &transition, &[], &[]),
            Err(KernelPortError::Contract(_))
        ));
        // A substituted idempotency key fails the same way.
        let mut rekeyed = identity.clone();
        rekeyed.idempotency_key = "idem-substituted".to_owned();
        assert!(matches!(
            check_identity_binding(&rekeyed, &transition, &[], &[]),
            Err(KernelPortError::Contract(_))
        ));
        // A head bound to another fence fails as well.
        assert!(matches!(
            check_identity_binding(&identity, &transition, &[], &[ordering_head(&other)]),
            Err(KernelPortError::Contract(_))
        ));
    }

    #[test]
    fn prepared_admission_rejects_tampered_and_unsupported_plans() {
        // 1927 acceptance: changing the plan contents, effect ceiling, named
        // operation parameters, or admission digest after staging causes
        // rejection rather than execution; an unsupported recorded plan is
        // visible as recovery work and is not reinterpreted.
        let fence = test_fence(1);
        let identity = identity(&fence);
        let mut transition = transition(&fence);
        let heads = vec![ordering_head(&fence)];
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&identity.request.metadata, &transition, &[], &heads),
        )
        .expect("admission hash");
        check_identity_binding(&identity, &transition, &[], &heads).expect("admitted plan");
        // Widened effect ceiling after staging is rejected.
        let mut widened = transition.clone();
        widened.requested_effect_ceiling = EffectClass::ReversibleMutation;
        assert!(matches!(
            check_identity_binding(&identity, &widened, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Mutated named-operation parameters after staging are rejected.
        let mut reparam = transition.clone();
        reparam.named_operations[0].parameters.insert(
            "subject".to_owned(),
            serde_json::json!("observation-substituted"),
        );
        assert!(matches!(
            check_identity_binding(&identity, &reparam, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Mutated admission digest after staging is rejected.
        let mut redigest = transition.clone();
        redigest.admission_contract_set_digest = "d".repeat(64);
        assert!(matches!(
            check_identity_binding(&identity, &redigest, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Unsupported operation manifest is refused as visible recovery work.
        let mut unsupported = transition.clone();
        unsupported.operation_manifest_digest =
            OperationManifestDigest::new("f".repeat(64)).expect("digest shape");
        unsupported.identity.canonical_request_hash =
            canonical_request_hash(&CanonicalRequestView::from_apply(
                &identity.request.metadata,
                &unsupported,
                &[],
                &heads,
            ))
            .expect("recomputed hash");
        let error = match check_identity_binding(&identity, &unsupported, &[], &heads) {
            Err(error) => error,
            Ok(()) => unreachable!("unsupported manifest must fail"),
        };
        assert!(
            matches!(error, KernelPortError::Contract(ref detail) if detail.contains("recovery")),
            "unsupported plan must name recovery, got: {error:?}"
        );
    }
}
