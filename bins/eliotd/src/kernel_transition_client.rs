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
    OrderingHeadExpectation, PreparedTransition, RevisionHeadExpectation, StoreHealth,
    WriteReceipt, validate_store_receipt_envelope,
};

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
fn check_identity_binding(
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
    if transition.state_fence != identity.request.metadata.state_fence {
        return Err(KernelPortError::Contract(
            "daemon transition fence does not match the admitted identity".to_owned(),
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
        Box::pin(async move {
            check_identity_binding(
                &identity,
                &transition,
                &expected_revision_heads,
                &expected_ordering_heads,
            )?;
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
            Ok(receipt)
        })
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        let state_fence = self.kernel_binding.state_fence.clone();
        Box::pin(async move {
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
        })
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        Box::pin(async move {
            let value = self
                .transact_async("health", serde_json::json!({}))
                .await
                .map_err(kernel_port_error)?;
            let value = kind_value(&value, "health")?;
            serde_json::from_value(value)
                .map_err(|error| KernelPortError::Contract(error.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
        SessionId, SourceId, StateFence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
        OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId, SecurityContext,
        TransitionClass,
    };

    fn test_fence(generation: u64) -> StateFence {
        StateFence::new(
            AuthorityEpoch::new(1).expect("authority epoch"),
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
        PreparedTransition {
            identity: OperationIdentity {
                operation_id: OperationId::new("op-daemon-1").expect("operation id"),
                idempotency_key: "idem-daemon-1".to_owned(),
                canonical_request_hash: "c".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("governor").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope:governor").expect("ordering scope")],
            transition_class: TransitionClass::TaskControl,
            requested_effect_ceiling: EffectClass::ReversibleMutation,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: OperationManifestDigest::new("manifest")
                .expect("manifest digest"),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::UpdateTaskState,
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
        let transition = transition(&fence);
        // Exact admitted terms pass with the initiating source preserved:
        // the adapter never rewrites it to the daemon transport peer.
        check_identity_binding(&identity, &transition, &[], &[ordering_head(&fence)])
            .expect("exact binding");
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
}
