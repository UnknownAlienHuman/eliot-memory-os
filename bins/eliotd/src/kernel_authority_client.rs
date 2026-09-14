//! Authenticated Kernel P-07 authority adapter for `eliotd`.
//!
//! Architecture traceability: A13.2 keeps Kernel authority and failure-domain
//! ownership explicit; I1.8 defines the daemon/Kernel call path, I2.23 the
//! typed contract payloads, and I6.10 the pending-until-activation saga with
//! Kernel-first revocation.
//!
//! This module owns only the `P07AuthorityPort` transport adapter: caller
//! binding validation, authenticated request encoding, exact receipt decoding,
//! and typed transport-failure mapping. Kernel owns activation, fencing, and
//! the route; Governor owns the semantic gating around the receipts returned
//! here.
//!
//! Forbidden boundary: no canned receipts, no `UnavailableP07AuthorityPort` in
//! the production path, no epoch invention (epochs stay with T6), no Store
//! access, and no local authority minting. The operation names below address
//! the daemon→Kernel P-07 route: until the Kernel front-door grant route lands
//! (T6/#15), the Kernel rejects them and every method fails closed through
//! the typed mapping — honest diagnosed degradation, never invented rights.
//!
//! `cfg(test)` doubles in the colocated test module are gating proofs only:
//! they exercise the pure binding/decode/mapping logic, never a production
//! success path.

use std::sync::Arc;

use eliot_authority::{
    GrantActivationRequest, GrantRevocationRequest, IntroductionActivationRequest,
    IntroductionRevocationRequest, P07AuthorityPort, P07PortError, SnapshotId,
};
use eliot_contracts::StateFence;
use eliot_governor::{KernelGenerationSnapshotProvider, KernelPortError};
use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};

use super::{kind_value, DaemonKernelClient};

/// Daemon→Kernel P-07 route names. These name the Kernel-owned front-door
/// route (T6/#15); until it exists the Kernel rejects them and the adapter
/// fails closed.
const ACTIVATE_GRANT_OPERATION: &str = "activate_grant";
const REVOKE_GRANT_OPERATION: &str = "revoke_grant";
const ACTIVATE_INTRODUCTION_OPERATION: &str = "activate_introduction";
const REVOKE_INTRODUCTION_OPERATION: &str = "revoke_introduction";

const ACTIVATION_RECEIPT_KIND: &str = "authority_activation_receipt";
const REVOCATION_RECEIPT_KIND: &str = "authority_revocation_receipt";

/// Reason reported when the Kernel has not yet published the exact launched
/// `eliotd` process receipt. The session cannot carry authority yet, so the
/// adapter degrades to `Unavailable` (retry via reconnect) rather than
/// reporting a refusal of the presented authority itself.
const PRE_ADMISSION_RECEIPT_PENDING: &str =
    "Kernel has not published the exact launched process receipt";

/// Authenticated P-07 transport over an already-connected Kernel client.
///
/// The client is retained exactly once by the daemon composition root. This
/// adapter performs no session management, clock reads, or retries: one
/// presentation means one authenticated round trip, and any ambiguity fails
/// closed to the typed error (lost acknowledgements surface as
/// `UnknownOutcome` with the exact snapshot for reconciliation).
pub(crate) struct KernelAuthorityClient {
    kernel: Arc<DaemonKernelClient>,
}

impl KernelAuthorityClient {
    /// Retains the already-connected authenticated Kernel client.
    pub(crate) fn new(kernel: Arc<DaemonKernelClient>) -> Self {
        Self { kernel }
    }

    fn active_fence(&self) -> StateFence {
        self.kernel.snapshot().state_fence()
    }
}

impl P07AuthorityPort for KernelAuthorityClient {
    fn activate_grant(
        &self,
        request: &GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let payload = serde_json::json!({
            "grant_id": request.grant_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
        });
        let value = self
            .kernel
            .request_blocking(ACTIVATE_GRANT_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = kind_value(&value, ACTIVATION_RECEIPT_KIND)
            .map_err(|_| P07PortError::InvalidBinding)?;
        decode_activation_receipt(value, request)
    }

    fn revoke_grant(
        &self,
        request: &GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let payload = serde_json::json!({
            "grant_id": request.grant_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
        });
        let value = self
            .kernel
            .request_blocking(REVOKE_GRANT_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = kind_value(&value, REVOCATION_RECEIPT_KIND)
            .map_err(|_| P07PortError::InvalidBinding)?;
        decode_revocation_receipt(value, request.snapshot_id.as_str(), &fence)
    }

    fn activate_introduction(
        &self,
        request: &IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let payload = serde_json::json!({
            "introduction_id": request.introduction_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
        });
        let value = self
            .kernel
            .request_blocking(ACTIVATE_INTRODUCTION_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = kind_value(&value, ACTIVATION_RECEIPT_KIND)
            .map_err(|_| P07PortError::InvalidBinding)?;
        decode_activation_receipt_for(value, request.snapshot_id.as_str(), &request.binding)
    }

    fn revoke_introduction(
        &self,
        request: &IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let payload = serde_json::json!({
            "introduction_id": request.introduction_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
        });
        let value = self
            .kernel
            .request_blocking(REVOKE_INTRODUCTION_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = kind_value(&value, REVOCATION_RECEIPT_KIND)
            .map_err(|_| P07PortError::InvalidBinding)?;
        decode_revocation_receipt(value, request.snapshot_id.as_str(), &fence)
    }
}

/// Validates the caller-side binding before any transport is touched: the
/// fence must be well-formed, the epoch must agree with the fence, and the
/// presented fence must be the currently active Kernel fence. Anything else is
/// an internally inconsistent presentation, never a Kernel refusal.
fn check_binding(
    binding: &AuthorityBinding,
    active_fence: &StateFence,
) -> Result<(), P07PortError> {
    binding
        .state_fence
        .validate()
        .map_err(|_| P07PortError::InvalidBinding)?;
    if binding.authority_epoch != binding.state_fence.authority_epoch
        || binding.state_fence != *active_fence
    {
        return Err(P07PortError::InvalidBinding);
    }
    Ok(())
}

/// Maps an authenticated-transport failure to the typed P-07 error:
/// - admission/session failures (including the missing front-door route until
///   T6/#15 lands) refuse the presented authority: `NotAdmitted`;
/// - a session that cannot carry authority yet (pre-admission receipt
///   pending) degrades to `Unavailable` for reconnect, not refusal;
/// - contract/shape mismatches are caller-visible binding failures:
///   `InvalidBinding`;
/// - an unproven delivery outcome may have committed before the ack was lost:
///   `UnknownOutcome` with the exact snapshot, retained — never collapsed to
///   unavailable/non-executed.
fn map_transport(error: KernelPortError, snapshot_id: &SnapshotId) -> P07PortError {
    match error {
        KernelPortError::NotAdmitted(reason) if reason == PRE_ADMISSION_RECEIPT_PENDING => {
            P07PortError::Unavailable
        }
        KernelPortError::NotAdmitted(_) => P07PortError::NotAdmitted,
        KernelPortError::Contract(_) => P07PortError::InvalidBinding,
        KernelPortError::Unknown(_) => P07PortError::UnknownOutcome {
            snapshot_id: snapshot_id.clone(),
        },
    }
}

/// Decodes an activation response and binds it to the exact presented grant
/// request: only a validated `Active` receipt for the presented snapshot and
/// fence epoch is authority. Anything else fails closed.
fn decode_activation_receipt(
    value: serde_json::Value,
    request: &GrantActivationRequest,
) -> Result<AuthorityActivationReceipt, P07PortError> {
    decode_activation_receipt_for(value, request.snapshot_id.as_str(), &request.binding)
}

fn decode_activation_receipt_for(
    value: serde_json::Value,
    snapshot_id: &str,
    binding: &AuthorityBinding,
) -> Result<AuthorityActivationReceipt, P07PortError> {
    let receipt: AuthorityActivationReceipt =
        serde_json::from_value(value).map_err(|_| P07PortError::InvalidBinding)?;
    receipt
        .validate()
        .map_err(|_| P07PortError::InvalidBinding)?;
    if receipt.snapshot_id != snapshot_id
        || receipt.authority_epoch != binding.state_fence.authority_epoch
    {
        return Err(P07PortError::InvalidBinding);
    }
    Ok(receipt)
}

/// Decodes a revocation response: only a validated terminal revocation receipt
/// (`Revoked`/`Expired`/`Superseded`) for the presented snapshot and fence
/// epoch fences the projection. Anything else fails closed.
fn decode_revocation_receipt(
    value: serde_json::Value,
    snapshot_id: &str,
    fence: &StateFence,
) -> Result<AuthorityRevocationReceipt, P07PortError> {
    let receipt: AuthorityRevocationReceipt =
        serde_json::from_value(value).map_err(|_| P07PortError::InvalidBinding)?;
    receipt
        .validate()
        .map_err(|_| P07PortError::InvalidBinding)?;
    if receipt.snapshot_id != snapshot_id || receipt.authority_epoch != fence.authority_epoch {
        return Err(P07PortError::InvalidBinding);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_authority::{GrantId, GrantStatus, IntroductionStatus};
    use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration};
    use eliot_governor::{PresentedAuthorityRequest, RetainedAuthorityRequest};
    use eliot_receipts::{EffectClass, ProofCeiling};
    use eliot_runtime_contracts::AuthorityState;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(1).expect("resource generation"),
        )
    }

    fn test_binding(fence: &StateFence) -> AuthorityBinding {
        AuthorityBinding {
            authority_id: ContractId::new("authority:test").expect("authority id"),
            authority_owner: "test-owner".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        }
    }

    fn grant_request(fence: &StateFence) -> GrantActivationRequest {
        GrantActivationRequest {
            grant_id: GrantId::new("grant-1").expect("grant id"),
            snapshot_id: SnapshotId::new("snap-1").expect("snapshot id"),
            binding: test_binding(fence),
        }
    }

    fn owner_snapshot(fence: &StateFence) -> eliot_governor::AuthorityOwnerSnapshot {
        let graph = eliot_authority::GrantGraph::from_grants(std::iter::empty(), 1)
            .and_then(|graph| graph.recovery_snapshot())
            .expect("empty grant graph snapshot");
        let effect_authorizer = eliot_authority::EffectAuthorizer::default()
            .snapshot()
            .expect("empty effect authorizer snapshot");
        eliot_governor::AuthorityOwnerSnapshot::new(fence.clone(), graph, effect_authorizer)
            .expect("authority snapshot")
    }

    #[test]
    fn activation_decode_accepts_only_exact_validated_active_receipts() {
        let fence = test_fence();
        let request = grant_request(&fence);

        // The binding gate runs before any transport: a stale fence, a split
        // epoch, or a malformed fence fails closed as InvalidBinding.
        let mut stale_fence = fence.clone();
        stale_fence.resource_generation = ResourceGeneration::new(2).expect("resource generation");
        let mut stale_binding = test_binding(&fence);
        stale_binding.state_fence = stale_fence;
        assert!(matches!(
            check_binding(&stale_binding, &fence),
            Err(P07PortError::InvalidBinding)
        ));
        let mut split_binding = test_binding(&fence);
        split_binding.authority_epoch = test_epoch(2);
        assert!(matches!(
            check_binding(&split_binding, &fence),
            Err(P07PortError::InvalidBinding)
        ));
        check_binding(&request.binding, &fence).expect("exact binding passes");

        // Transport admission refusal is NotAdmitted, never a receipt.
        assert!(matches!(
            map_transport(
                KernelPortError::NotAdmitted("fenced".to_owned()),
                &request.snapshot_id
            ),
            P07PortError::NotAdmitted
        ));
        // A session that cannot carry authority yet degrades to Unavailable.
        assert!(matches!(
            map_transport(
                KernelPortError::NotAdmitted(PRE_ADMISSION_RECEIPT_PENDING.to_owned()),
                &request.snapshot_id
            ),
            P07PortError::Unavailable
        ));
        // Shape mismatches are binding failures.
        assert!(matches!(
            map_transport(
                KernelPortError::Contract("bad shape".to_owned()),
                &request.snapshot_id
            ),
            P07PortError::InvalidBinding
        ));
        // Lost acknowledgement keeps the exact snapshot for reconciliation.
        match map_transport(
            KernelPortError::Unknown("delivery outcome was not proven".to_owned()),
            &request.snapshot_id,
        ) {
            P07PortError::UnknownOutcome { snapshot_id } => {
                assert_eq!(snapshot_id.as_str(), "snap-1");
            }
            other => panic!("expected an unknown outcome, got {other:?}"),
        }

        // Only a validated Active receipt bound to the exact snapshot and
        // epoch decodes: anything else fails closed without a receipt.
        let valid = serde_json::to_value(AuthorityActivationReceipt {
            activation_id: "act-1".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Active,
        })
        .expect("receipt JSON");
        let receipt =
            decode_activation_receipt(valid, &request).expect("exact active receipt decodes");
        assert_eq!(receipt.activation_id, "act-1");

        let non_active = serde_json::to_value(AuthorityActivationReceipt {
            activation_id: "act-2".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::PendingKernelActivation,
        })
        .expect("receipt JSON");
        assert!(matches!(
            decode_activation_receipt(non_active, &request),
            Err(P07PortError::InvalidBinding)
        ));

        let foreign_snapshot = serde_json::to_value(AuthorityActivationReceipt {
            activation_id: "act-3".to_owned(),
            snapshot_id: "snap-other".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Active,
        })
        .expect("receipt JSON");
        assert!(matches!(
            decode_activation_receipt(foreign_snapshot, &request),
            Err(P07PortError::InvalidBinding)
        ));

        let foreign_epoch = serde_json::to_value(AuthorityActivationReceipt {
            activation_id: "act-4".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("authority epoch lineage"),
                std::num::NonZeroU64::new(2).expect("authority epoch sequence"),
            )
            .expect("authority epoch"),
            state: AuthorityState::Active,
        })
        .expect("receipt JSON");
        assert!(matches!(
            decode_activation_receipt(foreign_epoch, &request),
            Err(P07PortError::InvalidBinding)
        ));

        // A revocation receipt in a non-terminal state never fences.
        let non_terminal = serde_json::to_value(AuthorityRevocationReceipt {
            revocation_id: "rev-1".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Active,
        })
        .expect("receipt JSON");
        assert!(matches!(
            decode_revocation_receipt(non_terminal, "snap-1", &fence),
            Err(P07PortError::InvalidBinding)
        ));
        let revoked = serde_json::to_value(AuthorityRevocationReceipt {
            revocation_id: "rev-2".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Revoked,
        })
        .expect("receipt JSON");
        let receipt = decode_revocation_receipt(revoked, "snap-1", &fence)
            .expect("terminal revocation receipt decodes");
        assert_eq!(receipt.revocation_id, "rev-2");
    }

    #[test]
    fn lost_ack_stays_pending_unknown_and_revoke_blocks_without_canonical_reconcile() {
        // cfg(test)-only gating proof: the adapter maps a lost acknowledgement
        // to UnknownOutcome with the exact snapshot, and the Governor
        // retention record keeps the exact request pending; a
        // revoke-then-reconcile failure leaves effects blocked, never active.
        // No production success path is exercised here.
        let fence = test_fence();
        let request = grant_request(&fence);
        let snapshot = owner_snapshot(&fence);

        // Lost ack maps to UnknownOutcome carrying the exact snapshot id.
        let outcome = map_transport(
            KernelPortError::Unknown("delivery outcome was not proven".to_owned()),
            &request.snapshot_id,
        );
        let snapshot_id = match outcome {
            P07PortError::UnknownOutcome { snapshot_id } => snapshot_id,
            other => panic!("expected an unknown outcome, got {other:?}"),
        };
        assert_eq!(snapshot_id.as_str(), "snap-1");

        // The exact request is retained under its snapshot and stays pending:
        // unknown, never active, never collapsed to unavailable.
        let mut retained = RetainedAuthorityRequest::retain(
            PresentedAuthorityRequest::GrantActivation(request.clone()),
            snapshot.clone(),
        )
        .expect("retention");
        assert_eq!(retained.request().snapshot_id().as_str(), "snap-1");
        retained
            .note_unknown_outcome(&snapshot_id)
            .expect("unknown outcome files against the exact snapshot");
        assert_eq!(
            retained.grant_status(Some(GrantStatus::PendingActivation)),
            GrantStatus::PendingActivation
        );
        // A foreign snapshot cannot reconcile this presentation.
        let foreign = SnapshotId::new("snap-other").expect("snapshot id");
        assert!(
            retained.note_unknown_outcome(&foreign).is_err(),
            "foreign snapshots must not reconcile the retained request"
        );

        // Revoke path: Kernel revokes first with a validated terminal receipt,
        // then canonical reconciliation fails. The retained revocation intent
        // blocks effects instead of reporting an active right.
        let revocation = GrantRevocationRequest {
            grant_id: request.grant_id.clone(),
            snapshot_id: request.snapshot_id.clone(),
            binding: request.binding.clone(),
        };
        let mut revoked = RetainedAuthorityRequest::retain(
            PresentedAuthorityRequest::GrantRevocation(revocation),
            snapshot,
        )
        .expect("revocation retention");
        let receipt = AuthorityRevocationReceipt {
            revocation_id: "rev-9".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Revoked,
        };
        revoked
            .note_revoked(&receipt)
            .expect("validated revocation receipt files");
        assert_eq!(
            revoked.grant_status(Some(GrantStatus::Active)),
            GrantStatus::Revoked,
            "a filed revocation overrides even a recovered Active"
        );
        // Simulate the canonical-reconciliation failure after the Kernel
        // receipt: intent stays visible and strictly blocks.
        revoked.note_revocation_intended();
        assert_eq!(
            revoked.grant_status(Some(GrantStatus::Active)),
            GrantStatus::Revoked,
            "revocation intent without canonical reconcile still blocks effects"
        );
        assert_eq!(
            revoked.introduction_status(),
            Some(IntroductionStatus::Revoked),
            "revocation intent is visible on every projection, never an active right"
        );
        // No activation can ever resurrect this presentation: it is not an
        // activation presentation, and its state is terminal.
        let activation = AuthorityActivationReceipt {
            activation_id: "act-never".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state: AuthorityState::Active,
        };
        assert!(
            revoked.note_activated(&activation).is_err(),
            "activation must never resurrect a revoked presentation"
        );
    }
}
