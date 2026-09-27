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
//! the production path, no epoch invention, no Store access, and no local
//! authority minting. The operation names below address the Kernel-owned
//! front-door P-07 route; the Kernel binds the canonical Governor closure
//! owner through it and serves activation, revocation, and restart
//! rehydration from that owner, never from a no-authority stand-in.
//!
//! Every request presents the compact [`AuthorityBinding`] plus the
//! principal/session/scope subject this client proves from its own
//! authenticated owner session, because the compact binding alone cannot
//! distinguish a cross-principal, cross-session, or cross-scope presentation
//! from the one the session may perform. Both are checked before the
//! transport is touched; neither carries a secret, provider detail,
//! arbitrary payload, or free prose.
//!
//! `cfg(test)` doubles in the colocated test module are gating proofs only:
//! they exercise the pure binding/decode/mapping logic, never a production
//! success path.

use std::sync::Arc;

use eliot_authority::{
    GrantActivationRequest, GrantRevocationRequest, IntroductionActivationRequest,
    IntroductionRevocationRequest, P07AuthorityPort, P07PortError, P07RefusalCause,
    RootTransitionActivationReceipt, RootTransitionActivationRequest, SnapshotId,
};
use eliot_contracts::StateFence;
use eliot_governor::{KernelGenerationSnapshotProvider, KernelPortError};
use eliot_receipts::{AuthorityBinding, AuthorityRequestSubject};
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};

use super::{DaemonKernelClient, SERVICE_NAME, kind_value};

/// Daemon→Kernel P-07 route names. These address the Kernel-owned front-door
/// route (T6/#15), where the canonical Governor closure owner is bound and
/// activation, revocation, and restart rehydration are served from that
/// owner.
const ACTIVATE_GRANT_OPERATION: &str = "activate_grant";
const REVOKE_GRANT_OPERATION: &str = "revoke_grant";
const ACTIVATE_INTRODUCTION_OPERATION: &str = "activate_introduction";
const REVOKE_INTRODUCTION_OPERATION: &str = "revoke_introduction";
/// Authenticated root-transition route (issue #2962). It is a DISTINCT
/// Kernel-owned front-door operation, not an `activate_grant` overload: the
/// payload is the complete typed root-transition operation, and the reply is
/// the transition-specific activation receipt.
const ACTIVATE_ROOT_TRANSITION_OPERATION: &str = "activate_root_transition";

const ACTIVATION_RECEIPT_KIND: &str = "authority_activation_receipt";
const REVOCATION_RECEIPT_KIND: &str = "authority_revocation_receipt";
/// Closed Kernel application kind for a decided P-07 refusal.
const P07_AUTHORITY_REFUSAL_KIND: &str = "authority_operation_refused";
const ROOT_TRANSITION_RECEIPT_KIND: &str = "authority_root_transition_receipt";

/// The exact session capability this adapter presents as its authenticated
/// scope. It is the same closed constant the daemon's authenticated
/// `ClientHello` declares in `daemon_kernel_client::handshake::client_hello`,
/// and the Kernel front-door policy admits exactly this capability for the
/// daemon session, so the presented scope is derived evidence on both sides
/// rather than a locally chosen label.
const DAEMON_SESSION_CAPABILITY: &str = "daemon";

/// Reason reported when the Kernel has not yet published the exact launched
/// `eliotd` process receipt. The session cannot carry authority yet, so the
/// adapter degrades to `Unavailable` (retry via reconnect) rather than
/// reporting a refusal of the presented authority itself.
const PRE_ADMISSION_RECEIPT_PENDING: &str =
    "Kernel has not published the exact launched process receipt";

/// Exact typed P-07 error variant names carried by the refusal frame. The
/// client matches the frame on these closed tokens, never on free prose, so a
/// refusal that arrives under any other name fails closed.
const P07_ERROR_IDENTITY_CONFLICT: &str = "IdentityConflict";
const P07_ERROR_UNKNOWN_OUTCOME: &str = "UnknownOutcome";
const P07_ERROR_INVALID_BINDING: &str = "InvalidBinding";
const P07_ERROR_UNAVAILABLE: &str = "Unavailable";
const P07_ERROR_NOT_ADMITTED: &str = "NotAdmitted";
const P07_ERROR_REFUSED: &str = "Refused";

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

    /// Builds the presented principal/session/scope subject from the
    /// authenticated owner session this client already holds.
    ///
    /// No value is invented here. The principal is this daemon's own service
    /// identity as its authenticated handshake declares it, the session is the
    /// live transport connection correlation the Kernel proves from the same
    /// handshake frame, and the scope is the session capability both sides
    /// admit. Absent authenticated session evidence is a pre-admission state,
    /// not a refusal of the presented authority, so it degrades to
    /// `Unavailable` and the caller reconnects instead of presenting an
    /// unbound subject.
    ///
    /// The two decisions stay distinct. Absent session evidence keeps
    /// `Unavailable`, because I7.20 classifies no cause for a session the
    /// Kernel has not yet published and inventing one would over-claim. A
    /// subject the *proven* session facts cannot bind into is a different
    /// decision and reports its own cause.
    fn subject(&self) -> Result<AuthorityRequestSubject, P07PortError> {
        let facts = self
            .kernel
            .owner_session_facts()
            .ok_or(P07PortError::Unavailable)?;
        AuthorityRequestSubject::new(
            SERVICE_NAME,
            facts.connection_id(),
            DAEMON_SESSION_CAPABILITY,
        )
        .map_err(|_| P07PortError::Refused {
            cause: P07RefusalCause::SessionSubjectUnbindable,
        })
    }
}

impl P07AuthorityPort for KernelAuthorityClient {
    fn activate_grant(
        &self,
        request: &GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let subject = self.subject()?;
        let payload = serde_json::json!({
            "grant_id": request.grant_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
            "subject": subject,
        });
        let value = self
            .kernel
            .request_blocking(ACTIVATE_GRANT_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = p07_route_value(&value, ACTIVATION_RECEIPT_KIND, ACTIVATE_GRANT_OPERATION)?;
        decode_activation_receipt(value, request)
    }

    fn revoke_grant(
        &self,
        request: &GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let subject = self.subject()?;
        let payload = serde_json::json!({
            "grant_id": request.grant_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
            "subject": subject,
        });
        let value = self
            .kernel
            .request_blocking(REVOKE_GRANT_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = p07_route_value(&value, REVOCATION_RECEIPT_KIND, REVOKE_GRANT_OPERATION)?;
        decode_revocation_receipt(value, request.snapshot_id.as_str(), &fence)
    }

    fn activate_introduction(
        &self,
        request: &IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let subject = self.subject()?;
        let payload = serde_json::json!({
            "introduction_id": request.introduction_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
            "subject": subject,
        });
        let value = self
            .kernel
            .request_blocking(ACTIVATE_INTRODUCTION_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = p07_route_value(
            &value,
            ACTIVATION_RECEIPT_KIND,
            ACTIVATE_INTRODUCTION_OPERATION,
        )?;
        decode_activation_receipt_for(value, request.snapshot_id.as_str(), &request.binding)
    }

    fn revoke_introduction(
        &self,
        request: &IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.binding, &fence)?;
        let subject = self.subject()?;
        let payload = serde_json::json!({
            "introduction_id": request.introduction_id.as_str(),
            "snapshot_id": request.snapshot_id.as_str(),
            "binding": request.binding,
            "subject": subject,
        });
        let value = self
            .kernel
            .request_blocking(REVOKE_INTRODUCTION_OPERATION, payload)
            .map_err(|error| map_transport(error, &request.snapshot_id))?;
        let value = p07_route_value(
            &value,
            REVOCATION_RECEIPT_KIND,
            REVOKE_INTRODUCTION_OPERATION,
        )?;
        decode_revocation_receipt(value, request.snapshot_id.as_str(), &fence)
    }

    /// Presents one exact authenticated root-transition operation.
    ///
    /// Same two proofs as the other four arms, at the same boundary and before
    /// the transport is touched: [`check_binding`] proves the presented fence
    /// is the CURRENT Kernel fence with a self-consistent epoch, and
    /// [`Self::subject`] proves the principal/session/scope from the live
    /// authenticated session. The payload then carries the whole typed
    /// operation — every bound transition field plus the subject — so nothing
    /// is tunnelled through an untyped map and ordinary grant activation is not
    /// overloaded. The reply must be the transition-specific receipt and must
    /// validate against the exact presented request, which is what proves both
    /// the semantic decision and the mechanical activation.
    fn activate_root_transition(
        &self,
        request: &RootTransitionActivationRequest,
    ) -> Result<RootTransitionActivationReceipt, P07PortError> {
        let fence = self.active_fence();
        check_binding(&request.record().binding, &fence)?;
        let subject = self.subject()?;
        if subject != *request.subject() {
            return Err(P07PortError::InvalidBinding);
        }
        let record = request.record();
        let payload = serde_json::json!({
            "operation_id": record.operation_id,
            "idempotency_key": record.idempotency_key,
            "transition_id": record.transition_id,
            "parent_grant_id": record.parent_grant_id,
            "child_grant_id": record.child_grant_id,
            "parent_grant_commitment": record.parent_grant_commitment,
            "child_grant_commitment": record.child_grant_commitment,
            "from_authority_root_ref": record.from_authority_root_ref,
            "to_authority_root_ref": record.to_authority_root_ref,
            "issuer": record.issuer,
            "graph_snapshot_id": record.graph_snapshot_id,
            "predecessor_graph_revision": record.predecessor_graph_revision,
            "expected_next_graph_revision": record.expected_next_graph_revision,
            "policy_revision": record.policy_revision,
            "deadline_unix_ms": record.deadline_unix_ms,
            "effect_ceiling": record.effect_ceiling,
            "semantic_decision_ref": record.semantic_decision_ref,
            "canonical_request_digest": request.canonical_request_digest(),
            "binding": record.binding,
            "subject": subject,
        });
        let snapshot_id = transition_snapshot_id(record.graph_snapshot_id.as_str())?;
        let value = self
            .kernel
            .request_blocking(ACTIVATE_ROOT_TRANSITION_OPERATION, payload)
            .map_err(|error| map_transport(error, &snapshot_id))?;
        let value = kind_value(&value, ROOT_TRANSITION_RECEIPT_KIND)
            .map_err(|_| P07PortError::InvalidBinding)?;
        let receipt: RootTransitionActivationReceipt =
            serde_json::from_value(value).map_err(|_| P07PortError::InvalidBinding)?;
        receipt
            .validate(request)
            .map_err(|error| map_transition_validation_error(&error))?;
        Ok(receipt)
    }
}

/// Adapts one transition's graph-snapshot identity to the retention-ledger
/// snapshot identity the typed P-07 errors carry, so a lost acknowledgement
/// names the exact snapshot the operation was presented under.
fn transition_snapshot_id(graph_snapshot_id: &str) -> Result<SnapshotId, P07PortError> {
    SnapshotId::new(graph_snapshot_id.to_owned()).map_err(|_| P07PortError::InvalidBinding)
}

/// Maps a refused transition receipt onto the typed P-07 vocabulary.
///
/// A receipt that does not commit the exact presented operation is an identity
/// conflict, never a silent success: the caller re-serves fresh state instead of
/// retrying the same operation under a new request.
fn map_transition_validation_error(error: &eliot_authority::AuthorityError) -> P07PortError {
    match error {
        eliot_authority::AuthorityError::IdentityConflict => P07PortError::IdentityConflict,
        eliot_authority::AuthorityError::P07Unavailable => P07PortError::Unavailable,
        _ => P07PortError::InvalidBinding,
    }
}

/// Validates the caller-side binding before any transport is touched: the
/// fence must be well-formed, the epoch must agree with the fence, and the
/// presented fence must be the currently active Kernel fence.
///
/// The three decisions are reported as three distinct typed I7.20 causes rather
/// than one `InvalidBinding`, because the code has already separated them: a
/// presentation that contradicts *itself* (`INVALID_ARGUMENT`, repair the
/// binding) is not the same failure as a well-formed presentation of a fence
/// that is not the current Kernel fence (`STALE_STATE_FENCE`, fail closed).
/// The principal/session/scope subject travels beside this binding and is
/// proved separately by [`KernelAuthorityClient::subject`], so neither check is
/// satisfied by the other.
fn check_binding(
    binding: &AuthorityBinding,
    active_fence: &StateFence,
) -> Result<(), P07PortError> {
    binding
        .state_fence
        .validate()
        .map_err(|_| P07PortError::Refused {
            cause: P07RefusalCause::StateFenceUnvalidated,
        })?;
    if binding.authority_epoch != binding.state_fence.authority_epoch {
        return Err(P07PortError::Refused {
            cause: P07RefusalCause::AuthorityEpochDisagreesWithFence,
        });
    }
    if binding.state_fence != *active_fence {
        return Err(P07PortError::Refused {
            cause: P07RefusalCause::StaleStateFence,
        });
    }
    Ok(())
}

/// Maps an authenticated-transport failure to the typed P-07 error:
/// - admission/session failures (including an unbound Kernel P-07 owner) refuse
///   the presented authority: `NotAdmitted`;
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

/// Decodes an answered P-07 route, checking for its typed refusal before
/// comparing the success receipt kind. A completed refusal is not a transport
/// loss and must not become `UnknownOutcome`.
///
/// A frame that answers with neither the typed refusal nor the receipt kind
/// this operation must return has a name of its own: the answer did not come
/// from the route that was presented.
fn p07_route_value(
    value: &serde_json::Value,
    receipt_kind: &str,
    operation: &str,
) -> Result<serde_json::Value, P07PortError> {
    if value.get("kind").and_then(serde_json::Value::as_str) == Some(P07_AUTHORITY_REFUSAL_KIND) {
        return Err(p07_refusal_error(value, operation));
    }
    kind_value(value, receipt_kind).map_err(|_| P07PortError::Refused {
        cause: P07RefusalCause::ResponseRouteMismatch,
    })
}

/// Accepts only the closed I7.20 disposition vocabulary the canonical protocol
/// enum defines, so a new or misspelled control value fails closed here too.
fn is_i720_disposition(value: &str) -> bool {
    serde_json::from_value::<eliot_protocol::AgentResponseDisposition>(serde_json::Value::String(
        value.to_owned(),
    ))
    .is_ok()
}

/// Projects one answered P-07 refusal frame onto the typed P-07 error.
///
/// The projection is strict in both directions. The frame must name the
/// operation that was presented, and a classified refusal must carry a typed
/// cause, the closed directive that cause establishes, a disposition the
/// canonical I7.20 enum defines, and a reason code the canonical additive
/// registry contains. Each vocabulary is checked rather than assumed, so a
/// frame this adapter cannot classify is reported as exactly that instead of
/// decaying into a generic `InvalidBinding`.
///
/// Refusals the Kernel could not classify keep their exact existing variant and
/// carry no I7.20 field at all: their producers sit behind a boundary the frame
/// cannot see, and no cause is invented to fill the gap.
fn p07_refusal_error(value: &serde_json::Value, expected_operation: &str) -> P07PortError {
    use eliot_authority::{P07RefusalCause as Cause, P07RefusalDirective as Directive};

    let refusal = value.get("value");
    let framed = |name: &str| refusal.and_then(|body| body.get(name));
    let framed_str = |name: &str| framed(name).and_then(serde_json::Value::as_str);
    let unclassifiable = || P07PortError::Refused {
        cause: Cause::RefusalFrameIncompatible,
    };
    if framed_str("operation") != Some(expected_operation) {
        return unclassifiable();
    }
    let snapshot = framed("snapshot_id");
    let carries_no_snapshot = snapshot.is_some_and(serde_json::Value::is_null);
    // A classified refusal is recognised only when all four of its I7.20 fields
    // are present and each belongs to the vocabulary it claims.
    let classified = match (
        framed_str("cause").and_then(Cause::from_wire),
        framed_str("directive").and_then(Directive::from_wire),
        framed_str("disposition").filter(|value| is_i720_disposition(value)),
        framed_str("reason_code")
            .filter(|value| eliot_protocol::agent_reason_code(value).is_some()),
    ) {
        (Some(cause), Some(directive), Some(_), Some(_)) => Some((cause, directive)),
        _ => None,
    };
    match framed_str("p07_error") {
        // Identity conflict keeps its exact variant and its absent snapshot; the
        // typed cause only states what the operator is already being told.
        Some(P07_ERROR_IDENTITY_CONFLICT)
            if carries_no_snapshot
                && classified
                    == Some((
                        Cause::OperationIdentityAlreadyCommitted,
                        Directive::ResubmitFromCurrentState,
                    )) =>
        {
            P07PortError::IdentityConflict
        }
        // A lost acknowledgement keeps its exact snapshot for reconciliation and
        // is never collapsed to unavailable or non-executed.
        Some(P07_ERROR_UNKNOWN_OUTCOME)
            if classified
                == Some((
                    Cause::CommitOutcomeUnproven,
                    Directive::ReconcileExactSnapshot,
                )) =>
        {
            let Some(snapshot_value) = snapshot.and_then(serde_json::Value::as_str) else {
                return unclassifiable();
            };
            let Ok(snapshot_id) = SnapshotId::new(snapshot_value.to_owned()) else {
                return unclassifiable();
            };
            P07PortError::UnknownOutcome { snapshot_id }
        }
        // Refusals whose cause the Kernel cannot see keep their exact variant.
        Some(P07_ERROR_INVALID_BINDING) if carries_no_snapshot && classified.is_none() => {
            P07PortError::InvalidBinding
        }
        Some(P07_ERROR_UNAVAILABLE) if carries_no_snapshot && classified.is_none() => {
            P07PortError::Unavailable
        }
        Some(P07_ERROR_NOT_ADMITTED) if carries_no_snapshot && classified.is_none() => {
            P07PortError::NotAdmitted
        }
        // The Kernel classified the refusal, so the exact typed cause crosses
        // the boundary instead of one generic code standing in for it.
        Some(P07_ERROR_REFUSED) => match classified {
            Some((cause, _)) => P07PortError::Refused { cause },
            None => unclassifiable(),
        },
        _ => unclassifiable(),
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

        // The binding gate runs before any transport, and keeps its three
        // decisions apart: a presentation that contradicts itself and a
        // well-formed presentation of a fence that is not the current Kernel
        // fence are different typed failures, neither of them a receipt.
        let mut stale_fence = fence.clone();
        stale_fence.resource_generation = ResourceGeneration::new(2).expect("resource generation");
        let mut stale_binding = test_binding(&fence);
        stale_binding.state_fence = stale_fence;
        assert!(matches!(
            check_binding(&stale_binding, &fence),
            Err(P07PortError::Refused {
                cause: P07RefusalCause::StaleStateFence
            })
        ));
        let mut split_binding = test_binding(&fence);
        split_binding.authority_epoch = test_epoch(2);
        assert!(matches!(
            check_binding(&split_binding, &fence),
            Err(P07PortError::Refused {
                cause: P07RefusalCause::AuthorityEpochDisagreesWithFence
            })
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
