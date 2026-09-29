//! Kernel-owned, short-lived Operator binding over the authenticated User
//! Broker channel. The caller must supply the current owner registration read
//! from Kernel/ORS; a wire receipt is never its own authority.

use std::collections::BTreeMap;

use eliot_ipc::{PeerIdentity, Session, TransportError};
use eliot_platform_windows::fresh_activation_nonce_material;
use eliot_user_broker_core::{
    BrokerRedemption, OperatorBindingChallengeGrant, OperatorBindingChallengeRequest,
    OperatorBindingGrant, OperatorBindingPeer, OperatorBindingRedeemRequest,
    RegistrationReceipt, RegistrationStatus,
};

const BROKER_MODULE_ID: &str = "eliot-user-broker";
const OPERATOR_BINDING_TTL_MS: u64 = 30_000;

#[derive(Clone)]
struct PendingChallenge {
    request: OperatorBindingChallengeRequest,
    grant: OperatorBindingChallengeGrant,
    broker_connection_id: String,
}

#[derive(Clone)]
struct ActiveBinding {
    request: OperatorBindingRedeemRequest,
    grant: OperatorBindingGrant,
    redemption: BrokerRedemption,
    broker_connection_id: String,
}

/// One composition-local authority table. Restart drops every challenge and
/// session token; old UI state cannot revive the table.
#[derive(Default)]
pub(crate) struct KernelOperatorBindings {
    pending_by_context: BTreeMap<String, PendingChallenge>,
    active_by_token: BTreeMap<String, ActiveBinding>,
}

impl KernelOperatorBindings {
    /// Issues one fresh challenge after comparing the complete wire context
    /// against the owner registration and the OS-authenticated Broker peer.
    pub(crate) fn challenge(
        &mut self,
        request: OperatorBindingChallengeRequest,
        current: &RegistrationReceipt,
        broker_session: &Session,
        observed_at_ms: u64,
    ) -> Result<OperatorBindingChallengeGrant, TransportError> {
        request.validate().map_err(|_| TransportError::SessionFenced)?;
        validate_broker_context(&request.context.registration, current, broker_session, observed_at_ms)?;
        if request.context.endpoint_expires_at <= observed_at_ms {
            return Err(TransportError::SessionFenced);
        }
        self.prune(observed_at_ms);
        let context_digest = request.context.digest().map_err(|_| TransportError::SessionFenced)?;
        if let Some(existing) = self.pending_by_context.get(&context_digest) {
            if existing.request != request
                || existing.broker_connection_id != broker_session.connection_id
            {
                return Err(TransportError::IdentityConflict);
            }
            return Ok(existing.grant.clone());
        }
        let expires_at = observed_at_ms
            .checked_add(OPERATOR_BINDING_TTL_MS)
            .ok_or(TransportError::SessionFenced)?
            .min(request.context.endpoint_expires_at)
            .min(current.expires_at);
        if expires_at <= observed_at_ms {
            return Err(TransportError::SessionFenced);
        }
        let grant = OperatorBindingChallengeGrant {
            schema_version: 1,
            challenge_id: fresh_nonce()?,
            challenge_token: fresh_nonce()?,
            context_digest: context_digest.clone(),
            broker_registration_digest: current.registration_digest.clone(),
            expires_at,
        };
        grant.validate_for(&request, observed_at_ms)
            .map_err(|_| TransportError::SessionFenced)?;
        self.pending_by_context.insert(context_digest, PendingChallenge {
            request,
            grant: grant.clone(),
            broker_connection_id: broker_session.connection_id.clone(),
        });
        Ok(grant)
    }

    /// Consumes the exact challenge once. An exact reply retry returns the
    /// retained grant; changed context or token is a conflict.
    pub(crate) fn redeem(
        &mut self,
        request: OperatorBindingRedeemRequest,
        current: &RegistrationReceipt,
        broker_session: &Session,
        observed_at_ms: u64,
    ) -> Result<OperatorBindingGrant, TransportError> {
        request.validate(observed_at_ms).map_err(|_| TransportError::SessionFenced)?;
        validate_broker_context(&request.context.registration, current, broker_session, observed_at_ms)?;
        if let Some(active) = self.active_by_token.values().find(|active| {
            active.request.challenge.challenge_id == request.challenge.challenge_id
        }) {
            if active.request != request || active.broker_connection_id != broker_session.connection_id {
                return Err(TransportError::IdentityConflict);
            }
            return Ok(active.grant.clone());
        }
        let context_digest = request.context.digest().map_err(|_| TransportError::SessionFenced)?;
        let pending = self.pending_by_context.get(&context_digest)
            .ok_or(TransportError::SessionFenced)?;
        if pending.request.context != request.context
            || pending.grant != request.challenge
            || pending.broker_connection_id != broker_session.connection_id
        {
            return Err(TransportError::IdentityConflict);
        }
        let expires_at = observed_at_ms
            .checked_add(OPERATOR_BINDING_TTL_MS)
            .ok_or(TransportError::SessionFenced)?
            .min(current.expires_at)
            .min(request.context.endpoint_expires_at);
        if expires_at <= observed_at_ms {
            return Err(TransportError::SessionFenced);
        }
        let grant = OperatorBindingGrant {
            schema_version: 1,
            challenge_id: request.challenge.challenge_id.clone(),
            context_digest,
            kernel_session_token: fresh_nonce()?,
            expires_at,
        };
        grant.validate_for(&request, observed_at_ms)
            .map_err(|_| TransportError::SessionFenced)?;
        let redemption = BrokerRedemption::from_grant(&request, &grant, observed_at_ms)
            .map_err(|_| TransportError::SessionFenced)?;
        self.pending_by_context.remove(&grant.context_digest);
        self.active_by_token.insert(grant.kernel_session_token.clone(), ActiveBinding {
            request,
            grant: grant.clone(),
            redemption,
            broker_connection_id: broker_session.connection_id.clone(),
        });
        Ok(grant)
    }

    /// Validates a Governor-presented redemption against the original Kernel
    /// grant, current owner registration, and independently observed UI peer.
    pub(crate) fn validate_redemption(
        &mut self,
        presented: &BrokerRedemption,
        observed_peer: &OperatorBindingPeer,
        current: &RegistrationReceipt,
        observed_at_ms: u64,
    ) -> Result<(), TransportError> {
        presented.validate().map_err(|_| TransportError::SessionFenced)?;
        observed_peer.validate().map_err(|_| TransportError::SessionFenced)?;
        let active = self.active_by_token.get(&presented.kernel_session_token)
            .ok_or(TransportError::SessionFenced)?;
        if active.redemption != *presented
            || active.request.context.peer != *observed_peer
            || active.request.context.registration != *current
            || current.status != RegistrationStatus::Active
            || current.expires_at <= observed_at_ms
            || active.request.context.endpoint_expires_at <= observed_at_ms
            || active.grant.expires_at <= observed_at_ms
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    fn prune(&mut self, observed_at_ms: u64) {
        self.pending_by_context.retain(|_, value| value.grant.expires_at > observed_at_ms);
        self.active_by_token.retain(|_, value| value.grant.expires_at > observed_at_ms);
    }
}

fn validate_broker_context(
    presented: &RegistrationReceipt,
    current: &RegistrationReceipt,
    session: &Session,
    observed_at_ms: u64,
) -> Result<(), TransportError> {
    if session.module_generation.module_id.as_str() != BROKER_MODULE_ID
        || presented != current
        || current.status != RegistrationStatus::Active
        || current.expires_at <= observed_at_ms
        || !session.authority_epoch.is_same_authority(&current.authority_epoch)
    {
        return Err(TransportError::SessionFenced);
    }
    match &session.peer {
        PeerIdentity::Authenticated { process_id, user_identity, session_identity, .. }
            if user_identity == &current.windows_sid
                && session_identity == &current.interactive_session_id
                && current.broker_process_id == process_id.to_string() => Ok(()),
        _ => Err(TransportError::UnauthenticatedPeer),
    }
}

fn fresh_nonce() -> Result<String, TransportError> {
    fresh_activation_nonce_material()
        .map(|material| material.as_str().to_owned())
        .map_err(|_| TransportError::SessionFenced)
}
