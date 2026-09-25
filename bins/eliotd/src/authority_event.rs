//! Authenticated product-event ingress for production authority revocation.
//!
//! The periodic owner-feed trigger is a read/publish maintenance arm; it is
//! not an authority-revocation event and therefore never mints ingress
//! metadata. This module is the typed product-event boundary. The caller
//! supplies both admitted request identities and operation identities, and
//! the handler forwards the complete revocation ingress through the dedicated
//! P-07 adapter before running the owner-state persistence arm.

use std::sync::Arc;

use eliot_governor::{
    AuthorityOwnerStateIngress, AuthorityRevocationIngress, CompositionError,
    PendingEffectAdmission,
};
use eliot_store_api::{RevocationHistoryRoot, WriteReceipt};

use super::kernel_authority_client::KernelAuthorityClient;
use super::owner_feed::{OwnerFeedTrigger, maintain_owner_feed_with_product_event};
use super::{DaemonComposition, DaemonError, DaemonKernelClient};

/// Stable product-event kind for a complete authority-revocation ingress.
pub const AUTHORITY_REVOCATION_EVENT_KIND: &str = "authority.revoked";
/// Current product-event wire revision.
pub const AUTHORITY_REVOCATION_EVENT_VERSION: u16 = 1;

/// One authenticated product event carrying the complete revocation and
/// owner-state CAS witnesses required by the production fan-out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationProductEvent {
    /// Closed event discriminator.
    pub kind: String,
    /// Event wire revision.
    pub version: u16,
    /// Complete Store revocation ingress, including its authenticated identity.
    pub revocation: AuthorityRevocationIngress,
    /// Authenticated identity/CAS witness for the post-fan-out owner image.
    pub owner_state: AuthorityOwnerStateIngress,
}

impl AuthorityRevocationProductEvent {
    /// Validates the event envelope without minting or repairing any field.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.kind != AUTHORITY_REVOCATION_EVENT_KIND
            || self.version != AUTHORITY_REVOCATION_EVENT_VERSION
        {
            return Err(CompositionError::Provider(
                "authority revocation product event has an unsupported kind or version".to_owned(),
            ));
        }
        self.revocation
            .validate()
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        self.owner_state
            .validate()
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        if self.revocation.identity.request.state_fence
            != self.owner_state.identity.request.state_fence
            || self.revocation.operation_id == self.owner_state.operation_id
            || self.revocation.identity.request.metadata.request_id
                == self.owner_state.identity.request.metadata.request_id
            || self.revocation.identity.idempotency_key == self.owner_state.identity.idempotency_key
        {
            return Err(CompositionError::Provider(
                "authority revocation product event identities/operations are not distinct and fence-bound"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Outcome of one complete product event: the Store receipt for the
/// revocation row and the readback-proven owner publication revision/root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRevocationProductEventOutcome {
    /// Exact canonical Store receipt for the durable revocation record.
    pub revocation_receipt: WriteReceipt,
    /// Owner graph revision published after durable fan-out readback.
    pub owner_revision: u64,
    /// Shared Store history root observed by the fan-out.
    pub history_root: RevocationHistoryRoot,
}

/// Dispatches one authenticated product event through the production
/// revocation → owner-state persistence → owner-publication chain.
pub async fn dispatch_authority_revocation_product_event(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    owner_feed: &mut OwnerFeedTrigger,
    event: &AuthorityRevocationProductEvent,
) -> Result<AuthorityRevocationProductEventOutcome, DaemonError> {
    event.validate().map_err(DaemonError::Composition)?;
    let revocation_receipt = KernelAuthorityClient::new(Arc::clone(kernel))
        .record_authority_revocation(&event.revocation)
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;
    let (owner_revision, history_root) =
        maintain_owner_feed_with_product_event(composition, kernel, owner_feed, &event.owner_state)
            .await
            .map_err(DaemonError::Composition)?;
    Ok(AuthorityRevocationProductEventOutcome {
        revocation_receipt,
        owner_revision,
        history_root,
    })
}

/// Stable product-event kind for a real pending-effect admission.
pub const PENDING_EFFECT_ADMISSION_EVENT_KIND: &str = "authority.pending-effect";
/// Current pending-effect product-event wire revision.
pub const PENDING_EFFECT_ADMISSION_EVENT_VERSION: u16 = 1;

/// One authenticated product event carrying a real action lease/proposal and
/// the owner-state CAS identity required to persist the resulting effect.
#[derive(Clone, Debug)]
pub struct PendingEffectProductEvent {
    /// Closed event discriminator.
    pub kind: String,
    /// Event wire revision.
    pub version: u16,
    /// Product-supplied lease, proposal, WorkScope, Session, and executor data.
    pub admission: PendingEffectAdmission,
    /// Authenticated owner-state persistence witness.
    pub owner_state: AuthorityOwnerStateIngress,
}

impl PendingEffectProductEvent {
    /// Validates event shape and exact fence/session bindings without
    /// manufacturing any product input.
    pub fn validate(&self) -> Result<(), CompositionError> {
        if self.kind != PENDING_EFFECT_ADMISSION_EVENT_KIND
            || self.version != PENDING_EFFECT_ADMISSION_EVENT_VERSION
        {
            return Err(CompositionError::Provider(
                "pending-effect product event has an unsupported kind or version".to_owned(),
            ));
        }
        self.owner_state
            .validate()
            .map_err(|error| CompositionError::Provider(error.to_string()))?;
        let fence = &self.owner_state.identity.request.state_fence;
        if self.admission.action_lease.authority_binding.state_fence != *fence
            || self.admission.work_scope.state_fence != *fence
            || self.admission.session.state_fence != *fence
        {
            return Err(CompositionError::Provider(
                "pending-effect product event is not bound to its authenticated owner fence"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Dispatches one authenticated pending-effect product event and persists the
/// resulting Authority owner snapshot before returning the authorization.
pub async fn dispatch_pending_effect_product_event(
    composition: &mut DaemonComposition,
    event: &PendingEffectProductEvent,
) -> Result<eliot_authority::AuthorizedEffect, DaemonError> {
    event.validate().map_err(DaemonError::Composition)?;
    composition
        .admit_pending_effect_and_persist(&event.admission, &event.owner_state)
        .await
}

/// Closed authenticated product-event union consumed by the daemon runtime.
#[derive(Clone, Debug)]
pub enum AuthenticatedProductEvent {
    /// A complete authority-revocation event.
    AuthorityRevocation(AuthorityRevocationProductEvent),
    /// A real pending-effect admission event.
    PendingEffect(PendingEffectProductEvent),
}

/// Dispatches one event from the authenticated product-event lane.
pub async fn dispatch_authenticated_product_event(
    composition: &mut DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    owner_feed: &mut OwnerFeedTrigger,
    event: &AuthenticatedProductEvent,
) -> Result<(), DaemonError> {
    match event {
        AuthenticatedProductEvent::AuthorityRevocation(event) => {
            dispatch_authority_revocation_product_event(composition, kernel, owner_feed, event)
                .await
                .map(|_| ())
        }
        AuthenticatedProductEvent::PendingEffect(event) => {
            dispatch_pending_effect_product_event(composition, event)
                .await
                .map(|_| ())
        }
    }
}
