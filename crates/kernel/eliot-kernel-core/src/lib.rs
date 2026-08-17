//! P-07 Kernel decision core: authority activation, fencing, generation
//! routing, control reserve, front-door admission and recovery state.
//!
//! This crate is the Kernel's *decision* core, not its transport, storage or
//! process mechanics. It owns:
//!
//! - private, non-forgeable authority issuance and consumption
//!   ([`KernelAuthority`], [`KernelAuthorityKey`], [`AuthorityReceipt`]);
//! - exact route fences with epoch binding ([`RouteFence`], [`RouteScope`])
//!   and epoch activation ([`EpochActivation`]);
//! - the runtime generation route table and cutover decisions
//!   ([`GenerationRouter`], [`CutoverDecision`]);
//! - the bounded control reserve and synchronous front door
//!   ([`ControlReserve`], [`FrontDoor`]);
//! - the role-filtered recovery view ([`RecoveryViewBuilder`]).
//!
//! [`KernelAuthority`] and [`RouteFence`] are the existing P-07 control-plane
//! capability family. They are intentionally not converted into, or accepted
//! as, P-03 process dispatch permits; process authority lives only in
//! [`ProcessDispatchAuthorityController`].
//!
//! The crate performs no model inference, no storage writes and no process
//! launch. It never contains a secret in a serializable, loggable or
//! transportable value: the private key is redacted and non-serializable, and
//! authority is only ever granted by the Kernel itself.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authority;
pub mod authority_controller;
pub mod error;
pub mod module;

pub use authority::{
    AuthorityGrant, AuthorityGrantRequest, AuthorityReceipt, KernelAuthority, KernelAuthorityKey,
};
pub use authority_controller::{
    AuthoritySnapshotBinding, DispatchSnapshotCodec, ProcessDispatchAuthorityController,
    ProcessExecutionReplayBegin, ProcessExecutionReplayRecord, ProcessExecutionReplayState,
    ProcessExecutionReplayStore, SealedAuthoritySnapshot, process_admission_digest,
};
pub use error::{KernelError, KernelResult};
pub use module::control_reserve_front_door::{
    AuthorityDecision, ControlPermit, ControlReserve, DecisionDenialReason, FrontDoor,
    IdempotencyDisposition, IdempotencyLedger,
};
pub use module::epoch_and_fence::{EpochActivation, RouteFence, RouteScope};
pub use module::generation_routing::{CutoverDecision, GenerationRoute, GenerationRouter};
pub use module::recovery_state_view::{RecoveryViewBuilder, project_operational_state};

use eliot_contracts::{
    ContractIdentity, ContractVersion, contract_identity as make_contract_identity,
};

/// Stable wire name for this contract family.
pub const CONTRACT_NAME: &str = "eliot.kernel.core";
/// Current wire revision for this contract family.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Returns the stable contract identity for schema/provenance handshakes.
///
/// # Errors
///
/// Returns an error when the canonical contract shape cannot be serialized.
pub fn contract_identity() -> Result<ContractIdentity, KernelError> {
    #[derive(serde::Serialize)]
    struct Shape {
        surface: &'static str,
        version: ContractVersion,
        authority_rule: &'static str,
        fence_rule: &'static str,
        receipt_rule: &'static str,
    }

    make_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "authority_fence_routing_control_recovery",
            version: CONTRACT_VERSION,
            authority_rule: "private_issuance_and_keyed_mac_consumption",
            fence_rule: "exact_route_and_epoch_binding",
            receipt_rule: "non_forgeable_and_idempotent",
        },
    )
    .map_err(KernelError::Foundation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_identity_is_stable_and_present() -> Result<(), KernelError> {
        let identity = contract_identity()?;
        assert_eq!(identity.name.as_str(), CONTRACT_NAME);
        assert!(!identity.shape_sha256.is_empty());
        Ok(())
    }

    #[test]
    fn authority_and_front_door_compose_end_to_end() -> Result<(), KernelError> {
        let key = KernelAuthorityKey::from_bytes([11u8; 32]);
        let authority = KernelAuthority::new(key, eliot_contracts::AuthorityEpoch::genesis());
        let receipt = authority.issue(AuthorityGrantRequest::new(
            eliot_contracts::ContractId::new("authority-1")?,
            "kernel",
            RouteScope::new("store_bridge")?,
            eliot_contracts::ResourceGeneration::genesis(),
            eliot_receipts::EffectClass::ReversibleMutation,
            eliot_receipts::ProofCeiling::ScopedVerification,
            1,
            None,
        )?)?;

        let front_door = FrontDoor::new(authority, 4, 16)?;
        let decision = front_door.authorize(
            &receipt,
            &RouteScope::new("store_bridge")?,
            50,
            "idem-1",
            "digest-1",
        )?;
        assert!(decision.is_granted());
        Ok(())
    }
}
