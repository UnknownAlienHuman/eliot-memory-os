//! Kernel lifecycle and admission state machine.

use std::fmt;

use eliot_contracts::{AuthorityEpoch, ContractId, ResourceGeneration};
use eliot_kernel_core::{
    AuthorityGrantRequest, ControlPermit, FrontDoor, KernelAuthority, KernelAuthorityKey,
    KernelError, RouteScope,
};
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{HostKernelHandshake, KernelControlCommand, KernelReadyReceipt};
use crate::validate_text;

/// Recovery may fast-forward to a durable epoch, but an unbounded value is
/// treated as corrupt rather than allowed to become an implicit replay loop.
const MAX_EPOCH_SYNC_GAP: u64 = 4_096;

/// Lifecycle states owned by the Kernel service.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KernelServiceState {
    /// No Host lineage has been admitted.
    Cold,
    /// Durable Host lineage is being reconciled.
    Reconciling,
    /// Candidate process is alive without authority.
    ShadowNoAuthority,
    /// Host has prepared the exclusive handoff.
    HandoffPrepared,
    /// One-time activation nonce is being consumed.
    Activating,
    /// Normal control admission is open.
    Ready,
    /// Process remains observable but normal admission is closed.
    Degraded,
    /// New work is closed and existing work is draining.
    Draining,
    /// The lineage stopped cleanly.
    Stopped,
    /// A bounded failure has closed admission.
    Failed,
    /// Automatic recovery is no longer permitted.
    ManualRecovery,
}

impl fmt::Display for KernelServiceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cold => "COLD",
            Self::Reconciling => "RECONCILING",
            Self::ShadowNoAuthority => "SHADOW_NO_AUTHORITY",
            Self::HandoffPrepared => "HANDOFF_PREPARED",
            Self::Activating => "ACTIVATING",
            Self::Ready => "READY",
            Self::Degraded => "DEGRADED",
            Self::Draining => "DRAINING",
            Self::Stopped => "STOPPED",
            Self::Failed => "FAILED",
            Self::ManualRecovery => "MANUAL_RECOVERY",
        })
    }
}

impl KernelServiceState {
    fn transition_to(self, next: Self) -> Result<Self, KernelServiceError> {
        let legal = matches!(
            (self, next),
            (Self::Cold | Self::Stopped, Self::Reconciling)
                | (Self::Failed, Self::Reconciling | Self::ManualRecovery)
                | (Self::Reconciling, Self::ShadowNoAuthority | Self::Failed)
                | (
                    Self::ShadowNoAuthority,
                    Self::HandoffPrepared | Self::Failed
                )
                | (Self::HandoffPrepared, Self::Activating | Self::Failed)
                | (
                    Self::Activating,
                    Self::Ready | Self::Degraded | Self::Failed
                )
                | (Self::Ready, Self::Degraded | Self::Draining | Self::Failed)
                | (Self::Degraded, Self::Ready | Self::Draining | Self::Failed)
                | (Self::Draining, Self::Stopped | Self::Failed)
        );
        legal
            .then_some(next)
            .ok_or(KernelServiceError::IllegalTransition {
                from: self,
                to: next,
            })
    }
}

/// A failure classification retained for recovery without raw process output.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceFailure {
    /// An external observation could not establish a current outcome.
    UnknownExternalState,
    /// The Host handoff did not match this candidate.
    HandoffMismatch,
    /// Readiness evidence did not prove the required postcondition.
    ReadinessNotProven,
    /// The restart budget has been exhausted.
    RestartBudgetExhausted,
    /// A stable provider or contract error occurred.
    Contract(String),
}

/// Kernel service operation failure. It contains no secret or process output.
#[derive(Debug, Error)]
pub enum KernelServiceError {
    /// A field failed bounded identity validation.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// A lifecycle transition is not admitted.
    #[error("illegal Kernel service transition from {from} to {to}")]
    IllegalTransition {
        /// Current state.
        from: KernelServiceState,
        /// Requested state.
        to: KernelServiceState,
    },
    /// A presented handshake does not match the active candidate.
    #[error("Host/Kernel handshake mismatch for {field}")]
    HandshakeMismatch {
        /// Mismatching field.
        field: &'static str,
    },
    /// A failed lineage cannot restart without Host containment evidence.
    #[error("Host containment evidence is required before replacing a failed Kernel lineage")]
    MissingContainmentEvidence,
    /// The readiness receipt did not prove all required dimensions.
    #[error("Kernel readiness was not proven")]
    ReadinessNotProven,
    /// The service is not allowed to admit normal work in its current state.
    #[error("normal admission is closed in Kernel state {0}")]
    AdmissionClosed(KernelServiceState),
    /// A post-commit publication failure fenced this service instance.
    #[error("generation authority is fenced until forward recovery")]
    GenerationFenced,
    /// The one-time restart budget is exhausted.
    #[error("Kernel restart budget exhausted")]
    RestartBudgetExhausted,
    /// The control reserve cannot accept another control operation.
    #[error("Kernel control reserve exhausted")]
    ControlReserveExhausted,
    /// A platform contract rejected a provider-neutral request.
    #[error("platform contract: {0}")]
    Platform(String),
    /// A Kernel decision-core error.
    #[error("Kernel decision core: {0}")]
    Core(#[from] KernelError),
}

/// A held admission lease backed by the Kernel control reserve.
#[derive(Debug)]
pub struct AdmissionLease {
    permit: ControlPermit,
    activation_id: String,
    authority_epoch: AuthorityEpoch,
}

impl AdmissionLease {
    /// Returns the activation identity covered by this lease.
    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    /// Returns the authority epoch covered by this lease.
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the opaque held permit for transition-gateway instrumentation.
    #[must_use]
    pub const fn control_permit(&self) -> &ControlPermit {
        &self.permit
    }

    /// Releases the bounded control capacity held by this lease.
    ///
    /// Dropping a lease also releases the permit; this explicit operation is
    /// provided for transition gateways that model release as a named step.
    pub fn release(self) {
        drop(self);
    }
}

/// The in-process Kernel service owner.
pub struct KernelService {
    state: KernelServiceState,
    authority: KernelAuthority,
    front_door: FrontDoor,
    handshake: Option<HostKernelHandshake>,
    ready: Option<KernelReadyReceipt>,
    failure: Option<ServiceFailure>,
    generation_fenced: bool,
}

impl KernelService {
    /// Creates a cold service with a private authority key and bounded control capacities.
    pub fn new(
        key_bytes: [u8; 32],
        control_capacity: usize,
        ledger_capacity: usize,
    ) -> Result<Self, KernelServiceError> {
        let authority = KernelAuthority::new(
            KernelAuthorityKey::from_bytes(key_bytes),
            AuthorityEpoch::genesis(),
        );
        Ok(Self {
            state: KernelServiceState::Cold,
            front_door: FrontDoor::new(authority.clone(), control_capacity, ledger_capacity)?,
            authority,
            handshake: None,
            ready: None,
            failure: None,
            generation_fenced: false,
        })
    }

    /// Returns the current service state.
    pub const fn state(&self) -> KernelServiceState {
        self.state
    }

    /// Returns the active authority epoch.
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.front_door.epoch()
    }

    /// Returns the available bounded control capacity.
    pub fn available_control(&self) -> usize {
        self.front_door.available_control()
    }

    /// Returns the last failure classification, if the service is failed.
    pub fn failure(&self) -> Option<&ServiceFailure> {
        self.failure.as_ref()
    }

    /// Returns the accepted Host handshake, if a lineage is present.
    pub fn handshake(&self) -> Option<&HostKernelHandshake> {
        self.handshake.as_ref()
    }

    /// Returns the readiness receipt, if normal admission is open.
    pub fn ready_receipt(&self) -> Option<&KernelReadyReceipt> {
        self.ready.as_ref()
    }

    /// Returns whether generation publication has fenced this service
    /// instance pending restart or forward recovery.
    pub const fn generation_fenced(&self) -> bool {
        self.generation_fenced
    }

    /// Closes service admission after a durable generation commit could not
    /// be published consistently.  The failure is retained as evidence and
    /// cannot be cleared by an in-process lifecycle command.
    pub fn fence_generation(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<(), KernelServiceError> {
        let reason = reason.into();
        validate_text(&reason, "generation_fence.reason")?;
        self.generation_fenced = true;
        self.failure = Some(ServiceFailure::Contract(reason));
        if matches!(
            self.state,
            KernelServiceState::Reconciling
                | KernelServiceState::ShadowNoAuthority
                | KernelServiceState::HandoffPrepared
                | KernelServiceState::Activating
                | KernelServiceState::Ready
                | KernelServiceState::Degraded
                | KernelServiceState::Draining
        ) {
            self.transition(KernelServiceState::Failed)?;
        }
        Ok(())
    }

    /// Applies one lifecycle command through the single Kernel transition boundary.
    pub fn apply(
        &mut self,
        command: KernelControlCommand,
    ) -> Result<KernelServiceState, KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        match command {
            KernelControlCommand::Reconcile(handshake) => self.reconcile(handshake)?,
            KernelControlCommand::Shadow => {
                self.transition(KernelServiceState::ShadowNoAuthority)?;
            }
            KernelControlCommand::PrepareHandoff => {
                self.transition(KernelServiceState::HandoffPrepared)?;
            }
            KernelControlCommand::Activate => self.transition(KernelServiceState::Activating)?,
            KernelControlCommand::Ready(receipt) => self.mark_ready(receipt)?,
            KernelControlCommand::Degrade(reason) => {
                validate_text(reason.as_str(), "degrade.reason")?;
                self.transition(KernelServiceState::Degraded)?;
                self.failure = Some(ServiceFailure::Contract(reason.as_str().to_owned()));
            }
            KernelControlCommand::Drain => self.transition(KernelServiceState::Draining)?,
            KernelControlCommand::Stop => self.transition(KernelServiceState::Stopped)?,
            KernelControlCommand::Fail(reason) => {
                validate_text(reason.as_str(), "failure.reason")?;
                self.transition(KernelServiceState::Failed)?;
                self.failure = Some(ServiceFailure::Contract(reason.as_str().to_owned()));
            }
        }
        Ok(self.state)
    }

    /// Reconciles and pins a new Host installation lineage.
    pub fn reconcile(&mut self, handshake: HostKernelHandshake) -> Result<(), KernelServiceError> {
        handshake.validate()?;
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.state == KernelServiceState::Failed && handshake.containment_action.is_none() {
            return Err(KernelServiceError::MissingContainmentEvidence);
        }
        if matches!(
            self.state,
            KernelServiceState::Ready | KernelServiceState::Draining
        ) {
            return Err(KernelServiceError::IllegalTransition {
                from: self.state,
                to: KernelServiceState::Reconciling,
            });
        }
        self.transition(KernelServiceState::Reconciling)?;
        self.handshake = Some(handshake);
        self.ready = None;
        self.failure = None;
        Ok(())
    }

    /// Publishes a readiness receipt after exact handshake and health checks.
    pub fn mark_ready(&mut self, receipt: KernelReadyReceipt) -> Result<(), KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        let handshake = self
            .handshake
            .as_ref()
            .ok_or(KernelServiceError::HandshakeMismatch {
                field: "missing_handshake",
            })?;
        if self.state != KernelServiceState::Activating {
            return Err(KernelServiceError::IllegalTransition {
                from: self.state,
                to: KernelServiceState::Ready,
            });
        }
        receipt.validate(handshake)?;
        self.ready = Some(receipt);
        self.failure = None;
        self.transition(KernelServiceState::Ready)?;
        Ok(())
    }

    /// Raises the Kernel authority epoch, fencing every previously issued receipt.
    pub fn advance_authority_epoch(&mut self) -> Result<AuthorityEpoch, KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.authority.current_epoch() != self.front_door.epoch() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch",
            });
        }
        let epoch = self.front_door.advance_epoch()?;
        let mirrored = self.authority.advance_epoch()?;
        if epoch != mirrored {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch",
            });
        }
        Ok(epoch)
    }

    /// Replays the durable epoch lineage before admitting a front-door
    /// session.  Epochs may only move forward; a durable regression is a
    /// startup fence rather than an implicit genesis reset.
    pub fn synchronize_authority_epoch(
        &mut self,
        target: AuthorityEpoch,
    ) -> Result<(), KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        let current = self.authority_epoch();
        if self.authority.current_epoch() != current {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch",
            });
        }
        if target.value() < current.value() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch_regression",
            });
        }
        let gap = target.value().checked_sub(current.value()).ok_or(
            KernelServiceError::HandshakeMismatch {
                field: "authority_epoch_corrupt",
            },
        )?;
        if gap > MAX_EPOCH_SYNC_GAP {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch_oversized",
            });
        }
        let front_door_epoch = self.front_door.synchronize_epoch(target)?;
        let mirrored = self.authority.synchronize_epoch(target)?;
        if front_door_epoch != mirrored || mirrored != target {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch",
            });
        }
        Ok(())
    }

    /// Acquires one bounded control lease for a normal admitted operation.
    pub fn acquire_admission(&self) -> Result<AdmissionLease, KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(self.state));
        }
        let handshake = self
            .handshake
            .as_ref()
            .ok_or(KernelServiceError::AdmissionClosed(self.state))?;
        let permit = self
            .front_door
            .acquire_control()
            .map_err(|error| match error {
                KernelError::ControlReserveExhausted => KernelServiceError::ControlReserveExhausted,
                other => KernelServiceError::Core(other),
            })?;
        Ok(AdmissionLease {
            permit,
            activation_id: handshake.activation_id.as_str().to_owned(),
            authority_epoch: self.front_door.epoch(),
        })
    }

    /// Issues one scoped authority receipt for a control-plane caller.
    pub fn issue_control_receipt(
        &self,
        authority_id: ContractId,
        route: RouteScope,
        now_ms: i64,
        expiry_ms: Option<i64>,
    ) -> Result<eliot_kernel_core::AuthorityReceipt, KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.state != KernelServiceState::Ready {
            return Err(KernelServiceError::AdmissionClosed(self.state));
        }
        let _permit = self
            .front_door
            .acquire_control()
            .map_err(|error| match error {
                KernelError::ControlReserveExhausted => KernelServiceError::ControlReserveExhausted,
                other => KernelServiceError::Core(other),
            })?;
        let generation = ResourceGeneration::genesis();
        let request = AuthorityGrantRequest::new(
            authority_id,
            "kernel-service",
            route,
            generation,
            EffectClass::ReversibleMutation,
            ProofCeiling::ScopedVerification,
            now_ms,
            expiry_ms,
        )?;
        self.authority.issue(request).map_err(Into::into)
    }

    fn transition(&mut self, next: KernelServiceState) -> Result<(), KernelServiceError> {
        self.state = self.state.transition_to(next)?;
        Ok(())
    }
}

// Keep the public surface intentionally small: authority receipts are issued
// only through the service and never by a transport or platform adapter.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_epoch_sync_is_direct_and_rejects_oversized_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([7; 32], 2, 4)?;
        service.synchronize_authority_epoch(AuthorityEpoch::new(100)?)?;
        assert_eq!(service.authority_epoch(), AuthorityEpoch::new(100)?);
        let oversized = AuthorityEpoch::new(4_300)?;
        assert!(matches!(
            service.synchronize_authority_epoch(oversized),
            Err(KernelServiceError::HandshakeMismatch {
                field: "authority_epoch_oversized"
            })
        ));
        Ok(())
    }

    #[test]
    fn generation_fence_blocks_lifecycle_and_admission_until_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([9; 32], 2, 4)?;
        service.fence_generation("publication failed")?;
        assert!(service.generation_fenced());
        assert!(matches!(
            service.apply(KernelControlCommand::Shadow),
            Err(KernelServiceError::GenerationFenced)
        ));
        assert!(matches!(
            service.acquire_admission(),
            Err(KernelServiceError::GenerationFenced)
        ));
        Ok(())
    }
}
