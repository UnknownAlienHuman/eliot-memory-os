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

use crate::protocol::{
    HostKernelCandidateBinding, KernelActivationPermit, KernelActivationQuery,
    KernelActivationReceipt, KernelControlCommand, KernelReadyReceipt,
};
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
    candidate: Option<HostKernelCandidateBinding>,
    activation_receipt: Option<KernelActivationReceipt>,
    activation_request_digest: Option<String>,
    ready: Option<KernelReadyReceipt>,
    failure: Option<ServiceFailure>,
    generation_fenced: bool,
    store_rebind_receipt: Option<crate::protocol::StoreRebindReceipt>,
    store_rebind_request_digest: Option<String>,
    /// Receipts from completed Store-only rebinds in this Kernel lineage.
    /// They remain queryable by exact operation/request identity without
    /// reopening the old gateway.
    store_rebind_history: Vec<crate::protocol::StoreRebindReceipt>,
    /// The prior committed receipt retained while a replacement is degraded
    /// but not yet durably committed.  Recovery restores it instead of
    /// pretending that a maybe-durable replacement was rolled back.
    store_rebind_previous: Option<(crate::protocol::StoreRebindReceipt, String)>,
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
            candidate: None,
            activation_receipt: None,
            activation_request_digest: None,
            ready: None,
            failure: None,
            generation_fenced: false,
            store_rebind_receipt: None,
            store_rebind_request_digest: None,
            store_rebind_history: Vec::new(),
            store_rebind_previous: None,
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

    /// Returns the accepted nonce-free candidate binding, if present.
    pub fn candidate_binding(&self) -> Option<&HostKernelCandidateBinding> {
        self.candidate.as_ref()
    }

    /// Returns the exact consumed activation receipt, if present.
    pub fn activation_receipt(&self) -> Option<&KernelActivationReceipt> {
        self.activation_receipt.as_ref()
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
            KernelControlCommand::BootstrapStore(_) => {
                return Err(KernelServiceError::InvalidField {
                    field: "store_bootstrap",
                    reason: "Store bootstrap requires the authenticated Kernel composition boundary",
                });
            }
            KernelControlCommand::Reconcile => {
                return Err(KernelServiceError::InvalidField {
                    field: "candidate",
                    reason: "Reconcile requires the request candidate binding",
                });
            }
            KernelControlCommand::Shadow => {
                self.transition(KernelServiceState::ShadowNoAuthority)?;
            }
            KernelControlCommand::PrepareHandoff => {
                self.transition(KernelServiceState::HandoffPrepared)?;
            }
            KernelControlCommand::Activate(_) => {
                return Err(KernelServiceError::InvalidField {
                    field: "activation_permit",
                    reason: "Activate requires the authenticated request boundary",
                });
            }
            KernelControlCommand::ReconcileActivation(_) => {
                return Err(KernelServiceError::InvalidField {
                    field: "activation_query",
                    reason: "activation reconciliation requires the authenticated request boundary",
                });
            }
            KernelControlCommand::RebindStore(_) => {
                return Err(KernelServiceError::InvalidField {
                    field: "store_rebind",
                    reason: "Store rebind requires the authenticated Kernel composition boundary",
                });
            }
            KernelControlCommand::ReconcileRebindStore(_) => {
                return Err(KernelServiceError::InvalidField {
                    field: "store_rebind_query",
                    reason: "Store rebind reconciliation requires the authenticated request boundary",
                });
            }
            KernelControlCommand::ProbeReady => {
                // A wire command cannot carry a caller-shaped readiness
                // receipt. The composition root must perform live
                // observations and call `publish_ready` with its own receipt.
                return Err(KernelServiceError::ReadinessNotProven);
            }
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
    pub fn reconcile(
        &mut self,
        candidate: HostKernelCandidateBinding,
    ) -> Result<(), KernelServiceError> {
        candidate.validate()?;
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.state == KernelServiceState::Failed && candidate.containment_action.is_none() {
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
        self.candidate = Some(candidate);
        self.activation_receipt = None;
        self.activation_request_digest = None;
        self.ready = None;
        self.failure = None;
        Ok(())
    }

    /// Consumes one exact permit after its durable Host append is committed.
    pub fn activate_permit(
        &mut self,
        permit: &KernelActivationPermit,
        generation: ResourceGeneration,
        request_digest: String,
    ) -> Result<KernelActivationReceipt, KernelServiceError> {
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(KernelServiceError::HandshakeMismatch {
                field: "missing_candidate",
            })?;
        permit.validate(candidate, generation)?;
        if self.activation_receipt.is_some() || self.activation_request_digest.is_some() {
            return Err(KernelServiceError::InvalidField {
                field: "activation_permit",
                reason: "activation permit was already consumed",
            });
        }
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "activation_request_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        self.transition(KernelServiceState::Activating)?;
        let receipt = KernelActivationReceipt::issue(permit);
        self.activation_receipt = Some(receipt.clone());
        self.activation_request_digest = Some(request_digest);
        Ok(receipt)
    }

    /// Reconciles an unknown Activate delivery without accepting the permit again.
    pub fn reconcile_activation(
        &self,
        query: &KernelActivationQuery,
    ) -> Result<Option<KernelActivationReceipt>, KernelServiceError> {
        query.validate()?;
        match (
            self.activation_receipt.as_ref(),
            self.activation_request_digest.as_deref(),
        ) {
            (Some(receipt), Some(digest))
                if receipt.operation_id == query.operation_id
                    && digest == query.activate_request_digest =>
            {
                Ok(Some(receipt.clone()))
            }
            (None, None) => Ok(None),
            _ => Err(KernelServiceError::HandshakeMismatch {
                field: "activation_query",
            }),
        }
    }

    /// Admits a Store-only same-lineage rebind without restarting Kernel.
    ///
    /// Validates the immutable requirement, fresh Store process/Job, current
    /// candidate/generation/authority epoch and Store fence, transitions
    /// `Ready -> Degraded`, preserves PID/start/Job, authority epoch,
    /// generation and consumed activation nonce, and returns a bound receipt
    /// without clearing initial one-shot flags.
    pub fn rebind_store(
        &mut self,
        handoff: &crate::protocol::StoreRebindHandoff,
        request_digest: String,
    ) -> Result<crate::protocol::StoreRebindReceipt, KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        if self.state != KernelServiceState::Ready {
            return Err(KernelServiceError::IllegalTransition {
                from: self.state,
                to: KernelServiceState::Degraded,
            });
        }
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(KernelServiceError::HandshakeMismatch {
                field: "missing_candidate",
            })?;
        if self.activation_receipt.is_none() || self.activation_request_digest.is_none() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "missing_activation",
            });
        }
        handoff.validate()?;
        if handoff.candidate_binding_digest != candidate.compute_digest()? {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.candidate_binding",
            });
        }
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.request_digest",
            });
        }
        if self.store_rebind_receipt.is_some() || self.store_rebind_request_digest.is_some() {
            if self.store_rebind_request_digest.as_deref() == Some(request_digest.as_str())
                && self.store_rebind_receipt.as_ref().is_some_and(|r| {
                    r.operation_id == handoff.operation_id && r.request_digest == request_digest
                })
                && let Some(receipt) = self.store_rebind_receipt.clone()
            {
                return Ok(receipt);
            }
            if self.state != KernelServiceState::Ready {
                return Err(KernelServiceError::InvalidField {
                    field: "store_rebind.operation_id",
                    reason: "Store rebind already consumed for this lineage",
                });
            }
            let previous_receipt =
                self.store_rebind_receipt
                    .take()
                    .ok_or(KernelServiceError::HandshakeMismatch {
                        field: "store_rebind.receipt",
                    })?;
            let previous_digest = self.store_rebind_request_digest.take().ok_or(
                KernelServiceError::HandshakeMismatch {
                    field: "store_rebind.request_digest",
                },
            )?;
            if self.store_rebind_previous.is_some() {
                return Err(KernelServiceError::InvalidField {
                    field: "store_rebind.operation_id",
                    reason: "another Store rebind is already in recovery",
                });
            }
            self.store_rebind_previous = Some((previous_receipt, previous_digest));
        }
        self.transition(KernelServiceState::Degraded)?;
        self.ready = None;
        self.failure = Some(ServiceFailure::Contract(
            "store-rebind:degraded-for-fence".to_owned(),
        ));
        let requirement_digest = handoff.compute_requirement_digest()?;
        let receipt = crate::protocol::StoreRebindReceipt {
            operation_id: handoff.operation_id.clone(),
            request_digest: request_digest.clone(),
            requirement_digest,
            process_binding: handoff.process_binding.clone(),
            candidate_binding_digest: handoff.candidate_binding_digest.clone(),
            generation: handoff.generation,
            authority_epoch: handoff.authority_epoch,
            store_fence: handoff.store_fence.clone(),
        };
        receipt.validate()?;
        self.store_rebind_receipt = Some(receipt.clone());
        self.store_rebind_request_digest = Some(request_digest);
        Ok(receipt)
    }

    /// Reconciles an unknown Store rebind delivery without resending authority.
    pub fn reconcile_store_rebind(
        &self,
        query: &crate::protocol::StoreRebindQuery,
    ) -> Result<Option<crate::protocol::StoreRebindReceipt>, KernelServiceError> {
        query.validate()?;
        let mut known_operation = false;
        if let (Some(receipt), Some(digest)) = (
            self.store_rebind_receipt.as_ref(),
            self.store_rebind_request_digest.as_deref(),
        ) && receipt.operation_id == query.operation_id
        {
            known_operation = true;
            if digest == query.request_digest {
                return Ok(Some(receipt.clone()));
            }
        }
        if let Some((receipt, digest)) = &self.store_rebind_previous
            && receipt.operation_id == query.operation_id
        {
            known_operation = true;
            if digest == &query.request_digest {
                return Ok(Some(receipt.clone()));
            }
        }
        if let Some(receipt) = self
            .store_rebind_history
            .iter()
            .find(|receipt| receipt.operation_id == query.operation_id)
        {
            known_operation = true;
            if receipt.request_digest == query.request_digest {
                return Ok(Some(receipt.clone()));
            }
        }
        if !known_operation
            && self.store_rebind_receipt.is_none()
            && self.store_rebind_request_digest.is_none()
            && self.store_rebind_previous.is_none()
            && self.store_rebind_history.is_empty()
        {
            return Ok(None);
        }
        Err(KernelServiceError::HandshakeMismatch {
            field: "store_rebind_query",
        })
    }

    /// Marks the current Store rebind durable and retires the previous
    /// gateway receipt into exact-identity history.
    pub fn commit_store_rebind(&mut self) -> Result<(), KernelServiceError> {
        if let Some((previous, _digest)) = self.store_rebind_previous.take()
            && !self
                .store_rebind_history
                .iter()
                .any(|receipt| receipt.operation_id == previous.operation_id)
        {
            self.store_rebind_history.push(previous);
        }
        Ok(())
    }

    /// Returns the last Store rebind receipt, if any.
    pub fn store_rebind_receipt(&self) -> Option<&crate::protocol::StoreRebindReceipt> {
        self.store_rebind_receipt.as_ref()
    }

    /// Restores a durable Store rebind receipt before control admission.
    pub fn restore_store_rebind_for_recovery(
        &mut self,
        receipt: crate::protocol::StoreRebindReceipt,
        request_digest: String,
    ) -> Result<(), KernelServiceError> {
        receipt.validate()?;
        if request_digest != receipt.request_digest {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.request_digest",
            });
        }
        if self.store_rebind_receipt.is_some() || self.store_rebind_request_digest.is_some() {
            if self.store_rebind_receipt.as_ref() == Some(&receipt)
                && self.store_rebind_request_digest.as_deref() == Some(request_digest.as_str())
            {
                return Ok(());
            }
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind.operation_id",
                reason: "Store rebind already consumed for this lineage",
            });
        }
        self.store_rebind_receipt = Some(receipt);
        self.store_rebind_request_digest = Some(request_digest);
        if self.state == KernelServiceState::Ready {
            self.transition(KernelServiceState::Degraded)?;
            self.ready = None;
            self.failure = Some(ServiceFailure::Contract(
                "store-rebind:recovered-degraded".to_owned(),
            ));
        }
        Ok(())
    }

    /// Rolls back an uncommitted Store rebind after a durability failure.
    pub fn rollback_store_rebind_for_recovery_failure(&mut self) {
        let had_rebind = self.store_rebind_previous.is_some()
            || self.store_rebind_receipt.is_some()
            || self.store_rebind_request_digest.is_some();
        if let Some((previous, previous_digest)) = self.store_rebind_previous.take() {
            self.store_rebind_receipt = Some(previous);
            self.store_rebind_request_digest = Some(previous_digest);
        } else if self.store_rebind_receipt.is_some() || self.store_rebind_request_digest.is_some()
        {
            self.store_rebind_receipt = None;
            self.store_rebind_request_digest = None;
        }
        if had_rebind
            && self.state == KernelServiceState::Degraded
            && self.failure.as_ref().is_some_and(|f| {
                matches!(f, ServiceFailure::Contract(s) if s == "store-rebind:degraded-for-fence")
            })
        {
            let _ = self.transition(KernelServiceState::Ready);
            self.failure = None;
        }
    }

    /// Publishes an initial, repeated, or recovery readiness receipt after
    /// exact candidate, activation receipt, and health checks.
    pub fn mark_ready(&mut self, receipt: KernelReadyReceipt) -> Result<(), KernelServiceError> {
        if self.generation_fenced {
            return Err(KernelServiceError::GenerationFenced);
        }
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(KernelServiceError::HandshakeMismatch {
                field: "missing_candidate",
            })?;
        let activation = self
            .activation_receipt
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if !matches!(
            self.state,
            KernelServiceState::Activating
                | KernelServiceState::Ready
                | KernelServiceState::Degraded
        ) {
            return Err(KernelServiceError::IllegalTransition {
                from: self.state,
                to: KernelServiceState::Ready,
            });
        }
        receipt.validate(candidate, activation)?;
        self.ready = Some(receipt);
        self.failure = None;
        if self.state != KernelServiceState::Ready {
            self.transition(KernelServiceState::Ready)?;
        }
        Ok(())
    }

    /// Publishes a receipt authored by the Kernel composition after its live
    /// process, Job, authority, configuration, and Store observations pass.
    ///
    /// The receipt type remains private to the Kernel-owned composition path
    /// on the control wire: `ProbeReady` carries no receipt payload.
    pub fn publish_ready(&mut self, receipt: KernelReadyReceipt) -> Result<(), KernelServiceError> {
        self.mark_ready(receipt)
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
        let candidate = self
            .candidate
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
            activation_id: candidate.activation_id.as_str().to_owned(),
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
    use crate::protocol::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostProcessBinding,
        ProcessObservation, RestartBudget, StoreProcessBinding, StoreRebindHandoff,
        StoreRebindQuery,
    };
    use eliot_contracts::StateFence;
    use eliot_platform::{KernelActivationNonce, PlatformHandle};
    use eliot_runtime_contracts::{HealthVector, ServiceProcessState};

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| unreachable!())
    }

    fn candidate() -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: handle("installation-1"),
            host_epoch: AuthorityEpoch::new(1).unwrap_or_else(|_| unreachable!()),
            kernel_epoch: AuthorityEpoch::genesis(),
            activation_id: handle("activation-1"),
            artifact_hash: handle("artifact-1"),
            config_hash: handle("config-1"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle(crate::protocol::KERNEL_CONTROL_PIPE),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\\\eliot\\\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\\\eliot\\\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            restart_budget: RestartBudget::new(1, 1).unwrap_or_else(|_| unreachable!()),
            containment_action: None,
        }
    }

    fn permit(candidate: &HostKernelCandidateBinding) -> KernelActivationPermit {
        KernelActivationPermit {
            operation_id: handle("activation-operation-1"),
            candidate_binding_digest: candidate
                .compute_digest()
                .unwrap_or_else(|_| unreachable!()),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("journal-transaction-1"),
            journal_sequence: 7,
            generation: ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch,
            activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
                .unwrap_or_else(|_| unreachable!()),
        }
    }

    fn ready_receipt(
        candidate: &HostKernelCandidateBinding,
        activation: &KernelActivationReceipt,
        evidence: &str,
    ) -> KernelReadyReceipt {
        KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("process-evidence")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle(evidence)],
        }
    }

    fn rebind_handoff(
        candidate: &HostKernelCandidateBinding,
        operation: &str,
        process_id: u32,
    ) -> StoreRebindHandoff {
        let generation = ResourceGeneration::new(1).unwrap_or_else(|_| unreachable!());
        let authority_epoch = AuthorityEpoch::new(1).unwrap_or_else(|_| unreachable!());
        let requirement = crate::protocol::HostStoreBootstrapRequirement {
            route_identity: handle(crate::STORE_ROUTE_IDENTITY),
            canonical_pipe_identity: handle(r"\\.\pipe\eliot\store"),
            store_generation: generation,
            state_fence: StateFence::new(authority_epoch, generation),
            launch_nonce: handle("store-launch-nonce"),
            connection_id: handle("store-connection"),
            expected_peer_sid: handle("S-1-5-18"),
            expected_peer_session_id: 0,
            approved_artifact_hash: handle(&"a".repeat(64)),
            approved_config_hash: handle(&"b".repeat(64)),
            timeout_ms: 5_000,
        };
        let mut handoff = StoreRebindHandoff {
            operation_id: handle(operation),
            request_digest: "0".repeat(64),
            requirement,
            process_binding: StoreProcessBinding {
                process: HostProcessBinding {
                    process_id,
                    start_time_100ns: u64::from(process_id) + 100,
                    image_path: format!(r"C:\Eliot\store-{process_id}.exe"),
                },
                job: handle("Local\\Eliot-Store-test"),
            },
            candidate_binding_digest: candidate
                .compute_digest()
                .unwrap_or_else(|_| unreachable!()),
            generation,
            authority_epoch,
            store_fence: format!("{process_id:0>64}"),
        };
        handoff.request_digest = handoff
            .canonical_request_digest()
            .unwrap_or_else(|_| unreachable!());
        handoff
    }

    fn activate(
        service: &mut KernelService,
        candidate: HostKernelCandidateBinding,
    ) -> KernelActivationReceipt {
        let permit = permit(&candidate);
        service
            .reconcile(candidate)
            .unwrap_or_else(|_| unreachable!());
        service
            .apply(KernelControlCommand::Shadow)
            .unwrap_or_else(|_| unreachable!());
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .unwrap_or_else(|_| unreachable!());
        service
            .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn activation_is_consumed_once_and_unknown_delivery_reconciles_by_operation() {
        let mut service = KernelService::new([5; 32], 2, 4).unwrap_or_else(|_| unreachable!());
        let candidate = candidate();
        let permit = permit(&candidate);
        service
            .reconcile(candidate)
            .unwrap_or_else(|_| unreachable!());
        service
            .apply(KernelControlCommand::Shadow)
            .unwrap_or_else(|_| unreachable!());
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .unwrap_or_else(|_| unreachable!());
        let digest = "d".repeat(64);
        let receipt = service
            .activate_permit(&permit, ResourceGeneration::genesis(), digest.clone())
            .unwrap_or_else(|_| unreachable!());
        assert!(
            service
                .activate_permit(&permit, ResourceGeneration::genesis(), digest.clone())
                .is_err()
        );
        let reconciled = service
            .reconcile_activation(&KernelActivationQuery {
                operation_id: permit.operation_id.clone(),
                activate_request_digest: digest.clone(),
            })
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(reconciled, Some(receipt));
        assert!(
            service
                .reconcile_activation(&KernelActivationQuery {
                    operation_id: permit.operation_id,
                    activate_request_digest: "e".repeat(64),
                })
                .is_err()
        );
    }

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

    #[test]
    fn probe_ready_never_accepts_a_caller_receipt() -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([11; 32], 2, 4)?;
        assert!(matches!(
            service.apply(KernelControlCommand::ProbeReady),
            Err(KernelServiceError::ReadinessNotProven)
        ));
        assert_eq!(service.state(), KernelServiceState::Cold);
        Ok(())
    }

    #[test]
    fn ready_probe_replaces_receipt_without_reactivation_or_epoch_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([13; 32], 2, 4)?;
        let candidate = candidate();
        let activation = activate(&mut service, candidate.clone());
        let initial = ready_receipt(&candidate, &activation, "ready-initial");
        service.publish_ready(initial)?;
        let epoch = service.authority_epoch();
        let retained_candidate = service.candidate_binding().cloned();

        let repeated = ready_receipt(&candidate, &activation, "ready-repeat");
        service.publish_ready(repeated.clone())?;

        assert_eq!(service.state(), KernelServiceState::Ready);
        assert_eq!(service.ready_receipt(), Some(&repeated));
        assert_eq!(service.authority_epoch(), epoch);
        assert_eq!(service.candidate_binding(), retained_candidate.as_ref());
        assert_eq!(service.activation_receipt(), Some(&activation));
        Ok(())
    }

    #[test]
    fn degraded_probe_recovers_only_after_fresh_full_receipt()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([15; 32], 2, 4)?;
        let candidate = candidate();
        let activation = activate(&mut service, candidate.clone());
        service.publish_ready(ready_receipt(&candidate, &activation, "ready-initial"))?;
        service.apply(KernelControlCommand::Degrade(handle("store-lost")))?;
        assert_eq!(service.state(), KernelServiceState::Degraded);

        let recovery = ready_receipt(&candidate, &activation, "ready-recovery");
        service.publish_ready(recovery.clone())?;

        assert_eq!(service.state(), KernelServiceState::Ready);
        assert_eq!(service.ready_receipt(), Some(&recovery));
        assert!(service.failure().is_none());
        Ok(())
    }

    #[test]
    fn store_rebind_repeat_preserves_exact_history_and_rolls_back_uncommitted_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = KernelService::new([19; 32], 2, 4)?;
        let mut candidate = candidate();
        candidate.kernel_epoch = AuthorityEpoch::new(1)?;
        let activation = activate(&mut service, candidate.clone());
        service.publish_ready(ready_receipt(&candidate, &activation, "ready-initial"))?;

        let first = rebind_handoff(&candidate, "store-rebind-first", 101);
        let first_receipt = service.rebind_store(&first, first.request_digest.clone())?;
        service.commit_store_rebind()?;
        service.publish_ready(ready_receipt(&candidate, &activation, "ready-after-first"))?;

        let second = rebind_handoff(&candidate, "store-rebind-second", 102);
        let second_receipt = service.rebind_store(&second, second.request_digest.clone())?;
        assert_eq!(service.state(), KernelServiceState::Degraded);
        assert_eq!(
            service.reconcile_store_rebind(&StoreRebindQuery {
                operation_id: second.operation_id.clone(),
                request_digest: second.request_digest.clone(),
            })?,
            Some(second_receipt.clone())
        );

        service.rollback_store_rebind_for_recovery_failure();
        assert_eq!(service.state(), KernelServiceState::Ready);
        assert_eq!(service.store_rebind_receipt(), Some(&first_receipt));
        assert_eq!(
            service.reconcile_store_rebind(&StoreRebindQuery {
                operation_id: first.operation_id.clone(),
                request_digest: first.request_digest.clone(),
            })?,
            Some(first_receipt.clone())
        );
        assert!(
            service
                .reconcile_store_rebind(&StoreRebindQuery {
                    operation_id: second.operation_id.clone(),
                    request_digest: second.request_digest.clone(),
                })
                .is_err()
        );

        let second_retry = service.rebind_store(&second, second.request_digest.clone())?;
        service.commit_store_rebind()?;
        assert_eq!(second_retry, second_receipt);
        assert_eq!(
            service.reconcile_store_rebind(&StoreRebindQuery {
                operation_id: first.operation_id,
                request_digest: first.request_digest,
            })?,
            Some(first_receipt)
        );
        Ok(())
    }

    #[test]
    fn probe_publication_rejects_every_forbidden_state() {
        let candidate = candidate();
        let activation = KernelActivationReceipt::issue(&permit(&candidate));
        let forbidden = [
            KernelServiceState::Cold,
            KernelServiceState::Reconciling,
            KernelServiceState::ShadowNoAuthority,
            KernelServiceState::HandoffPrepared,
            KernelServiceState::Draining,
            KernelServiceState::Stopped,
            KernelServiceState::Failed,
            KernelServiceState::ManualRecovery,
        ];
        for state in forbidden {
            let mut service = KernelService::new([17; 32], 2, 4).unwrap_or_else(|_| unreachable!());
            service.candidate = Some(candidate.clone());
            service.activation_receipt = Some(activation.clone());
            service.state = state;
            assert!(matches!(
                service.publish_ready(ready_receipt(&candidate, &activation, "ready-forbidden")),
                Err(KernelServiceError::IllegalTransition {
                    from,
                    to: KernelServiceState::Ready
                }) if from == state
            ));
        }
    }
}
