//! Passive execution/cancellation view and evidence DTOs with local validation/accessors.
//!
//! Source anchors: Architecture A5.1 in `docs/architecture/ELIOT_ARCHITECTURE.md`
//! (bounded observations have separate capture-route and evaluation-status characteristics;
//! verifier-backed is not independent); Architecture A10.8 (verification/finish is
//! proof-bearing); Implementation I10.8.2 in `docs/architecture/ELIOT_IMPLEMENTATION.md`
//! (one `ProcessExecutor` facade provides `start`, `inspect`, `cancel`, and `reconcile`,
//! while ownership remains with Kernel, `eliot-testd`, User Broker, or a supervisor); and
//! Appendix P.12 in `docs/generated/rust-boundary-interfaces.md` (`inspect` ->
//! `ProcessExecutionView`, `cancel` -> `CancellationReceipt`, `reconcile` ->
//! `ProcessEvidence`).
//!
//! This child owns passive execution/cancellation view/evidence DTOs plus local
//! validation/accessors only; it owns no process lifecycle, dispatch, cancellation effect,
//! or canonical authority; physical execution/reconcile authority remains `ProcessExecutor`
//! and the owning control plane.

use super::{
    Assertability, CancellationStatus, ContractError, DescendantEvidence, EvidenceAxes,
    EvidenceStatus, ExitStatus, FencingToken, OperationId, ProcessExecutionBinding, ProcessHealth,
    ProcessIdentity, ProcessLifecycle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Typed process execution view.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionView {
    pub(super) binding: ProcessExecutionBinding,
    pub(super) lifecycle: ProcessLifecycle,
    pub(super) health: ProcessHealth,
    pub(super) cancellation: CancellationStatus,
    pub(super) identity: Option<ProcessIdentity>,
    pub(super) exit: Option<ExitStatus>,
    pub(super) descendants: Option<DescendantEvidence>,
}

impl ProcessExecutionView {
    /// Returns the exact permit/authority/process contour binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns health.
    pub const fn health(&self) -> &ProcessHealth {
        &self.health
    }

    /// Returns cancellation status.
    pub const fn cancellation(&self) -> CancellationStatus {
        self.cancellation
    }

    /// Returns resumed process identity when available.
    pub const fn identity(&self) -> Option<&ProcessIdentity> {
        self.identity.as_ref()
    }

    /// Returns exit observation.
    pub const fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    /// Returns descendant evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.binding.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.binding.request_digest()
    }

    /// Returns the authenticated fence.
    pub const fn fence(&self) -> &FencingToken {
        self.binding.state_fence()
    }

    fn validate_internal(&self) -> Result<(), ContractError> {
        if let Some(identity) = &self.identity
            && !self.binding.matches_identity(identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        if let (Some(identity), Some(descendants)) = (&self.identity, &self.descendants)
            && !descendants.matches(&self.binding, identity)
        {
            return Err(ContractError::EvidenceBindingMismatch);
        }
        Ok(())
    }
}

/// Reconciliation evidence emitted by a physical implementation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    view: ProcessExecutionView,
    stdout_ref: Option<String>,
    stderr_ref: Option<String>,
    axes: EvidenceAxes,
}

impl ProcessEvidence {
    /// Creates raw process evidence with C0-05 observation-only axes.
    pub fn new(
        view: ProcessExecutionView,
        stdout_ref: Option<String>,
        stderr_ref: Option<String>,
        axes: EvidenceAxes,
    ) -> Result<Self, ContractError> {
        let value = Self {
            view,
            stdout_ref,
            stderr_ref,
            axes,
        };
        value.validate()?;
        if axes.status != EvidenceStatus::Observed
            || axes.assertability != Assertability::NonAssertableUnverified
        {
            return Err(ContractError::EvidenceAuthorityEscalation);
        }
        Ok(value)
    }

    /// Validates the passive evidence structure without promoting or rejecting
    /// its epistemic status. Persistence owners apply their own status policy.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.view.binding.validate()?;
        self.view.validate_internal()?;
        self.axes
            .validate()
            .map_err(|_| ContractError::InvalidValue {
                field: "evidence_axes",
                reason: "C0-05 evidence axes are invalid",
            })
    }

    /// Returns the exact binding through the view.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        self.view.binding()
    }

    /// Returns operation identity.
    pub const fn operation_id(&self) -> &OperationId {
        self.view.operation_id()
    }

    /// Returns request digest.
    pub fn request_digest(&self) -> &str {
        self.view.request_digest()
    }

    /// Returns the process view.
    pub const fn view(&self) -> &ProcessExecutionView {
        &self.view
    }

    /// Returns stdout evidence handle.
    pub fn stdout_ref(&self) -> Option<&str> {
        self.stdout_ref.as_deref()
    }

    /// Returns stderr evidence handle.
    pub fn stderr_ref(&self) -> Option<&str> {
        self.stderr_ref.as_deref()
    }

    /// Returns C0-05 evidence axes.
    pub const fn axes(&self) -> EvidenceAxes {
        self.axes
    }
}

/// Exact cancellation command binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationRequest {
    pub(super) binding: ProcessExecutionBinding,
}

impl CancellationRequest {
    /// Binds cancellation to the exact validated dispatch.
    pub fn new(binding: ProcessExecutionBinding) -> Self {
        Self { binding }
    }

    /// Returns the exact binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }
}

/// Cancellation receipt bound to exact permit, authority, process, Job, image, and session.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReceipt {
    pub(super) binding: ProcessExecutionBinding,
    pub(super) identity: Option<ProcessIdentity>,
    pub(super) status: CancellationStatus,
    pub(super) lifecycle: ProcessLifecycle,
    pub(super) no_effect_proven: bool,
    pub(super) descendants: Option<DescendantEvidence>,
}

impl CancellationReceipt {
    /// Returns the exact authority/process binding.
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }

    /// Returns cancellation status.
    pub const fn status(&self) -> CancellationStatus {
        self.status
    }

    /// Returns lifecycle.
    pub const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns whether no physical effect was proven.
    pub const fn no_effect_proven(&self) -> bool {
        self.no_effect_proven
    }

    /// Returns descendant cleanup evidence.
    pub const fn descendants(&self) -> Option<&DescendantEvidence> {
        self.descendants.as_ref()
    }
}
