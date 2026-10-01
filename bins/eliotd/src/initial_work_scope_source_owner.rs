//! Initial authenticated WorkScope source-owner transaction.
//!
//! This is the narrow task-free BindScope path: it asks the existing Host
//! observer for the declared root, issues an exact-root discovery lease before
//! opening governing-source bytes, lets Governor capture and admit the approved source
//! pair, and submits the ordinary canonical transition through the neutral
//! Kernel write port. The caller must perform fresh named owner readback and
//! install the returned owner only after both receipt and readback validation.

use std::path::Path;

use eliot_contracts::OperationId;
use eliot_governor::{
    InitialWorkScopeAdmissionAuthority, KernelTransitionPort, PreparedWorkScopeSourceAdmission,
    VerifiedGoverningSourceApproval, WorkScopeOwnerSnapshotReadback, WorkScopeSourceAdmissionError,
    issue_initial_work_scope_source_discovery_lease, prepare_initial_work_scope_source_admission,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::WriteReceipt;
use eliot_workscope::{DiscoveryLeaseKey, WorkScopeDescriptor};
use thiserror::Error;

use crate::task_binding_admission;

/// Result of the normal Kernel apply edge before post-commit owner installation.
#[derive(Clone, Debug)]
pub struct AppliedInitialWorkScopeSourceAdmission {
    /// Exact prepared owner whose snapshot was submitted.
    pub prepared: PreparedWorkScopeSourceAdmission,
    /// Kernel-validated committed receipt for the submitted transition.
    pub receipt: WriteReceipt,
}

/// Runs one initial BindScope source admission through the real canonical
/// Kernel write port.
///
/// `approval` must come from the independently verified signed setup
/// snapshot. `lease_key` must be projected from the original authenticated
/// Kernel peer and request; no identity component is derived from task input.
/// `owner_readback` must be the exact fresh Empty WorkScope named-read result
/// obtained before source observation. `owner_clock` is the daemon's trusted
/// clock and is sampled before lease issuance and after source capture.
///
/// The returned receipt has already passed the exact authority/causal-parent
/// validator. The caller must still read WorkScope back from the named owner,
/// call [`PreparedWorkScopeSourceAdmission::validate_owner_readback`], and
/// only then install `prepared.owner` into the live Governor composition.
#[allow(clippy::too_many_arguments)]
pub async fn apply_initial_work_scope_source_admission(
    transition_port: &dyn KernelTransitionPort,
    identity: &RequestIdentity,
    operation_id: &OperationId,
    admission_authority: &InitialWorkScopeAdmissionAuthority,
    explicit_root: &Path,
    lease_key: &DiscoveryLeaseKey,
    descriptor: &WorkScopeDescriptor,
    approval: &VerifiedGoverningSourceApproval,
    owner_readback: &WorkScopeOwnerSnapshotReadback,
    owner_clock: impl Fn() -> u64,
) -> Result<AppliedInitialWorkScopeSourceAdmission, InitialWorkScopeSourceOwnerError> {
    let explicit_root_identity = explicit_root
        .to_str()
        .ok_or(InitialWorkScopeSourceOwnerError::NonUnicodeRoot)?;
    // The Host observer reads only bounded workspace identity facts here; it
    // does not open governing-source document bytes. It is tied to the
    // caller's explicit root; cwd and nearby roots are never consulted.
    let observed = task_binding_admission::observe_explicit_workspace(
        explicit_root,
        &identity.request.state_fence,
    )
    .map_err(|error| InitialWorkScopeSourceOwnerError::WorkspaceObservation(error.to_string()))?;

    // The one-read lease is issued after workspace identity is known and
    // before the Bootstrap parser opens any governing-source document bytes.
    let discovery_lease = issue_initial_work_scope_source_discovery_lease(
        identity,
        approval,
        explicit_root_identity,
        lease_key,
        owner_clock(),
    )?;

    let prepared = prepare_initial_work_scope_source_admission(
        identity,
        operation_id,
        admission_authority,
        descriptor,
        &observed,
        identity.request.state_fence.resource_generation.value(),
        approval,
        owner_readback,
        lease_key,
        &discovery_lease,
        owner_clock,
    )?;

    let receipt = transition_port
        .apply_prepared(
            identity,
            prepared.transition.clone(),
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| InitialWorkScopeSourceOwnerError::KernelApply(error.to_string()))?;
    prepared.validate_write_receipt(&receipt)?;

    Ok(AppliedInitialWorkScopeSourceAdmission { prepared, receipt })
}

/// Refusal from the initial BindScope source-owner transaction.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitialWorkScopeSourceOwnerError {
    /// Root identity must be representable by the signed source approval.
    #[error("explicit WorkScope root identity is not Unicode")]
    NonUnicodeRoot,
    /// The existing Host observer could not verify the explicit root.
    #[error("explicit WorkScope root observation failed: {0}")]
    WorkspaceObservation(String),
    /// Governor rejected source, owner, policy, or causal admission.
    #[error(transparent)]
    Admission(#[from] WorkScopeSourceAdmissionError),
    /// The neutral Kernel write port rejected or failed the prepared write.
    #[error("Kernel rejected initial WorkScope source admission: {0}")]
    KernelApply(String),
}
