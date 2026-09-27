//! Kernel-owned descendant registration and closure receipts.
//!
//! Implementation: I18.53 CHILD-1/CHILD-2 (every visible child is registered
//! before launch and appears in the closure receipt; cancellation and restart
//! cannot orphan descendants), I1.4 (Kernel `eliotd` makes semantic lifecycle
//! decisions while Kernel physically performs start/stop/fence; surviving
//! child PIDs are never adopted), I1.5 (a post-`DrainCommitRecord` generation
//! starts only after the old generation's process descendants are terminated
//! or explicitly reconciled).
//!
//! This module owns the in-memory registration index and the closure receipt
//! shape. It performs no launch, kill, or inspect itself: the process gateway
//! registers at its single executor handoff, and the cancel, restart, and
//! shutdown paths close entries through the gateway. The registry is
//! deliberately not durable: across a Kernel replacement Host closes the
//! whole Kernel Job lineage before any replacement activates (I1.4), so no
//! pre-restart child can still be alive to reconcile.

use std::collections::BTreeMap;

use eliot_contracts::EpochId;
use eliot_process::{
    CancellationStatus, ContractError, Generation, OperationId, ProcessExecutionView,
    ProcessLifecycle,
};

/// One child registered before its launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RegisteredDescendant {
    operation_id: OperationId,
    owner_module: String,
    authority_epoch: EpochId,
    generation: Generation,
}

impl RegisteredDescendant {
    /// Binds one admitted launch to its descendant registration. The caller
    /// must have validated the admission; the registry additionally refuses
    /// a blank owner so a registration can never name nobody.
    pub(crate) fn new(
        operation_id: OperationId,
        owner_module: String,
        authority_epoch: EpochId,
        generation: Generation,
    ) -> Result<Self, ContractError> {
        if owner_module.trim().is_empty() {
            return Err(ContractError::InvalidValue {
                field: "registered_descendant.owner_module",
                reason: "must be non-blank",
            });
        }
        Ok(Self {
            operation_id,
            owner_module,
            authority_epoch,
            generation,
        })
    }

    /// Returns the registered operation identity.
    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the owning module identity.
    pub(crate) fn owner_module(&self) -> &str {
        &self.owner_module
    }

    /// Returns the authority epoch the child was admitted under.
    pub(crate) fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the generation the child was admitted under.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }
}

/// In-memory index of launched-but-not-closed descendants, keyed by exact
/// operation identity.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct DescendantRegistry {
    entries: BTreeMap<OperationId, RegisteredDescendant>,
}

impl DescendantRegistry {
    /// Creates an empty registry.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Registers one child before its launch. A duplicate operation identity
    /// is a conflict, never a silent re-registration: the replay store
    /// already serializes launch attempts per operation.
    pub(crate) fn register(
        &mut self,
        descendant: RegisteredDescendant,
    ) -> Result<(), ContractError> {
        if self.entries.contains_key(descendant.operation_id()) {
            return Err(ContractError::InvalidValue {
                field: "registered_descendant.operation_id",
                reason: "descendant is already registered",
            });
        }
        self.entries
            .insert(descendant.operation_id().clone(), descendant);
        Ok(())
    }

    /// Returns the registration for one operation, if still open.
    pub(crate) fn get(&self, operation_id: &OperationId) -> Option<&RegisteredDescendant> {
        self.entries.get(operation_id)
    }

    /// Removes one registration after its closure is proven. Returns the
    /// removed entry, or `None` when nothing was registered.
    pub(crate) fn remove(&mut self, operation_id: &OperationId) -> Option<RegisteredDescendant> {
        self.entries.remove(operation_id)
    }

    /// Returns every still-open operation identity, in order.
    pub(crate) fn registered_operation_ids(&self) -> Vec<OperationId> {
        self.entries.keys().cloned().collect()
    }
}

/// Closure receipt for one launched child: the registration it closes, the
/// exact observed lifecycle and cancellation state, and the observed
/// descendant tree. `all_closed` holds exactly when the root reached a
/// proven terminal lifecycle and the tree observation is complete with every
/// member terminated; anything else keeps the registration open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescendantClosureReceipt {
    operation_id: OperationId,
    owner_module: String,
    authority_epoch: EpochId,
    generation: Generation,
    lifecycle: ProcessLifecycle,
    cancellation: CancellationStatus,
    descendant_process_ids: Vec<String>,
    descendants_complete: bool,
    tree_terminated: bool,
    evidence_ref: Option<String>,
    all_closed: bool,
}

impl DescendantClosureReceipt {
    /// Builds the closure receipt for one registration from the exact current
    /// execution view. This is an observation, not a claim: an open or
    /// unproven tree yields an open receipt and the caller retains the
    /// registration.
    pub(crate) fn close(registration: &RegisteredDescendant, view: &ProcessExecutionView) -> Self {
        let (descendant_process_ids, descendants_complete, tree_terminated, evidence_ref) =
            match view.descendants() {
                Some(tree) => (
                    tree.process_ids()
                        .iter()
                        .map(|process| process.as_str().to_owned())
                        .collect(),
                    tree.complete(),
                    tree.tree_terminated(),
                    tree.evidence_ref().map(str::to_owned),
                ),
                None => (Vec::new(), false, false, None),
            };
        let lifecycle = view.lifecycle();
        // Proven closure mirrors the daemon-restart bar exactly: a terminal
        // root lifecycle plus a complete, terminated tree observation.
        // `Quarantined` is deliberately not closing: a fenced lineage keeps
        // unknown tree state for manual recovery.
        let all_closed = matches!(
            lifecycle,
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled
        ) && descendants_complete
            && tree_terminated;
        Self {
            operation_id: registration.operation_id().clone(),
            owner_module: registration.owner_module().to_owned(),
            authority_epoch: registration.authority_epoch().clone(),
            generation: registration.generation(),
            lifecycle,
            cancellation: view.cancellation(),
            descendant_process_ids,
            descendants_complete,
            tree_terminated,
            evidence_ref,
            all_closed,
        }
    }

    /// Validates receipt coherence: the closed flag must equal the proven
    /// terminal-plus-tree conjunction it claims, and a closed receipt must
    /// carry the raw evidence handle behind the claim.
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        if self.owner_module.trim().is_empty() {
            return Err(ContractError::InvalidValue {
                field: "descendant_closure.owner_module",
                reason: "must be non-blank",
            });
        }
        let proven = matches!(
            self.lifecycle,
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled
        ) && self.descendants_complete
            && self.tree_terminated;
        if self.all_closed != proven {
            return Err(ContractError::InvalidValue {
                field: "descendant_closure.all_closed",
                reason: "closed flag disagrees with the observed lifecycle and tree",
            });
        }
        if self.all_closed && self.evidence_ref.as_deref().is_none_or(str::is_empty) {
            return Err(ContractError::InvalidValue {
                field: "descendant_closure.evidence_ref",
                reason: "closure claims require a raw evidence handle",
            });
        }
        Ok(())
    }

    /// Returns the closed operation identity.
    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the owning module identity.
    pub(crate) fn owner_module(&self) -> &str {
        &self.owner_module
    }

    /// Returns the observed root lifecycle.
    pub(crate) const fn lifecycle(&self) -> ProcessLifecycle {
        self.lifecycle
    }

    /// Returns the observed cancellation state.
    pub(crate) const fn cancellation(&self) -> CancellationStatus {
        self.cancellation
    }

    /// Returns whether every observed tree member was terminated.
    pub(crate) const fn tree_terminated(&self) -> bool {
        self.tree_terminated
    }

    /// Returns the raw evidence handle behind the tree observation, if any.
    pub(crate) fn evidence_ref(&self) -> Option<&str> {
        self.evidence_ref.as_deref()
    }

    /// Returns whether the root reached a proven terminal lifecycle with a
    /// complete, terminated tree observation.
    pub(crate) const fn all_closed(&self) -> bool {
        self.all_closed
    }
}
