//! Governor scope-identity admission entries (issue #1787).
//!
//! Consumes the session/scope/task authorities without duplicating them: the
//! live [`WorkScopeBindingOwner`] is read at the retained fence, session and
//! task records stay with their owners, and governing sources/privacy arrive
//! from the onboarding path that retains them. Nothing here rebuilds admission
//! or attach reconciliation; those stay with their owning slices.
//!
//! Entries:
//!
//! - [`GovernorComposition::resolve_scope_identity`] runs the evidence-first
//!   order for an attach caller;
//! - [`GovernorComposition::issue_scope_resolution_receipt`] issues a durable
//!   receipt from the live owner binding (implementation in
//!   `eliot-workscope`);
//! - [`GovernorComposition::require_scope_guard_for_observed`] enforces the
//!   guard at a trigger and returns the current snapshot only on `Allow`;
//! - [`GovernorComposition::admit_scope_relocation`] admits an authorized
//!   relocation/attach receipt as the new expected binding, gated on a fresh
//!   `MATCHED` source-closure check for the observed instance;
//! - [`GovernorComposition::admit_observed_scope_attach`] is the owning thin
//!   caller for the attach trigger path: it produces the owner-issued attach
//!   receipt from a live mechanical observation plus the retained descriptor
//!   and explicit authorization, then admits it through
//!   [`GovernorComposition::admit_scope_relocation`];
//! - [`check_task_observation`] is the daemon fast-path helper: it enforces
//!   the sources-independent identity legs (instance, scope claim,
//!   generation) and never fabricates source-closure outcomes. Lineage is
//!   deliberately not compared here — the daemon edge does not observe it —
//!   and is enforced on lineage-observing paths (resolver tiers, issuance,
//!   full guard).

use crate::CompositionError;
use eliot_contracts::StateFence;

pub use eliot_workscope::{
    BindingToken, GenerationEvidence, GoverningSourceSet, GuardTrigger, GuardVerdict,
    HostObservedHandles, IdentityEvidence, IdentityLegOutcome, ManifestBoundaryClaim,
    PrivacyProfile, ProposalSource, RegisteredInstanceEvidence, ResolutionAuthentication,
    ResolutionOutcome, ResolutionRequest, ResolutionTier, ResumedTaskEvidence, ScopeBinding,
    ScopeBindingDisposition, ScopeBindingGuard, ScopeFingerprint, ScopeRelocationOrAttachReceipt,
    ScopeResolution, SessionTaskClaim, TriggerReport, WorkScopeBindingOwner,
    WorkScopeBindingSnapshot, WorkScopeDescriptor, WorkScopeResolutionReceipt, WorkScopeResolver,
    WorkspaceInstanceIdentity, check_at_trigger, derive_observed_resources, identity_legs,
    issue_resolution_receipt, produce_attach_receipt, rebind_with_receipt,
};

/// Daemon-edge scope observation verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskScopeOutcome {
    /// Observed instance, scope claim, and generation agree; existing alias
    /// checks still apply downstream.
    Clear,
    /// Observed workspace instance or root is not the bound instance.
    DifferentInstance,
    /// Scope claim or evidence disagrees or is missing; ask, do not select.
    Ambiguous,
    /// Observed generation moved past the bound generation.
    StaleBinding,
}

/// One daemon-edge scope observation check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskScopeCheck {
    pub outcome: TaskScopeOutcome,
    pub detail: String,
}

/// Checks one task observation against the retained binding.
///
/// Enforces exact instance/root identity, the scope claim, and the observed
/// resource generation. Withholds (`DifferentInstance`, `Ambiguous`,
/// `StaleBinding`) on any disagreement and preserves the retained binding;
/// `Clear` admits nothing by itself — the caller's existing alias and fence
/// checks still run. Malformed inputs withhold as `Ambiguous`, never allow.
#[must_use]
pub fn check_task_observation(
    expected: &ScopeBinding,
    observed_scope_claim: &str,
    observed_instance: &WorkspaceInstanceIdentity,
    observed_generation: &GenerationEvidence,
) -> TaskScopeCheck {
    if expected.validate().is_err() {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::Ambiguous,
            detail: "retained scope binding is malformed".to_owned(),
        };
    }
    if observed_instance.validate().is_err() {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::Ambiguous,
            detail: "observed workspace instance evidence is malformed".to_owned(),
        };
    }
    if observed_generation.validate().is_err() {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::Ambiguous,
            detail: "observed generation evidence is malformed".to_owned(),
        };
    }
    if observed_scope_claim.trim().is_empty() {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::Ambiguous,
            detail: "task observation names no scope to check".to_owned(),
        };
    }
    if expected.scope.instance_ref != observed_instance.instance_ref
        || expected.scope.root_identity != observed_instance.root_identity
    {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::DifferentInstance,
            detail: format!(
                "observed workspace instance {} is not the bound instance {}",
                observed_instance.instance_ref, expected.scope.instance_ref
            ),
        };
    }
    if expected.scope.scope_ref != observed_scope_claim {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::Ambiguous,
            detail: "task observation scope claim disagrees with the bound scope".to_owned(),
        };
    }
    if expected.scope.generation != observed_generation.resource_generation.value() {
        return TaskScopeCheck {
            outcome: TaskScopeOutcome::StaleBinding,
            detail: "observed resource generation moved past the bound generation".to_owned(),
        };
    }
    TaskScopeCheck {
        outcome: TaskScopeOutcome::Clear,
        detail: "observed instance, scope claim, and generation agree".to_owned(),
    }
}

/// Maps a non-allow trigger report to the fail-closed composition error.
///
/// The retained binding is untouched; the detail names the trigger and the
/// identity outcome so the caller asks the cheapest discriminative question
/// instead of retrying against another candidate.
pub(crate) fn guard_recovery_error(report: &TriggerReport, context: &str) -> CompositionError {
    let disposition = report.receipt.as_ref().map_or_else(
        || format!("{:?}", report.identity),
        |receipt| format!("{:?}", receipt.disposition),
    );
    CompositionError::Recovery(format!(
        "{context}: scope guard withheld at trigger {:?} ({disposition})",
        report.trigger
    ))
}

/// Requires the retained binding to be fresh and `MATCHED` at `fence`.
///
/// This is the retained-data leg installed at every trigger point that has no
/// new observation: the owner must be bound, readable at the exact fence (a
/// generation change fails closed here until an explicit rebind), the
/// retained guard receipt must be `MATCHED`, agree with the binding on every
/// identity field, and carry the binding's governing-source generation. Any
/// drift blocks the scope-sensitive operation; it never selects another
/// candidate and never transfers task state or project memory.
pub fn require_fresh_matched_binding(
    work_scope: Option<&WorkScopeBindingOwner>,
    fence: &StateFence,
    context: &str,
) -> Result<WorkScopeBindingSnapshot, CompositionError> {
    let owner = work_scope.ok_or_else(|| {
        CompositionError::Recovery(format!(
            "{context}: WorkScope binding is unbound; scope-guarded work is unavailable"
        ))
    })?;
    let snapshot = owner
        .read_current(fence)
        .map_err(|error| CompositionError::Recovery(format!("{context}: {error}")))?;
    ensure_snapshot_fresh(&snapshot, context)?;
    Ok(snapshot)
}

/// Enforces `MATCHED` agreement on an already-read snapshot.
pub(crate) fn ensure_snapshot_fresh(
    snapshot: &WorkScopeBindingSnapshot,
    context: &str,
) -> Result<(), CompositionError> {
    use eliot_workscope::ScopeBindingDisposition as Disposition;
    let receipt = &snapshot.guard_receipt;
    let binding = &snapshot.binding;
    if receipt.disposition != Disposition::Matched {
        return Err(CompositionError::Recovery(format!(
            "{context}: scope binding guard receipt is not matched ({:?}); rebind or revalidate before scope-sensitive work",
            receipt.disposition
        )));
    }
    if receipt.expected_scope_ref != binding.scope.scope_ref
        || receipt.observed_scope_ref != binding.scope.scope_ref
        || receipt.expected_lineage_ref != binding.scope.lineage_ref
        || receipt.observed_lineage_ref != binding.scope.lineage_ref
        || receipt.expected_instance_ref != binding.scope.instance_ref
        || receipt.observed_instance_ref != binding.scope.instance_ref
        || receipt.source_generation != binding.governing_source_generation
    {
        return Err(CompositionError::Recovery(format!(
            "{context}: scope binding guard receipt drifted from the retained binding"
        )));
    }
    Ok(())
}
