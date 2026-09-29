//! Governor scope-identity admission entries (issue #1787).
//!
//! Consumes the session/scope/task authorities without duplicating them: the
//! live [`WorkScopeBindingOwner`] is read at the retained fence, session and
//! task records stay with their owners, and governing sources/privacy arrive
//! from the onboarding path that retains them. Nothing here rebuilds admission
//! or attach reconciliation; those stay with their owning slices.
//!
//! Entries (production callers live on [`GovernorComposition`]):
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
//! - [`require_matched_guard_at_use_boundary`] is the use-boundary seam for a
//!   dispatch producer that already holds the retained binding read at the
//!   admission fence: it derives the observed binding from owner-supplied live
//!   resources and fail-closes with the full guard verdict instead of a
//!   boolean.
//!
//! Ported-from: work/1787-workscope-identity@443e39841049b0f80a25bebca813f470f8ad311c.

use crate::CompositionError;
use eliot_contracts::StateFence;
use eliot_security_contracts::PrivacyClass;

pub use eliot_workscope::{
    BindingToken, GenerationEvidence, GoverningSourceSet, GuardTrigger, GuardVerdict,
    HostObservedHandles, IdentityEvidence, IdentityLegOutcome, ManifestBoundaryClaim,
    ObservedScopeResources, PrivacyProfile, ProposalSource, RegisteredInstanceEvidence,
    ResolutionAuthentication, ResolutionOutcome, ResolutionRequest, ResolutionTier,
    ResumedTaskEvidence, ScopeBinding, ScopeBindingDisposition, ScopeBindingGuard, ScopeFingerprint,
    ScopeRelocationOrAttachReceipt, ScopeResolution, SessionTaskClaim, TriggerReport,
    WorkScopeBindingOwner, WorkScopeBindingSnapshot, WorkScopeDescriptor,
    WorkScopeResolutionReceipt, WorkScopeResolver, WorkspaceInstanceIdentity, check_at_trigger,
    derive_observed_resources, identity_legs, issue_resolution_receipt, observed_scope_binding,
    produce_attach_receipt, rebind_with_receipt,
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

/// Runs the full existing `ScopeBindingGuard` at one I4.2.1 use boundary from
/// owner-derived live resources and fail-closes with the typed verdict
/// (issue #1746, W3).
///
/// This is the Governor-owned evaluate-and-map core for a dispatch producer
/// that already holds the retained binding read at the admission fence:
/// attach/resume, first tool/process event for a task, agent/process launch,
/// a root/worktree/cwd/editor-workspace change, and a scope-sensitive
/// canonical write or Material effect. The trigger is supplied by the
/// boundary and never guessed here.
///
/// The observed binding is derived from `observed` through the existing owner
/// (`observed_scope_binding`: exact instance/root, lineage, and resource
/// generation against the retained scope reference), never from a caller cwd,
/// a normalized path string, or a hand-built `ScopeBinding`. A live
/// observation that names several instances fails closed as
/// `ScopeObservationAmbiguous` without selecting one. The full guard
/// (`check_at_trigger`) then runs with the caller-retained source closure:
/// `Allow` requires an identity-clear `MATCHED` receipt, so an
/// identity-clear observation without source closure withholds instead of
/// admitting.
///
/// The verdict is preserved in full. Success returns the fresh `MATCHED`
/// `TriggerReport`; any other outcome fails closed with
/// `ScopeGuardWithheld` carrying the exact identity leg
/// (`DIFFERENT_INSTANCE`, `AMBIGUOUS`, `STALE_BINDING`), the verdict, the
/// trigger, and the complete receipt disposition (`MATCHED`,
/// `STALE_BINDING`, `DIFFERENT_INSTANCE`, `AMBIGUOUS`, `PROVISIONAL_REBIND`,
/// `CONFLICTED`). Nothing is rebound, moved, or selected here: a relocation
/// still requires its explicit owner receipt (`rebind_with_receipt`, admitted
/// through `GovernorComposition::admit_scope_relocation`), and scope
/// uncertainty permits only the already-defined quarantined capture route
/// (the `admit_capture` cold-unbound candidate with the conflicting lineage
/// preserved) — never a task-bound write or Material authority.
///
/// This entry performs no owner read and retains no quarantine record: the
/// caller reads the retained binding at the exact admission fence (a
/// generation change fails closed there until an explicit rebind) and the
/// owning composition entry retains the conflicting lineage, exactly like
/// `require_fresh_matched_binding`. It creates no second resolver, authority
/// store, scanner, or bridge-local durable state.
///
/// `caller: STITCH`. The first-task-event adopter is the skill-dispatch edge
/// (`bins/eliotd/src/skill_dispatch.rs::plan_skill_pair` with
/// `GuardTrigger::FirstToolEvent`): observe the explicit root through
/// `task_binding_admission::observe_explicit_workspace`, read the retained
/// binding at the admitted fence, run this seam, and project a withheld
/// report through the existing skill owner (which already carries
/// `ScopeGuardWithheld` with the exact report). The launch adopter runs the
/// same seam with `GuardTrigger::AgentLaunch` from the launch ingress.
/// Attach/resume and the canonical write already have their owning entries
/// (`GovernorComposition::admit_observed_scope_attach`,
/// `DaemonComposition::run_work_scope_guard_at_use_boundary`,
/// `GovernorComposition::check_canonical_write_work_scope`).
pub fn require_matched_guard_at_use_boundary(
    expected: &ScopeBinding,
    observed: &ObservedScopeResources,
    privacy_class: PrivacyClass,
    governing_source_generation: u64,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    trigger: GuardTrigger,
) -> Result<TriggerReport, CompositionError> {
    let observed_binding =
        observed_scope_binding(expected, observed, privacy_class, governing_source_generation)
            .map_err(|error| match error {
                eliot_workscope::WorkScopeError::AmbiguousObservation { observed_instances } => {
                    CompositionError::ScopeObservationAmbiguous {
                        trigger,
                        observed_instances,
                    }
                }
                other => CompositionError::Recovery(other.to_string()),
            })?;
    let report = check_at_trigger(expected, &observed_binding, source_closure, trigger);
    if report.is_matched() {
        Ok(report)
    } else {
        Err(CompositionError::ScopeGuardWithheld {
            claimed_scope: expected.scope.scope_ref.clone(),
            observed_scope: observed_binding.scope.scope_ref.clone(),
            trigger: report.trigger,
            identity: report.identity,
            verdict: report.verdict,
            report: Box::new(report),
        })
    }
}
