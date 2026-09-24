//! `ScopeBindingGuard` trigger evaluation (issue #1787, guard slice).
//!
//! Implements the I4.2.1 trigger set: session attach/resume, first tool or
//! process event for a task, agent/process launch, worktree/root/cwd/editor
//! change, scope-sensitive canonical writes and Material effects, and
//! VCS/relocation/generation changes. The trigger determines *when* the guard
//! runs; the [`ScopeBinding`] comparison determines the disposition.
//!
//! Two evaluation shapes exist because governing-source closure is not
//! available at every trigger:
//!
//! - [`check_at_trigger`] runs the full guard (identity, generation, privacy,
//!   and source closure) wherever the caller retains a [`GoverningSourceSet`]
//!   and [`PrivacyProfile`]. `Allow` requires a `MATCHED` receipt; anything
//!   else withholds or quarantines.
//! - [`identity_legs`] runs only the sources-independent legs (instance,
//!   scope, generation). Fast-path edges such as daemon task admission use it
//!   to withhold on `DIFFERENT_INSTANCE`, `AMBIGUOUS`, or `STALE_BINDING`
//!   without fabricating source-closure outcomes. An identity-clear result on
//!   such an edge is *not* an allow: source closure is enforced where sources
//!   exist (resolution issuance and owner admission).
//!
//! A mismatching observation never moves task state or project memory.
//! `DIFFERENT_INSTANCE` and `AMBIGUOUS` quarantine: the retained binding is
//! preserved and the conflicting observation is held separately until an
//! explicit authorized rebind ([`rebind_with_receipt`]) completes.

use super::{
    GoverningSourceSet, ObservedScopeResources, PrivacyProfile, ScopeBinding,
    ScopeBindingDisposition, ScopeBindingGuard, ScopeBindingGuardReceipt, ScopeIdentity,
    ScopeRelocationKind, ScopeRelocationOrAttachReceipt, WorkScopeBindingOwner,
    WorkScopeDescriptor, WorkScopeError, counter, text,
};
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Mandatory revalidation trigger (I4.2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardTrigger {
    SessionAttachResume,
    FirstToolEvent,
    AgentLaunch,
    RootChange,
    CanonicalWrite,
    MaterialEffect,
    GenerationChange,
}

/// Sources-independent guard legs, in [`ScopeBindingGuard`] precedence order.
///
/// Lineage, instance, and root evidence decide `DifferentInstance` before the
/// scope reference is compared, and generation is compared before any source
/// closure. Display names, proximity, recency, manifest names, copied markers,
/// and remote URLs never appear here: they are not inputs to this function.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityLegOutcome {
    DifferentInstance,
    Ambiguous,
    StaleBinding,
    IdentityClear,
}

/// What one trigger evaluation permits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardVerdict {
    Allow,
    Withhold,
    Quarantine,
}

/// Complete record of one trigger evaluation.
///
/// `receipt` is present only when the caller supplied source closure and the
/// full guard ran. `identity` always reflects the sources-independent legs, so
/// a fast-path edge can withhold without a receipt while never allowing
/// without one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TriggerReport {
    pub trigger: GuardTrigger,
    pub identity: IdentityLegOutcome,
    pub receipt: Option<ScopeBindingGuardReceipt>,
    pub verdict: GuardVerdict,
}

/// Compares identity and generation legs without source closure.
///
/// Mirrors the precedence of [`ScopeBindingGuard::check`] for the legs that do
/// not need governing sources: lineage/instance/root mismatch decides
/// `DifferentInstance`, scope-reference mismatch decides `Ambiguous`, and
/// generation mismatch decides `StaleBinding`.
#[must_use]
pub fn identity_legs(expected: &ScopeBinding, observed: &ScopeBinding) -> IdentityLegOutcome {
    if expected.scope.lineage_ref != observed.scope.lineage_ref
        || expected.scope.instance_ref != observed.scope.instance_ref
        || expected.scope.root_identity != observed.scope.root_identity
    {
        IdentityLegOutcome::DifferentInstance
    } else if expected.scope.scope_ref != observed.scope.scope_ref {
        IdentityLegOutcome::Ambiguous
    } else if expected.scope.generation != observed.scope.generation
        || expected.governing_source_generation != observed.governing_source_generation
    {
        IdentityLegOutcome::StaleBinding
    } else {
        IdentityLegOutcome::IdentityClear
    }
}

/// Runs the guard at one trigger and maps the disposition to a verdict.
///
/// With a source closure the full [`ScopeBindingGuard::check`] runs and
/// `Allow` requires `MATCHED`. Without one, only [`identity_legs`] runs:
/// mismatches withhold or quarantine exactly as with a receipt, while an
/// identity-clear observation withholds pending source closure instead of
/// allowing. Conflicting observations quarantine: the retained binding is
/// untouched and no task or memory transfer occurs.
#[must_use]
pub fn check_at_trigger(
    expected: &ScopeBinding,
    observed: &ScopeBinding,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
    trigger: GuardTrigger,
) -> TriggerReport {
    let identity = identity_legs(expected, observed);
    let receipt = source_closure
        .map(|(sources, privacy)| ScopeBindingGuard.check(expected, observed, sources, privacy));
    let verdict = match identity {
        IdentityLegOutcome::DifferentInstance | IdentityLegOutcome::Ambiguous => {
            GuardVerdict::Quarantine
        }
        IdentityLegOutcome::StaleBinding => GuardVerdict::Withhold,
        IdentityLegOutcome::IdentityClear => match &receipt {
            Some(report) if report.disposition == ScopeBindingDisposition::Matched => {
                GuardVerdict::Allow
            }
            _ => GuardVerdict::Withhold,
        },
    };
    TriggerReport {
        trigger,
        identity,
        receipt,
        verdict,
    }
}

impl TriggerReport {
    /// Validates a trigger report without re-running the guard.
    ///
    /// # Errors
    ///
    /// Returns an error when a present receipt is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        if let Some(receipt) = &self.receipt {
            text(&receipt.expected_scope_ref, "report.expected_scope_ref")?;
            text(&receipt.observed_scope_ref, "report.observed_scope_ref")?;
            text(
                &receipt.expected_instance_ref,
                "report.expected_instance_ref",
            )?;
            text(
                &receipt.observed_instance_ref,
                "report.observed_instance_ref",
            )?;
            counter(receipt.source_generation, "report.source_generation")?;
        }
        Ok(())
    }
}

/// Produces an authorized attach receipt for one newly observed workspace instance.
///
/// This is the production side of the attach edge that [`rebind_with_receipt`]
/// consumes: it binds a live caller-supplied observation of a newly observed
/// workspace instance (mechanical truth enters only through the caller's
/// `observed` value: canonical root, worktree git dir, VCS common dir, root
/// commit) to the retained scope as a new instance under explicit
/// authorization. The prior instance is preserved verbatim inside the
/// receipt (I4.1/I4.7: a confirmed attach never rewrites the old root identity
/// or task history); admission of the observed instance happens later through
/// [`rebind_with_receipt`], never here.
///
/// Fail-closed production rules, mirroring the issuance slice:
/// - authority comes from the live [`WorkScopeBindingOwner`] read at `fence`
///   (a stale fence fails here) plus the retained [`WorkScopeDescriptor`]
///   describing that binding on every identity field — never from
///   self-asserted observation fields alone;
/// - the retained guard receipt must already be `MATCHED`: attach extends a
///   healthy binding, it does not repair a withheld one;
/// - the observation must name exactly one instance of the same kind and the
///   same repository lineage as the bound scope (attach stays within one
///   lineage; a different lineage is a different scope, and several similar
///   checkouts stay ambiguous per I4.1);
/// - the observed instance must be genuinely new (both instance reference and
///   root identity differ from the bound instance): re-attaching the bound
///   instance, or an observation that reuses its reference under another root,
///   fails instead of minting a no-op or alias receipt;
/// - the observed instance generation must equal the admission fence
///   generation, so the receipt is bound to the fence it is issued under;
/// - branch, commit, dirty state, display names, manifest names, copied
///   markers, and remote URLs never enter the receipt: they stay generation
///   or supporting evidence in the observation.
///
/// This function performs no filesystem, process, or VCS reads: mechanical
/// truth enters only through the caller-supplied `observed` value, which the
/// real ingress derives from mechanical facts. Raw paths and hints are
/// evidence, not authority (I4.3.1).
///
/// # Errors
///
/// Returns an error when references, observations, or the fence are malformed
/// ([`WorkScopeError::InvalidStateFence`]), the owner read disagrees with the
/// fence ([`WorkScopeError::StateFenceMismatch`]), the retained binding is not
/// `MATCHED` ([`WorkScopeError::BindingReceiptNotMatched`]), or the
/// observation is not exactly one new same-lineage instance of the bound scope
/// ([`WorkScopeError::BindingReceiptMismatch`]).
pub fn produce_attach_receipt(
    receipt_ref: impl Into<String>,
    descriptor: &WorkScopeDescriptor,
    owner: &WorkScopeBindingOwner,
    observed: &ObservedScopeResources,
    authorizing_ref: impl Into<String>,
    fence: &StateFence,
) -> Result<ScopeRelocationOrAttachReceipt, WorkScopeError> {
    let receipt_ref = receipt_ref.into();
    let authorizing_ref = authorizing_ref.into();
    text(&receipt_ref, "receipt_ref")?;
    text(&authorizing_ref, "authorizing_ref")?;
    descriptor.validate()?;
    observed.validate()?;
    fence
        .validate()
        .map_err(|_| WorkScopeError::InvalidStateFence)?;
    let snapshot = owner
        .read_current(fence)
        .map_err(|_| WorkScopeError::StateFenceMismatch)?;
    if !super::binding_matches_descriptor(&snapshot.binding, descriptor) {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if snapshot.guard_receipt.disposition != ScopeBindingDisposition::Matched {
        return Err(WorkScopeError::BindingReceiptNotMatched);
    }
    let bound = &snapshot.binding.scope;
    if observed.kind != bound.kind {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let observed_lineage = observed
        .lineage
        .as_ref()
        .ok_or(WorkScopeError::BindingReceiptMismatch)?;
    if bound.lineage_ref.as_deref() != Some(observed_lineage.lineage_ref.as_str()) {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if observed.instances.len() != 1 {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let observed_instance = &observed.instances[0];
    if observed_instance.generation != fence.resource_generation.value() {
        return Err(WorkScopeError::StateFenceMismatch);
    }
    if observed_instance.instance_ref == bound.instance_ref
        || observed_instance.root_identity == bound.root_identity
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let prior_instance = descriptor
        .instances
        .iter()
        .find(|instance| {
            instance.instance_ref == bound.instance_ref
                && instance.root_identity == bound.root_identity
        })
        .ok_or(WorkScopeError::BindingReceiptMismatch)?;
    let receipt = ScopeRelocationOrAttachReceipt {
        receipt_ref,
        kind: ScopeRelocationKind::Attach,
        scope_ref: bound.scope_ref.clone(),
        scope_kind: bound.kind,
        lineage: observed_lineage.clone(),
        prior_instance: prior_instance.clone(),
        observed_instance: observed_instance.clone(),
        authorizing_ref,
        state_fence: fence.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Admits an authorized relocation/attach receipt as the new expected binding.
///
/// Validates the receipt, requires it to name the expected scope, and requires
/// its fence to match the admission fence exactly. The returned binding
/// carries the observed workspace-instance identity and generation, so the
/// same operation is admitted afterwards only with that instance and fence.
/// The prior identity stays preserved inside the receipt; nothing rewrites
/// history.
///
/// # Errors
///
/// Returns an error when the receipt is malformed, names another scope, or
/// its fence does not match the admission fence, or when the derived binding
/// is malformed.
pub fn rebind_with_receipt(
    receipt: &ScopeRelocationOrAttachReceipt,
    expected_scope_ref: &str,
    privacy_class: PrivacyClass,
    governing_source_generation: u64,
    fence: &StateFence,
) -> Result<ScopeBinding, WorkScopeError> {
    receipt.validate()?;
    text(expected_scope_ref, "expected_scope_ref")?;
    counter(governing_source_generation, "governing_source_generation")?;
    if receipt.scope_ref != expected_scope_ref {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if !fences_match_exact(&receipt.state_fence, fence) {
        return Err(WorkScopeError::StateFenceMismatch);
    }
    let binding = ScopeBinding {
        scope: ScopeIdentity {
            scope_ref: receipt.scope_ref.clone(),
            kind: receipt.scope_kind,
            lineage_ref: Some(receipt.lineage.lineage_ref.clone()),
            instance_ref: receipt.observed_instance.instance_ref.clone(),
            root_identity: receipt.observed_instance.root_identity.clone(),
            generation: receipt.observed_instance.generation,
        },
        privacy_class,
        governing_source_generation,
    };
    binding.validate()?;
    Ok(binding)
}
