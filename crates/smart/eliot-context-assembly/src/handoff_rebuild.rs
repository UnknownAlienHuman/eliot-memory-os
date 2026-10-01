//! Rebuild a current delta View from a retained handoff checkpoint (#1730 W6).
//!
//! This module is the Context delta-reconstruction caller. The runtime caller
//! performs the #1729 coherent reads (fence-bound revision heads observed
//! before and after a stable read through the Governor read owner), admits
//! the current content through the admission owner, and presents the evidence
//! here. [`rebuild_handoff_view`] re-checks that evidence, invokes the
//! accepted pure compiler ([`assemble_active_view_with_measurement`]) with
//! the current approved recipe, and returns the checkpoint, the target
//! View/recipe/fence, and the revalidation evidence together.
//!
//! Rebuild, not restamp: changed generation/fence members travel on the
//! request, retained-fence-bound content is named invalidated once a member
//! moves, unavailable members and known losses (including lost distinctions)
//! are emitted verbatim from the retained checkpoint, and a derived summary
//! keeps its own identity with source links through the owner's
//! `HandoffRebuildRequest::attach_derived_summary` check, re-applied here to
//! every carried summary. A missing original stays
//! missing: nothing here synthesizes content for an unavailable member or a
//! known loss.
//!
//! Missing mandatory floor content (the compiler's explicit incompleteness)
//! or a surviving blocking critical attention item/conflict blocks the
//! dependent action as [`HandoffRebuildOutcome::DiagnosticOnly`], which keeps
//! the explicit dispositions available for diagnostic inspection. Retained-side
//! blocking (gate admission, lease fencing, continuity dispatch) stays with
//! its owners in `eliot-agent-contracts` and is never re-decided here.
//!
//! STITCH: the runtime resume owner calls [`rebuild_handoff_view`] with the
//! `HandoffRebuildRequest` derived by `recover_handoff` once an `Executable`
//! admission with `rebuild_required` exists. No provider adapter, fabric
//! entrypoint, or kernel route calls this module directly.

use eliot_agent_contracts::{
    HandoffCheckpoint, HandoffCheckpointId, HandoffContinuity, HandoffDegradation,
    HandoffDerivedSummary, HandoffKnownLoss, HandoffRebuildRequest, HandoffRecoveryError,
    HandoffResumeRevalidation, HandoffUnavailableMember, PublicReference,
    RetainedHandoffCheckpoint,
};
use eliot_context_contracts::{
    AdmittedContextSet, ContextRecipe, DecisionContextIncomplete, QualityScorecard,
    ResolvedContextRecipe,
};
use eliot_context_measurement::MeasurementParams;
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_store_api::{RevisionHead, StoreError};
use thiserror::Error;

use crate::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_measurement,
};

/// Current observations the runtime caller presents for one rebuild.
///
/// Every value is caller-observed, never retrieved here: the canonical bytes
/// behind the admitted set were read through the #1729 coherent
/// read owner (fence-bound heads, stable across the read), and the admitted
/// set was built by the admission owner under the current approved recipe.
#[derive(Clone, Debug)]
pub struct HandoffRebuildCurrent<'a> {
    /// Current admitted set built from canonical bytes read under the
    /// applicable fence.
    pub admitted: &'a AdmittedContextSet,
    /// Current approved recipe content the compiler must run under.
    pub recipe: &'a ContextRecipe,
    /// Owner-resolved approved policy revision this compilation is pinned to.
    ///
    /// #1724 W4: this is the revision whose declared `layout.role_positions` the
    /// renderer applies, so it is the executed order rather than a hint about it.
    pub approved: &'a ResolvedContextRecipe,
    /// Quality evidence for the current compilation.
    pub quality: &'a QualityScorecard,
    /// Caller-owned immutable projection parameters.
    pub policy: &'a AssemblyPolicy,
    /// Caller-owned measurement parameters for the sole #704 owner.
    pub params: &'a MeasurementParams,
    /// Full revision heads observed before the stable read.
    pub heads_before: &'a [RevisionHead],
    /// Full revision heads observed after the stable read.
    pub heads_after: &'a [RevisionHead],
}

/// Rebuilt current delta View with its checkpoint, recipe, fence, and
/// revalidation evidence (I12.17).
///
/// The checkpoint half is carried by identity plus the verbatim retained
/// dispositions; the complete retained payload stays with the resume gate
/// that admitted it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRebuiltView {
    /// Checkpoint the rebuild derives from.
    pub checkpoint_id: HandoffCheckpointId,
    /// Continuity the retained transfer supports.
    pub continuity: HandoffContinuity,
    /// Target View rebuilt by the pure compiler under the current recipe.
    pub view: ActiveUnderstandingViewResult,
    /// Current approved recipe the compiler ran under.
    pub recipe_ref: PublicReference,
    /// Applicable fence: the revalidated current fence once a generation or
    /// the fence moved, else the retained fence.
    pub fence: StateFence,
    /// Resume-time revalidation the rebuild derives from.
    pub revalidation: HandoffResumeRevalidation,
    /// Changed generation or fence members, named explicitly.
    pub changed_members: Vec<String>,
    /// Retained-fence-bound content refs invalidated for dependent use once a
    /// member moved: the retained diff plus the retained artifact refs. Empty
    /// when the retained fence still covers the resume.
    pub invalidated_members: Vec<String>,
    /// Expected members the checkpoint cannot place in an exact set,
    /// verbatim: the denominator does not shrink to what happened to fit.
    pub unavailable_members: Vec<HandoffUnavailableMember>,
    /// Losses already known at the boundary, verbatim.
    pub known_losses: Vec<HandoffKnownLoss>,
    /// Distinction names flattened from every `LOST_DISTINCTIONS`
    /// degradation across unavailable members and known losses. They must be
    /// re-derived from canonical state, never inferred from retained form.
    pub lost_distinctions: Vec<String>,
    /// Verifiers still pending at the boundary, retained across the restart.
    pub pending_verifier_refs: Vec<PublicReference>,
    /// Derived summaries admitted against the rebuild request, each with its
    /// own identity and source links.
    pub summaries: Vec<HandoffDerivedSummary>,
}

/// Blocked rebuild with its explicit dispositions for diagnostic inspection.
///
/// The dependent action stays blocked; the carried values stay available to
/// inspect what is missing or surviving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffRebuildDiagnostic {
    /// Observed cause of the blocked dependent action.
    pub cause: String,
    /// Checkpoint the rebuild attempt derives from.
    pub checkpoint_id: HandoffCheckpointId,
    /// Resume-time revalidation the rebuild attempt derives from.
    pub revalidation: HandoffResumeRevalidation,
    /// Surviving blocking critical attention/conflict refs, empty when the
    /// block is a current floor gap rather than a retained survivor.
    pub blocking_refs: Vec<PublicReference>,
    /// Current floor gap reported by the compiler, present when mandatory
    /// floor content is missing from the current admitted set.
    pub incomplete: Option<Box<DecisionContextIncomplete>>,
    /// Expected members the checkpoint cannot place in an exact set.
    pub unavailable_members: Vec<HandoffUnavailableMember>,
    /// Losses already known at the boundary.
    pub known_losses: Vec<HandoffKnownLoss>,
}

/// Outcome of one delta View rebuild.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffRebuildOutcome {
    /// The current delta View was rebuilt; the dependent action may proceed
    /// under the carried fence once its remaining owners admit it.
    Executable {
        /// Rebuilt View with checkpoint, recipe, fence, and revalidation.
        rebuilt: Box<HandoffRebuiltView>,
    },
    /// The dependent action stays blocked; diagnostic inspection remains
    /// available on the carried dispositions.
    DiagnosticOnly {
        /// Blocked rebuild with its explicit dispositions.
        diagnostic: Box<HandoffRebuildDiagnostic>,
    },
}

/// Failure of one delta View rebuild.
///
/// Record-level failures keep their typed owner errors; only this caller's
/// own binding and coherence refusals are local variants.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffRebuildError {
    /// A handoff recovery owner rejected the retained input or a summary.
    #[error(transparent)]
    Recovery(#[from] HandoffRecoveryError),
    /// The accepted pure compiler refused the current inputs.
    #[error(transparent)]
    Assembly(#[from] AssemblyError),
    /// A presented revision head failed its owner validation.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The rebuild request does not derive from the retained checkpoint it
    /// was presented with.
    #[error("rebuild request does not derive from the retained checkpoint")]
    CheckpointMismatch,
    /// The supplied recipe content is not the approved recipe the request
    /// names.
    #[error("supplied recipe is not the approved recipe named by the rebuild request")]
    RecipeMismatch,
    /// The observed heads moved across the stable read, so there is no
    /// coherent canonical delta to compile.
    #[error("observed revision heads moved across the stable read")]
    UnstableHeads,
    /// An observed head is not bound to the applicable fence.
    #[error("observed revision head is not bound to the applicable fence")]
    ForeignHead,
    /// The current admitted set is not bound to the applicable fence.
    #[error("current admitted set is not bound to the applicable fence")]
    StaleFence,
}

/// Rebuilds the current delta View for one retained checkpoint (I12.17).
///
/// The caller obtains canonical delta inputs using #1729 and invokes the
/// accepted pure Context compiler with the current approved recipe through
/// this function. Fail-closed order:
///
/// 1. The retained checkpoint proves its own binding and flag consistency
///    through its owner validator.
/// 2. The request must derive from that retained checkpoint (identity,
///    continuity, revalidation, retained fence, and digest-bound diff).
/// 3. The request's own delta inputs and every carried derived summary are
///    re-checked through their owner validators.
/// 4. The supplied recipe content must be the approved recipe the request
///    names.
/// 5. The #1729 coherence evidence must hold: every observed head validates,
///    the full heads are stable across the read, and every head is bound to
///    the applicable fence.
/// 6. A surviving blocking critical item degrades to diagnostic inspection.
/// 7. The pure compiler runs; its explicit incompleteness degrades to
///    diagnostic inspection while any other refusal stays typed.
///
/// A missing original stays missing: unavailable members, known losses, and
/// lost distinctions are emitted from the retained checkpoint verbatim, and
/// no summary may stand in for them as original evidence.
pub fn rebuild_handoff_view(
    retained: &RetainedHandoffCheckpoint,
    request: &HandoffRebuildRequest,
    current: &HandoffRebuildCurrent<'_>,
) -> Result<HandoffRebuildOutcome, HandoffRebuildError> {
    check_request_binding(retained, request)?;
    check_request_inputs(request)?;
    check_approved_recipe(request, current)?;
    let applicable = applicable_fence(request);
    check_stable_heads(current, applicable)?;
    let checkpoint = &retained.checkpoint;
    let blocking_refs = surviving_blockers(checkpoint);
    if !blocking_refs.is_empty() {
        return Ok(HandoffRebuildOutcome::DiagnosticOnly {
            diagnostic: Box::new(diagnostic(
                "a blocking critical attention item or conflict survives; the dependent action stays blocked while diagnostic inspection remains available",
                retained,
                None,
                blocking_refs,
            )),
        });
    }
    let result = match assemble_active_view_with_measurement(
        current.admitted,
        current.recipe,
        current.approved,
        current.quality.clone(),
        current.policy,
        current.params,
    ) {
        Ok(result) => result,
        Err(AssemblyError::Incomplete(incomplete)) => {
            return Ok(HandoffRebuildOutcome::DiagnosticOnly {
                diagnostic: Box::new(diagnostic(
                    "current mandatory floor content is missing; the dependent action stays blocked while diagnostic inspection remains available",
                    retained,
                    Some(incomplete),
                    Vec::new(),
                )),
            });
        }
        Err(other) => return Err(other.into()),
    };
    let rebuild_required = !request.changed_members.is_empty();
    let invalidated_members = invalidated_refs(checkpoint, rebuild_required);
    let lost_distinctions = collect_lost_distinctions(checkpoint);
    Ok(HandoffRebuildOutcome::Executable {
        rebuilt: Box::new(HandoffRebuiltView {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            continuity: request.continuity,
            view: result,
            recipe_ref: request.recipe_ref.clone(),
            fence: applicable.clone(),
            revalidation: request.revalidation.clone(),
            changed_members: request.changed_members.clone(),
            invalidated_members,
            unavailable_members: checkpoint.work.unavailable.clone(),
            known_losses: checkpoint.known_losses.clone(),
            lost_distinctions,
            pending_verifier_refs: request.delta.pending_verifier_refs.clone(),
            summaries: request.summaries.clone(),
        }),
    })
}

/// Checks fail-closed steps 1-2: the retained checkpoint proves its binding
/// and flag consistency, and the request derives from that checkpoint.
fn check_request_binding(
    retained: &RetainedHandoffCheckpoint,
    request: &HandoffRebuildRequest,
) -> Result<(), HandoffRebuildError> {
    retained.validate().map_err(HandoffRecoveryError::from)?;
    let checkpoint = &retained.checkpoint;
    if request.checkpoint_id != checkpoint.checkpoint_id
        || request.continuity != checkpoint.continuity
        || request.revalidation != retained.revalidation
        || request.delta.state_fence != checkpoint.state_fence
        || request.delta.diff_ref != checkpoint.diff_ref
    {
        return Err(HandoffRebuildError::CheckpointMismatch);
    }
    Ok(())
}

/// Checks fail-closed step 3: the request's delta inputs and every carried
/// derived summary through their owner validators.
fn check_request_inputs(request: &HandoffRebuildRequest) -> Result<(), HandoffRebuildError> {
    request
        .recipe_ref
        .validate()
        .map_err(HandoffRecoveryError::from)?;
    request.delta.validate()?;
    for summary in &request.summaries {
        summary.validate_against(request)?;
    }
    Ok(())
}

/// Checks fail-closed step 4: the supplied recipe content is valid and is
/// the approved recipe the request names.
fn check_approved_recipe(
    request: &HandoffRebuildRequest,
    current: &HandoffRebuildCurrent<'_>,
) -> Result<(), HandoffRebuildError> {
    current.recipe.validate().map_err(AssemblyError::Contract)?;
    if let Some(digest) = &request.recipe_ref.digest
        && *digest != current.recipe.recipe_sha256
    {
        return Err(HandoffRebuildError::RecipeMismatch);
    }
    Ok(())
}

/// Returns the applicable fence: the revalidated current fence once a
/// generation or the fence moved, else the retained fence.
fn applicable_fence(request: &HandoffRebuildRequest) -> &StateFence {
    if request.changed_members.is_empty() {
        &request.delta.state_fence
    } else {
        &request.revalidation.current_fence
    }
}

/// Checks fail-closed step 5: the #1729 coherence evidence holds and the
/// current admitted set is bound to the applicable fence.
fn check_stable_heads(
    current: &HandoffRebuildCurrent<'_>,
    applicable: &StateFence,
) -> Result<(), HandoffRebuildError> {
    for head in current
        .heads_before
        .iter()
        .chain(current.heads_after.iter())
    {
        head.validate()?;
    }
    if current.heads_before.len() != current.heads_after.len()
        || !current
            .heads_before
            .iter()
            .all(|head| current.heads_after.contains(head))
    {
        return Err(HandoffRebuildError::UnstableHeads);
    }
    for head in current.heads_before {
        if !fences_match_exact(&head.state_fence, applicable) {
            return Err(HandoffRebuildError::ForeignHead);
        }
    }
    if !fences_match_exact(&current.admitted.binding.state_fence, applicable) {
        return Err(HandoffRebuildError::StaleFence);
    }
    Ok(())
}

/// Collects the surviving blocking critical attention/conflict refs for
/// fail-closed step 6.
fn surviving_blockers(checkpoint: &HandoffCheckpoint) -> Vec<PublicReference> {
    checkpoint
        .critical_items
        .iter()
        .filter(|item| item.blocks_dependent_action)
        .map(|item| item.item_ref.clone())
        .collect()
}

/// Names the retained-fence-bound content invalidated for dependent use once
/// a member moved: the retained diff plus the retained artifact refs.
fn invalidated_refs(checkpoint: &HandoffCheckpoint, rebuild_required: bool) -> Vec<String> {
    if !rebuild_required {
        return Vec::new();
    }
    std::iter::once(checkpoint.diff_ref.id.as_str())
        .chain(
            checkpoint
                .artifact_refs
                .iter()
                .map(|reference| reference.id.as_str()),
        )
        .map(str::to_owned)
        .collect()
}

/// Flattens every `LOST_DISTINCTIONS` degradation across unavailable members
/// and known losses into the explicit emission.
fn collect_lost_distinctions(checkpoint: &HandoffCheckpoint) -> Vec<String> {
    let mut lost = Vec::new();
    for member in &checkpoint.work.unavailable {
        push_lost_distinctions(&member.degradation, &mut lost);
    }
    for loss in &checkpoint.known_losses {
        push_lost_distinctions(&loss.degradation, &mut lost);
    }
    lost
}

/// Builds the diagnostic value shared by both blocked paths.
fn diagnostic(
    cause: &str,
    retained: &RetainedHandoffCheckpoint,
    incomplete: Option<Box<DecisionContextIncomplete>>,
    blocking_refs: Vec<PublicReference>,
) -> HandoffRebuildDiagnostic {
    HandoffRebuildDiagnostic {
        cause: cause.to_owned(),
        checkpoint_id: retained.checkpoint.checkpoint_id.clone(),
        revalidation: retained.revalidation.clone(),
        blocking_refs,
        incomplete,
        unavailable_members: retained.checkpoint.work.unavailable.clone(),
        known_losses: retained.checkpoint.known_losses.clone(),
    }
}

/// Flattens one degradation's lost distinctions into the explicit emission.
fn push_lost_distinctions(degradation: &HandoffDegradation, out: &mut Vec<String>) {
    if let HandoffDegradation::LostDistinctions { distinctions } = degradation {
        out.extend(distinctions.iter().cloned());
    }
}
