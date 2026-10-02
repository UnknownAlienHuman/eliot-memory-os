//! Governor resume-owner join for retained handoff resume (I12.17, I7.15).
//!
//! [`capture_handoff_checkpoint`](super::capture_handoff_checkpoint) is the one
//! canonical caller that persists a checkpoint through the governed owner event
//! stream, and [`read_back_capture`](super::read_back_capture) is the durable
//! readback that admits its compaction permit. This module is the resume-side
//! symmetric join: the Governor-side entrypoint that admits a resume from one
//! retained checkpoint only after the durable capture reads back out of the
//! same owner, and only after the current authority observations come from a
//! real owner read rather than a caller assertion.
//!
//! The join performs no IO, mints no authority, launches no worker, and reads
//! no store:
//!
//! - resume evidence must be the complete retained payload: a checkpoint
//!   reference alone is refused with
//!   [`HandoffRecoveryError::CheckpointPayloadRequired`](eliot_agent_contracts::HandoffRecoveryError::CheckpointPayloadRequired),
//!   so a saved provider token, public reference, or bare continuation handle
//!   can never resume on its own;
//! - the retained payload is re-checked with the existing
//!   [`RetainedHandoffCheckpoint::validate`](eliot_agent_contracts::RetainedHandoffCheckpoint::validate),
//!   which re-runs the checkpoint-to-link binding (including the continuity
//!   attempt-identity rule) against the original digests;
//! - the durable capture is corroborated against the live owner event stream
//!   through [`stored_capture_binding`](super::stored_capture_binding): the
//!   stored text is parsed back out of the committed event, so the resume
//!   consumes what the store actually holds and not a binding the caller
//!   recomputed. A checkpoint with no committed binding is refused;
//! - current authority observations come from
//!   [`read_resume_authority_observations`], which queries the coordination
//!   owner for the live session, work item and lease under the caller's exact
//!   authority epoch and fence. The generations, the fence, the current Task
//!   Controller lease and the readback availability are all owner observations;
//!   a read that cannot be completed leaves the lease observation unusable and
//!   the gate refuses, so this join mints no generations and fabricates no
//!   fence, lease, or epoch;
//! - the admitted run itself is [`recover_handoff`](eliot_agent_contracts::recover_handoff),
//!   which gates destructive compaction on durable readback, admits the resume
//!   under fresh authority, dispatches the continuity branch (replayed
//!   messages stay inert and never re-execute tools), reconciles every
//!   in-flight operation without duplicating launch or effects, derives the
//!   rebuild request for the external Context caller, and binds the admitted
//!   outcome to the causal link and intent.
//!
//! What this join deliberately does not do belongs to its real owners, which
//! are named here rather than faked:
//!
//! - the world, module and route generation observations come from those
//!   owners; the coordination owner supplies the scope generation it fences
//!   with and refuses the join when the remaining owners are not wired;
//! - advancing an admitted intent to executed belongs to the worker owner and
//!   runs through
//!   [`HandoffRecoveryFinish::mark_executed`](eliot_agent_contracts::HandoffRecoveryFinish::mark_executed)
//!   only when the bound worker actually executes;
//! - updating the attempt record belongs to the attempt owner, which cites
//!   the bound link's revalidation reference;
//! - rebuilding the delta View belongs to the external Context
//!   delta-reconstruction caller, which feeds the returned rebuild request to
//!   the accepted pure Context compiler under the current approved recipe.

#![forbid(unsafe_code)]

use eliot_agent_contracts::{
    HandoffAttemptIdentity, HandoffAuthorityObservations, HandoffCausalLink, HandoffCaptureRegistry,
    HandoffCheckpointError, HandoffCheckpointId, HandoffProviderCompactionCapability,
    HandoffProviderGap, HandoffRecoveryError, HandoffRecoveryInputs, HandoffRecoveryOutput,
    HandoffResumeEvidence, HandoffResumeIntent, HandoffSourceGenerations, PublicReference,
    TaskControllerLease, recover_handoff,
};
use eliot_contracts::{EpochId, StateFence};
use thiserror::Error;

use super::{
    CoordinationError, CoordinationOwner, HandoffPersistenceError, stored_capture_binding,
};

/// Failure of the Governor resume-owner join.
///
/// The owner-read refusal keeps the coordination owner's own typed error, the
/// authority and evidence refusals keep the recovery owner's typed errors, the
/// durable-capture corroboration keeps the persistence owner's typed error, and
/// the retained-payload re-check keeps the checkpoint record owner's typed
/// error. No failure is collapsed into a generic code.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffResumeError {
    /// A capture, registry, or permit rejection from the persistence join.
    #[error(transparent)]
    Persistence(#[from] HandoffPersistenceError),
    /// A retained-payload or checkpoint-record rejection from the checkpoint
    /// owner, e.g. the re-checked checkpoint-to-link binding.
    #[error(transparent)]
    Checkpoint(#[from] HandoffCheckpointError),
    /// An authority, evidence, dispatch, or binding rejection, already typed by
    /// the recovery owner.
    #[error(transparent)]
    Recovery(#[from] HandoffRecoveryError),
    /// A live-owner read rejection, already typed by the coordination owner.
    #[error(transparent)]
    Coordination(#[from] CoordinationError),
}

/// What the resume owner asks the live owner for.
///
/// Every field is an identity the caller already holds; the join resolves them
/// against the owner and never accepts a caller-supplied generation, fence, or
/// lease as the current observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffResumeAuthorityQuery<'a> {
    /// Work item the retained checkpoint belongs to.
    pub work_item_id: &'a str,
    /// Session presenting the resume.
    pub session_id: &'a str,
    /// Owner-supplied time the read is taken at.
    pub now: u64,
    /// Authority epoch the presenter runs under.
    pub authority_epoch: EpochId,
    /// Complete fence the presenter runs under.
    pub state_fence: &'a StateFence,
    /// Generations the non-coordination owners (world, module, route) report.
    ///
    /// These are cross-owner observations the resume owner carries, not values
    /// the coordination owner can derive. They are compared member by member
    /// against the retained boundary, so a change in any one of them fences
    /// only the dependent permissions and content.
    pub cross_owner_generations: HandoffSourceGenerations,
    /// Task Controller lease the presenter claims to hold.
    pub claimed_lease: TaskControllerLease,
}

/// Reads the current authority the resume gate must be decided against.
///
/// The scope generation and the current fence are the coordination owner's own
/// observations: the live session, work item and lease are read under the
/// presenter's exact authority epoch and fence, and the scope generation comes
/// from the fence the owner itself enforces. The world, module and route
/// generations are the cross-owner observations the caller carries, and the
/// claimed Task Controller lease stays the presenter's claim so the gate's
/// holder/epoch comparison is a real check rather than a self-assertion.
///
/// The returned value is an observation, not authority: `lease_is_current`
/// still has to hold before the presenter is treated as the current holder, and
/// the gate still refuses when `authority_readback_available` is false.
pub fn read_resume_authority_observations<'a>(
    owner: &CoordinationOwner,
    query: &HandoffResumeAuthorityQuery<'a>,
) -> Result<HandoffAuthorityObservations, HandoffResumeError> {
    let projection = owner.read_active_work_lease(
        query.work_item_id,
        query.session_id,
        query.now,
        query.authority_epoch.clone(),
        query.state_fence,
    )?;
    let current_fence = projection.lease.state_fence.clone();
    let current_generations = HandoffSourceGenerations {
        scope: current_fence.resource_generation,
        world: query.cross_owner_generations.world,
        module: query.cross_owner_generations.module,
        route: query.cross_owner_generations.route,
    };
    let observations = HandoffAuthorityObservations {
        current_generations,
        current_fence,
        authority_readback_available: true,
        current_lease: TaskControllerLease {
            holder: projection.lease.holder_session_id.clone(),
            epoch: projection.lease.authority_epoch.sequence.get(),
        },
        lease_holder: query.claimed_lease.holder.clone(),
        lease_epoch: query.claimed_lease.epoch,
    };
    observations.validate()?;
    Ok(observations)
}

/// The identity a resume request carries into the recovery run.
///
/// It is the resume owner's own request record: the retained evidence, the
/// attempt-identity evidence the transfer runs under, the link it is bound to,
/// the provider capability and gap, and the current approved recipe. The
/// current authority observations are deliberately absent — they come from
/// [`read_resume_authority_observations`], never from this record.
#[derive(Clone, Debug)]
pub struct HandoffResumeRequest<'a> {
    /// Checkpoint the compaction caller compacts under.
    pub capture_checkpoint_id: &'a HandoffCheckpointId,
    /// Registered capture operations the compaction permit is gated on.
    pub registry: &'a HandoffCaptureRegistry,
    /// Complete retained evidence, or a refused bare reference.
    pub evidence: &'a HandoffResumeEvidence,
    /// Attempt-identity evidence the transfer runs under.
    pub attempt_identity: &'a HandoffAttemptIdentity,
    /// Causal link the transfer is bound to, absent only for a fresh start.
    pub link: Option<&'a HandoffCausalLink>,
    /// Provider capability observed for the compacting route.
    pub capability: HandoffProviderCompactionCapability,
    /// Honestly recorded provider gap, required for internal compaction.
    pub gap: Option<&'a HandoffProviderGap>,
    /// Current approved recipe the rebuild runs under.
    pub recipe_ref: &'a PublicReference,
    /// Incoming resume request, reconciled against the bound intent.
    pub resume_request: &'a HandoffResumeIntent,
    /// Live-owner read the current authority observations come from.
    pub authority: &'a HandoffResumeAuthorityQuery<'a>,
}

/// Resumes under the live owner read, the durable readback, and the retained
/// payload, in that order.
///
/// This is the Governor-side entrypoint a real resume caller reaches. It
/// resolves the current authority observations from the coordination owner,
/// feeds the recovery owners, and returns their output; every refusal along the
/// way is typed and none of them issues an executable resumed session.
///
/// The authority read lives here and not one layer down: this join owns the
/// live owner, and it resolves
/// [`read_resume_authority_observations`] exactly once before it builds
/// [`HandoffRecoveryInputs`]. Those observations then travel inside
/// `inputs.observations` as an owner observation, which is the only channel the
/// recovery owners read current authority from.
pub fn resume_retained_handoff(
    owner: &CoordinationOwner,
    request: &HandoffResumeRequest<'_>,
    intent: &mut HandoffResumeIntent,
) -> Result<HandoffRecoveryOutput, HandoffResumeError> {
    let observations = read_resume_authority_observations(owner, request.authority)?;
    let inputs = HandoffRecoveryInputs {
        capture_checkpoint_id: request.capture_checkpoint_id,
        registry: request.registry,
        evidence: request.evidence,
        observations: &observations,
        attempt_identity: request.attempt_identity,
        link: request.link,
        capability: request.capability,
        gap: request.gap,
        recipe_ref: request.recipe_ref,
        resume_request: request.resume_request,
    };
    resume_from_retained_handoff(owner, request.registry, &inputs, intent)
}

/// Resumes from one retained handoff checkpoint through the Governor owner.
///
/// Reads the durable capture back out of the owner, re-checks the complete
/// retained payload with its existing validator, and runs the recovery-handoff
/// owners in order over caller-resolved inputs. A reference-only resume, a
/// binding mismatch, or a capture that does not read back fails closed: no
/// executable resumed session is issued.
///
/// This join takes no authority query. The current authority observations are
/// already resolved and carried in `inputs.observations`, and taking the query
/// here as well would leave two ways to state current authority for one run: an
/// observation the owner read, and a caller record that merely looks like one.
/// Reading the owner twice would not fix that, it would only make two reads
/// that can disagree. A caller that has not resolved the observations yet goes
/// through [`resume_retained_handoff`], which is the layer that owns the read.
pub fn resume_from_retained_handoff(
    owner: &CoordinationOwner,
    registry: &HandoffCaptureRegistry,
    inputs: &HandoffRecoveryInputs<'_>,
    intent: &mut HandoffResumeIntent,
) -> Result<HandoffRecoveryOutput, HandoffResumeError> {
    let retained = inputs.evidence.retained()?;
    retained.validate()?;
    // Existence of the committed binding is the corroboration: the text is
    // parsed out of the owner event stream by `stored_capture_binding`, so this
    // proves the store holds this checkpoint rather than that a caller could
    // recompute one. A checkpoint with no committed binding is refused here.
    stored_capture_binding(owner, &retained.checkpoint.checkpoint_id)?;
    registry.require_compaction_permit(&retained.checkpoint.checkpoint_id)?;
    Ok(recover_handoff(inputs, intent)?)
}
