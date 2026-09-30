//! Recovery-handoff runtime owners (I12.17, I7.15).
//!
//! The record side of the handoff lives next to this module: the complete
//! checkpoint payload, the capture operation, the provider gap, the retained
//! checkpoint with its revalidation, and the idempotent resume intent (see
//! [`HandoffCheckpoint`](crate::HandoffCheckpoint)). The remaining gap on
//! every row is the runtime side, which is what this module owns without
//! performing IO, minting authority, or reading a store:
//!
//! - [`HandoffCaptureRegistry`] is the capture/persistence owner state
//!   machine: every actual ELIOT-controlled compaction caller registers its
//!   capture operation here, and destructive compaction is permitted only
//!   through a registered operation with durable readback;
//! - [`HandoffProviderHook`] is the capability-aware adapter hook decision:
//!   a controllable pre-hook runs the capture operation, an internal
//!   provider compaction requires a recorded gap and admits only an
//!   explicitly partial/rehydrated continuation;
//! - [`HandoffResumeGate`] is the resume/revalidation owner: it consumes a
//!   retained checkpoint plus caller-supplied current authority observations,
//!   fails closed when authority readback is unavailable, fences only the
//!   dependent members a generation change touches, and degrades to
//!   diagnostic inspection while a blocking item survives;
//! - [`HandoffTransferDispatcher`] branches the five continuity modes with
//!   their per-mode attempt-identity rules, keeps replayed messages inert,
//!   and never resets budget, retry history, or external-effect uncertainty
//!   (the decision carries no budget fields by construction);
//! - [`HandoffRebuildRequest`] carries the canonical delta inputs the
//!   external Context caller feeds to the accepted pure Context compiler
//!   with the current approved recipe, and [`HandoffDerivedSummary`] keeps a
//!   derived summary identity separate from original evidence;
//! - [`HandoffRecoveryFinish`] binds the observed outcome to the existing
//!   [`HandoffCausalLink`](crate::HandoffCausalLink) and the attempt-bound
//!   intent only after the required checks, reconciling repeats instead of
//!   launching another worker, and advances the intent to executed only when
//!   the bound worker actually executes;
//! - [`recover_handoff`] runs these owners in order so every helper has a
//!   real caller: registry permit, evidence, gate, dispatcher, effect
//!   reconciliation, rebuild request, and finish.
//!
//! A checkpoint reference alone, a saved provider token, or a bare
//! continuation handle is never sufficient input: resume evidence is the
//! [`HandoffResumeEvidence`] enum, whose reference-only arm fails closed with
//! [`HandoffRecoveryError::CheckpointPayloadRequired`]. A native
//! continuation handle admits an equal attempt only together with its
//! session, compatible route, and fresh authority epoch, as the existing
//! link validator already enforces.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{OperationId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AgentAttemptId, ContractError, HandoffAttemptIdentity, HandoffCaptureAcceptance,
    HandoffCaptureOperation, HandoffCausalLink, HandoffCheckpointError, HandoffCheckpointId,
    HandoffContinuity, HandoffEffectDisposition, HandoffEffectRecord,
    HandoffProviderCompactionCapability, HandoffProviderGap, HandoffResumeIntent,
    HandoffResumeRevalidation, HandoffResumeStatus, HandoffSourceGenerations, PublicReference,
    RetainedHandoffCheckpoint, TaskControllerLease, validate_text,
};

/// Failure of a recovery-handoff runtime step.
///
/// Every variant names the failing gate; no failure is collapsed into a
/// generic code. Record-level failures keep their typed owner errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffRecoveryError {
    /// A handoff checkpoint record rejection, already typed by its owner.
    #[error(transparent)]
    Checkpoint(#[from] HandoffCheckpointError),
    /// A shared agent-contract rejection, already typed by the owner crate.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// No capture operation is registered for this checkpoint, so no caller
    /// may compact under it.
    #[error("no capture operation is registered for checkpoint {checkpoint_id}")]
    UnregisteredCaptureCaller {
        /// The checkpoint a caller tried to compact under.
        checkpoint_id: String,
    },
    /// The checkpoint is already registered under another capture operation.
    #[error("checkpoint {checkpoint_id} is already registered under another capture operation")]
    DuplicateCaptureRegistration {
        /// The already-registered checkpoint.
        checkpoint_id: String,
    },
    /// An internal provider compaction was handled without a recorded gap.
    #[error("internal provider compaction requires a recorded provider gap")]
    MissingProviderGap,
    /// A provider that offers the controllable pre-hook has no gap to
    /// record; it has a capture operation to run.
    #[error(
        "a controllable pre-hook provider has no gap to record; run the capture operation instead"
    )]
    UnexpectedProviderGap,
    /// The recorded provider gap does not admit this continuity.
    #[error("continuity {continuity:?} is refused under the recorded provider gap")]
    ContinuationRefusedForGap {
        /// The refused continuity.
        continuity: HandoffContinuity,
    },
    /// Only a reference was supplied where the complete payload is required.
    #[error(
        "a checkpoint reference alone cannot resume; the complete checkpoint payload is required"
    )]
    CheckpointPayloadRequired,
    /// Current authority could not be read back, so no executable resumed
    /// session is issued.
    #[error("current authority readback is unavailable; no executable resumed session is issued")]
    AuthorityReadbackUnavailable,
    /// The carried revalidation no longer matches current observations.
    #[error("the carried revalidation does not match the current authority observations")]
    StaleRevalidationObservations,
    /// A non-fresh transfer requires the causal link it is bound to.
    #[error("a non-fresh transfer requires the causal link it is bound to")]
    LinkRequired,
    /// A fresh transfer inherits no state and admits no causal link.
    #[error("a fresh transfer inherits no conversational state and admits no causal link")]
    LinkForbiddenForFresh,
    /// The bound link names a different target attempt than the intent.
    #[error("the causal link names a different target attempt than the resume intent")]
    TargetAttemptMismatch,
    /// The outcome link is not the link the retained checkpoint is bound to.
    #[error("the outcome link is not the link the retained checkpoint is bound to")]
    ResumedLinkMismatch,
    /// Only an admitted or executing outcome can be bound.
    #[error("only an admitted or executing outcome can be bound; observed {status:?}")]
    OutcomeNotAdmissible {
        /// The observed status that cannot be bound.
        status: HandoffResumeStatus,
    },
    /// A derived summary reused the checkpoint identity instead of carrying
    /// its own derived identity.
    #[error("a derived summary must carry its own identity, not the checkpoint identity")]
    DerivedSummaryReusesCheckpointIdentity,
    /// A derived summary does not source from this rebuild request.
    #[error("a derived summary does not source from this rebuild request")]
    DerivedSummarySourceMismatch,
}

/// Registered capture operations at the controlled boundary (I12.17).
///
/// Every actual ELIOT-controlled compaction and resumable handoff caller
/// registers its capture operation here: the registry carries checkpoint
/// identity to operation identity, reconciles a lost commit response
/// against the same operation, and permits destructive compaction only
/// through a registered operation with durable readback. An unregistered
/// caller cannot obtain a permit. Registering, reconciling, or gating
/// performs no IO and proves no persistence; the Governor/Task Controller
/// producer and the Store own the durable path.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCaptureRegistry {
    /// Capture operations keyed by the checkpoint identity they persist.
    operations: BTreeMap<String, HandoffCaptureOperation>,
}

impl HandoffCaptureRegistry {
    /// Registers a capture operation with its first observed acceptance.
    ///
    /// Re-registering the same operation reconciles its acceptance through
    /// [`HandoffCaptureOperation::reconcile`], which still refuses a second
    /// checkpoint identity. Registering the same checkpoint under another
    /// operation is refused.
    pub fn register(
        &mut self,
        operation: HandoffCaptureOperation,
    ) -> Result<(), HandoffRecoveryError> {
        operation.validate()?;
        let checkpoint_id = operation.checkpoint_id.clone();
        let key = checkpoint_id.as_str().to_owned();
        match self.operations.get_mut(&key) {
            None => {
                self.operations.insert(key, operation);
                Ok(())
            }
            Some(existing) => {
                if existing.operation_id.as_str() != operation.operation_id.as_str() {
                    return Err(HandoffRecoveryError::DuplicateCaptureRegistration {
                        checkpoint_id: key,
                    });
                }
                existing.reconcile(&checkpoint_id, operation.acceptance.clone())?;
                Ok(())
            }
        }
    }

    /// Returns the registered capture operation for one checkpoint, if any.
    ///
    /// The canonical persistence caller reads the registration before
    /// committing, so a second capture of the same checkpoint replays the
    /// same operation instead of registering over durable acceptance.
    pub fn operation(
        &self,
        checkpoint_id: &HandoffCheckpointId,
    ) -> Option<&HandoffCaptureOperation> {
        self.operations.get(checkpoint_id.as_str())
    }

    /// Reconciles a lost commit response against the registered operation.
    ///
    /// The operation keeps its identity: reconciling never mints a second
    /// checkpoint for one operation, and an unknown acceptance still refuses
    /// destructive compaction until durable readback arrives.
    pub fn reconcile_commit(
        &mut self,
        operation_id: &OperationId,
        checkpoint_id: &HandoffCheckpointId,
        acceptance: HandoffCaptureAcceptance,
    ) -> Result<(), HandoffRecoveryError> {
        let key = checkpoint_id.as_str().to_owned();
        let existing = self
            .operations
            .values_mut()
            .find(|operation| operation.operation_id.as_str() == operation_id.as_str());
        match existing {
            None => Err(HandoffRecoveryError::UnregisteredCaptureCaller { checkpoint_id: key }),
            Some(operation) => {
                operation.reconcile(checkpoint_id, acceptance)?;
                Ok(())
            }
        }
    }

    /// Refuses the requested compaction unless the checkpoint is registered
    /// with durable readback.
    pub fn require_compaction_permit(
        &self,
        checkpoint_id: &HandoffCheckpointId,
    ) -> Result<(), HandoffRecoveryError> {
        match self.operations.get(checkpoint_id.as_str()) {
            None => Err(HandoffRecoveryError::UnregisteredCaptureCaller {
                checkpoint_id: checkpoint_id.as_str().to_owned(),
            }),
            Some(operation) => {
                operation.require_compaction_permit()?;
                Ok(())
            }
        }
    }
}

/// Capability-aware adapter hook decision (I12.17).
///
/// A provider that offers the controllable pre-hook runs the capture
/// operation; there is no gap to record. A provider that compacts
/// internally without a controllable pre-hook requires the honestly
/// recorded gap, and continuation is restricted to the explicitly
/// partial/rehydrated path the gap admits. The hook mints no capture and
/// serializes no private native reasoning or transcript.
pub struct HandoffProviderHook;

impl HandoffProviderHook {
    /// Records an honestly observed internal provider compaction as a gap.
    ///
    /// The gap carries the provider and the observed cause only: no private
    /// native reasoning or transcript is serialized, and no checkpoint is
    /// claimed to have preceded the compaction. Continuation under the
    /// returned gap stays restricted to the explicitly partial/rehydrated
    /// path through [`Self::admit_continuation`], and every other continuity
    /// is refused with the dependent action.
    ///
    /// STITCH: adapter/fabric entrypoints that observe an internal
    /// compaction without a controllable pre-hook record here. No provider
    /// adapter on main offers such a pre-hook (the claude/codex/opencode
    /// adapters launch sidecars and only measure compaction as probe
    /// telemetry), so every observed provider compaction records a gap
    /// rather than claiming a preceding capture.
    pub fn record_internal_compaction(
        provider_ref: PublicReference,
        cause: String,
    ) -> Result<HandoffProviderGap, HandoffRecoveryError> {
        validate_text(&cause, "provider_gap.cause")?;
        let gap = HandoffProviderGap {
            provider_ref,
            capability: HandoffProviderCompactionCapability::InternalCompactionWithoutPreHook,
            cause,
        };
        gap.validate()?;
        Ok(gap)
    }

    /// Admits or refuses continuation for one provider observation.
    pub fn admit_continuation(
        capability: HandoffProviderCompactionCapability,
        gap: Option<&HandoffProviderGap>,
        continuity: HandoffContinuity,
    ) -> Result<(), HandoffRecoveryError> {
        match capability {
            HandoffProviderCompactionCapability::ControllablePreHook => {
                if gap.is_some() {
                    return Err(HandoffRecoveryError::UnexpectedProviderGap);
                }
                Ok(())
            }
            HandoffProviderCompactionCapability::InternalCompactionWithoutPreHook => {
                let gap = gap.ok_or(HandoffRecoveryError::MissingProviderGap)?;
                gap.validate()?;
                if gap.admits_continuation(continuity) {
                    Ok(())
                } else {
                    Err(HandoffRecoveryError::ContinuationRefusedForGap { continuity })
                }
            }
        }
    }
}

/// Current authority observations the resume owner supplies (I12.17).
///
/// The observations are caller-supplied precisely because this crate reads
/// no owner: the Kernel queries the current task, scope, world, module,
/// policy, route, and lease owners and carries their answers here. The
/// generations and fence are compared against the carried revalidation; the
/// lease presenter is checked against the current Task Controller lease
/// without revoking anything, since revocation belongs to the real owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffAuthorityObservations {
    /// Generations the resume owner observes now.
    pub current_generations: HandoffSourceGenerations,
    /// Fence the resume owner observes now.
    pub current_fence: StateFence,
    /// Whether current authority could be read back. When false, no
    /// executable resumed session is issued.
    pub authority_readback_available: bool,
    /// Current Task Controller lease the presenter is checked against.
    pub current_lease: TaskControllerLease,
    /// Lease holder the resume presenter claims.
    pub lease_holder: String,
    /// Lease epoch the resume presenter claims.
    pub lease_epoch: u64,
}

impl HandoffAuthorityObservations {
    /// Re-checks the observation record.
    pub fn validate(&self) -> Result<(), HandoffRecoveryError> {
        self.current_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        self.current_lease.validate()?;
        validate_text(&self.lease_holder, "observations.lease_holder")?;
        Ok(())
    }

    /// Returns whether the presenter holds the current lease at the current
    /// epoch. A mismatch fails closed into fencing instructions for the
    /// real owner, never into a blanket revocation here.
    pub fn lease_is_current(&self) -> bool {
        self.current_lease
            .authorizes(&self.lease_holder, self.lease_epoch)
    }
}

/// Resume evidence the decision gate consumes (I12.17).
///
/// The gate consumes the complete retained payload, never a bare handle: a
/// saved provider token, a public reference, or a continuation handle alone
/// is refused with
/// [`HandoffRecoveryError::CheckpointPayloadRequired`]. The reference-only
/// arm exists so that refusal is a typed branch the gate takes, rather than
/// an unwritten assumption.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffResumeEvidence {
    /// The complete retained checkpoint with its resume-time revalidation.
    Complete(Box<RetainedHandoffCheckpoint>),
    /// Only a reference was supplied; no payload, no revalidation.
    ReferenceOnly(PublicReference),
}

impl HandoffResumeEvidence {
    /// Returns the retained payload, refusing a reference-only resume.
    pub fn retained(&self) -> Result<&RetainedHandoffCheckpoint, HandoffRecoveryError> {
        match self {
            Self::Complete(retained) => Ok(retained.as_ref()),
            Self::ReferenceOnly(_) => Err(HandoffRecoveryError::CheckpointPayloadRequired),
        }
    }
}

/// Fencing instruction for a stale lease, carried to its real owner.
///
/// The instruction names the Task Controller lease that stopped matching;
/// revocation or fencing is executed by the Task Controller owner, never by
/// this record. An expired lease is not proof that an effect stopped, so
/// the checkpoint's unreconciled effects stay
/// [`HandoffEffectDisposition::OutcomeUnknown`](crate::HandoffEffectDisposition)
/// until reconciled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffLeaseFencing {
    /// Lease owner that must fence the stale lease: `task-controller`.
    pub owner: String,
    /// Holder the stale presenter claimed.
    pub holder: String,
    /// Epoch the stale presenter claimed.
    pub epoch: u64,
}

/// Owner handle named by [`HandoffLeaseFencing::owner`].
pub const HANDOFF_LEASE_OWNER_TASK_CONTROLLER: &str = "task-controller";

impl HandoffLeaseFencing {
    /// Carries a stale Task Controller lease observation to its owner.
    pub fn stale_task_controller_lease(
        holder: String,
        epoch: u64,
    ) -> Result<Self, HandoffRecoveryError> {
        validate_text(&holder, "lease_fencing.holder")?;
        Ok(Self {
            owner: HANDOFF_LEASE_OWNER_TASK_CONTROLLER.to_owned(),
            holder,
            epoch,
        })
    }

    /// Re-checks the fencing instruction.
    pub fn validate(&self) -> Result<(), HandoffRecoveryError> {
        if self.owner != HANDOFF_LEASE_OWNER_TASK_CONTROLLER {
            return Err(ContractError::ForeignOwner("lease_fencing.owner").into());
        }
        validate_text(&self.holder, "lease_fencing.holder")?;
        Ok(())
    }
}

/// Dependent-only fencing derived from a resume-time revalidation (I12.17).
///
/// A changed generation fences only the dependent permissions and content
/// it names, never unrelated work. An empty [`fenced_members`](Self::fenced_members)
/// list means the retained fence still covers the resume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffFencing {
    /// Changed generation or fence members: a subset of
    /// `scope`, `world`, `module`, `route`, `fence`.
    pub fenced_members: Vec<String>,
    /// Stale-lease fencing for the real owner, when the presenter is not
    /// the current holder at the current epoch.
    pub stale_lease: Option<HandoffLeaseFencing>,
}

impl HandoffFencing {
    /// Derives fencing from one revalidation and one lease observation.
    pub fn for_resume(
        revalidation: &HandoffResumeRevalidation,
        stale_lease: Option<HandoffLeaseFencing>,
    ) -> Result<Self, HandoffRecoveryError> {
        if let Some(fencing) = &stale_lease {
            fencing.validate()?;
        }
        Ok(Self {
            fenced_members: changed_generation_members(revalidation),
            stale_lease,
        })
    }

    /// Returns whether the retained fence no longer covers the dependent
    /// permissions and content, so the resume owner must obtain fresh
    /// authority and rebuild a current delta View.
    pub fn requires_rebuild(&self) -> bool {
        !self.fenced_members.is_empty()
    }
}

/// Names the revalidation members that changed since the capture boundary.
fn changed_generation_members(revalidation: &HandoffResumeRevalidation) -> Vec<String> {
    let mut members = Vec::new();
    if revalidation.scope_changed {
        members.push("scope".to_owned());
    }
    if revalidation.world_changed {
        members.push("world".to_owned());
    }
    if revalidation.module_changed {
        members.push("module".to_owned());
    }
    if revalidation.route_changed {
        members.push("route".to_owned());
    }
    if revalidation.fence_changed {
        members.push("fence".to_owned());
    }
    members
}

/// Resume admission decided by the resume owner (I12.17).
///
/// An executable admission carries its fencing and rebuild obligations; a
/// diagnostic admission keeps inspection available while the dependent
/// action stays blocked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffResumeAdmission {
    /// The resumed session may be issued under the carried obligations.
    Executable {
        /// Dependent-only fencing for changed generations and stale leases.
        fencing: HandoffFencing,
        /// Whether a current delta View must be rebuilt before execution.
        rebuild_required: bool,
        /// Whether unfinished verifiers or unreconciled effects survive, so
        /// a restart retains them instead of dropping them.
        effects_pending: bool,
    },
    /// The dependent action stays blocked; diagnostic inspection may remain
    /// available.
    DiagnosticOnly {
        /// Observed cause of the blocked action.
        cause: String,
    },
}

/// Requires the resume intent to name the handoff and target attempt the
/// retained link binds.
///
/// A crossed intent — the right target under the wrong handoff, or a stale
/// target — is refused as a stale resume request before any authority,
/// dispatch, or binding step can act on it, so it can never launch another
/// worker.
fn require_intent_for_link(
    intent: &HandoffResumeIntent,
    link: &HandoffCausalLink,
) -> Result<(), HandoffRecoveryError> {
    if intent.handoff_id != link.handoff_id || intent.target_attempt_id != link.target_attempt_id {
        return Err(HandoffCheckpointError::StaleResumeRequest {
            handoff_id: intent.handoff_id.as_str().to_owned(),
        }
        .into());
    }
    Ok(())
}

/// Resume/revalidation owner (I12.17, I7.15).
///
/// The gate consumes the complete retained payload with its carried
/// revalidation, checks the carried revalidation against current
/// observations, and admits an executable session only under fresh
/// authority. When authority readback is unavailable it issues nothing: a
/// missing readback is refused, never treated as a fresh grant. A blocking
/// critical item degrades the admission to diagnostic inspection instead of
/// dropping the item.
pub struct HandoffResumeGate;

impl HandoffResumeGate {
    /// Admits or refuses a resumed session for one retained checkpoint.
    pub fn admit(
        evidence: &HandoffResumeEvidence,
        observations: &HandoffAuthorityObservations,
        intent: &HandoffResumeIntent,
    ) -> Result<HandoffResumeAdmission, HandoffRecoveryError> {
        observations.validate()?;
        intent.validate()?;
        let retained = evidence.retained()?;
        retained.validate()?;
        require_intent_for_link(intent, &retained.link)?;
        if !observations.authority_readback_available {
            return Err(HandoffRecoveryError::AuthorityReadbackUnavailable);
        }
        if retained.revalidation.current_generations != observations.current_generations
            || retained.revalidation.current_fence != observations.current_fence
        {
            return Err(HandoffRecoveryError::StaleRevalidationObservations);
        }
        let stale_lease = if observations.lease_is_current() {
            None
        } else {
            Some(HandoffLeaseFencing::stale_task_controller_lease(
                observations.lease_holder.clone(),
                observations.lease_epoch,
            )?)
        };
        let fencing = HandoffFencing::for_resume(&retained.revalidation, stale_lease)?;
        let effects_pending = retained.checkpoint.has_unfinished_verifiers_or_effects();
        if retained.checkpoint.dependent_action_blocked() {
            return Ok(HandoffResumeAdmission::DiagnosticOnly {
                cause: "a blocking critical attention item or conflict survives; the dependent action stays blocked while diagnostic inspection remains available"
                    .to_owned(),
            });
        }
        let rebuild_required = fencing.requires_rebuild();
        Ok(HandoffResumeAdmission::Executable {
            fencing,
            rebuild_required,
            effects_pending,
        })
    }
}

/// Transfer decision branched by the dispatch owner (I7.15).
///
/// `NativeResume` keeps the attempt identity only with the compatible
/// native session, route, and fresh authority the link validator already
/// required. `NewAttempt` and `InertReplay` create the required new ELIOT
/// attempt; `FreshStart` inherits no conversational state and admits no
/// causal link. Replay is inert context by decision value: it never
/// re-executes old tools.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffDispatchDecision {
    /// The compatible native session continues under fresh authority.
    NativeResume {
        /// Target attempt the resume continues.
        target_attempt_id: AgentAttemptId,
    },
    /// A new ELIOT attempt carries preserved results and unresolved work.
    NewAttempt {
        /// Continuity the new attempt transfers under.
        continuity: HandoffContinuity,
        /// Target attempt the transfer creates.
        target_attempt_id: AgentAttemptId,
    },
    /// A new ELIOT attempt receives replayed public messages as inert
    /// context; tools and effects never re-execute.
    InertReplay {
        /// Target attempt the replay fills with inert context.
        target_attempt_id: AgentAttemptId,
    },
    /// A new attempt starts with no prior conversational state.
    FreshStart {
        /// Target attempt the fresh start creates.
        target_attempt_id: AgentAttemptId,
    },
}

impl HandoffDispatchDecision {
    /// Returns the target attempt the decision binds.
    pub fn target_attempt_id(&self) -> &AgentAttemptId {
        match self {
            Self::NativeResume { target_attempt_id }
            | Self::NewAttempt {
                target_attempt_id, ..
            }
            | Self::InertReplay { target_attempt_id }
            | Self::FreshStart { target_attempt_id } => target_attempt_id,
        }
    }

    /// Returns whether the decided transfer may execute tools.
    ///
    /// The rule is the existing per-mode value: replayed messages are inert
    /// context and must never re-execute old tools.
    pub fn may_execute_tools(&self) -> bool {
        match self {
            Self::NativeResume { .. } => HandoffContinuity::NativeResume.permits_tool_execution(),
            Self::NewAttempt { continuity, .. } => continuity.permits_tool_execution(),
            Self::InertReplay { .. } => HandoffContinuity::Replayed.permits_tool_execution(),
            Self::FreshStart { .. } => HandoffContinuity::Fresh.permits_tool_execution(),
        }
    }
}

/// Continuity dispatcher (I7.15).
///
/// Every mode is an explicit branch: no mode inherits the identity rule of
/// another, and no transfer is validated by a blanket comparison. The
/// provider hook runs inside the dispatch so no entrypoint can admit a
/// transfer without the capability decision.
pub struct HandoffTransferDispatcher;

impl HandoffTransferDispatcher {
    /// Dispatches one transfer under its continuity mode.
    pub fn dispatch(
        continuity: HandoffContinuity,
        attempt_identity: &HandoffAttemptIdentity,
        link: Option<&HandoffCausalLink>,
        capability: HandoffProviderCompactionCapability,
        gap: Option<&HandoffProviderGap>,
        target_attempt_id: AgentAttemptId,
    ) -> Result<HandoffDispatchDecision, HandoffRecoveryError> {
        HandoffProviderHook::admit_continuation(capability, gap, continuity)?;
        match continuity {
            HandoffContinuity::Fresh => {
                if link.is_some() {
                    return Err(HandoffRecoveryError::LinkForbiddenForFresh);
                }
                if *attempt_identity != HandoffAttemptIdentity::NoInheritedState {
                    return Err(ContractError::HandoffAttemptIdentityMismatch { continuity }.into());
                }
                Ok(HandoffDispatchDecision::FreshStart { target_attempt_id })
            }
            HandoffContinuity::Replayed => {
                let link = link.ok_or(HandoffRecoveryError::LinkRequired)?;
                link.validate(attempt_identity)?;
                Ok(HandoffDispatchDecision::InertReplay { target_attempt_id })
            }
            HandoffContinuity::NativeResume => {
                let link = link.ok_or(HandoffRecoveryError::LinkRequired)?;
                link.validate(attempt_identity)?;
                Ok(HandoffDispatchDecision::NativeResume { target_attempt_id })
            }
            HandoffContinuity::NativeFork | HandoffContinuity::Rehydrated => {
                let link = link.ok_or(HandoffRecoveryError::LinkRequired)?;
                link.validate(attempt_identity)?;
                Ok(HandoffDispatchDecision::NewAttempt {
                    continuity,
                    target_attempt_id,
                })
            }
        }
    }
}

/// Reconciliation instruction for one in-flight operation (I7.15).
///
/// A lost acknowledgement, an expired lease, or a silent retry is not proof
/// that an effect stopped, so an unreconciled operation is retained for
/// reconciliation instead of being re-dispatched or dropped. A completed
/// effect keeps the receipt its owner retains; it is never re-executed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffEffectInstruction {
    /// The operation was admitted but never dispatched; no effect exists.
    NeverDispatched {
        /// Identity of the in-flight operation.
        operation_id: OperationId,
    },
    /// The effect completed; its receipt stays with its owner.
    CompletedReceiptRetained {
        /// Identity of the in-flight operation.
        operation_id: OperationId,
    },
    /// The dispatched outcome is unreconciled; the operation stays open
    /// under the observed cause until its owner reconciles it.
    RetainForReconciliation {
        /// Identity of the in-flight operation.
        operation_id: OperationId,
        /// Observed cause of the unreconciled outcome.
        cause: String,
    },
}

/// Lost-acknowledgement and replay reconciler (I7.15).
///
/// Reconciling one disposition instead of re-deriving it after a lost
/// acknowledgement is what keeps a retry from duplicating a launch or a
/// tool: no instruction here dispatches, executes, or clears an effect.
pub struct HandoffEffectReconciler;

impl HandoffEffectReconciler {
    /// Reconciles one in-flight operation without duplicating its effect.
    pub fn reconcile_effect(
        effect: &HandoffEffectRecord,
    ) -> Result<HandoffEffectInstruction, HandoffRecoveryError> {
        validate_text(effect.operation_id.as_str(), "effect.operation_id")?;
        match &effect.disposition {
            HandoffEffectDisposition::NotStarted => Ok(HandoffEffectInstruction::NeverDispatched {
                operation_id: effect.operation_id.clone(),
            }),
            HandoffEffectDisposition::Completed { receipt_ref } => {
                receipt_ref.validate()?;
                Ok(HandoffEffectInstruction::CompletedReceiptRetained {
                    operation_id: effect.operation_id.clone(),
                })
            }
            HandoffEffectDisposition::OutcomeUnknown { cause } => {
                validate_text(cause, "effect.cause")?;
                Ok(HandoffEffectInstruction::RetainForReconciliation {
                    operation_id: effect.operation_id.clone(),
                    cause: cause.clone(),
                })
            }
        }
    }
}

/// Canonical delta inputs for the Context rebuild caller (I12.17).
///
/// The runtime caller obtains these inputs from the retained checkpoint and
/// invokes the accepted pure Context compiler with the current approved
/// recipe. The compiler itself is never called here: the `ContextCompiler`
/// stays pure, and this request is the caller-side value the external
/// delta-reconstruction caller consumes. Changed, invalidated, and
/// unavailable members travel explicitly: the changed generation members
/// are named on the request, while unavailable members and known losses
/// stay on the checkpoint the request names, so the denominator cannot
/// shrink to what happened to fit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffDeltaInputs {
    /// Frozen diff, digest-bound as an immutable artifact.
    pub diff_ref: PublicReference,
    /// Immutable artifacts the boundary depends on.
    pub artifact_refs: Vec<PublicReference>,
    /// Handles of the epistemic position at the boundary.
    pub epistemic_position_handles: Vec<PublicReference>,
    /// Handles of the exact atoms the next decision is load-bearing on.
    pub load_bearing_atom_handles: Vec<PublicReference>,
    /// Verifiers that were still pending at the boundary, retained across
    /// the restart.
    pub pending_verifier_refs: Vec<PublicReference>,
    /// Source scope, world, module, and route generations at the boundary.
    pub source_generations: HandoffSourceGenerations,
    /// State Fence the checkpoint was captured under.
    pub state_fence: StateFence,
}

impl HandoffDeltaInputs {
    /// Re-checks the delta inputs, including the digest-bound diff.
    pub fn validate(&self) -> Result<(), HandoffRecoveryError> {
        self.diff_ref.validate()?;
        if self.diff_ref.digest.is_none() {
            return Err(HandoffCheckpointError::DiffReferenceIsNotImmutable.into());
        }
        for reference in self
            .artifact_refs
            .iter()
            .chain(self.epistemic_position_handles.iter())
            .chain(self.load_bearing_atom_handles.iter())
            .chain(self.pending_verifier_refs.iter())
        {
            reference.validate()?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::StaleFence)?;
        Ok(())
    }
}

/// Derived summary identity (I12.17, I12.13).
///
/// A summary has a derived identity with source links; a missing original
/// stays missing and is never replaced by fluent prose labeled evidence.
/// The summary reference must not reuse the checkpoint identity, and it
/// must source from the rebuild request it is attached to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffDerivedSummary {
    /// Reference of the derived summary, with its own identity.
    pub summary_ref: PublicReference,
    /// Checkpoint the summary derives from.
    pub source_checkpoint_id: HandoffCheckpointId,
    /// Source links the derived summary was compiled from.
    pub source_refs: Vec<PublicReference>,
}

impl HandoffDerivedSummary {
    /// Records a derived summary with its own identity and source links.
    pub fn new(
        summary_ref: PublicReference,
        source_checkpoint_id: HandoffCheckpointId,
        source_refs: Vec<PublicReference>,
    ) -> Result<Self, HandoffRecoveryError> {
        summary_ref.validate()?;
        validate_text(
            source_checkpoint_id.as_str(),
            "derived_summary.source_checkpoint_id",
        )?;
        if summary_ref.id.as_str() == source_checkpoint_id.as_str() {
            return Err(HandoffRecoveryError::DerivedSummaryReusesCheckpointIdentity);
        }
        if source_refs.is_empty() {
            return Err(ContractError::EmptyCollection("derived_summary.source_refs").into());
        }
        for reference in &source_refs {
            reference.validate()?;
        }
        Ok(Self {
            summary_ref,
            source_checkpoint_id,
            source_refs,
        })
    }

    /// Admits the summary against the rebuild request it derives from.
    pub fn validate_against(
        &self,
        request: &HandoffRebuildRequest,
    ) -> Result<(), HandoffRecoveryError> {
        self.summary_ref.validate()?;
        if self.source_checkpoint_id != request.checkpoint_id {
            return Err(HandoffRecoveryError::DerivedSummarySourceMismatch);
        }
        Ok(())
    }
}

/// Rebuild request for the Context delta-reconstruction caller (I12.17).
///
/// The request returns the checkpoint, the target recipe and fence, and the
/// revalidation evidence together. Missing mandatory floor, verifier, or
/// directive content blocks its dependent action through the gate's
/// diagnostic admission; it never becomes prose labeled evidence here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffRebuildRequest {
    /// Checkpoint the rebuild derives from.
    pub checkpoint_id: HandoffCheckpointId,
    /// Continuity the retained transfer supports.
    pub continuity: HandoffContinuity,
    /// Canonical delta inputs for the pure Context compiler.
    pub delta: HandoffDeltaInputs,
    /// Current approved recipe the compiler must run under.
    pub recipe_ref: PublicReference,
    /// Changed generation or fence members, named explicitly.
    pub changed_members: Vec<String>,
    /// Resume-time revalidation the rebuild derives from, carried together
    /// with the checkpoint, recipe and fence for the external caller.
    pub revalidation: HandoffResumeRevalidation,
    /// Derived summaries admitted against this request so far.
    pub summaries: Vec<HandoffDerivedSummary>,
}

impl HandoffRebuildRequest {
    /// Derives the rebuild request from one retained checkpoint and the
    /// current approved recipe.
    pub fn from_retained(
        retained: &RetainedHandoffCheckpoint,
        recipe_ref: PublicReference,
    ) -> Result<Self, HandoffRecoveryError> {
        retained.validate()?;
        recipe_ref.validate()?;
        let checkpoint = &retained.checkpoint;
        let delta = HandoffDeltaInputs {
            diff_ref: checkpoint.diff_ref.clone(),
            artifact_refs: checkpoint.artifact_refs.clone(),
            epistemic_position_handles: checkpoint.epistemic_position_handles.clone(),
            load_bearing_atom_handles: checkpoint.load_bearing_atom_handles.clone(),
            pending_verifier_refs: checkpoint.pending_verifier_refs.clone(),
            source_generations: checkpoint.source_generations,
            state_fence: checkpoint.state_fence.clone(),
        };
        delta.validate()?;
        Ok(Self {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            continuity: checkpoint.continuity,
            delta,
            recipe_ref,
            changed_members: changed_generation_members(&retained.revalidation),
            revalidation: retained.revalidation.clone(),
            summaries: Vec::new(),
        })
    }

    /// Attaches a compiler-produced derived summary after checking its
    /// derived identity against this request.
    pub fn attach_derived_summary(
        &mut self,
        summary: HandoffDerivedSummary,
    ) -> Result<(), HandoffRecoveryError> {
        summary.validate_against(self)?;
        self.summaries.push(summary);
        Ok(())
    }
}

/// Recovery-handoff finisher (I12.17, I7.15).
///
/// The observed resume outcome is bound to the existing causal link and the
/// attempt-bound intent only after the required checkpoint, content, and
/// authority checks. A repeated resume request reconciles the same target
/// intent; a stale request naming another target cannot launch another
/// worker. Retained data and resources are released only by their existing
/// owners under terminal-retention rules, never by this record. The
/// attempt-record update itself belongs to the attempt owner, which cites
/// the bound link's revalidation reference.
pub struct HandoffRecoveryFinish;

impl HandoffRecoveryFinish {
    /// Binds the observed outcome to the causal link and intent.
    ///
    /// Only an admitted or executing outcome can be bound, the intent
    /// advances forward along the five-state recovery path, and the bound
    /// link carries the post-resume revalidation reference. A fresh
    /// transfer binds no link and returns `None`.
    pub fn finish(
        retained: &RetainedHandoffCheckpoint,
        intent: &mut HandoffResumeIntent,
        request: &HandoffResumeIntent,
        link: Option<&HandoffCausalLink>,
        observed: HandoffResumeStatus,
    ) -> Result<Option<HandoffCausalLink>, HandoffRecoveryError> {
        retained.validate()?;
        intent.reconcile(request)?;
        require_intent_for_link(intent, &retained.link)?;
        if !matches!(
            observed,
            HandoffResumeStatus::ResumeAdmitted | HandoffResumeStatus::ResumedExecution
        ) {
            return Err(HandoffRecoveryError::OutcomeNotAdmissible { status: observed });
        }
        match link {
            None => {
                if retained.checkpoint.continuity != HandoffContinuity::Fresh {
                    return Err(HandoffRecoveryError::LinkRequired);
                }
                intent.advance(observed)?;
                Ok(None)
            }
            Some(link) => {
                if link.handoff_id != retained.link.handoff_id {
                    return Err(HandoffRecoveryError::ResumedLinkMismatch);
                }
                if link.target_attempt_id != intent.target_attempt_id {
                    return Err(HandoffRecoveryError::TargetAttemptMismatch);
                }
                intent.advance(observed)?;
                let mut bound = link.clone();
                bound.post_resume_revalidation_ref = Some(retained.revalidation_ref()?);
                bound.validate(&retained.attempt_identity)?;
                Ok(Some(bound))
            }
        }
    }

    /// Advances an admitted intent to executed when the bound worker actually
    /// executes.
    ///
    /// The transition reconciles the same target intent, so a repeated
    /// execution report observes the recorded stage instead of launching
    /// again, and a stale request naming another target is refused. Only an
    /// admitted intent advances: every earlier state has no launched worker
    /// to report, and an already-executing intent admits no second launch.
    pub fn mark_executed(
        intent: &mut HandoffResumeIntent,
        request: &HandoffResumeIntent,
    ) -> Result<(), HandoffRecoveryError> {
        intent.reconcile(request)?;
        if !intent.admits_execution() {
            return Err(HandoffRecoveryError::OutcomeNotAdmissible {
                status: intent.status,
            });
        }
        intent.advance(HandoffResumeStatus::ResumedExecution)?;
        Ok(())
    }
}

/// Inputs to one recovery-handoff run.
///
/// Every field is caller-supplied observation or record: the pipeline reads
/// no store, queries no owner, and mints no authority. The resume owner
/// carries these values; cross-owner reads stay with the owners the issue
/// names.
#[derive(Clone, Debug)]
pub struct HandoffRecoveryInputs<'a> {
    /// Checkpoint the compaction caller wants to compact under.
    pub capture_checkpoint_id: &'a HandoffCheckpointId,
    /// Registered capture operations the permit is gated on.
    pub registry: &'a HandoffCaptureRegistry,
    /// Resume evidence: the complete payload or a refused bare reference.
    pub evidence: &'a HandoffResumeEvidence,
    /// Current authority observations from the owning readers.
    pub observations: &'a HandoffAuthorityObservations,
    /// Attempt-identity evidence the transfer runs under.
    pub attempt_identity: &'a HandoffAttemptIdentity,
    /// Causal link the transfer is bound to, absent only for fresh starts.
    pub link: Option<&'a HandoffCausalLink>,
    /// Provider capability observed for the compacting route.
    pub capability: HandoffProviderCompactionCapability,
    /// Honestly recorded provider gap, required for internal compaction.
    pub gap: Option<&'a HandoffProviderGap>,
    /// Current approved recipe the rebuild runs under.
    pub recipe_ref: &'a PublicReference,
    /// Incoming resume request, reconciled against the bound intent.
    pub resume_request: &'a HandoffResumeIntent,
}

/// Outcome of one recovery-handoff run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffRecoveryOutput {
    /// Resume admission decided by the gate.
    pub admission: HandoffResumeAdmission,
    /// Transfer decision, absent when the dependent action stays blocked.
    pub dispatch: Option<HandoffDispatchDecision>,
    /// Rebuild request, present only when the retained fence no longer
    /// covers the dependent permissions and content.
    pub rebuild: Option<HandoffRebuildRequest>,
    /// Per-operation reconciliation instructions; no instruction dispatches
    /// or clears an effect.
    pub effect_instructions: Vec<HandoffEffectInstruction>,
    /// Bound causal link carrying the revalidation reference, absent for
    /// fresh starts and blocked actions.
    pub bound_link: Option<HandoffCausalLink>,
    /// Latest reported recovery status for the bound intent.
    pub intent_status: HandoffResumeStatus,
}

/// Returns whether the intent already reached at least the given recovery
/// stage, so a repeated run observes the recorded stage instead of
/// regressing it or failing the repeat.
fn status_at_or_after(current: HandoffResumeStatus, floor: HandoffResumeStatus) -> bool {
    use HandoffResumeStatus::{
        CheckpointStored, CompactionObserved, ResumeAdmitted, ResumedExecution, RevalidationPending,
    };
    matches!(
        (current, floor),
        (_, CheckpointStored)
            | (
                CompactionObserved | RevalidationPending | ResumeAdmitted | ResumedExecution,
                CompactionObserved,
            )
            | (
                RevalidationPending | ResumeAdmitted | ResumedExecution,
                RevalidationPending,
            )
            | (ResumeAdmitted | ResumedExecution, ResumeAdmitted)
            | (ResumedExecution, ResumedExecution)
    )
}

/// Advances the intent to at least the given recovery stage.
///
/// A repeat that already reached or passed the stage observes it instead of
/// regressing: only a genuinely earlier status after a later one is refused,
/// by [`HandoffResumeIntent::advance`].
fn advance_floor(
    intent: &mut HandoffResumeIntent,
    floor: HandoffResumeStatus,
) -> Result<(), HandoffRecoveryError> {
    if status_at_or_after(intent.status, floor) {
        return Ok(());
    }
    intent.advance(floor)?;
    Ok(())
}

/// Runs the recovery-handoff owners in order (I12.17, I7.15).
///
/// The run gates destructive compaction on durable readback, consumes the
/// complete retained payload, admits the resume under fresh authority,
/// dispatches the continuity branch, reconciles every in-flight operation
/// without duplicating launch or tools, derives the rebuild request when a
/// changed generation fences the retained authority, and binds the admitted
/// outcome to the causal link and intent. The bound status is
/// [`HandoffResumeStatus::ResumeAdmitted`]: the bound worker may be launched,
/// and the resume owner advances the intent to
/// [`HandoffResumeStatus::ResumedExecution`] through
/// [`HandoffRecoveryFinish::mark_executed`] only when the worker actually
/// executes, so admitted and executed resumes stay distinct. A blocked
/// dependent action returns a diagnostic admission with no dispatch, no
/// rebuild, and no bound link.
pub fn recover_handoff(
    inputs: &HandoffRecoveryInputs<'_>,
    intent: &mut HandoffResumeIntent,
) -> Result<HandoffRecoveryOutput, HandoffRecoveryError> {
    inputs
        .registry
        .require_compaction_permit(inputs.capture_checkpoint_id)?;
    let retained = inputs.evidence.retained()?;
    advance_floor(intent, HandoffResumeStatus::CompactionObserved)?;
    advance_floor(intent, HandoffResumeStatus::RevalidationPending)?;
    let admission = HandoffResumeGate::admit(inputs.evidence, inputs.observations, intent)?;
    let rebuild_required = match &admission {
        HandoffResumeAdmission::Executable {
            rebuild_required, ..
        } => *rebuild_required,
        HandoffResumeAdmission::DiagnosticOnly { .. } => {
            return Ok(HandoffRecoveryOutput {
                admission,
                dispatch: None,
                rebuild: None,
                effect_instructions: Vec::new(),
                bound_link: None,
                intent_status: intent.status,
            });
        }
    };
    let continuity = retained.checkpoint.continuity;
    let dispatch = HandoffTransferDispatcher::dispatch(
        continuity,
        inputs.attempt_identity,
        inputs.link,
        inputs.capability,
        inputs.gap,
        intent.target_attempt_id.clone(),
    )?;
    advance_floor(intent, HandoffResumeStatus::ResumeAdmitted)?;
    let mut effect_instructions = Vec::with_capacity(retained.checkpoint.effects.len());
    for effect in &retained.checkpoint.effects {
        effect_instructions.push(HandoffEffectReconciler::reconcile_effect(effect)?);
    }
    let rebuild = if rebuild_required {
        Some(HandoffRebuildRequest::from_retained(
            retained,
            inputs.recipe_ref.clone(),
        )?)
    } else {
        None
    };
    let bound_link = HandoffRecoveryFinish::finish(
        retained,
        intent,
        inputs.resume_request,
        inputs.link,
        HandoffResumeStatus::ResumeAdmitted,
    )?;
    Ok(HandoffRecoveryOutput {
        admission,
        dispatch: Some(dispatch),
        rebuild,
        effect_instructions,
        bound_link,
        intent_status: intent.status,
    })
}
