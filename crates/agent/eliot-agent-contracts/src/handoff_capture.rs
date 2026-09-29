//! One controlled-boundary capture operation for the pre-compaction handoff
//! checkpoint (I12.17).
//!
//! Every ELIOT-controlled compaction and resumable-handoff boundary is
//! registered against this one operation, so a boundary cannot capture under a
//! private path and a capture cannot be replayed as a second checkpoint
//! identity. Destructive compaction is admitted only after a durable readback
//! of the record the governed transaction wrote, and three refusals are
//! structural rather than procedural:
//!
//! - a transport acknowledgement and a locally computed hash are not a
//!   readback, so neither can move a capture into the read-back state;
//! - every digest is compared with the value recorded at capture time and is
//!   never recomputed over the bytes this operation still holds;
//! - every retained artifact is leased to this capture identity, so an
//!   artifact that is merely named by a predictable path is not owned by it.
//!
//! The module performs no IO and reads no store. It is the admission rule the
//! Governor/Task Controller capture path and the Store readback path both
//! answer to, and the resume path refuses without it.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ContractVersion, OperationId, ResourceGeneration, StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AgentAttemptId, ContractError, HANDOFF_EFFECT_REFERENCE_KIND, HandoffCheckpoint,
    HandoffCheckpointId, HandoffCursors, HandoffSourceGenerations, PublicReference, RevisionId,
    validate_text,
};

/// Stable contract name of the controlled-boundary capture operation.
pub const HANDOFF_CAPTURE_CONTRACT_NAME: &str = "eliot.agent.handoff-capture";

/// Current semantic revision of the controlled-boundary capture operation.
///
/// A capture record written against another revision is refused instead of
/// being read as the current admission rule.
pub const HANDOFF_CAPTURE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// An ELIOT-controlled boundary that must capture before it proceeds.
///
/// The set is closed and every arm names the product symbol it is registered
/// against, so the registration is a fact about real callers rather than a
/// claim that some caller exists. A boundary that is not an arm here has no
/// capture operation and must not present a checkpoint as its own.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCaptureBoundary {
    /// The host plugin pre-compaction hook, the boundary Claude Code fires
    /// before it destroys conversational state.
    HostPreCompactHook,
    /// Durable work-unit resume onto the exact remaining work.
    DurableWorkUnitResume,
    /// Sealed plan-attachment rehydration after a restart.
    SealedAttachmentRehydration,
    /// The new attempt created after a meaningful effect, carrying the sealed
    /// handoff away from the source attempt.
    NextAttemptAfterEffect,
}

impl HandoffCaptureBoundary {
    /// Every controlled boundary, as the independent denominator a
    /// registration census is compared against.
    pub const CONTROLLED_BOUNDARIES: [Self; 4] = [
        Self::HostPreCompactHook,
        Self::DurableWorkUnitResume,
        Self::SealedAttachmentRehydration,
        Self::NextAttemptAfterEffect,
    ];

    /// The product symbol this boundary is registered against.
    ///
    /// The value is the owner-side symbol, not a display label: it is what a
    /// reader checks to decide whether a boundary was registered against the
    /// real caller or against a name that merely looks like one.
    #[must_use]
    pub const fn caller_symbol(self) -> &'static str {
        match self {
            Self::HostPreCompactHook => {
                "crates/eliot-engine/src/plugin.rs::EliotHookService::evaluate_pre_compact"
            }
            Self::DurableWorkUnitResume => {
                "crates/agent/eliot-swarm/src/lib.rs::DurableWorkMachine::resume"
            }
            Self::SealedAttachmentRehydration => {
                "crates/agent/eliot-swarm/src/durable_dispatch.rs::rehydrate_attachment_through_port"
            }
            Self::NextAttemptAfterEffect => {
                "crates/kernel/eliot-ipc/src/host_conformance.rs::AttemptGate::next_attempt_after_effect"
            }
        }
    }

    /// Whether passing this boundary destroys conversational state that the
    /// checkpoint is the only remaining record of.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::HostPreCompactHook)
    }
}

/// Condition under which a retained artifact may be released.
///
/// A lease has no arm that releases on the loss of a response, because an
/// unreconciled outcome is not a release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffLeaseRelease {
    /// Release only after the resumed attempt has reconciled the retained
    /// artifacts against its own work.
    AfterResumeReconciled,
    /// Release only under the owner's terminal-retention rule.
    TerminalRetention,
}

/// One artifact retained across the boundary and leased to this capture.
///
/// The lease names the capture that owns it. Retention is therefore compared
/// against the operation that performed the capture, and an artifact that only
/// appears under a predictable reference is not retained by anybody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffArtifactLease {
    /// Exact immutable artifact reference held across the boundary.
    pub artifact_ref: PublicReference,
    /// Capture identity that owns this retention.
    pub retained_by_capture: HandoffCheckpointId,
    /// Condition under which the retention may be released.
    pub release: HandoffLeaseRelease,
}

impl HandoffArtifactLease {
    fn validate(&self) -> Result<(), HandoffCaptureError> {
        self.artifact_ref.validate()?;
        validate_text(
            self.retained_by_capture.as_str(),
            "lease.retained_by_capture",
        )?;
        if self.artifact_ref.digest.is_none() {
            return Err(HandoffCaptureError::RetainedArtifactIsNotImmutable);
        }
        Ok(())
    }
}

/// What the store returned when the capture record was read back.
///
/// Every field is what the read observed. Nothing here is derived from the
/// bytes the capture operation still holds, so a readback cannot agree with
/// the capture by construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCaptureReadback {
    /// Identity the store returned the record under.
    pub capture_id: HandoffCheckpointId,
    /// Capture operation the store committed.
    pub operation_id: OperationId,
    /// Boundary the store recorded for the commit.
    pub boundary: HandoffCaptureBoundary,
    /// Canonical generation the read was served from.
    pub read_generation: ResourceGeneration,
    /// Digest the store reports for the stored checkpoint payload.
    pub readback_checkpoint_digest: String,
    /// Digest the store reports for the stored frozen diff.
    pub readback_diff_digest: String,
    /// Artifacts the store reports as retained for this capture.
    pub observed_retained_artifacts: Vec<PublicReference>,
    /// Verifiers the store reports as still pending for this capture.
    pub observed_pending_verifiers: Vec<PublicReference>,
    /// In-flight operations the store reports as still unreconciled.
    pub observed_pending_effects: Vec<PublicReference>,
}

/// Recorded state of one capture operation.
///
/// `Committed` is deliberately distinct from `ReadBack`: the first is a
/// transport fact about a request, the second is an observation of stored
/// bytes. Only the second admits destructive compaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCaptureState {
    /// The bounded source snapshot was taken and the diff frozen. Nothing has
    /// been written.
    Captured,
    /// The governed transaction acknowledged the write. This is a transport
    /// acknowledgement and is not a durable readback.
    Committed {
        /// Exact acknowledgement observed for the commit.
        transport_acknowledgement: String,
    },
    /// The commit response was lost, so acceptance is unknown. Compaction is
    /// refused and the operation reconciles under its existing identity.
    CommitResponseUnknown {
        /// Observed cause of the lost response.
        cause: String,
    },
    /// The stored record was read back and admitted.
    ReadBack {
        /// What the store returned.
        readback: Box<HandoffCaptureReadback>,
    },
}

impl HandoffCaptureState {
    /// Whether this state is a durable readback of stored bytes.
    #[must_use]
    pub const fn is_durable_readback(&self) -> bool {
        matches!(self, Self::ReadBack { .. })
    }
}

/// The bounded source snapshot one capture operation takes at a boundary.
///
/// This is the coherent snapshot the boundary obtains before it is allowed to
/// proceed: who was running, what was frozen, what is retained, and which
/// verifiers and in-flight effects were still open. It is the input to
/// [`HandoffCapture::capture`] and carries no persistence claim of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCaptureSource {
    /// Identity of this capture operation and of the checkpoint it captures.
    pub capture_id: HandoffCheckpointId,
    /// Identity of the one capture operation for this boundary and attempt.
    pub operation_id: OperationId,
    /// Controlled boundary this capture is taken at.
    pub boundary: HandoffCaptureBoundary,
    /// Task that was running at the boundary.
    pub source_task_id: TaskId,
    /// Attempt that was running at the boundary.
    pub source_attempt_id: AgentAttemptId,
    /// Session the source attempt was running in.
    pub source_session_ref: PublicReference,
    /// Plan revision observed at the boundary.
    pub source_plan_revision: RevisionId,
    /// Acceptance revision the plan revision was admitted against.
    pub source_acceptance_revision: RevisionId,
    /// State Fence the snapshot was taken under.
    pub source_fence: StateFence,
    /// Scope, world, module and route generations observed at the boundary.
    pub source_generations: HandoffSourceGenerations,
    /// Source event and outbox cursors observed at the boundary.
    pub source_cursors: HandoffCursors,
    /// Current diff, frozen as a digest-bound immutable artifact.
    pub frozen_diff: PublicReference,
    /// Digest of the captured checkpoint payload as recorded at capture time.
    pub recorded_checkpoint_digest: String,
    /// Digest of the frozen diff as recorded at capture time.
    pub recorded_diff_digest: String,
    /// The independently declared set of artifacts this capture retains.
    pub expected_retained_artifacts: Vec<PublicReference>,
    /// The independently declared set of verifiers still pending.
    pub expected_pending_verifiers: Vec<PublicReference>,
    /// The independently declared set of in-flight operation identities whose
    /// external effects are still unreconciled.
    pub expected_pending_effects: Vec<PublicReference>,
}

impl HandoffCaptureSource {
    /// Validates the bounded source snapshot.
    ///
    /// The frozen diff must be an immutable digest-bound artifact, and both
    /// recorded digests must be present text, so a snapshot that names a
    /// mutable path or a bare commit identity cannot be captured.
    pub fn validate(&self) -> Result<(), HandoffCaptureError> {
        validate_text(self.capture_id.as_str(), "source.capture_id")?;
        validate_text(self.source_task_id.as_str(), "source.source_task_id")?;
        validate_text(self.source_attempt_id.as_str(), "source.source_attempt_id")?;
        self.source_session_ref.validate()?;
        validate_text(
            &self.recorded_checkpoint_digest,
            "source.recorded_checkpoint_digest",
        )?;
        validate_text(&self.recorded_diff_digest, "source.recorded_diff_digest")?;
        validate_artifacts(&self.expected_retained_artifacts)?;
        validate_artifacts(&self.expected_pending_verifiers)?;
        validate_artifacts(&self.expected_pending_effects)?;
        self.frozen_diff.validate()?;
        if self.frozen_diff.digest.is_none() {
            return Err(HandoffCaptureError::FrozenDiffIsNotImmutable);
        }
        self.validate_coherence()
    }

    /// Proves the snapshot was taken at one moment rather than assembled from
    /// several.
    ///
    /// A checkpoint whose fence disagrees with its own scope, world, module and
    /// route generations, or whose revisions are blank, is a record stitched
    /// together after the boundary and cannot bound what was captured. Every
    /// disagreement is a named refusal.
    fn validate_coherence(&self) -> Result<(), HandoffCaptureError> {
        validate_text(
            self.source_plan_revision.as_str(),
            "source.source_plan_revision",
        )?;
        validate_text(
            self.source_acceptance_revision.as_str(),
            "source.source_acceptance_revision",
        )?;
        self.source_fence
            .validate()
            .map_err(|_| HandoffCaptureError::SnapshotFenceIsStale)?;
        if self.source_fence.resource_generation != self.source_generations.scope {
            return Err(HandoffCaptureError::SnapshotIsNotCoherent {
                field: "source_generations.scope",
            });
        }
        self.source_cursors
            .validate()
            .map_err(HandoffCaptureError::Capture)?;
        Ok(())
    }
}

/// One capture of a handoff checkpoint at a controlled boundary.
///
/// The record is the whole admission rule: what was captured, what was frozen,
/// what is retained, what the store returned, and whether the boundary may now
/// destroy conversational state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCapture {
    /// Identity of this capture operation and of the checkpoint it captured.
    pub capture_id: HandoffCheckpointId,
    /// Identity of the one capture operation for this boundary and attempt.
    pub operation_id: OperationId,
    /// Contract revision this record was written against.
    pub contract_version: ContractVersion,
    /// Controlled boundary this capture was taken at.
    pub boundary: HandoffCaptureBoundary,
    /// Task that was running at the boundary.
    pub source_task_id: TaskId,
    /// Attempt that was running at the boundary.
    pub source_attempt_id: AgentAttemptId,
    /// Session the source attempt was running in.
    pub source_session_ref: PublicReference,
    /// Plan revision observed at the boundary.
    pub source_plan_revision: RevisionId,
    /// Acceptance revision the plan revision was admitted against.
    pub source_acceptance_revision: RevisionId,
    /// State Fence the capture was taken under.
    pub source_fence: StateFence,
    /// Scope, world, module and route generations observed at the boundary.
    pub source_generations: HandoffSourceGenerations,
    /// Source event and outbox cursors observed at the boundary.
    pub source_cursors: HandoffCursors,
    /// Current diff, frozen as a digest-bound immutable artifact.
    pub frozen_diff: PublicReference,
    /// Digest of the captured checkpoint payload as recorded at capture time.
    pub recorded_checkpoint_digest: String,
    /// Digest of the frozen diff as recorded at capture time.
    pub recorded_diff_digest: String,
    /// The independently declared set of artifacts this capture retains.
    pub expected_retained_artifacts: Vec<PublicReference>,
    /// The independently declared set of verifiers still pending.
    pub expected_pending_verifiers: Vec<PublicReference>,
    /// The independently declared set of in-flight operation identities whose
    /// external effects are still unreconciled.
    pub expected_pending_effects: Vec<PublicReference>,
    /// Retention leases owned by this capture.
    pub artifact_leases: Vec<HandoffArtifactLease>,
    /// Recorded state of the capture.
    pub state: HandoffCaptureState,
}

impl HandoffCapture {
    /// Constructs and validates a capture at a controlled boundary.
    ///
    /// The frozen diff must already be an immutable digest-bound artifact: a
    /// mutable path or a bare commit identity is refused here rather than at
    /// resume, so a capture cannot be taken that nothing can be read back from.
    /// The retention leases must be present and owned by this capture, so a
    /// boundary cannot be captured with nothing actually retained.
    pub fn capture(
        source: HandoffCaptureSource,
        artifact_leases: Vec<HandoffArtifactLease>,
    ) -> Result<Self, HandoffCaptureError> {
        let capture = Self {
            capture_id: source.capture_id,
            operation_id: source.operation_id,
            contract_version: HANDOFF_CAPTURE_CONTRACT_VERSION,
            boundary: source.boundary,
            source_task_id: source.source_task_id,
            source_attempt_id: source.source_attempt_id,
            source_session_ref: source.source_session_ref,
            source_plan_revision: source.source_plan_revision,
            source_acceptance_revision: source.source_acceptance_revision,
            source_fence: source.source_fence,
            source_generations: source.source_generations,
            source_cursors: source.source_cursors,
            frozen_diff: source.frozen_diff,
            recorded_checkpoint_digest: source.recorded_checkpoint_digest,
            recorded_diff_digest: source.recorded_diff_digest,
            expected_retained_artifacts: source.expected_retained_artifacts,
            expected_pending_verifiers: source.expected_pending_verifiers,
            expected_pending_effects: source.expected_pending_effects,
            artifact_leases,
            state: HandoffCaptureState::Captured,
        };
        capture.validate()?;
        Ok(capture)
    }

    /// Validates the capture against its own contract revision and identity.
    pub fn validate(&self) -> Result<(), HandoffCaptureError> {
        if self.contract_version != HANDOFF_CAPTURE_CONTRACT_VERSION {
            return Err(HandoffCaptureError::UnsupportedContractVersion {
                version: self.contract_version,
            });
        }
        self.source().validate()?;
        self.validate_leases()
    }

    /// The bounded source snapshot this capture was taken from.
    #[must_use]
    pub fn source(&self) -> HandoffCaptureSource {
        HandoffCaptureSource {
            capture_id: self.capture_id.clone(),
            operation_id: self.operation_id,
            boundary: self.boundary,
            source_task_id: self.source_task_id,
            source_attempt_id: self.source_attempt_id.clone(),
            source_session_ref: self.source_session_ref.clone(),
            source_plan_revision: self.source_plan_revision.clone(),
            source_acceptance_revision: self.source_acceptance_revision.clone(),
            source_fence: self.source_fence,
            source_generations: self.source_generations,
            source_cursors: self.source_cursors.clone(),
            frozen_diff: self.frozen_diff.clone(),
            recorded_checkpoint_digest: self.recorded_checkpoint_digest.clone(),
            recorded_diff_digest: self.recorded_diff_digest.clone(),
            expected_retained_artifacts: self.expected_retained_artifacts.clone(),
            expected_pending_verifiers: self.expected_pending_verifiers.clone(),
            expected_pending_effects: self.expected_pending_effects.clone(),
        }
    }

    /// Records the transport acknowledgement of the governed transaction.
    ///
    /// This is the only effect of a commit acknowledgement: the capture stays
    /// inadmissible for destructive compaction until a readback is recorded.
    pub fn record_commit_transport(
        &mut self,
        transport_acknowledgement: String,
    ) -> Result<(), HandoffCaptureError> {
        validate_text(
            &transport_acknowledgement,
            "capture.transport_acknowledgement",
        )?;
        if !matches!(self.state, HandoffCaptureState::Captured) {
            return Err(HandoffCaptureError::IllegalCaptureTransition {
                from: self.state_name(),
                to: "committed",
            });
        }
        self.state = HandoffCaptureState::Committed {
            transport_acknowledgement,
        };
        Ok(())
    }

    /// Records that the commit response was lost.
    ///
    /// The capture keeps its identity and stays inadmissible. A caller that
    /// lost the response reconciles this same operation; it does not capture
    /// again and it does not compact on unknown acceptance.
    pub fn record_commit_response_loss(
        &mut self,
        cause: String,
    ) -> Result<(), HandoffCaptureError> {
        validate_text(&cause, "capture.cause")?;
        if matches!(
            self.state,
            HandoffCaptureState::CommitResponseUnknown { .. } | HandoffCaptureState::ReadBack { .. }
        ) {
            return Err(HandoffCaptureError::IllegalCaptureTransition {
                from: self.state_name(),
                to: "commit_response_unknown",
            });
        }
        self.state = HandoffCaptureState::CommitResponseUnknown { cause };
        Ok(())
    }

    /// Records a durable readback and admits the readback state.
    ///
    /// The readback is compared with the operation's own recorded content: the
    /// identity, the operation, the boundary, both digests, the retained
    /// artifact set and the pending verifier set must agree. The expected sets
    /// are the ones this capture declared before the boundary, so the check
    /// compares two independent sets rather than one list against itself.
    pub fn record_readback(
        &mut self,
        readback: HandoffCaptureReadback,
    ) -> Result<(), HandoffCaptureError> {
        self.validate_readback(&readback)?;
        if matches!(self.state, HandoffCaptureState::ReadBack { .. }) {
            return Err(HandoffCaptureError::IllegalCaptureTransition {
                from: self.state_name(),
                to: "read_back",
            });
        }
        self.state = HandoffCaptureState::ReadBack {
            readback: Box::new(readback),
        };
        Ok(())
    }

    /// Binds this capture to the exact checkpoint payload it captured.
    ///
    /// The capture identity, the source attempt, the source session, the
    /// frozen diff and the pending verifiers must all agree with the payload.
    /// A capture whose readback is durable but whose content is a different
    /// payload is refused, so a durable record cannot lend its readback to a
    /// checkpoint it did not capture.
    pub fn bind_checkpoint(
        &self,
        checkpoint: &HandoffCheckpoint,
    ) -> Result<(), HandoffCaptureError> {
        checkpoint.validate()?;
        if self.capture_id != checkpoint.checkpoint_id {
            return Err(HandoffCaptureError::CaptureIdentityMismatch {
                expected: self.capture_id.as_str().to_owned(),
                observed: checkpoint.checkpoint_id.as_str().to_owned(),
            });
        }
        if self.source_attempt_id != checkpoint.source_attempt_id {
            return Err(HandoffCaptureError::CaptureSourceAttemptMismatch);
        }
        if self.source_task_id != checkpoint.source_task_id {
            return Err(HandoffCaptureError::CaptureSourceTaskMismatch);
        }
        if self.source_session_ref != checkpoint.source_session_ref {
            return Err(HandoffCaptureError::CaptureSourceSessionMismatch);
        }
        if self.source_plan_revision != checkpoint.source_plan_revision
            || self.source_acceptance_revision != checkpoint.source_acceptance_revision
        {
            return Err(HandoffCaptureError::CaptureRevisionMismatch);
        }
        if self.source_fence != checkpoint.state_fence {
            return Err(HandoffCaptureError::CaptureFenceMismatch);
        }
        if self.source_generations != checkpoint.source_generations {
            return Err(HandoffCaptureError::CaptureGenerationMismatch);
        }
        if self.source_cursors != checkpoint.source_cursors {
            return Err(HandoffCaptureError::CaptureCursorMismatch);
        }
        if self.frozen_diff.digest != checkpoint.diff_ref.digest
            || self.frozen_diff.id != checkpoint.diff_ref.id
        {
            return Err(HandoffCaptureError::FrozenDiffDoesNotMatchCheckpoint);
        }
        compare_reference_sets(
            &self.expected_pending_verifiers,
            &checkpoint.pending_verifier_refs,
            "expected_pending_verifiers",
        )?;
        self.compare_effect_identities(checkpoint)
    }

    /// Compares the captured in-flight operation identities with the payload's.
    ///
    /// Every captured effect reference must name the payload's
    /// [`HANDOFF_EFFECT_REFERENCE_KIND`] and its id must be one of the
    /// payload's in-flight operation ids, and every payload effect must appear.
    /// An effect the capture did not retain is an effect a resume can no longer
    /// exclude.
    fn compare_effect_identities(
        &self,
        checkpoint: &HandoffCheckpoint,
    ) -> Result<(), HandoffCaptureError> {
        let payload: BTreeMap<String, String> = checkpoint
            .effects
            .iter()
            .map(|effect| {
                (
                    effect.operation_id.value().to_string(),
                    effect.disposition.revision_text().to_owned(),
                )
            })
            .collect();
        let mut captured: BTreeMap<String, String> = BTreeMap::new();
        for reference in &self.expected_pending_effects {
            if reference.kind != HANDOFF_EFFECT_REFERENCE_KIND {
                return Err(HandoffCaptureError::EffectReferenceIsNotAnOperation {
                    kind: reference.kind.clone(),
                });
            }
            if captured
                .insert(
                    reference.id.as_str().to_owned(),
                    reference.revision.as_str().to_owned(),
                )
                .is_some()
            {
                return Err(ContractError::DuplicateItem("expected_pending_effects").into());
            }
        }
        for (operation_id, revision) in &captured {
            match payload.get(operation_id) {
                Some(payload_revision) if payload_revision == revision => {}
                Some(payload_revision) => {
                    return Err(HandoffCaptureError::EffectDispositionMismatch {
                        operation_id: operation_id.clone(),
                        captured: revision.clone(),
                        recorded: payload_revision.clone(),
                    });
                }
                None => {
                    return Err(HandoffCaptureError::CapturedEffectIsNotInThePayload {
                        operation_id: operation_id.clone(),
                    });
                }
            }
        }
        for operation_id in payload.keys() {
            if !captured.contains_key(operation_id) {
                return Err(HandoffCaptureError::PayloadEffectWasNotRetained {
                    operation_id: operation_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Returns the durable readback, when this capture has one.
    #[must_use]
    pub fn readback(&self) -> Option<&HandoffCaptureReadback> {
        match &self.state {
            HandoffCaptureState::ReadBack { readback } => Some(readback),
            _ => None,
        }
    }

    /// Whether this boundary may now destroy conversational state.
    ///
    /// The answer is a readback of stored bytes under this capture's own
    /// identity. An acknowledgement, a locally computed hash, an unreconciled
    /// commit response and an unregistered boundary all answer `false`.
    #[must_use]
    pub fn admits_destructive_compaction(&self) -> bool {
        self.state.is_durable_readback()
            && self
                .readback()
                .is_some_and(|readback| readback.capture_id == self.capture_id)
    }

    /// Reconciles a lost commit response against the same operation.
    ///
    /// The readback must name this capture identity. A readback of any other
    /// capture is refused rather than adopted, so a lost response cannot
    /// produce a second checkpoint identity.
    pub fn reconcile(
        &mut self,
        readback: HandoffCaptureReadback,
    ) -> Result<(), HandoffCaptureError> {
        if !matches!(
            self.state,
            HandoffCaptureState::CommitResponseUnknown { .. } | HandoffCaptureState::Captured
        ) {
            return Err(HandoffCaptureError::IllegalCaptureTransition {
                from: self.state_name(),
                to: "reconciled",
            });
        }
        self.record_readback(readback)
    }

    fn validate_readback(
        &self,
        readback: &HandoffCaptureReadback,
    ) -> Result<(), HandoffCaptureError> {
        validate_text(
            readback.readback_checkpoint_digest.as_str(),
            "readback.readback_checkpoint_digest",
        )?;
        validate_text(
            readback.readback_diff_digest.as_str(),
            "readback.readback_diff_digest",
        )?;
        validate_artifacts(&readback.observed_retained_artifacts)?;
        validate_artifacts(&readback.observed_pending_verifiers)?;
        validate_artifacts(&readback.observed_pending_effects)?;
        if readback.capture_id != self.capture_id {
            return Err(HandoffCaptureError::CaptureIdentityMismatch {
                expected: self.capture_id.as_str().to_owned(),
                observed: readback.capture_id.as_str().to_owned(),
            });
        }
        if readback.operation_id != self.operation_id {
            return Err(HandoffCaptureError::CaptureOperationMismatch);
        }
        if readback.boundary != self.boundary {
            return Err(HandoffCaptureError::CaptureBoundaryMismatch);
        }
        compare_recorded_digest(
            &self.recorded_checkpoint_digest,
            &readback.readback_checkpoint_digest,
            "recorded_checkpoint_digest",
        )?;
        compare_recorded_digest(
            &self.recorded_diff_digest,
            &readback.readback_diff_digest,
            "recorded_diff_digest",
        )?;
        compare_reference_sets(
            &self.expected_retained_artifacts,
            &readback.observed_retained_artifacts,
            "expected_retained_artifacts",
        )?;
        compare_reference_sets(
            &self.expected_pending_verifiers,
            &readback.observed_pending_verifiers,
            "expected_pending_verifiers",
        )?;
        compare_reference_sets(
            &self.expected_pending_effects,
            &readback.observed_pending_effects,
            "expected_pending_effects",
        )
    }

    fn validate_leases(&self) -> Result<(), HandoffCaptureError> {
        if self.artifact_leases.is_empty() {
            return Err(ContractError::EmptyCollection("capture.artifact_leases").into());
        }
        let mut seen: BTreeSet<(String, String, String)> =
            BTreeSet::new();
        for lease in &self.artifact_leases {
            lease.validate()?;
            if lease.retained_by_capture != self.capture_id {
                return Err(HandoffCaptureError::LeaseNotOwnedByThisCapture {
                    artifact: lease.artifact_ref.id.as_str().to_owned(),
                    owner: lease.retained_by_capture.as_str().to_owned(),
                });
            }
            if !seen.insert(reference_key(&lease.artifact_ref)) {
                return Err(ContractError::DuplicateItem("capture.artifact_leases").into());
            }
            if !self
                .expected_retained_artifacts
                .iter()
                .any(|expected| reference_key(expected) == reference_key(&lease.artifact_ref))
            {
                return Err(HandoffCaptureError::LeasedArtifactIsNotExpected {
                    artifact: lease.artifact_ref.id.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            HandoffCaptureState::Captured => "captured",
            HandoffCaptureState::Committed { .. } => "committed",
            HandoffCaptureState::CommitResponseUnknown { .. } => "commit_response_unknown",
            HandoffCaptureState::ReadBack { .. } => "read_back",
        }
    }
}

/// One controlled boundary's registration against the single capture
/// operation.
///
/// The record names the owner-side symbol rather than a display label, so a
/// reader can check that the boundary is a real caller instead of a name that
/// only looks like one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffBoundaryRegistration {
    /// The controlled boundary.
    pub boundary: HandoffCaptureBoundary,
    /// The product symbol this boundary is registered against.
    pub caller_symbol: &'static str,
    /// Whether passing this boundary destroys conversational state.
    pub destructive: bool,
}

/// Outcome of registering a capture with the boundary ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoffCaptureRegistration {
    /// The capture is the first identity registered for this boundary and
    /// source attempt.
    First(HandoffCapture),
    /// An identical replay of the registered identity. The registered capture
    /// is returned unchanged, so a repeated request reconciles one operation.
    Replayed(HandoffCapture),
}

/// The one capture identity per controlled boundary and source attempt.
///
/// The ledger is what makes a second checkpoint identity unrepresentable: a
/// repeated request for a boundary that already has a capture either replays
/// the registered capture or is refused, and a different identity for the same
/// boundary and attempt is never admitted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HandoffCaptureLedger {
    captures: BTreeMap<(HandoffCaptureBoundary, AgentAttemptId), HandoffCapture>,
}

impl HandoffCaptureLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a bounded source snapshot and registers it as the one identity
    /// for its boundary and source attempt.
    ///
    /// This is the entry point a controlled boundary uses. Construction and
    /// registration happen together, so a capture that was validated can never
    /// exist outside the ledger and a second identity for the same boundary
    /// cannot be minted by calling the constructor directly.
    pub fn capture_and_register(
        &mut self,
        source: HandoffCaptureSource,
        artifact_leases: Vec<HandoffArtifactLease>,
    ) -> Result<HandoffCaptureRegistration, HandoffCaptureError> {
        let capture = HandoffCapture::capture(source, artifact_leases)?;
        self.register(capture)
    }

    /// The registration census of the controlled boundaries.
    ///
    /// Every controlled boundary appears exactly once with the product symbol
    /// it is registered against, so the registration is checkable against the
    /// owner crate's own declared set rather than against a list a caller
    /// supplies.
    #[must_use]
    pub fn registration_census(&self) -> Vec<HandoffBoundaryRegistration> {
        HandoffCaptureBoundary::CONTROLLED_BOUNDARIES
            .into_iter()
            .map(|boundary| HandoffBoundaryRegistration {
                boundary,
                caller_symbol: boundary.caller_symbol(),
                destructive: boundary.is_destructive(),
            })
            .collect()
    }

    /// Registers a capture against its boundary and source attempt.
    ///
    /// An identical replay is reconciled onto the registered capture. A
    /// different identity for the same boundary and attempt is refused with
    /// [`HandoffCaptureError::ForeignCaptureIdentity`], so a lost response can
    /// never become a second checkpoint.
    pub fn register(
        &mut self,
        capture: HandoffCapture,
    ) -> Result<HandoffCaptureRegistration, HandoffCaptureError> {
        capture.validate()?;
        let key = (capture.boundary, capture.source_attempt_id.clone());
        let Some(registered) = self.captures.get(&key) else {
            self.captures.insert(key, capture.clone());
            return Ok(HandoffCaptureRegistration::First(capture));
        };
        if registered.same_identity(&capture) {
            return Ok(HandoffCaptureRegistration::Replayed(registered.clone()));
        }
        Err(HandoffCaptureError::ForeignCaptureIdentity {
            boundary: capture.boundary,
            capture_id: capture.capture_id.as_str().to_owned(),
        })
    }

    /// Returns the registered capture for a boundary and source attempt.
    #[must_use]
    pub fn get(
        &self,
        boundary: HandoffCaptureBoundary,
        source_attempt_id: &AgentAttemptId,
    ) -> Option<&HandoffCapture> {
        self.captures
            .get(&(boundary, source_attempt_id.clone()))
    }

    /// The boundaries that currently have a registered capture.
    #[must_use]
    pub fn registered_boundaries(&self) -> Vec<HandoffCaptureBoundary> {
        let mut boundaries: Vec<HandoffCaptureBoundary> =
            self.captures.keys().map(|(boundary, _)| *boundary).collect();
        boundaries.dedup();
        boundaries
    }

    /// The controlled boundaries that have no registered capture.
    ///
    /// The expected side is [`HandoffCaptureBoundary::CONTROLLED_BOUNDARIES`],
    /// which the owner crate declares, so a boundary cannot be dropped from the
    /// denominator by the same registration that failed to cover it.
    #[must_use]
    pub fn unregistered_boundaries(&self) -> Vec<HandoffCaptureBoundary> {
        let registered = self.registered_boundaries();
        HandoffCaptureBoundary::CONTROLLED_BOUNDARIES
            .into_iter()
            .filter(|boundary| !registered.contains(boundary))
            .collect()
    }

    /// Whether the named boundary may now destroy conversational state.
    ///
    /// The gate is the registered capture's own durable readback. A boundary
    /// with no registered capture, a capture that holds only a transport
    /// acknowledgement, and a capture whose commit response was lost all answer
    /// `false`; a non-destructive boundary is not gated by this call because it
    /// destroys nothing.
    #[must_use]
    pub fn admits_destructive_compaction(
        &self,
        boundary: HandoffCaptureBoundary,
        source_attempt_id: &AgentAttemptId,
    ) -> bool {
        boundary.is_destructive()
            && self
                .get(boundary, source_attempt_id)
                .is_some_and(HandoffCapture::admits_destructive_compaction)
    }
}

impl HandoffCapture {
    /// Whether the two captures are the same operation under the same
    /// identity, whatever state each has reached.
    fn same_identity(&self, other: &Self) -> bool {
        self.capture_id == other.capture_id
            && self.operation_id == other.operation_id
            && self.boundary == other.boundary
            && self.source_attempt_id == other.source_attempt_id
            && self.recorded_checkpoint_digest == other.recorded_checkpoint_digest
            && self.recorded_diff_digest == other.recorded_diff_digest
            && reference_key(&self.frozen_diff) == reference_key(&other.frozen_diff)
    }
}

/// Validates a reference stream and rejects repeated exact units.
fn validate_artifacts(
    references: &[PublicReference],
) -> Result<(), HandoffCaptureError> {
    for reference in references {
        reference.validate()?;
    }
    let mut seen: BTreeSet<(String, String, String)> =
        BTreeSet::new();
    for reference in references {
        if !seen.insert(reference_key(reference)) {
            return Err(ContractError::DuplicateItem("capture.references").into());
        }
    }
    Ok(())
}

/// Compares a declared expected set with a set observed by the store.
///
/// Both directions are proven. An expected artifact the store does not hold is
/// a lost retention, and an artifact the store holds that this capture never
/// declared is retained under an identity this operation does not own.
fn compare_reference_sets(
    expected: &[PublicReference],
    observed: &[PublicReference],
    field: &'static str,
) -> Result<(), HandoffCaptureError> {
    let expected_set: BTreeSet<(String, String, String)> =
        expected.iter().map(reference_key).collect();
    let observed_set: BTreeSet<(String, String, String)> =
        observed.iter().map(reference_key).collect();
    for key in &expected_set {
        if !observed_set.contains(key) {
            return Err(HandoffCaptureError::ExpectedUnitNotRetained {
                field,
                unit: key.1.clone(),
            });
        }
    }
    for key in &observed_set {
        if !expected_set.contains(key) {
            return Err(HandoffCaptureError::UnexpectedRetainedUnit {
                field,
                unit: key.1.clone(),
            });
        }
    }
    Ok(())
}

/// Compares a stored digest with the value recorded at capture time.
///
/// The recorded value is never recomputed from the bytes the capture operation
/// holds, so agreement means the store holds what was captured rather than
/// that a hash function agrees with itself.
fn compare_recorded_digest(
    recorded: &str,
    observed: &str,
    field: &'static str,
) -> Result<(), HandoffCaptureError> {
    if recorded != observed {
        return Err(HandoffCaptureError::ReadbackDigestMismatch {
            field,
            recorded: recorded.to_owned(),
            observed: observed.to_owned(),
        });
    }
    Ok(())
}

/// Canonical comparison key of one public reference.
fn reference_key(reference: &PublicReference) -> (String, String, String) {
    (
        reference.kind.clone(),
        reference.id.as_str().to_owned(),
        reference.revision.as_str().to_owned(),
    )
}

/// Refusal of a controlled-boundary capture.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HandoffCaptureError {
    /// A shared agent-contract rejection, already typed by the owner crate.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// The capture record was written against another contract revision.
    #[error("handoff capture contract version {version} is not the current revision")]
    UnsupportedContractVersion {
        /// Revision carried by the refused record.
        version: ContractVersion,
    },
    /// The frozen diff is a mutable path or a bare commit identity.
    #[error("frozen diff is not a digest-bound immutable artifact")]
    FrozenDiffIsNotImmutable,
    /// The snapshot's state fence did not validate.
    #[error("the source snapshot was taken under a stale state fence")]
    SnapshotFenceIsStale,
    /// Two source positions in the snapshot disagree with each other.
    #[error("the source snapshot is not coherent: {field} disagrees with the fence")]
    SnapshotIsNotCoherent {
        /// Snapshot field that disagrees.
        field: &'static str,
    },
    /// A retained artifact is not a digest-bound immutable artifact.
    #[error("retained artifact is not a digest-bound immutable artifact")]
    RetainedArtifactIsNotImmutable,
    /// The readback names a different capture than the one it is offered to.
    #[error("readback names capture {observed}, not the captured {expected}")]
    CaptureIdentityMismatch {
        /// Capture this operation recorded.
        expected: String,
        /// Capture the readback returned.
        observed: String,
    },
    /// The readback belongs to a different capture operation.
    #[error("readback belongs to a different capture operation")]
    CaptureOperationMismatch,
    /// The readback was recorded at a different boundary.
    #[error("readback was recorded at a different controlled boundary")]
    CaptureBoundaryMismatch,
    /// The capture names a different source attempt than the payload.
    #[error("capture was taken from a different source attempt than the payload")]
    CaptureSourceAttemptMismatch,
    /// The capture names a different source task than the payload.
    #[error("capture was taken from a different source task than the payload")]
    CaptureSourceTaskMismatch,
    /// The capture names a different source session than the payload.
    #[error("capture was taken from a different source session than the payload")]
    CaptureSourceSessionMismatch,
    /// The capture froze a different diff than the payload records.
    #[error("frozen diff does not match the checkpoint payload")]
    FrozenDiffDoesNotMatchCheckpoint,
    /// The capture was taken under different plan or acceptance revisions.
    #[error("capture revisions do not match the checkpoint payload")]
    CaptureRevisionMismatch,
    /// The capture was taken under a different state fence.
    #[error("capture state fence does not match the checkpoint payload")]
    CaptureFenceMismatch,
    /// The capture observed different source generations.
    #[error("capture source generations do not match the checkpoint payload")]
    CaptureGenerationMismatch,
    /// The capture observed different source cursors.
    #[error("capture source cursors do not match the checkpoint payload")]
    CaptureCursorMismatch,
    /// A digest the store returned differs from the recorded value.
    #[error("readback {field} is {observed}, not the recorded {recorded}")]
    ReadbackDigestMismatch {
        /// Recorded digest field.
        field: &'static str,
        /// Value recorded at capture time.
        recorded: String,
        /// Value the store returned.
        observed: String,
    },
    /// A unit this capture declared as retained is not retained by the store.
    #[error("{field} unit {unit} is declared but the store does not retain it")]
    ExpectedUnitNotRetained {
        /// Declared set the comparison was made against.
        field: &'static str,
        /// Unit missing from the store's observation.
        unit: String,
    },
    /// The store retains a unit this capture never declared.
    #[error("{field} unit {unit} is retained but was never declared by this capture")]
    UnexpectedRetainedUnit {
        /// Declared set the comparison was made against.
        field: &'static str,
        /// Undeclared unit the store holds.
        unit: String,
    },
    /// A lease names a capture other than the one that took it.
    #[error("artifact {artifact} is leased to capture {owner}, not to this one")]
    LeaseNotOwnedByThisCapture {
        /// Artifact the lease names.
        artifact: String,
        /// Capture the lease names.
        owner: String,
    },
    /// A lease names an artifact this capture did not declare as retained.
    #[error("artifact {artifact} is leased but is not a declared retained artifact")]
    LeasedArtifactIsNotExpected {
        /// Artifact the lease names.
        artifact: String,
    },
    /// A retained effect reference does not name an in-flight operation.
    #[error("effect reference kind {kind} does not name an in-flight operation")]
    EffectReferenceIsNotAnOperation {
        /// Reference kind that was offered.
        kind: String,
    },
    /// The captured disposition of an operation differs from the payload's.
    #[error("effect {operation_id} is captured as {captured}, not the recorded {recorded}")]
    EffectDispositionMismatch {
        /// In-flight operation the capture named.
        operation_id: String,
        /// Disposition revision the capture recorded.
        captured: String,
        /// Disposition revision the payload records.
        recorded: String,
    },
    /// The capture retained an operation the payload does not carry.
    #[error("captured effect {operation_id} is not an in-flight operation of this payload")]
    CapturedEffectIsNotInThePayload {
        /// Operation the capture named.
        operation_id: String,
    },
    /// The payload carries an in-flight operation the capture did not retain.
    #[error("payload effect {operation_id} was not retained by this capture")]
    PayloadEffectWasNotRetained {
        /// Operation the payload carries.
        operation_id: String,
    },
    /// A second capture identity was offered for a registered boundary.
    #[error("boundary {boundary:?} already has a registered capture; {capture_id} is not it")]
    ForeignCaptureIdentity {
        /// Boundary that is already registered.
        boundary: HandoffCaptureBoundary,
        /// Identity that was refused.
        capture_id: String,
    },
    /// The requested state transition is not admitted from the current state.
    #[error("capture transition {from} -> {to} is not admitted")]
    IllegalCaptureTransition {
        /// Current state.
        from: &'static str,
        /// Requested state.
        to: &'static str,
    },
}
