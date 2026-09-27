//! Provider-neutral composite outcome for one guarded OS-state operation.
//!
//! Architecture: A0.3 (a hidden expansion of authority fails closed), A12.2
//! (identity is bound at the installation boundary), A13.2 (failure domains),
//! ARCH-OBS-01. Implementation: I2.6 (an error preserves operation identity,
//! module/generation, State Fence, causal chain, effect status and a raw
//! evidence handle), I5.19 (one receipt envelope, never a second journal),
//! I7.20 (typed disposition plus a required recovery action), I14.24
//! (containment), I15.4 (no secret value crosses a boundary).
//!
//! This module owns one closed payload. It performs no provider execution, no
//! persistence, no retry, and grants no retry authority. The finite guard
//! sequence can produce a primary failure, an explicit restoration failure,
//! and an emergency restoration failure at the same time; those are three
//! separate slots, and none of them may be overwritten to simplify a
//! `Result`.
//!
//! Privacy: every object, state, generation, and evidence axis is an opaque
//! bounded [`PlatformHandle`] reference. No raw token, ACL, principal value,
//! or path is representable in this payload, and no secret value ever enters
//! it. Variable-length identities are precomputed into bounded references
//! before the guarded mutation, while normal allocation is still safe.

use eliot_contracts::{RequestId, RequestMetadata};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{PlatformHandle, ProviderError, validate_context, validate_text};

/// Which guard owned the protected OS state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardKind {
    /// Thread impersonation (`SetThreadToken` / `RevertToSelf`).
    ThreadImpersonation,
    /// Token privilege elevation (`AdjustTokenPrivileges`).
    TokenPrivilege,
}

/// The exact OS error observation for one slot.
///
/// An unavailable code is explicit. A zero is a real Win32 value and is never
/// used as a stand-in for "unknown" or "not reported".
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsErrorCode {
    /// The exact code the failed OS call reported, captured immediately after
    /// that call and before any other call could overwrite it.
    Exact(u32),
    /// The failure was not an OS call, or the OS call reported no code.
    NotReported,
    /// A code existed but could not be captured; the cause remains unknown.
    Unknown,
}

/// The bounded effect classification of one primary or restoration slot.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectDisposition {
    /// No call for this slot was ever issued.
    NotAttempted,
    /// The call failed with no observed effect; the protected state is proven
    /// unchanged.
    ProvenUnchanged,
    /// The effect was applied and observed.
    Applied,
    /// A previously applied effect was restored and observed.
    Restored,
    /// The effect was applied and restoration is incomplete.
    Partial,
    /// The OS result could not be classified safely.
    Unknown,
}

/// How strongly a disposition is supported.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectCertainty {
    /// An exact OS observation supports the disposition.
    Observed,
    /// No observation supports the disposition; it is the only honest reading.
    Unverified,
}

/// Which restoration step of the finite guard sequence one attempt belongs to.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestorationStage {
    /// The sequence never reached a restoration step.
    NotAttempted,
    /// Construction-time compensation, issued before the guard became armed.
    ConstructionCompensation,
    /// The explicit, normal-path restoration.
    Explicit,
    /// The emergency restoration attempted by the armed guard destructor.
    Emergency,
}

/// One attempt inside the finite guard restoration sequence.
///
/// Attempts are additive. A later attempt never replaces or erases an earlier
/// one, and a successful emergency restoration never erases the explicit
/// failure that preceded it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorationAttempt {
    /// The step of the guard sequence this attempt belongs to.
    pub stage: RestorationStage,
    /// The one-based attempt number inside `stage`. Zero is never valid.
    pub attempt: u32,
    /// The bounded effect classification of this attempt alone.
    pub disposition: EffectDisposition,
    /// How strongly `disposition` is supported.
    pub certainty: EffectCertainty,
    /// The exact OS error observed for this attempt alone.
    pub code: OsErrorCode,
}

/// The explicit and emergency restoration slots, kept apart.
///
/// Both vectors are retained even when only one is populated, so a caller can
/// never collapse a double fault into a single answer.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorationRecord {
    /// Attempts made on the explicit, normal restoration path.
    pub explicit: Vec<RestorationAttempt>,
    /// Attempts made by the emergency path while the guard stayed armed.
    pub emergency: Vec<RestorationAttempt>,
}

impl RestorationRecord {
    /// Every recorded attempt, explicit first, in slot order.
    pub fn attempts(&self) -> impl Iterator<Item = &RestorationAttempt> {
        self.explicit.iter().chain(self.emergency.iter())
    }
}

/// The primary failure of the guarded operation itself.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRecord {
    /// The bounded effect classification of the primary operation.
    pub disposition: EffectDisposition,
    /// How strongly `disposition` is supported.
    pub certainty: EffectCertainty,
    /// The exact OS error observed for the primary operation.
    pub code: OsErrorCode,
    /// The coarse non-secret classification, reusing the one existing P-01
    /// provider registry instead of a second error-code registry.
    pub provider: ProviderError,
}

/// What the guard owner asked for, and what was actually observed.
///
/// A requested containment is never reported as an observed containment.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentRecord {
    /// The containment the guard owner requested before stopping.
    pub requested: ContainmentRequest,
    /// The containment the independent reader can actually observe.
    pub observed: ContainmentObservation,
}

impl ContainmentRecord {
    /// No containment was requested or observed.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            requested: ContainmentRequest::None,
            observed: ContainmentObservation::NotObserved,
        }
    }
}

/// The containment the guard owner requested.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainmentRequest {
    /// No containment was requested.
    None,
    /// Bounded terminal containment was requested before ordinary
    /// persistence, logging, and callback code could run.
    Terminal,
}

/// The containment that is actually observable after the fact.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContainmentObservation {
    /// Nothing was submitted.
    NotObserved,
    /// One complete fixed record was accepted by the approved sink.
    Recorded,
    /// Submission was attempted and the OS refused it.
    Refused { code: OsErrorCode },
    /// A second terminal entry could not re-enter the writer.
    ReentryRefused,
}

/// The single next action required before ordinary work may continue.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequiredNextAction {
    /// The guard owner established continuation-safe OS state, so the caller
    /// may return normally.
    ContinueNormally,
    /// The independent supervisor must reconcile the exact retained evidence
    /// before the affected object is adopted or overwritten.
    ReconcileRetainedEvidence,
    /// A fresh process must establish the OS state before anything continues.
    RestartForCleanState,
    /// The affected object stays blocked for an explicit owner decision.
    HoldObjectBlocked,
}

/// One closed composite retaining every simultaneous failure of a guarded
/// operation, its exact identities, its effect certainty, its terminal
/// containment, and the one required next action.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardRevertOutcome {
    /// The parent operation identity and the validated State Fence under
    /// which the guarded mutation was admitted.
    pub parent_operation: RequestMetadata,
    /// The child operation identity of the guarded mutation itself.
    pub child_operation: RequestId,
    /// Which guard owned the protected state.
    pub guard: GuardKind,
    /// Opaque bounded reference to the protected object. Never a path, token,
    /// ACL, or principal value.
    pub protected_object: PlatformHandle,
    /// Opaque bounded reference to the exact pre-state the guard expected.
    pub expected_pre_state: PlatformHandle,
    /// Opaque bounded reference to the exact post-state the guard expected.
    pub expected_post_state: PlatformHandle,
    /// Opaque bounded reference to the generation of the protected object.
    pub generation: PlatformHandle,
    /// Opaque bounded reference to the retained bounded evidence record.
    pub evidence_ref: PlatformHandle,
    /// The primary failure slot. Retained independently of restoration.
    pub primary: Option<FailureRecord>,
    /// The restoration slots. Retained independently of the primary failure.
    pub restoration: RestorationRecord,
    /// The requested and observed terminal containment.
    pub containment: ContainmentRecord,
    /// The one next action required before ordinary work continues.
    pub next_action: RequiredNextAction,
}

/// Fail-closed rejection of an unbindable composite.
#[derive(Clone, Copy, Debug, Eq, Error, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuardOutcomeError {
    #[error("guard operation context is invalid")]
    InvalidOperationContext,
    #[error("guard outcome reference is invalid")]
    InvalidReference,
    #[error("a restoration attempt number must be one or greater")]
    InvalidRestorationAttempt,
    #[error("a normal return was requested without continuation-safe OS state")]
    UnsafeContinuation,
}

impl GuardRevertOutcome {
    /// Validates the composite and its single load-bearing invariant.
    ///
    /// # Errors
    ///
    /// Returns [`GuardOutcomeError::InvalidOperationContext`] for an
    /// unvalidated parent operation, [`GuardOutcomeError::InvalidReference`]
    /// for a blank or control-bearing reference,
    /// [`GuardOutcomeError::InvalidRestorationAttempt`] for a zero attempt
    /// number, and [`GuardOutcomeError::UnsafeContinuation`] when a normal
    /// return is demanded for a composite whose OS state is not proven
    /// continuation-safe.
    pub fn validate(&self) -> Result<(), GuardOutcomeError> {
        validate_context(&self.parent_operation)
            .map_err(|_| GuardOutcomeError::InvalidOperationContext)?;
        for reference in [
            &self.protected_object,
            &self.expected_pre_state,
            &self.expected_post_state,
            &self.generation,
            &self.evidence_ref,
        ] {
            validate_text(reference.as_str(), "guard_outcome.reference")
                .map_err(|_| GuardOutcomeError::InvalidReference)?;
        }
        if self
            .restoration
            .attempts()
            .any(|attempt| attempt.attempt == 0)
        {
            return Err(GuardOutcomeError::InvalidRestorationAttempt);
        }
        if self.next_action == RequiredNextAction::ContinueNormally && !self.continuation_is_safe()
        {
            return Err(GuardOutcomeError::UnsafeContinuation);
        }
        Ok(())
    }

    /// Whether the guard owner established continuation-safe OS state.
    ///
    /// A normal return is permitted only when this holds. Any observed
    /// containment, any requested containment, any unverified attempt, and any
    /// applied, partial, or unknown restoration disposition all mean the thread
    /// or token state is not proven safe, so the caller must use terminal
    /// containment before any ordinary persistence, logging, or callback code
    /// runs.
    #[must_use]
    pub fn continuation_is_safe(&self) -> bool {
        if self.containment.requested != ContainmentRequest::None
            || self.containment.observed != ContainmentObservation::NotObserved
        {
            return false;
        }
        self.restoration
            .attempts()
            .all(attempt_is_continuation_safe)
    }
}

fn attempt_is_continuation_safe(attempt: &RestorationAttempt) -> bool {
    attempt.certainty == EffectCertainty::Observed
        && matches!(
            attempt.disposition,
            EffectDisposition::NotAttempted
                | EffectDisposition::ProvenUnchanged
                | EffectDisposition::Restored
        )
}
