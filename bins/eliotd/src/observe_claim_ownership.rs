//! Recoverable ownership of an `eliot.observe` semantic claim (issue #2565
//! W3).
//!
//! # The defect this module exists to fix, stated exactly
//!
//! The observe flight claims a pair, then calls
//! [`admit_captured_observation`](crate::observation_adapters::ForwardingObservationReconciliation::admit_captured_observation),
//! which drives the Governor owner and a real canonical `CaptureCandidate`
//! commit, then submits a result. Between the claim and the result there was
//! **no durable record that an effect was possible**.
//!
//! On this row's protocol version (`send_claim_protocol_version == 0`) the
//! durable attempt phase advances through exactly two values that the observe
//! route writes: `Claimed` (`persist_observe_claim_attempt`) and
//! `DeferredNoEffect` (`defer_host_request_attempt`). Both are pre-effect
//! states whose meaning is "nothing was attempted". The one phase whose entire
//! meaning is "an effect may already have occurred; a restart must not read
//! this as fresh work" is `DispatchStarted`, and on `origin/main` the only
//! writer of it is the `UserAutomation` host-transport custody observer — a
//! route whose rows are `UserAutomation` operations carrying an authenticated
//! *transport channel binding*, which an `eliot.observe` semantic claim does
//! not have and must not fabricate.
//!
//! So a daemon crash between claim and retained completion left a row reading
//! as a clean pre-effect claim while the capture may already have committed.
//! Reclaiming that row under the same-identity retry policy is then a blind
//! redispatch of an effect that may have happened — exactly the window AUD5
//! names. That is a defect, not a remark.
//!
//! # What is durable, and what is only an index
//!
//! The durable owner of one claim is the single ORS `HostRequestRecord`: its
//! `attempt` (attempt id, generation, owner connection, launch nonce, session
//! epoch), `fence_digest`, `authority_epoch`, `generation`, `deadline_unix_ms`,
//! `state`, and — once the phase leg below has run — the phase itself.
//!
//! The Kernel's `host_request_connection_index` is an **index over that record,
//! not a second owner**. Everything this module needs to reconstruct a claim
//! after a restart is read from the durable row:
//!
//! - operation and request digest: `record.operation_id`, `record.request_digest`;
//! - attempt and fence: `record.attempt`, `record.fence_digest`;
//! - applicability: `record.authority_epoch`, `record.generation`;
//! - deadline: `record.deadline_unix_ms`;
//! - the executable bytes: `record.payload_body` (bound by `payload_digest`);
//! - the phase: `record.attempt.phase`.
//!
//! Nothing here is derived from a live queue entry, so dropping the index
//! loses no claim and no possible effect.
//!
//! # Where the phase is written, and why it precedes any effect
//!
//! [`ObserveClaimPhaseAdvance`] is the exact pre-effect phase record for one
//! admitted claim. It is built from admitted inputs only and is passed to the
//! Kernel's existing phase-advance leg by
//! `run_observe_poll` BEFORE `execute_observation_capture` is called. The
//! ordering is structural, not conventional: the phase leg is a separate
//! `await` whose failure returns from the poll step, and the owner call sits
//! behind it with no path that reaches the owner without it.
//!
//! [`observe_claim_phase_admits_effect`] is the second half of that guarantee,
//! and it is decidable from the DURABLE ROW alone: a restarted daemon re-reads
//! the row and learns whether the phase was recorded, without trusting any
//! in-memory value.
//!
//! # Replacement and revocation
//!
//! Two independent mechanisms, both reading the durable row:
//!
//! - **Refused as a current result.** [`resolve_observe_claim_currency`]
//!   compares the presented wire attempt against the claim, the claim against
//!   the row's own attempt (id, generation, fence digest), the presented
//!   authority epoch against both the admitted fence and the row's own epoch,
//!   the presented expiry against the row's deadline, and the observation time
//!   against that deadline. Every mismatch is [`ObserveClaimRefusal`], and a
//!   refusal never reaches a result body.
//! - **Possible effect preserved.** [`observe_claim_ownership_preserved`] reads
//!   the same row and returns the ORIGINAL attempt identity, its durable phase
//!   and the row state. Its reconciliation is
//!   [`PreservedEffectReconciliation::OutcomeUnknown`] unless the durable
//!   phase is one of the two pre-effect phases. Rejection therefore never
//!   becomes forgetting, and an unknown outcome never becomes success or
//!   failure.
//!
//! # Scope
//!
//! `eliot.observe` only. Read-only requests are **not** copied here: the
//! evidence-query lane keeps its own requeue-on-disconnect behaviour untouched,
//! because a read has no possible effect to preserve. The four `eliot.observe`
//! suboperations with no connected owner are not copied here either — they still
//! retire through the defer leg with their named residual owner and never
//! acquire a claim whose effects nothing could reconcile.
//!
//! What is deliberately NOT here: this module adds no store, table, queue,
//! protocol leg or tool vocabulary. It is the decision layer over the durable
//! row the existing carrier already owns, plus the typed read of that row's
//! phase. Persisting it is the existing Kernel phase leg's job, which this
//! module calls through the one `semantic_observe_*` carrier vocabulary.

#![forbid(unsafe_code)]

use eliot_contracts::OperationId;
use eliot_ors::{HostRequestAttempt, HostRequestAttemptPhase, HostRequestRecord, HostRequestState};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};

/// The admitted capability these claims belong to.
///
/// Spelled here rather than imported so this module carries no dependency on
/// the serve module's private constant while still refusing any attempt minted
/// for another facet.
const OBSERVE_CLAIM_CAPABILITY: &str = "eliot.observe";

/// Refusal code: the presented claim is not the durable row's current attempt.
///
/// Reached by a replaced, superseded or disconnected claim. It is a refusal of
/// CURRENCY, not an erasure: the possible effect stays durable on the original
/// attempt, readable through [`observe_claim_ownership_preserved`].
pub const OBSERVE_CLAIM_STALE_ATTEMPT: &str = "OBSERVE_CLAIM_STALE_ATTEMPT";

/// Refusal code: the row's fence, authority epoch or generation was replaced.
///
/// The identity arm of replacement: a rotated authority epoch or a re-advanced
/// resource generation invalidates the claim even when the attempt triple still
/// matches, because the effect would be applied under a fence that no longer
/// holds. As above, the durable row keeps the possible effect.
pub const OBSERVE_CLAIM_FENCE_REPLACED: &str = "OBSERVE_CLAIM_FENCE_REPLACED";

/// Refusal code: the durable phase evidence this effect requires was not
/// recorded before the effect.
///
/// The W3 guarantee expressed as a refusal: an effect that could not be
/// attributed to a recorded phase is refused, and the operation stays
/// claimable for an attempt that does record the phase. Nothing is guessed
/// about whether the unattributable effect happened — the durable row answers
/// that separately.
pub const OBSERVE_CLAIM_PHASE_NOT_DURABLE: &str = "OBSERVE_CLAIM_PHASE_NOT_DURABLE";

/// Returns whether a durable attempt phase proves no effect was possible.
///
/// Exactly the two pre-effect phases qualify. `DispatchStarted`,
/// `DeliveryOutcomeUnknown`, `DeliveredToAuthenticatedHost` and
/// `ResponseReceived` all mean the effect may have occurred, and an absent
/// phase is not a phase at all — so absent resolves to "unknown", never to
/// "clean".
#[must_use]
pub fn observe_phase_is_pre_effect(phase: HostRequestAttemptPhase) -> bool {
    matches!(
        phase,
        HostRequestAttemptPhase::Claimed | HostRequestAttemptPhase::DeferredNoEffect
    )
}

/// The identity one claim carries, and the exact thing a replacement must
/// invalidate.
///
/// Every value is read from the Kernel-admitted envelope and its Kernel-minted
/// attempt, or — for the fence digest — from the durable row itself. Nothing is
/// taken from host-authored identity text and nothing is defaulted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveClaimIdentity {
    /// The Kernel-admitted operation this claim may complete.
    pub operation_id: String,
    /// The exact admitted request digest bound to that operation.
    pub request_digest: String,
    /// The durable attempt identity that must be presented to complete it.
    pub attempt_id: String,
    /// The fencing generation that must be presented to complete it.
    pub generation: u64,
    /// The durable fence digest observed on the admitted row.
    pub fence_digest: String,
    /// The admitted deadline. A presentation past it is expired, never merely
    /// stale.
    pub deadline_unix_ms: u64,
}

impl ObserveClaimIdentity {
    /// Returns whether the presented wire attempt is this claim's attempt.
    ///
    /// Operation, attempt id and generation are all compared. A capability
    /// minted for a previous lifecycle cannot complete this claim even when the
    /// operation matches, because the attempt identity is unique per claim.
    #[must_use]
    pub fn matches_presented_attempt(&self, presented: &LocalReadAttempt) -> bool {
        presented.operation_id == self.operation_id
            && presented.attempt_id == self.attempt_id
            && presented.fencing_generation == self.generation
    }

    /// Returns whether the durable row's own attempt is this claim's attempt.
    ///
    /// Attempt id, generation and fence digest are compared. The fence digest
    /// is part of this comparison rather than carried alongside it: a row whose
    /// fence moved is not the row this claim was taken from.
    #[must_use]
    pub fn matches_durable_attempt(&self, durable: &HostRequestAttempt) -> bool {
        durable.attempt_id.as_str() == self.attempt_id
            && durable.generation == self.generation
            && durable.fence_digest == self.fence_digest
    }
}

/// How the durable row must resolve one preserved possible effect.
///
/// `OutcomeUnknown` is the honest answer and is deliberately the common one: it
/// is the state a crash between dispatch and retained completion leaves.
/// Mapping it to failure would authorize a blind retry; mapping it to success
/// would assert an outcome nobody observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreservedEffectReconciliation {
    /// The effect may or may not have occurred and the row proves neither. The
    /// operation stays reconciling against its ORIGINAL attempt; it is not free
    /// to be redispatched as fresh work.
    OutcomeUnknown,
    /// The row proves no effect was possible under this attempt.
    ///
    /// Reachable only from a durable pre-effect phase. This is a proof read off
    /// the recorded phase, never an inference from a missing observation, from
    /// the daemon having restarted, or from the queue having been emptied.
    ProvenNoEffect,
}

impl PreservedEffectReconciliation {
    /// Stable wire discriminator for the preserved-effect reconciliation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutcomeUnknown => "outcome_unknown",
            Self::ProvenNoEffect => "proven_no_effect",
        }
    }
}

/// The durable evidence one claim may already have produced.
///
/// Read off the ORS row, never off the daemon's memory — which is what lets a
/// restarted daemon reconstruct it and is why the in-memory queue stays a
/// reconstructable index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserveClaimPreservedEffect {
    /// The ORIGINAL attempt identity the possible effect is attached to. Even
    /// after a replacement or revocation this is the attempt that must be
    /// reconciled, never the replacement's.
    pub attempt_id: String,
    /// The fencing generation of that original attempt.
    pub generation: u64,
    /// The durable phase that attempt reached. Absent stays absent: a row with
    /// no attempt reports [`ObserveClaimAbsence::NoRecordedAttempt`] below
    /// rather than an invented phase.
    pub phase: Option<HostRequestAttemptPhase>,
    /// The exact owner operation whose receipt the effect would produce.
    pub owner_operation_id: String,
    /// What the durable evidence resolves to.
    pub reconciliation: PreservedEffectReconciliation,
    /// The durable row state, so a caller can see whether the row is still
    /// claimable from a queue or already fenced away from one.
    pub state: HostRequestState,
}

/// Whether the row carries any recorded attempt at all.
///
/// This exists so "no attempt" stays visibly different from "an attempt at a
/// pre-effect phase". Both resolve to `OutcomeUnknown`, and collapsing them
/// would let a row with no claim record be read as a claim that was safely
/// abandoned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveClaimAbsence {
    /// The row carries no attempt, so nothing was ever claimed and nothing can
    /// prove anything either way.
    NoRecordedAttempt,
}

/// Projects the durable row into the preserved possible effect for one claim.
///
/// Total by construction: it answers for a row with an attempt, a row without
/// one, and a row whose attempt was replaced. In every case the ORIGINAL attempt
/// identity stays attached to the possible effect, so a replacement can never
/// detach the effect from the attempt that may have caused it and re-attach it
/// to fresh work.
#[must_use]
pub fn observe_claim_ownership_preserved(
    record: &HostRequestRecord,
    owner_operation_id: &str,
) -> ObserveClaimPreservedEffect {
    match record.attempt.as_ref() {
        Some(attempt) => ObserveClaimPreservedEffect {
            attempt_id: attempt.attempt_id.as_str().to_owned(),
            generation: attempt.generation,
            phase: Some(attempt.phase),
            owner_operation_id: owner_operation_id.to_owned(),
            // A proof read off the recorded phase and nothing else. Every other
            // phase, including every transport phase, resolves to unknown.
            reconciliation: if observe_phase_is_pre_effect(attempt.phase) {
                PreservedEffectReconciliation::ProvenNoEffect
            } else {
                PreservedEffectReconciliation::OutcomeUnknown
            },
            state: record.state,
        },
        // Absent stays absent. The absence of a claim record is not a proof
        // that nothing ran, so the reconciliation is `OutcomeUnknown` and no
        // phase is invented to fill the slot.
        None => ObserveClaimPreservedEffect {
            attempt_id: String::new(),
            generation: 0,
            phase: None,
            owner_operation_id: owner_operation_id.to_owned(),
            reconciliation: PreservedEffectReconciliation::OutcomeUnknown,
            state: record.state,
        },
    }
}

/// Returns whether the row's absence of any recorded attempt is the reason a
/// claim cannot resolve.
///
/// The single consumer of this is the diagnostic that distinguishes "there was
/// never a claim" from "a claim exists and is stale", because the two refuse
/// for different reasons and must not be reported identically.
#[must_use]
pub fn observe_claim_absence(record: &HostRequestRecord) -> Option<ObserveClaimAbsence> {
    record
        .attempt
        .is_none()
        .then_some(ObserveClaimAbsence::NoRecordedAttempt)
}

/// The typed refusals one claim presentation can receive.
///
/// Every arm refuses the presented claim AS A CURRENT RESULT. None erases the
/// durable row, and none asserts anything about whether an effect occurred —
/// that remains [`observe_claim_ownership_preserved`]'s honest
/// `OutcomeUnknown`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserveClaimRefusal {
    /// The presentation is not this operation's admitted envelope, or the
    /// attempt does not bind that envelope, or the attempt was minted for
    /// another facet. A foreign or substituted input reaches no owner and causes
    /// no effect.
    ForeignClaim {
        /// The operation the presentation named, retained for the audit record.
        presented_operation: String,
    },
    /// The presented attempt is not the durable row's current attempt.
    StaleAttempt {
        /// The attempt the presentation named, retained for the audit record.
        presented_attempt: String,
    },
    /// The row's fence or authority epoch was replaced after the claim.
    FenceReplaced {
        /// The attempt the presentation named, retained for the audit record.
        presented_attempt: String,
    },
    /// The admitted deadline elapsed. Observed HERE, at the point the claim is
    /// resolved, and not only at submission.
    Expired {
        /// The attempt the presentation named, retained for the audit record.
        presented_attempt: String,
    },
    /// The durable row carries no attempt, so there is no claim to complete and
    /// no phase evidence to trust.
    Unclaimed,
    /// The durable row carries no recorded pre-effect phase for this claim, so an
    /// effect would not be attributable. The operation stays claimable for an
    /// attempt that does record the phase.
    PhaseNotDurable {
        /// The attempt the presentation named, retained for the audit record.
        presented_attempt: String,
    },
}

impl ObserveClaimRefusal {
    /// Stable refusal code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ForeignClaim { .. } | Self::StaleAttempt { .. } => OBSERVE_CLAIM_STALE_ATTEMPT,
            Self::FenceReplaced { .. } | Self::Expired { .. } => OBSERVE_CLAIM_FENCE_REPLACED,
            Self::Unclaimed | Self::PhaseNotDurable { .. } => OBSERVE_CLAIM_PHASE_NOT_DURABLE,
        }
    }
}

/// Builds the claim identity for one admitted observe pair against its durable
/// row.
///
/// Every value is read from the admitted envelope, its minted attempt, and the
/// durable row. The fence digest in particular comes from `record`, because the
/// envelope carries a `StateFence` and the row carries the *digest* the owner
/// committed — deriving one from the other here would be a local computation
/// standing in for an owner attestation.
///
/// Nothing is defaulted: a pair that fails envelope validation, fails attempt
/// validation, binds a different operation, or was minted for another facet is
/// an `Err`, never a plausible-looking claim.
pub fn observe_claim_identity(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    record: &HostRequestRecord,
) -> Result<ObserveClaimIdentity, String> {
    envelope
        .validate()
        .map_err(|error| format!("observe claim envelope is not admitted shape: {error}"))?;
    attempt
        .validate()
        .map_err(|error| format!("observe claim attempt is not bound shape: {error}"))?;
    let operation_id = host_request_operation_id(envelope);
    if attempt.operation_id != operation_id {
        return Err(
            "observe claim attempt does not bind the admitted envelope operation".to_owned(),
        );
    }
    if attempt.facet_method != OBSERVE_CLAIM_CAPABILITY {
        return Err("observe claim attempt is not admitted for the observe operation".to_owned());
    }
    if attempt.fencing_generation == 0 {
        // A never-claimed generation is not a claim. Minting one here would be
        // fabricating an attempt, which is the exact thing the phase evidence
        // exists to prevent.
        return Err("observe claim attempt has no fencing generation".to_owned());
    }
    Ok(ObserveClaimIdentity {
        operation_id,
        request_digest: envelope.envelope_sha256.clone(),
        attempt_id: attempt.attempt_id.clone(),
        generation: attempt.fencing_generation,
        fence_digest: record.fence_digest.clone(),
        deadline_unix_ms: envelope.identity.deadline_unix_ms,
    })
}

/// Resolves whether one presented claim is still the row's CURRENT claim.
///
/// This is the replacement/revocation gate, and it is a complete comparison
/// rather than a presence check. In order: the operation, request digest and
/// attempt identity are compared against the presentation; the claim is
/// compared against the row's own attempt (id, generation, fence digest); the
/// presented authority epoch is compared against BOTH the admitted fence and
/// the row's own recorded epoch; the presented expiry is compared against the
/// row's deadline; and the observation time is compared against that deadline.
/// The row's recorded `generation` is compared against the admitted fence's
/// resource generation in the same step, because a re-advanced generation
/// invalidates the claim even while every attempt identity still matches.
///
/// `now_unix_ms` is passed in rather than read here so the observation point
/// stays visible at the call site instead of hiding inside a clock read.
pub fn resolve_observe_claim_currency(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    record: &HostRequestRecord,
    claim: &ObserveClaimIdentity,
    now_unix_ms: u64,
) -> Result<ObserveClaimIdentity, ObserveClaimRefusal> {
    let presented_operation = attempt.operation_id.clone();
    if claim.operation_id != host_request_operation_id(envelope)
        || claim.request_digest != envelope.envelope_sha256
        || !claim.matches_presented_attempt(attempt)
    {
        return Err(ObserveClaimRefusal::ForeignClaim {
            presented_operation,
        });
    }
    let Some(durable) = record.attempt.as_ref() else {
        return Err(ObserveClaimRefusal::Unclaimed);
    };
    let presented_attempt = attempt.attempt_id.clone();
    if !claim.matches_durable_attempt(durable) {
        return Err(ObserveClaimRefusal::StaleAttempt { presented_attempt });
    }
    if !attempt
        .authority_epoch
        .is_same_authority(&envelope.state_fence.authority_epoch)
        || !attempt
            .authority_epoch
            .is_same_authority(&record.authority_epoch)
        || attempt.expires_at_unix_ms != record.deadline_unix_ms
        || record.generation != envelope.state_fence.resource_generation.value()
    {
        return Err(ObserveClaimRefusal::FenceReplaced { presented_attempt });
    }
    if now_unix_ms > record.deadline_unix_ms {
        return Err(ObserveClaimRefusal::Expired { presented_attempt });
    }
    Ok(claim.clone())
}

/// Returns whether the durable row already records the pre-effect phase for
/// this claim.
///
/// The W3 ordering check, and deliberately a question about the DURABLE ROW
/// rather than about a value the flight is holding. A daemon that recorded the
/// phase and then restarted still answers `true`; a daemon that never recorded
/// it answers `false` even if it still holds the pair in its queue. That is
/// what lets a recovered daemon tell "this attempt may already have effected"
/// from "this attempt never started" without trusting its own memory.
#[must_use]
pub fn observe_claim_phase_is_durable(
    record: &HostRequestRecord,
    claim: &ObserveClaimIdentity,
) -> bool {
    matches!(
        record.attempt.as_ref(),
        Some(attempt)
            if claim.matches_durable_attempt(attempt)
                && !observe_phase_is_pre_effect(attempt.phase)
    )
}

/// The gate the flight must satisfy before any owner call is permitted.
///
/// This is the W3 refusal expressed positively. It answers one question — may
/// this claim cause an effect — from three durable facts and nothing else: the
/// claim is the row's current attempt, the row's deadline has not elapsed, and
/// the row records a phase for that attempt that is not a pre-effect phase (so
/// the effect this claim may cause is attributable to this attempt if the
/// process dies mid-flight).
///
/// When it refuses, the caller must NOT call the owner. It reports
/// [`ObserveClaimRefusal::PhaseNotDurable`] and keeps the row, so the
/// operation is neither executed unattributably nor freed for a blind retry.
#[must_use = "the caller must act on this verdict: a refusal means the row must NOT be freed for a blind retry"]
pub fn observe_claim_phase_admits_effect(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    record: &HostRequestRecord,
    claim: &ObserveClaimIdentity,
    now_unix_ms: u64,
) -> Result<(), ObserveClaimRefusal> {
    resolve_observe_claim_currency(envelope, attempt, record, claim, now_unix_ms)?;
    if observe_claim_phase_is_durable(record, claim) {
        Ok(())
    } else {
        Err(ObserveClaimRefusal::PhaseNotDurable {
            presented_attempt: attempt.attempt_id.clone(),
        })
    }
}

/// Builds the typed owner operation identity one claim's capture commits under.
///
/// Derived from the Kernel-admitted operation exactly as the Governor owner
/// derives it, in one place, so a capture and its reconciliation reference can
/// never name two different operations. Returns an `Err` rather than a
/// best-effort string: a malformed operation identity must not become a
/// plausible-looking reconciliation reference.
pub fn observe_claim_owner_operation(
    envelope: &HostRequestEnvelope,
    observation_identity: &str,
) -> Result<OperationId, String> {
    let base = OperationId::new(host_request_operation_id(envelope))
        .map_err(|error| format!("observe claim base operation is invalid: {error}"))?;
    OperationId::new(format!("{base}/observe-{observation_identity}"))
        .map_err(|error| format!("observe claim owner operation is invalid: {error}"))
}
