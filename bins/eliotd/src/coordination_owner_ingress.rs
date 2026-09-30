//! Typed coordination result ingress for the coordination owner's write route.
//!
//! This module is the *only* way to reach
//! [`DaemonComposition::commit_coordination_candidate_result`](crate::DaemonComposition::commit_coordination_candidate_result):
//! that entry takes a [`CoordinationResultIngress`] and lowers it here, so a
//! caller cannot present a raw draft that skipped the closed-shape check, and
//! this type is not a sibling shape that production never constructs.
//!
//! Nothing here mints, defaults, or derives coordination identity. The ingress
//! validates the closed shape and refuses a blank or control-bearing field, so
//! a driver cannot smuggle an empty handle past the owner by constructing the
//! struct with a placeholder. A driver that has no admitted session, work item,
//! and lease must not call the commit entry at all.
//!
//! The four identity fields have distinct issuers, and conflating them is the
//! defect this type makes visible:
//!
//! | Field | Issuer | Meaning |
//! |---|---|---|
//! | `session_id` | the Kernel, on the admitted attempt | the registered actor |
//! | `work_item_id` | the Governor issuer, from the admitted attempt | the claimed durable item |
//! | `lease_id` | the Governor issuer, from the admitted attempt | the fenced claim on that item |
//! | `result_id` | the Governor issuer, from the admitted attempt | this one candidate result reference |
//!
//! Every one of those is a *presented* handle that the coordination owner
//! re-checks against the image it already holds; none of them is derived here.
//! `result_ref` is the candidate artifact handle. It is a reference, never a
//! verifier outcome, an acceptance claim, or a finish input: the coordination
//! owner stamps the admitted receipt at `CandidateArtifact` and this ingress
//! cannot express anything stronger, because the ceiling has exactly one
//! representable variant.
//!
//! # Production producer (issue #370 R1)
//!
//! This ingress is the live, total shape on the durable route, and it now has
//! one production construction site:
//! `campaign_task_controller::record_task_controller_coordination_candidate`.
//! That site fills `session_id`, `work_item_id`, `lease_id`, and `result_id`
//! from `eliot_governor::IssuedCoordinationWork`, which derives them from the
//! Kernel-issued `TaskControllerAttempt` for the exact admitted claim, and it
//! fills `result_ref` from the Kernel-validated `result_digest` of the response
//! bytes the Kernel durably accepted. No field here is a literal and none is
//! defaulted; a caller with no issued identity has nothing to construct.
//!
//! What this ingress still cannot express is recorded rather than papered over:
//! it carries no provider identity, no #361 execution-unit binding, and no
//! #369 physical route observation. The architecture contract's
//! `agent.coordinator.attempt-reconciliation` entrypoint owns the typed provider
//! result, and `eliot_coordination::AgentResultDraft` carries no such member, so
//! an admitted coordination receipt is a candidate *reference* for one admitted
//! attempt and not a provider result binding. The ceiling below is therefore the
//! strongest thing this route can say, and it is enforced by the owner, not by
//! this type.

use eliot_contracts::{EpochId, StateFence};
use eliot_governor::{AgentResultDraft, CompositionError, ResultAdmissionCeiling};
use serde::{Deserialize, Serialize};

/// Maximum bounded length of one coordination ingress text field.
///
/// This is the same order of magnitude the coordination owner itself applies to
/// its own reference fields, and it is deliberately generous: the point is to
/// refuse an unbounded or control-bearing handle, not to second-guess a
/// legitimately long reference.
const MAX_FIELD_LEN: usize = 1024;

/// One admitted coordination candidate result awaiting durable publication.
///
/// Every field is required and every field is validated here before the
/// coordination owner sees it, so a structural mistake is a typed
/// [`CompositionError`] at the ingress rather than an owner failure discovered
/// mid-commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationResultIngress {
    /// Retry identity for this exact submission. An exact replay under one
    /// request id is the owner's own idempotent return; the same request id
    /// with different bytes is the owner's own conflict.
    pub request_id: String,
    /// Candidate result reference identity, issued by the submitting attempt.
    pub result_id: String,
    /// The registered coordination session the lease is held by.
    pub session_id: String,
    /// The coordination work item the result belongs to.
    pub work_item_id: String,
    /// The fenced coordination lease that authorizes this submission.
    pub lease_id: String,
    /// Authority epoch under which the result was admitted.
    pub authority_epoch: EpochId,
    /// Fence the submission is admitted under. The coordination owner re-checks
    /// it against the fence its own lease record carries, so this is the fence
    /// the submitting attempt observed, never a fence of its own choosing.
    pub state_fence: StateFence,
    /// Candidate artifact handle. A reference only, never proof.
    pub result_ref: String,
    /// Observation time of this submission, as the coordination owner requires
    /// for its own lease-window and heartbeat arithmetic.
    pub now: u64,
}

/// Refuses one structurally unusable ingress field by name.
///
/// This is a shape failure in the request this daemon was handed, not a refusal
/// by the coordination owner, so it is classified as a typed composition
/// `Owner` error and never dressed as an owner verdict or a provider admission.
fn require_field(value: &str, field: &'static str) -> Result<(), CompositionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > MAX_FIELD_LEN
    {
        return Err(CompositionError::Owner(format!(
            "coordination ingress field {field} is blank, control-bearing, or longer than {MAX_FIELD_LEN} bytes"
        )));
    }
    Ok(())
}

impl CoordinationResultIngress {
    /// Validates the closed ingress shape and lowers it to the owner's own
    /// draft type.
    ///
    /// The returned draft carries `ResultAdmissionCeiling::CandidateArtifact`
    /// because that is the only representable ceiling on the owner's wire; a
    /// caller cannot express a finish, completion, or closure ceiling here
    /// because the enum admits no such variant.
    pub fn into_draft(self) -> Result<AgentResultDraft, CompositionError> {
        for (value, field) in [
            (&self.request_id, "request_id"),
            (&self.result_id, "result_id"),
            (&self.session_id, "session_id"),
            (&self.work_item_id, "work_item_id"),
            (&self.lease_id, "lease_id"),
            (&self.result_ref, "result_ref"),
        ] {
            require_field(value, field)?;
        }
        if self.now == 0 {
            return Err(CompositionError::Owner(
                "coordination ingress field now must be greater than zero".to_owned(),
            ));
        }
        // The epoch and the fence are two owner-validated views of one
        // admission, so an ingress that disagrees with itself is refused here
        // rather than at the owner. The owner still re-checks both against the
        // lease record it holds; this is not a second copy of that check.
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(CompositionError::Owner(
                "coordination ingress authority_epoch does not match its state_fence".to_owned(),
            ));
        }
        self.state_fence.validate().map_err(|error| {
            CompositionError::Owner(format!(
                "coordination ingress state_fence is invalid: {error}"
            ))
        })?;
        Ok(AgentResultDraft {
            request_id: self.request_id,
            result_id: self.result_id,
            lease_id: self.lease_id,
            session_id: self.session_id,
            work_item_id: self.work_item_id,
            authority_epoch: self.authority_epoch,
            state_fence: self.state_fence,
            result_ref: self.result_ref,
            ceiling: ResultAdmissionCeiling::CandidateArtifact,
            now: self.now,
        })
    }
}
