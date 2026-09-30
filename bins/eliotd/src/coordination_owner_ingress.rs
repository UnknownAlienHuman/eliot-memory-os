//! Typed coordination result ingress for the coordination owner's write route.
//!
//! This module defines the exact shape a session/work-item driver must present
//! to [`DaemonComposition::commit_coordination_candidate_result`](crate::DaemonComposition::commit_coordination_candidate_result).
//! It exists so the missing material is named and typed rather than described
//! in prose: every field below is one the coordination owner re-checks against
//! the image it already holds, and every one of them must come from an admitted
//! owner, never from this daemon.
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
//! | `session_id` | the coordination owner, via `register_session` | the registered actor |
//! | `work_item_id` | the coordination owner, via `register_work` | the claimed durable item |
//! | `lease_id` | the coordination owner, via `acquire_work` | the fenced claim on that item |
//! | `result_id` | the submitting attempt | this one candidate result reference |
//!
//! `result_ref` is the candidate artifact handle. It is a reference, never a
//! verifier outcome, an acceptance claim, or a finish input: the coordination
//! owner stamps the admitted receipt at `CandidateArtifact` and this ingress
//! cannot express anything stronger, because the ceiling has exactly one
//! representable variant.

use eliot_contracts::{EpochId, StateFence};
use eliot_governor::{AgentResultDraft, ResultAdmissionCeiling};
use serde::{Deserialize, Serialize};

use crate::DaemonError;

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
/// [`DaemonError::ProviderAdmission`] at the ingress rather than an owner
/// failure discovered mid-commit.
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
    /// Candidate artifact handle. A reference only, never proof.
    pub result_ref: String,
    /// Observation time of this submission, as the coordination owner requires
    /// for its own lease-window and heartbeat arithmetic.
    pub now: u64,
}

fn require_field(value: &str, field: &'static str) -> Result<(), DaemonError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > MAX_FIELD_LEN
    {
        return Err(DaemonError::ProviderAdmission(
            eliot_agent_coordinator::CoordinatorError::InvalidField(field),
        ));
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
    pub fn into_draft(self, state_fence: StateFence) -> Result<AgentResultDraft, DaemonError> {
        for (value, field) in [
            (&self.request_id, "coordination_ingress.request_id"),
            (&self.result_id, "coordination_ingress.result_id"),
            (&self.session_id, "coordination_ingress.session_id"),
            (&self.work_item_id, "coordination_ingress.work_item_id"),
            (&self.lease_id, "coordination_ingress.lease_id"),
            (&self.result_ref, "coordination_ingress.result_ref"),
        ] {
            require_field(value, field)?;
        }
        if self.now == 0 {
            return Err(DaemonError::ProviderAdmission(
                eliot_agent_coordinator::CoordinatorError::InvalidField("coordination_ingress.now"),
            ));
        }
        Ok(AgentResultDraft {
            request_id: self.request_id,
            result_id: self.result_id,
            lease_id: self.lease_id,
            session_id: self.session_id,
            work_item_id: self.work_item_id,
            authority_epoch: self.authority_epoch,
            state_fence,
            result_ref: self.result_ref,
            ceiling: ResultAdmissionCeiling::CandidateArtifact,
            now: self.now,
        })
    }
}
