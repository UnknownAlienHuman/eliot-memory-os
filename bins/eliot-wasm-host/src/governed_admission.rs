//! Trusted native governed-admission caller for learning compilations (#1869).
//!
//! Bounded production slice of the typed `admit` domain handoff: the host
//! process runs the full owner-bound chain — live claim admissibility,
//! issuance binding, owner-sourced clock, governed retrieval, admission,
//! and assembly — using the live [`Governor`] handle and registry held
//! from actual Governor authority. Every authority check recomputes
//! against live owner state on every call:
//!
//! ```text
//! live owner clock (process clock, never requester envelopes)
//! → issue_learning_record_admission_after_commit(governor, claim, evidence):
//!   the exact durable record and authenticated readback must be live-admissible
//!   RIGHT NOW
//! → digest equality: caller-built verified handles and record ticket must
//!   cite the exact freshly minted issuance (no transplanted/stale permits)
//! → produce → retrieve_governed → admit_context_with_record_learning
//!   → assemble_active_view_with_record_learning (or fail closed)
//! ```
//!
//! Authority discipline (mirrors the [`GovernorGrant`] port-grant pattern
//! in [`crate::contour`]): the caller binds `governor`, `claim`, ticket,
//! overlay, backlog, and cross-task records from the authenticated owner
//! channel. This module never fabricates a permit, never mints authority
//! from ambient input, and never moves Governor state into the WASM guest
//! (the guest contour refuses marked inputs outright). Re-minting inside
//! these entrypoints recomputes live admissibility for comparison only.
//!
//! The orchestration here is the host-owned counterpart of the rlib
//! composition helpers: every security invariant (ticket re-verification,
//! overlay liveness, backlog backing, cross-task admission, per-mark
//! binding) lives once in `eliot-improvement`/`eliot-context-admission`
//! and executes below; this module only sequences the boundary flow with
//! host-held owner inputs.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_admission::admit_context_with_record_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_record_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, ContextError, ContextOutcome, ContextRecipe, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_governor::{
    Governor, LearningRecordAdmissionClaim, LearningRecordDurabilityEvidence,
    issue_learning_record_admission_after_commit,
};
use eliot_improvement::candidate_bounds::{
    BoundsError, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef, retrieve_governed,
};
use eliot_improvement::{
    CarriageMark, LearningProduction, PresentedRecordLearning, bounds_to_context_error,
    check_governed_record_carriage, datetime_from_unix, produce_learning_candidate,
};

/// One host-composed governed learning compilation: retrieval decision,
/// admission, and the projected view when admission completed.
#[derive(Clone, Debug)]
pub struct HostGovernedCompilation {
    pub retrieval: RetrievalDecision,
    pub admission: AdmissionResult,
    pub view: Option<ActiveUnderstandingViewResult>,
}

/// Fail-closed host admission errors with stable codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostAdmitError {
    /// The claim is not live-admissible under the current owner state.
    ClaimRefused(String),
    /// A caller-built verified handle cites a different issuance than the
    /// live mint for this claim.
    IssuanceMismatch,
    /// The process clock is unavailable; expiry cannot be decided.
    ClockUnavailable,
    /// Campaign overlay record required for composed retrieval.
    OverlayRequired,
    /// Governed production refused.
    Production(String),
    /// Governed retrieval refused.
    Retrieval(String),
    /// Governed admission refused.
    Admission(String),
    /// Governed assembly refused.
    Assembly(String),
    /// A guest/native response failed the honored-output gate.
    HonorRefused(String),
}

impl fmt::Display for HostAdmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimRefused(reason) => write!(formatter, "CLAIM_REFUSED:{reason}"),
            Self::IssuanceMismatch => formatter.write_str("ISSUANCE_MISMATCH"),
            Self::ClockUnavailable => formatter.write_str("OWNER_CLOCK_UNAVAILABLE"),
            Self::OverlayRequired => formatter.write_str("OVERLAY_REQUIRED"),
            Self::Production(reason) => write!(formatter, "PRODUCTION_REFUSED:{reason}"),
            Self::Retrieval(reason) => write!(formatter, "RETRIEVAL_REFUSED:{reason}"),
            Self::Admission(reason) => write!(formatter, "ADMISSION_REFUSED:{reason}"),
            Self::Assembly(reason) => write!(formatter, "ASSEMBLY_REFUSED:{reason}"),
            Self::HonorRefused(reason) => write!(formatter, "HONOR_REFUSED:{reason}"),
        }
    }
}

impl std::error::Error for HostAdmitError {}

/// Live owner wall clock in unix seconds. Requester envelopes never supply
/// time on any authority path in this module.
fn live_now_secs() -> Result<u64, HostAdmitError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| HostAdmitError::ClockUnavailable)
}

fn live_now_ms() -> Result<u64, HostAdmitError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| {
            u64::try_from(elapsed.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
        })
        .map_err(|_| HostAdmitError::ClockUnavailable)
}

/// Re-anchor caller-built verified handles to the live issuance: mint the
/// claim fresh under the current owner and require digest equality.
/// Returns the live clock the caller must enforce with.
fn live_issuance(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
    production: &LearningProduction<'_>,
    presented: &PresentedRecordLearning<'_>,
) -> Result<(u64, u64), HostAdmitError> {
    let now_secs = live_now_secs()?;
    let now_ms = live_now_ms()?;
    let fresh = issue_learning_record_admission_after_commit(governor, claim, evidence)
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if production.verified.permit().digest() != fresh.digest()
        || presented.verified.permit().digest() != fresh.digest()
    {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    let fresh_record_ticket = fresh
        .record_ticket()
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if presented.record_ticket.digest != fresh_record_ticket.digest {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    Ok((now_secs, now_ms))
}

/// Trusted native governed admission: run the complete owner-bound
/// learning compilation in the host process.
///
/// `governor` is the live owner handle and every other issuance artifact
/// arrives bound from the authenticated owner channel (see
/// [`GovernorGrant`]). Unmarked ordinary inputs compile exactly as the
/// underlying screens decide; marked influence passes only with a live
/// issuance, live overlay, active backlog backing, and (cross-task) fresh
/// admission. Any failure refuses the whole compilation.
#[allow(clippy::too_many_arguments)]
pub fn admit_governed_host<F>(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
    production: LearningProduction<'_>,
    presented: PresentedRecordLearning<'_>,
    mut input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<HostGovernedCompilation, HostAdmitError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    let (now_secs, now_ms) = live_issuance(governor, claim, evidence, &production, &presented)?;
    let presented = PresentedRecordLearning {
        now_unix_secs: now_secs,
        now_unix_ms: now_ms,
        ..presented
    };
    let overlay = presented.overlay.ok_or(HostAdmitError::OverlayRequired)?;
    let permit = presented.verified.permit();
    let produced = produce_learning_candidate(production)
        .map_err(|error| HostAdmitError::Production(error.to_string()))?;
    let reusable = ReusableCandidateRef {
        candidate_id: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.candidate_id.clone())
            .ok_or(HostAdmitError::Retrieval(
                BoundsError::ReusableBackingMismatch.to_string(),
            ))?,
        closure_ref: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.closure_ref.clone()),
        owner: produced
            .learning
            .as_ref()
            .and_then(|mark| mark.owner.clone()),
        origin_campaign_id: permit.source_campaign_id().to_string(),
    };
    let retrieval = retrieve_governed(GovernedRetrieval {
        requesting_campaign_id: presented.requesting_campaign_id,
        requesting_task_id: presented.requesting_task_id,
        overlay,
        reusable: Some(&reusable),
        draft_delta_present: false,
        cross_task_admission: presented.cross_task_admission,
        backlog: presented.backlog,
        verified: presented.verified,
        now: datetime_from_unix(now_secs)
            .map_err(|error| HostAdmitError::Retrieval(error.to_string()))?,
    })
    .map_err(|error| HostAdmitError::Retrieval(error.to_string()))?;
    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission = admit_context_with_record_learning(&input, presented)
        .map_err(|error| HostAdmitError::Admission(error.to_string()))?;
    let view = match &admission.outcome {
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_record_learning(
                set, recipe, quality, policy, measure, presented,
            )
            .map_err(|error: AssemblyError| HostAdmitError::Assembly(error.to_string()))?,
        ),
        ContextOutcome::Incomplete(_) => None,
    };
    Ok(HostGovernedCompilation {
        retrieval,
        admission,
        view,
    })
}

/// Trusted honored-output gate: validate a natively produced admission
/// result against the input that produced it and the live Governor
/// issuance before the host honors anything admitted in it.
///
/// Envelope coherence (task identity plus exact State Fence), input-digest
/// rebinding (anti-substitution), then the full live-owner carriage gate
/// over admitted marked atoms. Unmarked results over unticketed inputs
/// pass on coherence alone. Intended for the host dispatch that honors
/// component/native retrieval output once the typed domain handoff lands.
pub fn check_governed_host_output(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
    presented: PresentedRecordLearning<'_>,
    input: &AdmissionInput,
    admission: &AdmissionResult,
) -> Result<(), HostAdmitError> {
    let now_secs = live_now_secs()?;
    let now_ms = live_now_ms()?;
    let fresh = issue_learning_record_admission_after_commit(governor, claim, evidence)
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if presented.verified.permit().digest() != fresh.digest() {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    let fresh_record_ticket = fresh
        .record_ticket()
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if presented.record_ticket.digest != fresh_record_ticket.digest {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    if admission.binding.task_id.as_str() != input.binding.task_id.as_str()
        || !eliot_contracts::fences_match_exact(
            &admission.binding.state_fence,
            &input.binding.state_fence,
        )
    {
        return Err(HostAdmitError::HonorRefused(
            "admission binding drifted from the requested compilation".to_owned(),
        ));
    }
    let input_digest = input
        .canonical_digest()
        .map_err(|_| HostAdmitError::HonorRefused("input digest failure".to_owned()))?;
    if input_digest != admission.input_digest {
        return Err(HostAdmitError::HonorRefused(
            "admission answers a different input".to_owned(),
        ));
    }
    let marked = match &admission.outcome {
        ContextOutcome::Complete(set) => set
            .records
            .iter()
            .any(|record| record.candidate.learning.is_some()),
        ContextOutcome::Incomplete(_) => false,
    };
    if !marked && input.learning_tickets.is_empty() {
        return Ok(());
    }
    let mut marks = Vec::new();
    if let ContextOutcome::Complete(set) = &admission.outcome {
        for record in &set.records {
            if record.candidate.binding.scope_id != admission.binding.scope_id {
                return Err(HostAdmitError::HonorRefused(
                    "admission binding scope drifted from the requested compilation".to_owned(),
                ));
            }
            if let Some(provenance) = &record.candidate.learning {
                provenance
                    .validate()
                    .map_err(|error| HostAdmitError::HonorRefused(error.to_string()))?;
                marks.push(CarriageMark {
                    campaign_id: provenance.campaign_id.as_str(),
                    overlay_id: provenance.overlay_id.as_deref(),
                    candidate_id: provenance.candidate_id.as_deref(),
                    closure_ref: provenance.closure_ref.as_deref(),
                    owner: provenance.owner.as_deref(),
                    draft: provenance.draft,
                    expires_at_unix_secs: provenance.expires_at_unix_secs,
                    permit_digest: provenance.permit_digest.as_str(),
                    binding_task_id: record.candidate.binding.task_id.as_str(),
                    record: provenance.record.as_ref(),
                });
            }
        }
    }
    let presented = PresentedRecordLearning {
        now_unix_secs: now_secs,
        now_unix_ms: now_ms,
        ..presented
    };
    check_governed_record_carriage(
        &presented,
        admission.binding.scope_id.as_str(),
        &admission.binding.state_fence,
        &marks,
    )
    .map_err(bounds_to_context_error)
    .map_err(|error| HostAdmitError::HonorRefused(error.to_string()))
}
