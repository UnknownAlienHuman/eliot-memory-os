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
//! → issue_learning_admission(governor, claim): the claim must be
//!   live-admissible RIGHT NOW (admitting state, live epoch/generation)
//! → digest equality: caller-built verified handles must cite the exact
//!   freshly minted issuance for this claim (no transplanted/stale permits)
//! → produce → retrieve_governed → admit_context_with_learning
//!   → assemble_active_view_with_learning (or fail closed)
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
//!
//! # Incomplete compilation is retained, not collapsed (#1726 W6)
//!
//! When the assembled packet cannot be produced because the grade is
//! incomplete, the host returns [`HostAdmitError::QualityIncomplete`] carrying
//! the whole [`IncompleteCompilation`]: the recipe actually attempted, the
//! exact handles the admitted set really reached, and the complete
//! twelve-dimension card with every failed, unknown, degraded and
//! not-applicable result, together with the typed operation-scoped refusal
//! the assembly owner produced. This is the only host refusal that is a
//! record rather than a message. Every other failure keeps its own string
//! variant, and none of them is an incomplete grade, so a structural contract
//! rejection is never confused with a compilation that ran and found its
//! packet lacking. No `ActiveUnderstandingView` is produced on this path: a
//! failed compilation returns no packet, only the evidence about why.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_admission::admit_context_with_learning;
use eliot_context_assembly::{
    ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy,
    assemble_active_view_with_learning,
};
use eliot_context_contracts::{
    AdmissionInput, AdmissionResult, AdmittedContextSet, ContextError, ContextOutcome,
    ContextRecipe, IncompleteCompilation, QualityDimensionResult, QualityScorecard,
    SerializedContextMeasurement,
};
use eliot_governor::{Governor, LearningAdmissionClaim, issue_learning_admission};
use eliot_improvement::candidate_bounds::{
    BoundsError, CrossTaskCarryover, GovernedRetrieval, RetrievalDecision, ReusableCandidateRef,
    retrieve_governed,
};
use eliot_improvement::{CarriageMark, bounds_to_context_error};
use eliot_improvement::{
    LearningProduction, PresentedLearning, datetime_from_unix, produce_learning_candidate,
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
    /// The compilation was attempted and could not produce a complete grade.
    ///
    /// #1726 W6. This is the one host refusal that is not a message. The
    /// assembly owner already produces the complete card together with the
    /// typed operation-scoped refusal; this variant carries that record
    /// unchanged across the host boundary instead of collapsing it into a
    /// string, so the daemon-facing response still names the attempted recipe,
    /// the exact handles the compilation had, and every failed and unknown
    /// dimension result. A host reader branches on the variant, not on text.
    ///
    /// `Display` renders the class, the operation and the blocking dimensions
    /// for a log line; the authoritative detail is the retained record, and it
    /// is never dropped to make the message shorter.
    QualityIncomplete(Box<IncompleteCompilation>),
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
            Self::QualityIncomplete(retained) => {
                // This is the daemon-facing response, so it is where the
                // retained attempt is actually read rather than merely carried.
                // Three facts cross here and none of them is an aggregate:
                //
                // * A2 — the diagnostic-display suitability. It is `Ok` for a
                //   read-only display even though the dependent action was
                //   refused, and it names the applicability inputs that are
                //   still unresolved, so the packet is shown WITH its
                //   limitation rather than as an error blob.
                // * A6 — the mandatory/optional split for the operation that
                //   was actually requested. An optional dimension's unknown
                //   does not appear in the mandatory list, so it cannot
                //   conceal a mandatory failure, and a mandatory failure is
                //   named even when unrelated dimensions are also uncertain.
                // * W6 — the complete non-passing result set, which is wider
                //   than the blocking list: a failed dimension that did not
                //   block the requested operation is still reported.
                //
                // Rendered for a log line and a human reader. The authoritative
                // detail remains the retained record; nothing here filters a
                // result to make the line shorter.
                // `diagnostic_display` re-validates, so it is fallible in principle. A
                // record only reaches this variant through
                // `IncompleteCompilation::retain`, which validates it before
                // returning, so a failure here would mean the retained record
                // stopped satisfying its own contract. `Display` cannot report
                // that as an error without inventing a second failure inside a
                // formatter, so the refusal is rendered explicitly instead —
                // which is also the honest reading: a record that cannot
                // re-validate is not a diagnostic packet.
                let Ok((suitability, incomplete)) = retained.diagnostic_display() else {
                    return write!(
                        formatter,
                        "QUALITY_INCOMPLETE:retained_record_failed_revalidation:operation={:?}:attempted_recipe={}",
                        retained.refusal.operation, retained.attempted_recipe_digest,
                    );
                };
                // The split is against the operation the compilation was
                // REFUSED for — read from the retained refusal — and never
                // against the display operation above. `DiagnosticDisplay`
                // requires nothing by construction, so splitting on it would
                // report an empty mandatory set and hide exactly the failures
                // this is here to name.
                let refused = retained.refusal.operation;
                // The split comes from the contract owner's own per-operation
                // required set, so "optional" is a closed function of the
                // operation and not something a producer flags. The two lists
                // partition the complete non-passing set: an optional unknown is
                // never in the mandatory list, so it cannot conceal a
                // mandatory failure, and a mandatory failure is still named
                // when unrelated dimensions are also uncertain.
                let (mandatory, optional) =
                    retained.incomplete_results_by_requirement(refused, &[]);
                let dimensions = |results: &[QualityDimensionResult]| {
                    results
                        .iter()
                        .map(|result| {
                            let dimension = result.dimension;
                            let state = &result.state;
                            format!("{dimension:?}={state:?}")
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                };
                write!(
                    formatter,
                    "QUALITY_INCOMPLETE:attempted_recipe={}:operation={refused:?}:mandatory=[{}]:optional=[{}]:unresolved_applicability={:?}:handles={}:omissions={}",
                    retained.attempted_recipe_digest,
                    dimensions(&mandatory),
                    dimensions(&optional),
                    suitability.unresolved_applicability,
                    retained.available_handles.len(),
                    retained.omitted_handles.len(),
                )?;
                if !incomplete.is_empty() {
                    write!(formatter, ":incomplete_results={}", dimensions(&incomplete))?;
                }
                Ok(())
            }
        }
    }
}

/// Retain one refused compilation attempt across the host boundary.
///
/// #1726 W6. The assembly owner's `AssemblyError::QualityIncomplete` already
/// retains the complete card and the typed operation-scoped refusal; this is
/// where the ADMISSION owner is still available to supply the exact handles the
/// attempt had, which the assembly error does not carry. Everything else is
/// passed through unchanged: the recipe is the one the caller attempted, and
/// the card is the one the assembly owner graded. No dimension is filtered, no
/// result is summarised, and the retained record is validated by
/// [`IncompleteCompilation::retain`] before it is returned, so a record that
/// does not describe a real attempt never reaches a host reader.
///
/// Every other assembly failure keeps its own `Assembly` variant: a structural
/// contract rejection is not an incomplete grade, and nothing about it is
/// stringified into this path.
fn retained_incomplete(
    error: AssemblyError,
    recipe: &ContextRecipe,
    admitted: &AdmittedContextSet,
) -> HostAdmitError {
    match error {
        AssemblyError::QualityIncomplete(quality, refusal) => {
            // A retention that itself fails is a contract failure of this
            // module, not a silent success: it is reported as an assembly
            // refusal with the contract cause, because a half-retained
            // diagnostic is exactly the collapse this variant exists to stop.
            IncompleteCompilation::retain(&admitted.binding, recipe, admitted, *quality, *refusal)
                .map_or_else(
                    |cause| HostAdmitError::Assembly(cause.to_string()),
                    |retained| HostAdmitError::QualityIncomplete(Box::new(retained)),
                )
        }
        other => HostAdmitError::Assembly(other.to_string()),
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

/// Re-anchor caller-built verified handles to the live issuance: mint the
/// claim fresh under the current owner and require digest equality.
/// Returns the live clock the caller must enforce with.
fn live_issuance(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
    production: &LearningProduction<'_>,
    presented: &PresentedLearning<'_>,
) -> Result<u64, HostAdmitError> {
    let now = live_now_secs()?;
    let fresh = issue_learning_admission(governor, claim)
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if production.verified.permit().digest() != fresh.digest()
        || presented.verified.permit().digest() != fresh.digest()
    {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    Ok(now)
}

/// Both surfaces must cite the same distinct cross-task admission, or neither
/// may cite one.
///
/// The producer and the retrieval/carriage screens are separate owners of the
/// two cross-task checks, so a caller that threaded one carryover into
/// production and another into the screens would let a stale record produce an
/// atom for a task the screens never checked. Identity is the owner-issued
/// pair, not the object identity: both the cross-task ticket digest and the
/// record's `admission_id` must agree, because either alone can be copied onto
/// a different record.
fn same_cross_task_carryover(
    production: Option<&CrossTaskCarryover<'_>>,
    presented: Option<&CrossTaskCarryover<'_>>,
) -> bool {
    match (production, presented) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.cross_task_permit().digest() == right.cross_task_permit().digest()
                && left.record().admission_id == right.record().admission_id
        }
        _ => false,
    }
}

/// Trusted native governed admission: run the complete owner-bound
/// learning compilation in the host process.
///
/// `governor` is the live owner handle and every other issuance artifact
/// arrives bound from the authenticated owner channel (see
/// [`GovernorGrant`]). Unmarked ordinary inputs compile exactly as the
/// underlying screens decide; marked influence passes only with a live
/// issuance, live overlay, active backlog backing, and — when the compilation
/// is for a task other than the local admission's target — the same distinct
/// owner-issued cross-task carryover on both the producer and the screens. Any
/// failure refuses the whole compilation.
#[allow(clippy::too_many_arguments)]
pub fn admit_governed_host<F>(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
    production: LearningProduction<'_>,
    presented: PresentedLearning<'_>,
    mut input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<HostGovernedCompilation, HostAdmitError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    let now = live_issuance(governor, claim, &production, &presented)?;
    if !same_cross_task_carryover(production.cross_task, presented.cross_task) {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    let presented = PresentedLearning {
        now_unix_secs: now,
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
        cross_task: presented.cross_task,
        backlog: presented.backlog,
        verified: presented.verified,
        now: datetime_from_unix(now)
            .map_err(|error| HostAdmitError::Retrieval(error.to_string()))?,
    })
    .map_err(|error| HostAdmitError::Retrieval(error.to_string()))?;
    input.candidates.candidates.push(produced);
    input.learning_tickets.push(presented.ticket.clone());
    let admission = admit_context_with_learning(&input, presented)
        .map_err(|error| HostAdmitError::Admission(error.to_string()))?;
    let view = match &admission.outcome {
        // The admitted set is still in scope on this arm, so the exact handles
        // the attempt reached are available to the retention rather than being
        // reconstructed from the card.
        ContextOutcome::Complete(set) => Some(
            assemble_active_view_with_learning(set, recipe, quality, policy, measure, presented)
                .map_err(|error| retained_incomplete(error, recipe, set))?,
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
    claim: &LearningAdmissionClaim,
    presented: PresentedLearning<'_>,
    input: &AdmissionInput,
    admission: &AdmissionResult,
) -> Result<(), HostAdmitError> {
    let now = live_now_secs()?;
    let fresh = issue_learning_admission(governor, claim)
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if presented.verified.permit().digest() != fresh.digest() {
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
                });
            }
        }
    }
    let presented = PresentedLearning {
        now_unix_secs: now,
        ..presented
    };
    eliot_improvement::check_governed_carriage(&presented, &admission.binding.state_fence, &marks)
        .map_err(bounds_to_context_error)
        .map_err(|error| HostAdmitError::HonorRefused(error.to_string()))
}
