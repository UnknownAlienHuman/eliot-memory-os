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
//! → compose_governed_compilation: ticket re-verification, overlay
//!   liveness, backlog backing, cross-task admission, admit, assemble
//! ```
//!
//! Authority discipline (mirrors the [`GovernorGrant`] port-grant pattern
//! in [`crate::contour`]): the caller binds `governor`, `claim`, ticket,
//! overlay, backlog, and cross-task records from the authenticated owner
//! channel. This module never fabricates a permit, never mints authority
//! from ambient input, and never moves Governor state into the WASM guest
//! (the guest contour refuses marked inputs outright; see
//! `eliot-context-compiler-wasm`). Re-minting inside these entrypoints
//! recomputes live admissibility for comparison only.
//!
//! Host-side honored-output check ([`check_governed_host_output`]) applies
//! the same live binding to a `GuestResponse` before the host honors
//! anything admitted in it.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_compiler_wasm::{
    ComposeError, GovernedCompilation, GuestRequest, GuestResponse, HonorError,
    check_honored_output, compose_governed_compilation,
};
use eliot_context_assembly::AssemblyPolicy;
use eliot_context_contracts::{
    AdmissionInput, ContextError, ContextRecipe, QualityScorecard, SerializedContextMeasurement,
};
use eliot_governor::{Governor, LearningAdmissionClaim, issue_learning_admission};
use eliot_improvement::{LearningProduction, PresentedLearning};

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
    /// The governed composition refused.
    ComposeFailed(String),
    /// A guest/native response failed the honored-output gate.
    HonorRefused(String),
}

impl fmt::Display for HostAdmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClaimRefused(reason) => write!(formatter, "CLAIM_REFUSED:{reason}"),
            Self::IssuanceMismatch => formatter.write_str("ISSUANCE_MISMATCH"),
            Self::ClockUnavailable => formatter.write_str("OWNER_CLOCK_UNAVAILABLE"),
            Self::ComposeFailed(reason) => write!(formatter, "COMPOSE_FAILED:{reason}"),
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

/// Trusted native governed admission: run the complete owner-bound
/// learning compilation in the host process.
///
/// `governor` is the live owner handle and every other issuance artifact
/// arrives bound from the authenticated owner channel (see
/// [`GovernorGrant`]). Unmarked ordinary inputs compile exactly as the
/// underlying screens decide; marked influence passes only with a live
/// issuance, live overlay, active backlog backing, and (cross-task) fresh
/// admission. Any failure refuses the whole compilation.
pub fn admit_governed_host<F>(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
    production: LearningProduction<'_>,
    presented: PresentedLearning<'_>,
    input: AdmissionInput,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    measure: F,
) -> Result<GovernedCompilation, HostAdmitError>
where
    F: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
{
    let now = live_issuance(governor, claim, &production, &presented)?;
    let presented = PresentedLearning {
        now_unix_secs: now,
        ..presented
    };
    compose_governed_compilation(production, presented, input, recipe, quality, policy, measure)
        .map_err(|error: ComposeError| HostAdmitError::ComposeFailed(error.to_string()))
}

/// Trusted honored-output gate: validate a `GuestResponse` against the
/// request that produced it and the live Governor issuance before the host
/// honors anything admitted in it.
///
/// Same live binding as [`admit_governed_host`] (fresh mint + digest
/// equality + owner clock), then the shared honored-output check over the
/// response content. Unmarked coherent output passes; marked atoms admitted
/// anywhere without a live issuance refuse here even if the producing
/// contour passed them structurally.
pub fn check_governed_host_output(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
    presented: PresentedLearning<'_>,
    request: &GuestRequest,
    response: &GuestResponse,
) -> Result<(), HostAdmitError> {
    let now = live_now_secs()?;
    let fresh = issue_learning_admission(governor, claim)
        .map_err(|error| HostAdmitError::ClaimRefused(error.to_string()))?;
    if presented.verified.permit().digest() != fresh.digest() {
        return Err(HostAdmitError::IssuanceMismatch);
    }
    let presented = PresentedLearning {
        now_unix_secs: now,
        ..presented
    };
    check_honored_output(request, response, presented)
        .map_err(|error: HonorError| HostAdmitError::HonorRefused(error.to_string()))
}
