//! Governor-owned production cue evaluation over live closure inputs.
//!
//! T11.4 evaluation owner (CPU-side, deterministic, fence-bound): builds the
//! exact [`ActivationRequest`](eliot_cue_contracts::ActivationRequest) from
//! the live [`CueSnapshotBuildCandidate`](eliot_cue_contracts::CueSnapshotBuildCandidate)
//! (reconstructed from the live seven-role closure by
//! [`reconstruct_cue_snapshot`](crate::cue_composition::reconstruct_cue_snapshot)),
//! caller-supplied normalized seeds, and the caller-supplied versioned
//! numerical [`ActivationProfile`](eliot_cue_activation::ActivationProfile),
//! runs the bounded matching math, and admits the pair through the cue
//! owner's exact admission. No normalization, indexing, I/O, or authority
//! decision runs here: seeds arrive as normalizer-owner artifacts, the
//! candidate arrives from the Smart index owner, the profile arrives from
//! its caller, and every cross-binding is enforced fail-closed.
//!
//! Request scaffolding (all derived, nothing inferred):
//!
//! ```text
//! snapshot/bounds/profile  ← candidate snapshot + caller profile
//!                            (preflight enforces profile-bounds equality,
//!                            snapshot/fence/profile agreement);
//! edges                    ← candidate relation edges verbatim (the live
//!                            zero-edge build yields a direct-only request);
//! seeds                    ← caller normalized cues (non-empty; each seed
//!                            scope must equal the live closure scope);
//! fence                    ← live closure fence (candidate and evaluation
//!                            bind it; a refresh fails closed, never stale);
//! identity/clock           ← content-bound request id, empty observation
//!                            clock, no deadline, not cancelled.
//! ```
//!
//! The matching math itself is reused from the in-tree evaluated core
//! ([`evaluate_activation`](eliot_cue_activation::evaluate_activation)) —
//! one engine, not two — wrapped here with Governor closure binding and
//! output re-validation. The numerical profile is always caller-supplied;
//! nothing here default-enables a profile.

use eliot_contracts::{ClockReading, canonical_json_bytes, sha256_hex};
use eliot_cue_activation::{ActivationProfile, CueActivationEvaluation, evaluate_activation};
use eliot_cue_contracts::{
    ActivationRequest, ActivationRequestId, ActivationRequestSpec, CONTRACT_REVISION,
    CueSnapshotBuildCandidate, NormalizationOutcome, NormalizationProfile, NormalizedCue,
    ObservedCue, ObservedCueId, SnapshotId,
};
use eliot_cue_normalizer::{NormalizationPolicy, normalize_cue};
use serde::Serialize;
use thiserror::Error;

use crate::context_inputs::SevenRoleInputs;
use crate::cue_composition::{CueReconstructionCache, reconstruct_cue_snapshot};

/// One production cue evaluation: the admitted request plus its evaluated,
/// re-validated output (which carries the admitted result and the
/// policy/candidate/input binding digests).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveCueEvaluation {
    /// Admitted request built from the live candidate, seeds, and profile.
    pub request: ActivationRequest,
    /// Evaluated output bound to the exact candidate, request, and profile.
    pub evaluation: CueActivationEvaluation,
}

/// Fail-closed errors for production cue evaluation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CueEvaluationError {
    /// No normalized seeds were supplied; an evaluation without seeds is a
    /// malformed request, never an empty result.
    #[error("cue evaluation requires at least one normalized seed")]
    NoSeeds,
    /// A seed scope differs from the live closure scope.
    #[error("cue seed scope differs from the live closure scope")]
    SeedScope,
    /// The live cue reconstruction failed (degraded role, unexpected
    /// payload, or closure mismatch — never absorbed).
    #[error("live cue reconstruction failed: {0}")]
    Reconstruction(String),
    /// Request scaffolding failed (identity or shape the owners reject).
    #[error("cue request scaffolding failed: {0}")]
    Request(String),
    /// The bounded evaluation failed (limits, stale input, deadline, or
    /// profile mismatch — never retried as the same decision).
    #[error("cue evaluation failed: {0}")]
    Evaluation(String),
    /// The evaluated output failed re-validation against the exact
    /// candidate, request, and profile.
    #[error("cue evaluation output rejected: {0}")]
    Output(String),
}

/// Evaluates one bounded cue activation over live closure inputs.
///
/// Reconstructs the cue snapshot from `seven` (fence-bound through
/// `snapshot_id`/`normalization_profile`), scaffolds the exact request from
/// the live candidate plus `seeds` and `profile`, runs the evaluation, and
/// re-validates the output. Deterministic over its inputs: the request id is
/// content-bound, the clock is empty, and no I/O runs. Holds no state beyond
/// an ephemeral reconstruction cache.
pub fn evaluate_live_cue_pair(
    seven: &SevenRoleInputs,
    snapshot_id: SnapshotId,
    normalization_profile: eliot_cue_contracts::NormalizationProfile,
    seeds: Vec<NormalizedCue>,
    profile: &ActivationProfile,
) -> Result<LiveCueEvaluation, CueEvaluationError> {
    if seeds.is_empty() {
        return Err(CueEvaluationError::NoSeeds);
    }
    if seeds.iter().any(|seed| {
        seed.observed.context.scope_id.as_str() != seven.scope_id.as_str()
    }) {
        return Err(CueEvaluationError::SeedScope);
    }
    let mut cache = CueReconstructionCache::new();
    let reconstruction = reconstruct_cue_snapshot(
        seven,
        &snapshot_id,
        &normalization_profile,
        &mut cache,
    )
    .map_err(|error| CueEvaluationError::Reconstruction(error.to_string()))?;
    let candidate = reconstruction.candidate;
    let request = scaffold_request(seven, &candidate, seeds, profile)?;
    let evaluation = evaluate_activation(&candidate, &request, profile)
        .map_err(|error| CueEvaluationError::Evaluation(error.to_string()))?;
    evaluation
        .validate_against(&candidate, &request, profile)
        .map_err(|error| CueEvaluationError::Output(error.to_string()))?;
    Ok(LiveCueEvaluation {
        request,
        evaluation,
    })
}

/// Canonical shape of the content-bound request identity preimage.
#[derive(Serialize)]
struct RequestIdentity<'a> {
    domain: &'static str,
    candidate_build_digest: &'a str,
    profile_digest: &'a str,
    fence: &'a eliot_contracts::StateFence,
    scope: &'a str,
    seed_ids: Vec<&'a str>,
}

/// Builds the exact activation request from live and caller inputs.
///
/// Edges, bounds, snapshot, profile, and fence come from the live candidate
/// and the caller profile verbatim; seeds arrive as caller data. The request
/// id binds the candidate build digest, profile digest, fence, scope, and
/// sorted seed identities so re-evaluation over unchanged inputs is
/// idempotent. Identity minting here binds content only and grants nothing.
fn scaffold_request(
    seven: &SevenRoleInputs,
    candidate: &CueSnapshotBuildCandidate,
    seeds: Vec<NormalizedCue>,
    profile: &ActivationProfile,
) -> Result<ActivationRequest, CueEvaluationError> {
    let failed = |detail: &str| CueEvaluationError::Request(detail.to_owned());
    let mut seed_ids: Vec<&str> = seeds
        .iter()
        .map(|seed| seed.observed.observed_cue_id.as_str())
        .collect();
    seed_ids.sort_unstable();
    let preimage = RequestIdentity {
        domain: "eliot.cue.live-request.v1",
        candidate_build_digest: candidate.build_digest.as_str(),
        profile_digest: profile.digest.as_str(),
        fence: &seven.state_fence,
        scope: seven.scope_id.as_str(),
        seed_ids,
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|_| failed("request identity is not canonical"))?;
    let request_id = ActivationRequestId::new(sha256_hex(&bytes)).map_err(|_| failed("request identity rejected"))?;
    Ok(ActivationRequest::new(ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.to_owned(),
        request_id,
        seeds,
        snapshot_id: candidate.snapshot.snapshot_id.clone(),
        relation_edges: candidate.relation_edges.clone(),
        bounds: profile.bounds,
        state_fence: seven.state_fence.clone(),
        normalization_profile: candidate.snapshot.rebuild.normalization_profile.clone(),
        observed_at: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
        deadline_ms: None,
        cancelled: false,
    }))
}

/// Admitted seeds driven from live observations, plus their visible frontier.
///
/// `seeds` preserves caller observation order (the evaluation canonicalizes
/// for its input digest, so order here carries no authority). `excluded`
/// names every observation that produced no seed and why: ambiguous or
/// unsupported normalizations, keyless results, and stale or foreign
/// contexts are frontier evidence, never silent drops.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrivenSeeds {
    /// Normalized seeds admitted for evaluation, in observation order.
    pub seeds: Vec<NormalizedCue>,
    /// Observations excluded from seeding, with reasons.
    pub excluded: Vec<SeedExclusion>,
}

/// One observation excluded from seeding, with its stable reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedExclusion {
    /// Identity of the excluded observation.
    pub observed_cue_id: ObservedCueId,
    /// Stable reason class (`ambiguous-outcome`, `unsupported-outcome`,
    /// `unknown-outcome`, `empty-keys`, `stale-fence`, `foreign-scope`).
    pub reason: &'static str,
}

/// Fail-closed errors for seed driving. A malformed observation or a
/// normalization failure aborts the drive (caller shape, never partial
/// output); per-observation fate otherwise lands in
/// [`DrivenSeeds::excluded`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SeedDriveError {
    /// An observation fails its owner validation.
    #[error("seed observation is invalid: {0}")]
    InvalidObserved(String),
    /// Normalization itself failed (policy or signature fault, not an
    /// outcome disposition).
    #[error("seed normalization failed: {0}")]
    Normalization(String),
}

/// Drives admitted evaluation seeds from live observations through the
/// normalizer owner (CPU-side, deterministic, fence-bound).
///
/// Each observation validates through its owner, normalizes under the exact
/// caller `policy` and `profile`, and passes only with a usable outcome
/// (`Lossless` or `AuthorizedLoss`), non-empty comparison keys, and a
/// context fence/scope equal to the live closure. Anything else is excluded
/// with its reason — including an empty observation set, which yields zero
/// seeds (the evaluator then fails closed with `NoSeeds` rather than
/// synthesizing a pair). Holds no state; the policy, profile, and
/// observations arrive as caller-owned artifacts.
pub fn drive_observation_seeds(
    seven: &SevenRoleInputs,
    observations: Vec<ObservedCue>,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<DrivenSeeds, SeedDriveError> {
    let mut seeds = Vec::with_capacity(observations.len());
    let mut excluded = Vec::new();
    for observed in &observations {
        observed
            .validate()
            .map_err(|error| SeedDriveError::InvalidObserved(error.to_string()))?;
        let envelope = normalize_cue(observed, policy, profile)
            .map_err(|error| SeedDriveError::Normalization(error.to_string()))?;
        let normalized = envelope.normalized;
        let exclusion = match &normalized.outcome {
            NormalizationOutcome::Lossless | NormalizationOutcome::AuthorizedLoss { .. } => None,
            NormalizationOutcome::Ambiguous { .. } => Some("ambiguous-outcome"),
            NormalizationOutcome::Unsupported { .. } => Some("unsupported-outcome"),
            // Future owner variants exclude fail-closed: an unknown outcome
            // is frontier evidence, never an admitted seed.
            _ => Some("unknown-outcome"),
        };
        if let Some(reason) = exclusion {
            excluded.push(SeedExclusion {
                observed_cue_id: observed.observed_cue_id.clone(),
                reason,
            });
            continue;
        }
        if normalized.comparison_keys.is_empty() {
            excluded.push(SeedExclusion {
                observed_cue_id: observed.observed_cue_id.clone(),
                reason: "empty-keys",
            });
            continue;
        }
        if normalized.observed.context.state_fence != seven.state_fence {
            excluded.push(SeedExclusion {
                observed_cue_id: observed.observed_cue_id.clone(),
                reason: "stale-fence",
            });
            continue;
        }
        if normalized.observed.context.scope_id.as_str() != seven.scope_id.as_str() {
            excluded.push(SeedExclusion {
                observed_cue_id: observed.observed_cue_id.clone(),
                reason: "foreign-scope",
            });
            continue;
        }
        seeds.push(normalized);
    }
    Ok(DrivenSeeds { seeds, excluded })
}
