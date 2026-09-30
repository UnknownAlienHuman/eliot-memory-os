#![forbid(unsafe_code)]

//! Daemon fire-side cue activation over the reconstructed cue role (#1720 A12).
//!
//! This is the `eliotd` composition root that makes the substantive
//! `eliot-cue-activation` crate reachable from the production binary through
//! its declared canonical path: the Governor reconstructs the cue role from
//! the Kernel-owned named-read closure
//! ([`eliot_governor::reconstruct_cue_snapshot`]), and this drive evaluates
//! the resulting candidate with
//! [`evaluate_activation`](eliot_cue_activation::evaluate_activation) under a
//! direct-only, exact-first daemon fire policy.
//!
//! Governed inputs only: the candidate comes from the Governor over the
//! Kernel named-read seven-role closure; request seeds are the candidate's
//! own admitted normalized cues; the fence, scope and clock are the closure's
//! own. No second durable store is introduced: the per-call reconstruction
//! cache is dropped with the call, and the evaluation summary travels in the
//! reconstruction response body whose digest the existing replay-exact
//! request/response path already covers.
//!
//! Profile adoption is two-phase and never minted: the first reconstruction
//! runs under this adapter's fire-side profile reference, the capture profile
//! embedded in the admitted bindings is then adopted (all bindings and keys
//! must agree on exactly one, or the evaluation is skipped), and the second
//! reconstruction plus the request run under that adopted profile, so the
//! evaluator's profile-binding checks compare governed values throughout.
//! A non-complete cue role, an empty binding set, a mixed profile set, or any
//! owner refusal becomes an explicit [`CueActivationSkip`] disposition; the
//! reconstruction itself is always still served.

use std::collections::BTreeSet;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_cue_activation::{
    ActivationError, ActivationProfile, MatchRule, evaluate_activation,
};
use eliot_cue_contracts::{
    ActivationBounds, ActivationBoundsSpec, ActivationRequest, ActivationRequestId,
    ActivationRequestSpec, ActivationStrength, CONTRACT_REVISION, Completeness, CueContractError,
    CueKind, CueSnapshotBuildCandidate, Digest, MatchMode, MAX_SEEDS, NormalizationOutcome,
    NormalizationProfile, NormalizedCue, SnapshotId,
};
use eliot_governor::{
    CueCompositionError, CueReconstructionCache, SevenRoleInputs, reconstruct_cue_snapshot,
};
use serde_json::{Value, json};
use thiserror::Error;

/// Fire-side adapter profile every daemon reconstruction starts from.
///
/// The digest covers a fixed descriptor, so the reference is stable across
/// calls; it names the adapter, never a capture claim.
const ADAPTER_PROFILE_ID: &str = "eliotd-cue-fire-v1";
/// Revision of the daemon fire-side adapter profile.
const ADAPTER_PROFILE_REVISION: u32 = 1;
/// Fixed descriptor the adapter profile digest is computed over.
const ADAPTER_PROFILE_DESCRIPTOR: &str = "eliotd-cue-fire-v1/1/fire-side-adapter-reference";
/// Numerical activation policy this drive evaluates under.
const ACTIVATION_PROFILE_ID: &str = "eliotd-cue-fire-v1";
/// Revision of the daemon numerical activation policy.
const ACTIVATION_PROFILE_REVISION: u32 = 1;
/// Uniform direct-match strength for every synthesized daemon match rule.
///
/// One fixed strength keeps exact-first ordering purely key-driven; this drive
/// claims no per-kind tuning.
const DIRECT_STRENGTH: u16 = 900;
/// Upper bound the daemon request allows for direct activations.
const MAX_DIRECT_HITS: u16 = u16::MAX;
/// Upper bound the daemon request allows for returned activations.
const MAX_RESULT_HITS: u16 = u16::MAX;
/// Upper bound the daemon request allows for inspected candidate nodes.
///
/// Covers every seed/binding pair (`MAX_SEEDS` seeds over at most
/// `MAX_SNAPSHOT_MEMBERS` bindings) without ever truncating the direct phase.
const MAX_INSPECTED_NODES: u32 = 4_194_304;
/// Upper bound the daemon request allows for accounting work units.
const MAX_ACCOUNTED_WORK: u64 = 1_000_000;
/// Upper bound the daemon request allows for canonical output bytes.
const MAX_OUTPUT_BYTES: u32 = 1_000_000;
/// Upper bound the daemon request allows for returned trace steps.
const MAX_TRACE_STEPS: u16 = 1024;

/// Why one cue activation evaluation did not run.
///
/// Every variant names the refusing stage and keeps the typed owner error, so
/// a skipped evaluation stays distinguishable from an evaluated one with no
/// direct hits.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CueActivationSkip {
    /// The cue role is authoritatively empty: there are no bindings to fire.
    #[error("cue role is authoritatively empty; no bindings can activate")]
    CueRoleEmpty,
    /// The cue role is not a complete projection; degraded input is never indexed.
    #[error("cue role is not a complete projection; degraded input is never indexed")]
    CueRoleNotReady,
    /// The Governor cue reconstruction refused the closure.
    #[error("governor cue reconstruction refused: {0}")]
    ReconstructionFailed(CueCompositionError),
    /// The reconstructed candidate carries no admitted bindings, so no seeds exist.
    #[error("reconstructed cue candidate carries no admitted bindings")]
    NoSeedCues,
    /// The admitted bindings and keys do not agree on exactly one normalization profile.
    #[error("admitted bindings disagree on the capture normalization profile")]
    MixedSeedProfiles,
    /// A seed is ambiguous/unsupported or carries no comparison keys.
    #[error("a request seed cannot be evaluated")]
    SeedNotEvaluable,
    /// A seed key asks for prefix/signature matching outside its admitted kind.
    #[error("a seed key asks for matching its kind does not admit")]
    UnsupportedKeyMode,
    /// The candidate carries more bindings than one bounded request accepts.
    #[error("candidate carries more bindings than one bounded request accepts: {count}")]
    TooManySeeds {
        /// Number of admitted bindings the candidate carried.
        count: usize,
    },
    /// A daemon-built identity, profile, bound set or request failed its own validation.
    #[error("daemon-built activation input rejected: {0}")]
    ContractRejected(CueContractError),
    /// The bounded evaluator refused the governed candidate/request/profile triple.
    #[error("bounded cue evaluation refused: {0}")]
    EvaluationRefused(ActivationError),
}

/// Deterministic summary of one evaluated cue activation.
///
/// Scalar values only: the full evaluation stays with the evaluator, and this
/// summary travels in the reconstruction response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CueActivationSummary {
    /// Request identity derived from the candidate build digest.
    pub request_id: String,
    /// Snapshot identity the candidate was reconstructed under.
    pub snapshot_id: String,
    /// Build digest of the evaluated candidate.
    pub candidate_build_digest: String,
    /// Input digest binding candidate, request and numerical policy.
    pub input_digest: String,
    /// Number of seed cues the request evaluated.
    pub seed_cues: usize,
    /// Number of direct comparison hits.
    pub direct_hits: usize,
    /// Number of relation-derived hits (always zero under the direct-only policy).
    pub derived_hits: usize,
    /// Number of recorded trace steps.
    pub trace_steps: usize,
    /// Stable completeness label of the result.
    pub completeness: &'static str,
}

/// Outcome of one fire-side cue activation drive evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CueActivationDisposition {
    /// The Governor candidate evaluated under the daemon fire policy.
    Evaluated(CueActivationSummary),
    /// No evaluation ran, with the refusing stage preserved.
    Skipped(CueActivationSkip),
}

impl CueActivationDisposition {
    /// Renders this disposition as the `cue_activation` section of the
    /// reconstruction response body.
    #[must_use]
    pub fn response_value(&self) -> Value {
        match self {
            CueActivationDisposition::Evaluated(summary) => json!({
                "evaluated": true,
                "request_id": summary.request_id.clone(),
                "snapshot_id": summary.snapshot_id.clone(),
                "candidate_build_digest": summary.candidate_build_digest.clone(),
                "input_digest": summary.input_digest.clone(),
                "seed_cues": summary.seed_cues,
                "direct_hits": summary.direct_hits,
                "derived_hits": summary.derived_hits,
                "trace_steps": summary.trace_steps,
                "completeness": summary.completeness,
            }),
            CueActivationDisposition::Skipped(skip) => json!({
                "evaluated": false,
                "stage": skip.stage(),
                "reason": skip.reason(),
            }),
        }
    }
}

impl CueActivationSkip {
    /// Stable stage name for the response body.
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        match self {
            CueActivationSkip::CueRoleEmpty | CueActivationSkip::CueRoleNotReady => "cue_role",
            CueActivationSkip::ReconstructionFailed(_) => "reconstruct",
            CueActivationSkip::NoSeedCues
            | CueActivationSkip::MixedSeedProfiles
            | CueActivationSkip::SeedNotEvaluable
            | CueActivationSkip::UnsupportedKeyMode
            | CueActivationSkip::TooManySeeds { .. } => "seeds",
            CueActivationSkip::ContractRejected(_) => "request",
            CueActivationSkip::EvaluationRefused(_) => "evaluate",
        }
    }

    /// Stable reason detail for the response body.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            CueActivationSkip::CueRoleEmpty => "cue role is authoritatively empty".to_owned(),
            CueActivationSkip::CueRoleNotReady => {
                "cue role is not a complete projection".to_owned()
            }
            CueActivationSkip::ReconstructionFailed(error) => error.to_string(),
            CueActivationSkip::NoSeedCues => "candidate carries no admitted bindings".to_owned(),
            CueActivationSkip::MixedSeedProfiles => {
                "bindings disagree on the capture profile".to_owned()
            }
            CueActivationSkip::SeedNotEvaluable => "a seed cannot be evaluated".to_owned(),
            CueActivationSkip::UnsupportedKeyMode => {
                "a seed key asks for matching its kind does not admit".to_owned()
            }
            CueActivationSkip::TooManySeeds { count } => {
                format!("candidate carries {count} bindings over the request bound")
            }
            CueActivationSkip::ContractRejected(error) => error.to_string(),
            CueActivationSkip::EvaluationRefused(error) => error.to_string(),
        }
    }
}

/// Drives one fire-side cue activation evaluation over reconstructed roles.
///
/// Pure over the Governor seven-role closure: the candidate is reconstructed
/// from the Kernel-owned named-read projections, seeds are the candidate's
/// own admitted cues, and the request replays deterministically under the
/// same State Fence. Never fails the caller: every refusal becomes a
/// [`CueActivationDisposition::Skipped`] the response body carries.
#[must_use]
pub fn evaluate_cue_activation(seven: &SevenRoleInputs) -> CueActivationDisposition {
    if seven.cue.state == ProjectionState::KnownEmpty {
        return CueActivationDisposition::Skipped(CueActivationSkip::CueRoleEmpty);
    }
    if seven.cue.state != ProjectionState::Complete {
        return CueActivationDisposition::Skipped(CueActivationSkip::CueRoleNotReady);
    }
    let snapshot_id = match daemon_snapshot_id(seven) {
        Ok(snapshot_id) => snapshot_id,
        Err(skip) => return CueActivationDisposition::Skipped(skip),
    };
    let adapter_profile = match daemon_adapter_profile() {
        Ok(adapter_profile) => adapter_profile,
        Err(skip) => return CueActivationDisposition::Skipped(skip),
    };
    let mut cache = CueReconstructionCache::new();
    let first = match reconstruct_cue_snapshot(seven, &snapshot_id, &adapter_profile, &mut cache) {
        Ok(reconstruction) => reconstruction.candidate,
        Err(error) => {
            return CueActivationDisposition::Skipped(CueActivationSkip::ReconstructionFailed(error));
        }
    };
    let adopted = match adopted_capture_profile(&first) {
        Ok(adopted) => adopted,
        Err(skip) => return CueActivationDisposition::Skipped(skip),
    };
    let candidate = if adopted == adapter_profile {
        first
    } else {
        match reconstruct_cue_snapshot(seven, &snapshot_id, &adopted, &mut cache) {
            Ok(reconstruction) => reconstruction.candidate,
            Err(error) => {
                return CueActivationDisposition::Skipped(CueActivationSkip::ReconstructionFailed(
                    error,
                ));
            }
        }
    };
    let seeds: Vec<NormalizedCue> = candidate
        .admitted_bindings
        .iter()
        .map(|binding| binding.normalized.clone())
        .collect();
    if seeds.len() > MAX_SEEDS {
        return CueActivationDisposition::Skipped(CueActivationSkip::TooManySeeds {
            count: seeds.len(),
        });
    }
    let rules = match daemon_match_rules(&seeds) {
        Ok(rules) => rules,
        Err(skip) => return CueActivationDisposition::Skipped(skip),
    };
    let bounds = ActivationBounds::new(ActivationBoundsSpec {
        max_depth: 0,
        max_fanout: 0,
        max_results: MAX_RESULT_HITS,
        max_nodes: MAX_INSPECTED_NODES,
        max_edges: 0,
        max_work: MAX_ACCOUNTED_WORK,
        max_path_len: 0,
        max_seeds: u16::try_from(seeds.len()).unwrap_or(u16::MAX),
        max_direct: MAX_DIRECT_HITS,
        max_derived: 0,
        max_trace_steps: MAX_TRACE_STEPS,
        max_output_bytes: MAX_OUTPUT_BYTES,
        activation_threshold: ActivationStrength(1),
    });
    if let Err(error) = bounds.validate() {
        return CueActivationDisposition::Skipped(CueActivationSkip::ContractRejected(error));
    }
    let profile = match ActivationProfile::seal(
        ACTIVATION_PROFILE_ID.to_owned(),
        ACTIVATION_PROFILE_REVISION,
        bounds,
        rules,
        Vec::new(),
        None,
    ) {
        Ok(profile) => profile,
        Err(error) => {
            return CueActivationDisposition::Skipped(CueActivationSkip::ContractRejected(error));
        }
    };
    let build_digest = candidate.build_digest.as_str().to_owned();
    let request_id = match ActivationRequestId::new(format!("cue-{build_digest}")) {
        Ok(request_id) => request_id,
        Err(error) => {
            return CueActivationDisposition::Skipped(CueActivationSkip::ContractRejected(error));
        }
    };
    let request = ActivationRequest::new(ActivationRequestSpec {
        schema_revision: CONTRACT_REVISION.to_owned(),
        request_id,
        seeds,
        snapshot_id: candidate.snapshot.snapshot_id.clone(),
        relation_edges: Vec::new(),
        bounds,
        state_fence: candidate.snapshot.state_fence.clone(),
        normalization_profile: adopted,
        observed_at: seven.clock.clone(),
        deadline_ms: None,
        cancelled: false,
    });
    let evaluation = match evaluate_activation(&candidate, &request, &profile) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            return CueActivationDisposition::Skipped(CueActivationSkip::EvaluationRefused(error));
        }
    };
    CueActivationDisposition::Evaluated(CueActivationSummary {
        request_id: evaluation.result.request_id.as_str().to_owned(),
        snapshot_id: evaluation.result.snapshot_id.as_str().to_owned(),
        candidate_build_digest: evaluation.candidate_build_digest.as_str().to_owned(),
        input_digest: evaluation.input_digest.as_str().to_owned(),
        seed_cues: request.seeds.len(),
        direct_hits: evaluation.result.direct.len(),
        derived_hits: evaluation.result.derived.len(),
        trace_steps: evaluation.result.trace.steps.len(),
        completeness: completeness_label(&evaluation.result.completeness),
    })
}

/// Derives the snapshot identity for one reconstruction deterministically.
///
/// The identity binds scope and State Fence, so the same request replayed
/// under the same fence rebuilds under the same identity; content binding
/// stays with the candidate build digest the Governor computes.
fn daemon_snapshot_id(seven: &SevenRoleInputs) -> Result<SnapshotId, CueActivationSkip> {
    let bytes = canonical_json_bytes(&(&seven.scope_id, &seven.state_fence)).map_err(|_| {
        CueActivationSkip::ContractRejected(CueContractError::Foundation {
            field: "cue.snapshot_closure",
        })
    })?;
    let fence_hex = sha256_hex(&bytes);
    SnapshotId::new(format!("cue-snapshot-{fence_hex}"))
        .map_err(CueActivationSkip::ContractRejected)
}

/// Builds the daemon fire-side adapter profile reference.
///
/// The digest covers the fixed adapter descriptor, so the reference is stable
/// and names the adapter rather than any capture claim.
fn daemon_adapter_profile() -> Result<NormalizationProfile, CueActivationSkip> {
    let digest = Digest::new(sha256_hex(ADAPTER_PROFILE_DESCRIPTOR.as_bytes()))
        .map_err(CueActivationSkip::ContractRejected)?;
    Ok(NormalizationProfile::new(
        ADAPTER_PROFILE_ID.to_owned(),
        ADAPTER_PROFILE_REVISION,
        digest,
    ))
}

/// Adopts the single capture profile the admitted bindings agree on.
///
/// The Governor decode stays the only reader of the cue payload: this
/// function only compares the profiles the reconstructed candidate already
/// carries. A binding set with no members, mixed profiles, or an
/// unevaluable seed refuses the evaluation instead of guessing a profile.
fn adopted_capture_profile(
    candidate: &CueSnapshotBuildCandidate,
) -> Result<NormalizationProfile, CueActivationSkip> {
    let first = match candidate.admitted_bindings.first() {
        Some(binding) => binding,
        None => return Err(CueActivationSkip::NoSeedCues),
    };
    let mut profiles = BTreeSet::new();
    for binding in &candidate.admitted_bindings {
        let normalized = &binding.normalized;
        if !seed_evaluable(normalized) {
            return Err(CueActivationSkip::SeedNotEvaluable);
        }
        profiles.insert((
            normalized.profile.profile_id.clone(),
            normalized.profile.profile_revision,
            normalized.profile.digest.as_str().to_owned(),
        ));
        for key in &normalized.comparison_keys {
            profiles.insert((
                key.profile.profile_id.clone(),
                key.profile.profile_revision,
                key.profile.digest.as_str().to_owned(),
            ));
        }
    }
    if profiles.len() != 1 {
        return Err(CueActivationSkip::MixedSeedProfiles);
    }
    let adopted = first.normalized.profile.clone();
    adopted
        .validate()
        .map_err(CueActivationSkip::ContractRejected)?;
    Ok(adopted)
}

/// Returns whether one admitted cue can serve as an evaluation seed.
///
/// Ambiguous or unsupported normalizations and keyless cues never seed a
/// request; the evaluator would refuse them, so the drive names the skip.
fn seed_evaluable(seed: &NormalizedCue) -> bool {
    if seed.comparison_keys.is_empty() {
        return false;
    }
    match &seed.outcome {
        NormalizationOutcome::Ambiguous { .. } | NormalizationOutcome::Unsupported { .. } => false,
        _ => true,
    }
}

/// Synthesizes the daemon match rules covering exactly the seed keys.
///
/// One uniform-strength rule per distinct observed kind/mode pair, plus the
/// exact-mode rule for every kind that also appears broadly, so the
/// evaluator's exact-priority check compares governed keys throughout.
/// Prefix keys outside path kinds and signature keys outside error signatures
/// refuse the evaluation instead of widening it.
fn daemon_match_rules(seeds: &[NormalizedCue]) -> Result<Vec<MatchRule>, CueActivationSkip> {
    let mut pairs = BTreeSet::new();
    for seed in seeds {
        for key in &seed.comparison_keys {
            if key.match_mode == MatchMode::Prefix
                && seed.observed.kind != CueKind::FilePath
                && seed.observed.kind != CueKind::DirPath
            {
                return Err(CueActivationSkip::UnsupportedKeyMode);
            }
            if key.match_mode == MatchMode::Signature
                && seed.observed.kind != CueKind::ErrorSignature
            {
                return Err(CueActivationSkip::UnsupportedKeyMode);
            }
            pairs.insert((seed.observed.kind, key.match_mode));
        }
    }
    let mut broad_kinds = BTreeSet::new();
    for (kind, mode) in &pairs {
        if *mode != MatchMode::Exact {
            broad_kinds.insert(*kind);
        }
    }
    for kind in broad_kinds {
        pairs.insert((kind, MatchMode::Exact));
    }
    Ok(pairs
        .into_iter()
        .map(|(kind, mode)| MatchRule::new(kind, mode, ActivationStrength(DIRECT_STRENGTH)))
        .collect())
}

/// Renders one activation completeness as a stable response label.
fn completeness_label(completeness: &Completeness) -> &'static str {
    match completeness {
        Completeness::Complete => "complete",
        Completeness::Truncated { .. } => "truncated",
        Completeness::Partial { .. } => "partial",
        Completeness::Blocked { .. } => "blocked",
        Completeness::Unavailable { .. } => "unavailable",
        Completeness::Unknown { .. } => "unknown",
        Completeness::SourceUnavailable { .. } => "source_unavailable",
        Completeness::NoDirectMatch { .. } => "no_direct_match",
        Completeness::Stale { .. } => "stale",
        _ => "unknown",
    }
}
