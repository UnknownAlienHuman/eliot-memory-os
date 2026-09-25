//! Governor-owned risk and attestation for reactive-context admission (I7.19, #1942 C1).
//!
//! This module is the SOLE production source of the per-item `risk` the C1
//! transport supplies to `BridgeRunner::admit_reactive_injection`. It consumes
//! only threaded owner evidence and withholds when evidence is missing — it
//! never defaults, never infers, and never interprets plan text.
//!
//! Authority boundaries:
//! ```text
//! governor owns:  per-item risk tier + governance attestation below, derived
//!                 from the live Governor-minted GovernanceProfile and the
//!                 evaluation fence. The tier rule is a deterministic function
//!                 of owner-derived axes; every arm requires the full evidence
//!                 set, otherwise assessment withholds.
//! smart owns:     item selection, cue/firing/relations, scope/status/
//!                 governance strings, fence, severity (owner-set stickiness),
//!                 delivery channel, dedup keys (producer
//!                 `plan_bridge_admissions`; unmerged A lane at time of writing).
//! bridge owns:    session binding, ledger mutation, receipts, stickiness,
//!                 dedup, and the final AdmissionBasis construction including
//!                 the tier rendering (exact table in
//!                 `control-20260921/1942-governor-reactive-handoff.md`).
//! ```
//!
//! Inputs are threaded, never minted: the live [`GovernanceProfile`] comes
//! from [`GovernorCoverageDerivation::current`] (the sole minter of profile
//! revisions; `crates/governor/eliot-integration-coverage`), the criticality
//! bit is the Smart-owner stickiness observation (a `bool`, never a plan
//! string), and the fence is the evaluation [`StateFence`] the transport
//! planned under. Scope/status/governance strings pass through untouched —
//! the bridge records them verbatim and this module never reads them.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_integration_coverage::{EventCompleteness, GovernanceProfile};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fail-closed assessment errors. Missing evidence withholds the item — no
/// arm of the tier rule runs without the full evidence set.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveAdmissionError {
    /// No current profile has been derived: risk cannot be assessed.
    #[error("no current GovernanceProfile derived: risk cannot be assessed")]
    MissingGovernanceProfile,
    /// The live profile is unverified (route mismatch): risk cannot be assessed.
    #[error("GovernanceProfile is unverified: risk cannot be assessed")]
    UnverifiedProfile,
    /// Watchdog or trace freshness is stale: risk cannot be assessed.
    #[error("stale supervision evidence: risk cannot be assessed")]
    StaleEvidence,
    /// The evaluation fence is invalid (zero resource generation).
    #[error("evaluation fence is invalid")]
    InvalidFence,
}

/// Governor-assessed risk tier for one reactive item.
///
/// Governor-owned vocabulary over owner-derived axes — not an alias of the
/// bridge `RiskTier` and convertible to nothing here (no `From` shim). Each
/// variant names one exact evidence conjunction documented on
/// [`assess_reactive_risk`]; the C1 transport renders each variant 1:1 to the
/// bridge tier when building `AdmissionBasis` (table in the 1942 handoff).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReactiveRiskTier {
    /// Normal item under a complete, fresh, fully authorizing posture.
    Low,
    /// Normal item under a partial or not-fully-authorizing posture.
    Elevated,
    /// Critical item while enforcement is not currently authorized.
    High,
    /// Critical item while pre-action enforcement is authorized and fresh.
    Severe,
}

/// Governor risk + attestation for one reactive item.
///
/// Binds the assessed tier to the exact profile revision/fingerprint and
/// fence it was evaluated under, so the transport cannot mix an assessment
/// across posture changes or fence rotations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveRiskAssessment {
    /// Assessed tier (evidence conjunction, see [`assess_reactive_risk`]).
    pub tier: ReactiveRiskTier,
    /// Profile revision the assessment was evaluated under.
    pub profile_revision: u64,
    /// Profile fingerprint the assessment was evaluated under.
    pub profile_fingerprint: String,
    /// Evaluation fence, echoed for the transport's fence rendering.
    pub fence: StateFence,
    /// Smart-owner stickiness observation the tier was evaluated with.
    pub critical: bool,
}

impl ReactiveRiskAssessment {
    /// Canonical fence-epoch spelling for the bridge `fence_epoch` text
    /// field: `<lineage-uuid>:<sequence>`. Defined here as part of the
    /// Governor contract and pinned by test; the bridge validates bounded
    /// text only. The transport renders from the attested echo, never from
    /// raw plan text.
    #[must_use]
    pub fn fence_epoch_text(&self) -> String {
        format!(
            "{}:{}",
            self.fence.authority_epoch.lineage_id.as_str(),
            self.fence.authority_epoch.sequence.get()
        )
    }

    /// Fence generation for the bridge `fence_generation` field (non-zero:
    /// the assessment constructor rejects zero-generation fences).
    #[must_use]
    pub fn fence_generation_value(&self) -> u64 {
        self.fence.resource_generation.value()
    }
}

/// Assesses per-item risk and attestation from threaded owner evidence.
///
/// `profile` is the live [`GovernanceProfile`] reference from
/// [`GovernorCoverageDerivation::current`](eliot_integration_coverage::GovernorCoverageDerivation::current)
/// (`None` when nothing has been derived); `critical` is the Smart-owner
/// stickiness observation for this item; `fence` is the evaluation fence.
/// Pure computation: no reads, no clock, no I/O, no minted state.
///
/// Withholds (`Err`) on missing evidence — never a guessed tier:
/// - `None` profile → [`ReactiveAdmissionError::MissingGovernanceProfile`];
/// - unverified profile (route mismatch) → `UnverifiedProfile`;
/// - stale Watchdog or trace freshness → `StaleEvidence`;
/// - zero-generation fence → `InvalidFence`.
///
/// Tier rule (all evidence present, verified, and fresh):
/// - `critical` + `authorizes_enforcement` → `Severe`;
/// - `critical` + enforcement not authorized → `High`;
/// - normal + `completeness == Complete` + `authorizes_complete_coverage_ops`
///   → `Low`;
/// - normal otherwise → `Elevated`.
///
/// # Errors
///
/// Returns [`ReactiveAdmissionError`] on any missing/invalid evidence above.
pub fn assess_reactive_risk(
    profile: Option<&GovernanceProfile>,
    critical: bool,
    fence: &StateFence,
) -> Result<ReactiveRiskAssessment, ReactiveAdmissionError> {
    fence
        .validate()
        .map_err(|_| ReactiveAdmissionError::InvalidFence)?;
    let profile = profile.ok_or(ReactiveAdmissionError::MissingGovernanceProfile)?;
    if !profile.verified {
        return Err(ReactiveAdmissionError::UnverifiedProfile);
    }
    if !profile.watchdog_fresh || !profile.trace_fresh {
        return Err(ReactiveAdmissionError::StaleEvidence);
    }
    let tier = if critical {
        if profile.authorizes_enforcement {
            ReactiveRiskTier::Severe
        } else {
            ReactiveRiskTier::High
        }
    } else if profile.completeness == EventCompleteness::Complete
        && profile.authorizes_complete_coverage_ops
    {
        ReactiveRiskTier::Low
    } else {
        ReactiveRiskTier::Elevated
    };
    Ok(ReactiveRiskAssessment {
        tier,
        profile_revision: profile.revision,
        profile_fingerprint: profile.fingerprint.clone(),
        fence: fence.clone(),
        critical,
    })
}

/// Governor risk attestation bound to one admission material.
///
/// This is the typed atom join key between Governor risk and the admission
/// trace: `atom_id` is the stable identity of the evaluated candidate, and
/// `assessment` is the owner-state attestation (tier, profile
/// revision/fingerprint, echoed fence, criticality bit) evaluated under
/// [`assess_reactive_risk`]. Provenance travels with the binding — profile
/// revision and fingerprint name the exact GovernanceProfile derivation,
/// the echoed fence names the evaluation posture — while atom-to-source
/// resolution stays with the admission join, which owns the candidates.
/// The binding carries no warning text and decides no admission outcome:
/// risk evidence stays factual and separate from warning authority, which
/// the admission join derives from candidate-owned epistemic signals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AtomRiskBinding {
    /// Stable identity of the risk-assessed material.
    pub atom_id: ArtifactId,
    /// Owner-state risk attestation for this material.
    pub assessment: ReactiveRiskAssessment,
}

/// Binds one Governor risk attestation to one admission material.
///
/// Pure threading of [`assess_reactive_risk`] over owner state with the
/// atom join key attached: the same evidence set is required and the same
/// withholds apply (`MissingGovernanceProfile`, `UnverifiedProfile`,
/// `StaleEvidence`, `InvalidFence`) — a bound material is never a guessed
/// tier. No reads, no clock, no I/O, no minted state beyond the binding.
///
/// # Errors
///
/// Returns [`ReactiveAdmissionError`] on any missing/invalid evidence, with
/// exactly the [`assess_reactive_risk`] semantics above.
pub fn bind_atom_risk(
    profile: Option<&GovernanceProfile>,
    critical: bool,
    fence: &StateFence,
    atom_id: ArtifactId,
) -> Result<AtomRiskBinding, ReactiveAdmissionError> {
    Ok(AtomRiskBinding {
        atom_id,
        assessment: assess_reactive_risk(profile, critical, fence)?,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_integration_coverage::{
        ALL_EVENTS, DispatchOrdering, EventCoverage, EventDisposition, GovernorCoverageDerivation,
        IntegrationCoverageProfile, TraceFreshness, WatchdogEvidence,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                NonZeroU64::new(7).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(3).expect("generation"),
        )
    }

    fn full_enforcement_events() -> Vec<EventCoverage> {
        observed_pre_action_events(true)
    }

    fn observed_pre_action_events(pre_enforced: bool) -> Vec<EventCoverage> {
        ALL_EVENTS
            .iter()
            .map(|event| EventCoverage {
                event: *event,
                disposition: if pre_enforced
                    && matches!(
                        event,
                        eliot_integration_coverage::LogicalEvent::PreToolUse
                            | eliot_integration_coverage::LogicalEvent::PermissionRequest
                    ) {
                    EventDisposition::Enforced
                } else {
                    EventDisposition::Observed
                },
                ordering: DispatchOrdering::PreDispatch,
                completeness: EventCompleteness::Complete,
                proof_ceiling: "test-ceiling".to_owned(),
                source: "test-source".to_owned(),
                gaps: Vec::new(),
            })
            .collect()
    }

    fn fresh_watchdog() -> WatchdogEvidence {
        WatchdogEvidence {
            supervisor_id: "watchdog-1".to_owned(),
            fresh: true,
            summary: "test supervision".to_owned(),
        }
    }

    /// Real production chain: verified coverage + fresh watchdog/trace through
    /// the actual derivation owner, then assessment of its live profile.
    fn live_derivation() -> (GovernorCoverageDerivation, GovernanceProfile) {
        let coverage = IntegrationCoverageProfile::candidate(
            "fingerprint-1",
            full_enforcement_events(),
            EventCompleteness::Complete,
            "test-ceiling",
            "test-source",
            Vec::new(),
        )
        .expect("candidate")
        .verify("fingerprint-1", true)
        .expect("verified");
        let mut derivation = GovernorCoverageDerivation::new();
        let profile = derivation
            .derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh)
            .expect("derive");
        (derivation, profile)
    }

    #[test]
    fn critical_with_enforcement_authorized_is_severe() {
        let (derivation, _) = live_derivation();
        let assessment = assess_reactive_risk(derivation.current(), true, &test_fence())
            .expect("assess critical");
        assert_eq!(assessment.tier, ReactiveRiskTier::Severe);
        assert!(assessment.critical);
        // Attestation binds the exact live revision/fingerprint/fence.
        let live = derivation.current().expect("live profile");
        assert_eq!(assessment.profile_revision, live.revision);
        assert_eq!(assessment.profile_fingerprint, live.fingerprint);
        assert_eq!(assessment.fence, test_fence());
        assert_eq!(assessment.fence_epoch_text(), format!("{TEST_LINEAGE}:7"));
        assert_eq!(assessment.fence_generation_value(), 3);
    }

    #[test]
    fn normal_with_complete_posture_is_low() {
        let (derivation, _) = live_derivation();
        let assessment = assess_reactive_risk(derivation.current(), false, &test_fence())
            .expect("assess normal");
        assert_eq!(assessment.tier, ReactiveRiskTier::Low);
        assert!(!assessment.critical);
    }

    #[test]
    fn degraded_posture_steps_tiers_down_without_guessing() {
        // Stale trace keeps a verified profile but removes freshness evidence:
        // assessment withholds instead of inventing a tier.
        let coverage = IntegrationCoverageProfile::candidate(
            "fingerprint-2",
            full_enforcement_events(),
            EventCompleteness::Complete,
            "test-ceiling",
            "test-source",
            Vec::new(),
        )
        .expect("candidate")
        .verify("fingerprint-2", true)
        .expect("verified");
        let mut derivation = GovernorCoverageDerivation::new();
        derivation
            .derive(&coverage, &fresh_watchdog(), TraceFreshness::Stale)
            .expect("derive");
        assert_eq!(
            assess_reactive_risk(derivation.current(), true, &test_fence()),
            Err(ReactiveAdmissionError::StaleEvidence)
        );
        // Route mismatch revokes verification: withhold, not a degraded tier.
        let (_, _) = derivation
            .report_route_mismatch("fingerprint-2", "fingerprint-rogue")
            .expect("mismatch");
        assert_eq!(
            assess_reactive_risk(derivation.current(), false, &test_fence()),
            Err(ReactiveAdmissionError::UnverifiedProfile)
        );
    }

    #[test]
    fn critical_without_enforcement_authorization_is_high() {
        // Verified, fresh, complete posture — but pre-action events only
        // observed, so enforcement is not authorized: critical steps to High,
        // normal stays Low.
        let coverage = IntegrationCoverageProfile::candidate(
            "fingerprint-3",
            observed_pre_action_events(false),
            EventCompleteness::Complete,
            "test-ceiling",
            "test-source",
            Vec::new(),
        )
        .expect("candidate")
        .verify("fingerprint-3", true)
        .expect("verified");
        let mut derivation = GovernorCoverageDerivation::new();
        derivation
            .derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh)
            .expect("derive");
        assert!(
            !derivation
                .current()
                .expect("live profile")
                .authorizes_enforcement
        );
        assert_eq!(
            assess_reactive_risk(derivation.current(), true, &test_fence()).map(|a| a.tier),
            Ok(ReactiveRiskTier::High)
        );
        assert_eq!(
            assess_reactive_risk(derivation.current(), false, &test_fence()).map(|a| a.tier),
            Ok(ReactiveRiskTier::Low)
        );
    }

    #[test]
    fn normal_with_partial_posture_is_elevated() {
        // Verified and fresh, but the coverage denominator is partial: a
        // normal item steps to Elevated rather than Low.
        let coverage = IntegrationCoverageProfile::candidate(
            "fingerprint-4",
            full_enforcement_events(),
            EventCompleteness::Partial,
            "test-ceiling",
            "test-source",
            vec!["blind-interval-9".to_owned()],
        )
        .expect("candidate")
        .verify("fingerprint-4", true)
        .expect("verified");
        let mut derivation = GovernorCoverageDerivation::new();
        derivation
            .derive(&coverage, &fresh_watchdog(), TraceFreshness::Fresh)
            .expect("derive");
        assert_eq!(
            assess_reactive_risk(derivation.current(), false, &test_fence()).map(|a| a.tier),
            Ok(ReactiveRiskTier::Elevated)
        );
    }

    #[test]
    fn missing_profile_and_zero_generation_fence_withhold() {
        assert_eq!(
            assess_reactive_risk(None, true, &test_fence()),
            Err(ReactiveAdmissionError::MissingGovernanceProfile)
        );
        let (derivation, _) = live_derivation();
        // A zero-generation fence is invalid by contract
        // (`StateFence::validate` rejects it); assessment must not attest
        // under it.
        let mut bad = test_fence();
        bad.resource_generation = ResourceGeneration::default();
        assert_eq!(bad.resource_generation.value(), 0);
        assert_eq!(
            assess_reactive_risk(derivation.current(), false, &bad),
            Err(ReactiveAdmissionError::InvalidFence)
        );
    }
}
