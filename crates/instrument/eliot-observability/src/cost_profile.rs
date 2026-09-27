//! Declared telemetry cost profiles for every event family on the running path.
//!
//! Telemetry consumes the same resources it observes, so each family carries a
//! [`TelemetryCostProfile`] naming its impact class, enforced capture mode,
//! sampling rate with its denominator, CPU/wall/allocation/memory/I/O/queue and
//! storage cost, hot-path latency delta, evidence coverage with blind
//! intervals, decision/recovery value, privacy/retention/disclosure cost, and
//! its qualification expiry with a removal/kill condition.
//!
//! Two properties are enforced by the types rather than by prose:
//!
//! * authority, lease, route, audit, external-effect, verifier, finish,
//!   recovery and control-loss are the nine full-evidence boundaries, pinned by
//!   [`TelemetryBoundary::full_evidence_boundaries`]. A profile that captures
//!   one of them partially is rejected as
//!   [`ObservabilityError::IncompleteCriticalEvidence`];
//! * a sampled, problem-only or disabled family carries
//!   [`PartialCaptureEvidence`], which has no complete-coverage variant, and
//!   [`CompleteEvidenceCoverage::new`] refuses every non-full mode.
//!   [`TelemetryCoverage::reports_complete_coverage`] additionally requires the
//!   declared mode to be [`CaptureMode::Full`], so a partial record cannot
//!   report complete coverage even if its fields are forged;
//! * [`RouteTelemetryConfiguration::new_for_route`] resolves both properties for
//!   one active route, so inspecting a route's configuration shows full capture
//!   for every full-evidence boundary and an explicit profile for every
//!   optional diagnostic family, and refuses a route whose collection is no
//!   longer justified.
//!
//! I16.11 stays visible: every rejection here is a typed
//! [`ObservabilityError`] for the emitting route to record, never a silent
//! success.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ObservabilityError, text, unique};
use crate::field_policy::{TelemetryFieldFamily, policy_for};

/// Instant, in Unix milliseconds, at which every published cost profile stops
/// being justified unless collection is re-justified.
///
/// One year after the `2026-09-27` revision these profiles were published on,
/// so telemetry collection is periodically re-argued rather than inherited.
pub const QUALIFICATION_EXPIRY_MS: i64 = 1_822_003_200_000;

/// Impact class of one event family, using the Governor terms from
/// `ARCH-ACT-01`: `Observe`, `Reversible`, `Material`, `Critical`.
///
/// `Forbidden` is not a family impact class: a family no route may observe is a
/// declared capture mode, not an impact class.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryImpactClass {
    /// No external change.
    Observe,
    /// Small local rollback.
    Reversible,
    /// Changes behavior, several resources, or external state.
    Material,
    /// Security, schema, credentials, or irreversible/high-blast effect.
    Critical,
}

impl TelemetryImpactClass {
    /// The canonical impact name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "OBSERVE",
            Self::Reversible => "REVERSIBLE",
            Self::Material => "MATERIAL",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for TelemetryImpactClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Declared capture mode for one family, with the exact I16.9 terms.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureMode {
    /// Every candidate occurrence of the family is retained.
    Full,
    /// A declared fraction is retained; the denominator is preserved and the
    /// unretained occurrences stay visible.
    Sampled,
    /// Only problem occurrences are retained; the denominator is preserved and
    /// the suppressed non-problem occurrences form a blind interval.
    OnProblem,
    /// The family is not collected; the whole denominator is a blind interval.
    DisabledWithGap,
}

impl CaptureMode {
    /// The canonical I16.9 capture-mode name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Sampled => "SAMPLED",
            Self::OnProblem => "ON_PROBLEM",
            Self::DisabledWithGap => "DISABLED_WITH_GAP",
        }
    }

    /// Whether this mode retains complete required evidence.
    #[must_use]
    pub const fn is_full_evidence(self) -> bool {
        matches!(self, Self::Full)
    }
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The named boundary an event family is collected across.
///
/// The nine full-evidence boundaries are non-negotiable: authority, lease,
/// route, audit, external-effect, verifier, finish, recovery and control-loss.
/// The remaining names are optional diagnostic detail that may be sampled,
/// problem-only or collected with a stated gap.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryBoundary {
    /// Grant, fencing and scope of an effect.
    Authority,
    /// Claim, hold and release of a work item.
    Lease,
    /// Dispatch decision and route selection.
    Route,
    /// Durable receipt for an audited decision.
    Audit,
    /// Applied external effect.
    ExternalEffect,
    /// Independent verification of a claim.
    Verifier,
    /// Terminal finish decision.
    Finish,
    /// Recovery entry, action and outcome.
    Recovery,
    /// Loss of the control channel and the later visible control-loss state.
    ControlLoss,
    /// Query metadata of one captured query.
    QueryMetadata,
    /// Per-event process debugging detail.
    ProcessDebug,
    /// Bounded dashboard counters.
    Metrics,
    /// Diagnostic detail about preserved raw evidence.
    EvidencePreservation,
}

impl TelemetryBoundary {
    /// Every governed boundary, full evidence first.
    #[must_use]
    pub const fn all() -> [Self; 13] {
        [
            Self::Authority,
            Self::Lease,
            Self::Route,
            Self::Audit,
            Self::ExternalEffect,
            Self::Verifier,
            Self::Finish,
            Self::Recovery,
            Self::ControlLoss,
            Self::QueryMetadata,
            Self::ProcessDebug,
            Self::Metrics,
            Self::EvidencePreservation,
        ]
    }

    /// The boundary name recorded on the profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Lease => "lease",
            Self::Route => "route",
            Self::Audit => "audit",
            Self::ExternalEffect => "external_effect",
            Self::Verifier => "verifier",
            Self::Finish => "finish",
            Self::Recovery => "recovery",
            Self::ControlLoss => "control_loss",
            Self::QueryMetadata => "query_metadata",
            Self::ProcessDebug => "process_debug",
            Self::Metrics => "metrics",
            Self::EvidencePreservation => "evidence_preservation",
        }
    }

    /// The nine boundaries that retain complete required evidence.
    #[must_use]
    pub const fn full_evidence_boundaries() -> [Self; 9] {
        [
            Self::Authority,
            Self::Lease,
            Self::Route,
            Self::Audit,
            Self::ExternalEffect,
            Self::Verifier,
            Self::Finish,
            Self::Recovery,
            Self::ControlLoss,
        ]
    }

    /// Whether this boundary is one of the nine full-evidence boundaries.
    #[must_use]
    pub const fn requires_full_evidence(self) -> bool {
        matches!(
            self,
            Self::Authority
                | Self::Lease
                | Self::Route
                | Self::Audit
                | Self::ExternalEffect
                | Self::Verifier
                | Self::Finish
                | Self::Recovery
                | Self::ControlLoss
        )
    }
}

impl fmt::Display for TelemetryBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for TelemetryFieldFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What happens to a collection at its qualification expiry.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryKillCondition {
    /// Re-justify the family, then remove it and its records.
    Remove,
    /// Stop collecting the family immediately.
    Kill,
}

impl TelemetryKillCondition {
    /// The canonical kill-condition name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Remove => "REMOVE",
            Self::Kill => "KILL",
        }
    }
}

impl fmt::Display for TelemetryKillCondition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Sampling rate applied to a family: retained occurrences out of a preserved
/// denominator, plus the capture mode that fixes the rate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingRate {
    /// Retained occurrences per `denominator` candidates; `0` for no capture.
    pub retained: u32,
    /// The candidates the retained occurrences are selected from.
    pub denominator: u32,
    /// The capture mode that fixes the rate.
    pub basis: CaptureMode,
}

impl SamplingRate {
    /// Every candidate is retained, with a `1:1` denominator.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            retained: 1,
            denominator: 1,
            basis: CaptureMode::Full,
        }
    }

    /// One occurrence retained out of `denominator` candidates.
    #[must_use]
    pub const fn sampled(denominator: u32) -> Self {
        Self {
            retained: 1,
            denominator,
            basis: CaptureMode::Sampled,
        }
    }

    /// No occurrence is retained; the whole denominator is a blind interval.
    #[must_use]
    pub const fn disabled(denominator: u32) -> Self {
        Self {
            retained: 0,
            denominator,
            basis: CaptureMode::DisabledWithGap,
        }
    }

    /// Candidates counted in the denominator but not retained.
    #[must_use]
    pub const fn blind_occurrences(self) -> u32 {
        self.denominator - self.retained
    }

    /// Validates that the rate is exact and consistent with its basis.
    fn validate(&self) -> Result<(), ObservabilityError> {
        if self.denominator == 0 {
            return Err(ObservabilityError::InvalidField {
                field: "sampling.denominator",
                reason: "sampling denominator must be greater than zero",
            });
        }
        if self.retained == 0 {
            return match self.basis {
                CaptureMode::DisabledWithGap => Ok(()),
                _ => Err(ObservabilityError::InvalidField {
                    field: "sampling.retained",
                    reason: "only a family disabled with a gap may retain zero occurrences",
                }),
            };
        }
        if self.retained > self.denominator {
            return Err(ObservabilityError::InvalidField {
                field: "sampling.retained",
                reason: "retained occurrences cannot exceed the sampling denominator",
            });
        }
        match self.basis {
            CaptureMode::Full => {
                if self.retained != self.denominator {
                    return Err(ObservabilityError::InvalidField {
                        field: "sampling.basis",
                        reason: "full capture must retain every candidate",
                    });
                }
                Ok(())
            }
            CaptureMode::Sampled | CaptureMode::OnProblem => {
                if self.retained == self.denominator {
                    return Err(ObservabilityError::InvalidField {
                        field: "sampling.basis",
                        reason: "a sampled or problem-only family must retain less than its denominator",
                    });
                }
                Ok(())
            }
            CaptureMode::DisabledWithGap => Err(ObservabilityError::InvalidField {
                field: "sampling.basis",
                reason: "a family disabled with a gap must retain zero occurrences",
            }),
        }
    }
}

/// The interval during which a family was not captured.
///
/// A blind interval is measured from the denominator, never inferred from a
/// missing sample.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindInterval {
    /// Immutable handle naming the interval.
    pub interval_ref: String,
    /// Why the family was not captured for this interval.
    pub reason_ref: String,
    /// Interval length in milliseconds; never zero.
    pub duration_ms: u64,
}

impl BlindInterval {
    fn validate(&self) -> Result<(), ObservabilityError> {
        text(&self.interval_ref, "blind_interval.interval_ref")?;
        text(&self.reason_ref, "blind_interval.reason_ref")?;
        if self.duration_ms == 0 {
            return Err(ObservabilityError::InvalidField {
                field: "blind_interval.duration_ms",
                reason: "a stated blind interval must have a non-zero duration",
            });
        }
        Ok(())
    }
}

/// Complete evidence coverage for a family captured under
/// [`CaptureMode::Full`].
///
/// [`new`](Self::new) is the only way to obtain this value and it refuses every
/// non-full mode, so complete coverage is unconstructible for a sampled,
/// problem-only or disabled family.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteEvidenceCoverage {
    /// Every candidate occurrence of the family was retained.
    pub all_candidates_retained: bool,
    /// The family is the complete required-evidence surface of its boundary.
    pub complete_for_scope: bool,
}

impl CompleteEvidenceCoverage {
    /// Declares complete coverage for a family captured under
    /// [`CaptureMode::Full`].
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityError::CoverageOverstated`] for every other mode.
    pub const fn new(mode: CaptureMode) -> Result<Self, ObservabilityError> {
        if !mode.is_full_evidence() {
            return Err(ObservabilityError::CoverageOverstated);
        }
        Ok(Self {
            all_candidates_retained: true,
            complete_for_scope: true,
        })
    }
}

/// Bounded coverage for a family that is not captured in full.
///
/// Every variant preserves the sampling denominator, and the two modes that
/// suppress occurrences also carry the blind interval. There is deliberately no
/// complete-coverage variant.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialCaptureEvidence {
    /// The sampling rate whose denominator bounds what was retained.
    pub sampling: SamplingRate,
    /// Occurrences counted in the denominator but not retained.
    pub blind_occurrences: u32,
    /// The blind interval itself, when one was stated.
    pub blind_interval: Option<BlindInterval>,
}

impl PartialCaptureEvidence {
    /// Bounded coverage under declared sampling; the denominator is preserved
    /// and the unretained occurrences are counted.
    #[must_use]
    pub const fn sampled(sampling: SamplingRate) -> Self {
        Self {
            blind_occurrences: sampling.blind_occurrences(),
            sampling,
            blind_interval: None,
        }
    }

    /// Bounded coverage under problem-only capture; the denominator is
    /// preserved and the suppressed non-problem occurrences form one blind
    /// interval.
    #[must_use]
    pub const fn on_problem(sampling: SamplingRate, blind_interval: BlindInterval) -> Self {
        Self {
            blind_occurrences: sampling.blind_occurrences(),
            sampling,
            blind_interval: Some(blind_interval),
        }
    }

    /// Bounded coverage for a family that is not collected; the whole
    /// denominator is one blind interval.
    #[must_use]
    pub const fn disabled(sampling: SamplingRate, blind_interval: BlindInterval) -> Self {
        Self {
            blind_occurrences: sampling.blind_occurrences(),
            sampling,
            blind_interval: Some(blind_interval),
        }
    }

    /// Whether this record names its blind interval; a blind interval with no
    /// handle is not a stated interval.
    #[must_use]
    pub const fn states_blind_interval(&self) -> bool {
        self.blind_interval.is_some()
    }

    /// Validates that the rate is exact, matches the mode and states the blind
    /// interval where the mode suppresses occurrences.
    fn validate(&self) -> Result<(), ObservabilityError> {
        self.sampling.validate()?;
        if self.blind_occurrences != self.sampling.blind_occurrences() {
            return Err(ObservabilityError::InvalidField {
                field: "coverage.blind_occurrences",
                reason: "blind occurrences must equal the unretained part of the denominator",
            });
        }
        match self.sampling.basis {
            CaptureMode::Full => Err(ObservabilityError::CoverageOverstated),
            CaptureMode::Sampled => Ok(()),
            CaptureMode::OnProblem | CaptureMode::DisabledWithGap => {
                if !self.states_blind_interval() {
                    return Err(ObservabilityError::InvalidField {
                        field: "coverage.blind_interval",
                        reason: "a problem-only or disabled family must state its blind interval",
                    });
                }
                if let Some(interval) = &self.blind_interval {
                    interval.validate()?;
                }
                Ok(())
            }
        }
    }
}

/// Evidence coverage of one family, tied to its capture mode.
///
/// `Full` carries [`CompleteEvidenceCoverage`]; the three partial modes carry
/// [`PartialCaptureEvidence`]. The pairing is total over [`CaptureMode`], so
/// the mode in force decides which coverage is representable.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCoverage {
    /// The mode this coverage was declared for.
    pub capture_mode: CaptureMode,
    /// Coverage when the family is captured in full.
    pub complete: Option<CompleteEvidenceCoverage>,
    /// Coverage when the family is sampled, problem-only or disabled.
    pub partial: Option<PartialCaptureEvidence>,
}

impl TelemetryCoverage {
    /// Declares the coverage for one capture mode.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityError::InvalidField`] when the coverage does not
    /// match the mode: `Full` requires complete coverage and no partial
    /// evidence, and a partial mode requires the reverse.
    pub fn declare(
        capture_mode: CaptureMode,
        complete: Option<CompleteEvidenceCoverage>,
        partial: Option<PartialCaptureEvidence>,
    ) -> Result<Self, ObservabilityError> {
        let matches_mode = if capture_mode.is_full_evidence() {
            complete.is_some() && partial.is_none()
        } else {
            complete.is_none() && partial.is_some()
        };
        if !matches_mode {
            return Err(ObservabilityError::InvalidField {
                field: "coverage",
                reason: "coverage variant must match the declared capture mode",
            });
        }
        if let Some(partial) = &partial {
            partial.validate()?;
        }
        Ok(Self {
            capture_mode,
            complete,
            partial,
        })
    }

    /// Whether this coverage states complete coverage.
    ///
    /// The declared mode must be [`CaptureMode::Full`] as well, so a partial
    /// family cannot report complete coverage.
    #[must_use]
    pub fn reports_complete_coverage(&self) -> bool {
        self.capture_mode.is_full_evidence() && self.complete.is_some() && self.partial.is_none()
    }

    /// The sampling denominator in force, when the family is not captured in
    /// full.
    #[must_use]
    pub fn sampling_denominator(&self) -> Option<u32> {
        self.partial
            .as_ref()
            .map(|partial| partial.sampling.denominator)
    }

    /// The blind interval in force, when the family is not captured in full.
    #[must_use]
    pub fn blind_interval(&self) -> Option<&BlindInterval> {
        self.partial
            .as_ref()
            .and_then(|partial| partial.blind_interval.as_ref())
    }
}

/// Qualification expiry of one family: collection must be re-justified before
/// this instant, and the kill condition applies at or after it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationExpiry {
    /// Instant, in Unix milliseconds, after which the family is no longer
    /// justified without re-justification.
    pub expires_at_ms: i64,
    /// What happens to the collection at expiry.
    pub kill_condition: TelemetryKillCondition,
    /// The stated reason the collection is removed or killed.
    pub condition_ref: String,
}

impl QualificationExpiry {
    /// Whether the collection is past its qualification at `observed_at_ms`.
    ///
    /// Expiry is judged against wall-clock milliseconds only, so it does not
    /// require a monotonic reading to be available.
    #[must_use]
    pub const fn is_expired(&self, observed_at_ms: i64) -> bool {
        observed_at_ms >= self.expires_at_ms
    }
}

/// One machine-readable telemetry cost profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryCostProfile {
    /// The boundary this profile governs.
    pub boundary: TelemetryBoundary,
    /// The telemetry field family whose records cross that boundary.
    pub family: TelemetryFieldFamily,
    /// Impact class of the boundary.
    pub impact_class: TelemetryImpactClass,
    /// The capture mode enforced for this boundary.
    pub capture_mode: CaptureMode,
    /// The sampling rate and its preserved denominator.
    pub sampling: SamplingRate,
    /// CPU, wall, allocation, memory, I/O, queue and storage cost of capture.
    pub resource_cost: String,
    /// The hot-path latency delta attributable to this boundary.
    pub hot_path_latency_delta: String,
    /// Evidence coverage, with blind intervals where capture is not full.
    pub coverage: TelemetryCoverage,
    /// Decision problems, diagnosis and recovery value references.
    pub decision_value_refs: Vec<String>,
    /// Privacy, retention and disclosure cost of the boundary.
    pub privacy_retention_disclosure_cost: String,
    /// Qualification expiry with its removal/kill condition.
    pub qualification: QualificationExpiry,
}

impl TelemetryCostProfile {
    /// Validates the capture-mode enforcement of this profile.
    ///
    /// Full-evidence boundaries admit only [`CaptureMode::Full`], the sampling
    /// basis and the coverage variant must both match the declared mode, a
    /// partial family must preserve its denominator, and the qualification must
    /// name a condition.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        self.sampling.validate()?;
        if self.boundary.requires_full_evidence() && !self.capture_mode.is_full_evidence() {
            return Err(ObservabilityError::IncompleteCriticalEvidence {
                family: self.family,
            });
        }
        if self.sampling.basis != self.capture_mode {
            return Err(ObservabilityError::InvalidField {
                field: "cost_profile.sampling",
                reason: "sampling basis must match the enforced capture mode",
            });
        }
        let declared = TelemetryCoverage::declare(
            self.capture_mode,
            self.coverage.complete,
            self.coverage.partial.clone(),
        )?;
        if declared != self.coverage {
            return Err(ObservabilityError::InvalidField {
                field: "cost_profile.coverage",
                reason: "coverage must match the declared capture mode",
            });
        }
        if !self.capture_mode.is_full_evidence() && !self.states_bounded_coverage() {
            return Err(ObservabilityError::InvalidField {
                field: "cost_profile.coverage",
                reason: "a sampled or disabled family must state its sampling denominator",
            });
        }
        if !self.capture_mode.is_full_evidence() && self.coverage.complete.is_some() {
            return Err(ObservabilityError::CoverageOverstated);
        }
        text(&self.resource_cost, "cost_profile.resource_cost")?;
        text(
            &self.hot_path_latency_delta,
            "cost_profile.hot_path_latency_delta",
        )?;
        if self.decision_value_refs.is_empty() {
            return Err(ObservabilityError::Empty {
                field: "cost_profile.decision_value_refs",
            });
        }
        unique(
            self.decision_value_refs.iter(),
            "cost_profile.decision_value_refs",
        )?;
        for reference in &self.decision_value_refs {
            text(reference, "cost_profile.decision_value_ref")?;
        }
        text(
            &self.privacy_retention_disclosure_cost,
            "cost_profile.privacy_retention_disclosure_cost",
        )?;
        text(
            &self.qualification.condition_ref,
            "cost_profile.qualification.condition_ref",
        )?;
        if self.qualification.expires_at_ms <= 0 {
            return Err(ObservabilityError::InvalidField {
                field: "cost_profile.qualification.expires_at_ms",
                reason: "qualification expiry must be a positive Unix millisecond instant",
            });
        }
        Ok(())
    }

    /// Whether this profile states complete coverage for its boundary.
    #[must_use]
    pub fn reports_complete_coverage(&self) -> bool {
        self.capture_mode.is_full_evidence() && self.coverage.reports_complete_coverage()
    }

    /// Whether this profile is past its qualification at `observed_at_ms`.
    #[must_use]
    pub fn is_expired(&self, observed_at_ms: i64) -> bool {
        self.qualification.is_expired(observed_at_ms)
    }

    /// Whether this profile states the sampling denominator or the blind
    /// interval its non-full capture mode requires.
    ///
    /// A partial family stating neither could be read as complete coverage, so
    /// it is not an acceptable declared profile.
    #[must_use]
    pub fn states_bounded_coverage(&self) -> bool {
        self.coverage.sampling_denominator().is_some() || self.coverage.blind_interval().is_some()
    }

    /// Admits one record offered against this profile, enforcing the declared
    /// capture mode in code.
    ///
    /// A route must collect exactly as the profile declares: it may not retain
    /// less than a full-evidence boundary requires, may not retain more than the
    /// declared rate allows, may not report complete coverage under a non-full
    /// mode, may not drop the denominator or the blind interval that mode
    /// requires, and may not continue past the qualification expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityError::IncompleteCriticalEvidence`] when a
    /// full-evidence boundary would be captured partially or sampled,
    /// [`ObservabilityError::InvalidField`] when `proposed` disagrees with the
    /// declared mode or drops required bounded coverage,
    /// [`ObservabilityError::CoverageOverstated`] when `offered` reports
    /// complete coverage under a non-full mode, or
    /// [`ObservabilityError::QualificationExpired`] when the collection is past
    /// its qualification.
    pub fn admit_capture(
        &self,
        proposed: CaptureMode,
        offered: &TelemetryCoverage,
        observed_at_ms: i64,
    ) -> Result<(), ObservabilityError> {
        self.validate()?;
        if self.capture_mode.is_full_evidence() && proposed != self.capture_mode {
            return Err(ObservabilityError::IncompleteCriticalEvidence {
                family: self.family,
            });
        }
        if proposed != self.capture_mode {
            return Err(ObservabilityError::InvalidField {
                field: "capture_mode",
                reason: "a route may neither widen nor narrow the declared capture mode",
            });
        }
        if !proposed.is_full_evidence() {
            // Check the raw field, not only the mode-guarded accessor: a record
            // that carries a complete-coverage claim under a non-full mode is
            // overstated even when the accessor already discounts it.
            if offered.complete.is_some() {
                return Err(ObservabilityError::CoverageOverstated);
            }
            if offered.sampling_denominator().is_none() && offered.blind_interval().is_none() {
                return Err(ObservabilityError::InvalidField {
                    field: "coverage",
                    reason: "a sampled or suppressed family must state its denominator or blind interval",
                });
            }
        }
        if self.is_expired(observed_at_ms) {
            return Err(ObservabilityError::QualificationExpired {
                family: self.family,
            });
        }
        Ok(())
    }
}

impl fmt::Display for TelemetryCostProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {} {}/{}",
            self.boundary,
            self.family.as_str(),
            self.capture_mode,
            self.sampling.retained,
            self.sampling.denominator,
        )
    }
}

/// One declared cost profile, as a compile-time table row.
///
/// The capture mode and the sampling rate live in the coverage declaration, so
/// a published profile cannot carry a rate that disagrees with its mode.
struct ProfileDeclaration {
    boundary: TelemetryBoundary,
    family: TelemetryFieldFamily,
    impact_class: TelemetryImpactClass,
    coverage: CoverageDeclaration,
    resource_cost: &'static str,
    hot_path_latency_delta: &'static str,
    decision_value_refs: &'static [&'static str],
    privacy_retention_disclosure_cost: &'static str,
    kill_condition: TelemetryKillCondition,
    condition_ref: &'static str,
}

/// How one declared profile states its evidence coverage, and at what rate.
enum CoverageDeclaration {
    /// Every candidate occurrence of the family is retained.
    Complete,
    /// A declared fraction is retained; the denominator is preserved.
    Sampled(SamplingRate),
    /// Only problem occurrences are retained; the suppressed remainder is one
    /// blind interval.
    OnProblem(SamplingRate, BlindIntervalDeclaration),
    /// The family is not collected; the whole denominator is one blind
    /// interval.
    DisabledWithGap(SamplingRate, BlindIntervalDeclaration),
}

/// One declared blind interval.
struct BlindIntervalDeclaration {
    interval_ref: &'static str,
    reason_ref: &'static str,
    duration_ms: u64,
}

const METRIC_SAMPLING: SamplingRate = SamplingRate {
    retained: 1,
    denominator: 60,
    basis: CaptureMode::OnProblem,
};

/// The nine full-evidence boundaries, then the optional diagnostic families.
const PROFILE_DECLARATIONS: [ProfileDeclaration; 13] = [
    ProfileDeclaration {
        boundary: TelemetryBoundary::Authority,
        family: TelemetryFieldFamily::Session,
        impact_class: TelemetryImpactClass::Critical,
        coverage: CoverageDeclaration::Complete,
        resource_cost: "one bounded session-transition event per transition; no per-tick state.",
        hot_path_latency_delta: "one session-transition append on the control path; off the dispatch hot path.",
        decision_value_refs: &[
            "A0.3: hidden creation or expansion of authority is a Hard Boundary",
            "A10.4: the authority epoch binds every governed action",
        ],
        privacy_retention_disclosure_cost: "opaque session references only; rolling-window purge on session close",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when session authority replaces the opaque reference scheme",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Lease,
        family: TelemetryFieldFamily::Lease,
        impact_class: TelemetryImpactClass::Material,
        resource_cost: "one bounded lease-transition event per claim, hold and release.",
        hot_path_latency_delta: "one lease-transition append on the scheduler path.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A10.4: lease state bounds governed work",
            "A2.3: leases and result aggregation belong to the orchestration layer",
        ],
        privacy_retention_disclosure_cost: "lease references only; purge on release plus rolling window",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when lease authority leaves the running Kernel-daemon path",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Route,
        family: TelemetryFieldFamily::RouteFingerprint,
        impact_class: TelemetryImpactClass::Material,
        resource_cost: "one bounded route-fingerprint record per dispatch decision.",
        hot_path_latency_delta: "one route-fingerprint append on the dispatch path.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A0.3: an untraceable irreversible or external effect is a Hard Boundary",
            "A10.4: route selection is a governed decision surface",
        ],
        privacy_retention_disclosure_cost: "route fingerprints disclose no arguments or topology",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when dispatch leaves the running Kernel-daemon path",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Audit,
        family: TelemetryFieldFamily::AuditReceipt,
        impact_class: TelemetryImpactClass::Critical,
        resource_cost: "one sealed canonical receipt per audited decision; never sampled.",
        hot_path_latency_delta: "no hot-path delta; the audit write is already on the effect path.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "I16.11: the critical event path begins with a normal audit write",
            "A0.3: hidden rewriting of provenance or history is a Hard Boundary",
        ],
        privacy_retention_disclosure_cost: "sealed canonical storage only; signed extracts by scope",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove only by compliance-surface migration with dual control",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::ExternalEffect,
        family: TelemetryFieldFamily::IoHandle,
        impact_class: TelemetryImpactClass::Critical,
        resource_cost: "one immutable handle per applied effect; bytes stay in BlobStore.",
        hot_path_latency_delta: "one handle mint per effect; no payload copy on the hot path.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A0.3: an untraceable irreversible or external effect is a Hard Boundary",
            "I16.9: Material and Critical effect boundaries keep complete required evidence",
        ],
        privacy_retention_disclosure_cost: "handles disclose presence only; raw bytes need an explicit per-blob grant",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when raw-output preservation moves to a successor store",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Verifier,
        family: TelemetryFieldFamily::TaskId,
        impact_class: TelemetryImpactClass::Material,
        resource_cost: "one bounded verification record per verifier invocation; the result is a reference, not a payload.",
        hot_path_latency_delta: "outside the synchronous decision boundary; the verifier publishes a bounded record.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A0.3: a false VERIFIED_COMPLETE or other proof claim is a Hard Boundary",
            "A14.8: proof levels stay distinct and a local PASS is not promoted",
        ],
        privacy_retention_disclosure_cost: "opaque task identifiers only; export with redacted extracts",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when verification leaves the running Kernel-daemon path",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Finish,
        family: TelemetryFieldFamily::TraceId,
        impact_class: TelemetryImpactClass::Material,
        resource_cost: "one bounded finish-decision record per terminal decision, with its trace lineage.",
        hot_path_latency_delta: "one finish-decision append on the terminal path.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A0.3: a false VERIFIED_COMPLETE or other proof claim is a Hard Boundary",
            "I16.9: finish boundaries retain complete required evidence",
        ],
        privacy_retention_disclosure_cost: "opaque trace identifiers only",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when the finish decision moves to a successor lineage carrier",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Recovery,
        family: TelemetryFieldFamily::Principal,
        impact_class: TelemetryImpactClass::Material,
        resource_cost: "one bounded recovery record per recovery entry, action and outcome.",
        hot_path_latency_delta: "off the hot path; recovery is a bounded entrypoint.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "A0.3: restoration of revoked influence after recovery is a Hard Boundary",
            "I16.9: recovery boundaries retain complete required evidence",
        ],
        privacy_retention_disclosure_cost: "opaque principal references only; no principal export",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when recovery records leave the running Kernel-daemon path",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::ControlLoss,
        family: TelemetryFieldFamily::CrashReport,
        impact_class: TelemetryImpactClass::Critical,
        resource_cost: "one bounded control-loss record per lost channel; the later visible state is retained too.",
        hot_path_latency_delta: "none on the hot path; the record is written when a channel returns.",
        coverage: CoverageDeclaration::Complete,
        decision_value_refs: &[
            "I16.11: a visible control-loss state follows when the next channel returns",
            "A0.3: hidden capture of control is a Hard Boundary",
        ],
        privacy_retention_disclosure_cost: "crash class only in labels; dumps need an incident grant",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when control-loss intake moves to a successor edge",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::QueryMetadata,
        family: TelemetryFieldFamily::QueryMetadata,
        impact_class: TelemetryImpactClass::Observe,
        resource_cost: "one handle-minted metadata record per retained query; content is a reference.",
        hot_path_latency_delta: "one handle mint per retained query on the intake path; unretained queries cost the denominator count only.",
        coverage: CoverageDeclaration::Sampled(SamplingRate::sampled(100)),
        decision_value_refs: &[
            "I16.9: optional ranking detail may use declared sampling when full capture would damage the hot path",
        ],
        privacy_retention_disclosure_cost: "query text stays behind an immutable handle; rolling-window purge",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when query intake leaves the running Kernel-daemon path",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::ProcessDebug,
        family: TelemetryFieldFamily::OperationalLog,
        impact_class: TelemetryImpactClass::Observe,
        resource_cost: "one scrubbed event per retained diagnostic occurrence in the rolling buffer.",
        hot_path_latency_delta: "one scrubbed append per retained diagnostic occurrence; unretained occurrences cost the denominator count only.",
        coverage: CoverageDeclaration::Sampled(SamplingRate::sampled(10)),
        decision_value_refs: &[
            "I16.9: missing sampled evidence stays visible and is not full coverage",
            "A0.2: a metric or signal must not become the system objective",
        ],
        privacy_retention_disclosure_cost: "scrubbed labels and handles only; raw re-export is forbidden",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when rolling logs move to a successor surface",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::Metrics,
        family: TelemetryFieldFamily::MetricSample,
        impact_class: TelemetryImpactClass::Observe,
        resource_cost: "one bounded sample per problem signal; counters are aggregates, never per-request payloads.",
        hot_path_latency_delta: "one sample append per problem signal; suppressed non-problem occurrences cost the denominator count only.",
        coverage: CoverageDeclaration::OnProblem(
            METRIC_SAMPLING,
            BlindIntervalDeclaration {
                interval_ref: "blind:metrics:non_problem",
                reason_ref: "bounded-metric-buffer:downsample-past-5_000",
                duration_ms: 60_000,
            },
        ),
        decision_value_refs: &[
            "I16.9: metrics use bounded local retention and downsampling",
            "A0.2: a metric must not become the system objective",
        ],
        privacy_retention_disclosure_cost: "aggregates disclose counts only; per-sample export is forbidden",
        kill_condition: TelemetryKillCondition::Remove,
        condition_ref: "remove when metrics move to a successor surface",
    },
    ProfileDeclaration {
        boundary: TelemetryBoundary::EvidencePreservation,
        family: TelemetryFieldFamily::IoHandle,
        impact_class: TelemetryImpactClass::Observe,
        resource_cost: "no capture cost; raw evidence is not duplicated into diagnostic telemetry.",
        hot_path_latency_delta: "none; nothing is emitted on this boundary.",
        coverage: CoverageDeclaration::DisabledWithGap(
            SamplingRate::disabled(1),
            BlindIntervalDeclaration {
                interval_ref: "blind:evidence_preservation:diagnostic",
                reason_ref: "raw evidence is not duplicated into diagnostic telemetry",
                duration_ms: 1,
            },
        ),
        decision_value_refs: &[
            "I16.9: missing telemetry means missing observability, never evidence of absence",
        ],
        privacy_retention_disclosure_cost: "no disclosure: the boundary is not collected",
        kill_condition: TelemetryKillCondition::Kill,
        condition_ref: "kill if any route duplicates raw evidence into diagnostic telemetry",
    },
];

impl BlindIntervalDeclaration {
    fn build(&self) -> BlindInterval {
        BlindInterval {
            interval_ref: self.interval_ref.to_owned(),
            reason_ref: self.reason_ref.to_owned(),
            duration_ms: self.duration_ms,
        }
    }
}

impl ProfileDeclaration {
    fn build(&self) -> TelemetryCostProfile {
        TelemetryCostProfile {
            boundary: self.boundary,
            family: self.family,
            impact_class: self.impact_class,
            capture_mode: self.coverage.capture_mode(),
            sampling: self.coverage.sampling(),
            resource_cost: self.resource_cost.to_owned(),
            hot_path_latency_delta: self.hot_path_latency_delta.to_owned(),
            coverage: self.coverage.build(),
            decision_value_refs: owned_refs(self.decision_value_refs),
            privacy_retention_disclosure_cost: self.privacy_retention_disclosure_cost.to_owned(),
            qualification: qualification(self.kill_condition, self.condition_ref),
        }
    }
}

impl CoverageDeclaration {
    /// The capture mode this declaration states.
    fn capture_mode(&self) -> CaptureMode {
        match self {
            Self::Complete => CaptureMode::Full,
            Self::Sampled(sampling)
            | Self::OnProblem(sampling, _)
            | Self::DisabledWithGap(sampling, _) => sampling.basis,
        }
    }

    /// The sampling rate this declaration states.
    fn sampling(&self) -> SamplingRate {
        match self {
            Self::Complete => SamplingRate::complete(),
            Self::Sampled(sampling)
            | Self::OnProblem(sampling, _)
            | Self::DisabledWithGap(sampling, _) => *sampling,
        }
    }

    /// The coverage this declaration states, tied to its own capture mode.
    fn build(&self) -> TelemetryCoverage {
        let complete = match self {
            Self::Complete => Some(CompleteEvidenceCoverage {
                all_candidates_retained: true,
                complete_for_scope: true,
            }),
            _ => None,
        };
        let sampling = self.sampling();
        let partial = match self {
            Self::Complete => None,
            Self::Sampled(_) => Some(PartialCaptureEvidence::sampled(sampling)),
            Self::OnProblem(_, interval) => Some(PartialCaptureEvidence::on_problem(
                sampling,
                interval.build(),
            )),
            Self::DisabledWithGap(_, interval) => {
                Some(PartialCaptureEvidence::disabled(sampling, interval.build()))
            }
        };
        TelemetryCoverage {
            capture_mode: self.capture_mode(),
            complete,
            partial,
        }
    }
}

fn owned_refs(references: &[&str]) -> Vec<String> {
    references
        .iter()
        .map(|reference| (*reference).to_owned())
        .collect()
}

fn qualification(
    kill_condition: TelemetryKillCondition,
    condition_ref: &str,
) -> QualificationExpiry {
    QualificationExpiry {
        expires_at_ms: QUALIFICATION_EXPIRY_MS,
        kill_condition,
        condition_ref: condition_ref.to_owned(),
    }
}

/// Full cost-profile inventory for the running path, one profile per boundary.
///
/// The nine full-evidence boundaries come first, then the optional diagnostic
/// families.
#[must_use]
pub fn cost_profile_inventory() -> Vec<TelemetryCostProfile> {
    PROFILE_DECLARATIONS
        .iter()
        .map(ProfileDeclaration::build)
        .collect()
}

/// Returns the cost profile governing one boundary, when the boundary is on the
/// path.
#[must_use]
pub fn cost_profile_for(boundary: TelemetryBoundary) -> Option<TelemetryCostProfile> {
    cost_profile_inventory()
        .into_iter()
        .find(|profile| profile.boundary == boundary)
}

/// Returns every cost profile whose records belong to one field family.
///
/// A family can cross more than one boundary with a different capture mode at
/// each, so a family lookup returns a list rather than one profile.
#[must_use]
pub fn cost_profiles_for(family: TelemetryFieldFamily) -> Vec<TelemetryCostProfile> {
    cost_profile_inventory()
        .into_iter()
        .filter(|profile| profile.family == family)
        .collect()
}

/// Validates the whole inventory: every boundary has exactly one profile, every
/// governed field family has at least one, each profile agrees with its
/// [`TelemetryFieldPolicy`](crate::field_policy::TelemetryFieldPolicy), the
/// nine full-evidence boundaries are captured in full, and no partial family
/// reports complete coverage.
///
/// # Errors
///
/// Returns the first [`ObservabilityError`] from a profile, from the matching
/// field policy, or from an inventory-level coverage rule.
pub fn validate_cost_profile_inventory() -> Result<(), ObservabilityError> {
    let profiles = cost_profile_inventory();
    unique(
        profiles.iter().map(|profile| profile.boundary),
        "cost_profile_inventory.boundaries",
    )?;
    for boundary in TelemetryBoundary::all() {
        if !profiles.iter().any(|profile| profile.boundary == boundary) {
            return Err(ObservabilityError::Empty {
                field: "cost_profile_inventory.boundary",
            });
        }
    }
    for family in TelemetryFieldFamily::all() {
        if !profiles.iter().any(|profile| profile.family == family) {
            return Err(ObservabilityError::Empty {
                field: "cost_profile_inventory.family",
            });
        }
    }
    for profile in &profiles {
        profile.validate()?;
        let policy = policy_for(profile.family).ok_or(ObservabilityError::Empty {
            field: "cost_profile_inventory.field_policy",
        })?;
        policy.validate()?;
        if policy.family != profile.family {
            return Err(ObservabilityError::IdentityConflict);
        }
    }
    for boundary in TelemetryBoundary::full_evidence_boundaries() {
        let profile = cost_profile_for(boundary).ok_or(ObservabilityError::Empty {
            field: "cost_profile_inventory.full_evidence",
        })?;
        if !profile.capture_mode.is_full_evidence() || !profile.reports_complete_coverage() {
            return Err(ObservabilityError::IncompleteCriticalEvidence {
                family: profile.family,
            });
        }
    }
    for profile in &profiles {
        if !profile.capture_mode.is_full_evidence() && profile.reports_complete_coverage() {
            return Err(ObservabilityError::CoverageOverstated);
        }
    }
    Ok(())
}

/// Enforces the capture mode in force at `boundary` and returns the profile
/// that governs it.
///
/// A full-evidence boundary admitted with a partial capture would understate
/// required evidence, and a family admitted past its qualification is no longer
/// justified. Both are rejected, so a route cannot report partial capture as
/// full coverage and cannot keep collecting past re-justification.
///
/// # Errors
///
/// Returns [`ObservabilityError::Empty`] when the boundary has no published
/// profile, [`ObservabilityError::IncompleteCriticalEvidence`] when a
/// full-evidence boundary would be captured partially,
/// [`ObservabilityError::QualificationExpired`] when the collection is past its
/// qualification, or the profile's own typed validation error otherwise.
pub fn enforce_capture_mode(
    boundary: TelemetryBoundary,
    observed_at_ms: i64,
) -> Result<TelemetryCostProfile, ObservabilityError> {
    let profile = cost_profile_for(boundary).ok_or(ObservabilityError::Empty {
        field: "cost_profile.boundary",
    })?;
    profile.validate()?;
    if boundary.requires_full_evidence() && !profile.capture_mode.is_full_evidence() {
        return Err(ObservabilityError::IncompleteCriticalEvidence {
            family: profile.family,
        });
    }
    if profile.is_expired(observed_at_ms) {
        return Err(ObservabilityError::QualificationExpired {
            family: profile.family,
        });
    }
    Ok(profile)
}

/// The resolved telemetry capture configuration in force for one route.
///
/// This is the object a route inspects to obtain the I16.9 fact and its limit at
/// once: the profiles captured in full across the nine full-evidence
/// boundaries, and the explicit profile of every optional diagnostic family,
/// whose coverage states its sampling denominator or its blind interval and
/// never reports complete coverage. Nothing here is a parallel ledger; the
/// configuration resolves the published
/// [`cost_profile_inventory`](cost_profile_inventory) through
/// [`enforce_capture_mode`], so every guarantee it exposes is the guarantee the
/// declared profile already carries.
///
/// I16.11 keeps the resolution visible: a route that cannot justify its
/// collection is refused with a typed [`ObservabilityError`] instead of
/// receiving a configuration that quietly drops a boundary. The configuration
/// therefore exists only for a still-justified collection, because
/// [`enforce_capture_mode`] refuses a family past its [`QualificationExpiry`]
/// before the value is built.
///
/// That refusal is the ONLY consultation of the expiry in this cell, and it
/// happens once, at construction. It is not a periodic re-justification:
/// [`RouteTelemetryConfiguration::is_expired`] reports a later instant than the
/// one the value was built at, and nothing re-consults it, because no caller
/// reaches this type yet. The [`TelemetryKillCondition`] each profile declares
/// is likewise read by no code in the repository — it is a declared string and
/// nothing more. Both belong to the stitching phase that gives this type a
/// production caller; until then this cell re-justifies a route once, on
/// construction, and says so rather than claiming a loop it does not run.
///
/// It is resolved rather than configured: the constructor is the only way to
/// obtain one, so the value is serializable for inspection but not
/// deserializable, and no unchecked path can assert a coverage claim this type
/// would have refused.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RouteTelemetryConfiguration {
    /// The route whose collection this configuration governs.
    route_ref: String,
    /// The full-evidence boundaries captured in full, in
    /// [`TelemetryBoundary::all`] order.
    full_evidence: Vec<TelemetryCostProfile>,
    /// The optional diagnostic families, in [`TelemetryBoundary::all`] order.
    optional_diagnostic: Vec<TelemetryCostProfile>,
}

impl RouteTelemetryConfiguration {
    /// Resolves the capture configuration in force for `route_ref` at
    /// `observed_at_ms`.
    ///
    /// The inventory is validated as a whole and then every governed boundary
    /// is admitted through [`enforce_capture_mode`], which refuses a
    /// full-evidence boundary that is not captured in full and a family past
    /// its qualification expiry. On top of that this resolution refuses a
    /// full-evidence boundary whose coverage record does not state complete
    /// evidence, an optional family that reports complete coverage, and an
    /// optional family that states neither its sampling denominator nor its
    /// blind interval.
    ///
    /// # Errors
    ///
    /// Returns [`ObservabilityError::InvalidField`] for a blank route
    /// reference, the inventory's own typed error when a published profile
    /// disagrees with its declaration,
    /// [`ObservabilityError::IncompleteCriticalEvidence`] when a full-evidence
    /// boundary would not retain complete evidence,
    /// [`ObservabilityError::QualificationExpired`] when a family is past its
    /// qualification expiry, [`ObservabilityError::CoverageOverstated`] when an
    /// optional family reports complete coverage, and
    /// [`ObservabilityError::InvalidField`] when an optional family states
    /// neither a sampling denominator nor a blind interval.
    pub fn new_for_route(
        route_ref: impl Into<String>,
        observed_at_ms: i64,
    ) -> Result<Self, ObservabilityError> {
        let route_ref = route_ref.into();
        text(&route_ref, "route_telemetry_configuration.route_ref")?;
        validate_cost_profile_inventory()?;
        let mut configuration = Self {
            route_ref,
            full_evidence: Vec::new(),
            optional_diagnostic: Vec::new(),
        };
        for boundary in TelemetryBoundary::all() {
            let profile = enforce_capture_mode(boundary, observed_at_ms)?;
            if boundary.requires_full_evidence() {
                if !profile.reports_complete_coverage() {
                    return Err(ObservabilityError::IncompleteCriticalEvidence {
                        family: profile.family,
                    });
                }
                configuration.full_evidence.push(profile);
                continue;
            }
            if profile.reports_complete_coverage() {
                return Err(ObservabilityError::CoverageOverstated);
            }
            if !profile.states_bounded_coverage() {
                return Err(ObservabilityError::InvalidField {
                    field: "route_telemetry_configuration.optional_coverage",
                    reason: "an optional family must state its sampling denominator or blind interval",
                });
            }
            configuration.optional_diagnostic.push(profile);
        }
        Ok(configuration)
    }

    /// The route whose collection this configuration governs.
    #[must_use]
    pub fn route_ref(&self) -> &str {
        &self.route_ref
    }

    /// The profiles captured in full across the full-evidence boundaries, in
    /// [`TelemetryBoundary::all`] order.
    #[must_use]
    pub fn full_evidence_profiles(&self) -> &[TelemetryCostProfile] {
        &self.full_evidence
    }

    /// The explicit profile of every optional diagnostic family, in
    /// [`TelemetryBoundary::all`] order.
    #[must_use]
    pub fn optional_diagnostic_profiles(&self) -> &[TelemetryCostProfile] {
        &self.optional_diagnostic
    }

    /// The profile governing `boundary` in this route, when the boundary is on
    /// the path.
    #[must_use]
    pub fn profile_for(&self, boundary: TelemetryBoundary) -> Option<&TelemetryCostProfile> {
        self.full_evidence
            .iter()
            .chain(&self.optional_diagnostic)
            .find(|profile| profile.boundary == boundary)
    }

    /// Whether this route's collection is past the qualification expiry at
    /// `observed_at_ms`, at which point each profile's declared
    /// [`TelemetryKillCondition`] applies.
    #[must_use]
    pub fn is_expired(&self, observed_at_ms: i64) -> bool {
        self.full_evidence
            .iter()
            .chain(&self.optional_diagnostic)
            .any(|profile| profile.is_expired(observed_at_ms))
    }
}
