//! Governor-owned runtime integration coverage (I7.16, I7.22, I7.23).
//!
//! Architecture vs implementation:
//! - I7.16 requires an [`IntegrationCoverageProfile`] recording what the exact
//!   concrete host/adapter fingerprint actually exposes and enforces for every
//!   lifecycle/effect event, plus a revision-bearing [`GovernanceProfile`]
//!   derived by the Governor from that coverage, Watchdog supervision evidence
//!   and trace freshness. Lost guarantees revoke dependent authority.
//! - I7.22 keeps discovery (candidate profiles) separate from conformance and
//!   production observation on the exact active fingerprint. Route mismatch
//!   makes results candidate-only and invalidates dependent capability
//!   evidence.
//! - I7.23 binds completeness claims to an explicit denominator: blind
//!   intervals and missing sources yield `PARTIAL`/`UNKNOWN`, never a
//!   self-reported pass.
//!
//! Ownership:
//! - The Governor (via [`GovernorCoverageDerivation`]) is the sole owner of
//!   [`GovernanceProfile`] revisions. Watchdog [`WatchdogEvidence`] is an
//!   input to derivation, never a substitute grade.
//! - Hook observation never mints authority: only `ENFORCED` dispositions on
//!   the pre-action events can authorize enforcement-dependent operations.
//! - Discovery outputs candidate (unverified) profiles only; exact
//!   active-fingerprint production observation is required before claims
//!   become verified.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod discovery_owner;
pub mod discovery_publication;

/// Fail-closed derivation and authorization errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CoverageError {
    #[error("invalid coverage field: {0}")]
    InvalidField(&'static str),
    #[error("profile fingerprint does not match the active fingerprint")]
    FingerprintMismatch,
    #[error("verified claims require exact active-fingerprint production observation")]
    ProductionObservationRequired,
    #[error("candidate profile is not verified for production claims")]
    CandidateNotVerified,
    #[error("duplicate capability: {0}")]
    DuplicateCapability(String),
    #[error("unknown capability: {0}")]
    UnknownCapability(String),
    #[error("capability revoked after coverage loss: {0}")]
    CapabilityRevoked(String),
    #[error("capability binding is stale (revision or fingerprint drift): {0}")]
    StaleCapabilityBinding(String),
    #[error("profile does not authorize this operation: {0}")]
    CapabilityNotAuthorized(String),
}

/// The ten logical lifecycle/effect events of I7.16.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
pub enum LogicalEvent {
    SessionStart,
    UserPromptSubmit,
    SubagentStart,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PreCompact,
    PostCompact,
    SubagentStop,
    #[serde(rename = "Stop/FinishAttempt")]
    #[schemars(rename = "Stop/FinishAttempt")]
    StopFinishAttempt,
}

/// The complete I7.16 logical event set in canonical order.
pub const ALL_EVENTS: [LogicalEvent; 10] = [
    LogicalEvent::SessionStart,
    LogicalEvent::UserPromptSubmit,
    LogicalEvent::SubagentStart,
    LogicalEvent::PreToolUse,
    LogicalEvent::PermissionRequest,
    LogicalEvent::PostToolUse,
    LogicalEvent::PreCompact,
    LogicalEvent::PostCompact,
    LogicalEvent::SubagentStop,
    LogicalEvent::StopFinishAttempt,
];

/// Per-event observation/enforcement axis from I7.16.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventDisposition {
    Enforced,
    Observed,
    ExplicitObserve,
    Unavailable,
}

/// Pre/post-dispatch ordering of one event observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DispatchOrdering {
    PreDispatch,
    PostDispatch,
    Unknown,
}

/// Completeness of one event stream or a whole profile (I7.23 denominator).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventCompleteness {
    Complete,
    Partial,
    Unknown,
    NotApplicable,
}

/// Trace freshness input to Governor derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TraceFreshness {
    Fresh,
    Stale,
}

/// One event's runtime coverage: disposition, ordering, completeness, proof
/// ceiling, source evidence and gap evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventCoverage {
    pub event: LogicalEvent,
    pub disposition: EventDisposition,
    pub ordering: DispatchOrdering,
    pub completeness: EventCompleteness,
    pub proof_ceiling: String,
    pub source: String,
    pub gaps: Vec<String>,
}

impl EventCoverage {
    /// Validates source, proof ceiling and gap evidence text.
    ///
    /// Gap binding (I7.23): a `PARTIAL` event must name its blind
    /// interval or missing source; a `COMPLETE` event must not carry gap
    /// evidence, otherwise the completeness claim is contradictory.
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.proof_ceiling, "event.proof_ceiling")?;
        validate_text(&self.source, "event.source")?;
        for gap in &self.gaps {
            validate_text(gap, "event.gaps.item")?;
        }
        match self.completeness {
            EventCompleteness::Partial if self.gaps.is_empty() => {
                return Err(CoverageError::InvalidField(
                    "event.gaps.required_when_partial",
                ));
            }
            EventCompleteness::Complete if !self.gaps.is_empty() => {
                return Err(CoverageError::InvalidField(
                    "event.gaps.unexpected_when_complete",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Runtime coverage for one exact host/adapter fingerprint.
///
/// A profile built by discovery is a candidate (`verified == false`). Only
/// [`Self::verify`] against the exact active fingerprint with production
/// observation promotes it to verified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCoverageProfile {
    pub fingerprint: String,
    pub verified: bool,
    pub events: Vec<EventCoverage>,
    pub completeness: EventCompleteness,
    pub proof_ceiling: String,
    pub source: String,
    pub gaps: Vec<String>,
}

impl IntegrationCoverageProfile {
    /// Builds a candidate (unverified) profile from discovery output.
    pub fn candidate(
        fingerprint: impl Into<String>,
        events: Vec<EventCoverage>,
        completeness: EventCompleteness,
        proof_ceiling: impl Into<String>,
        source: impl Into<String>,
        gaps: Vec<String>,
    ) -> Result<Self, CoverageError> {
        let profile = Self {
            fingerprint: fingerprint.into(),
            verified: false,
            events,
            completeness,
            proof_ceiling: proof_ceiling.into(),
            source: source.into(),
            gaps,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Promotes a candidate to verified after exact active-fingerprint
    /// production observation. Discovery output alone is never sufficient.
    /// The candidate is re-validated so a mutated profile cannot be
    /// promoted with contradictory or missing evidence.
    pub fn verify(
        mut self,
        active_fingerprint: &str,
        production_observed: bool,
    ) -> Result<Self, CoverageError> {
        self.validate()?;
        if self.fingerprint != active_fingerprint {
            return Err(CoverageError::FingerprintMismatch);
        }
        if !production_observed {
            return Err(CoverageError::ProductionObservationRequired);
        }
        self.verified = true;
        Ok(self)
    }

    /// Returns the disposition recorded for one logical event, if present.
    #[must_use]
    pub fn disposition(&self, event: LogicalEvent) -> Option<EventDisposition> {
        self.events
            .iter()
            .find(|coverage| coverage.event == event)
            .map(|coverage| coverage.disposition)
    }

    /// Validates identity, event evidence, gaps and completeness binding.
    ///
    /// Every profile declares all ten [`ALL_EVENTS`] logical events: an
    /// omitted event is rejected rather than treated as unavailable, so a
    /// missing observation/enforcement axis can never be silent (I7.16).
    /// A `COMPLETE` profile additionally requires every event to be
    /// `COMPLETE`; any partial event forces the profile to `PARTIAL` or
    /// worse with gap evidence (I7.23 denominator binding).
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.fingerprint, "coverage.fingerprint")?;
        validate_text(&self.proof_ceiling, "coverage.proof_ceiling")?;
        validate_text(&self.source, "coverage.source")?;
        if self.events.len() > ALL_EVENTS.len() {
            return Err(CoverageError::InvalidField("coverage.events"));
        }
        let mut seen = BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if !seen.insert(event.event) {
                return Err(CoverageError::InvalidField("coverage.events.duplicate"));
            }
        }
        for required in ALL_EVENTS {
            if !seen.contains(&required) {
                return Err(CoverageError::InvalidField("coverage.events.incomplete"));
            }
        }
        if self.completeness == EventCompleteness::Complete
            && self
                .events
                .iter()
                .any(|event| event.completeness != EventCompleteness::Complete)
        {
            return Err(CoverageError::InvalidField("coverage.events.completeness"));
        }
        if self.completeness != EventCompleteness::Complete && self.gaps.is_empty() {
            return Err(CoverageError::InvalidField(
                "coverage.gaps.required_when_incomplete",
            ));
        }
        for gap in &self.gaps {
            validate_text(gap, "coverage.gaps.item")?;
        }
        Ok(())
    }
}

/// Watchdog supervision evidence: an input to Governor derivation, never a
/// substitute grade and never authority by itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WatchdogEvidence {
    pub supervisor_id: String,
    pub fresh: bool,
    pub summary: String,
}

impl WatchdogEvidence {
    /// Validates the supervision evidence binding.
    pub fn validate(&self) -> Result<(), CoverageError> {
        validate_text(&self.supervisor_id, "watchdog.supervisor_id")?;
        validate_text(&self.summary, "watchdog.summary")?;
        Ok(())
    }
}

/// Governor-derived authority vector bound to one profile revision and one
/// exact fingerprint. It is a vector, never a single marketing grade.
///
/// Each boolean names one independent derivation axis (verification,
/// enforcement, completeness, Watchdog freshness, trace freshness), so the
/// excessive-bools lint is allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernanceProfile {
    pub revision: u64,
    pub fingerprint: String,
    pub verified: bool,
    pub authorizes_enforcement: bool,
    pub authorizes_complete_coverage_ops: bool,
    pub completeness: EventCompleteness,
    pub watchdog_fresh: bool,
    pub trace_fresh: bool,
}

impl GovernanceProfile {
    /// Returns whether an operation with the given requirements is authorized
    /// under this revision.
    #[must_use]
    pub const fn authorizes(&self, requires_enforced: bool, requires_complete: bool) -> bool {
        if !self.verified {
            return false;
        }
        if requires_enforced && !self.authorizes_enforcement {
            return false;
        }
        if requires_complete && !self.authorizes_complete_coverage_ops {
            return false;
        }
        true
    }
}

/// A capability bound to the exact profile revision and fingerprint that
/// authorized its issuance.
///
/// The three booleans are independent domain axes (two issuance requirements
/// plus revocation state), not a bool bag, so the excessive-bools lint is
/// allowed here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssuedCapability {
    pub capability_id: String,
    pub requires_enforced: bool,
    pub requires_complete: bool,
    pub profile_revision: u64,
    pub fingerprint: String,
    pub revoked: bool,
}

/// The Governor-owned derivation owner: the sole minter of
/// [`GovernanceProfile`] revisions and the sole revoker of capabilities bound
/// to them.
#[derive(Clone, Debug)]
pub struct GovernorCoverageDerivation {
    revision: u64,
    current: Option<GovernanceProfile>,
    capabilities: BTreeMap<String, IssuedCapability>,
}

impl GovernorCoverageDerivation {
    /// Creates an empty derivation owner with no current profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0,
            current: None,
            capabilities: BTreeMap::new(),
        }
    }

    /// Returns the current revision (zero when nothing has been derived).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the current [`GovernanceProfile`], if one has been derived.
    #[must_use]
    pub fn current(&self) -> Option<&GovernanceProfile> {
        self.current.as_ref()
    }

    /// Derives the [`GovernanceProfile`] from runtime coverage, Watchdog evidence
    /// and trace freshness.
    ///
    /// Enforcement is authorized only when the profile is verified, trace and
    /// Watchdog evidence are fresh, and both pre-action events (`PreToolUse`,
    /// `PermissionRequest`) are `ENFORCED`. Observation alone never authorizes
    /// enforcement. An unchanged re-derivation is idempotent and keeps the
    /// current revision; any content change emits a new revision and revokes
    /// every capability the new profile no longer authorizes.
    pub fn derive(
        &mut self,
        coverage: &IntegrationCoverageProfile,
        watchdog: &WatchdogEvidence,
        trace: TraceFreshness,
    ) -> Result<GovernanceProfile, CoverageError> {
        coverage.validate()?;
        watchdog.validate()?;
        if !coverage.verified {
            return Err(CoverageError::CandidateNotVerified);
        }
        let trace_fresh = trace == TraceFreshness::Fresh;
        let pre_action_enforced = matches!(
            coverage.disposition(LogicalEvent::PreToolUse),
            Some(EventDisposition::Enforced)
        ) && matches!(
            coverage.disposition(LogicalEvent::PermissionRequest),
            Some(EventDisposition::Enforced)
        );
        let authorizes_enforcement = pre_action_enforced && watchdog.fresh && trace_fresh;
        let authorizes_complete_coverage_ops =
            coverage.completeness == EventCompleteness::Complete && watchdog.fresh && trace_fresh;
        let candidate = GovernanceProfile {
            revision: self.revision.saturating_add(1).max(1),
            fingerprint: coverage.fingerprint.clone(),
            verified: true,
            authorizes_enforcement,
            authorizes_complete_coverage_ops,
            completeness: coverage.completeness,
            watchdog_fresh: watchdog.fresh,
            trace_fresh,
        };
        if let Some(current) = self.current.as_ref()
            && (GovernanceProfile {
                revision: current.revision,
                ..candidate.clone()
            }) == *current
        {
            return Ok(current.clone());
        }
        self.revision = candidate.revision;
        self.current = Some(candidate.clone());
        self.revoke_unauthorized();
        Ok(candidate)
    }

    /// Reports an observed route mismatch: the active route is no longer the
    /// profile fingerprint. Emits a new revision that authorizes nothing and
    /// revokes every capability bound to the lost fingerprint.
    pub fn report_route_mismatch(
        &mut self,
        expected_fingerprint: &str,
        observed_fingerprint: &str,
    ) -> Result<(GovernanceProfile, Vec<String>), CoverageError> {
        validate_text(expected_fingerprint, "route.expected_fingerprint")?;
        validate_text(observed_fingerprint, "route.observed_fingerprint")?;
        if expected_fingerprint == observed_fingerprint {
            return Err(CoverageError::InvalidField("route.no_mismatch"));
        }
        let revision = self.revision.saturating_add(1).max(1);
        let profile = GovernanceProfile {
            revision,
            fingerprint: observed_fingerprint.to_owned(),
            verified: false,
            authorizes_enforcement: false,
            authorizes_complete_coverage_ops: false,
            completeness: EventCompleteness::Unknown,
            watchdog_fresh: false,
            trace_fresh: false,
        };
        self.revision = revision;
        self.current = Some(profile.clone());
        let revoked = self.revoke_all();
        Ok((profile, revoked))
    }

    /// Issues a capability bound to the current profile revision and
    /// fingerprint. Issuance records the dependency; [`Self::authorize`]
    /// enforces it.
    pub fn issue_capability(
        &mut self,
        capability_id: impl Into<String>,
        requires_enforced: bool,
        requires_complete: bool,
    ) -> Result<IssuedCapability, CoverageError> {
        let capability_id = capability_id.into();
        validate_text(&capability_id, "capability.id")?;
        if self.capabilities.contains_key(&capability_id) {
            return Err(CoverageError::DuplicateCapability(capability_id));
        }
        let current = self
            .current
            .as_ref()
            .ok_or(CoverageError::CandidateNotVerified)?;
        let capability = IssuedCapability {
            capability_id: capability_id.clone(),
            requires_enforced,
            requires_complete,
            profile_revision: current.revision,
            fingerprint: current.fingerprint.clone(),
            revoked: false,
        };
        self.capabilities.insert(capability_id, capability.clone());
        Ok(capability)
    }

    /// Authorizes one capability use under the current revision. Fails when
    /// the capability was revoked, its revision/fingerprint binding is stale,
    /// or the current profile no longer authorizes its requirements.
    pub fn authorize(&self, capability_id: &str) -> Result<(), CoverageError> {
        let capability = self
            .capabilities
            .get(capability_id)
            .ok_or_else(|| CoverageError::UnknownCapability(capability_id.to_owned()))?;
        if capability.revoked {
            return Err(CoverageError::CapabilityRevoked(capability_id.to_owned()));
        }
        let current = self
            .current
            .as_ref()
            .ok_or(CoverageError::CandidateNotVerified)?;
        if capability.profile_revision != current.revision
            || capability.fingerprint != current.fingerprint
        {
            return Err(CoverageError::StaleCapabilityBinding(
                capability_id.to_owned(),
            ));
        }
        if !current.authorizes(capability.requires_enforced, capability.requires_complete) {
            return Err(CoverageError::CapabilityNotAuthorized(
                capability_id.to_owned(),
            ));
        }
        Ok(())
    }

    fn revoke_unauthorized(&mut self) {
        let Some(current) = self.current.as_ref() else {
            return;
        };
        for capability in self.capabilities.values_mut() {
            if capability.revoked {
                continue;
            }
            let binding_current = capability.profile_revision == current.revision
                && capability.fingerprint == current.fingerprint;
            if !binding_current
                || !current.authorizes(capability.requires_enforced, capability.requires_complete)
            {
                capability.revoked = true;
            }
        }
    }

    fn revoke_all(&mut self) -> Vec<String> {
        let mut revoked = Vec::new();
        for capability in self.capabilities.values_mut() {
            if !capability.revoked {
                capability.revoked = true;
                revoked.push(capability.capability_id.clone());
            }
        }
        revoked.sort();
        revoked
    }
}

impl Default for GovernorCoverageDerivation {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CoverageError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoverageError::InvalidField(field));
    }
    Ok(())
}
