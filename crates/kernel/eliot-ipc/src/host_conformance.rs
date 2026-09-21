//! I7.22 host fingerprint conformance for adapter/tool admission.
//!
//! Discovery may identify an installation and create a declared candidate
//! profile, but production capability requires bounded conformance-probe
//! evidence plus active production-observation evidence on the exact active
//! fingerprint. Help text, README, model catalog, and handshake booleans
//! never grant production capability by themselves.
//!
//! This module integrates with the [`ServerHandshakePolicy`] /
//! [`HandshakeResult`] / [`ServerFirstConnection`] /
//! [`AcceptedAgentBridgeTransport`] admission foundation: transport admission
//! proves who the peer is, while this module proves what the exact active
//! host/adapter fingerprint can observably do. It invents no clock; every
//! expiry check takes an explicit `now_unix_ms` from the owner.

use std::collections::BTreeMap;

use thiserror::Error;

/// Fail-closed validation failures for fingerprint conformance.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConformanceError {
    /// A required token (fingerprint field, scope, route, reason) is blank,
    /// oversized, or malformed.
    #[error("invalid host conformance input")]
    InvalidInput,
    /// Only candidate-discovery evidence exists where a verified capability
    /// claim is required.
    #[error("candidate-only evidence cannot satisfy a verified capability claim")]
    CandidateOnlyWhereVerifiedRequired,
    /// The only otherwise-qualifying evidence has expired.
    #[error("capability evidence is stale")]
    StaleEvidence,
    /// The only otherwise-qualifying evidence was invalidated (for example by
    /// a route mismatch).
    #[error("capability evidence is broken")]
    BrokenEvidence,
    /// No evidence covers the required scope on the exact fingerprint.
    #[error("capability evidence scope mismatch")]
    ScopeMismatch,
    /// No evidence names the exact active fingerprint.
    #[error("capability evidence fingerprint mismatch")]
    FingerprintMismatch,
    /// The fingerprint is quarantined pending reconciliation.
    #[error("host fingerprint is quarantined pending reconciliation")]
    Quarantined,
    /// Retry/substitution was attempted after meaningful provider output,
    /// tool use, or external effect without a causally linked new attempt.
    #[error("silent mid-attempt failover is denied after meaningful effect")]
    SilentFailoverDenied,
}

/// Canonical host/adapter identity from installation discovery.
///
/// Binds the installation record, the executable/package hash, the host and
/// adapter versions, and the applicable route identity into one exact string.
/// Production capability evidence must name this exact value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostFingerprint {
    installation_id: String,
    executable_sha256: String,
    package_sha256: Option<String>,
    host_version: String,
    adapter_version: String,
    route_id: String,
}

impl HostFingerprint {
    /// Builds a fingerprint, validating every field fail-closed.
    pub fn new(
        installation_id: impl Into<String>,
        executable_sha256: impl Into<String>,
        package_sha256: Option<String>,
        host_version: impl Into<String>,
        adapter_version: impl Into<String>,
        route_id: impl Into<String>,
    ) -> Result<Self, ConformanceError> {
        let fingerprint = Self {
            installation_id: installation_id.into(),
            executable_sha256: executable_sha256.into(),
            package_sha256,
            host_version: host_version.into(),
            adapter_version: adapter_version.into(),
            route_id: route_id.into(),
        };
        fingerprint.validate()?;
        Ok(fingerprint)
    }

    fn validate(&self) -> Result<(), ConformanceError> {
        // Fingerprint fields are joined with `/` by `canonical`, so a `/`
        // inside a field would let two distinct field tuples project to one
        // canonical string and share each other's evidence. Reject it.
        if !is_canonical_field(&self.installation_id)
            || !is_sha256(&self.executable_sha256)
            || !is_canonical_field(&self.host_version)
            || !is_canonical_field(&self.adapter_version)
            || !is_canonical_field(&self.route_id)
        {
            return Err(ConformanceError::InvalidInput);
        }
        if let Some(package) = &self.package_sha256
            && !is_sha256(package)
        {
            return Err(ConformanceError::InvalidInput);
        }
        Ok(())
    }

    /// Returns the exact canonical string that capability evidence must name.
    #[must_use]
    pub fn canonical(&self) -> String {
        let package = self.package_sha256.as_deref().unwrap_or("-");
        format!(
            "{}/{}/{}/{}/{}/{}",
            self.installation_id,
            self.executable_sha256,
            package,
            self.host_version,
            self.adapter_version,
            self.route_id
        )
    }
}

/// Separation of discovery, probe, and production evidence (I7.22).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceTier {
    /// Declared candidate profile from installation discovery only.
    CandidateDiscovery,
    /// Bounded conformance-probe evidence with captured raw events/effects.
    ConformanceProbe,
    /// Production observation confirming the capability on the exact active
    /// fingerprint.
    ProductionObservation,
}

/// Expiry-scoped capability evidence bound to one exact fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEvidence {
    fingerprint: String,
    tier: EvidenceTier,
    scope: String,
    proof_ceiling: String,
    expires_unix_ms: u64,
    evidence_links: Vec<String>,
    invalidated: bool,
}

impl CapabilityEvidence {
    /// Issues capability evidence, validating every field fail-closed.
    pub fn new(
        fingerprint: &HostFingerprint,
        tier: EvidenceTier,
        scope: impl Into<String>,
        proof_ceiling: impl Into<String>,
        expires_unix_ms: u64,
        evidence_links: Vec<String>,
    ) -> Result<Self, ConformanceError> {
        let evidence = Self {
            fingerprint: fingerprint.canonical(),
            tier,
            scope: scope.into(),
            proof_ceiling: proof_ceiling.into(),
            expires_unix_ms,
            evidence_links,
            invalidated: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), ConformanceError> {
        if !is_token(&self.fingerprint)
            || !is_token(&self.scope)
            || !is_token(&self.proof_ceiling)
            || self.expires_unix_ms == 0
            || self.evidence_links.is_empty()
            || self.evidence_links.len() > 16
        {
            return Err(ConformanceError::InvalidInput);
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.evidence_links.len());
        for link in &self.evidence_links {
            if !is_token(link) || seen.contains(&link.as_str()) {
                return Err(ConformanceError::InvalidInput);
            }
            seen.push(link.as_str());
        }
        Ok(())
    }

    /// Returns the exact fingerprint this evidence was issued for.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the evidence tier.
    #[must_use]
    pub const fn tier(&self) -> EvidenceTier {
        self.tier
    }

    /// Returns the applicable scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the proof ceiling recorded at issuance.
    #[must_use]
    pub fn proof_ceiling(&self) -> &str {
        &self.proof_ceiling
    }

    /// Returns the evidence links recorded at issuance.
    #[must_use]
    pub fn evidence_links(&self) -> &[String] {
        &self.evidence_links
    }

    /// Returns true once this evidence has been invalidated.
    #[must_use]
    pub const fn is_invalidated(&self) -> bool {
        self.invalidated
    }

    /// Returns true when the evidence is neither invalidated nor expired.
    #[must_use]
    pub const fn is_live(&self, now_unix_ms: u64) -> bool {
        !self.invalidated && self.expires_unix_ms > now_unix_ms
    }

    /// Permanently invalidates this evidence (for example after a route
    /// mismatch on its fingerprint).
    pub fn invalidate(&mut self) {
        self.invalidated = true;
    }
}

/// Admission coverage for one adapter on one active fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCoverage {
    /// Discovered from metadata but lacking probe and active-fingerprint
    /// observation. Must never satisfy a verified tool/enforcement claim.
    CandidateOnly,
    /// Bounded probe plus active production observation on the exact
    /// fingerprint, in scope, live, and unquarantined.
    Verified,
}

/// Computes adapter admission coverage on the exact active fingerprint.
///
/// Verified coverage requires both live, scope-matching
/// [`EvidenceTier::ConformanceProbe`] evidence and live, scope-matching
/// [`EvidenceTier::ProductionObservation`] evidence naming the exact active
/// fingerprint. Anything less is candidate coverage. A quarantined
/// fingerprint is always rejected.
pub fn admit_coverage(
    evidence: &[CapabilityEvidence],
    active: &HostFingerprint,
    required_scope: &str,
    now_unix_ms: u64,
    quarantine: &FingerprintQuarantine,
) -> Result<AdmissionCoverage, ConformanceError> {
    active.validate()?;
    if !is_token(required_scope) {
        return Err(ConformanceError::InvalidInput);
    }
    if quarantine.is_quarantined(&active.canonical()) {
        return Err(ConformanceError::Quarantined);
    }
    let live_for_scope = |tier: EvidenceTier| {
        evidence.iter().any(|item| {
            item.tier() == tier
                && item.fingerprint() == active.canonical()
                && item.scope() == required_scope
                && item.is_live(now_unix_ms)
        })
    };
    if live_for_scope(EvidenceTier::ConformanceProbe)
        && live_for_scope(EvidenceTier::ProductionObservation)
    {
        Ok(AdmissionCoverage::Verified)
    } else {
        Ok(AdmissionCoverage::CandidateOnly)
    }
}

/// Requires verified capability evidence for a tool/enforcement claim.
///
/// Accepts only live, scope-matching probe plus production-observation
/// evidence on the exact active fingerprint. Rejects stale, broken,
/// scope-mismatched, fingerprint-mismatched, quarantined, or candidate-only
/// evidence with a specific error.
pub fn require_verified_capability(
    evidence: &[CapabilityEvidence],
    active: &HostFingerprint,
    required_scope: &str,
    now_unix_ms: u64,
    quarantine: &FingerprintQuarantine,
) -> Result<(), ConformanceError> {
    active.validate()?;
    if !is_token(required_scope) {
        return Err(ConformanceError::InvalidInput);
    }
    if quarantine.is_quarantined(&active.canonical()) {
        return Err(ConformanceError::Quarantined);
    }
    let exact: Vec<&CapabilityEvidence> = evidence
        .iter()
        .filter(|item| item.fingerprint() == active.canonical())
        .collect();
    if exact.is_empty() {
        return Err(ConformanceError::FingerprintMismatch);
    }
    let scoped: Vec<&CapabilityEvidence> = exact
        .iter()
        .filter(|item| item.scope() == required_scope)
        .copied()
        .collect();
    if scoped.is_empty() {
        return Err(ConformanceError::ScopeMismatch);
    }
    let probe = scoped
        .iter()
        .any(|item| item.tier() == EvidenceTier::ConformanceProbe);
    let observation = scoped
        .iter()
        .any(|item| item.tier() == EvidenceTier::ProductionObservation);
    if !probe || !observation {
        return Err(ConformanceError::CandidateOnlyWhereVerifiedRequired);
    }
    let live_probe = scoped
        .iter()
        .any(|item| item.tier() == EvidenceTier::ConformanceProbe && item.is_live(now_unix_ms));
    let live_observation = scoped.iter().any(|item| {
        item.tier() == EvidenceTier::ProductionObservation && item.is_live(now_unix_ms)
    });
    if live_probe && live_observation {
        return Ok(());
    }
    let qualifying_broken = scoped.iter().any(|item| {
        (item.tier() == EvidenceTier::ConformanceProbe
            || item.tier() == EvidenceTier::ProductionObservation)
            && item.is_invalidated()
    });
    if qualifying_broken {
        return Err(ConformanceError::BrokenEvidence);
    }
    Err(ConformanceError::StaleEvidence)
}

/// Safe disposition for a route-mismatched fingerprint.
///
/// Quarantine is the default: the fingerprint stays rejected until
/// reconciliation. `RejectUse` skips the quarantine entry (for example when
/// policy owns a different safe disposition) while still marking the attempt
/// candidate-only and invalidating dependent evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteMismatchDisposition {
    Quarantine,
    RejectUse,
}

/// Outcome of requested-versus-actual route reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRouteOutcome {
    /// True when observed route exactly equals the requested route.
    pub matches: bool,
    /// A mismatched attempt is candidate-only and can never satisfy a
    /// verified claim.
    pub candidate_only: bool,
    /// Dependent capability evidence invalidated by this reconciliation.
    pub invalidated_count: usize,
    /// True when the fingerprint was quarantined by this reconciliation.
    pub quarantined: bool,
}

/// Reconciles one completed attempt's observed route against its requested
/// route.
///
/// A mismatch marks the result candidate-only, invalidates every dependent
/// capability evidence entry bound to the mismatched fingerprint (evidence
/// for unrelated fingerprints is left live), and quarantines the mismatched
/// fingerprint pending reconciliation (unless `disposition` specifies
/// `RejectUse`). An unknown observed route (`None`) fails closed as a
/// mismatch. A match changes nothing.
pub fn reconcile_attempt_route(
    requested_route: &str,
    observed_route: Option<&str>,
    dependent_evidence: &mut [CapabilityEvidence],
    quarantine: &mut FingerprintQuarantine,
    mismatched_fingerprint: &HostFingerprint,
    disposition: RouteMismatchDisposition,
) -> Result<AttemptRouteOutcome, ConformanceError> {
    if !is_token(requested_route) {
        return Err(ConformanceError::InvalidInput);
    }
    mismatched_fingerprint.validate()?;
    let matches = observed_route == Some(requested_route);
    if matches {
        return Ok(AttemptRouteOutcome {
            matches: true,
            candidate_only: false,
            invalidated_count: 0,
            quarantined: false,
        });
    }
    // Only evidence bound to the mismatched fingerprint is dependent on it.
    // Evidence for unrelated fingerprints must survive this reconciliation.
    let mismatched_canonical = mismatched_fingerprint.canonical();
    let mut invalidated_count = 0;
    for item in dependent_evidence.iter_mut() {
        if item.fingerprint() == mismatched_canonical && !item.is_invalidated() {
            item.invalidate();
            invalidated_count += 1;
        }
    }
    let quarantined = if disposition == RouteMismatchDisposition::Quarantine {
        quarantine.quarantine(
            &mismatched_fingerprint.canonical(),
            "observed route differs from requested route",
        )?;
        true
    } else {
        false
    };
    Ok(AttemptRouteOutcome {
        matches: false,
        candidate_only: true,
        invalidated_count,
        quarantined,
    })
}

/// Quarantine registry for route-mismatched fingerprints.
///
/// A quarantined fingerprint is rejected by [`admit_coverage`] and
/// [`require_verified_capability`] until the owner reconciles it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FingerprintQuarantine {
    entries: BTreeMap<String, String>,
}

impl FingerprintQuarantine {
    /// Creates an empty quarantine registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Quarantines one exact canonical fingerprint with a reason.
    pub fn quarantine(
        &mut self,
        fingerprint_canonical: &str,
        reason: &str,
    ) -> Result<(), ConformanceError> {
        if !is_token(fingerprint_canonical) || !is_token(reason) {
            return Err(ConformanceError::InvalidInput);
        }
        if self.entries.len() >= 1024 && !self.entries.contains_key(fingerprint_canonical) {
            return Err(ConformanceError::InvalidInput);
        }
        self.entries
            .insert(fingerprint_canonical.to_owned(), reason.to_owned());
        Ok(())
    }

    /// Returns true while the exact fingerprint is quarantined.
    #[must_use]
    pub fn is_quarantined(&self, fingerprint_canonical: &str) -> bool {
        self.entries.contains_key(fingerprint_canonical)
    }

    /// Reconciles one fingerprint, clearing its quarantine entry.
    /// Returns true when an entry was present.
    pub fn reconcile(&mut self, fingerprint_canonical: &str) -> bool {
        self.entries.remove(fingerprint_canonical).is_some()
    }

    /// Returns the number of quarantined fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no fingerprint is quarantined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Logical attempt phase for the no-silent-failover boundary (I7.22).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptPhase {
    /// No meaningful provider output, tool use, or external effect yet:
    /// route retry/substitution may stay under the same logical request.
    BeforeMeaningfulWork,
    /// The boundary was crossed: substitution must create a causally linked
    /// new attempt with sealed handoff.
    AfterMeaningfulEffect,
}

/// Gate enforcing no silent mid-attempt failover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptGate {
    attempt_id: String,
    causal_parent: Option<String>,
    phase: AttemptPhase,
}

impl AttemptGate {
    /// Opens a new root attempt.
    pub fn new(attempt_id: impl Into<String>) -> Result<Self, ConformanceError> {
        let gate = Self {
            attempt_id: attempt_id.into(),
            causal_parent: None,
            phase: AttemptPhase::BeforeMeaningfulWork,
        };
        if !is_token(&gate.attempt_id) {
            return Err(ConformanceError::InvalidInput);
        }
        Ok(gate)
    }

    /// Returns the attempt identity.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Returns the causal parent for attempts created after the boundary.
    #[must_use]
    pub const fn causal_parent(&self) -> Option<&String> {
        self.causal_parent.as_ref()
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> AttemptPhase {
        self.phase
    }

    /// Records meaningful provider output, crossing the failover boundary.
    pub fn record_meaningful_output(&mut self) {
        self.phase = AttemptPhase::AfterMeaningfulEffect;
    }

    /// Records tool use, crossing the failover boundary.
    pub fn record_tool_use(&mut self) {
        self.phase = AttemptPhase::AfterMeaningfulEffect;
    }

    /// Records an external effect, crossing the failover boundary.
    pub fn record_external_effect(&mut self) {
        self.phase = AttemptPhase::AfterMeaningfulEffect;
    }

    /// Returns true only before meaningful output, tool use, or effect.
    #[must_use]
    pub const fn retry_or_substitute_allowed(&self) -> bool {
        matches!(self.phase, AttemptPhase::BeforeMeaningfulWork)
    }

    /// Retries or substitutes the route under the same logical request.
    /// Denied after the boundary; use [`AttemptGate::next_attempt_after_effect`].
    pub fn retry_or_substitute(&self) -> Result<(), ConformanceError> {
        if self.retry_or_substitute_allowed() {
            Ok(())
        } else {
            Err(ConformanceError::SilentFailoverDenied)
        }
    }

    /// Creates the causally linked new attempt required after the boundary,
    /// carrying the sealed handoff from this attempt.
    pub fn next_attempt_after_effect(
        &self,
        new_attempt_id: impl Into<String>,
    ) -> Result<Self, ConformanceError> {
        let id = new_attempt_id.into();
        if !is_token(&id) || id == self.attempt_id {
            return Err(ConformanceError::InvalidInput);
        }
        Ok(Self {
            attempt_id: id,
            causal_parent: Some(self.attempt_id.clone()),
            phase: AttemptPhase::BeforeMeaningfulWork,
        })
    }
}

fn is_token(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

/// Validates one `HostFingerprint` field: a token that additionally carries
/// no `/`, keeping [`HostFingerprint::canonical`] an unambiguous projection
/// of the exact field tuple.
fn is_canonical_field(value: &str) -> bool {
    is_token(value) && !value.contains('/')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
