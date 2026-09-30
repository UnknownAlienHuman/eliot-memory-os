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

use eliot_protocol::{ContinuityKind, HandoffCausalLink, ProtocolError, RehydrationBundle};
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
    /// No evidence carries the required proof ceiling on the exact
    /// fingerprint.
    #[error("capability evidence proof ceiling mismatch")]
    ProofCeilingMismatch,
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
    /// The handoff link names a different source attempt.
    #[error("handoff source attempt does not match the current attempt")]
    HandoffSourceMismatch,
    /// The handoff link names a different target attempt.
    #[error("handoff target attempt does not match the new attempt")]
    HandoffTargetMismatch,
    /// The sealed rehydration bundle digest does not match the handoff link.
    #[error("sealed rehydration bundle digest does not match the handoff link")]
    HandoffBundleDigestMismatch,
    /// A protocol handoff or sealed bundle failed its typed validation.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
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

/// Expiry-scoped capability evidence bound to one exact fingerprint and its
/// explicit fingerprint invalidation dependencies.
///
/// Discovery-only and qualified-probe records are issued shape-checked by
/// [`CapabilityEvidence::new`]. Production-observation records are never
/// issued there: a caller-selected production tier would prove nothing was
/// observed. They are projected only by the checked owner projection
/// [`AttemptRouteOutcome::project_production_observation`], which witnesses a
/// positively observed production attempt and derives the bound receipt by
/// exact readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEvidence {
    fingerprint: String,
    tier: EvidenceTier,
    scope: String,
    proof_ceiling: String,
    expires_unix_ms: u64,
    evidence_links: Vec<String>,
    invalidation_dependencies: Vec<HostFingerprint>,
    invalidated: bool,
    /// True only when projected by the checked owner projection from a
    /// positively observed production attempt. [`CapabilityEvidence::new`]
    /// always leaves this false, so caller-minted records can never satisfy
    /// the production admission path.
    production_observed: bool,
}

impl CapabilityEvidence {
    /// Issues discovery-only or qualified-probe capability evidence,
    /// validating every field fail-closed.
    ///
    /// `EvidenceTier::ProductionObservation` is rejected here: the production
    /// admission path needs a private checked owner projection, not a
    /// caller-selected tier label. Use
    /// [`AttemptRouteOutcome::project_production_observation`].
    pub fn new(
        fingerprint: &HostFingerprint,
        tier: EvidenceTier,
        scope: impl Into<String>,
        proof_ceiling: impl Into<String>,
        expires_unix_ms: u64,
        evidence_links: Vec<String>,
        invalidation_dependencies: Vec<HostFingerprint>,
    ) -> Result<Self, ConformanceError> {
        if tier == EvidenceTier::ProductionObservation {
            return Err(ConformanceError::InvalidInput);
        }
        let evidence = Self {
            fingerprint: fingerprint.canonical(),
            tier,
            scope: scope.into(),
            proof_ceiling: proof_ceiling.into(),
            expires_unix_ms,
            evidence_links,
            invalidation_dependencies,
            invalidated: false,
            production_observed: false,
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
        let mut seen_dependencies = Vec::with_capacity(self.invalidation_dependencies.len());
        for dependency in &self.invalidation_dependencies {
            dependency.validate()?;
            let canonical = dependency.canonical();
            if canonical == self.fingerprint || seen_dependencies.contains(&canonical) {
                return Err(ConformanceError::InvalidInput);
            }
            seen_dependencies.push(canonical);
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

    /// Returns exact host fingerprints whose invalidation also invalidates
    /// this evidence. Its own fingerprint is an implicit dependency.
    #[must_use]
    pub fn invalidation_dependencies(&self) -> &[HostFingerprint] {
        &self.invalidation_dependencies
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
/// fingerprint is always rejected. Verified tool/enforcement claims must
/// additionally match the applicable proof ceiling; see
/// [`admit_coverage_for_claim`].
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
                // A caller-selected production label proves nothing was
                // observed; only the owner projection witnesses production.
                && (tier != EvidenceTier::ProductionObservation || item.production_observed)
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

/// Computes claim-qualified adapter admission coverage on the exact active
/// fingerprint.
///
/// Like [`admit_coverage`], but each qualifying evidence item must also
/// carry exactly the required proof ceiling: evidence issued for one
/// capability ceiling cannot authorize another (I7.22 "confirm the same
/// capability"; I7.16 proof ceiling). Ceiling equality is exact and
/// fail-closed; the docs define no ceiling ordering.
pub fn admit_coverage_for_claim(
    evidence: &[CapabilityEvidence],
    active: &HostFingerprint,
    required_scope: &str,
    required_proof_ceiling: &str,
    now_unix_ms: u64,
    quarantine: &FingerprintQuarantine,
) -> Result<AdmissionCoverage, ConformanceError> {
    active.validate()?;
    if !is_token(required_scope) || !is_token(required_proof_ceiling) {
        return Err(ConformanceError::InvalidInput);
    }
    let active_canonical = active.canonical();
    if quarantine.is_quarantined(&active_canonical) {
        return Err(ConformanceError::Quarantined);
    }
    let live_for_claim = |tier: EvidenceTier| {
        evidence.iter().any(|item| {
            item.tier() == tier
                // A caller-selected production label proves nothing was
                // observed; only the owner projection witnesses production.
                && (tier != EvidenceTier::ProductionObservation || item.production_observed)
                && item.fingerprint() == active_canonical
                && item.scope() == required_scope
                && item.proof_ceiling() == required_proof_ceiling
                && item.is_live(now_unix_ms)
        })
    };
    if live_for_claim(EvidenceTier::ConformanceProbe)
        && live_for_claim(EvidenceTier::ProductionObservation)
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
/// evidence with a specific error. Verified tool/enforcement claims must
/// additionally match the applicable proof ceiling; see
/// [`require_verified_capability_for_claim`].
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
    let active_canonical = active.canonical();
    if quarantine.is_quarantined(&active_canonical) {
        return Err(ConformanceError::Quarantined);
    }
    verified_on_fingerprint(
        evidence,
        &active_canonical,
        required_scope,
        None,
        now_unix_ms,
    )
}

/// Requires verified capability evidence for one exact claim.
///
/// Like [`require_verified_capability`], but each qualifying evidence item
/// must also carry exactly the required proof ceiling: evidence issued for
/// one capability ceiling cannot authorize another (I7.22 "confirm the same
/// capability"; I7.16 proof ceiling). Ceiling equality is exact and
/// fail-closed; the docs define no ceiling ordering.
pub fn require_verified_capability_for_claim(
    evidence: &[CapabilityEvidence],
    active: &HostFingerprint,
    required_scope: &str,
    required_proof_ceiling: &str,
    now_unix_ms: u64,
    quarantine: &FingerprintQuarantine,
) -> Result<(), ConformanceError> {
    active.validate()?;
    if !is_token(required_scope) || !is_token(required_proof_ceiling) {
        return Err(ConformanceError::InvalidInput);
    }
    let active_canonical = active.canonical();
    if quarantine.is_quarantined(&active_canonical) {
        return Err(ConformanceError::Quarantined);
    }
    verified_on_fingerprint(
        evidence,
        &active_canonical,
        required_scope,
        Some(required_proof_ceiling),
        now_unix_ms,
    )
}

/// Runs the exact-fingerprint evidence ladder without consulting quarantine.
///
/// Callers check quarantine first or, for reconciliation release, present
/// revalidation evidence for the quarantined fingerprint itself. With
/// `ceiling` set, each qualifying item must also carry exactly the required
/// proof ceiling.
fn verified_on_fingerprint(
    evidence: &[CapabilityEvidence],
    active_canonical: &str,
    required_scope: &str,
    ceiling: Option<&str>,
    now_unix_ms: u64,
) -> Result<(), ConformanceError> {
    let exact: Vec<&CapabilityEvidence> = evidence
        .iter()
        .filter(|item| item.fingerprint() == active_canonical)
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
    let qualified: Vec<&CapabilityEvidence> = match ceiling {
        None => scoped,
        Some(required) => {
            let matching: Vec<&CapabilityEvidence> = scoped
                .iter()
                .filter(|item| item.proof_ceiling() == required)
                .copied()
                .collect();
            if matching.is_empty() {
                return Err(ConformanceError::ProofCeilingMismatch);
            }
            matching
        }
    };
    let probe = qualified
        .iter()
        .any(|item| item.tier() == EvidenceTier::ConformanceProbe);
    // A caller-selected production label proves nothing was observed; only
    // the owner projection witnesses production (I7.22).
    let observation = qualified
        .iter()
        .any(|item| item.tier() == EvidenceTier::ProductionObservation && item.production_observed);
    if !probe || !observation {
        return Err(ConformanceError::CandidateOnlyWhereVerifiedRequired);
    }
    let live_probe = qualified
        .iter()
        .any(|item| item.tier() == EvidenceTier::ConformanceProbe && item.is_live(now_unix_ms));
    let live_observation = qualified.iter().any(|item| {
        item.tier() == EvidenceTier::ProductionObservation
            && item.production_observed
            && item.is_live(now_unix_ms)
    });
    if live_probe && live_observation {
        return Ok(());
    }
    let qualifying_broken = qualified.iter().any(|item| {
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

/// Requested-versus-actual route finding for one reconciled attempt.
///
/// An unknown actual route is not an observed mismatch: missing telemetry
/// never manufactures a mismatch event (I7.22).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFinding {
    /// Observed route exactly equals the requested route.
    Matched,
    /// No actual route was observed. The result is candidate-only, but
    /// nothing is invalidated or quarantined.
    UnknownRoute,
    /// A positively observed route differs from the requested route.
    ObservedMismatch,
}

/// Outcome of requested-versus-actual route reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRouteOutcome {
    /// True when observed route exactly equals the requested route.
    pub matches: bool,
    /// Requested-versus-actual finding: match, unknown route, or observed
    /// mismatch.
    pub finding: RouteFinding,
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
/// An observed mismatch marks the result candidate-only, invalidates every
/// capability evidence entry bound to or explicitly dependent on the
/// mismatched fingerprint (unrelated evidence stays live), and quarantines
/// the mismatched fingerprint pending reconciliation (unless `disposition`
/// specifies `RejectUse`). An unknown observed route (`None`) marks the
/// result candidate-only without invalidating or quarantining anything:
/// missing telemetry never manufactures a mismatch event, and an unknown
/// route cannot satisfy a verified claim. A match changes nothing.
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
    let finding = match observed_route {
        Some(observed) if observed == requested_route => RouteFinding::Matched,
        Some(_) => RouteFinding::ObservedMismatch,
        None => RouteFinding::UnknownRoute,
    };
    if finding == RouteFinding::Matched {
        return Ok(AttemptRouteOutcome {
            matches: true,
            finding,
            candidate_only: false,
            invalidated_count: 0,
            quarantined: false,
        });
    }
    if finding == RouteFinding::UnknownRoute {
        return Ok(AttemptRouteOutcome {
            matches: false,
            finding,
            candidate_only: true,
            invalidated_count: 0,
            quarantined: false,
        });
    }
    // Only evidence bound to the mismatched fingerprint is dependent on it.
    // Evidence for unrelated fingerprints must survive this reconciliation.
    let mismatched_canonical = mismatched_fingerprint.canonical();
    let mut invalidated_count = 0;
    for item in dependent_evidence.iter_mut() {
        let depends_on_mismatch = item.fingerprint() == mismatched_canonical
            || item
                .invalidation_dependencies()
                .iter()
                .any(|dependency| dependency.canonical() == mismatched_canonical);
        if depends_on_mismatch && !item.is_invalidated() {
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
        finding,
        candidate_only: true,
        invalidated_count,
        quarantined,
    })
}

/// Owner bound on projected production-observation lifetime: one day in
/// milliseconds. Projected evidence additionally never outlives its
/// corroborating probe, so production confirmation stays bounded by both the
/// owner clock and the probe it confirms.
const MAX_PRODUCTION_OBSERVATION_TTL_MS: u64 = 86_400_000;

impl AttemptRouteOutcome {
    /// Projects production-observation evidence from a positively observed
    /// production attempt (I7.22 "confirm the same capability on the exact
    /// active fingerprint").
    ///
    /// This is the sole owner of [`EvidenceTier::ProductionObservation`]:
    /// [`CapabilityEvidence::new`] rejects that tier because a
    /// caller-selected label proves nothing was observed. Only a matched
    /// reconciliation finding — the owner-observed record that the attempt's
    /// actual route equalled its requested route — witnesses production.
    ///
    /// The bound receipt is derived by exact readback, never by copying
    /// caller-selected tier, expiry, or proof strings: the fingerprint comes
    /// from the exact active fingerprint, the scope and proof ceiling from
    /// the live corroborating probe for the same capability, and the expiry
    /// from the owner clock bounded by [`MAX_PRODUCTION_OBSERVATION_TTL_MS`]
    /// and the probe's own expiry. `observed_span` names the observed
    /// production run captured for this attempt.
    pub fn project_production_observation(
        &self,
        probe: &CapabilityEvidence,
        active: &HostFingerprint,
        observed_span: &str,
        now_unix_ms: u64,
    ) -> Result<CapabilityEvidence, ConformanceError> {
        if self.finding != RouteFinding::Matched {
            return Err(ConformanceError::InvalidInput);
        }
        active.validate()?;
        if !is_token(observed_span) {
            return Err(ConformanceError::InvalidInput);
        }
        let active_canonical = active.canonical();
        if probe.tier() != EvidenceTier::ConformanceProbe
            || probe.fingerprint() != active_canonical
            || !probe.is_live(now_unix_ms)
        {
            return Err(ConformanceError::CandidateOnlyWhereVerifiedRequired);
        }
        let owner_bounded = now_unix_ms
            .checked_add(MAX_PRODUCTION_OBSERVATION_TTL_MS)
            .ok_or(ConformanceError::InvalidInput)?;
        let evidence = CapabilityEvidence {
            fingerprint: active_canonical,
            tier: EvidenceTier::ProductionObservation,
            scope: probe.scope().to_owned(),
            proof_ceiling: probe.proof_ceiling().to_owned(),
            expires_unix_ms: owner_bounded.min(probe.expires_unix_ms),
            evidence_links: vec![observed_span.to_owned()],
            invalidation_dependencies: probe.invalidation_dependencies().to_vec(),
            invalidated: false,
            production_observed: true,
        };
        evidence.validate()?;
        Ok(evidence)
    }
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
    ///
    /// Production release must present exact current revalidation evidence
    /// instead; see [`FingerprintQuarantine::reconcile_with_revalidation`].
    pub fn reconcile(&mut self, fingerprint_canonical: &str) -> bool {
        self.entries.remove(fingerprint_canonical).is_some()
    }

    /// Reconciles one fingerprint only against exact current revalidation
    /// evidence: live probe plus production-observation evidence naming the
    /// quarantined fingerprint in scope. Returns true when the entry was
    /// released, false when no entry was present. A failed revalidation
    /// leaves the entry quarantined and reports the exact evidence reason.
    /// Release restores admissibility consideration only; every verified
    /// claim still gates on its own evidence.
    pub fn reconcile_with_revalidation(
        &mut self,
        active: &HostFingerprint,
        revalidation: &[CapabilityEvidence],
        required_scope: &str,
        now_unix_ms: u64,
    ) -> Result<bool, ConformanceError> {
        active.validate()?;
        if !is_token(required_scope) {
            return Err(ConformanceError::InvalidInput);
        }
        let canonical = active.canonical();
        if !self.is_quarantined(&canonical) {
            return Ok(false);
        }
        verified_on_fingerprint(revalidation, &canonical, required_scope, None, now_unix_ms)?;
        self.entries.remove(&canonical);
        Ok(true)
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

/// Shape-only gate enforcing no silent mid-attempt failover.
///
/// Handoff values carried here are not persisted and grant no admission
/// authority; their owning production boundary remains responsible for both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptGate {
    attempt_id: String,
    causal_parent: Option<String>,
    phase: AttemptPhase,
    handoff: Option<HandoffCausalLink>,
    rehydration_bundle: Option<RehydrationBundle>,
}

impl AttemptGate {
    /// Opens a new root attempt.
    pub fn new(attempt_id: impl Into<String>) -> Result<Self, ConformanceError> {
        let gate = Self {
            attempt_id: attempt_id.into(),
            causal_parent: None,
            phase: AttemptPhase::BeforeMeaningfulWork,
            handoff: None,
            rehydration_bundle: None,
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

    /// Returns the shape-validated causal handoff carried by this attempt.
    /// This value does not prove persistence or grant admission authority.
    #[must_use]
    pub const fn handoff(&self) -> Option<&HandoffCausalLink> {
        self.handoff.as_ref()
    }

    /// Returns the sealed rehydration bundle carried by this attempt.
    /// This value does not prove persistence or grant admission authority.
    #[must_use]
    pub const fn rehydration_bundle(&self) -> Option<&RehydrationBundle> {
        self.rehydration_bundle.as_ref()
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
    /// carrying the sealed handoff from this attempt. The handoff is
    /// validated under [`ContinuityKind::Rehydrated`]: this gate only ever
    /// issues a new attempt, never a native resume. Production
    /// substitution must additionally verify target-route admission; see
    /// [`AttemptGate::next_attempt_after_effect_for_admitted_target`].
    /// Persisting the handoff and retaining source effects belong to the
    /// dispatch/durable owners, not this shape gate.
    pub fn next_attempt_after_effect(
        &self,
        new_attempt_id: impl Into<String>,
        handoff: HandoffCausalLink,
        rehydration_bundle: RehydrationBundle,
    ) -> Result<Self, ConformanceError> {
        let id = new_attempt_id.into();
        if !is_token(&id) || id == self.attempt_id {
            return Err(ConformanceError::InvalidInput);
        }
        handoff.validate_for_continuity(ContinuityKind::Rehydrated)?;
        rehydration_bundle.validate()?;
        if handoff.source_attempt_id != self.attempt_id {
            return Err(ConformanceError::HandoffSourceMismatch);
        }
        if handoff.target_attempt_id != id {
            return Err(ConformanceError::HandoffTargetMismatch);
        }
        let bundle_digest = rehydration_bundle.canonical_digest()?;
        let Some(link_digest) = handoff.rehydration_bundle_digest.as_ref() else {
            return Err(ConformanceError::HandoffBundleDigestMismatch);
        };
        if link_digest.as_str() != bundle_digest {
            return Err(ConformanceError::HandoffBundleDigestMismatch);
        }
        Ok(Self {
            attempt_id: id,
            causal_parent: Some(self.attempt_id.clone()),
            phase: AttemptPhase::BeforeMeaningfulWork,
            handoff: Some(handoff),
            rehydration_bundle: Some(rehydration_bundle),
        })
    }

    /// Creates the causally linked new attempt required after the boundary,
    /// additionally requiring verified target-route admission on the exact
    /// target fingerprint before the handoff is accepted. Link, bundle, and
    /// identity checks are unchanged from
    /// [`AttemptGate::next_attempt_after_effect`].
    #[allow(clippy::too_many_arguments)]
    pub fn next_attempt_after_effect_for_admitted_target(
        &self,
        new_attempt_id: impl Into<String>,
        handoff: HandoffCausalLink,
        rehydration_bundle: RehydrationBundle,
        target: &HostFingerprint,
        target_evidence: &[CapabilityEvidence],
        required_scope: &str,
        now_unix_ms: u64,
        quarantine: &FingerprintQuarantine,
    ) -> Result<Self, ConformanceError> {
        require_verified_capability(
            target_evidence,
            target,
            required_scope,
            now_unix_ms,
            quarantine,
        )?;
        self.next_attempt_after_effect(new_attempt_id, handoff, rehydration_bundle)
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
