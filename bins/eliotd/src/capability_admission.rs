//! Governor-side production capability-evidence admission gate (issue #1959, I3.4).
//!
//! Architecture: I3.4 (Capability and Route Registry); A2.3 (contract → ports →
//! adapters layering); A0.3 hard boundaries stay fail-closed. This cell is the
//! Governor application evaluation owned by `eliotd`: it decides production
//! admission from already-threaded evidence, never from build success,
//! installed configuration, PID, port, or a generic health result — none of
//! those are inputs here by construction, so none can satisfy this gate.
//!
//! A requested operation is admissible only when its exact route and capability
//! fingerprint carries non-stale `probe_passed` or `observed` evidence:
//!
//! - route identity is whole-value [`RouteFingerprint`] equality (I3.4 route
//!   fingerprint); a changed runtime/adapter/serializer/tool/feature dependency
//!   changes the fingerprint, matches no evidence scope, and blocks —
//!   capability is route-specific and is never generalized silently;
//! - evidence freshness is `observed_at_unix_ms <= now_unix_ms <
//!   expires_at_unix_ms` at the exact requested generation; expiry or a
//!   generation change defers until requalified, it never serves the previous
//!   generation as current;
//! - critical capabilities additionally require both a matching
//!   [`StaticCapabilityAttestation`] (artifact/config/protocol/dependency
//!   identity with a clean invalidation set) and a fresh
//!   [`DynamicCapabilityPulse`] tied to the exact generation — static
//!   compatibility without a live pulse is not current readiness, and a live
//!   pulse without exact artifact identity is not semantic capability.
//!
//! Non-admission is an explicit [`AdmissionDisposition`]: absent evidence
//! blocks, stale evidence defers, ambiguous evidence requires authority,
//! degraded evidence caps at observe-only, and fresh broken/unsupported
//! evidence blocks. Stale broken/unsupported records are superseded by
//! requalification instead of vetoing it. `broken`/`unsupported` on the exact
//! fingerprint overrides declared proof, per I3.4.
//!
//! Delegation boundary (delegate, never copy):
//!
//! - evidence collection (handshake/probe/pulse observation) and durable
//!   evidence reads (`GetCapabilityEvidenceState`) stay with their owners; the
//!   caller threads already-observed records per call, so a refresh surfaces
//!   as an exact mismatch instead of silent divergence;
//! - quarantine, recovery, and requalification directives stay with their
//!   owners; this cell only names the disposition, it never executes recovery.
//!
//! Like the neighboring admission joins, this helper never mints admission: it
//! evaluates presented evidence and returns a disposition.

use std::collections::BTreeSet;

use eliot_agent_api::AttemptId;
use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{HumanModelPreferencePolicy, ModelRole};

use crate::route_receipts::{
    GovernorRouteAttempt, RouteAdmissionVisibility, RouteReceiptError, RuntimeObservedFacts,
};

/// Canonical required capability set for one model invoke (R2, I1.11 step 9).
///
/// Union of the Task Controller launch intent (`required_competence`,
/// owner-enforced non-empty by the coordinator plan) and the explicit Human
/// Dreamer-role preference (`required_capabilities`, owner-validated text),
/// sorted for determinism. Both inputs arrive owner-shaped and
/// caller-threaded per call; this function unites them without defaulting,
/// inferring, or narrowing: an empty union — or any blank or
/// control-bearing name, which would otherwise narrow the set and widen
/// admission — fails closed as `None`, never an empty admit.
#[must_use]
pub fn canonical_required_set(
    launch_competence: &[String],
    policy: &HumanModelPreferencePolicy,
) -> Option<Vec<String>> {
    let mut required = BTreeSet::new();
    for item in launch_competence {
        required.insert(item.clone());
    }
    for preference in policy
        .roles
        .iter()
        .filter(|preference| preference.role == ModelRole::Dreamer)
    {
        for capability in &preference.required_capabilities {
            required.insert(capability.clone());
        }
    }
    if required.is_empty() {
        return None;
    }
    for name in &required {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return None;
        }
    }
    Some(required.into_iter().collect())
}

/// Capability evidence standing, mirroring the I3.4
/// `CapabilityEvidenceRecord.status` vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityEvidenceStatus {
    /// Configured intent or legacy import; never runtime proof.
    Declared,
    /// A live probe succeeded against the exact fingerprint.
    ProbePassed,
    /// Production behavior was observed against the exact fingerprint.
    Observed,
    /// Partially working; material work is not proven.
    Degraded,
    /// Reproduced failure on the exact fingerprint; overrides declared proof.
    Broken,
    /// Proven incapable on the exact fingerprint; overrides declared proof.
    Unsupported,
    /// No standing either way; never proof.
    Unknown,
}

/// One capability evidence record over an exact route and generation.
///
/// The durable registry owns collection and storage; this shape is the
/// already-observed value the caller threads per admission call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityEvidenceRecord {
    /// Capability under evaluation (non-blank, no control characters).
    pub capability: String,
    /// Exact route fingerprint the evidence was taken against.
    pub route: RouteFingerprint,
    /// Exact generation the evidence was taken against.
    pub generation: u64,
    /// Evidence standing at observation time.
    pub status: CapabilityEvidenceStatus,
    /// Unix-millisecond observation time.
    pub observed_at_unix_ms: u64,
    /// Unix-millisecond time after which the record is stale.
    pub expires_at_unix_ms: u64,
}

/// Expensive identity/compatibility evidence for a critical capability.
///
/// Carries artifact/config/protocol/dependency identity plus the invalidation
/// set outcome: `invalidated` means a dependency in the set changed and the
/// attestation no longer binds, even if every other field still matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticCapabilityAttestation {
    /// Capability under evaluation (non-blank, no control characters).
    pub capability: String,
    /// Exact route fingerprint the attestation was taken against.
    pub route: RouteFingerprint,
    /// True when the invalidation set tripped (dependency rotated).
    pub invalidated: bool,
}

/// Current liveness/readiness/capacity evidence for a critical capability.
///
/// Binds the exact generation: a pulse observed at another generation says
/// nothing about the requested one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicCapabilityPulse {
    /// Capability under evaluation (non-blank, no control characters).
    pub capability: String,
    /// Exact route fingerprint the pulse was taken against.
    pub route: RouteFingerprint,
    /// Exact generation the pulse was observed at.
    pub generation: u64,
    /// Unix-millisecond observation time.
    pub observed_at_unix_ms: u64,
    /// Unix-millisecond time after which the pulse is no longer fresh.
    pub fresh_until_unix_ms: u64,
    /// Current liveness/readiness/capacity holds.
    pub live: bool,
    /// Observed degradation caps the route at observe-only.
    pub degraded: bool,
}

/// One production admission request for a single capability on one route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionAdmissionRequest {
    /// Capability requested (non-blank, no control characters).
    pub capability: String,
    /// Exact requested route fingerprint.
    pub route: RouteFingerprint,
    /// Exact generation admission is requested at.
    pub generation: u64,
    /// Unix-millisecond observation time the evidence is checked against.
    pub now_unix_ms: u64,
    /// True when the capability is critical (static + pulse both required).
    pub critical: bool,
}

/// Explicit production admission disposition, mirroring the I3.4
/// `OperationDisposition.decision` vocabulary plus `Defer` for stale evidence
/// that requalification can restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    /// Matching fresh `probe_passed` or `observed` evidence (plus static and
    /// pulse for critical capabilities): production work may proceed.
    Admit,
    /// Evidence exists but is stale (expired, generation drift); requalify
    /// the exact fingerprint, then ask again.
    Defer,
    /// The route is unavailable but a qualified alternate may exist; the
    /// caller must select it explicitly, never silently.
    Alternate,
    /// Read-only status only; material work is not proven.
    ObserveOnly,
    /// Intent exists but no runtime proof; an authority decision (probe,
    /// challenge, or grant) must qualify the route first.
    RequireAuthority,
    /// No usable evidence, or the exact fingerprint is proven broken or
    /// unsupported: production work must not proceed.
    Block,
}

/// Bounded admission outcome: the disposition plus a static diagnostic reason.
///
/// Reasons are `&'static str` so the gate stays allocation-free and
/// deterministic; the reason names the failed join, never a dynamic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionOutcome {
    /// The admission disposition for the requested operation.
    pub disposition: AdmissionDisposition,
    /// Static reason naming the deciding join.
    pub reason: &'static str,
}

impl AdmissionOutcome {
    /// Builds an outcome from a disposition and its static reason.
    #[must_use]
    pub const fn new(disposition: AdmissionDisposition, reason: &'static str) -> Self {
        Self {
            disposition,
            reason,
        }
    }

    /// Returns true only for production admission.
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self.disposition, AdmissionDisposition::Admit)
    }
}

/// Evaluates one production admission request against threaded evidence.
///
/// Order is load-bearing: malformed requests block first, then absent scope
/// evidence blocks, then fresh `broken`/`unsupported` on the exact fingerprint
/// blocks (overriding declared proof), then fresh `probe_passed`/`observed`
/// evidence admits toward the critical join, then conflicting fresh evidence
/// requires authority, then fresh `degraded` caps at observe-only, then stale
/// evidence defers, and declared/unknown intent alone requires authority.
/// Critical capabilities additionally require both a bound static attestation
/// and a fresh live pulse at the exact generation; neither alone suffices.
///
/// Build success, installed configuration, PID, port, and generic health are
/// not parameters, so they cannot satisfy this gate by construction.
#[must_use]
pub fn evaluate_production_admission(
    request: &ProductionAdmissionRequest,
    evidence: &[CapabilityEvidenceRecord],
    static_attestation: Option<&StaticCapabilityAttestation>,
    pulse: Option<&DynamicCapabilityPulse>,
) -> AdmissionOutcome {
    if !is_capability_name(&request.capability) || request.route.validate().is_err() {
        return AdmissionOutcome::new(
            AdmissionDisposition::Block,
            "production admission request identity is malformed",
        );
    }
    let scope = match_scope(request, evidence);
    if scope.is_empty() {
        return AdmissionOutcome::new(
            AdmissionDisposition::Block,
            "no capability evidence for the exact route",
        );
    }
    let base = check_scope(request, &scope);
    if base.disposition != AdmissionDisposition::Admit || !request.critical {
        return base;
    }
    check_critical(request, static_attestation, pulse)
}

/// Evidence bundle threaded per admission call.
///
/// Durable reads stay with their owners; the caller threads already-observed
/// records, one static attestation, and one pulse per call, so a refresh
/// surfaces as an exact mismatch instead of silent divergence.
#[derive(Clone, Debug)]
pub struct ProductionEvidenceBundle<'a> {
    /// Capability evidence records observed for the requested route.
    pub records: &'a [CapabilityEvidenceRecord],
    /// Static attestation bound to the exact fingerprint, if any.
    pub static_attestation: Option<&'a StaticCapabilityAttestation>,
    /// Dynamic pulse observed at the requested generation, if any.
    pub pulse: Option<&'a DynamicCapabilityPulse>,
}

/// Production route admission decision: the funnel outcome plus the Governor
/// attempt receipt recording requested versus observed routing.
///
/// The receipt is minted for admitted and denied attempts alike so blocked
/// production work stays visible exactly where it happened. Visibility never
/// implies admission: only [`AdmissionOutcome::admitted`] admits.
#[derive(Clone, Debug)]
pub struct RouteAdmissionDecision {
    /// The funnel disposition for the requested operation.
    pub outcome: AdmissionOutcome,
    /// Attempt receipt binding the requested route to the observed route.
    pub attempt: GovernorRouteAttempt,
}

/// Admits one production route and records its attempt receipt.
///
/// Composition entry point over the proven funnel and receipt flow: evaluates
/// [`evaluate_production_admission`] from threaded evidence, then records
/// [`RouteAdmissionVisibility::observe`] plus [`GovernorRouteAttempt::new`] for the
/// same requested route. Malformed routes, observed facts, or attempt linkage
/// fail closed with [`RouteReceiptError`] before any admission decision is
/// produced.
///
/// # Errors
///
/// Returns [`RouteReceiptError`] when the requested route, the observed
/// facts, or the attempt linkage is malformed.
pub fn admit_production_route(
    request: &ProductionAdmissionRequest,
    evidence: &ProductionEvidenceBundle<'_>,
    attempt_id: AttemptId,
    observed_facts: &RuntimeObservedFacts,
) -> Result<RouteAdmissionDecision, RouteReceiptError> {
    let receipt = RouteAdmissionVisibility::observe(request.route.clone(), observed_facts)?;
    let attempt = GovernorRouteAttempt::new(attempt_id, request.route.clone(), receipt)?;
    let outcome = evaluate_production_admission(
        request,
        evidence.records,
        evidence.static_attestation,
        evidence.pulse,
    );
    Ok(RouteAdmissionDecision { outcome, attempt })
}

/// Collects the evidence records scoped to the exact requested capability and
/// route fingerprint. Records for other capabilities or routes never qualify
/// and are never generalized across.
fn match_scope<'a>(
    request: &ProductionAdmissionRequest,
    evidence: &'a [CapabilityEvidenceRecord],
) -> Vec<&'a CapabilityEvidenceRecord> {
    evidence
        .iter()
        .filter(|record| record.capability == request.capability && record.route == request.route)
        .collect()
}

/// Returns true for a record that is fresh at the requested generation and
/// time: observed no later than now and not yet expired.
fn is_fresh_at(record: &CapabilityEvidenceRecord, request: &ProductionAdmissionRequest) -> bool {
    record.generation == request.generation
        && record.observed_at_unix_ms <= request.now_unix_ms
        && request.now_unix_ms < record.expires_at_unix_ms
}

/// Evaluates the evidence scope short of the critical join.
///
/// Fresh `broken`/`unsupported` on the exact fingerprint blocks first
/// (overriding declared proof); stale broken/unsupported records are
/// superseded fall-through for requalification, never a permanent veto.
/// Fresh `probe_passed`/`observed` evidence admits toward the critical join;
/// conflicting fresh evidence requires authority; fresh `degraded` caps at
/// observe-only; otherwise stale runtime evidence defers and declared/unknown
/// intent alone requires authority.
fn check_scope(
    request: &ProductionAdmissionRequest,
    scope: &[&CapabilityEvidenceRecord],
) -> AdmissionOutcome {
    if scope.iter().any(|record| {
        matches!(
            record.status,
            CapabilityEvidenceStatus::Broken | CapabilityEvidenceStatus::Unsupported
        ) && is_fresh_at(record, request)
    }) {
        return AdmissionOutcome::new(
            AdmissionDisposition::Block,
            "broken or unsupported evidence on the exact fingerprint overrides declared proof",
        );
    }
    let fresh_qualifying = scope.iter().any(|record| {
        matches!(
            record.status,
            CapabilityEvidenceStatus::ProbePassed | CapabilityEvidenceStatus::Observed
        ) && is_fresh_at(record, request)
    });
    let fresh_degraded = scope.iter().any(|record| {
        matches!(record.status, CapabilityEvidenceStatus::Degraded) && is_fresh_at(record, request)
    });
    if fresh_qualifying && fresh_degraded {
        return AdmissionOutcome::new(
            AdmissionDisposition::RequireAuthority,
            "conflicting fresh evidence on the exact fingerprint needs an authority decision",
        );
    }
    if !fresh_qualifying {
        return stale_or_declared(scope, fresh_degraded);
    }
    AdmissionOutcome::new(
        AdmissionDisposition::Admit,
        "matching fresh probe or observation evidence admits the exact route",
    )
}

/// Dispositions the scope when no fresh qualifying evidence exists: fresh
/// degradation caps at observe-only, stale runtime evidence defers until
/// requalified, and declared/unknown intent alone requires authority.
fn stale_or_declared(
    scope: &[&CapabilityEvidenceRecord],
    fresh_degraded: bool,
) -> AdmissionOutcome {
    if fresh_degraded {
        return AdmissionOutcome::new(
            AdmissionDisposition::ObserveOnly,
            "degraded evidence caps the exact fingerprint at observe-only",
        );
    }
    if scope.iter().any(|record| {
        matches!(
            record.status,
            CapabilityEvidenceStatus::ProbePassed
                | CapabilityEvidenceStatus::Observed
                | CapabilityEvidenceStatus::Degraded
        )
    }) {
        return AdmissionOutcome::new(
            AdmissionDisposition::Defer,
            "capability evidence for the exact route is stale at this generation and time",
        );
    }
    AdmissionOutcome::new(
        AdmissionDisposition::RequireAuthority,
        "declared intent alone is not runtime proof for production admission",
    )
}
/// Evaluates the critical-capability join after fresh qualifying evidence.
///
/// Requires both a bound [`StaticCapabilityAttestation`] (exact fingerprint,
/// clean invalidation set) and a fresh live [`DynamicCapabilityPulse`] tied to
/// the exact generation; neither alone suffices. A missing or tripped static
/// attestation requires authority, while a missing, stale, non-live, or
/// degraded pulse defers (or caps at observe-only) until requalified.
fn check_critical(
    request: &ProductionAdmissionRequest,
    static_attestation: Option<&StaticCapabilityAttestation>,
    pulse: Option<&DynamicCapabilityPulse>,
) -> AdmissionOutcome {
    let bound_static = static_attestation.is_some_and(|attestation| {
        attestation.capability == request.capability
            && attestation.route == request.route
            && !attestation.invalidated
    });
    if !bound_static {
        return AdmissionOutcome::new(
            AdmissionDisposition::RequireAuthority,
            "critical capability lacks a bound static attestation for the exact fingerprint",
        );
    }
    let Some(seen) =
        pulse.filter(|seen| seen.capability == request.capability && seen.route == request.route)
    else {
        return AdmissionOutcome::new(
            AdmissionDisposition::Defer,
            "critical capability lacks a dynamic pulse for the exact route",
        );
    };
    if seen.generation != request.generation
        || seen.observed_at_unix_ms > request.now_unix_ms
        || request.now_unix_ms >= seen.fresh_until_unix_ms
    {
        return AdmissionOutcome::new(
            AdmissionDisposition::Defer,
            "critical capability pulse is stale at this generation and time",
        );
    }
    if seen.degraded {
        return AdmissionOutcome::new(
            AdmissionDisposition::ObserveOnly,
            "critical capability pulse reports degradation",
        );
    }
    if !seen.live {
        return AdmissionOutcome::new(
            AdmissionDisposition::Defer,
            "critical capability pulse does not report liveness",
        );
    }
    AdmissionOutcome::new(
        AdmissionDisposition::Admit,
        "bound static attestation plus a fresh live pulse admit the critical capability",
    )
}

/// Returns true for a bounded non-blank capability name.
fn is_capability_name(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_agent_api::LowercaseSha256;
    use eliot_contracts::sha256_hex;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const TEST_NOW: u64 = 1_000_000;
    const TEST_GENERATION: u64 = 7;

    fn test_digest(seed: &str) -> TestResult<LowercaseSha256> {
        serde_json::from_value(serde_json::json!(sha256_hex(seed.as_bytes()))).map_err(Into::into)
    }

    fn test_route() -> TestResult<RouteFingerprint> {
        Ok(RouteFingerprint {
            host_family: "test-host".to_owned(),
            adapter: "adapter-a".to_owned(),
            protocol_transport: "fixture".to_owned(),
            runtime_hash: test_digest("go59-runtime")?,
            adapter_hash: test_digest("go59-adapter")?,
            provider: "provider-a".to_owned(),
            model: "model-a".to_owned(),
            auth_billing: "fixture-account".to_owned(),
            serializer_hash: test_digest("go59-serializer")?,
            tool_semantics_hash: test_digest("go59-tools")?,
            reasoning_mode: "bounded".to_owned(),
            continuation_behavior: "fresh".to_owned(),
            feature_flags_hash: test_digest("go59-features")?,
        })
    }

    fn test_request(route: &RouteFingerprint, critical: bool) -> ProductionAdmissionRequest {
        ProductionAdmissionRequest {
            capability: "route.execute".to_owned(),
            route: route.clone(),
            generation: TEST_GENERATION,
            now_unix_ms: TEST_NOW,
            critical,
        }
    }

    fn test_record(
        route: &RouteFingerprint,
        status: CapabilityEvidenceStatus,
    ) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord {
            capability: "route.execute".to_owned(),
            route: route.clone(),
            generation: TEST_GENERATION,
            status,
            observed_at_unix_ms: TEST_NOW - 60_000,
            expires_at_unix_ms: TEST_NOW + 60_000,
        }
    }

    fn test_static(route: &RouteFingerprint) -> StaticCapabilityAttestation {
        StaticCapabilityAttestation {
            capability: "route.execute".to_owned(),
            route: route.clone(),
            invalidated: false,
        }
    }

    fn test_pulse(route: &RouteFingerprint) -> DynamicCapabilityPulse {
        DynamicCapabilityPulse {
            capability: "route.execute".to_owned(),
            route: route.clone(),
            generation: TEST_GENERATION,
            observed_at_unix_ms: TEST_NOW - 1_000,
            fresh_until_unix_ms: TEST_NOW + 30_000,
            live: true,
            degraded: false,
        }
    }

    #[test]
    fn declared_only_route_is_rejected_for_production() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        let outcome = evaluate_production_admission(
            &request,
            std::slice::from_ref(&test_record(&route, CapabilityEvidenceStatus::Declared)),
            None,
            None,
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::RequireAuthority);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn absent_evidence_blocks() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        let outcome = evaluate_production_admission(&request, &[], None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::Block);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn matching_fresh_observed_evidence_admits() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        let outcome = evaluate_production_admission(
            &request,
            std::slice::from_ref(&test_record(&route, CapabilityEvidenceStatus::Observed)),
            None,
            None,
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::Admit);
        assert!(outcome.admitted());
        Ok(())
    }

    #[test]
    fn critical_route_needs_static_and_pulse_together() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, true);
        let observed = test_record(&route, CapabilityEvidenceStatus::Observed);
        let evidence = std::slice::from_ref(&observed);
        let alone = evaluate_production_admission(&request, evidence, None, None);
        assert_ne!(alone.disposition, AdmissionDisposition::Admit);
        let static_only =
            evaluate_production_admission(&request, evidence, Some(&test_static(&route)), None);
        assert_ne!(static_only.disposition, AdmissionDisposition::Admit);
        let pulse_only =
            evaluate_production_admission(&request, evidence, None, Some(&test_pulse(&route)));
        assert_ne!(pulse_only.disposition, AdmissionDisposition::Admit);
        let together = evaluate_production_admission(
            &request,
            evidence,
            Some(&test_static(&route)),
            Some(&test_pulse(&route)),
        );
        assert_eq!(together.disposition, AdmissionDisposition::Admit);
        assert!(together.admitted());
        Ok(())
    }

    #[test]
    fn expired_pulse_returns_critical_route_to_non_admissible() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, true);
        let observed = test_record(&route, CapabilityEvidenceStatus::Observed);
        let evidence = std::slice::from_ref(&observed);
        let mut pulse = test_pulse(&route);
        pulse.fresh_until_unix_ms = TEST_NOW;
        let outcome = evaluate_production_admission(
            &request,
            evidence,
            Some(&test_static(&route)),
            Some(&pulse),
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::Defer);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn generation_change_returns_route_to_non_admissible() -> TestResult {
        let route = test_route()?;
        let mut request = test_request(&route, true);
        request.generation = TEST_GENERATION + 1;
        let observed = test_record(&route, CapabilityEvidenceStatus::Observed);
        let evidence = std::slice::from_ref(&observed);
        let outcome = evaluate_production_admission(
            &request,
            evidence,
            Some(&test_static(&route)),
            Some(&test_pulse(&route)),
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::Defer);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn fingerprint_dependency_change_blocks_without_silent_generalization() -> TestResult {
        let route = test_route()?;
        let mut rotated = test_route()?;
        rotated.adapter_hash = test_digest("go59-adapter-rotated")?;
        let request = test_request(&rotated, false);
        let outcome = evaluate_production_admission(
            &request,
            std::slice::from_ref(&test_record(&route, CapabilityEvidenceStatus::Observed)),
            None,
            None,
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::Block);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn broken_evidence_overrides_fresh_observation() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        let records = [
            test_record(&route, CapabilityEvidenceStatus::Observed),
            test_record(&route, CapabilityEvidenceStatus::Broken),
        ];
        let outcome = evaluate_production_admission(&request, &records, None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::Block);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn stale_broken_evidence_does_not_veto_fresh_observation() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        // Broken record from a previous generation: superseded once matching
        // fresh evidence is recorded at the requested generation.
        let mut superseded = test_record(&route, CapabilityEvidenceStatus::Broken);
        superseded.generation = TEST_GENERATION - 1;
        let records = [
            test_record(&route, CapabilityEvidenceStatus::Observed),
            superseded,
        ];
        let outcome = evaluate_production_admission(&request, &records, None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::Admit);
        assert!(outcome.admitted());
        // Same for an expired broken record at the requested generation.
        let mut expired = test_record(&route, CapabilityEvidenceStatus::Broken);
        expired.expires_at_unix_ms = TEST_NOW;
        let records = [
            test_record(&route, CapabilityEvidenceStatus::Observed),
            expired,
        ];
        let outcome = evaluate_production_admission(&request, &records, None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::Admit);
        assert!(outcome.admitted());
        // A stale broken record alone needs requalification; it does not
        // block outright.
        let mut lone = test_record(&route, CapabilityEvidenceStatus::Broken);
        lone.generation = TEST_GENERATION - 1;
        let outcome =
            evaluate_production_admission(&request, std::slice::from_ref(&lone), None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::RequireAuthority);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn degraded_evidence_caps_at_observe_only() -> TestResult {
        let route = test_route()?;
        let request = test_request(&route, false);
        let outcome = evaluate_production_admission(
            &request,
            std::slice::from_ref(&test_record(&route, CapabilityEvidenceStatus::Degraded)),
            None,
            None,
        );
        assert_eq!(outcome.disposition, AdmissionDisposition::ObserveOnly);
        assert!(!outcome.admitted());
        Ok(())
    }

    #[test]
    fn generic_health_claim_without_evidence_still_blocks() -> TestResult {
        // The gate takes no build, install, PID, port, or health input: a
        // bare readiness claim with no matching evidence cannot admit.
        let route = test_route()?;
        let request = test_request(&route, false);
        let outcome = evaluate_production_admission(&request, &[], None, None);
        assert_eq!(outcome.disposition, AdmissionDisposition::Block);
        assert!(!outcome.admitted());
        Ok(())
    }

    fn test_policy_with(caps: &[&str]) -> HumanModelPreferencePolicy {
        use eliot_agent_coordinator::{
            BillingClass, MODEL_PREFERENCE_SCHEMA_VERSION, RoleModelPreference,
        };
        HumanModelPreferencePolicy {
            schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
            policy_id: "policy-required-set".to_owned(),
            revision: "policy-rev-1".to_owned(),
            account_scope: "account-required-set".to_owned(),
            roles: vec![
                RoleModelPreference {
                    role: ModelRole::Dreamer,
                    preferred: Vec::new(),
                    denied: Vec::new(),
                    allowed_billing: BTreeSet::from([BillingClass::Free]),
                    allow_paid_fallback: false,
                    allow_degraded_routes: false,
                    minimum_context_window: 1,
                    maximum_cost_class: 10,
                    maximum_latency_class: 10,
                    required_capabilities: caps.iter().map(|cap| (*cap).to_owned()).collect(),
                },
                RoleModelPreference {
                    role: ModelRole::Worker,
                    preferred: Vec::new(),
                    denied: Vec::new(),
                    allowed_billing: BTreeSet::from([BillingClass::Free]),
                    allow_paid_fallback: false,
                    allow_degraded_routes: false,
                    minimum_context_window: 1,
                    maximum_cost_class: 10,
                    maximum_latency_class: 10,
                    // Worker-role capabilities never leak into the Dreamer
                    // invoke set.
                    required_capabilities: BTreeSet::from(["worker-only".to_owned()]),
                },
            ],
        }
    }

    #[test]
    fn canonical_required_set_unites_launch_and_dreamer_policy() {
        let set = canonical_required_set(
            &["rust".to_owned(), "route.execute".to_owned()],
            &test_policy_with(&["telemetry", "rust"]),
        )
        .expect("union must produce");
        assert_eq!(set, vec!["route.execute", "rust", "telemetry"]);
        // Launch-only and policy-only both produce; duplicates collapse.
        assert_eq!(
            canonical_required_set(&["rust".to_owned()], &test_policy_with(&[])),
            Some(vec!["rust".to_owned()])
        );
        assert_eq!(
            canonical_required_set(&[], &test_policy_with(&["telemetry"])),
            Some(vec!["telemetry".to_owned()])
        );
    }

    #[test]
    fn canonical_required_set_fails_closed_on_empty_or_malformed() {
        assert_eq!(
            canonical_required_set(&[], &test_policy_with(&[])),
            None,
            "an empty union never admits"
        );
        assert_eq!(
            canonical_required_set(&["  ".to_owned()], &test_policy_with(&[])),
            None,
            "a blank launch item fails the whole set, never narrows it"
        );
        assert_eq!(
            canonical_required_set(&["rust".to_owned()], &test_policy_with(&["ok\u{7}"])),
            None,
            "a control-bearing policy item fails the whole set"
        );
    }
}
