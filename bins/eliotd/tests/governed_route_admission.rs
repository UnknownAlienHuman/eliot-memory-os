//! Governor production route admission caller proof (issues #1958, #1959).
//!
//! Drives the production entry point [`admit_production_route`](eliotd::admit_production_route)
//! the way a real Governor caller does: a policy-selected requested route,
//! runtime-observed facts from handshake evidence, threaded capability
//! evidence, and an attempt identity. Proves the admission decision flows
//! through the funnel with requested/observed separation intact, and that
//! non-admission stays visible on the attempt receipt without admitting.

use eliot_agent_api::{AttemptId, LowercaseSha256, RouteFingerprint};
use eliotd::{
    AdmissionDisposition, CapabilityEvidenceRecord, CapabilityEvidenceStatus,
    DynamicCapabilityPulse, ProductionAdmissionRequest, ProductionEvidenceBundle,
    RouteCapabilityIndex, RouteReceiptError, RuntimeObservedFacts, StaticCapabilityAttestation,
    admit_production_route, effective_route_key,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_NOW: u64 = 2_000_000;
const TEST_GENERATION: u64 = 11;

fn digest(byte: u8) -> TestResult<LowercaseSha256> {
    let hex: String = std::iter::repeat_n(byte as char, 64).collect();
    serde_json::from_value(serde_json::Value::String(hex)).map_err(Into::into)
}

fn requested_route() -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: "opencode".to_owned(),
        adapter: "eliot-opencode-adapter".to_owned(),
        protocol_transport: "HTTP+SSE".to_owned(),
        runtime_hash: digest(b'a')?,
        adapter_hash: digest(b'b')?,
        provider: "configured-provider".to_owned(),
        model: "configured-model".to_owned(),
        auth_billing: "configured-billing".to_owned(),
        serializer_hash: digest(b'c')?,
        tool_semantics_hash: digest(b'd')?,
        reasoning_mode: "reasoning-visible".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: digest(b'e')?,
    })
}

/// Handshake-observed facts where the runtime exposed a DIFFERENT provider
/// than policy configured: the separation case the receipt must preserve.
fn observed_facts(route: &RouteFingerprint) -> TestResult<RuntimeObservedFacts> {
    Ok(RuntimeObservedFacts {
        host_family: route.host_family.clone(),
        adapter: route.adapter.clone(),
        protocol_transport: route.protocol_transport.clone(),
        runtime_hash: route.runtime_hash.clone(),
        adapter_hash: route.adapter_hash.clone(),
        provider: Some("observed-provider".to_owned()),
        model: Some("observed-model".to_owned()),
        auth_billing: Some("observed-billing".to_owned()),
        serializer_hash: route.serializer_hash.clone(),
        tool_semantics_hash: route.tool_semantics_hash.clone(),
        reasoning_mode: route.reasoning_mode.clone(),
        continuation_behavior: route.continuation_behavior.clone(),
        feature_flags_hash: route.feature_flags_hash.clone(),
        evidence_refs: vec!["handshake:session-9".to_owned()],
    })
}

fn fresh_record(route: &RouteFingerprint) -> CapabilityEvidenceRecord {
    CapabilityEvidenceRecord {
        capability: "route.execute".to_owned(),
        route: route.clone(),
        generation: TEST_GENERATION,
        status: CapabilityEvidenceStatus::Observed,
        observed_at_unix_ms: TEST_NOW - 60_000,
        expires_at_unix_ms: TEST_NOW + 60_000,
    }
}

fn bound_static(route: &RouteFingerprint) -> StaticCapabilityAttestation {
    StaticCapabilityAttestation {
        capability: "route.execute".to_owned(),
        route: route.clone(),
        invalidated: false,
    }
}

fn fresh_pulse(route: &RouteFingerprint) -> DynamicCapabilityPulse {
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

fn critical_request(route: &RouteFingerprint) -> ProductionAdmissionRequest {
    ProductionAdmissionRequest {
        capability: "route.execute".to_owned(),
        route: route.clone(),
        generation: TEST_GENERATION,
        now_unix_ms: TEST_NOW,
        critical: true,
    }
}

#[test]
fn production_admission_flows_through_funnel_with_separated_receipt() -> TestResult {
    let requested = requested_route()?;
    let facts = observed_facts(&requested)?;
    let record = fresh_record(&requested);
    let evidence = ProductionEvidenceBundle {
        records: std::slice::from_ref(&record),
        static_attestation: Some(&bound_static(&requested)),
        pulse: Some(&fresh_pulse(&requested)),
    };
    let decision = admit_production_route(
        &critical_request(&requested),
        &evidence,
        AttemptId::new("attempt-1")?,
        &facts,
    )?;
    assert_eq!(decision.outcome.disposition, AdmissionDisposition::Admit);
    assert!(decision.outcome.admitted());
    // Requested policy selection preserved; observed values evidence-backed,
    // never inferred from the request.
    assert_eq!(decision.attempt.requested_route, requested);
    assert_eq!(
        decision.attempt.actual.observed_route.provider,
        "observed-provider"
    );
    assert!(
        decision
            .attempt
            .actual
            .diverged_fields()
            .contains(&"provider".to_owned()),
        "provider divergence must be classified"
    );
    decision.attempt.validate().map_err(|error| {
        format!("attempt receipt linkage must hold on the caller path: {error}")
    })?;

    // Capability lookup keys off the complete OBSERVED fingerprint: the
    // observed route hits, a serializer-rotated sibling misses.
    let mut index = RouteCapabilityIndex::new();
    index.insert(&decision.attempt.actual.observed_route, digest(b'1')?)?;
    assert_eq!(
        index
            .lookup(&decision.attempt.actual.observed_route)?
            .map(LowercaseSha256::as_str),
        Some(digest(b'1')?.as_str())
    );
    let mut rotated = decision.attempt.actual.observed_route.clone();
    rotated.serializer_hash = digest(b'f')?;
    assert_eq!(index.lookup(&rotated)?, None);
    assert_ne!(
        effective_route_key(&decision.attempt.actual.observed_route)?.as_str(),
        effective_route_key(&rotated)?.as_str()
    );
    Ok(())
}

#[test]
fn expired_pulse_defers_with_visible_receipt() -> TestResult {
    let requested = requested_route()?;
    let facts = observed_facts(&requested)?;
    let record = fresh_record(&requested);
    let static_attestation = bound_static(&requested);
    let mut pulse = fresh_pulse(&requested);
    pulse.fresh_until_unix_ms = TEST_NOW;
    let evidence = ProductionEvidenceBundle {
        records: std::slice::from_ref(&record),
        static_attestation: Some(&static_attestation),
        pulse: Some(&pulse),
    };
    let decision = admit_production_route(
        &critical_request(&requested),
        &evidence,
        AttemptId::new("attempt-2")?,
        &facts,
    )?;
    assert_eq!(decision.outcome.disposition, AdmissionDisposition::Defer);
    assert!(!decision.outcome.admitted());
    // Visibility without admission: the blocked attempt still carries its
    // separated receipt.
    decision
        .attempt
        .validate()
        .map_err(|error| format!("blocked attempt must stay visible and linked: {error}"))?;
    assert_eq!(
        decision.attempt.actual.observed_route.provider,
        "observed-provider"
    );
    Ok(())
}

#[test]
fn malformed_facts_fail_closed_before_decision() -> TestResult {
    let requested = requested_route()?;
    let mut facts = observed_facts(&requested)?;
    facts.evidence_refs.clear();
    let record = fresh_record(&requested);
    let evidence = ProductionEvidenceBundle {
        records: std::slice::from_ref(&record),
        static_attestation: None,
        pulse: None,
    };
    let error = match admit_production_route(
        &ProductionAdmissionRequest {
            critical: false,
            ..critical_request(&requested)
        },
        &evidence,
        AttemptId::new("attempt-3")?,
        &facts,
    ) {
        Err(error) => error,
        Ok(_) => return Err("evidenceless observation must not decide".into()),
    };
    assert!(
        matches!(error, RouteReceiptError::EmptyEvidence),
        "unexpected failure: {error:?}"
    );
    Ok(())
}
