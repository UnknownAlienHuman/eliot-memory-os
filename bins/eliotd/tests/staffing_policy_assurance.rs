//! Capability-based staffing proof for issue #1963 (acceptance only).
//!
//! Under the assurance preset, a task requiring independent review receives a
//! writer plus an independently eligible audit route when available; when it
//! is unavailable, the plan receipt explicitly escalates or defers rather
//! than silently substituting a same-family or paid route. The receipt
//! identifies the selected route classes, routes, budget/privacy constraints,
//! and evidence inputs used. Provider switching mid-attempt is denied without
//! an explicit receipted policy-authorized degradation.

use eliot_agent_api::{BudgetEnvelope, RouteFingerprint};
use eliot_contracts::sha256_hex;
use eliot_security_contracts::PrivacyClass;
use eliotd::staffing_policy::{
    PolicyAuthorizedDegradation, RouteCandidate, RouteClassEvidence, StaffingConstraints,
    StaffingPolicyError, UnavailableDispositionKind, check_attempt_route_continuity, plan_staffing,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(seed: &str) -> eliot_agent_api::LowercaseSha256 {
    serde_json::from_value(serde_json::json!(sha256_hex(seed.as_bytes()))).expect("test digest")
}

fn test_route(seed: &str, provider: &str, model: &str) -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: format!("host-{seed}"),
        adapter: format!("adapter-{seed}"),
        protocol_transport: "test-transport".to_owned(),
        runtime_hash: digest(&format!("runtime-{seed}")),
        adapter_hash: digest(&format!("adapter-hash-{seed}")),
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: format!("billing-{seed}"),
        serializer_hash: digest(&format!("serializer-{seed}")),
        tool_semantics_hash: digest(&format!("tools-{seed}")),
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: digest(&format!("features-{seed}")),
    })
}

fn test_budget() -> BudgetEnvelope {
    BudgetEnvelope {
        context_tokens: 8_000,
        wall_time_ms: 60_000,
        output_bytes: 256_000,
        cost_microunits: 1_000_000,
        max_depth: 3,
        max_descendants: 8,
    }
}

fn constraints() -> StaffingConstraints {
    StaffingConstraints {
        budget: test_budget(),
        privacy_ceiling: PrivacyClass::Private,
        evidence_refs: vec!["quota-window-rolling-hours".to_owned()],
    }
}

fn candidate(
    route: RouteFingerprint,
    family: &str,
    paid: bool,
    admits: bool,
    evidence: &str,
) -> RouteCandidate {
    RouteCandidate {
        route,
        family: family.to_owned(),
        paid,
        quota_admits: admits,
        capacity_admits: admits,
        privacy_admits: admits,
        evidence_ref: evidence.to_owned(),
    }
}

#[test]
fn assurance_staffs_writer_plus_independent_audit_when_available() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let audit_route = test_route("audit", "provider-b", "model-b")?;
    let evidence = vec![
        RouteClassEvidence {
            route_class: "bulk_implementation".to_owned(),
            candidates: vec![candidate(
                writer_route.clone(),
                "family-a",
                false,
                true,
                "capability-writer-1",
            )],
            evidence_refs: vec!["capability-writer-1".to_owned()],
        },
        RouteClassEvidence {
            route_class: "independent_blind_audit".to_owned(),
            candidates: vec![candidate(
                audit_route.clone(),
                "family-b",
                false,
                true,
                "capability-audit-1",
            )],
            evidence_refs: vec!["capability-audit-1".to_owned()],
        },
    ];
    let receipt = plan_staffing(&policy, "assurance-task", true, &evidence, &constraints())?;
    assert_eq!(receipt.lanes.len(), 2);
    assert_eq!(receipt.lanes[0].role, "writer");
    assert_eq!(receipt.lanes[1].role, "auditor");
    assert_eq!(receipt.lanes[0].route_class, "bulk_implementation");
    assert_eq!(receipt.lanes[1].route_class, "independent_blind_audit");
    assert_eq!(receipt.lanes[0].route, writer_route);
    assert_eq!(receipt.lanes[1].route, audit_route);
    assert_ne!(
        receipt.lanes[0].route.provider,
        receipt.lanes[1].route.provider
    );
    assert_eq!(receipt.budget, test_budget());
    assert_eq!(receipt.privacy_ceiling, PrivacyClass::Private);
    assert!(
        receipt
            .evidence_refs
            .contains(&"capability-writer-1".to_owned())
    );
    assert!(
        receipt
            .evidence_refs
            .contains(&"capability-audit-1".to_owned())
    );
    assert!(!receipt.receipt_digest.is_empty());
    Ok(())
}

#[test]
fn assurance_escalates_when_audit_unavailable_instead_of_substituting() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let same_family = test_route("audit-same", "provider-a2", "model-a2")?;
    let paid_route = test_route("audit-paid", "provider-c", "model-c")?;
    let evidence = vec![
        RouteClassEvidence {
            route_class: "bulk_implementation".to_owned(),
            candidates: vec![candidate(
                writer_route.clone(),
                "family-a",
                false,
                true,
                "capability-writer-1",
            )],
            evidence_refs: vec!["capability-writer-1".to_owned()],
        },
        RouteClassEvidence {
            route_class: "independent_blind_audit".to_owned(),
            candidates: vec![
                candidate(
                    same_family,
                    "family-a",
                    false,
                    true,
                    "capability-audit-same",
                ),
                candidate(paid_route, "family-c", true, true, "capability-audit-paid"),
            ],
            evidence_refs: vec!["capability-audit-stale".to_owned()],
        },
    ];
    let receipt = plan_staffing(&policy, "assurance-task", true, &evidence, &constraints())?;
    // Writer still staffed; no auditor lane substituted.
    assert_eq!(receipt.lanes.len(), 1);
    assert_eq!(receipt.lanes[0].role, "writer");
    assert_eq!(receipt.lanes[0].route, writer_route);
    // Explicit escalate for the unavailable audit class.
    let audit = receipt
        .unavailable
        .iter()
        .find(|item| item.route_class == "independent_blind_audit")
        .ok_or("missing audit disposition")?;
    assert_eq!(audit.disposition, UnavailableDispositionKind::Escalate);
    // Dreamer classes defer explicitly (non-executing), never silently spent.
    assert!(
        receipt
            .unavailable
            .iter()
            .any(|item| item.route_class == "dreamer_curation"
                && item.disposition == UnavailableDispositionKind::Defer)
    );
    Ok(())
}

#[test]
fn provider_switch_denied_without_receipted_degradation() -> TestResult {
    let before = test_route("writer", "provider-a", "model-a")?;
    let after = test_route("audit", "provider-b", "model-b")?;
    assert!(check_attempt_route_continuity(&before, &before, None, "attempt-1").is_ok());
    let denied = check_attempt_route_continuity(&before, &after, None, "attempt-1");
    assert!(matches!(
        denied,
        Err(StaffingPolicyError::ProviderSwitchDenied(_))
    ));
    let from = sha256_hex(
        &eliot_contracts::canonical_json_bytes(&before).map_err(|e| format!("bytes: {e}"))?,
    );
    let to = sha256_hex(
        &eliot_contracts::canonical_json_bytes(&after).map_err(|e| format!("bytes: {e}"))?,
    );
    let approval = PolicyAuthorizedDegradation {
        attempt_id: "attempt-1".to_owned(),
        from_route_digest: from,
        to_route_digest: to,
        reason: "audit route lost capacity; receipted degrade before continuation".to_owned(),
        policy_revision: "assurance-rev-1".to_owned(),
    };
    assert!(check_attempt_route_continuity(&before, &after, Some(&approval), "attempt-1").is_ok());
    Ok(())
}
