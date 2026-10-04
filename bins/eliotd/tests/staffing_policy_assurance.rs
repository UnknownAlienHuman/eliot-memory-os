//! Capability-based staffing proof for issue #1963 (acceptance only).
//!
//! Under the assurance preset, a task requiring independent review receives a
//! writer plus an independently eligible audit route when available; when it
//! is unavailable, the plan receipt explicitly escalates or defers rather
//! than silently substituting a same-family or paid route. The receipt
//! identifies the selected route classes, routes, budget/privacy constraints,
//! the outcome profiles consulted, and evidence inputs used. Provider switching
//! mid-attempt is denied without an explicit receipted policy-authorized
//! degradation.

use std::collections::HashMap;

use eliot_agent_api::{BudgetEnvelope, RouteFingerprint};
use eliot_contracts::sha256_hex;
use eliot_governor::{
    ExecutionIdentity, RouteBehaviorFingerprint, RouteOutcomeCounts, RouteOutcomeProfile,
    RouteOutcomeProfileIndex,
};
use eliot_security_contracts::PrivacyClass;
use eliotd::staffing_policy::{
    MIN_ROUTE_OUTCOME_SAMPLES, PolicyAuthorizedDegradation, RouteCandidate, RouteClassEvidence,
    RouteEligibility, RouteOutcomeBinding, RouteOutcomeEvidence, StaffingConstraints,
    StaffingPolicyError, UnavailableDispositionKind, check_attempt_route_continuity, plan_staffing,
    route_outcome_evidence, verify_receipt_digest,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(seed: &str) -> TestResult<eliot_agent_api::LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(sha256_hex(
        seed.as_bytes()
    )))?)
}

fn test_route(seed: &str, provider: &str, model: &str) -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: format!("host-{seed}"),
        adapter: format!("adapter-{seed}"),
        protocol_transport: "test-transport".to_owned(),
        runtime_hash: digest(&format!("runtime-{seed}"))?,
        adapter_hash: digest(&format!("adapter-hash-{seed}"))?,
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: format!("billing-{seed}"),
        serializer_hash: digest(&format!("serializer-{seed}"))?,
        tool_semantics_hash: digest(&format!("tools-{seed}"))?,
        reasoning_mode: "bounded".to_owned(),
        continuation_behavior: "fresh".to_owned(),
        feature_flags_hash: digest(&format!("features-{seed}"))?,
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
    with_outcome(route, family, paid, admits, evidence, None)
}

fn with_outcome(
    route: RouteFingerprint,
    family: &str,
    paid: bool,
    admits: bool,
    evidence: &str,
    outcome: Option<RouteOutcomeEvidence>,
) -> RouteCandidate {
    RouteCandidate {
        route,
        family: family.to_owned(),
        paid,
        eligibility: RouteEligibility {
            quota_admits: admits,
            capacity_admits: admits,
            privacy_admits: admits,
        },
        evidence_ref: evidence.to_owned(),
        outcome,
    }
}

/// An outcome profile over equal-stack samples that produced nothing verified.
fn failing_profile(reference: &str) -> RouteOutcomeEvidence {
    RouteOutcomeEvidence {
        verified_complete: 0,
        partial: 0,
        failed: MIN_ROUTE_OUTCOME_SAMPLES,
        unknown: 1,
        stale: false,
        evidence_refs: vec![reference.to_owned()],
    }
}

/// Owner-issued behaviour identity for the exact effective route, standing in
/// for what the route owner supplies. This test constructs it; the policy never
/// derives one from a `RouteFingerprint`.
fn behavior_fingerprint(seed: &str) -> RouteBehaviorFingerprint {
    RouteBehaviorFingerprint {
        host_family: format!("host-{seed}"),
        adapter_id: format!("adapter-{seed}"),
        adapter_version: format!("adapter-{seed}-v1"),
        protocol_kind: "test-protocol".to_owned(),
        transport_kind: "test-transport".to_owned(),
        runtime_version: format!("runtime-{seed}-v1"),
        runtime_hash: format!("runtime-hash-{seed}"),
        adapter_hash: format!("adapter-hash-{seed}"),
        provider_and_model_request: format!("provider-{seed}/model-{seed}"),
        auth_profile_class: "user-broker".to_owned(),
        billing_mode: "subscription".to_owned(),
        account_mode: "named-account".to_owned(),
        execution_identity: ExecutionIdentity::InteractiveUser,
        required_user_broker_class: "user-broker".to_owned(),
        retention_policy: "bounded".to_owned(),
        network_policy: "egress-allowed".to_owned(),
        session_locator_semantics: "per-attempt".to_owned(),
        workspace_scope_policy: "scope-bound".to_owned(),
        serializer_fingerprint: format!("serializer-{seed}"),
        tool_call_id_and_role_ordering: format!("tool-ordering-{seed}"),
        reasoning_continuation_and_compaction: format!("reasoning-{seed}"),
        feature_flags_and_behavior_affecting_profiles: format!("features-{seed}"),
    }
}

fn outcome_profile(counts: RouteOutcomeCounts) -> RouteOutcomeProfile {
    RouteOutcomeProfile {
        task_class_and_recipe: "assurance-task/recipe-1963".to_owned(),
        governance_and_environment_profile: "installation-1".to_owned(),
        sample_window_and_distribution: "window-1".to_owned(),
        outcome_counts: counts,
        verifier_coverage_and_quality_measures: "verifier-coverage-1".to_owned(),
        latency_cost_quota_and_cleanup_measures: "latency-cost-1".to_owned(),
        continuation_context_and_route_mismatch_failures: "continuation-failures-0".to_owned(),
        independence_and_common_lineage_notes: "single-family".to_owned(),
        confidence_coverage_and_known_biases: "confidence-low".to_owned(),
        evidence_refs: vec!["outcome-evidence-1".to_owned()],
        valid_until_and_stale_dependencies: "valid-until-window-1".to_owned(),
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

#[test]
fn widened_budget_rejects_instead_of_staffing() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![candidate(
            writer_route,
            "family-a",
            false,
            true,
            "capability-writer-1",
        )],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let mut wide = constraints();
    wide.budget.cost_microunits = test_budget().cost_microunits + 1;
    assert!(
        matches!(
            plan_staffing(&policy, "assurance-task", false, &evidence, &wide),
            Err(StaffingPolicyError::Contract(_))
        ),
        "supplied constraints must not widen the policy per-job budget"
    );
    Ok(())
}

#[test]
fn local_only_ceiling_closes_external_lanes_fail_closed() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![candidate(
            writer_route,
            "family-a",
            false,
            true,
            "capability-writer-1",
        )],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let mut secret = constraints();
    secret.privacy_ceiling = PrivacyClass::Secret;
    assert!(
        matches!(
            plan_staffing(&policy, "secret-task", false, &evidence, &secret),
            Err(StaffingPolicyError::NoWriterRoute(_))
        ),
        "a local-only ceiling must staff no external lane, not substitute one"
    );
    Ok(())
}

#[test]
fn receipt_digest_rebinds_at_the_persistence_boundary() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![candidate(
            writer_route,
            "family-a",
            false,
            true,
            "capability-writer-1",
        )],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let mut receipt = plan_staffing(&policy, "assurance-task", false, &evidence, &constraints())?;
    assert!(verify_receipt_digest(&receipt).is_ok());
    receipt.task_class = "tampered-task".to_owned();
    assert!(
        matches!(
            verify_receipt_digest(&receipt),
            Err(StaffingPolicyError::Contract(_))
        ),
        "a tampered candidate must fail the persistence-boundary check"
    );
    Ok(())
}

#[test]
fn blank_evidence_identity_rejects_fail_closed() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let writer_route = test_route("writer", "provider-a", "model-a")?;
    let audit_route = test_route("audit", "provider-b", "model-b")?;
    // A blank auditor family must fail closed: unknown lineage can never
    // prove cross-family independence.
    let evidence = vec![
        RouteClassEvidence {
            route_class: "bulk_implementation".to_owned(),
            candidates: vec![candidate(
                writer_route,
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
                audit_route,
                "   ",
                false,
                true,
                "capability-audit-1",
            )],
            evidence_refs: vec!["capability-audit-1".to_owned()],
        },
    ];
    assert!(
        matches!(
            plan_staffing(&policy, "assurance-task", true, &evidence, &constraints()),
            Err(StaffingPolicyError::Contract(_))
        ),
        "blank auditor lineage must reject before any lane is staffed"
    );
    Ok(())
}

/// I3.4/I3.6: staffing is computed from task outcomes, so a route whose own
/// equal-stack samples rejected this task class is not staffed while another
/// eligible route exists, and the counts it was decided on stay in the receipt.
#[test]
fn observed_outcome_failure_keeps_its_route_out_of_the_selection() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let rejected_route = test_route("rejected", "provider-a", "model-a")?;
    let kept_route = test_route("kept", "provider-c", "model-c")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![
            with_outcome(
                rejected_route.clone(),
                "family-a",
                false,
                true,
                "capability-writer-1",
                Some(failing_profile("outcome-rejected-1")),
            ),
            candidate(
                kept_route.clone(),
                "family-c",
                false,
                true,
                "capability-writer-2",
            ),
        ],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let receipt = plan_staffing(&policy, "assurance-task", false, &evidence, &constraints())?;
    assert_eq!(receipt.lanes.len(), 1);
    assert_eq!(
        receipt.lanes[0].route, kept_route,
        "a route whose own outcome samples produced nothing verified must not be staffed while an eligible alternative exists"
    );
    // The refused profile stays visible, bound to the exact route, with its
    // counts: aggregated success elsewhere cannot hide them.
    let refused = receipt
        .route_outcome_evidence
        .iter()
        .find(|record| record.route == rejected_route)
        .ok_or("the consulted outcome profile is not recorded in the receipt")?;
    assert_eq!(refused.profile.failed, MIN_ROUTE_OUTCOME_SAMPLES);
    assert_eq!(refused.profile.unknown, 1);
    assert_eq!(refused.profile.verified_complete, 0);
    assert!(
        receipt
            .evidence_refs
            .contains(&"outcome-rejected-1".to_owned()),
        "outcome evidence inputs are part of the receipt's evidence inputs"
    );
    verify_receipt_digest(&receipt)?;
    Ok(())
}

/// A route every eligible candidate rejected on its own samples is a typed
/// refusal, never a fallback onto the route that was already ruled out.
#[test]
fn every_outcome_rejected_writer_is_a_typed_refusal() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let rejected_route = test_route("rejected", "provider-a", "model-a")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![with_outcome(
            rejected_route,
            "family-a",
            false,
            true,
            "capability-writer-1",
            Some(failing_profile("outcome-rejected-1")),
        )],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let refusal = plan_staffing(&policy, "assurance-task", false, &evidence, &constraints());
    assert!(
        matches!(refusal, Err(StaffingPolicyError::NoWriterRoute(_))),
        "a writer class whose only routes were rejected by their own outcomes refuses instead of staffing one"
    );
    Ok(())
}

/// I3.4 keeps routing on policy defaults and controlled pilots until enough
/// equal-stack evidence exists, and a profile whose declared stale dependencies
/// moved is not read as success or as failure. Neither moves a route.
#[test]
fn sparse_and_stale_outcome_profiles_carry_no_signal() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let sparse_route = test_route("sparse", "provider-a", "model-a")?;
    let stale_route = test_route("stale", "provider-b", "model-b")?;
    let mut sparse = failing_profile("outcome-sparse-1");
    // One failed sample: too sparse to say anything about this route.
    sparse.failed = 1;
    sparse.unknown = 0;
    let mut stale = failing_profile("outcome-stale-1");
    stale.stale = true;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![
            with_outcome(
                sparse_route.clone(),
                "family-a",
                false,
                true,
                "capability-writer-1",
                Some(sparse),
            ),
            with_outcome(
                stale_route.clone(),
                "family-b",
                false,
                true,
                "capability-writer-2",
                Some(stale),
            ),
        ],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let receipt = plan_staffing(&policy, "assurance-task", false, &evidence, &constraints())?;
    assert_eq!(
        receipt.lanes[0].route, sparse_route,
        "policy-default order stands until enough equal-stack evidence exists"
    );
    // Both profiles are still recorded, so their absence of signal is auditable.
    assert_eq!(receipt.route_outcome_evidence.len(), 2);
    Ok(())
}

/// Aggregated success authorizes nothing: a route with verified samples is not
/// promoted over one with none, and its own minority failures stay in the
/// receipt rather than being averaged away.
#[test]
fn outcome_success_never_promotes_a_route_over_policy_default_order() -> TestResult {
    let policy = eliotd::staffing_policy::ModelRolePolicy::assurance(test_budget())?;
    let first_route = test_route("first", "provider-a", "model-a")?;
    let second_route = test_route("second", "provider-b", "model-b")?;
    let evidence = vec![RouteClassEvidence {
        route_class: "bulk_implementation".to_owned(),
        candidates: vec![
            candidate(
                first_route.clone(),
                "family-a",
                false,
                true,
                "capability-writer-1",
            ),
            with_outcome(
                second_route.clone(),
                "family-b",
                false,
                true,
                "capability-writer-2",
                Some(RouteOutcomeEvidence {
                    verified_complete: MIN_ROUTE_OUTCOME_SAMPLES,
                    partial: 0,
                    failed: MIN_ROUTE_OUTCOME_SAMPLES,
                    unknown: 0,
                    stale: false,
                    evidence_refs: vec!["outcome-mixed-1".to_owned()],
                }),
            ),
        ],
        evidence_refs: vec!["capability-writer-1".to_owned()],
    }];
    let receipt = plan_staffing(&policy, "assurance-task", false, &evidence, &constraints())?;
    assert_eq!(
        receipt.lanes[0].route, first_route,
        "an outcome profile is never a promotion signal"
    );
    let mixed = receipt
        .route_outcome_evidence
        .iter()
        .find(|record| record.route == second_route)
        .ok_or("the consulted outcome profile is not recorded in the receipt")?;
    assert_eq!(
        mixed.profile.failed, MIN_ROUTE_OUTCOME_SAMPLES,
        "a minority failure beside a success stays visible in the counts"
    );
    Ok(())
}

/// The live staffing path reads the Governor's own retained outcome profiles,
/// keyed by the exact effective route, and never derives a behaviour identity
/// from a route fingerprint to do it.
#[test]
fn retained_outcome_profiles_are_read_from_the_governor_index() -> TestResult {
    let route = test_route("profiled", "provider-a", "model-a")?;
    let sibling = test_route("sibling", "provider-a", "model-a")?;
    let mut profiles = RouteOutcomeProfileIndex::new();
    profiles
        .record(
            &behavior_fingerprint("profiled"),
            outcome_profile(RouteOutcomeCounts {
                verified_complete: 0,
                partial: 1,
                failed: MIN_ROUTE_OUTCOME_SAMPLES,
                unknown: 2,
            }),
        )
        .map_err(|error| format!("record profile: {error}"))?;

    // The owner binds the exact effective route to its behaviour identity.
    let route_key =
        eliotd::effective_route_key(&route).map_err(|error| format!("route key: {error}"))?;
    let bindings = HashMap::from([(
        route_key.clone(),
        RouteOutcomeBinding {
            fingerprint: behavior_fingerprint("profiled"),
            stale: false,
        },
    )]);
    let profile = route_outcome_evidence(&profiles, &bindings, &route)?
        .ok_or("the retained profile for the exact effective route was not read")?;
    assert_eq!(profile.verified_complete, 0);
    assert_eq!(profile.partial, 1);
    assert_eq!(profile.failed, MIN_ROUTE_OUTCOME_SAMPLES);
    assert_eq!(profile.unknown, 2);
    assert!(!profile.stale);
    assert_eq!(profile.evidence_refs, vec!["outcome-evidence-1".to_owned()]);

    // A provider/model-identical sibling under a different behaviour identity
    // holds no profile of its own, so nothing is borrowed from it.
    assert!(
        route_outcome_evidence(&profiles, &bindings, &sibling)?.is_none(),
        "a route with no owner binding consumes no profile"
    );
    // An empty index and a stale binding are absences, never assumed success.
    assert!(
        route_outcome_evidence(&RouteOutcomeProfileIndex::new(), &bindings, &route)?.is_none(),
        "an empty profile index consumes nothing"
    );
    let stale_bindings = HashMap::from([(
        route_key,
        RouteOutcomeBinding {
            fingerprint: behavior_fingerprint("profiled"),
            stale: true,
        },
    )]);
    assert!(
        route_outcome_evidence(&profiles, &stale_bindings, &route)?.is_none(),
        "a stale binding contributes no signal"
    );
    // A retained profile with no evidence reference proves nothing and is
    // refused rather than consumed.
    let mut unevidenced = RouteOutcomeProfileIndex::new();
    let mut bare = outcome_profile(RouteOutcomeCounts::default());
    bare.evidence_refs.clear();
    unevidenced
        .record(&behavior_fingerprint("profiled"), bare)
        .map_err(|error| format!("record bare profile: {error}"))?;
    assert!(
        matches!(
            route_outcome_evidence(&unevidenced, &bindings, &route),
            Err(StaffingPolicyError::Contract(_))
        ),
        "a profile with no evidence reference must not be consumed"
    );
    Ok(())
}
