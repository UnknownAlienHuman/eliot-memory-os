use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use eliot_agent_api::{AttemptId, RouteFingerprint};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const NOW: u64 = 10_000;

fn route(provider: &str, model: &str, suffix: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: "opencode".to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: format!("runtime-{suffix}"),
        adapter_hash: "adapter-v1".to_owned(),
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: "account-scope-1".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "high".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn quota(disposition: QuotaDisposition) -> QuotaObservation {
    QuotaObservation {
        disposition,
        source: "provider-catalogue".to_owned(),
        receipt_ref: "quota-receipt-1".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        reset_at_unix_ms: Some(NOW + 1_000),
        remaining_microunits: Some(10),
    }
}

fn entry(
    entry_id: &str,
    provider: &str,
    model: &str,
    family: &str,
    billing_class: BillingClass,
    quota_disposition: QuotaDisposition,
    cost_class: u16,
) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        host_family: "opencode".to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: family.to_owned(),
        route: route(provider, model, entry_id),
        route_admission: RouteAdmissionStatus::Admitted,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: billing_class,
            source: "provider-catalogue".to_owned(),
            receipt_ref: format!("billing-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: quota(quota_disposition),
        context_window: 200_000,
        cost_class,
        latency_class: 1,
        capabilities: BTreeMap::from([
            (
                "coding".to_owned(),
                CapabilityObservation {
                    status: CapabilityStatus::Supported,
                    evidence_class: "runtime_probe".to_owned(),
                    receipt_ref: format!("capability-{entry_id}"),
                },
            ),
            (
                "reasoning".to_owned(),
                CapabilityObservation {
                    status: CapabilityStatus::Supported,
                    evidence_class: "runtime_probe".to_owned(),
                    receipt_ref: format!("reasoning-{entry_id}"),
                },
            ),
        ]),
        role_eligibility: BTreeSet::from([
            ModelRole::MainAgent,
            ModelRole::Worker,
            ModelRole::Challenger,
            ModelRole::Verifier,
        ]),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    }
}

fn snapshot(entries: Vec<ModelCatalogueEntry>) -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: "catalogue-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "opencode-provider-catalogue-v1".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries,
    }
}

fn selector(model_id: &str) -> ModelSelector {
    ModelSelector {
        host_family: None,
        provider_id: None,
        model_id: Some(model_id.to_owned()),
        model_family: None,
    }
}

fn preference(
    role: ModelRole,
    preferred: Vec<ModelSelector>,
    denied: Vec<ModelSelector>,
    allowed_billing: BTreeSet<BillingClass>,
    allow_paid_fallback: bool,
) -> RoleModelPreference {
    RoleModelPreference {
        role,
        preferred,
        denied,
        allowed_billing,
        allow_paid_fallback,
        allow_degraded_routes: false,
        minimum_context_window: 100_000,
        maximum_cost_class: 10,
        maximum_latency_class: 10,
        required_capabilities: BTreeSet::from(["coding".to_owned()]),
    }
}

fn policy(role_preference: RoleModelPreference, revision: &str) -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: "human-model-policy-1".to_owned(),
        revision: revision.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        roles: vec![role_preference],
    }
}

fn query(free_only: bool) -> ModelQuery {
    ModelQuery {
        query_id: "query-1".to_owned(),
        text: None,
        free_only,
        include_subscription_included: false,
        dispatchable_only: true,
        host_families: BTreeSet::new(),
        provider_ids: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["coding".to_owned()]),
        minimum_context_window: 100_000,
        limit: 100,
    }
}

#[test]
fn catalogue_entry_requires_exact_route_host_family_binding() {
    let exact = snapshot(vec![entry(
        "exact-host-family",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    )]);
    assert_eq!(exact.validate(), Ok(()));

    let mut mismatched_entry = entry(
        "mismatched-host-family",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    );
    mismatched_entry.host_family = "codex".to_owned();
    assert_eq!(
        snapshot(vec![mismatched_entry]).validate(),
        Err(ModelControlError::InvalidField("entry.route_binding"))
    );
}

#[test]
fn free_query_uses_billing_evidence_not_model_name() -> TestResult {
    let catalogue = snapshot(vec![
        entry(
            "paid-name-free",
            "provider-a",
            "model-free",
            "family-a",
            BillingClass::Paid,
            QuotaDisposition::Available,
            1,
        ),
        entry(
            "actually-free",
            "provider-b",
            "ordinary-model",
            "family-b",
            BillingClass::Free,
            QuotaDisposition::Available,
            1,
        ),
    ]);
    let receipt = query_model_catalogue(&catalogue, &query(true), NOW)?;
    assert_eq!(receipt.hits.len(), 1);
    assert_eq!(receipt.hits[0].entry.entry_id, "actually-free");
    assert_eq!(receipt.execution, ZeroModelExecutionCounters::zero());
    Ok(())
}

#[test]
fn stale_catalogue_cannot_compile_dispatch_candidate() {
    let mut catalogue = snapshot(vec![entry(
        "free",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    )]);
    catalogue.expires_at_unix_ms = NOW - 1;
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            Vec::new(),
            Vec::new(),
            BTreeSet::from([BillingClass::Free]),
            false,
        ),
        "revision-1",
    );
    assert!(matches!(
        compile_model_selection(
            &catalogue,
            &human_policy,
            ModelRole::Worker,
            "selection-1",
            NOW
        ),
        Err(ModelControlError::StaleCatalogue)
    ));
}

#[test]
fn exhausted_and_unknown_quota_are_not_dispatchable() {
    for disposition in [QuotaDisposition::Exhausted, QuotaDisposition::Unknown] {
        let catalogue = snapshot(vec![entry(
            "route-a",
            "provider-a",
            "model-a",
            "family-a",
            BillingClass::Free,
            disposition,
            1,
        )]);
        let human_policy = policy(
            preference(
                ModelRole::Worker,
                Vec::new(),
                Vec::new(),
                BTreeSet::from([BillingClass::Free]),
                false,
            ),
            "revision-1",
        );
        assert!(matches!(
            compile_model_selection(
                &catalogue,
                &human_policy,
                ModelRole::Worker,
                "selection-1",
                NOW
            ),
            Err(ModelControlError::NoDispatchableRoute(ModelRole::Worker))
        ));
    }
}

#[test]
fn unknown_billing_is_not_dispatchable() {
    let catalogue = snapshot(vec![entry(
        "unknown-billing",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Unknown,
        QuotaDisposition::Available,
        0,
    )]);
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            Vec::new(),
            Vec::new(),
            BTreeSet::from([BillingClass::Unknown]),
            true,
        ),
        "revision-1",
    );
    assert!(matches!(
        compile_model_selection(
            &catalogue,
            &human_policy,
            ModelRole::Worker,
            "selection-1",
            NOW
        ),
        Err(ModelControlError::NoDispatchableRoute(ModelRole::Worker))
    ));
}

#[test]
fn empty_catalogue_returns_no_dispatchable_route() {
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            Vec::new(),
            Vec::new(),
            BTreeSet::from([BillingClass::Free]),
            false,
        ),
        "revision-1",
    );
    assert!(matches!(
        compile_model_selection(
            &snapshot(Vec::new()),
            &human_policy,
            ModelRole::Worker,
            "selection-empty-catalogue",
            NOW
        ),
        Err(ModelControlError::NoDispatchableRoute(ModelRole::Worker))
    ));
}

#[test]
fn mixed_role_eligibility_selects_explicit_entry_and_preserves_rejection() -> TestResult {
    let mut empty_role = entry(
        "empty-role",
        "provider-a",
        "model-empty-role",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        0,
    );
    empty_role.role_eligibility.clear();
    let explicit_role = entry(
        "explicit-role",
        "provider-b",
        "model-explicit-role",
        "family-b",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    );
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            vec![selector("model-empty-role")],
            Vec::new(),
            BTreeSet::from([BillingClass::Free]),
            false,
        ),
        "revision-1",
    );
    let left = compile_model_selection(
        &snapshot(vec![empty_role.clone(), explicit_role.clone()]),
        &human_policy,
        ModelRole::Worker,
        "selection-mixed-role",
        NOW,
    )?;
    let right = compile_model_selection(
        &snapshot(vec![explicit_role, empty_role]),
        &human_policy,
        ModelRole::Worker,
        "selection-mixed-role",
        NOW,
    )?;

    assert_eq!(left.selected.entry_id, "explicit-role");
    assert_eq!(left.rejected.len(), 1);
    assert_eq!(left.rejected, right.rejected);
    assert_eq!(left.selection_digest, right.selection_digest);
    assert_eq!(
        left.rejected[0].reasons,
        vec![SelectionRejection::RoleNotEligible]
    );
    assert_eq!(left.execution, ZeroModelExecutionCounters::zero());
    assert!(left.candidate_only);
    assert!(!left.dispatch_authority);
    Ok(())
}

#[test]
fn denied_selector_overrides_preferred_selector() -> TestResult {
    let catalogue = snapshot(vec![
        entry(
            "preferred-denied",
            "provider-a",
            "model-a",
            "family-a",
            BillingClass::Free,
            QuotaDisposition::Available,
            0,
        ),
        entry(
            "fallback",
            "provider-b",
            "model-b",
            "family-b",
            BillingClass::Free,
            QuotaDisposition::Available,
            1,
        ),
    ]);
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            vec![selector("model-a")],
            vec![selector("model-a")],
            BTreeSet::from([BillingClass::Free]),
            false,
        ),
        "revision-1",
    );
    let receipt = compile_model_selection(
        &catalogue,
        &human_policy,
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    assert_eq!(receipt.selected.model_id, "model-b");
    assert!(receipt.rejected.iter().any(|rejection| {
        rejection.model_id == "model-a"
            && rejection
                .reasons
                .contains(&SelectionRejection::DeniedByHumanPolicy)
    }));
    Ok(())
}

#[test]
fn disabled_paid_fallback_returns_no_route() {
    let catalogue = snapshot(vec![entry(
        "paid",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Paid,
        QuotaDisposition::Available,
        1,
    )]);
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            Vec::new(),
            Vec::new(),
            BTreeSet::from([BillingClass::Paid]),
            false,
        ),
        "revision-1",
    );
    assert!(matches!(
        compile_model_selection(
            &catalogue,
            &human_policy,
            ModelRole::Worker,
            "selection-1",
            NOW
        ),
        Err(ModelControlError::NoDispatchableRoute(ModelRole::Worker))
    ));
}

#[test]
fn equivalent_input_permutation_has_same_selection_identity() -> TestResult {
    let first = entry(
        "free-a",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    );
    let second = entry(
        "free-b",
        "provider-b",
        "model-b",
        "family-b",
        BillingClass::Free,
        QuotaDisposition::Available,
        2,
    );
    let human_policy = policy(
        preference(
            ModelRole::Worker,
            Vec::new(),
            Vec::new(),
            BTreeSet::from([BillingClass::Free]),
            false,
        ),
        "revision-1",
    );
    let left = compile_model_selection(
        &snapshot(vec![first.clone(), second.clone()]),
        &human_policy,
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    let right = compile_model_selection(
        &snapshot(vec![second, first]),
        &human_policy,
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    assert_eq!(left.selected.entry_id, right.selected.entry_id);
    assert_eq!(left.catalogue_digest, right.catalogue_digest);
    assert_eq!(left.selection_digest, right.selection_digest);
    Ok(())
}

#[test]
fn preference_revision_changes_selection_identity() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "free",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    )]);
    let role_preference = preference(
        ModelRole::Worker,
        Vec::new(),
        Vec::new(),
        BTreeSet::from([BillingClass::Free]),
        false,
    );
    let left = compile_model_selection(
        &catalogue,
        &policy(role_preference.clone(), "revision-1"),
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    let right = compile_model_selection(
        &catalogue,
        &policy(role_preference, "revision-2"),
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    assert_ne!(left.selection_digest, right.selection_digest);
    Ok(())
}

fn telemetry(state: CoordinatedAttemptState) -> Result<AttemptTelemetryInput, Box<dyn Error>> {
    Ok(AttemptTelemetryInput {
        attempt_id: AttemptId::new("attempt-1")?,
        state,
        observed_at_unix_ms: NOW,
        started_at_unix_ms: NOW - 1_000,
        last_heartbeat_unix_ms: Some(NOW - 10),
        heartbeat_timeout_ms: 100,
        lease_expires_at_unix_ms: NOW + 1_000,
        deadline_unix_ms: NOW + 2_000,
        process: ProcessObservation::Alive,
        quota: quota(QuotaDisposition::Available),
        effect: AttemptEffectObservation::NoneObserved,
        open_descendants: 0,
    })
}

#[test]
fn stale_heartbeat_and_deadline_overrun_remain_distinct() -> TestResult {
    let mut stale = telemetry(CoordinatedAttemptState::Running)?;
    stale.last_heartbeat_unix_ms = Some(NOW - 1_000);
    let stale_projection = project_attempt_health(&stale, NOW)?;
    assert_eq!(
        stale_projection.status,
        AttemptLivenessStatus::HeartbeatStale
    );

    let mut overdue = telemetry(CoordinatedAttemptState::Running)?;
    overdue.deadline_unix_ms = NOW - 1;
    let overdue_projection = project_attempt_health(&overdue, NOW)?;
    assert_eq!(
        overdue_projection.status,
        AttemptLivenessStatus::DeadlineExceeded
    );
    Ok(())
}

#[test]
fn heartbeat_exactly_at_timeout_remains_live() -> TestResult {
    let mut input = telemetry(CoordinatedAttemptState::Running)?;
    input.last_heartbeat_unix_ms = Some(NOW - input.heartbeat_timeout_ms);

    let projection = project_attempt_health(&input, NOW)?;
    assert_eq!(projection.status, AttemptLivenessStatus::Live);
    Ok(())
}

#[test]
fn unknown_process_is_not_eligible_for_work() -> TestResult {
    let mut input = telemetry(CoordinatedAttemptState::Running)?;
    input.process = ProcessObservation::Unknown;
    let projection = project_attempt_health(&input, NOW)?;
    assert_eq!(projection.status, AttemptLivenessStatus::ProcessUnknown);
    assert_eq!(
        projection.work_eligibility,
        AttemptWorkEligibility::Ineligible
    );
    assert!(
        projection
            .alerts
            .contains(&AttemptAlertCode::ProcessUnknown)
    );
    Ok(())
}

#[test]
fn terminal_attempt_is_not_reported_live() -> TestResult {
    let input = telemetry(CoordinatedAttemptState::CandidateResultSubmitted)?;
    let projection = project_attempt_health(&input, NOW)?;
    assert_eq!(projection.status, AttemptLivenessStatus::Terminal);
    assert_eq!(
        projection.work_eligibility,
        AttemptWorkEligibility::Ineligible
    );
    assert_eq!(
        projection.terminal_reconciliation,
        AttemptTerminalReconciliation::ReconciledCandidate
    );
    assert_eq!(
        projection.automation,
        AttemptAutomationDisposition::ManualOnly
    );
    Ok(())
}

#[test]
fn query_and_selection_never_claim_execution() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "free",
        "provider-a",
        "model-a",
        "family-a",
        BillingClass::Free,
        QuotaDisposition::Available,
        1,
    )]);
    let query_receipt = query_model_catalogue(&catalogue, &query(false), NOW)?;
    let selection_receipt = compile_model_selection(
        &catalogue,
        &policy(
            preference(
                ModelRole::Worker,
                Vec::new(),
                Vec::new(),
                BTreeSet::from([BillingClass::Free]),
                false,
            ),
            "revision-1",
        ),
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    assert_eq!(query_receipt.execution, ZeroModelExecutionCounters::zero());
    assert_eq!(
        selection_receipt.execution,
        ZeroModelExecutionCounters::zero()
    );
    assert!(selection_receipt.candidate_only);
    assert!(!selection_receipt.dispatch_authority);
    Ok(())
}
