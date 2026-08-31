use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;

use eliot_agent_api::{AttemptId, RouteFingerprint};

use super::*;
use crate::model_control::{
    ATTEMPT_HEALTH_PROJECTION_VERSION, AttemptAlertCode, AttemptEffectObservation,
    AttemptLivenessStatus, AttemptTelemetryInput, AttemptTerminalReconciliation, BillingClass,
    BillingEvidence, CapabilityObservation, CapabilityStatus, DispatchBlocker,
    HumanModelPreferencePolicy, MODEL_CATALOGUE_SCHEMA_VERSION, MODEL_PREFERENCE_SCHEMA_VERSION,
    ModelAvailability, ModelCatalogueEntry, ModelCatalogueSnapshot, ModelQuery, ModelRole,
    ModelSelectionReceipt, ModelSelector, ProcessObservation, QuotaDisposition, QuotaObservation,
    RoleModelPreference, RouteAdmissionStatus, RouteHealthStatus, ZeroModelExecutionCounters,
    compile_model_selection,
};
use crate::CoordinatedAttemptState;

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
        receipt_ref: format!("quota-{disposition:?}"),
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
    billing_class: BillingClass,
    quota_disposition: QuotaDisposition,
) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        host_family: "opencode".to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: format!("family-{provider}"),
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
        cost_class: 1,
        latency_class: 1,
        capabilities: BTreeMap::from([(
            "coding".to_owned(),
            CapabilityObservation {
                status: CapabilityStatus::Supported,
                evidence_class: "runtime_probe".to_owned(),
                receipt_ref: format!("capability-{entry_id}"),
            },
        )]),
        role_eligibility: BTreeSet::from([ModelRole::Worker]),
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

fn policy(account_scope: &str) -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: "human-model-policy-1".to_owned(),
        revision: "revision-1".to_owned(),
        account_scope: account_scope.to_owned(),
        roles: vec![RoleModelPreference {
            role: ModelRole::Worker,
            preferred: vec![ModelSelector {
                host_family: None,
                provider_id: None,
                model_id: Some("ordinary-model".to_owned()),
                model_family: None,
            }],
            denied: Vec::new(),
            allowed_billing: BTreeSet::from([BillingClass::Free]),
            allow_paid_fallback: false,
            allow_degraded_routes: false,
            minimum_context_window: 100_000,
            maximum_cost_class: 10,
            maximum_latency_class: 10,
            required_capabilities: BTreeSet::from(["coding".to_owned()]),
        }],
    }
}

fn query(free_only: bool) -> ModelQuery {
    ModelQuery {
        query_id: "operator-query-1".to_owned(),
        text: None,
        free_only,
        include_subscription_included: false,
        dispatchable_only: false,
        host_families: BTreeSet::new(),
        provider_ids: BTreeSet::new(),
        required_capabilities: BTreeSet::from(["coding".to_owned()]),
        minimum_context_window: 100_000,
        limit: 100,
    }
}

fn selected(
    catalogue: &ModelCatalogueSnapshot,
    preferences: &HumanModelPreferencePolicy,
    selection_id: &str,
) -> Result<ModelSelectionReceipt, crate::model_control::ModelControlError> {
    compile_model_selection(
        catalogue,
        preferences,
        ModelRole::Worker,
        selection_id,
        NOW,
    )
}

fn telemetry(
    selection: ModelSelectionReceipt,
    attempt_id: &str,
    open_descendants: u32,
) -> Result<SwarmAttemptTelemetryInput, Box<dyn Error>> {
    Ok(SwarmAttemptTelemetryInput {
        selection,
        telemetry: AttemptTelemetryInput {
            attempt_id: AttemptId::new(attempt_id)?,
            state: CoordinatedAttemptState::CandidateResultSubmitted,
            observed_at_unix_ms: NOW - 10,
            started_at_unix_ms: NOW - 100,
            last_heartbeat_unix_ms: Some(NOW - 20),
            heartbeat_timeout_ms: 1_000,
            lease_expires_at_unix_ms: NOW + 100,
            deadline_unix_ms: NOW + 100,
            process: ProcessObservation::Exited,
            quota: quota(QuotaDisposition::Available),
            effect: AttemptEffectObservation::KnownNotStarted,
            open_descendants,
        },
    })
}

fn input(
    catalogue: ModelCatalogueSnapshot,
    preferences: HumanModelPreferencePolicy,
    attempts: Option<Vec<SwarmAttemptTelemetryInput>>,
) -> SwarmControlBoardProjectionInput {
    SwarmControlBoardProjectionInput {
        catalogue: Some(catalogue),
        preferences: Some(preferences),
        attempt_telemetry: attempts,
    }
}

#[test]
fn free_filter_uses_billing_evidence_not_model_name() -> TestResult {
    let catalogue = snapshot(vec![
        entry(
            "paid-name-free",
            "provider-a",
            "model-free",
            BillingClass::Paid,
            QuotaDisposition::Available,
        ),
        entry(
            "actually-free",
            "provider-b",
            "ordinary-model",
            BillingClass::Free,
            QuotaDisposition::Available,
        ),
    ]);
    let view = compile_swarm_controlboard_projection(
        &input(catalogue, policy("account-scope-1"), Some(Vec::new())),
        &query(true),
        NOW,
    )?;
    let catalogue = view
        .catalogue
        .as_ref()
        .ok_or_else(|| io::Error::other("catalogue projection missing"))?;
    assert_eq!(catalogue.query.hits.len(), 1);
    assert_eq!(catalogue.query.hits[0].entry.entry_id, "actually-free");
    assert_eq!(catalogue.query.execution, ZeroModelExecutionCounters::zero());
    assert_eq!(view.execution, ZeroModelExecutionCounters::zero());
    Ok(())
}

#[test]
fn exhausted_quota_stays_visible_with_typed_dispatch_blocker() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "exhausted",
        "provider-a",
        "model-a",
        BillingClass::Free,
        QuotaDisposition::Exhausted,
    )]);
    let view = compile_swarm_controlboard_projection(
        &input(catalogue, policy("account-scope-1"), Some(Vec::new())),
        &query(false),
        NOW,
    )?;
    let catalogue = view
        .catalogue
        .as_ref()
        .ok_or_else(|| io::Error::other("catalogue projection missing"))?;
    assert_eq!(catalogue.query.hits.len(), 1);
    assert!(!catalogue.query.hits[0].dispatchable);
    assert!(
        catalogue.query.hits[0]
            .blockers
            .contains(&DispatchBlocker::QuotaExhausted)
    );
    Ok(())
}

#[test]
fn missing_providers_are_plan_gaps_not_healthy_empty_state() -> TestResult {
    let view = compile_swarm_controlboard_projection(
        &SwarmControlBoardProjectionInput {
            catalogue: None,
            preferences: None,
            attempt_telemetry: None,
        },
        &query(false),
        NOW,
    )?;
    assert!(view.catalogue.is_none());
    assert!(view.gaps.contains(&SwarmProjectionGap::ProviderUnavailable {
        provider: SwarmProjectionProvider::ModelCatalogue,
    }));
    assert!(view.gaps.contains(&SwarmProjectionGap::ProviderUnavailable {
        provider: SwarmProjectionProvider::HumanPreferences,
    }));
    assert!(view.gaps.contains(&SwarmProjectionGap::ProviderUnavailable {
        provider: SwarmProjectionProvider::AttemptTelemetry,
    }));
    Ok(())
}

#[test]
fn empty_catalogue_is_an_explicit_gap_not_provider_absence() -> TestResult {
    let view = compile_swarm_controlboard_projection(
        &input(
            snapshot(Vec::new()),
            policy("account-scope-1"),
            Some(Vec::new()),
        ),
        &query(false),
        NOW,
    )?;
    assert!(view.catalogue.is_some());
    assert!(view.gaps.contains(&SwarmProjectionGap::CatalogueEmpty));
    assert!(!view.gaps.contains(&SwarmProjectionGap::ProviderUnavailable {
        provider: SwarmProjectionProvider::ModelCatalogue,
    }));
    Ok(())
}

#[test]
fn terminal_attempt_with_descendants_keeps_closure_alerts() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "attempt-entry",
        "provider-a",
        "model-a",
        BillingClass::Free,
        QuotaDisposition::Available,
    )]);
    let preferences = policy("account-scope-1");
    let selection = selected(&catalogue, &preferences, "selection-1")?;
    let view = compile_swarm_controlboard_projection(
        &input(
            catalogue,
            preferences,
            Some(vec![telemetry(selection, "attempt-1", 1)?]),
        ),
        &query(false),
        NOW,
    )?;
    let attempt = view
        .attempts
        .first()
        .ok_or_else(|| io::Error::other("attempt projection missing"))?;
    assert_eq!(
        attempt.health.schema_version,
        ATTEMPT_HEALTH_PROJECTION_VERSION
    );
    assert_eq!(attempt.health.status, AttemptLivenessStatus::Terminal);
    assert!(
        attempt
            .health
            .alerts
            .contains(&AttemptAlertCode::DescendantsOpen)
    );
    assert!(
        attempt
            .health
            .alerts
            .contains(&AttemptAlertCode::TerminalWithOpenDescendants)
    );
    assert_eq!(
        attempt.health.terminal_reconciliation,
        AttemptTerminalReconciliation::Unreconciled
    );
    assert_eq!(
        attempt.selection_binding,
        SwarmAttemptSelectionBinding::ExactCurrent
    );
    assert_eq!(
        view.authority_ceiling,
        SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly
    );
    Ok(())
}

#[test]
fn catalogue_and_preference_scope_mismatch_fails_closed() {
    let input = SwarmControlBoardProjectionInput {
        catalogue: Some(snapshot(Vec::new())),
        preferences: Some(policy("different-account")),
        attempt_telemetry: Some(Vec::new()),
    };
    assert_eq!(
        compile_swarm_controlboard_projection(&input, &query(false), NOW),
        Err(SwarmControlBoardProjectionError::InvalidField(
            "account_scope"
        ))
    );
}

#[test]
fn tampered_selection_receipt_fails_closed() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "attempt-entry",
        "provider-a",
        "model-a",
        BillingClass::Free,
        QuotaDisposition::Available,
    )]);
    let preferences = policy("account-scope-1");
    let mut selection = selected(&catalogue, &preferences, "selection-1")?;
    selection.selected.route.model = "different-model".to_owned();
    let result = compile_swarm_controlboard_projection(
        &input(
            catalogue,
            preferences,
            Some(vec![telemetry(selection, "attempt-1", 0)?]),
        ),
        &query(false),
        NOW,
    );
    assert!(matches!(
        result,
        Err(SwarmControlBoardProjectionError::ModelControl(_))
    ));
    Ok(())
}

#[test]
fn current_selection_is_bound_to_exact_catalogue_and_human_policy() -> TestResult {
    let catalogue = snapshot(vec![entry(
        "attempt-entry",
        "provider-a",
        "model-a",
        BillingClass::Free,
        QuotaDisposition::Available,
    )]);
    let preferences = policy("account-scope-1");
    let selection = selected(&catalogue, &preferences, "selection-1")?;
    let expected_digest = selection.preference_policy_digest.clone();
    let view = compile_swarm_controlboard_projection(
        &input(
            catalogue,
            preferences,
            Some(vec![telemetry(selection, "attempt-1", 0)?]),
        ),
        &query(false),
        NOW,
    )?;
    let attempt = view
        .attempts
        .first()
        .ok_or_else(|| io::Error::other("attempt projection missing"))?;
    assert_eq!(
        attempt.selection_binding,
        SwarmAttemptSelectionBinding::ExactCurrent
    );
    assert_eq!(attempt.account_scope, "account-scope-1");
    assert_eq!(attempt.role, ModelRole::Worker);
    assert_eq!(attempt.catalogue_snapshot_id, "catalogue-1");
    assert_eq!(attempt.preference_policy_id, "human-model-policy-1");
    assert_eq!(attempt.preference_revision, "revision-1");
    assert_eq!(attempt.selected.route.model, "model-a");
    assert_eq!(attempt.preference_policy_digest, expected_digest);
    Ok(())
}

#[test]
fn stale_selection_remains_visible_without_becoming_current_authority() -> TestResult {
    let original = snapshot(vec![entry(
        "attempt-entry",
        "provider-a",
        "model-a",
        BillingClass::Free,
        QuotaDisposition::Available,
    )]);
    let preferences = policy("account-scope-1");
    let selection = selected(&original, &preferences, "selection-1")?;
    let current = snapshot(vec![entry(
        "replacement-entry",
        "provider-b",
        "model-b",
        BillingClass::Free,
        QuotaDisposition::Available,
    )]);
    let view = compile_swarm_controlboard_projection(
        &input(
            current,
            preferences,
            Some(vec![telemetry(selection, "attempt-1", 0)?]),
        ),
        &query(false),
        NOW,
    )?;
    let attempt = view
        .attempts
        .first()
        .ok_or_else(|| io::Error::other("attempt projection missing"))?;
    assert_eq!(
        attempt.selection_binding,
        SwarmAttemptSelectionBinding::StaleOrMismatched
    );
    assert_eq!(
        view.authority_ceiling,
        SwarmProjectionAuthorityCeiling::UnfilteredReadModelOnly
    );
    Ok(())
}

#[test]
fn dispatchable_only_query_cannot_hide_operator_blockers() {
    let mut hidden = query(false);
    hidden.dispatchable_only = true;
    assert_eq!(
        compile_swarm_controlboard_projection(
            &SwarmControlBoardProjectionInput {
                catalogue: Some(snapshot(Vec::new())),
                preferences: Some(policy("account-scope-1")),
                attempt_telemetry: Some(Vec::new()),
            },
            &hidden,
            NOW,
        ),
        Err(SwarmControlBoardProjectionError::InvalidField(
            "query.dispatchable_only"
        ))
    );
}
