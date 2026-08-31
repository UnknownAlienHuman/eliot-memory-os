use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, HumanModelPreferencePolicy, MODEL_CATALOGUE_SCHEMA_VERSION,
    MODEL_PREFERENCE_SCHEMA_VERSION, ModelAvailability, ModelCatalogueEntry,
    ModelCatalogueSnapshot, ModelControlError, ModelQuery, ModelRole, QuotaDisposition,
    QuotaObservation, RoleModelPreference, RouteAdmissionStatus, RouteHealthStatus,
    SelectionRejection, compile_model_selection, query_model_catalogue,
};

const NOW: u64 = 10_000;

fn route(model: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: "opencode".to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: "runtime-v1".to_owned(),
        adapter_hash: "adapter-v1".to_owned(),
        provider: "provider-a".to_owned(),
        model: model.to_owned(),
        auth_billing: "account-scope-1".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn entry(model: &str, role_eligibility: BTreeSet<ModelRole>) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: format!("entry-{model}"),
        account_scope: "account-scope-1".to_owned(),
        host_family: "opencode".to_owned(),
        provider_id: "provider-a".to_owned(),
        model_id: model.to_owned(),
        model_family: "family-a".to_owned(),
        route: route(model),
        route_admission: RouteAdmissionStatus::Admitted,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: BillingClass::Free,
            source: "test-billing".to_owned(),
            receipt_ref: format!("billing-{model}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "test-quota".to_owned(),
            receipt_ref: format!("quota-{model}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(1),
        },
        context_window: 128_000,
        cost_class: 0,
        latency_class: 0,
        capabilities: BTreeMap::new(),
        role_eligibility,
        evidence_refs: vec![format!("evidence-{model}")],
    }
}

fn snapshot(entries: Vec<ModelCatalogueEntry>) -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: "catalogue-role-eligibility".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries,
    }
}

fn policy() -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: "human-policy".to_owned(),
        revision: "revision-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        roles: vec![RoleModelPreference {
            role: ModelRole::Worker,
            preferred: Vec::new(),
            denied: Vec::new(),
            allowed_billing: BTreeSet::from([BillingClass::Free]),
            allow_paid_fallback: false,
            allow_degraded_routes: false,
            minimum_context_window: 1,
            maximum_cost_class: 10,
            maximum_latency_class: 10,
            required_capabilities: BTreeSet::new(),
        }],
    }
}

#[test]
fn empty_role_eligibility_does_not_expand_to_worker() {
    let catalogue = snapshot(vec![entry("model-empty", BTreeSet::new())]);

    assert!(matches!(
        compile_model_selection(
            &catalogue,
            &policy(),
            ModelRole::Worker,
            "selection-empty-role",
            NOW,
        ),
        Err(ModelControlError::NoDispatchableRoute(ModelRole::Worker))
    ));
}

#[test]
fn empty_role_entry_remains_visible_to_catalogue_queries() -> Result<(), ModelControlError> {
    let catalogue = snapshot(vec![entry("model-empty", BTreeSet::new())]);
    let receipt = query_model_catalogue(
        &catalogue,
        &ModelQuery {
            query_id: "query-empty-role".to_owned(),
            text: None,
            free_only: false,
            include_subscription_included: false,
            dispatchable_only: false,
            host_families: BTreeSet::new(),
            provider_ids: BTreeSet::new(),
            required_capabilities: BTreeSet::new(),
            minimum_context_window: 1,
            limit: 10,
        },
        NOW,
    )?;

    assert_eq!(receipt.hits.len(), 1);
    assert_eq!(receipt.hits[0].entry.model_id, "model-empty");
    Ok(())
}

#[test]
fn mixed_catalogue_rejects_empty_role_and_selects_explicit_worker(
) -> Result<(), ModelControlError> {
    let catalogue = snapshot(vec![
        entry("model-empty", BTreeSet::new()),
        entry("model-worker", BTreeSet::from([ModelRole::Worker])),
    ]);

    let receipt = compile_model_selection(
        &catalogue,
        &policy(),
        ModelRole::Worker,
        "selection-mixed-role",
        NOW,
    )?;

    assert_eq!(receipt.selected.model_id, "model-worker");
    let rejected = receipt
        .rejected
        .iter()
        .find(|candidate| candidate.model_id == "model-empty")
        .expect("empty-role entry must remain visible as a rejected candidate");
    assert!(
        rejected
            .reasons
            .contains(&SelectionRejection::RoleNotEligible)
    );
    Ok(())
}
