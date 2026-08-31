use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, HumanModelPreferencePolicy, MODEL_CATALOGUE_SCHEMA_VERSION,
    MODEL_PREFERENCE_SCHEMA_VERSION, ModelAvailability, ModelCatalogueEntry,
    ModelCatalogueSnapshot, ModelRole, ModelSelector, QuotaDisposition, QuotaObservation,
    RoleModelPreference, RouteAdmissionStatus, RouteHealthStatus, compile_model_selection,
};

const NOW: u64 = 10_000;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
        reasoning_mode: "default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn entry(entry_id: &str, provider: &str, model: &str, cost_class: u16) -> ModelCatalogueEntry {
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
            class: BillingClass::Free,
            source: "test-billing".to_owned(),
            receipt_ref: format!("billing-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "test-quota".to_owned(),
            receipt_ref: format!("quota-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(1),
        },
        context_window: 128_000,
        cost_class,
        latency_class: 0,
        capabilities: BTreeMap::new(),
        role_eligibility: BTreeSet::from([ModelRole::Worker]),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    }
}

fn snapshot() -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: "catalogue-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries: vec![
            entry("entry-a", "provider-a", "model-a", 0),
            entry("entry-b", "provider-b", "model-b", 1),
        ],
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

fn role_preference(role: ModelRole) -> RoleModelPreference {
    RoleModelPreference {
        role,
        preferred: vec![selector("model-a")],
        denied: Vec::new(),
        allowed_billing: BTreeSet::from([BillingClass::Free]),
        allow_paid_fallback: false,
        allow_degraded_routes: false,
        minimum_context_window: 1,
        maximum_cost_class: 10,
        maximum_latency_class: 10,
        required_capabilities: BTreeSet::new(),
    }
}

fn policy(denied: Vec<ModelSelector>) -> HumanModelPreferencePolicy {
    let mut worker = role_preference(ModelRole::Worker);
    worker.denied = denied;
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: "human-policy".to_owned(),
        revision: "revision-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        roles: vec![worker],
    }
}

fn compile(
    catalogue: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
) -> TestResult<eliot_agent_coordinator::ModelSelectionReceipt> {
    Ok(compile_model_selection(
        catalogue,
        policy,
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?)
}

#[test]
fn exact_preference_bytes_change_selection_identity_even_when_selection_is_unchanged() -> TestResult
{
    let catalogue = snapshot();
    let denied_b = compile(&catalogue, &policy(vec![selector("model-b")]))?;
    let allowed_b = compile(&catalogue, &policy(Vec::new()))?;

    assert_eq!(denied_b.selected.entry_id, "entry-a");
    assert_eq!(allowed_b.selected.entry_id, "entry-a");
    assert_ne!(denied_b.rejected, allowed_b.rejected);
    assert_ne!(
        denied_b.preference_policy_digest,
        allowed_b.preference_policy_digest
    );
    assert_ne!(
        denied_b.selection_digest, allowed_b.selection_digest,
        "different Human preference bytes under the same ID/revision must not share a selection identity"
    );
    Ok(())
}

#[test]
fn order_insensitive_policy_collections_have_one_identity() -> TestResult {
    let catalogue = snapshot();
    let mut first = policy(vec![selector("model-b"), selector("model-z")]);
    first.roles.push(role_preference(ModelRole::Verifier));

    let mut second = policy(vec![selector("model-z"), selector("model-b")]);
    second.roles.insert(0, role_preference(ModelRole::Verifier));

    let first = compile(&catalogue, &first)?;
    let second = compile(&catalogue, &second)?;
    assert_eq!(first.preference_policy_digest, second.preference_policy_digest);
    assert_eq!(first.selection_digest, second.selection_digest);
    Ok(())
}

#[test]
fn preferred_order_remains_identity_bearing() -> TestResult {
    let catalogue = snapshot();
    let mut first = policy(Vec::new());
    first.roles[0].preferred = vec![selector("model-a"), selector("model-b")];

    let mut second = first.clone();
    second.roles[0].preferred.reverse();

    let first = compile(&catalogue, &first)?;
    let second = compile(&catalogue, &second)?;
    assert_ne!(first.preference_policy_digest, second.preference_policy_digest);
    assert_ne!(first.selection_digest, second.selection_digest);
    Ok(())
}

#[test]
fn decision_ceiling_changes_identity_without_changing_selection() -> TestResult {
    let catalogue = snapshot();
    let first = policy(Vec::new());
    let mut second = first.clone();
    second.roles[0].maximum_cost_class += 1;

    let first = compile(&catalogue, &first)?;
    let second = compile(&catalogue, &second)?;
    assert_eq!(first.selected.entry_id, second.selected.entry_id);
    assert_ne!(first.preference_policy_digest, second.preference_policy_digest);
    assert_ne!(first.selection_digest, second.selection_digest);
    Ok(())
}

#[test]
fn catalogue_permutation_does_not_change_selection_identity() -> TestResult {
    let first_catalogue = snapshot();
    let mut second_catalogue = first_catalogue.clone();
    second_catalogue.entries.reverse();
    let policy = policy(Vec::new());

    let first = compile(&first_catalogue, &policy)?;
    let second = compile(&second_catalogue, &policy)?;
    assert_eq!(first.catalogue_digest, second.catalogue_digest);
    assert_eq!(first.preference_policy_digest, second.preference_policy_digest);
    assert_eq!(first.selection_digest, second.selection_digest);
    Ok(())
}

#[test]
fn serialized_receipt_exposes_exact_policy_binding() -> TestResult {
    let receipt = compile(&snapshot(), &policy(Vec::new()))?;
    let value = serde_json::to_value(&receipt)?;
    assert_eq!(
        value["preference_policy_digest"],
        serde_json::Value::String(receipt.preference_policy_digest)
    );
    Ok(())
}
