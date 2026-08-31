use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, MODEL_CATALOGUE_SCHEMA_VERSION, ModelAvailability,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError, QuotaDisposition,
    QuotaObservation, RouteAdmissionStatus, RouteHealthStatus,
};

const NOW: u64 = 10_000;

fn route(host_family: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: host_family.to_owned(),
        adapter: format!("eliot-agent-{host_family}"),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: "runtime-v1".to_owned(),
        adapter_hash: "adapter-v1".to_owned(),
        provider: "provider-a".to_owned(),
        model: "model-a".to_owned(),
        auth_billing: "account-scope-1".to_owned(),
        serializer_hash: "serializer-v1".to_owned(),
        tool_semantics_hash: "tools-v1".to_owned(),
        reasoning_mode: "default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: "features-v1".to_owned(),
    }
}

fn entry(entry_id: &str, host_family: &str) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        host_family: host_family.to_owned(),
        provider_id: "provider-a".to_owned(),
        model_id: "model-a".to_owned(),
        model_family: "family-a".to_owned(),
        route: route(host_family),
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
        cost_class: 0,
        latency_class: 0,
        capabilities: BTreeMap::new(),
        role_eligibility: BTreeSet::new(),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    }
}

fn snapshot(entry: ModelCatalogueEntry) -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: "catalogue-host-family-binding".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries: vec![entry],
    }
}

#[test]
fn public_catalogue_validation_requires_exact_host_family_binding() {
    assert_eq!(snapshot(entry("exact", "opencode")).validate(), Ok(()));

    let mut mismatched = entry("mismatched", "opencode");
    mismatched.host_family = "codex".to_owned();
    assert_eq!(
        snapshot(mismatched).validate(),
        Err(ModelControlError::InvalidField("entry.route_binding"))
    );
}
