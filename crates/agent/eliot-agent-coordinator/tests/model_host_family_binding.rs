use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, MODEL_CATALOGUE_SCHEMA_VERSION, ModelAvailability,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError, ModelRole, QuotaDisposition,
    QuotaObservation, RouteAdmissionStatus, RouteHealthStatus,
};

const NOW: u64 = 10_000;

fn route(host_family: &str) -> RouteFingerprint {
    RouteFingerprint {
        host_family: host_family.to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
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

fn snapshot(entry_host_family: &str, route_host_family: &str) -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: "catalogue-host-family-binding".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries: vec![ModelCatalogueEntry {
            entry_id: "entry-a".to_owned(),
            account_scope: "account-scope-1".to_owned(),
            host_family: entry_host_family.to_owned(),
            provider_id: "provider-a".to_owned(),
            model_id: "model-a".to_owned(),
            model_family: "family-a".to_owned(),
            route: route(route_host_family),
            route_admission: RouteAdmissionStatus::Admitted,
            route_health: RouteHealthStatus::Healthy,
            availability: ModelAvailability::Available,
            billing: BillingEvidence {
                class: BillingClass::Free,
                source: "test-billing".to_owned(),
                receipt_ref: "billing-receipt".to_owned(),
                observed_at_unix_ms: NOW - 100,
                expires_at_unix_ms: NOW + 100,
            },
            quota: QuotaObservation {
                disposition: QuotaDisposition::Available,
                source: "test-quota".to_owned(),
                receipt_ref: "quota-receipt".to_owned(),
                observed_at_unix_ms: NOW - 100,
                expires_at_unix_ms: NOW + 100,
                reset_at_unix_ms: Some(NOW + 1_000),
                remaining_microunits: Some(1),
            },
            context_window: 128_000,
            cost_class: 0,
            latency_class: 0,
            capabilities: BTreeMap::new(),
            role_eligibility: BTreeSet::from([ModelRole::Worker]),
            evidence_refs: vec!["entry-evidence".to_owned()],
        }],
    }
}

#[test]
fn catalogue_rejects_host_family_that_disagrees_with_route_fingerprint() {
    assert_eq!(
        snapshot("codex", "opencode").validate(),
        Err(ModelControlError::InvalidField("entry.route_binding"))
    );
}

#[test]
fn catalogue_accepts_exact_host_family_route_binding() {
    assert!(snapshot("opencode", "opencode").validate().is_ok());
}
