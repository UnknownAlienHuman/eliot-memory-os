use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use eliot_agent_api::{AuthorityEpoch, ResourceGeneration, RouteFingerprint, StateFence};
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, CapabilityObservation, CapabilityStatus, CheckDisposition,
    ModelAvailability, ModelCatalogueEntry, ModelCatalogueSnapshot, ModelRegistrySnapshot,
    ModelRole, QuotaDisposition, QuotaObservation, RankingDimension, RankingDisposition,
    RankingPolicy, RouteAdmissionStatus, RouteHealthStatus, RouteRequirements,
    compile_model_selection, find_models,
};

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

fn entry(id: &str, provider: &str, model: &str, cost_class: u16) -> ModelCatalogueEntry {
    ModelCatalogueEntry {
        entry_id: id.to_owned(),
        account_scope: "account-scope-1".to_owned(),
        host_family: "opencode".to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: "family".to_owned(),
        route: route(provider, model, id),
        route_admission: RouteAdmissionStatus::Admitted,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: BillingClass::Free,
            source: "catalogue".to_owned(),
            receipt_ref: format!("billing-{id}"),
            observed_at_unix_ms: NOW - 10,
            expires_at_unix_ms: NOW + 10,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "catalogue".to_owned(),
            receipt_ref: format!("quota-{id}"),
            observed_at_unix_ms: NOW - 10,
            expires_at_unix_ms: NOW + 10,
            reset_at_unix_ms: None,
            remaining_microunits: Some(100),
        },
        context_window: 200_000,
        cost_class,
        latency_class: 1,
        capabilities: BTreeMap::from([(
            "coding".to_owned(),
            CapabilityObservation {
                status: CapabilityStatus::Supported,
                evidence_class: "runtime_probe".to_owned(),
                receipt_ref: format!("capability-{id}"),
            },
        )]),
        role_eligibility: BTreeSet::from([ModelRole::Worker]),
        evidence_refs: vec![format!("evidence-{id}")],
    }
}

fn catalogue(entries: Vec<ModelCatalogueEntry>) -> ModelCatalogueSnapshot {
    ModelCatalogueSnapshot {
        schema_version: "eliot.agent-model-catalogue/v1".to_owned(),
        snapshot_id: "catalogue-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        collector_identity: "collector-v1".to_owned(),
        observed_at_unix_ms: NOW - 10,
        expires_at_unix_ms: NOW + 10,
        entries,
    }
}

fn requirements() -> Result<RouteRequirements, Box<dyn Error>> {
    Ok(RouteRequirements::new(
        "task-1",
        "attempt-1",
        "scope-1",
        StateFence::new(AuthorityEpoch::new(1)?, ResourceGeneration::new(1)?),
        "policy-1",
        NOW,
    ))
}

#[test]
fn denominator_retains_missing_expected_route() -> Result<(), Box<dyn Error>> {
    let present = entry("present", "provider-a", "model-a", 1);
    let missing = route("provider-b", "model-b", "missing");
    let snapshot = ModelRegistrySnapshot::with_expected_routes(
        &catalogue(vec![present]),
        vec![route("provider-a", "model-a", "present"), missing],
    )?;

    assert_eq!(snapshot.expected_route_count, 2);
    assert_eq!(snapshot.missing_route_count(), 1);
    assert!(!snapshot.complete());
    let result = find_models(
        &snapshot,
        &requirements()?,
        RankingPolicy::new("r1", vec![RankingDimension::RouteIdentity]),
    )?;
    assert_eq!(result.explanations.len(), 2);
    assert_eq!(result.missing_route_count, 1);
    assert!(
        result
            .explanations
            .iter()
            .any(|explanation| explanation.entry_id.is_none())
    );
    Ok(())
}

#[test]
fn hard_failure_and_missing_evidence_are_retained_together() -> Result<(), Box<dyn Error>> {
    let mut blocked = entry("blocked", "provider-a", "model-a", 1);
    blocked.route_admission = RouteAdmissionStatus::Rejected;
    let mut requirements = requirements()?;
    requirements
        .required_capabilities
        .insert("vision".to_owned());
    let snapshot = ModelRegistrySnapshot::from_catalogue(&catalogue(vec![blocked]))?;
    let result = find_models(&snapshot, &requirements, None::<&RankingPolicy>)?;
    let explanation = &result.explanations[0];

    assert!(!explanation.eligible);
    assert!(
        explanation
            .failures
            .iter()
            .any(|check| check.dimension == "admission")
    );
    assert!(
        explanation
            .missing_evidence
            .iter()
            .any(|check| check.dimension == "capability:vision")
    );
    assert_eq!(result.ranking, RankingDisposition::PolicyMissing);
    assert_eq!(result.execution.model_calls, 0);
    Ok(())
}

#[test]
fn supplied_lexicographic_policy_ranks_only_eligible_routes() -> Result<(), Box<dyn Error>> {
    let expensive = entry("expensive", "provider-a", "model-a", 2);
    let cheap = entry("cheap", "provider-b", "model-b", 1);
    let snapshot = ModelRegistrySnapshot::from_catalogue(&catalogue(vec![expensive, cheap]))?;
    let result = find_models(
        &snapshot,
        &requirements()?,
        RankingPolicy::new("r1", vec![RankingDimension::CostClass]),
    )?;

    assert_eq!(result.ranking, RankingDisposition::Ranked);
    assert_eq!(result.eligible[0].entry_id, "cheap");
    assert!(result.explanations.iter().all(|explanation| {
        explanation
            .checks
            .iter()
            .all(|check| check.disposition != CheckDisposition::Missing)
    }));
    Ok(())
}

#[test]
fn model_control_uses_registry_facade_and_keeps_candidate_boundary() -> Result<(), Box<dyn Error>> {
    let model = entry("model", "provider-a", "model-a", 1);
    let catalogue = catalogue(vec![model]);
    let preference = eliot_agent_coordinator::HumanModelPreferencePolicy {
        schema_version: "eliot.agent-model-preference/v1".to_owned(),
        policy_id: "policy-1".to_owned(),
        revision: "revision-1".to_owned(),
        account_scope: "account-scope-1".to_owned(),
        roles: vec![eliot_agent_coordinator::RoleModelPreference {
            role: ModelRole::Worker,
            preferred: Vec::new(),
            denied: Vec::new(),
            allowed_billing: BTreeSet::from([BillingClass::Free]),
            allow_paid_fallback: false,
            allow_degraded_routes: false,
            minimum_context_window: 100_000,
            maximum_cost_class: 10,
            maximum_latency_class: 10,
            required_capabilities: BTreeSet::from(["coding".to_owned()]),
        }],
    };
    let receipt = compile_model_selection(
        &catalogue,
        &preference,
        ModelRole::Worker,
        "selection-1",
        NOW,
    )?;
    assert_eq!(receipt.selected.entry_id, "model");
    assert!(receipt.candidate_only);
    assert!(!receipt.dispatch_authority);
    assert_eq!(receipt.execution.model_calls, 0);
    Ok(())
}
