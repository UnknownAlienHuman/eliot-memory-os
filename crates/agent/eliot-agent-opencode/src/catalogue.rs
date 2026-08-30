use eliot_agent_api::RouteFingerprint;
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, CapabilityObservation, CapabilityStatus,
    MODEL_CATALOGUE_SCHEMA_VERSION, ModelAvailability, ModelCatalogueEntry, ModelCatalogueSnapshot,
    ModelControlError, ModelRole, QuotaObservation, RouteAdmissionStatus, RouteHealthStatus,
    ZeroModelExecutionCounters,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

use crate::{HealthResponse, OpenCodeClient, OpenCodeRunError, ProviderCatalog, ProviderModel};

pub const OPENCODE_CATALOGUE_CONTEXT_VERSION: &str = "eliot.opencode-model-catalogue-context/v1";
pub const OPENCODE_CATALOGUE_COLLECTION_VERSION: &str =
    "eliot.opencode-model-catalogue-collection/v1";
pub const OPENCODE_HOST_FAMILY: &str = "opencode";
pub const OPENCODE_ADAPTER_ID: &str = "eliot-agent-opencode";
pub const OPENCODE_PROTOCOL_TRANSPORT: &str = "http+sse";

const MAX_EVIDENCE_REFS: usize = 256;
const MAX_PROVIDER_POLICIES: usize = 256;
const MAX_MODEL_OVERRIDES: usize = 1024;

#[derive(Debug, Error)]
pub enum OpenCodeCatalogueError {
    #[error(transparent)]
    Run(#[from] OpenCodeRunError),
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error("invalid OpenCode catalogue field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate OpenCode catalogue identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("OpenCode catalogue evidence set exceeds its bound")]
    EvidenceLimit,
}

fn text(value: &str, field: &'static str) -> Result<(), OpenCodeCatalogueError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OpenCodeCatalogueError::InvalidField(field));
    }
    Ok(())
}

fn window(
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    field: &'static str,
) -> Result<(), OpenCodeCatalogueError> {
    if observed_at_unix_ms == 0 || expires_at_unix_ms < observed_at_unix_ms {
        return Err(OpenCodeCatalogueError::InvalidField(field));
    }
    Ok(())
}

fn evidence_refs(groups: Vec<Vec<String>>) -> Result<Vec<String>, OpenCodeCatalogueError> {
    let mut refs = BTreeSet::new();
    for group in groups {
        for reference in group {
            text(&reference, "evidence_ref")?;
            refs.insert(reference);
            if refs.len() > MAX_EVIDENCE_REFS {
                return Err(OpenCodeCatalogueError::EvidenceLimit);
            }
        }
    }
    Ok(refs.into_iter().collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeBillingMode {
    CataloguePrice,
    Free,
    SubscriptionIncluded,
    Paid,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeRouteTemplate {
    pub runtime_hash: String,
    pub adapter_hash: String,
    pub auth_billing: String,
    pub serializer_hash: String,
    pub tool_semantics_hash: String,
    pub reasoning_mode: String,
    pub continuation_behavior: String,
    pub feature_flags_hash: String,
}

impl OpenCodeRouteTemplate {
    fn validate(&self) -> Result<(), OpenCodeCatalogueError> {
        for (value, field) in [
            (self.runtime_hash.as_str(), "route.runtime_hash"),
            (self.adapter_hash.as_str(), "route.adapter_hash"),
            (self.auth_billing.as_str(), "route.auth_billing"),
            (self.serializer_hash.as_str(), "route.serializer_hash"),
            (
                self.tool_semantics_hash.as_str(),
                "route.tool_semantics_hash",
            ),
            (self.reasoning_mode.as_str(), "route.reasoning_mode"),
            (
                self.continuation_behavior.as_str(),
                "route.continuation_behavior",
            ),
            (self.feature_flags_hash.as_str(), "route.feature_flags_hash"),
        ] {
            text(value, field)?;
        }
        Ok(())
    }

    fn route(&self, provider: &str, model: &str) -> RouteFingerprint {
        RouteFingerprint {
            host_family: OPENCODE_HOST_FAMILY.to_owned(),
            adapter: OPENCODE_ADAPTER_ID.to_owned(),
            protocol_transport: OPENCODE_PROTOCOL_TRANSPORT.to_owned(),
            runtime_hash: self.runtime_hash.clone(),
            adapter_hash: self.adapter_hash.clone(),
            provider: provider.to_owned(),
            model: model.to_owned(),
            auth_billing: self.auth_billing.clone(),
            serializer_hash: self.serializer_hash.clone(),
            tool_semantics_hash: self.tool_semantics_hash.clone(),
            reasoning_mode: self.reasoning_mode.clone(),
            continuation_behavior: self.continuation_behavior.clone(),
            feature_flags_hash: self.feature_flags_hash.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeProviderRoutePolicy {
    pub route: OpenCodeRouteTemplate,
    pub route_admission: RouteAdmissionStatus,
    pub route_health: RouteHealthStatus,
    pub billing_mode: OpenCodeBillingMode,
    pub model_billing_overrides: BTreeMap<String, OpenCodeBillingMode>,
    pub billing_source: String,
    pub billing_receipt_ref: String,
    pub quota: QuotaObservation,
    pub cost_class: u16,
    pub latency_class: u16,
    pub role_eligibility: BTreeSet<ModelRole>,
    pub evidence_refs: Vec<String>,
}

impl OpenCodeProviderRoutePolicy {
    fn validate(&self) -> Result<(), OpenCodeCatalogueError> {
        self.route.validate()?;
        text(&self.billing_source, "policy.billing_source")?;
        text(&self.billing_receipt_ref, "policy.billing_receipt_ref")?;
        text(&self.quota.source, "policy.quota.source")?;
        text(&self.quota.receipt_ref, "policy.quota.receipt_ref")?;
        window(
            self.quota.observed_at_unix_ms,
            self.quota.expires_at_unix_ms,
            "policy.quota.window",
        )?;
        if self.model_billing_overrides.len() > MAX_MODEL_OVERRIDES {
            return Err(OpenCodeCatalogueError::InvalidField(
                "policy.model_billing_overrides",
            ));
        }
        for model in self.model_billing_overrides.keys() {
            text(model, "policy.model_id")?;
        }
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(OpenCodeCatalogueError::EvidenceLimit);
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            text(reference, "policy.evidence_ref")?;
            if !seen.insert(reference) {
                return Err(OpenCodeCatalogueError::DuplicateIdentity(
                    "policy.evidence_ref",
                ));
            }
        }
        Ok(())
    }

    fn billing_mode(&self, model_id: &str) -> OpenCodeBillingMode {
        self.model_billing_overrides
            .get(model_id)
            .copied()
            .unwrap_or(self.billing_mode)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeCatalogueContext {
    pub schema_version: String,
    pub snapshot_id: String,
    pub account_scope: String,
    pub collector_identity: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub health_receipt_ref: String,
    pub catalogue_receipt_ref: String,
    pub provider_policies: BTreeMap<String, OpenCodeProviderRoutePolicy>,
    pub evidence_refs: Vec<String>,
}

impl OpenCodeCatalogueContext {
    pub fn validate(&self) -> Result<(), OpenCodeCatalogueError> {
        if self.schema_version != OPENCODE_CATALOGUE_CONTEXT_VERSION {
            return Err(OpenCodeCatalogueError::InvalidField("schema_version"));
        }
        text(&self.snapshot_id, "snapshot_id")?;
        text(&self.account_scope, "account_scope")?;
        text(&self.collector_identity, "collector_identity")?;
        text(&self.health_receipt_ref, "health_receipt_ref")?;
        text(&self.catalogue_receipt_ref, "catalogue_receipt_ref")?;
        window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "catalogue.window",
        )?;
        if self.provider_policies.len() > MAX_PROVIDER_POLICIES
            || self.evidence_refs.len() > MAX_EVIDENCE_REFS
        {
            return Err(OpenCodeCatalogueError::EvidenceLimit);
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            text(reference, "catalogue.evidence_ref")?;
            if !seen.insert(reference) {
                return Err(OpenCodeCatalogueError::DuplicateIdentity(
                    "catalogue.evidence_ref",
                ));
            }
        }
        for (provider, policy) in &self.provider_policies {
            text(provider, "provider_id")?;
            policy.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeCatalogueOmissionReason {
    ProviderDisconnected,
    MissingProviderPolicy,
    ConflictingModelIdentity,
    MissingContextWindow,
    InvalidModelMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeCatalogueOmission {
    pub provider_id: String,
    pub model_key: String,
    pub reason: OpenCodeCatalogueOmissionReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeCatalogueCollection {
    pub schema_version: String,
    pub snapshot: ModelCatalogueSnapshot,
    pub omissions: Vec<OpenCodeCatalogueOmission>,
    pub execution: ZeroModelExecutionCounters,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ProviderModelRoutingMetadata {
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    attachment: Option<bool>,
    #[serde(default)]
    reasoning: Option<bool>,
    #[serde(default, alias = "toolCall")]
    tool_call: Option<bool>,
    #[serde(default, alias = "structuredOutput")]
    structured_output: Option<bool>,
    #[serde(default)]
    cost: Option<ProviderModelCost>,
    #[serde(default)]
    limit: Option<ProviderModelLimit>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ProviderModelCost {
    #[serde(default)]
    input: Option<Number>,
    #[serde(default)]
    output: Option<Number>,
    #[serde(default)]
    reasoning: Option<Number>,
    #[serde(default, alias = "cacheRead")]
    cache_read: Option<Number>,
    #[serde(default, alias = "cacheWrite")]
    cache_write: Option<Number>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ProviderModelLimit {
    #[serde(default)]
    context: Option<u64>,
}

fn routing_metadata(
    model: &ProviderModel,
) -> Result<ProviderModelRoutingMetadata, OpenCodeCatalogueError> {
    let object = model
        .extra
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<String, Value>>();
    serde_json::from_value(Value::Object(object))
        .map_err(|_| OpenCodeCatalogueError::InvalidField("provider_model.metadata"))
}

fn number_value(value: &Number) -> Option<f64> {
    value
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn catalogue_price_class(cost: Option<&ProviderModelCost>) -> BillingClass {
    let Some(cost) = cost else {
        return BillingClass::Unknown;
    };
    let Some(input) = cost.input.as_ref().and_then(number_value) else {
        return BillingClass::Unknown;
    };
    let Some(output) = cost.output.as_ref().and_then(number_value) else {
        return BillingClass::Unknown;
    };
    let optional = [
        cost.reasoning.as_ref(),
        cost.cache_read.as_ref(),
        cost.cache_write.as_ref(),
    ];
    if optional
        .iter()
        .flatten()
        .any(|value| number_value(value).is_none())
    {
        return BillingClass::Unknown;
    }
    if input > 0.0
        || output > 0.0
        || optional
            .iter()
            .flatten()
            .filter_map(|value| number_value(value))
            .any(|value| value > 0.0)
    {
        BillingClass::Paid
    } else {
        BillingClass::Free
    }
}

fn billing_class(
    mode: OpenCodeBillingMode,
    metadata: &ProviderModelRoutingMetadata,
) -> BillingClass {
    match mode {
        OpenCodeBillingMode::CataloguePrice => catalogue_price_class(metadata.cost.as_ref()),
        OpenCodeBillingMode::Free => BillingClass::Free,
        OpenCodeBillingMode::SubscriptionIncluded => BillingClass::SubscriptionIncluded,
        OpenCodeBillingMode::Paid => BillingClass::Paid,
        OpenCodeBillingMode::Unknown => BillingClass::Unknown,
    }
}

fn capability(observed: Option<bool>, receipt_ref: &str) -> CapabilityObservation {
    CapabilityObservation {
        status: match observed {
            Some(true) => CapabilityStatus::Supported,
            Some(false) => CapabilityStatus::Unsupported,
            None => CapabilityStatus::Unknown,
        },
        evidence_class: "opencode_provider_catalogue".to_owned(),
        receipt_ref: receipt_ref.to_owned(),
    }
}

fn route_health(health: &HealthResponse, configured: RouteHealthStatus) -> RouteHealthStatus {
    if health.healthy {
        configured
    } else {
        RouteHealthStatus::Unavailable
    }
}

fn availability(health: RouteHealthStatus) -> ModelAvailability {
    match health {
        RouteHealthStatus::Healthy => ModelAvailability::Available,
        RouteHealthStatus::Degraded => ModelAvailability::Degraded,
        RouteHealthStatus::Unavailable => ModelAvailability::Unavailable,
        RouteHealthStatus::Unknown => ModelAvailability::Unknown,
    }
}

fn resolved_model_id(model_key: &str, model: &ProviderModel) -> Option<String> {
    match model.id.as_deref() {
        Some(id) if id.trim().is_empty() || id != model_key => None,
        Some(id) => Some(id.to_owned()),
        None if model_key.trim().is_empty() => None,
        None => Some(model_key.to_owned()),
    }
}

pub fn compile_opencode_model_catalogue(
    health: &HealthResponse,
    providers: &ProviderCatalog,
    context: &OpenCodeCatalogueContext,
) -> Result<OpenCodeCatalogueCollection, OpenCodeCatalogueError> {
    context.validate()?;
    text(&health.version, "health.version")?;
    let connected = providers
        .connected
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    let mut omissions = Vec::new();
    let mut ordered_providers = providers.all.iter().collect::<Vec<_>>();
    ordered_providers.sort_by(|left, right| left.id.cmp(&right.id));

    for provider in ordered_providers {
        text(&provider.id, "provider.id")?;
        let is_connected = connected.contains(provider.id.as_str())
            || provider.connected.is_some_and(|value| value);
        let policy = context.provider_policies.get(&provider.id);
        let mut models = provider.models.iter().collect::<Vec<_>>();
        models.sort_by(|left, right| left.0.cmp(right.0));
        for (model_key, model) in models {
            let omission = |reason| OpenCodeCatalogueOmission {
                provider_id: provider.id.clone(),
                model_key: model_key.clone(),
                reason,
            };
            if !is_connected {
                omissions.push(omission(
                    OpenCodeCatalogueOmissionReason::ProviderDisconnected,
                ));
                continue;
            }
            let Some(policy) = policy else {
                omissions.push(omission(
                    OpenCodeCatalogueOmissionReason::MissingProviderPolicy,
                ));
                continue;
            };
            let Some(model_id) = resolved_model_id(model_key, model) else {
                omissions.push(omission(
                    OpenCodeCatalogueOmissionReason::ConflictingModelIdentity,
                ));
                continue;
            };
            let metadata = match routing_metadata(model) {
                Ok(metadata) => metadata,
                Err(_) => {
                    omissions.push(omission(
                        OpenCodeCatalogueOmissionReason::InvalidModelMetadata,
                    ));
                    continue;
                }
            };
            let context_window = metadata
                .limit
                .as_ref()
                .and_then(|limit| limit.context)
                .or(model.context_limit)
                .filter(|value| *value > 0);
            let Some(context_window) = context_window else {
                omissions.push(omission(
                    OpenCodeCatalogueOmissionReason::MissingContextWindow,
                ));
                continue;
            };
            let observed_health = route_health(health, policy.route_health);
            let billing_mode = policy.billing_mode(&model_id);
            let billing = BillingEvidence {
                class: billing_class(billing_mode, &metadata),
                source: policy.billing_source.clone(),
                receipt_ref: policy.billing_receipt_ref.clone(),
                observed_at_unix_ms: context.observed_at_unix_ms,
                expires_at_unix_ms: context.expires_at_unix_ms,
            };
            let capabilities = BTreeMap::from([
                (
                    "attachment".to_owned(),
                    capability(metadata.attachment, &context.catalogue_receipt_ref),
                ),
                (
                    "reasoning".to_owned(),
                    capability(metadata.reasoning, &context.catalogue_receipt_ref),
                ),
                (
                    "structured_output".to_owned(),
                    capability(metadata.structured_output, &context.catalogue_receipt_ref),
                ),
                (
                    "tool_call".to_owned(),
                    capability(metadata.tool_call, &context.catalogue_receipt_ref),
                ),
            ]);
            let entry_evidence = evidence_refs(vec![
                context.evidence_refs.clone(),
                policy.evidence_refs.clone(),
                vec![
                    context.health_receipt_ref.clone(),
                    context.catalogue_receipt_ref.clone(),
                    policy.billing_receipt_ref.clone(),
                    policy.quota.receipt_ref.clone(),
                ],
            ])?;
            let family = metadata
                .family
                .filter(|family| !family.trim().is_empty())
                .unwrap_or_else(|| model_id.clone());
            entries.push(ModelCatalogueEntry {
                entry_id: format!("opencode:{}:{}", provider.id, model_id),
                account_scope: context.account_scope.clone(),
                host_family: OPENCODE_HOST_FAMILY.to_owned(),
                provider_id: provider.id.clone(),
                model_id: model_id.clone(),
                model_family: family,
                route: policy.route.route(&provider.id, &model_id),
                route_admission: policy.route_admission,
                route_health: observed_health,
                availability: availability(observed_health),
                billing,
                quota: policy.quota.clone(),
                context_window,
                cost_class: policy.cost_class,
                latency_class: policy.latency_class,
                capabilities,
                role_eligibility: policy.role_eligibility.clone(),
                evidence_refs: entry_evidence,
            });
        }
    }

    entries.sort_by(|left, right| {
        (
            left.provider_id.as_str(),
            left.model_id.as_str(),
            left.entry_id.as_str(),
        )
            .cmp(&(
                right.provider_id.as_str(),
                right.model_id.as_str(),
                right.entry_id.as_str(),
            ))
    });
    omissions.sort_by(|left, right| {
        (
            left.provider_id.as_str(),
            left.model_key.as_str(),
            left.reason,
        )
            .cmp(&(
                right.provider_id.as_str(),
                right.model_key.as_str(),
                right.reason,
            ))
    });
    let snapshot = ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: context.snapshot_id.clone(),
        account_scope: context.account_scope.clone(),
        collector_identity: context.collector_identity.clone(),
        observed_at_unix_ms: context.observed_at_unix_ms,
        expires_at_unix_ms: context.expires_at_unix_ms,
        entries,
    };
    snapshot.validate()?;
    Ok(OpenCodeCatalogueCollection {
        schema_version: OPENCODE_CATALOGUE_COLLECTION_VERSION.to_owned(),
        snapshot,
        omissions,
        execution: ZeroModelExecutionCounters::zero(),
    })
}

impl OpenCodeClient {
    pub async fn model_catalogue(
        &self,
        context: &OpenCodeCatalogueContext,
    ) -> Result<OpenCodeCatalogueCollection, OpenCodeCatalogueError> {
        context.validate()?;
        let health = self.health().await?;
        let providers = self.providers().await?;
        compile_opencode_model_catalogue(&health, &providers, context)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use eliot_agent_coordinator::{
        BillingClass, ModelQuery, ModelRole, QuotaDisposition, QuotaObservation,
        RouteAdmissionStatus, RouteHealthStatus, query_model_catalogue,
    };
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;
    use crate::{
        BasicAuth, LoopbackEndpoint, OpenCodeRunPolicy, Provider, ProviderCatalog, ProviderModel,
        UnknownFields,
    };

    const NOW: u64 = 10_000;

    fn metadata(value: Value) -> UnknownFields {
        value
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    fn model(id: &str, metadata_value: Value) -> ProviderModel {
        ProviderModel {
            id: Some(id.to_owned()),
            name: Some(id.to_owned()),
            context_limit: None,
            output_limit: None,
            extra: metadata(metadata_value),
        }
    }

    fn quota(disposition: QuotaDisposition) -> QuotaObservation {
        QuotaObservation {
            disposition,
            source: "opencode-provider".to_owned(),
            receipt_ref: "quota-receipt".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(10),
        }
    }

    fn policy(mode: OpenCodeBillingMode) -> OpenCodeProviderRoutePolicy {
        OpenCodeProviderRoutePolicy {
            route: OpenCodeRouteTemplate {
                runtime_hash: "runtime-hash".to_owned(),
                adapter_hash: "adapter-hash".to_owned(),
                auth_billing: "interactive-user".to_owned(),
                serializer_hash: "serializer-hash".to_owned(),
                tool_semantics_hash: "tool-semantics-hash".to_owned(),
                reasoning_mode: "catalogue-default".to_owned(),
                continuation_behavior: "native-resume".to_owned(),
                feature_flags_hash: "feature-flags-hash".to_owned(),
            },
            route_admission: RouteAdmissionStatus::Admitted,
            route_health: RouteHealthStatus::Healthy,
            billing_mode: mode,
            model_billing_overrides: BTreeMap::new(),
            billing_source: "models.dev".to_owned(),
            billing_receipt_ref: "billing-receipt".to_owned(),
            quota: quota(QuotaDisposition::Available),
            cost_class: 1,
            latency_class: 1,
            role_eligibility: BTreeSet::from([ModelRole::Worker]),
            evidence_refs: vec!["route-policy-receipt".to_owned()],
        }
    }

    fn context(mode: OpenCodeBillingMode) -> OpenCodeCatalogueContext {
        OpenCodeCatalogueContext {
            schema_version: OPENCODE_CATALOGUE_CONTEXT_VERSION.to_owned(),
            snapshot_id: "snapshot-1".to_owned(),
            account_scope: "account-1".to_owned(),
            collector_identity: "opencode-provider-catalogue-v1".to_owned(),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            health_receipt_ref: "health-receipt".to_owned(),
            catalogue_receipt_ref: "catalogue-receipt".to_owned(),
            provider_policies: BTreeMap::from([("provider-a".to_owned(), policy(mode))]),
            evidence_refs: vec!["collector-receipt".to_owned()],
        }
    }

    fn providers(model: ProviderModel, connected: bool) -> ProviderCatalog {
        ProviderCatalog {
            all: vec![Provider {
                id: "provider-a".to_owned(),
                name: Some("Provider A".to_owned()),
                models: BTreeMap::from([(
                    model
                        .id
                        .clone()
                        .unwrap_or_else(|| "missing-model-id".to_owned()),
                    model,
                )]),
                connected: Some(connected),
                extra: BTreeMap::new(),
            }],
            default: BTreeMap::new(),
            connected: if connected {
                vec!["provider-a".to_owned()]
            } else {
                Vec::new()
            },
            extra: BTreeMap::new(),
        }
    }

    fn health() -> HealthResponse {
        HealthResponse {
            healthy: true,
            version: "1.4.3".to_owned(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn zero_catalogue_price_is_free_without_name_inference()
    -> Result<(), Box<dyn std::error::Error>> {
        let ordinary = model(
            "ordinary-model",
            json!({
                "family": "ordinary",
                "reasoning": true,
                "tool_call": true,
                "cost": {"input": 0, "output": 0},
                "limit": {"context": 200000, "output": 32000}
            }),
        );
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(ordinary, true),
            &context(OpenCodeBillingMode::CataloguePrice),
        )?;
        assert_eq!(collection.snapshot.entries.len(), 1);
        assert_eq!(
            collection.snapshot.entries[0].billing.class,
            BillingClass::Free
        );
        assert_eq!(collection.execution, ZeroModelExecutionCounters::zero());
        Ok(())
    }

    #[test]
    fn free_name_with_omitted_cost_remains_unknown() -> Result<(), Box<dyn std::error::Error>> {
        let named_free = model(
            "model-free",
            json!({"limit": {"context": 200000, "output": 32000}}),
        );
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(named_free, true),
            &context(OpenCodeBillingMode::CataloguePrice),
        )?;
        assert_eq!(
            collection.snapshot.entries[0].billing.class,
            BillingClass::Unknown
        );
        let query = ModelQuery {
            query_id: "free-query".to_owned(),
            text: None,
            free_only: true,
            include_subscription_included: false,
            dispatchable_only: false,
            host_families: BTreeSet::new(),
            provider_ids: BTreeSet::new(),
            required_capabilities: BTreeSet::new(),
            minimum_context_window: 1,
            limit: 100,
        };
        assert!(
            query_model_catalogue(&collection.snapshot, &query, NOW)?
                .hits
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn subscription_policy_overrides_zero_catalogue_price() -> Result<(), Box<dyn std::error::Error>>
    {
        let zero_price = model(
            "subscription-model",
            json!({
                "cost": {"input": 0, "output": 0},
                "limit": {"context": 200000}
            }),
        );
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(zero_price, true),
            &context(OpenCodeBillingMode::SubscriptionIncluded),
        )?;
        assert_eq!(
            collection.snapshot.entries[0].billing.class,
            BillingClass::SubscriptionIncluded
        );
        Ok(())
    }

    #[test]
    fn disconnected_provider_is_omitted() -> Result<(), Box<dyn std::error::Error>> {
        let available = model(
            "model-a",
            json!({
                "cost": {"input": 0, "output": 0},
                "limit": {"context": 200000}
            }),
        );
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(available, false),
            &context(OpenCodeBillingMode::CataloguePrice),
        )?;
        assert!(collection.snapshot.entries.is_empty());
        assert_eq!(collection.omissions.len(), 1);
        assert_eq!(
            collection.omissions[0].reason,
            OpenCodeCatalogueOmissionReason::ProviderDisconnected
        );
        Ok(())
    }

    fn json_response(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    async fn serve_sequence(
        responses: Vec<Vec<u8>>,
    ) -> Result<(u16, Arc<Mutex<Vec<String>>>), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        tokio::spawn(async move {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                request_log
                    .lock()
                    .await
                    .push(String::from_utf8_lossy(&bytes).into_owned());
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        Ok((port, requests))
    }

    #[tokio::test]
    async fn client_catalogue_uses_only_health_and_provider_gets()
    -> Result<(), Box<dyn std::error::Error>> {
        let health_body = br#"{"healthy":true,"version":"1.4.3"}"#;
        let providers_body = br#"{"all":[{"id":"provider-a","connected":true,"models":{"model-a":{"id":"model-a","cost":{"input":0,"output":0},"limit":{"context":200000},"reasoning":true,"tool_call":true}}}],"default":{},"connected":["provider-a"]}"#;
        let (port, requests) = serve_sequence(vec![
            json_response(health_body),
            json_response(providers_body),
        ])
        .await?;
        let endpoint = format!("http://127.0.0.1:{port}").parse::<LoopbackEndpoint>()?;
        let auth = BasicAuth::new("opencode", SecretString::from("secret".to_owned()))?;
        let directory = if cfg!(windows) {
            PathBuf::from(r"C:\Scratch")
        } else {
            PathBuf::from("/tmp")
        };
        let client = OpenCodeClient::new(
            endpoint,
            auth,
            OpenCodeRunPolicy::new(directory)?
                .with_timeouts(Duration::from_secs(2), Duration::from_secs(1)),
        )?;
        let collection = client
            .model_catalogue(&context(OpenCodeBillingMode::CataloguePrice))
            .await?;
        assert_eq!(collection.snapshot.entries.len(), 1);
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /global/health HTTP/1.1"));
        assert!(requests[1].starts_with("GET /provider?directory="));
        assert!(requests.iter().all(|request| !request.contains("/session")));
        assert!(requests.iter().all(|request| !request.starts_with("POST ")));
        Ok(())
    }

    #[test]
    fn missing_context_window_is_visible_omission() -> Result<(), Box<dyn std::error::Error>> {
        let missing = model("model-a", json!({"cost": {"input": 0, "output": 0}}));
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(missing, true),
            &context(OpenCodeBillingMode::CataloguePrice),
        )?;
        assert!(collection.snapshot.entries.is_empty());
        assert_eq!(
            collection.omissions[0].reason,
            OpenCodeCatalogueOmissionReason::MissingContextWindow
        );
        Ok(())
    }

    #[test]
    fn existing_flat_context_limit_remains_supported() -> Result<(), Box<dyn std::error::Error>> {
        let mut flat = model("model-a", json!({"cost": {"input": 0, "output": 0}}));
        flat.context_limit = Some(128_000);
        let collection = compile_opencode_model_catalogue(
            &health(),
            &providers(flat, true),
            &context(OpenCodeBillingMode::CataloguePrice),
        )?;
        assert_eq!(collection.snapshot.entries[0].context_window, 128_000);
        Ok(())
    }

    #[test]
    fn directory_used_by_client_policy_is_absolute() {
        let directory = if cfg!(windows) {
            Path::new(r"C:\Scratch")
        } else {
            Path::new("/tmp")
        };
        assert!(directory.is_absolute());
    }
}
