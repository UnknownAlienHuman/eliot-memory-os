//! Zero-model catalogue, human preference, and attempt-health compilation.
//!
//! This module is pure and deterministic. It does not call a provider, launch
//! an agent, mint authority, mutate task state, or decide finish. Runtime
//! adapters supply immutable observations; A-02 compiles candidate selections
//! and read-only operator projections from those observations.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{AttemptId, RouteFingerprint};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::CoordinatedAttemptState;

pub const MODEL_CATALOGUE_SCHEMA_VERSION: &str = "eliot.agent-model-catalogue/v1";
pub const MODEL_PREFERENCE_SCHEMA_VERSION: &str = "eliot.agent-model-preference/v1";
pub const MODEL_QUERY_RECEIPT_VERSION: &str = "eliot.agent-model-query-receipt/v1";
pub const MODEL_SELECTION_RECEIPT_VERSION: &str = "eliot.agent-model-selection-receipt/v1";
pub const ATTEMPT_HEALTH_PROJECTION_VERSION: &str = "eliot.agent-attempt-health/v1";

const MAX_CATALOGUE_ENTRIES: usize = 4096;
const MAX_QUERY_RESULTS: usize = 512;
const MAX_SELECTORS: usize = 256;
const MAX_EVIDENCE_REFS: usize = 256;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelControlError {
    #[error("invalid model-control field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported model-control schema: {0}")]
    UnsupportedSchema(&'static str),
    #[error("duplicate model-control identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("catalogue observation is stale")]
    StaleCatalogue,
    #[error("Human preference policy has no entry for role {0:?}")]
    MissingRolePolicy(ModelRole),
    #[error("no dispatchable route exists for role {0:?}")]
    NoDispatchableRoute(ModelRole),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ModelControlError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ModelControlError::InvalidField(field));
    }
    Ok(())
}

fn validate_window(
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    field: &'static str,
) -> Result<(), ModelControlError> {
    if observed_at_unix_ms == 0 || expires_at_unix_ms < observed_at_unix_ms {
        return Err(ModelControlError::InvalidField(field));
    }
    Ok(())
}

fn validate_unique_texts(
    values: &[String],
    field: &'static str,
    allow_empty: bool,
) -> Result<(), ModelControlError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_EVIDENCE_REFS {
        return Err(ModelControlError::InvalidField(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value) {
            return Err(ModelControlError::DuplicateIdentity(field));
        }
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ModelControlError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ModelControlError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", eliot_receipts::sha256_hex(&bytes)))
}

fn catalogue_digest(snapshot: &ModelCatalogueSnapshot) -> Result<String, ModelControlError> {
    let mut normalized = snapshot.clone();
    normalized
        .entries
        .sort_by(|left, right| left.deterministic_key().cmp(&right.deterministic_key()));
    canonical_digest(&normalized)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelRole {
    MainAgent,
    Worker,
    Challenger,
    Verifier,
    Researcher,
    Synthesis,
    Watchdog,
    Dreamer,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BillingClass {
    Free,
    SubscriptionIncluded,
    Paid,
    Unknown,
}

impl BillingClass {
    const fn rank(self) -> u8 {
        match self {
            Self::Free => 0,
            Self::SubscriptionIncluded => 1,
            Self::Paid => 2,
            Self::Unknown => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteAdmissionStatus {
    Admitted,
    Candidate,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteHealthStatus {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

impl RouteHealthStatus {
    const fn rank(self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Unavailable => 2,
            Self::Unknown => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelAvailability {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

impl ModelAvailability {
    const fn rank(self) -> u8 {
        match self {
            Self::Available => 0,
            Self::Degraded => 1,
            Self::Unavailable => 2,
            Self::Unknown => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuotaDisposition {
    Available,
    Low,
    Exhausted,
    Unknown,
    NotExposed,
}

impl QuotaDisposition {
    const fn rank(self) -> u8 {
        match self {
            Self::Available => 0,
            Self::Low => 1,
            Self::Exhausted => 2,
            Self::Unknown => 3,
            Self::NotExposed => 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingEvidence {
    pub class: BillingClass,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl BillingEvidence {
    fn validate(&self) -> Result<(), ModelControlError> {
        validate_text(&self.source, "billing.source")?;
        validate_text(&self.receipt_ref, "billing.receipt_ref")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "billing.window",
        )
    }

    const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaObservation {
    pub disposition: QuotaDisposition,
    pub source: String,
    pub receipt_ref: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub reset_at_unix_ms: Option<u64>,
    pub remaining_microunits: Option<u64>,
}

impl QuotaObservation {
    fn validate(&self) -> Result<(), ModelControlError> {
        validate_text(&self.source, "quota.source")?;
        validate_text(&self.receipt_ref, "quota.receipt_ref")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "quota.window",
        )?;
        if self
            .reset_at_unix_ms
            .is_some_and(|reset| reset < self.observed_at_unix_ms)
        {
            return Err(ModelControlError::InvalidField("quota.reset_at_unix_ms"));
        }
        Ok(())
    }

    const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityObservation {
    pub status: CapabilityStatus,
    pub evidence_class: String,
    pub receipt_ref: String,
}

impl CapabilityObservation {
    fn validate(&self) -> Result<(), ModelControlError> {
        validate_text(&self.evidence_class, "capability.evidence_class")?;
        validate_text(&self.receipt_ref, "capability.receipt_ref")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogueEntry {
    pub entry_id: String,
    pub account_scope: String,
    pub host_family: String,
    pub provider_id: String,
    pub model_id: String,
    pub model_family: String,
    pub route: RouteFingerprint,
    pub route_admission: RouteAdmissionStatus,
    pub route_health: RouteHealthStatus,
    pub availability: ModelAvailability,
    pub billing: BillingEvidence,
    pub quota: QuotaObservation,
    pub context_window: u64,
    pub cost_class: u16,
    pub latency_class: u16,
    pub capabilities: BTreeMap<String, CapabilityObservation>,
    pub role_eligibility: BTreeSet<ModelRole>,
    pub evidence_refs: Vec<String>,
}

impl ModelCatalogueEntry {
    fn validate(&self, account_scope: &str) -> Result<(), ModelControlError> {
        for (value, field) in [
            (self.entry_id.as_str(), "entry.entry_id"),
            (self.account_scope.as_str(), "entry.account_scope"),
            (self.host_family.as_str(), "entry.host_family"),
            (self.provider_id.as_str(), "entry.provider_id"),
            (self.model_id.as_str(), "entry.model_id"),
            (self.model_family.as_str(), "entry.model_family"),
        ] {
            validate_text(value, field)?;
        }
        if self.account_scope != account_scope
            || self.provider_id != self.route.provider
            || self.model_id != self.route.model
            || self.context_window == 0
        {
            return Err(ModelControlError::InvalidField("entry.route_binding"));
        }
        self.route
            .validate()
            .map_err(|_| ModelControlError::InvalidField("entry.route"))?;
        self.billing.validate()?;
        self.quota.validate()?;
        if self.capabilities.len() > MAX_EVIDENCE_REFS {
            return Err(ModelControlError::InvalidField("entry.capabilities"));
        }
        for (name, observation) in &self.capabilities {
            validate_text(name, "entry.capability_name")?;
            observation.validate()?;
        }
        validate_unique_texts(&self.evidence_refs, "entry.evidence_refs", false)
    }

    fn deterministic_key(&self) -> (&str, &str, &str, &str, &str) {
        (
            self.host_family.as_str(),
            self.provider_id.as_str(),
            self.model_family.as_str(),
            self.model_id.as_str(),
            self.entry_id.as_str(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogueSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub account_scope: String,
    pub collector_identity: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub entries: Vec<ModelCatalogueEntry>,
}

impl ModelCatalogueSnapshot {
    pub fn validate(&self) -> Result<(), ModelControlError> {
        if self.schema_version != MODEL_CATALOGUE_SCHEMA_VERSION {
            return Err(ModelControlError::UnsupportedSchema("model_catalogue"));
        }
        validate_text(&self.snapshot_id, "catalogue.snapshot_id")?;
        validate_text(&self.account_scope, "catalogue.account_scope")?;
        validate_text(&self.collector_identity, "catalogue.collector_identity")?;
        validate_window(
            self.observed_at_unix_ms,
            self.expires_at_unix_ms,
            "catalogue.window",
        )?;
        if self.entries.len() > MAX_CATALOGUE_ENTRIES {
            return Err(ModelControlError::InvalidField("catalogue.entries"));
        }
        let mut entry_ids = BTreeSet::new();
        let mut route_keys = BTreeSet::new();
        for entry in &self.entries {
            entry.validate(&self.account_scope)?;
            if !entry_ids.insert(entry.entry_id.as_str()) {
                return Err(ModelControlError::DuplicateIdentity("catalogue.entry_id"));
            }
            let route_key = canonical_digest(&entry.route)?;
            if !route_keys.insert(route_key) {
                return Err(ModelControlError::DuplicateIdentity("catalogue.route"));
            }
        }
        Ok(())
    }

    pub const fn is_current(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.observed_at_unix_ms && now_unix_ms <= self.expires_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelQuery {
    pub query_id: String,
    pub text: Option<String>,
    pub free_only: bool,
    pub include_subscription_included: bool,
    pub dispatchable_only: bool,
    pub host_families: BTreeSet<String>,
    pub provider_ids: BTreeSet<String>,
    pub required_capabilities: BTreeSet<String>,
    pub minimum_context_window: u64,
    pub limit: usize,
}

impl ModelQuery {
    fn validate(&self) -> Result<(), ModelControlError> {
        validate_text(&self.query_id, "query.query_id")?;
        if let Some(text) = self.text.as_deref() {
            validate_text(text, "query.text")?;
        }
        if self.limit == 0 || self.limit > MAX_QUERY_RESULTS {
            return Err(ModelControlError::InvalidField("query.limit"));
        }
        for value in self
            .host_families
            .iter()
            .chain(&self.provider_ids)
            .chain(&self.required_capabilities)
        {
            validate_text(value, "query.filter")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "detail")]
pub enum DispatchBlocker {
    CatalogueStale,
    RouteNotAdmitted,
    RouteDegraded,
    RouteUnavailable,
    RouteHealthUnknown,
    ModelDegraded,
    ModelUnavailable,
    ModelAvailabilityUnknown,
    BillingEvidenceStale,
    QuotaEvidenceStale,
    QuotaExhausted,
    QuotaUnknown,
    QuotaNotExposed,
    ContextWindowTooSmall,
    CapabilityUnsupported(String),
    CapabilityUnknown(String),
}

fn dispatch_blockers(
    snapshot: &ModelCatalogueSnapshot,
    entry: &ModelCatalogueEntry,
    required_capabilities: &BTreeSet<String>,
    minimum_context_window: u64,
    allow_degraded: bool,
    now_unix_ms: u64,
) -> Vec<DispatchBlocker> {
    let mut blockers = BTreeSet::new();
    if !snapshot.is_current(now_unix_ms) {
        blockers.insert(DispatchBlocker::CatalogueStale);
    }
    if entry.route_admission != RouteAdmissionStatus::Admitted {
        blockers.insert(DispatchBlocker::RouteNotAdmitted);
    }
    match entry.route_health {
        RouteHealthStatus::Healthy => {}
        RouteHealthStatus::Degraded if allow_degraded => {}
        RouteHealthStatus::Degraded => {
            blockers.insert(DispatchBlocker::RouteDegraded);
        }
        RouteHealthStatus::Unavailable => {
            blockers.insert(DispatchBlocker::RouteUnavailable);
        }
        RouteHealthStatus::Unknown => {
            blockers.insert(DispatchBlocker::RouteHealthUnknown);
        }
    }
    match entry.availability {
        ModelAvailability::Available => {}
        ModelAvailability::Degraded if allow_degraded => {}
        ModelAvailability::Degraded => {
            blockers.insert(DispatchBlocker::ModelDegraded);
        }
        ModelAvailability::Unavailable => {
            blockers.insert(DispatchBlocker::ModelUnavailable);
        }
        ModelAvailability::Unknown => {
            blockers.insert(DispatchBlocker::ModelAvailabilityUnknown);
        }
    }
    if !entry.billing.is_current(now_unix_ms) {
        blockers.insert(DispatchBlocker::BillingEvidenceStale);
    }
    if entry.quota.is_current(now_unix_ms) {
        match entry.quota.disposition {
            QuotaDisposition::Available | QuotaDisposition::Low => {}
            QuotaDisposition::Exhausted => {
                blockers.insert(DispatchBlocker::QuotaExhausted);
            }
            QuotaDisposition::Unknown => {
                blockers.insert(DispatchBlocker::QuotaUnknown);
            }
            QuotaDisposition::NotExposed => {
                blockers.insert(DispatchBlocker::QuotaNotExposed);
            }
        }
    } else {
        blockers.insert(DispatchBlocker::QuotaEvidenceStale);
    }
    if entry.context_window < minimum_context_window {
        blockers.insert(DispatchBlocker::ContextWindowTooSmall);
    }
    for capability in required_capabilities {
        match entry.capabilities.get(capability).map(|value| value.status) {
            Some(CapabilityStatus::Supported) => {}
            Some(CapabilityStatus::Unsupported) | None => {
                blockers.insert(DispatchBlocker::CapabilityUnsupported(capability.clone()));
            }
            Some(CapabilityStatus::Unknown) => {
                blockers.insert(DispatchBlocker::CapabilityUnknown(capability.clone()));
            }
        }
    }
    blockers.into_iter().collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelQueryHit {
    pub entry: ModelCatalogueEntry,
    pub dispatchable: bool,
    pub blockers: Vec<DispatchBlocker>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroModelExecutionCounters {
    pub model_calls: u64,
    pub agent_attempts: u64,
    pub provider_generation_calls: u64,
}

impl ZeroModelExecutionCounters {
    pub const fn zero() -> Self {
        Self {
            model_calls: 0,
            agent_attempts: 0,
            provider_generation_calls: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelQueryReceipt {
    pub schema_version: String,
    pub query_id: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub hits: Vec<ModelQueryHit>,
    pub execution: ZeroModelExecutionCounters,
}

fn text_matches(entry: &ModelCatalogueEntry, query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    let needle = query.to_lowercase();
    [
        entry.host_family.as_str(),
        entry.provider_id.as_str(),
        entry.model_id.as_str(),
        entry.model_family.as_str(),
    ]
    .into_iter()
    .any(|value| value.to_lowercase().contains(&needle))
}

fn free_filter_matches(
    entry: &ModelCatalogueEntry,
    include_subscription_included: bool,
    now_unix_ms: u64,
) -> bool {
    if !entry.billing.is_current(now_unix_ms) {
        return false;
    }
    entry.billing.class == BillingClass::Free
        || (include_subscription_included
            && entry.billing.class == BillingClass::SubscriptionIncluded)
}

pub fn query_model_catalogue(
    snapshot: &ModelCatalogueSnapshot,
    query: &ModelQuery,
    now_unix_ms: u64,
) -> Result<ModelQueryReceipt, ModelControlError> {
    snapshot.validate()?;
    query.validate()?;
    let mut hits = snapshot
        .entries
        .iter()
        .filter(|entry| {
            (query.host_families.is_empty() || query.host_families.contains(&entry.host_family))
                && (query.provider_ids.is_empty()
                    || query.provider_ids.contains(&entry.provider_id))
                && text_matches(entry, query.text.as_deref())
                && (!query.free_only
                    || free_filter_matches(entry, query.include_subscription_included, now_unix_ms))
        })
        .filter_map(|entry| {
            let blockers = dispatch_blockers(
                snapshot,
                entry,
                &query.required_capabilities,
                query.minimum_context_window,
                false,
                now_unix_ms,
            );
            let dispatchable = blockers.is_empty();
            (!query.dispatchable_only || dispatchable).then(|| ModelQueryHit {
                entry: entry.clone(),
                dispatchable,
                blockers,
            })
        })
        .collect::<Vec<_>>();
    hits.sort_by(|left, right| {
        left.entry
            .deterministic_key()
            .cmp(&right.entry.deterministic_key())
    });
    hits.truncate(query.limit);
    Ok(ModelQueryReceipt {
        schema_version: MODEL_QUERY_RECEIPT_VERSION.to_owned(),
        query_id: query.query_id.clone(),
        catalogue_snapshot_id: snapshot.snapshot_id.clone(),
        catalogue_digest: catalogue_digest(snapshot)?,
        hits,
        execution: ZeroModelExecutionCounters::zero(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSelector {
    pub host_family: Option<String>,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub model_family: Option<String>,
}

impl ModelSelector {
    fn validate(&self) -> Result<(), ModelControlError> {
        let values = [
            self.host_family.as_deref(),
            self.provider_id.as_deref(),
            self.model_id.as_deref(),
            self.model_family.as_deref(),
        ];
        if values.iter().all(Option::is_none) {
            return Err(ModelControlError::InvalidField("selector"));
        }
        for value in values.into_iter().flatten() {
            validate_text(value, "selector.value")?;
        }
        Ok(())
    }

    fn matches(&self, entry: &ModelCatalogueEntry) -> bool {
        self.host_family
            .as_deref()
            .is_none_or(|value| value == entry.host_family)
            && self
                .provider_id
                .as_deref()
                .is_none_or(|value| value == entry.provider_id)
            && self
                .model_id
                .as_deref()
                .is_none_or(|value| value == entry.model_id)
            && self
                .model_family
                .as_deref()
                .is_none_or(|value| value == entry.model_family)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleModelPreference {
    pub role: ModelRole,
    pub preferred: Vec<ModelSelector>,
    pub denied: Vec<ModelSelector>,
    pub allowed_billing: BTreeSet<BillingClass>,
    pub allow_paid_fallback: bool,
    pub allow_degraded_routes: bool,
    pub minimum_context_window: u64,
    pub maximum_cost_class: u16,
    pub maximum_latency_class: u16,
    pub required_capabilities: BTreeSet<String>,
}

impl RoleModelPreference {
    fn validate(&self) -> Result<(), ModelControlError> {
        if self.preferred.len() > MAX_SELECTORS
            || self.denied.len() > MAX_SELECTORS
            || self.allowed_billing.is_empty()
            || self.minimum_context_window == 0
        {
            return Err(ModelControlError::InvalidField("role_preference"));
        }
        for selector in self.preferred.iter().chain(&self.denied) {
            selector.validate()?;
        }
        for capability in &self.required_capabilities {
            validate_text(capability, "role_preference.required_capability")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanModelPreferencePolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub revision: String,
    pub account_scope: String,
    pub roles: Vec<RoleModelPreference>,
}

impl HumanModelPreferencePolicy {
    pub fn validate(&self) -> Result<(), ModelControlError> {
        if self.schema_version != MODEL_PREFERENCE_SCHEMA_VERSION {
            return Err(ModelControlError::UnsupportedSchema("model_preference"));
        }
        validate_text(&self.policy_id, "policy.policy_id")?;
        validate_text(&self.revision, "policy.revision")?;
        validate_text(&self.account_scope, "policy.account_scope")?;
        if self.roles.is_empty() || self.roles.len() > 64 {
            return Err(ModelControlError::InvalidField("policy.roles"));
        }
        let mut roles = BTreeSet::new();
        for role in &self.roles {
            role.validate()?;
            if !roles.insert(role.role) {
                return Err(ModelControlError::DuplicateIdentity("policy.role"));
            }
        }
        Ok(())
    }

    fn role(&self, role: ModelRole) -> Result<&RoleModelPreference, ModelControlError> {
        self.roles
            .iter()
            .find(|preference| preference.role == role)
            .ok_or(ModelControlError::MissingRolePolicy(role))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "detail")]
pub enum SelectionRejection {
    Dispatch(DispatchBlocker),
    RoleNotEligible,
    DeniedByHumanPolicy,
    BillingClassDisallowed,
    PaidFallbackDisabled,
    CostClassTooHigh,
    LatencyClassTooHigh,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedModelCandidate {
    pub entry_id: String,
    pub host_family: String,
    pub provider_id: String,
    pub model_id: String,
    pub reasons: Vec<SelectionRejection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RankedCandidate<'a> {
    entry: &'a ModelCatalogueEntry,
    preference_rank: usize,
}

impl RankedCandidate<'_> {
    fn compare(&self, other: &Self) -> Ordering {
        (
            self.preference_rank,
            self.entry.billing.class.rank(),
            self.entry.route_health.rank(),
            self.entry.availability.rank(),
            self.entry.quota.disposition.rank(),
            self.entry.cost_class,
            self.entry.latency_class,
            self.entry.deterministic_key(),
        )
            .cmp(&(
                other.preference_rank,
                other.entry.billing.class.rank(),
                other.entry.route_health.rank(),
                other.entry.availability.rank(),
                other.entry.quota.disposition.rank(),
                other.entry.cost_class,
                other.entry.latency_class,
                other.entry.deterministic_key(),
            ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSelectionReceipt {
    pub schema_version: String,
    pub selection_id: String,
    pub selection_digest: String,
    pub role: ModelRole,
    pub account_scope: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub selected: ModelCatalogueEntry,
    pub rejected: Vec<RejectedModelCandidate>,
    pub execution: ZeroModelExecutionCounters,
    pub candidate_only: bool,
    pub dispatch_authority: bool,
}

fn preference_rank(entry: &ModelCatalogueEntry, selectors: &[ModelSelector]) -> usize {
    selectors
        .iter()
        .position(|selector| selector.matches(entry))
        .unwrap_or(usize::MAX)
}

fn selection_rejections(
    snapshot: &ModelCatalogueSnapshot,
    entry: &ModelCatalogueEntry,
    preference: &RoleModelPreference,
    now_unix_ms: u64,
) -> Vec<SelectionRejection> {
    let mut reasons = BTreeSet::new();
    for blocker in dispatch_blockers(
        snapshot,
        entry,
        &preference.required_capabilities,
        preference.minimum_context_window,
        preference.allow_degraded_routes,
        now_unix_ms,
    ) {
        reasons.insert(SelectionRejection::Dispatch(blocker));
    }
    if !entry.role_eligibility.is_empty() && !entry.role_eligibility.contains(&preference.role) {
        reasons.insert(SelectionRejection::RoleNotEligible);
    }
    if preference
        .denied
        .iter()
        .any(|selector| selector.matches(entry))
    {
        reasons.insert(SelectionRejection::DeniedByHumanPolicy);
    }
    if !preference.allowed_billing.contains(&entry.billing.class) {
        reasons.insert(SelectionRejection::BillingClassDisallowed);
    }
    if entry.billing.class == BillingClass::Paid && !preference.allow_paid_fallback {
        reasons.insert(SelectionRejection::PaidFallbackDisabled);
    }
    if entry.cost_class > preference.maximum_cost_class {
        reasons.insert(SelectionRejection::CostClassTooHigh);
    }
    if entry.latency_class > preference.maximum_latency_class {
        reasons.insert(SelectionRejection::LatencyClassTooHigh);
    }
    reasons.into_iter().collect()
}

pub fn compile_model_selection(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
    role: ModelRole,
    selection_id: &str,
    now_unix_ms: u64,
) -> Result<ModelSelectionReceipt, ModelControlError> {
    snapshot.validate()?;
    policy.validate()?;
    validate_text(selection_id, "selection_id")?;
    if snapshot.account_scope != policy.account_scope {
        return Err(ModelControlError::InvalidField("selection.account_scope"));
    }
    if !snapshot.is_current(now_unix_ms) {
        return Err(ModelControlError::StaleCatalogue);
    }
    let preference = policy.role(role)?;
    let mut eligible = Vec::new();
    let mut rejected = Vec::new();
    for entry in &snapshot.entries {
        let reasons = selection_rejections(snapshot, entry, preference, now_unix_ms);
        if reasons.is_empty() {
            eligible.push(RankedCandidate {
                entry,
                preference_rank: preference_rank(entry, &preference.preferred),
            });
        } else {
            rejected.push(RejectedModelCandidate {
                entry_id: entry.entry_id.clone(),
                host_family: entry.host_family.clone(),
                provider_id: entry.provider_id.clone(),
                model_id: entry.model_id.clone(),
                reasons,
            });
        }
    }
    eligible.sort_by(RankedCandidate::compare);
    rejected.sort_by(|left, right| {
        (
            left.host_family.as_str(),
            left.provider_id.as_str(),
            left.model_id.as_str(),
            left.entry_id.as_str(),
        )
            .cmp(&(
                right.host_family.as_str(),
                right.provider_id.as_str(),
                right.model_id.as_str(),
                right.entry_id.as_str(),
            ))
    });
    let selected = eligible
        .first()
        .ok_or(ModelControlError::NoDispatchableRoute(role))?
        .entry
        .clone();
    let catalogue_digest = catalogue_digest(snapshot)?;
    let selection_digest = canonical_digest(&(
        MODEL_SELECTION_RECEIPT_VERSION,
        selection_id,
        role,
        snapshot.snapshot_id.as_str(),
        catalogue_digest.as_str(),
        policy.policy_id.as_str(),
        policy.revision.as_str(),
        selected.entry_id.as_str(),
    ))?;
    Ok(ModelSelectionReceipt {
        schema_version: MODEL_SELECTION_RECEIPT_VERSION.to_owned(),
        selection_id: selection_id.to_owned(),
        selection_digest,
        role,
        account_scope: snapshot.account_scope.clone(),
        catalogue_snapshot_id: snapshot.snapshot_id.clone(),
        catalogue_digest,
        preference_policy_id: policy.policy_id.clone(),
        preference_revision: policy.revision.clone(),
        selected,
        rejected,
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessObservation {
    Alive,
    Exited,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptEffectObservation {
    NoneObserved,
    KnownNotStarted,
    Committed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptTelemetryInput {
    pub attempt_id: AttemptId,
    pub state: CoordinatedAttemptState,
    pub observed_at_unix_ms: u64,
    pub started_at_unix_ms: u64,
    pub last_heartbeat_unix_ms: Option<u64>,
    pub heartbeat_timeout_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub process: ProcessObservation,
    pub quota: QuotaObservation,
    pub effect: AttemptEffectObservation,
    pub open_descendants: u32,
}

impl AttemptTelemetryInput {
    fn validate(&self) -> Result<(), ModelControlError> {
        if self.observed_at_unix_ms == 0
            || self.started_at_unix_ms == 0
            || self.observed_at_unix_ms < self.started_at_unix_ms
            || self.heartbeat_timeout_ms == 0
            || self.lease_expires_at_unix_ms < self.started_at_unix_ms
            || self.deadline_unix_ms < self.started_at_unix_ms
            || self
                .last_heartbeat_unix_ms
                .is_some_and(|heartbeat| heartbeat < self.started_at_unix_ms)
        {
            return Err(ModelControlError::InvalidField("attempt_telemetry"));
        }
        self.quota.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptLivenessStatus {
    Starting,
    Live,
    Cancelling,
    HeartbeatMissing,
    HeartbeatStale,
    LeaseExpired,
    DeadlineExceeded,
    QuotaExhausted,
    QuotaUnknown,
    ProcessMissing,
    UnknownEffect,
    UnknownOutcome,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptAlertCode {
    HeartbeatMissing,
    HeartbeatStale,
    LeaseExpired,
    DeadlineExceeded,
    QuotaLow,
    QuotaExhausted,
    QuotaUnknown,
    ProcessMissing,
    ProcessUnknown,
    EffectUnknown,
    DescendantsOpen,
    TerminalWithOpenDescendants,
    UnknownOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptWorkEligibility {
    Eligible,
    Ineligible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptTerminalReconciliation {
    ReconciledCandidate,
    Unreconciled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptAutomationDisposition {
    ManualOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptHealthProjection {
    pub schema_version: String,
    pub attempt_id: AttemptId,
    pub observed_at_unix_ms: u64,
    pub status: AttemptLivenessStatus,
    pub alerts: Vec<AttemptAlertCode>,
    pub work_eligibility: AttemptWorkEligibility,
    pub terminal_reconciliation: AttemptTerminalReconciliation,
    pub automation: AttemptAutomationDisposition,
}

fn heartbeat_status(
    input: &AttemptTelemetryInput,
    now_unix_ms: u64,
    alerts: &mut BTreeSet<AttemptAlertCode>,
) -> AttemptLivenessStatus {
    match input.last_heartbeat_unix_ms {
        None => {
            alerts.insert(AttemptAlertCode::HeartbeatMissing);
            AttemptLivenessStatus::HeartbeatMissing
        }
        Some(last) if now_unix_ms.saturating_sub(last) > input.heartbeat_timeout_ms => {
            alerts.insert(AttemptAlertCode::HeartbeatStale);
            AttemptLivenessStatus::HeartbeatStale
        }
        Some(_) => AttemptLivenessStatus::Live,
    }
}

fn collect_attempt_alerts(
    input: &AttemptTelemetryInput,
    now_unix_ms: u64,
) -> (BTreeSet<AttemptAlertCode>, AttemptLivenessStatus) {
    let mut alerts = BTreeSet::new();
    let heartbeat = heartbeat_status(input, now_unix_ms, &mut alerts);
    if now_unix_ms > input.lease_expires_at_unix_ms {
        alerts.insert(AttemptAlertCode::LeaseExpired);
    }
    if now_unix_ms > input.deadline_unix_ms {
        alerts.insert(AttemptAlertCode::DeadlineExceeded);
    }
    match input.quota.disposition {
        QuotaDisposition::Available => {}
        QuotaDisposition::Low => {
            alerts.insert(AttemptAlertCode::QuotaLow);
        }
        QuotaDisposition::Exhausted => {
            alerts.insert(AttemptAlertCode::QuotaExhausted);
        }
        QuotaDisposition::Unknown | QuotaDisposition::NotExposed => {
            alerts.insert(AttemptAlertCode::QuotaUnknown);
        }
    }
    if !input.quota.is_current(now_unix_ms) {
        alerts.insert(AttemptAlertCode::QuotaUnknown);
    }
    match input.process {
        ProcessObservation::Alive => {}
        ProcessObservation::Exited => {
            alerts.insert(AttemptAlertCode::ProcessMissing);
        }
        ProcessObservation::Unknown => {
            alerts.insert(AttemptAlertCode::ProcessUnknown);
        }
    }
    if input.effect == AttemptEffectObservation::Unknown {
        alerts.insert(AttemptAlertCode::EffectUnknown);
    }
    if input.open_descendants > 0 {
        alerts.insert(AttemptAlertCode::DescendantsOpen);
        if input.state.is_terminal() {
            alerts.insert(AttemptAlertCode::TerminalWithOpenDescendants);
        }
    }
    if input.state == CoordinatedAttemptState::UnknownOutcome {
        alerts.insert(AttemptAlertCode::UnknownOutcome);
    }
    (alerts, heartbeat)
}

fn derive_attempt_status(
    input: &AttemptTelemetryInput,
    now_unix_ms: u64,
    heartbeat: AttemptLivenessStatus,
) -> AttemptLivenessStatus {
    if input.state.is_terminal() {
        AttemptLivenessStatus::Terminal
    } else if input.state == CoordinatedAttemptState::UnknownOutcome {
        AttemptLivenessStatus::UnknownOutcome
    } else if input.effect == AttemptEffectObservation::Unknown {
        AttemptLivenessStatus::UnknownEffect
    } else if input.quota.disposition == QuotaDisposition::Exhausted {
        AttemptLivenessStatus::QuotaExhausted
    } else if !input.quota.is_current(now_unix_ms)
        || matches!(
            input.quota.disposition,
            QuotaDisposition::Unknown | QuotaDisposition::NotExposed
        )
    {
        AttemptLivenessStatus::QuotaUnknown
    } else if now_unix_ms > input.lease_expires_at_unix_ms {
        AttemptLivenessStatus::LeaseExpired
    } else if now_unix_ms > input.deadline_unix_ms {
        AttemptLivenessStatus::DeadlineExceeded
    } else if input.process == ProcessObservation::Exited {
        AttemptLivenessStatus::ProcessMissing
    } else if input.state == CoordinatedAttemptState::CancellationRequested {
        AttemptLivenessStatus::Cancelling
    } else if input.state == CoordinatedAttemptState::Admitted
        && input.last_heartbeat_unix_ms.is_none()
    {
        AttemptLivenessStatus::Starting
    } else {
        heartbeat
    }
}

pub fn project_attempt_health(
    input: &AttemptTelemetryInput,
    now_unix_ms: u64,
) -> Result<AttemptHealthProjection, ModelControlError> {
    input.validate()?;
    if now_unix_ms < input.observed_at_unix_ms {
        return Err(ModelControlError::InvalidField(
            "attempt_health.now_unix_ms",
        ));
    }
    let (alerts, heartbeat) = collect_attempt_alerts(input, now_unix_ms);
    let status = derive_attempt_status(input, now_unix_ms, heartbeat);
    let terminal_reconciliation = if input.state.is_terminal()
        && input.open_descendants == 0
        && input.effect != AttemptEffectObservation::Unknown
    {
        AttemptTerminalReconciliation::ReconciledCandidate
    } else {
        AttemptTerminalReconciliation::Unreconciled
    };
    Ok(AttemptHealthProjection {
        schema_version: ATTEMPT_HEALTH_PROJECTION_VERSION.to_owned(),
        attempt_id: input.attempt_id.clone(),
        observed_at_unix_ms: now_unix_ms,
        status,
        alerts: alerts.into_iter().collect(),
        work_eligibility: if matches!(status, AttemptLivenessStatus::Live) {
            AttemptWorkEligibility::Eligible
        } else {
            AttemptWorkEligibility::Ineligible
        },
        terminal_reconciliation,
        automation: AttemptAutomationDisposition::ManualOnly,
    })
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum SwarmControlCommandDraft {
    RefreshCatalogue {
        account_scope: String,
    },
    UpdatePreferences {
        expected_revision: String,
        candidate: Box<HumanModelPreferencePolicy>,
    },
    LaunchSwarm {
        task_id: String,
        plan_revision: String,
        requested_roles: BTreeMap<ModelRole, u16>,
    },
    CancelAttempt {
        attempt_id: AttemptId,
        reason: String,
    },
}

impl SwarmControlCommandDraft {
    pub fn validate(&self) -> Result<(), ModelControlError> {
        match self {
            Self::RefreshCatalogue { account_scope } => {
                validate_text(account_scope, "command.account_scope")
            }
            Self::UpdatePreferences {
                expected_revision,
                candidate,
            } => {
                validate_text(expected_revision, "command.expected_revision")?;
                candidate.validate()
            }
            Self::LaunchSwarm {
                task_id,
                plan_revision,
                requested_roles,
            } => {
                validate_text(task_id, "command.task_id")?;
                validate_text(plan_revision, "command.plan_revision")?;
                if requested_roles.is_empty() || requested_roles.values().any(|count| *count == 0) {
                    return Err(ModelControlError::InvalidField("command.requested_roles"));
                }
                Ok(())
            }
            Self::CancelAttempt { reason, .. } => validate_text(reason, "command.cancel_reason"),
        }
    }
}

#[cfg(test)]
#[path = "model_control_tests.rs"]
mod tests;
