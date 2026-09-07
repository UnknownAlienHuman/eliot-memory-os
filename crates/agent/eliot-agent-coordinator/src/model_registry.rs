//! Provider-neutral, read-only model registry and eligibility search.
//!
//! The registry is deliberately a projection over the existing catalogue
//! contracts.  It owns no provider client, credentials, clock, admission, or
//! execution path.  A route can be absent from a supplied denominator and
//! that fact remains visible to callers; an absent route is never represented
//! by an empty, complete catalogue.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::{RouteFingerprint, StateFence};
use eliot_receipts::ProofCeiling;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model_control::{
    BillingClass, HumanModelPreferencePolicy, ModelAvailability, ModelCatalogueEntry,
    ModelCatalogueSnapshot, ModelControlError, ModelQuery, ModelQueryHit, ModelQueryReceipt,
    ModelRole, ModelSelectionReceipt, ModelSelector, QuotaDisposition, RouteAdmissionStatus,
    RouteHealthStatus, SelectionRejection, ZeroModelExecutionCounters,
};

pub const MODEL_REGISTRY_SCHEMA_VERSION: &str = "eliot.agent-model-registry/v1";
pub const MODEL_SEARCH_SCHEMA_VERSION: &str = "eliot.agent-model-search/v1";
const MAX_EXPECTED_ROUTES: usize = 4096;
const MAX_REQUIREMENTS: usize = 256;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelRegistryError {
    #[error("invalid model registry source: {0}")]
    InvalidSource(String),
    #[error("invalid model registry field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate model registry route identity")]
    DuplicateRoute,
    #[error("model registry serialization failed: {0}")]
    Serialization(String),
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Known,
    Missing,
    Stale,
    Invalid,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Complete,
    Incomplete,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEvidence {
    pub state: EvidenceState,
    pub source: Option<String>,
    pub receipt_ref: Option<String>,
    pub observed_at_unix_ms: Option<u64>,
    pub expires_at_unix_ms: Option<u64>,
}

impl RegistryEvidence {
    pub fn known(source: impl Into<String>, receipt_ref: impl Into<String>) -> Self {
        Self {
            state: EvidenceState::Known,
            source: Some(source.into()),
            receipt_ref: Some(receipt_ref.into()),
            observed_at_unix_ms: None,
            expires_at_unix_ms: None,
        }
    }

    pub const fn missing() -> Self {
        Self {
            state: EvidenceState::Missing,
            source: None,
            receipt_ref: None,
            observed_at_unix_ms: None,
            expires_at_unix_ms: None,
        }
    }

    fn validate(&self, field: &'static str) -> Result<(), ModelRegistryError> {
        match (&self.source, &self.receipt_ref) {
            (Some(source), Some(receipt))
                if source.trim().is_empty()
                    || receipt.trim().is_empty()
                    || source.chars().any(char::is_control)
                    || receipt.chars().any(char::is_control) =>
            {
                Err(ModelRegistryError::InvalidField(field))
            }
            (Some(_), Some(_))
                if self.state == EvidenceState::Known
                    && (self.observed_at_unix_ms.is_none()
                        || self.expires_at_unix_ms.is_none()) =>
            {
                Err(ModelRegistryError::InvalidField(field))
            }
            (Some(_), Some(_))
                if self
                    .observed_at_unix_ms
                    .zip(self.expires_at_unix_ms)
                    .is_some_and(|(observed, expires)| observed > expires) =>
            {
                Err(ModelRegistryError::InvalidField(field))
            }
            (Some(_), Some(_)) => Ok(()),
            (None, None) if self.state == EvidenceState::Known => {
                Err(ModelRegistryError::InvalidField(field))
            }
            (None, None) if self.state != EvidenceState::Known => Ok(()),
            _ => Err(ModelRegistryError::InvalidField(field)),
        }
    }

    fn current(&self, now_unix_ms: u64) -> EvidenceState {
        if self.state != EvidenceState::Known {
            return self.state;
        }
        match (self.observed_at_unix_ms, self.expires_at_unix_ms) {
            (Some(observed), Some(expires))
                if observed <= now_unix_ms && now_unix_ms <= expires =>
            {
                EvidenceState::Known
            }
            (Some(_), Some(_)) => EvidenceState::Stale,
            _ => EvidenceState::Missing,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RegistryRoute {
    Present {
        entry: ModelCatalogueEntry,
        evidence: RegistryEvidence,
    },
    Missing {
        route: RouteFingerprint,
        reason: String,
        evidence: RegistryEvidence,
    },
}

impl RegistryRoute {
    pub fn route(&self) -> &RouteFingerprint {
        match self {
            Self::Present { entry, .. } => &entry.route,
            Self::Missing { route, .. } => route,
        }
    }

    pub fn entry(&self) -> Option<&ModelCatalogueEntry> {
        match self {
            Self::Present { entry, .. } => Some(entry),
            Self::Missing { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRegistrySnapshot {
    pub schema_version: String,
    pub source_schema_version: String,
    pub source_snapshot_id: String,
    pub source_revision: Option<String>,
    pub account_scope: String,
    pub expected_route_count: usize,
    pub coverage: CoverageState,
    pub refresh_owner: Option<String>,
    pub routes: Vec<RegistryRoute>,
    pub source_evidence: RegistryEvidence,
    pub probe_evidence: RegistryEvidence,
    pub usage_evidence: RegistryEvidence,
    pub capacity_evidence: RegistryEvidence,
    pub canonical_digest: String,
    pub invalidation: Vec<String>,
}

impl ModelRegistrySnapshot {
    pub fn from_catalogue(catalogue: &ModelCatalogueSnapshot) -> Result<Self, ModelRegistryError> {
        let expected = catalogue
            .entries
            .iter()
            .map(|entry| entry.route.clone())
            .collect();
        let mut snapshot = Self::with_expected_routes(catalogue, expected)?;
        snapshot.coverage = if catalogue.entries.is_empty() {
            CoverageState::Complete
        } else {
            CoverageState::Unknown
        };
        snapshot.canonical_digest = snapshot_digest(&snapshot)?;
        Ok(snapshot)
    }

    pub fn with_expected_routes(
        catalogue: &ModelCatalogueSnapshot,
        expected_routes: Vec<RouteFingerprint>,
    ) -> Result<Self, ModelRegistryError> {
        catalogue.validate()?;
        if expected_routes.len() > MAX_EXPECTED_ROUTES {
            return Err(ModelRegistryError::InvalidField("expected_route_count"));
        }
        let expected_route_count = expected_routes.len();
        let mut expected = BTreeMap::new();
        for route in expected_routes {
            route
                .validate()
                .map_err(|error| ModelRegistryError::InvalidSource(error.to_string()))?;
            let key = route_key(&route)?;
            if expected.insert(key, route).is_some() {
                return Err(ModelRegistryError::DuplicateRoute);
            }
        }
        let mut present = BTreeMap::new();
        for entry in &catalogue.entries {
            let key = route_key(&entry.route)?;
            present.insert(key, entry.clone());
        }
        let mut routes = Vec::with_capacity(expected.len());
        for (key, route) in expected {
            if let Some(entry) = present.remove(&key) {
                routes.push(RegistryRoute::Present {
                    evidence: evidence_for_entry(&entry),
                    entry,
                });
            } else {
                routes.push(RegistryRoute::Missing {
                    route,
                    reason: "expected route absent from supplied catalogue".to_owned(),
                    evidence: RegistryEvidence::missing(),
                });
            }
        }
        if !present.is_empty() {
            return Err(ModelRegistryError::InvalidField("catalogue.entries"));
        }
        let mut snapshot = Self {
            schema_version: MODEL_REGISTRY_SCHEMA_VERSION.to_owned(),
            source_schema_version: catalogue.schema_version.clone(),
            source_snapshot_id: catalogue.snapshot_id.clone(),
            source_revision: None,
            account_scope: catalogue.account_scope.clone(),
            expected_route_count: routes.len(),
            coverage: if expected_route_count == catalogue.entries.len() {
                CoverageState::Complete
            } else {
                CoverageState::Incomplete
            },
            refresh_owner: Some(catalogue.collector_identity.clone()),
            routes,
            source_evidence: RegistryEvidence {
                state: EvidenceState::Known,
                source: Some(catalogue.collector_identity.clone()),
                receipt_ref: Some(catalogue.snapshot_id.clone()),
                observed_at_unix_ms: Some(catalogue.observed_at_unix_ms),
                expires_at_unix_ms: Some(catalogue.expires_at_unix_ms),
            },
            probe_evidence: RegistryEvidence::missing(),
            usage_evidence: RegistryEvidence::missing(),
            capacity_evidence: RegistryEvidence::missing(),
            canonical_digest: String::new(),
            invalidation: Vec::new(),
        };
        snapshot.canonical_digest = snapshot_digest(&snapshot)?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), ModelRegistryError> {
        if self.schema_version != MODEL_REGISTRY_SCHEMA_VERSION
            || self.source_schema_version.trim().is_empty()
            || self.source_snapshot_id.trim().is_empty()
            || self.account_scope.trim().is_empty()
            || self.expected_route_count != self.routes.len()
        {
            return Err(ModelRegistryError::InvalidField("registry.identity"));
        }
        self.source_evidence.validate("registry.source_evidence")?;
        self.probe_evidence.validate("registry.probe_evidence")?;
        self.usage_evidence.validate("registry.usage_evidence")?;
        self.capacity_evidence
            .validate("registry.capacity_evidence")?;
        if self
            .source_revision
            .as_deref()
            .is_some_and(|revision| revision.trim().is_empty())
            || self
                .refresh_owner
                .as_deref()
                .is_some_and(|owner| owner.trim().is_empty())
        {
            return Err(ModelRegistryError::InvalidField("registry.refresh_owner"));
        }
        let mut seen = BTreeSet::new();
        for route in &self.routes {
            let key = route_key(route.route())?;
            if !seen.insert(key) {
                return Err(ModelRegistryError::DuplicateRoute);
            }
            match route {
                RegistryRoute::Present { entry, evidence } => {
                    entry.validate(&self.account_scope)?;
                    evidence.validate("registry.route_evidence")?;
                }
                RegistryRoute::Missing {
                    route,
                    reason,
                    evidence,
                } => {
                    route
                        .validate()
                        .map_err(|error| ModelRegistryError::InvalidSource(error.to_string()))?;
                    if reason.trim().is_empty() {
                        return Err(ModelRegistryError::InvalidField("registry.missing.reason"));
                    }
                    evidence.validate("registry.missing.evidence")?;
                }
            }
        }
        if self.canonical_digest != snapshot_digest(self)? {
            return Err(ModelRegistryError::InvalidField(
                "registry.canonical_digest",
            ));
        }
        Ok(())
    }

    pub fn missing_route_count(&self) -> usize {
        self.routes
            .iter()
            .filter(|route| route.entry().is_none())
            .count()
    }

    pub fn complete(&self) -> bool {
        self.coverage == CoverageState::Complete
            && self.missing_route_count() == 0
            && self.invalidation.is_empty()
    }
}

fn evidence_for_entry(_entry: &ModelCatalogueEntry) -> RegistryEvidence {
    // Billing evidence is scoped to billing.  It cannot be promoted to a
    // route-wide receipt or to proof for unrelated capability dimensions.
    RegistryEvidence::missing()
}

fn route_key(route: &RouteFingerprint) -> Result<String, ModelRegistryError> {
    route
        .canonical_json()
        .map_err(|error| ModelRegistryError::Serialization(error.to_string()))
}

fn digest<T: Serialize>(value: &T) -> Result<String, ModelRegistryError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ModelRegistryError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", eliot_receipts::sha256_hex(&bytes)))
}

fn snapshot_digest(snapshot: &ModelRegistrySnapshot) -> Result<String, ModelRegistryError> {
    let mut normalized = snapshot.clone();
    normalized.canonical_digest.clear();
    digest(&normalized)
}

fn route_sort_key(route: &RouteFingerprint) -> String {
    route_key(route).unwrap_or_default()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostCeiling {
    pub amount_microunits: u64,
    pub currency: String,
    pub unit: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequirements {
    pub task_id: String,
    pub attempt_id: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub policy_revision: String,
    pub supplied_at_unix_ms: u64,
    pub required_capabilities: BTreeSet<String>,
    pub forbidden_capabilities: BTreeSet<String>,
    pub required_modalities: BTreeSet<String>,
    pub required_tool_semantics: Option<String>,
    pub required_structured_output: Option<bool>,
    pub minimum_context_window: Option<u64>,
    pub minimum_input_tokens: Option<u64>,
    pub minimum_output_tokens: Option<u64>,
    pub minimum_reasoning_tokens: Option<u64>,
    pub privacy_class: Option<String>,
    pub retention_class: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub cost_ceiling: Option<CostCeiling>,
    pub allowed_route_classes: BTreeSet<String>,
    pub allow_degraded: bool,
    pub require_fresh_capacity: bool,
    pub require_complete_coverage: bool,
    pub require_reliable: bool,
    pub deadline_unix_ms: Option<u64>,
    pub preferred_routes: Vec<RouteFingerprint>,
    pub fallback_policy: Option<String>,
}

impl RouteRequirements {
    pub fn new(
        task_id: impl Into<String>,
        attempt_id: impl Into<String>,
        scope: impl Into<String>,
        state_fence: StateFence,
        policy_revision: impl Into<String>,
        supplied_at_unix_ms: u64,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            attempt_id: attempt_id.into(),
            scope: scope.into(),
            state_fence,
            policy_revision: policy_revision.into(),
            supplied_at_unix_ms,
            required_capabilities: BTreeSet::new(),
            forbidden_capabilities: BTreeSet::new(),
            required_modalities: BTreeSet::new(),
            required_tool_semantics: None,
            required_structured_output: None,
            minimum_context_window: None,
            minimum_input_tokens: None,
            minimum_output_tokens: None,
            minimum_reasoning_tokens: None,
            privacy_class: None,
            retention_class: None,
            locality: None,
            region: None,
            cost_ceiling: None,
            allowed_route_classes: BTreeSet::new(),
            allow_degraded: false,
            require_fresh_capacity: false,
            require_complete_coverage: false,
            require_reliable: false,
            deadline_unix_ms: None,
            preferred_routes: Vec::new(),
            fallback_policy: None,
        }
    }

    fn validate(&self) -> Result<(), ModelRegistryError> {
        if self.task_id.trim().is_empty()
            || self.attempt_id.trim().is_empty()
            || self.scope.trim().is_empty()
            || self.policy_revision.trim().is_empty()
            || self.supplied_at_unix_ms == 0
            || self.state_fence.validate().is_err()
        {
            return Err(ModelRegistryError::InvalidField("requirements.binding"));
        }
        if self.preferred_routes.len() > MAX_REQUIREMENTS {
            return Err(ModelRegistryError::InvalidField(
                "requirements.preferred_routes",
            ));
        }
        for value in self
            .required_capabilities
            .iter()
            .chain(&self.forbidden_capabilities)
            .chain(&self.required_modalities)
            .chain(&self.allowed_route_classes)
        {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ModelRegistryError::InvalidField("requirements.vocabulary"));
            }
        }
        for value in [
            self.required_tool_semantics.as_deref(),
            self.privacy_class.as_deref(),
            self.retention_class.as_deref(),
            self.locality.as_deref(),
            self.region.as_deref(),
            self.fallback_policy.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(ModelRegistryError::InvalidField("requirements.value"));
            }
        }
        if let Some(ceiling) = &self.cost_ceiling
            && (ceiling.currency.trim().is_empty()
                || ceiling.unit.trim().is_empty()
                || ceiling.currency.chars().any(char::is_control)
                || ceiling.unit.chars().any(char::is_control))
        {
            return Err(ModelRegistryError::InvalidField(
                "requirements.cost_ceiling",
            ));
        }
        for route in &self.preferred_routes {
            route
                .validate()
                .map_err(|_| ModelRegistryError::InvalidField("requirements.preferred_routes"))?;
        }
        if self
            .deadline_unix_ms
            .is_some_and(|deadline| deadline < self.supplied_at_unix_ms)
        {
            return Err(ModelRegistryError::InvalidField("requirements.deadline"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RankingDimension {
    PreferenceOrder,
    BillingClass,
    CostClass,
    LatencyClass,
    RouteHealth,
    Availability,
    Quota,
    RouteIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankingPolicy {
    pub schema_version: String,
    pub revision: String,
    pub lexicographic: Vec<RankingDimension>,
}

impl RankingPolicy {
    pub fn new(revision: impl Into<String>, lexicographic: Vec<RankingDimension>) -> Self {
        Self {
            schema_version: "eliot.agent-model-ranking-policy/v1".to_owned(),
            revision: revision.into(),
            lexicographic,
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != "eliot.agent-model-ranking-policy/v1"
            || self.revision.trim().is_empty()
            || self.lexicographic.is_empty()
        {
            return Err("ranking policy is absent or invalid");
        }
        let mut seen = BTreeSet::new();
        if self
            .lexicographic
            .iter()
            .any(|dimension| !seen.insert(dimension))
        {
            return Err("ranking policy contains contradictory duplicate dimensions");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RankingPolicyInput {
    Provided(RankingPolicy),
    Missing,
}

impl From<&RankingPolicy> for RankingPolicyInput {
    fn from(value: &RankingPolicy) -> Self {
        Self::Provided(value.clone())
    }
}

impl From<RankingPolicy> for RankingPolicyInput {
    fn from(value: RankingPolicy) -> Self {
        Self::Provided(value)
    }
}

impl From<Option<&RankingPolicy>> for RankingPolicyInput {
    fn from(value: Option<&RankingPolicy>) -> Self {
        value.map_or(Self::Missing, |policy| Self::Provided(policy.clone()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckDisposition {
    Pass,
    Fail,
    Missing,
    Stale,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardCheck {
    pub dimension: String,
    pub disposition: CheckDisposition,
    pub detail: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteExplanation {
    pub route: RouteFingerprint,
    pub entry_id: Option<String>,
    pub checks: Vec<HardCheck>,
    pub failures: Vec<HardCheck>,
    pub missing_evidence: Vec<HardCheck>,
    pub eligible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RankingDisposition {
    Ranked,
    PolicyNeeded,
    PolicyMissing,
    PolicyInvalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSearchResult {
    pub schema_version: String,
    pub task_id: String,
    pub attempt_id: String,
    pub scope: String,
    pub snapshot_digest: String,
    pub requirements_digest: String,
    pub ranking_policy_digest: Option<String>,
    pub expected_route_count: usize,
    pub missing_route_count: usize,
    pub complete: bool,
    pub coverage: CoverageState,
    pub refresh_owner: Option<String>,
    pub explanations: Vec<RouteExplanation>,
    pub eligible: Vec<ModelCatalogueEntry>,
    pub ranking: RankingDisposition,
    pub ranking_blocker: Option<String>,
    pub unresolved_facts: Vec<String>,
    pub execution: ZeroModelExecutionCounters,
    pub proof_ceiling: ProofCeiling,
}

fn check(
    dimension: &str,
    disposition: CheckDisposition,
    detail: impl Into<String>,
    evidence_refs: Vec<String>,
) -> HardCheck {
    HardCheck {
        dimension: dimension.to_owned(),
        disposition,
        detail: detail.into(),
        evidence_refs,
    }
}

fn evidence_refs(evidence: &RegistryEvidence) -> Vec<String> {
    evidence
        .source
        .iter()
        .chain(evidence.receipt_ref.iter())
        .cloned()
        .collect()
}

fn capability_refs(entry: &ModelCatalogueEntry, capability: &str) -> Vec<String> {
    entry
        .capabilities
        .get(capability)
        .map(|observation| vec![observation.receipt_ref.clone()])
        .unwrap_or_default()
}

fn base_dispatch_blockers(
    snapshot: &ModelRegistrySnapshot,
    entry: &ModelCatalogueEntry,
    requirements: &RouteRequirements,
) -> Vec<crate::model_control::DispatchBlocker> {
    // Keep the legacy dispatch semantics in one shared evaluator.  The
    // registry only projects its result; it does not mint admission facts.
    let (Some(source), Some(observed), Some(expires)) = (
        snapshot.source_evidence.source.clone(),
        snapshot.source_evidence.observed_at_unix_ms,
        snapshot.source_evidence.expires_at_unix_ms,
    ) else {
        return Vec::new();
    };
    base_dispatch_blockers_for_catalogue(
        &ModelCatalogueSnapshot {
            schema_version: snapshot.source_schema_version.clone(),
            snapshot_id: snapshot.source_snapshot_id.clone(),
            account_scope: snapshot.account_scope.clone(),
            collector_identity: source,
            observed_at_unix_ms: observed,
            expires_at_unix_ms: expires,
            entries: Vec::new(),
        },
        entry,
        &requirements.required_capabilities,
        requirements.minimum_context_window.unwrap_or_default(),
        requirements.allow_degraded,
        requirements.supplied_at_unix_ms,
    )
}

fn base_dispatch_blockers_for_catalogue(
    snapshot: &ModelCatalogueSnapshot,
    entry: &ModelCatalogueEntry,
    required_capabilities: &BTreeSet<String>,
    minimum_context_window: u64,
    allow_degraded: bool,
    now_unix_ms: u64,
) -> Vec<crate::model_control::DispatchBlocker> {
    super::dispatch_blockers(
        snapshot,
        entry,
        required_capabilities,
        minimum_context_window,
        allow_degraded,
        now_unix_ms,
    )
}

#[allow(clippy::too_many_lines)]
fn route_checks(
    snapshot: &ModelRegistrySnapshot,
    route: &RegistryRoute,
    requirements: &RouteRequirements,
) -> RouteExplanation {
    let mut checks = Vec::new();
    let Some(entry) = route.entry() else {
        let (reason, evidence) = match route {
            RegistryRoute::Missing {
                reason, evidence, ..
            } => (reason.as_str(), evidence),
            RegistryRoute::Present { .. } => unreachable!("present route has an entry"),
        };
        let disposition = match evidence.current(requirements.supplied_at_unix_ms) {
            EvidenceState::Stale => CheckDisposition::Stale,
            EvidenceState::Invalid => CheckDisposition::Fail,
            EvidenceState::NotApplicable => CheckDisposition::NotApplicable,
            EvidenceState::Known | EvidenceState::Missing => CheckDisposition::Missing,
        };
        checks.push(check(
            "route_presence",
            disposition,
            reason,
            evidence_refs(evidence),
        ));
        return RouteExplanation {
            route: route.route().clone(),
            entry_id: None,
            failures: Vec::new(),
            missing_evidence: checks.clone(),
            checks,
            eligible: false,
        };
    };
    let base_blockers = base_dispatch_blockers(snapshot, entry, requirements);
    let source_state = snapshot
        .source_evidence
        .current(requirements.supplied_at_unix_ms);
    checks.push(check(
        "catalogue_source",
        if base_blockers.iter().any(|blocker| {
            matches!(
                blocker,
                crate::model_control::DispatchBlocker::CatalogueStale
            )
        }) {
            CheckDisposition::Stale
        } else {
            match source_state {
                EvidenceState::Known => CheckDisposition::Pass,
                EvidenceState::Stale => CheckDisposition::Stale,
                EvidenceState::Missing | EvidenceState::Invalid => CheckDisposition::Missing,
                EvidenceState::NotApplicable => CheckDisposition::NotApplicable,
            }
        },
        "catalogue source freshness",
        evidence_refs(&snapshot.source_evidence),
    ));
    let refs = entry.evidence_refs.clone();
    checks.push(check(
        "schema",
        CheckDisposition::Pass,
        "catalogue schema accepted",
        refs.clone(),
    ));
    let route_class = if requirements.allowed_route_classes.is_empty() {
        CheckDisposition::Pass
    } else {
        CheckDisposition::Missing
    };
    checks.push(check(
        "allowed_route_class",
        route_class,
        "route class constraint",
        Vec::new(),
    ));
    let admission = if entry.route_admission == RouteAdmissionStatus::Admitted {
        CheckDisposition::Pass
    } else {
        CheckDisposition::Fail
    };
    checks.push(check(
        "admission",
        admission,
        "route admission is an input fact",
        Vec::new(),
    ));
    let health = match entry.route_health {
        RouteHealthStatus::Healthy => CheckDisposition::Pass,
        RouteHealthStatus::Degraded if requirements.allow_degraded => CheckDisposition::Pass,
        RouteHealthStatus::Degraded | RouteHealthStatus::Unavailable => CheckDisposition::Fail,
        RouteHealthStatus::Unknown => CheckDisposition::Missing,
    };
    checks.push(check(
        "readiness",
        health,
        "route readiness/health",
        Vec::new(),
    ));
    let availability = match entry.availability {
        ModelAvailability::Available => CheckDisposition::Pass,
        ModelAvailability::Degraded if requirements.allow_degraded => CheckDisposition::Pass,
        ModelAvailability::Degraded | ModelAvailability::Unavailable => CheckDisposition::Fail,
        ModelAvailability::Unknown => CheckDisposition::Missing,
    };
    checks.push(check(
        "availability",
        availability,
        "model availability",
        Vec::new(),
    ));
    for capability in &requirements.required_capabilities {
        let result = match entry.capabilities.get(capability).map(|value| value.status) {
            Some(crate::model_control::CapabilityStatus::Supported) => CheckDisposition::Pass,
            Some(crate::model_control::CapabilityStatus::Unsupported) => CheckDisposition::Fail,
            Some(crate::model_control::CapabilityStatus::Unknown) | None => {
                CheckDisposition::Missing
            }
        };
        checks.push(check(
            &format!("capability:{capability}"),
            result,
            "required capability evidence",
            capability_refs(entry, capability),
        ));
    }
    for capability in &requirements.forbidden_capabilities {
        let result = match entry.capabilities.get(capability).map(|value| value.status) {
            Some(crate::model_control::CapabilityStatus::Supported) => CheckDisposition::Fail,
            Some(crate::model_control::CapabilityStatus::Unsupported) => CheckDisposition::Pass,
            Some(crate::model_control::CapabilityStatus::Unknown) | None => {
                CheckDisposition::Missing
            }
        };
        checks.push(check(
            &format!("forbidden_capability:{capability}"),
            result,
            "forbidden capability evidence",
            capability_refs(entry, capability),
        ));
    }
    for modality in &requirements.required_modalities {
        checks.push(check(
            &format!("modality:{modality}"),
            CheckDisposition::Missing,
            "catalogue entry has no modality evidence",
            Vec::new(),
        ));
    }
    if let Some(minimum) = requirements.minimum_context_window {
        checks.push(check(
            "context_window",
            if entry.context_window >= minimum {
                CheckDisposition::Pass
            } else {
                CheckDisposition::Fail
            },
            "context window boundary",
            Vec::new(),
        ));
    }
    for (dimension, required) in [
        ("input_tokens", requirements.minimum_input_tokens),
        ("output_tokens", requirements.minimum_output_tokens),
        ("reasoning_tokens", requirements.minimum_reasoning_tokens),
    ] {
        if required.is_some() {
            checks.push(check(
                dimension,
                CheckDisposition::Missing,
                "catalogue has no independent evidence for requested behavior limit",
                Vec::new(),
            ));
        }
    }
    if requirements.required_tool_semantics.is_some() {
        checks.push(check(
            "tool_semantics",
            CheckDisposition::Missing,
            "catalogue has no tool-semantics capability evidence",
            Vec::new(),
        ));
    }
    if requirements.required_structured_output.is_some() {
        checks.push(check(
            "structured_output",
            CheckDisposition::Missing,
            "catalogue has no structured-output capability evidence",
            Vec::new(),
        ));
    }
    for dimension in ["privacy", "retention", "locality", "region"] {
        let required = match dimension {
            "privacy" => requirements.privacy_class.is_some(),
            "retention" => requirements.retention_class.is_some(),
            "locality" => requirements.locality.is_some(),
            _ => requirements.region.is_some(),
        };
        if required {
            checks.push(check(
                dimension,
                CheckDisposition::Missing,
                "privacy evidence is not present in the catalogue entry",
                Vec::new(),
            ));
        }
    }
    if let Some(ceiling) = &requirements.cost_ceiling {
        if ceiling.currency.trim().is_empty() || ceiling.unit.trim().is_empty() {
            checks.push(check(
                "cost",
                CheckDisposition::Fail,
                "cost ceiling currency and unit are required",
                Vec::new(),
            ));
        } else {
            checks.push(check(
                "cost",
                CheckDisposition::Missing,
                "catalogue cost has no compatible currency/unit value",
                Vec::new(),
            ));
        }
    }
    let billing = if entry.billing.is_current(requirements.supplied_at_unix_ms)
        && entry.billing.class != BillingClass::Unknown
    {
        CheckDisposition::Pass
    } else if !entry.billing.is_current(requirements.supplied_at_unix_ms) {
        CheckDisposition::Stale
    } else {
        CheckDisposition::Missing
    };
    checks.push(check(
        "billing",
        billing,
        "billing evidence",
        vec![
            entry.billing.receipt_ref.clone(),
            entry.billing.source.clone(),
        ],
    ));
    let quota = if entry.quota.is_current(requirements.supplied_at_unix_ms) {
        match entry.quota.disposition {
            QuotaDisposition::Available | QuotaDisposition::Low => CheckDisposition::Pass,
            QuotaDisposition::Exhausted => CheckDisposition::Fail,
            QuotaDisposition::Unknown | QuotaDisposition::NotExposed => CheckDisposition::Missing,
        }
    } else {
        CheckDisposition::Stale
    };
    checks.push(check(
        "quota",
        quota,
        "quota evidence",
        vec![entry.quota.receipt_ref.clone(), entry.quota.source.clone()],
    ));
    if requirements.require_fresh_capacity {
        let capacity = snapshot
            .capacity_evidence
            .current(requirements.supplied_at_unix_ms);
        checks.push(check(
            "capacity",
            match capacity {
                EvidenceState::Known => CheckDisposition::Pass,
                EvidenceState::Stale => CheckDisposition::Stale,
                EvidenceState::Missing | EvidenceState::Invalid => CheckDisposition::Missing,
                EvidenceState::NotApplicable => CheckDisposition::NotApplicable,
            },
            "capacity evidence",
            evidence_refs(&snapshot.capacity_evidence),
        ));
    }
    if requirements.require_reliable {
        checks.push(check(
            "reliability",
            CheckDisposition::Missing,
            "reliability evidence is not supplied by the catalogue",
            Vec::new(),
        ));
    }
    if requirements
        .deadline_unix_ms
        .is_some_and(|deadline| deadline < requirements.supplied_at_unix_ms)
    {
        checks.push(check(
            "deadline",
            CheckDisposition::Fail,
            "deadline is already elapsed",
            refs,
        ));
    }
    let failures = checks
        .iter()
        .filter(|item| item.disposition == CheckDisposition::Fail)
        .cloned()
        .collect::<Vec<_>>();
    let missing_evidence = checks
        .iter()
        .filter(|item| {
            matches!(
                item.disposition,
                CheckDisposition::Missing | CheckDisposition::Stale
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    RouteExplanation {
        route: entry.route.clone(),
        entry_id: Some(entry.entry_id.clone()),
        eligible: failures.is_empty() && missing_evidence.is_empty(),
        checks,
        failures,
        missing_evidence,
    }
}

fn preference_rank(route: &RouteFingerprint, preferred: &[RouteFingerprint]) -> usize {
    preferred
        .iter()
        .position(|candidate| candidate == route)
        .unwrap_or(usize::MAX)
}

fn compare_entries(
    left: &ModelCatalogueEntry,
    right: &ModelCatalogueEntry,
    policy: &RankingPolicy,
    requirements: &RouteRequirements,
) -> Ordering {
    for dimension in &policy.lexicographic {
        let ordering = match dimension {
            RankingDimension::PreferenceOrder => {
                preference_rank(&left.route, &requirements.preferred_routes).cmp(&preference_rank(
                    &right.route,
                    &requirements.preferred_routes,
                ))
            }
            RankingDimension::BillingClass => left.billing.class.cmp(&right.billing.class),
            RankingDimension::CostClass => left.cost_class.cmp(&right.cost_class),
            RankingDimension::LatencyClass => left.latency_class.cmp(&right.latency_class),
            RankingDimension::RouteHealth => left.route_health.cmp(&right.route_health),
            RankingDimension::Availability => left.availability.cmp(&right.availability),
            RankingDimension::Quota => left.quota.disposition.cmp(&right.quota.disposition),
            RankingDimension::RouteIdentity => route_key(&left.route)
                .ok()
                .cmp(&route_key(&right.route).ok()),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    route_key(&left.route)
        .ok()
        .cmp(&route_key(&right.route).ok())
}

pub fn find_models<P>(
    snapshot: &ModelRegistrySnapshot,
    requirements: &RouteRequirements,
    ranking_policy: P,
) -> Result<ModelSearchResult, ModelRegistryError>
where
    P: Into<RankingPolicyInput>,
{
    snapshot.validate()?;
    requirements.validate()?;
    let ranking_policy = ranking_policy.into();
    let policy = match ranking_policy {
        RankingPolicyInput::Provided(policy) => Some(policy),
        RankingPolicyInput::Missing => None,
    };
    let mut explanations = snapshot
        .routes
        .iter()
        .map(|route| route_checks(snapshot, route, requirements))
        .collect::<Vec<_>>();
    explanations.sort_by_key(|left| route_sort_key(&left.route));
    let mut eligible = explanations
        .iter()
        .filter(|explanation| explanation.eligible)
        .filter_map(|explanation| {
            snapshot.routes.iter().find_map(|route| {
                (route.route() == &explanation.route)
                    .then(|| route.entry().cloned())
                    .flatten()
            })
        })
        .collect::<Vec<_>>();
    if requirements.require_complete_coverage && snapshot.coverage != CoverageState::Complete {
        eligible.clear();
    }
    let (ranking, ranking_blocker) = if let Some(ref policy) = policy {
        if policy.validate().is_ok() {
            eligible.sort_by(|left, right| compare_entries(left, right, policy, requirements));
            (RankingDisposition::Ranked, None)
        } else {
            eligible.sort_by(|left, right| {
                route_sort_key(&left.route).cmp(&route_sort_key(&right.route))
            });
            (
                RankingDisposition::PolicyInvalid,
                Some("supplied ranking policy is invalid or contradictory".to_owned()),
            )
        }
    } else {
        eligible.sort_by_key(|left| route_sort_key(&left.route));
        (
            RankingDisposition::PolicyMissing,
            Some("a versioned ranking policy is required".to_owned()),
        )
    };
    let mut unresolved_facts = Vec::new();
    for explanation in &explanations {
        for item in &explanation.missing_evidence {
            unresolved_facts.push(format!(
                "{}:{}",
                explanation.entry_id.as_deref().unwrap_or("missing"),
                item.dimension
            ));
        }
    }
    unresolved_facts.sort();
    unresolved_facts.dedup();
    if requirements.require_complete_coverage && snapshot.coverage != CoverageState::Complete {
        unresolved_facts.push("registry:coverage".to_owned());
    }
    let requirements_digest = digest(requirements)?;
    let ranking_policy_digest = policy.as_ref().map(digest).transpose()?;
    Ok(ModelSearchResult {
        schema_version: MODEL_SEARCH_SCHEMA_VERSION.to_owned(),
        task_id: requirements.task_id.clone(),
        attempt_id: requirements.attempt_id.clone(),
        scope: requirements.scope.clone(),
        snapshot_digest: snapshot.canonical_digest.clone(),
        requirements_digest,
        ranking_policy_digest,
        expected_route_count: snapshot.expected_route_count,
        missing_route_count: snapshot.missing_route_count(),
        complete: snapshot.complete(),
        coverage: snapshot.coverage,
        refresh_owner: snapshot.refresh_owner.clone(),
        explanations,
        eligible,
        ranking,
        ranking_blocker,
        unresolved_facts,
        execution: ZeroModelExecutionCounters::zero(),
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

/// Compatibility delegation for the existing model-control consumer.  The
/// legacy receipt remains its public shape; eligibility is evaluated here so
/// `model_control` has one registry owner for the selection decision.
#[allow(clippy::too_many_lines)]
pub(crate) fn compile_model_selection(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
    role: ModelRole,
    selection_id: &str,
    now_unix_ms: u64,
) -> Result<ModelSelectionReceipt, ModelControlError> {
    snapshot.validate()?;
    policy.validate()?;
    if snapshot.account_scope != policy.account_scope {
        return Err(ModelControlError::InvalidField("selection.account_scope"));
    }
    if !snapshot.is_current(now_unix_ms) {
        return Err(ModelControlError::StaleCatalogue);
    }
    let preference = policy
        .roles
        .iter()
        .find(|preference| preference.role == role)
        .ok_or(ModelControlError::MissingRolePolicy(role))?;
    let mut eligible = Vec::new();
    let mut rejected = Vec::new();
    for entry in &snapshot.entries {
        let base_blockers = base_dispatch_blockers_for_catalogue(
            snapshot,
            entry,
            &preference.required_capabilities,
            preference.minimum_context_window,
            preference.allow_degraded_routes,
            now_unix_ms,
        );
        let reasons = super::selection_rejections_with_blockers(entry, preference, base_blockers);
        if reasons.is_empty() {
            eligible.push((
                entry,
                preference_rank_selector(entry, &preference.preferred),
            ));
        } else {
            let mut reasons = reasons;
            if reasons.is_empty() {
                reasons.push(SelectionRejection::Dispatch(
                    crate::model_control::DispatchBlocker::RouteHealthUnknown,
                ));
            }
            rejected.push(crate::model_control::RejectedModelCandidate {
                entry_id: entry.entry_id.clone(),
                host_family: entry.host_family.clone(),
                provider_id: entry.provider_id.clone(),
                model_id: entry.model_id.clone(),
                reasons: reasons.into_iter().collect(),
            });
        }
    }
    eligible.sort_by(|(left, left_rank), (right, right_rank)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left.billing.class.cmp(&right.billing.class))
            .then_with(|| left.route_health.cmp(&right.route_health))
            .then_with(|| left.availability.cmp(&right.availability))
            .then_with(|| left.quota.disposition.cmp(&right.quota.disposition))
            .then_with(|| left.cost_class.cmp(&right.cost_class))
            .then_with(|| left.latency_class.cmp(&right.latency_class))
            .then_with(|| left.deterministic_key().cmp(&right.deterministic_key()))
            .then_with(|| route_sort_key(&left.route).cmp(&route_sort_key(&right.route)))
    });
    rejected.sort_by(|left, right| {
        left.host_family
            .cmp(&right.host_family)
            .then_with(|| left.provider_id.cmp(&right.provider_id))
            .then_with(|| left.model_id.cmp(&right.model_id))
            .then_with(|| left.entry_id.cmp(&right.entry_id))
    });
    let selected = eligible
        .first()
        .map(|(entry, _)| (*entry).clone())
        .ok_or(ModelControlError::NoDispatchableRoute(role))?;
    let catalogue_digest = super::catalogue_digest(snapshot)?;
    let preference_policy_digest = super::preference_policy_digest(policy)?;
    let selection_digest = super::canonical_digest(&(
        super::MODEL_SELECTION_RECEIPT_VERSION,
        selection_id,
        role,
        snapshot.snapshot_id.as_str(),
        catalogue_digest.as_str(),
        policy.policy_id.as_str(),
        policy.revision.as_str(),
        preference_policy_digest.as_str(),
        selected.entry_id.as_str(),
    ))?;
    let receipt = ModelSelectionReceipt {
        schema_version: super::MODEL_SELECTION_RECEIPT_VERSION.to_owned(),
        selection_id: selection_id.to_owned(),
        selection_digest,
        role,
        account_scope: snapshot.account_scope.clone(),
        catalogue_snapshot_id: snapshot.snapshot_id.clone(),
        catalogue_digest,
        preference_policy_id: policy.policy_id.clone(),
        preference_revision: policy.revision.clone(),
        preference_policy_digest,
        selected,
        rejected,
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn preference_rank_selector(entry: &ModelCatalogueEntry, selectors: &[ModelSelector]) -> usize {
    selectors
        .iter()
        .position(|selector| selector.matches(entry))
        .unwrap_or(usize::MAX)
}

pub(crate) fn query_model_catalogue(
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
                && super::text_matches(entry, query.text.as_deref())
                && (!query.free_only
                    || super::free_filter_matches(
                        entry,
                        query.include_subscription_included,
                        now_unix_ms,
                    ))
        })
        .filter_map(|entry| {
            let blockers = base_dispatch_blockers_for_catalogue(
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
        schema_version: super::MODEL_QUERY_RECEIPT_VERSION.to_owned(),
        query_id: query.query_id.clone(),
        catalogue_snapshot_id: snapshot.snapshot_id.clone(),
        catalogue_digest: super::catalogue_digest(snapshot)?,
        hits,
        execution: ZeroModelExecutionCounters::zero(),
    })
}
