//! Human-owned model preference policy contract.
//!
//! This module owns the policy-only schema for Human model preferences
//! (`HumanModelPreferencePolicy`, `RoleModelPreference`, `ModelSelector` and
//! their required enum dependencies), its structural validation, and the
//! canonical policy digest. It lives at this lower-level contract boundary so
//! the configuration/policy settings owner and the A-02 coordinator can share
//! one schema without a package cycle (issue #485, audit 5872395796).
//!
//! Catalogue-dependent selector matching, ranking, and queries stay in
//! `eliot-agent-coordinator`; only structural validation moves here. This
//! module performs no I/O, owns no store handle, and publishes nothing.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MODEL_PREFERENCE_SCHEMA_VERSION: &str = "eliot.agent-model-preference/v1";

const MAX_SELECTORS: usize = 256;

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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSelector {
    pub host_family: Option<String>,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub model_family: Option<String>,
}

impl ModelSelector {
    pub(crate) fn validate(&self) -> Result<(), ModelControlError> {
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
}

pub fn preference_policy_digest(
    policy: &HumanModelPreferencePolicy,
) -> Result<String, ModelControlError> {
    let mut normalized = policy.clone();
    normalized.roles.sort_by_key(|preference| preference.role);
    for preference in &mut normalized.roles {
        preference.denied.sort();
        preference.denied.dedup();
    }
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| ModelControlError::Serialization(error.to_string()))?;
    Ok(format!("sha256:{}", eliot_contracts::sha256_hex(&bytes)))
}
