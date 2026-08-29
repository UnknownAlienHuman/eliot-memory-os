//! Closed C0 contracts for Context provider registration and projection requests.
//!
//! The crate defines a denominator. It owns no provider implementation,
//! canonical read, Context admission, delivery receipt, ranking, or model call.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, RequestId, StateFence, TaskId, TaskRevision,
    canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.smart.context-contracts";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

const MAX_PROVIDERS: usize = 128;
const MAX_ROLES: usize = 32;
const MAX_ATOMS: usize = 8_192;
const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContextContractError {
    #[error("foundation contract: {0}")]
    Foundation(#[from] ContractError),
    #[error("{field} must be non-blank, bounded, and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} exceeds limit {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    #[error("duplicate {field}: {value}")]
    Duplicate { field: &'static str, value: String },
    #[error("provider values use incompatible state fences")]
    FenceMismatch,
    #[error("provider does not support role {0:?}")]
    RoleUnsupported(ContextRole),
    #[error("provider registry invariant failed: {0}")]
    RegistryInvalid(&'static str),
    #[error("expected-provider disposition hides availability")]
    DispositionInvalid,
    #[error("digest mismatch for {field}")]
    DigestMismatch { field: &'static str },
    #[error("cannot canonicalize contract value: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), ContextContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ContextContractError::InvalidText { field });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ContextContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ContextContractError::InvalidDigest { field });
    }
    Ok(())
}

#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn new(value: impl Into<String>) -> Result<Self, ContextContractError> {
        let value = value.into();
        validate_text(&value, "provider_id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextRole {
    Goal,
    Attention,
    Evidence,
    Model,
    Continuity,
    Safety,
    Unknown,
    Affordance,
    DecisionTail,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextProviderClass {
    GoalAcceptance,
    CriticalAttention,
    EpistemicPosition,
    Memory,
    UnderstandingModel,
    Continuity,
    SafetyNegativeMemory,
    Affordance,
    DecisionTail,
    SelfModel,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderAvailabilityClass {
    Available,
    Degraded,
    Unavailable,
    Stale,
    Unsupported,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderRequirement {
    Mandatory,
    Optional,
    Advisory,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProviderDescriptor {
    pub provider_id: ProviderId,
    pub class: ContextProviderClass,
    pub generation: String,
    pub contract_identity: ContractIdentity,
    pub supported_roles: Vec<ContextRole>,
    pub availability: ProviderAvailabilityClass,
    pub state_fence: StateFence,
}

impl ContextProviderDescriptor {
    pub fn validate(&self) -> Result<(), ContextContractError> {
        validate_text(self.provider_id.as_str(), "provider.provider_id")?;
        validate_text(&self.generation, "provider.generation")?;
        self.contract_identity.validate()?;
        self.state_fence.validate()?;
        if self.supported_roles.is_empty() || self.supported_roles.len() > MAX_ROLES {
            return Err(ContextContractError::LimitExceeded {
                field: "provider.supported_roles",
                limit: MAX_ROLES,
            });
        }
        let roles: BTreeSet<_> = self.supported_roles.iter().copied().collect();
        if roles.len() != self.supported_roles.len() {
            return Err(ContextContractError::Duplicate {
                field: "provider.supported_roles",
                value: self.provider_id.to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProviderRegistrySnapshot {
    pub registry_revision: TaskRevision,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub providers: Vec<ContextProviderDescriptor>,
    pub snapshot_sha256: String,
}

pub fn context_provider_registry_digest(
    registry: &ContextProviderRegistrySnapshot,
) -> Result<String, ContextContractError> {
    let mut normalized = registry.clone();
    normalized.snapshot_sha256.clear();
    normalized
        .providers
        .sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    for provider in &mut normalized.providers {
        provider.supported_roles.sort();
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| ContextContractError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn validate_context_provider_registry(
    registry: &ContextProviderRegistrySnapshot,
) -> Result<(), ContextContractError> {
    validate_text(&registry.scope_id, "registry.scope_id")?;
    registry.state_fence.validate()?;
    validate_digest(&registry.snapshot_sha256, "registry.snapshot_sha256")?;
    if registry.providers.is_empty() || registry.providers.len() > MAX_PROVIDERS {
        return Err(ContextContractError::LimitExceeded {
            field: "registry.providers",
            limit: MAX_PROVIDERS,
        });
    }
    let mut ids = BTreeSet::new();
    for provider in &registry.providers {
        provider.validate()?;
        if !registry
            .state_fence
            .is_compatible_with(&provider.state_fence)
        {
            return Err(ContextContractError::FenceMismatch);
        }
        if !ids.insert(provider.provider_id.as_str()) {
            return Err(ContextContractError::Duplicate {
                field: "registry.providers",
                value: provider.provider_id.to_string(),
            });
        }
    }
    if context_provider_registry_digest(registry)? != registry.snapshot_sha256 {
        return Err(ContextContractError::DigestMismatch {
            field: "registry.snapshot_sha256",
        });
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContextProvider {
    pub provider_id: ProviderId,
    pub class: ContextProviderClass,
    pub generation: String,
    pub contract_shape_sha256: String,
    pub requirement: ProviderRequirement,
    pub supported_roles: Vec<ContextRole>,
    pub required_roles: Vec<ContextRole>,
    pub availability: ProviderAvailabilityClass,
}

impl ExpectedContextProvider {
    fn validate(&self) -> Result<(), ContextContractError> {
        validate_text(self.provider_id.as_str(), "expected.provider_id")?;
        validate_text(&self.generation, "expected.generation")?;
        validate_digest(
            &self.contract_shape_sha256,
            "expected.contract_shape_sha256",
        )?;
        let supported: BTreeSet<_> = self.supported_roles.iter().copied().collect();
        let required: BTreeSet<_> = self.required_roles.iter().copied().collect();
        if supported.len() != self.supported_roles.len()
            || required.len() != self.required_roles.len()
        {
            return Err(ContextContractError::Duplicate {
                field: "expected.roles",
                value: self.provider_id.to_string(),
            });
        }
        if !required.is_subset(&supported) {
            let role = self
                .required_roles
                .iter()
                .find(|role| !supported.contains(role))
                .copied()
                .unwrap_or(ContextRole::Evidence);
            return Err(ContextContractError::RoleUnsupported(role));
        }
        if self.requirement == ProviderRequirement::Mandatory && required.is_empty() {
            return Err(ContextContractError::RegistryInvalid(
                "mandatory provider requires at least one role",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpectedProviderSetDisposition {
    Complete,
    Partial,
    Blocked,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedContextProviderSet {
    pub registry_snapshot_sha256: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub providers: Vec<ExpectedContextProvider>,
    pub disposition: ExpectedProviderSetDisposition,
    pub set_sha256: String,
}

pub fn expected_provider_set_digest(
    expected: &ExpectedContextProviderSet,
) -> Result<String, ContextContractError> {
    let mut normalized = expected.clone();
    normalized.set_sha256.clear();
    normalized
        .providers
        .sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    for provider in &mut normalized.providers {
        provider.supported_roles.sort();
        provider.required_roles.sort();
    }
    let bytes = canonical_json_bytes(&normalized)
        .map_err(|error| ContextContractError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn validate_expected_provider_set(
    expected: &ExpectedContextProviderSet,
) -> Result<(), ContextContractError> {
    validate_digest(
        &expected.registry_snapshot_sha256,
        "expected.registry_snapshot_sha256",
    )?;
    validate_digest(&expected.set_sha256, "expected.set_sha256")?;
    validate_text(&expected.scope_id, "expected.scope_id")?;
    expected.state_fence.validate()?;
    if expected.providers.is_empty() || expected.providers.len() > MAX_PROVIDERS {
        return Err(ContextContractError::LimitExceeded {
            field: "expected.providers",
            limit: MAX_PROVIDERS,
        });
    }
    let mut ids = BTreeSet::new();
    let mut degraded = false;
    let mut blocked = false;
    for provider in &expected.providers {
        provider.validate()?;
        if !ids.insert(provider.provider_id.as_str()) {
            return Err(ContextContractError::Duplicate {
                field: "expected.providers",
                value: provider.provider_id.to_string(),
            });
        }
        match (provider.requirement, provider.availability) {
            (
                ProviderRequirement::Mandatory,
                ProviderAvailabilityClass::Unavailable | ProviderAvailabilityClass::Unsupported,
            ) => blocked = true,
            (_, ProviderAvailabilityClass::Available) => {}
            _ => degraded = true,
        }
    }
    let required = if blocked {
        ExpectedProviderSetDisposition::Blocked
    } else if degraded {
        ExpectedProviderSetDisposition::Partial
    } else {
        ExpectedProviderSetDisposition::Complete
    };
    if expected.disposition != required {
        return Err(ContextContractError::DispositionInvalid);
    }
    if expected_provider_set_digest(expected)? != expected.set_sha256 {
        return Err(ContextContractError::DigestMismatch {
            field: "expected.set_sha256",
        });
    }
    Ok(())
}

/// One generic request shared by all provider implementations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextProviderProjectionRequest {
    pub request_id: RequestId,
    pub provider: ContextProviderDescriptor,
    pub expected_provider_set_sha256: String,
    pub scope_id: String,
    pub task_id: Option<TaskId>,
    pub state_fence: StateFence,
    pub requested_roles: Vec<ContextRole>,
    pub safety_floor_roles: Vec<ContextRole>,
    pub maximum_atoms: u32,
    pub maximum_rendered_bytes: u32,
}

pub fn validate_context_provider_request(
    request: &ContextProviderProjectionRequest,
) -> Result<(), ContextContractError> {
    request.provider.validate()?;
    validate_digest(
        &request.expected_provider_set_sha256,
        "request.expected_provider_set_sha256",
    )?;
    validate_text(&request.scope_id, "request.scope_id")?;
    request.state_fence.validate()?;
    if !request
        .state_fence
        .is_compatible_with(&request.provider.state_fence)
    {
        return Err(ContextContractError::FenceMismatch);
    }
    if request.maximum_atoms == 0 || request.maximum_atoms as usize > MAX_ATOMS {
        return Err(ContextContractError::LimitExceeded {
            field: "request.maximum_atoms",
            limit: MAX_ATOMS,
        });
    }
    if request.maximum_rendered_bytes == 0
        || request.maximum_rendered_bytes as usize > MAX_TEXT_BYTES * 16
    {
        return Err(ContextContractError::LimitExceeded {
            field: "request.maximum_rendered_bytes",
            limit: MAX_TEXT_BYTES * 16,
        });
    }
    let supported: BTreeSet<_> = request.provider.supported_roles.iter().copied().collect();
    let mut requested = BTreeSet::new();
    for role in &request.requested_roles {
        if !supported.contains(role) {
            return Err(ContextContractError::RoleUnsupported(*role));
        }
        if !requested.insert(*role) {
            return Err(ContextContractError::Duplicate {
                field: "request.requested_roles",
                value: format!("{role:?}"),
            });
        }
    }
    let mut floor = BTreeSet::new();
    for role in &request.safety_floor_roles {
        if !requested.contains(role) {
            return Err(ContextContractError::RoleUnsupported(*role));
        }
        if !floor.insert(*role) {
            return Err(ContextContractError::Duplicate {
                field: "request.safety_floor_roles",
                value: format!("{role:?}"),
            });
        }
    }
    Ok(())
}
