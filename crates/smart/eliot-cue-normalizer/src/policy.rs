//! Bounded, caller-supplied normalization parameters.
//!
//! These records describe an algorithm invocation. They do not authenticate a
//! `WorkScope`, establish policy authority, or perform any matching operation.

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::WorkScopeId;
use eliot_cue_contracts::{CueKind, Digest, NormalizationProfile};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::NormalizationError;

/// Maximum policy owner-reference bytes.
pub const MAX_OWNER_REFERENCE_BYTES: usize = 512;
/// Maximum policy identifier bytes.
pub const MAX_POLICY_ID_BYTES: usize = 256;
/// Maximum rules in one policy.
pub const MAX_POLICY_RULES: usize = 10;
/// Maximum signature algorithm-reference bytes.
pub const MAX_ALGORITHM_REFERENCE_BYTES: usize = 256;

/// Case behavior for a comparison key. Canonical spelling is never changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CasePolicy {
    /// Preserve case in the comparison key.
    Preserve,
    /// Fold only ASCII letters in the comparison key.
    AsciiInsensitive,
}

/// Separator behavior for path comparison keys. Canonical spelling is preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SeparatorPolicy {
    /// Preserve separators exactly.
    Preserve,
    /// Convert ordinary backslashes to forward slashes.
    Slash,
}

/// The finite rule for one cue kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalizationRule {
    /// Use the observed spelling and an exact key.
    Preserve,
    /// Build an explicitly configured path comparison key.
    Path {
        /// Case behavior.
        case: CasePolicy,
        /// Separator behavior.
        separators: SeparatorPolicy,
        /// Match operation owned by the supplied policy.
        match_mode: eliot_cue_contracts::MatchMode,
    },
    /// Build an explicitly configured symbol comparison key.
    Symbol {
        /// Case behavior.
        case: CasePolicy,
    },
    /// Validate an owner-qualified signature representation.
    Signature {
        /// Owner-qualified algorithm identity.
        algorithm_ref: String,
        /// Required textual prefix.
        prefix: String,
        /// Number of lowercase hexadecimal characters after the prefix.
        hex_length: usize,
    },
}

/// One kind-to-rule mapping. Mappings form a bounded set and must be unique.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Cue kind covered by this rule.
    pub kind: CueKind,
    /// Explicit operation parameters.
    pub rule: NormalizationRule,
}

/// A versioned A-11 algorithm parameter record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NormalizationPolicy {
    /// A-11 wire revision.
    pub schema_revision: String,
    /// External owner reference for the policy source.
    pub owner_reference: String,
    /// Stable policy identity.
    pub policy_id: String,
    /// Monotonic policy revision.
    pub policy_revision: u32,
    /// Profile bound to these exact algorithm parameters.
    pub profile: NormalizationProfile,
    /// Scope supplied by the caller; not authenticated here.
    pub scope_id: WorkScopeId,
    /// Fence supplied by the caller; retained and compared exactly.
    pub state_fence: StateFence,
    /// Bounded rule set.
    pub rules: Vec<PolicyRule>,
    /// Digest of the receipt-excluded policy preimage; both policy and profile digest fields are excluded.
    pub digest: Digest,
}

impl NormalizationPolicy {
    /// Constructs and seals a policy using its receipt-excluded preimage.
    pub fn sealed(
        owner_reference: String,
        policy_id: String,
        policy_revision: u32,
        profile: NormalizationProfile,
        scope_id: WorkScopeId,
        state_fence: StateFence,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, NormalizationError> {
        let placeholder = Digest::new("0".repeat(64)).map_err(NormalizationError::Contract)?;
        let mut policy = Self {
            schema_revision: crate::A11_CONTRACT_REVISION.to_owned(),
            owner_reference,
            policy_id,
            policy_revision,
            profile,
            scope_id,
            state_fence,
            rules,
            digest: placeholder,
        };
        policy.validate_shape()?;
        let definition_digest = policy.expected_digest()?;
        policy.profile.digest = definition_digest.clone();
        policy.digest = definition_digest;
        Ok(policy)
    }

    /// Validates shape, bounds, unique rules and the sealed preimage digest.
    pub fn validate(&self) -> Result<(), NormalizationError> {
        self.validate_shape()?;
        let expected = self.expected_digest()?;
        if self.profile.digest != expected || self.digest != expected {
            return Err(NormalizationError::PolicyDigestMismatch);
        }
        Ok(())
    }

    /// Returns the policy digest that excludes both the policy and profile digest fields.
    pub fn expected_digest(&self) -> Result<Digest, NormalizationError> {
        crate::bounds::preflight_policy(self)?;
        self.validate_shape()?;
        let bytes = canonical_json_bytes(&self.preimage())
            .map_err(|_| NormalizationError::Canonicalization { field: "policy" })?;
        Digest::new(sha256_hex(&bytes)).map_err(NormalizationError::Contract)
    }

    /// Finds the exact rule for one kind.
    #[must_use]
    pub fn rule_for(&self, kind: CueKind) -> Option<&NormalizationRule> {
        self.rules
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| &entry.rule)
    }

    fn validate_shape(&self) -> Result<(), NormalizationError> {
        crate::bounds::preflight_policy(self)?;
        if self.schema_revision != crate::A11_CONTRACT_REVISION {
            return Err(NormalizationError::InvalidField {
                field: "policy.schema_revision",
            });
        }
        bounded_text(
            &self.owner_reference,
            MAX_OWNER_REFERENCE_BYTES,
            "policy.owner_reference",
        )?;
        bounded_text(&self.policy_id, MAX_POLICY_ID_BYTES, "policy.policy_id")?;
        if self.policy_revision == 0 {
            return Err(NormalizationError::InvalidField {
                field: "policy.policy_revision",
            });
        }
        self.profile
            .validate()
            .map_err(NormalizationError::Contract)?;
        bounded_text(
            self.scope_id.as_str(),
            MAX_POLICY_ID_BYTES,
            "policy.scope_id",
        )?;
        self.state_fence
            .validate()
            .map_err(|_| NormalizationError::InvalidField {
                field: "policy.state_fence",
            })?;
        if self.rules.len() > MAX_POLICY_RULES {
            return Err(NormalizationError::BoundExceeded {
                field: "policy.rules",
                limit: MAX_POLICY_RULES,
            });
        }
        let mut kinds = std::collections::BTreeSet::new();
        for entry in &self.rules {
            if !kinds.insert(entry.kind) {
                return Err(NormalizationError::DuplicateRule);
            }
            validate_rule(entry.kind, &entry.rule)?;
        }
        if self.digest.as_str().len() != 64 {
            return Err(NormalizationError::InvalidField {
                field: "policy.digest",
            });
        }
        Ok(())
    }

    fn preimage(&self) -> PolicyPreimage<'_> {
        let mut rules = self.rules.clone();
        rules.sort_by_key(|entry| entry.kind);
        PolicyPreimage {
            schema_revision: &self.schema_revision,
            owner_reference: &self.owner_reference,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            profile_id: &self.profile.profile_id,
            profile_revision: self.profile.profile_revision,
            scope_id: self.scope_id.as_str(),
            state_fence: &self.state_fence,
            rules,
        }
    }
}

#[derive(Serialize)]
struct PolicyPreimage<'a> {
    schema_revision: &'a str,
    owner_reference: &'a str,
    policy_id: &'a str,
    policy_revision: u32,
    profile_id: &'a str,
    profile_revision: u32,
    scope_id: &'a str,
    state_fence: &'a StateFence,
    rules: Vec<PolicyRule>,
}

fn validate_rule(kind: CueKind, rule: &NormalizationRule) -> Result<(), NormalizationError> {
    match (kind, rule) {
        (CueKind::FilePath | CueKind::DirPath, NormalizationRule::Path { match_mode, .. }) => {
            if !matches!(
                match_mode,
                eliot_cue_contracts::MatchMode::Exact | eliot_cue_contracts::MatchMode::Prefix
            ) {
                return Err(NormalizationError::InvalidField {
                    field: "policy.path.match_mode",
                });
            }
            Ok(())
        }
        (CueKind::Symbol, NormalizationRule::Symbol { .. }) => Ok(()),
        (
            CueKind::ErrorSignature,
            NormalizationRule::Signature {
                algorithm_ref,
                prefix,
                hex_length,
            },
        ) => {
            bounded_text(
                algorithm_ref,
                MAX_ALGORITHM_REFERENCE_BYTES,
                "policy.signature.algorithm_ref",
            )?;
            bounded_text(prefix, 128, "policy.signature.prefix")?;
            if *hex_length == 0 || *hex_length > 1024 {
                return Err(NormalizationError::InvalidField {
                    field: "policy.signature.hex_length",
                });
            }
            Ok(())
        }
        (_, NormalizationRule::Preserve) if kind != CueKind::ErrorSignature => Ok(()),
        _ => Err(NormalizationError::InvalidField {
            field: "policy.rule.kind",
        }),
    }
}

fn bounded_text(value: &str, limit: usize, field: &'static str) -> Result<(), NormalizationError> {
    if value.len() > limit {
        return Err(NormalizationError::BoundExceeded { field, limit });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NormalizationError::InvalidField { field });
    }
    Ok(())
}
