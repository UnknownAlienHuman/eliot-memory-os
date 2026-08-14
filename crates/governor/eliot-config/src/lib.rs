//! Pure governance of immutable configuration and Human-owned policy snapshots.
//!
//! This package validates candidates and produces typed decisions. It does not
//! read sources, persist snapshots, publish state, or execute rollback.

#![forbid(unsafe_code)]

use eliot_contracts::{PolicyRevision, StateFence};
use eliot_security_contracts::PolicyFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.governor.config";
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("{field} must be non-blank")]
    Blank { field: &'static str },
    #[error("source set is not complete")]
    PartialSourceSet,
    #[error("snapshot applies to machine {actual}, not {expected}")]
    ForeignMachine { expected: String, actual: String },
    #[error("scope is ambiguous")]
    AmbiguousScope,
    #[error("duplicate configuration key: {0}")]
    DuplicateKey(String),
    #[error("stale state fence")]
    StaleFence,
    #[error("stale snapshot revision")]
    StaleRevision,
    #[error("policy substitution is not authorized")]
    UnauthorizedPolicy,
    #[error("unknown disposition is not admissible")]
    UnknownDisposition,
    #[error("rollback lineage is forged")]
    ForgedRollbackLineage,
    #[error("invalid snapshot: {0}")]
    InvalidSnapshot(&'static str),
}

fn non_blank(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigError::Blank { field });
    }
    Ok(())
}

/// Completeness of the source set used to construct a candidate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Human-owned identity. It is an identity reference, not an authority issuer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanOwner {
    pub owner_ref: String,
}

/// One deterministic configuration value. Secret material must be represented by a reference.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    pub key: String,
    pub value_ref: String,
    pub owner_ref: String,
}

impl Setting {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.key, "setting.key")?;
        non_blank(&self.value_ref, "setting.value_ref")?;
        non_blank(&self.owner_ref, "setting.owner_ref")
    }
}

/// The immutable configuration and policy payload admitted as one generation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigPolicySnapshot {
    pub snapshot_id: String,
    pub machine_id: String,
    pub scope_id: String,
    pub revision: PolicyRevision,
    pub source_completeness: SourceCompleteness,
    pub settings: Vec<Setting>,
    pub policy_owner: HumanOwner,
    pub policy_fence: PolicyFence,
    pub state_fence: StateFence,
    pub parent_snapshot_id: Option<String>,
    pub rollback_of: Option<String>,
}

impl ConfigPolicySnapshot {
    /// Validates the complete immutable snapshot and its provider fence.
    ///
    /// # Errors
    /// Returns `ConfigError` when source completeness, identity, fencing, or
    /// setting uniqueness is invalid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.snapshot_id, "snapshot_id")?;
        non_blank(&self.machine_id, "machine_id")?;
        non_blank(&self.scope_id, "scope_id")?;
        non_blank(&self.policy_owner.owner_ref, "policy_owner.owner_ref")?;
        if !matches!(self.source_completeness, SourceCompleteness::Complete) {
            return Err(ConfigError::PartialSourceSet);
        }
        if self.policy_fence.policy_snapshot_id != self.snapshot_id {
            return Err(ConfigError::InvalidSnapshot("policy fence identity"));
        }
        if self.policy_fence.state_fence != self.state_fence {
            return Err(ConfigError::InvalidSnapshot("policy/state fence mismatch"));
        }
        let mut keys = Vec::with_capacity(self.settings.len());
        for setting in &self.settings {
            setting.validate()?;
            if keys.iter().any(|key: &String| key == &setting.key) {
                return Err(ConfigError::DuplicateKey(setting.key.clone()));
            }
            keys.push(setting.key.clone());
        }
        if let Some(parent) = &self.parent_snapshot_id {
            non_blank(parent, "parent_snapshot_id")?;
        }
        if let Some(rollback) = &self.rollback_of {
            non_blank(rollback, "rollback_of")?;
        }
        Ok(())
    }
}

/// The observed facts used for deterministic applicability checking.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityContext {
    pub machine_id: String,
    pub scope_id: Option<String>,
    pub state_fence: StateFence,
    pub active_revision: PolicyRevision,
}

/// Per-snapshot applicability, with unknown/degraded outcomes kept typed.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Applicability {
    Applicable,
    Degraded,
    Narrowed,
    Unqualified,
    Unsupported,
    Conflicted,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityResult {
    pub outcome: Applicability,
    pub affected_keys: Vec<String>,
}

impl ConfigPolicySnapshot {
    /// Classifies this snapshot against an observed machine and scope.
    ///
    /// # Errors
    /// Returns `ConfigError` when the context is incomplete or the snapshot is
    /// foreign, stale, or structurally invalid.
    pub fn applicability(
        &self,
        context: &ApplicabilityContext,
    ) -> Result<ApplicabilityResult, ConfigError> {
        self.validate()?;
        non_blank(&context.machine_id, "context.machine_id")?;
        let scope = context
            .scope_id
            .as_deref()
            .ok_or(ConfigError::AmbiguousScope)?;
        if self.machine_id != context.machine_id {
            return Err(ConfigError::ForeignMachine {
                expected: context.machine_id.clone(),
                actual: self.machine_id.clone(),
            });
        }
        if self.scope_id != scope {
            return Ok(ApplicabilityResult {
                outcome: Applicability::Unsupported,
                affected_keys: self.settings.iter().map(|s| s.key.clone()).collect(),
            });
        }
        if self.state_fence != context.state_fence {
            return Err(ConfigError::StaleFence);
        }
        if self.revision < context.active_revision {
            return Err(ConfigError::StaleRevision);
        }
        Ok(ApplicabilityResult {
            outcome: Applicability::Applicable,
            affected_keys: self.settings.iter().map(|s| s.key.clone()).collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestTrigger {
    Human,
    Dreamer,
    WatchdogProblem,
    MaintenancePolicy,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeImpact {
    PresentationOnly,
    OperationalReversible,
    ModelCostRoute,
    PrivacySecurityAuthority,
    StorageMigration,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyApproval {
    pub owner_ref: String,
    pub snapshot_id: String,
    pub policy_fence: PolicyFence,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationChangeIntent {
    pub intent_id: String,
    pub requester_ref: String,
    pub trigger: RequestTrigger,
    pub current_snapshot_id: String,
    pub candidate: ConfigPolicySnapshot,
    pub impact: ChangeImpact,
    pub approval: Option<PolicyApproval>,
    pub declared_disposition: Option<String>,
}

impl ConfigurationChangeIntent {
    /// Checks that a proposed change is based on the active snapshot and has
    /// the required Human-owned policy approval.
    ///
    /// # Errors
    /// Returns `ConfigError` for stale, ambiguous, unknown, or unauthorized
    /// changes.
    pub fn validate(
        &self,
        active: &ConfigPolicySnapshot,
        context: &ApplicabilityContext,
    ) -> Result<(), ConfigError> {
        non_blank(&self.intent_id, "intent_id")?;
        non_blank(&self.requester_ref, "requester_ref")?;
        if self.current_snapshot_id != active.snapshot_id {
            return Err(ConfigError::StaleRevision);
        }
        self.candidate.applicability(context)?;
        if self.declared_disposition.as_deref() == Some("UNKNOWN") {
            return Err(ConfigError::UnknownDisposition);
        }
        if matches!(
            self.impact,
            ChangeImpact::ModelCostRoute
                | ChangeImpact::PrivacySecurityAuthority
                | ChangeImpact::StorageMigration
        ) && !self.approval.as_ref().is_some_and(|approval| {
            approval.owner_ref == self.candidate.policy_owner.owner_ref
                && approval.snapshot_id == self.candidate.snapshot_id
                && approval.policy_fence == self.candidate.policy_fence
        }) {
            return Err(ConfigError::UnauthorizedPolicy);
        }
        Ok(())
    }
}

/// Validates a rollback candidate as a new immutable lineage record.
///
/// # Errors
/// Returns `ConfigError` when the candidate does not point directly to the
/// active snapshot or fails applicability validation.
pub fn validate_rollback(
    active: &ConfigPolicySnapshot,
    rollback: &ConfigPolicySnapshot,
    context: &ApplicabilityContext,
) -> Result<(), ConfigError> {
    rollback.validate()?;
    rollback.applicability(context)?;
    if rollback.rollback_of.as_deref() != Some(active.snapshot_id.as_str())
        || rollback.parent_snapshot_id.as_deref() != Some(active.snapshot_id.as_str())
        || rollback.revision <= active.revision
        || rollback.snapshot_id == active.snapshot_id
    {
        return Err(ConfigError::ForgedRollbackLineage);
    }
    Ok(())
}

/// Returns the deterministic identity of this provider-composed contract.
///
/// # Errors
/// Returns the provider error if the contract identity cannot be constructed.
pub fn contract_identity()
-> Result<eliot_contracts::ContractIdentity, eliot_contracts::ContractError> {
    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({"immutable_snapshot": true, "provider_runtime": eliot_runtime_contracts::CONTRACT_NAME, "provider_security": eliot_security_contracts::CONTRACT_NAME}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }
    fn snapshot(machine: &str, scope: &str, revision: u64) -> ConfigPolicySnapshot {
        let fence = fence();
        let id = format!("snapshot-{revision}");
        let revision = match PolicyRevision::new(revision) {
            Ok(value) => value,
            Err(_) => PolicyRevision::genesis(),
        };
        ConfigPolicySnapshot {
            snapshot_id: id.clone(),
            machine_id: machine.into(),
            scope_id: scope.into(),
            revision,
            source_completeness: SourceCompleteness::Complete,
            settings: vec![Setting {
                key: "mode".into(),
                value_ref: "ref:mode".into(),
                owner_ref: "human-1".into(),
            }],
            policy_owner: HumanOwner {
                owner_ref: "human-1".into(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: id,
                state_fence: fence.clone(),
            },
            state_fence: fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }
    fn context() -> ApplicabilityContext {
        ApplicabilityContext {
            machine_id: "machine-1".into(),
            scope_id: Some("scope-1".into()),
            state_fence: fence(),
            active_revision: PolicyRevision::genesis(),
        }
    }

    #[test]
    fn partial_source_set_is_rejected() {
        let mut value = snapshot("machine-1", "scope-1", 1);
        value.source_completeness = SourceCompleteness::Partial;
        assert_eq!(value.validate(), Err(ConfigError::PartialSourceSet));
    }
    #[test]
    fn foreign_machine_is_rejected() {
        assert!(matches!(
            snapshot("other", "scope-1", 1).applicability(&context()),
            Err(ConfigError::ForeignMachine { .. })
        ));
    }

    #[test]
    fn ambiguous_scope_and_stale_context_are_rejected() {
        let value = snapshot("machine-1", "scope-1", 1);
        let mut ambiguous = context();
        ambiguous.scope_id = None;
        assert_eq!(
            value.applicability(&ambiguous),
            Err(ConfigError::AmbiguousScope)
        );

        let mut stale = context();
        stale.active_revision = match PolicyRevision::new(2) {
            Ok(value) => value,
            Err(_) => PolicyRevision::genesis(),
        };
        assert_eq!(value.applicability(&stale), Err(ConfigError::StaleRevision));

        let mut fenced = context();
        fenced.state_fence.resource_generation = match ResourceGeneration::new(2) {
            Ok(value) => value,
            Err(_) => ResourceGeneration::genesis(),
        };
        assert_eq!(value.applicability(&fenced), Err(ConfigError::StaleFence));
    }
    #[test]
    fn unauthorized_policy_substitution_is_rejected() {
        let active = snapshot("machine-1", "scope-1", 1);
        let candidate = snapshot("machine-1", "scope-1", 2);
        let intent = ConfigurationChangeIntent {
            intent_id: "i".into(),
            requester_ref: "r".into(),
            trigger: RequestTrigger::Dreamer,
            current_snapshot_id: active.snapshot_id.clone(),
            candidate,
            impact: ChangeImpact::PrivacySecurityAuthority,
            approval: None,
            declared_disposition: None,
        };
        assert_eq!(
            intent.validate(&active, &context()),
            Err(ConfigError::UnauthorizedPolicy)
        );
    }
    #[test]
    fn forged_rollback_lineage_is_rejected() {
        let active = snapshot("machine-1", "scope-1", 1);
        let rollback = snapshot("machine-1", "scope-1", 2);
        assert_eq!(
            validate_rollback(&active, &rollback, &context()),
            Err(ConfigError::ForgedRollbackLineage)
        );
    }
    #[test]
    fn duplicate_keys_and_unknown_disposition_are_rejected() {
        let mut value = snapshot("machine-1", "scope-1", 1);
        value.settings.push(value.settings[0].clone());
        assert!(matches!(
            value.validate(),
            Err(ConfigError::DuplicateKey(_))
        ));
        let active = snapshot("machine-1", "scope-1", 1);
        let candidate = snapshot("machine-1", "scope-1", 2);
        let intent = ConfigurationChangeIntent {
            intent_id: "i".into(),
            requester_ref: "r".into(),
            trigger: RequestTrigger::Human,
            current_snapshot_id: active.snapshot_id.clone(),
            candidate,
            impact: ChangeImpact::PresentationOnly,
            approval: None,
            declared_disposition: Some("UNKNOWN".into()),
        };
        assert_eq!(
            intent.validate(&active, &context()),
            Err(ConfigError::UnknownDisposition)
        );
    }
}
