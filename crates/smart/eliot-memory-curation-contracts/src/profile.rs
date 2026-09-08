use std::collections::BTreeSet;

use eliot_contracts::PolicyRevision;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, Digest, FindingClass, FiniteDenominator, MemberPartition, ProfileId,
    ProtectionClass, RequestBinding, RuleId, SourceIdentity, SourceSnapshot, contract_digest,
    unique,
};

/// Independent limits for one bounded screen attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenLimits {
    /// Maximum members examined in this page.
    pub max_items: u64,
    /// Maximum evidence references retained.
    pub max_references: u64,
    /// Maximum encoded input bytes.
    pub max_bytes: u64,
    /// Maximum cumulative work units.
    pub max_work_units: u64,
    /// Maximum encoded output bytes.
    pub max_output_bytes: u64,
    /// Optional wall deadline in milliseconds.
    pub deadline_ms: Option<u64>,
    /// Cancellation grace in milliseconds.
    pub cancellation_grace_ms: Option<u64>,
}
impl ScreenLimits {
    /// Validates each limit and its independent budget.
    pub fn validate(&self) -> Result<(), ContractError> {
        for (value, field) in [
            (self.max_items, "limits.max_items"),
            (self.max_references, "limits.max_references"),
            (self.max_bytes, "limits.max_bytes"),
            (self.max_work_units, "limits.max_work_units"),
            (self.max_output_bytes, "limits.max_output_bytes"),
        ] {
            if value == 0 {
                return Err(ContractError::Zero { field });
            }
        }
        if self.deadline_ms == Some(0) || self.cancellation_grace_ms == Some(0) {
            return Err(ContractError::Zero {
                field: "limits.time",
            });
        }
        Ok(())
    }
}

/// One closed deterministic rule declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    /// Stable rule identity.
    pub rule_id: RuleId,
    /// Structural finding class emitted by the rule.
    pub finding_class: FindingClass,
    /// Stable precedence, with lower values first.
    pub precedence: u16,
    /// Protection classes required before the rule can yield eligibility.
    pub required_protection: BTreeSet<ProtectionClass>,
}
impl RuleSpec {
    /// Validates rule bounds.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.required_protection.len() > 32 {
            return Err(ContractError::Bound {
                field: "rule.required_protection",
            });
        }
        Ok(())
    }
}

/// Frozen profile of deterministic structural screening rules.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenProfile {
    /// Profile identity.
    pub profile_id: ProfileId,
    /// Schema revision for this profile.
    pub schema_revision: PolicyRevision,
    /// Policy revision bound by the caller.
    pub policy_revision: PolicyRevision,
    /// Closed rule declarations.
    pub rules: Vec<RuleSpec>,
    /// Canonical requested finding set.
    pub requested_findings: BTreeSet<FindingClass>,
    /// Deterministic precedence order.
    pub precedence: Vec<RuleId>,
    /// Bounded request/output policy.
    pub limits: ScreenLimits,
}
impl ScreenProfile {
    /// Validates rule identity, precedence, and profile limits.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_revision.value() == 0 || self.policy_revision.value() == 0 {
            return Err(ContractError::Zero {
                field: "profile.revision",
            });
        }
        if self.rules.is_empty() {
            return Err(ContractError::Bound {
                field: "profile.rules",
            });
        }
        self.limits.validate()?;
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !ids.insert(rule.rule_id.clone()) {
                return Err(ContractError::Duplicate {
                    field: "profile.rules",
                });
            }
        }
        unique(&self.precedence, "profile.precedence")?;
        if self.precedence.len() != self.rules.len()
            || self.precedence.iter().any(|id| !ids.contains(id))
        {
            return Err(ContractError::Reconciliation {
                field: "profile.precedence",
            });
        }
        Ok(())
    }
}

/// Request for one bounded, read-only screen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationScreenRequest {
    /// Immutable source binding.
    pub source: SourceIdentity,
    /// Declared finite denominator.
    pub denominator: FiniteDenominator,
    /// Immutable target/reference partition selected with the request.
    pub partition: MemberPartition,
    /// Request/operation/idempotency/task/fence binding.
    pub binding: RequestBinding,
    /// Exact frozen profile.
    pub profile: ScreenProfile,
    /// Optional continuation cursor.
    pub cursor: Option<crate::CumulativeCursor>,
    /// Explicit cancellation marker supplied by the caller.
    pub cancellation_requested: bool,
}
impl CurationScreenRequest {
    /// Computes the immutable request identity used by continuation cursors.
    pub fn request_fingerprint(&self) -> Result<Digest, ContractError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            source: &'a SourceIdentity,
            denominator: &'a FiniteDenominator,
            partition: &'a MemberPartition,
            binding: &'a RequestBinding,
            profile: &'a ScreenProfile,
            cancellation_requested: bool,
        }
        contract_digest(&Payload {
            source: &self.source,
            denominator: &self.denominator,
            partition: &self.partition,
            binding: &self.binding,
            profile: &self.profile,
            cancellation_requested: self.cancellation_requested,
        })
    }

    /// Validates the request and all cross-record source/profile bindings.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.source.validate()?;
        self.denominator.validate_declared()?;
        self.partition.validate(&self.denominator)?;
        self.binding.validate()?;
        self.profile.validate()?;
        if self.binding.scope != self.source.scope
            || self.binding.state_fence != self.source.state_fence
        {
            return Err(ContractError::BindingMismatch {
                field: "request.source",
            });
        }
        match self.source.state_fence.policy_revision {
            Some(revision) if revision == self.profile.policy_revision => {}
            _ => {
                return Err(ContractError::BindingMismatch {
                    field: "request.policy_revision",
                });
            }
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(self)?;
        }
        Ok(())
    }
    /// Validates this request against the actual immutable source snapshot.
    pub fn validate_snapshot(&self, snapshot: &SourceSnapshot) -> Result<(), ContractError> {
        self.validate()?;
        snapshot.validate()?;
        if snapshot.identity != self.source
            || snapshot.denominator != self.denominator
            || snapshot.partition != self.partition
        {
            return Err(ContractError::BindingMismatch {
                field: "request.snapshot",
            });
        }
        Ok(())
    }
}
