//! Immutable policy and activation joins for the reactive planner.

use eliot_context_contracts::{
    ContextPlanningView, ReactiveInputError, ReactivePlanningBounds, canonical_planning_digest,
};
use eliot_contracts::{ArtifactId, ClockReading, ContractIdentity, OperationId, RequestId};
use eliot_cue_contracts::{ActivationRequest, ActivationResult, TargetHandle};
use eliot_protocol::{ReactiveContextContentRef, ReactiveContextPrivacy};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum policy identity text retained by this prototype.
pub const MAX_POLICY_TEXT: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.len() > MAX_POLICY_TEXT {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be bounded, non-blank text without control characters",
        });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be bounded, non-blank text without control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ReactiveInputError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ReactiveInputError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Exact, opaque disclosure permission for one unresolved Attention claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionDisclosureRule {
    pub attention_id: ArtifactId,
    pub claim_digest: String,
    pub minimum_privacy: ReactiveContextPrivacy,
}

/// Explicit join from an opaque A10 target to one current A15 view item.
/// A target without this binding remains activation frontier evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveTargetBinding {
    pub target: TargetHandle,
    pub item_id: ArtifactId,
    pub source_revision: Option<String>,
    pub source_digest: Option<String>,
}

/// Versioned, caller-supplied limits and delivery choices.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveDeliveryPolicy {
    pub policy_id: ArtifactId,
    pub policy_revision: u32,
    pub policy_digest: String,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub plan_id: ArtifactId,
    pub target_event_id: Option<ArtifactId>,
    pub target_event: String,
    pub delivery_profile: ReactiveContextContentRef,
    pub delivery_contract: ContractIdentity,
    pub allowed_modes: Vec<eliot_context_contracts::ReactiveDeliveryMode>,
    pub max_input_bytes: u64,
    pub max_items: u64,
    pub max_references: u64,
    pub max_work: u64,
    pub max_delivery_bytes: u64,
    pub max_delivery_stu: Option<u64>,
    pub fixed_reserve: u64,
    pub protocol_reserve: u64,
    pub output_reserve: u64,
    pub review_reserve: u64,
    pub delivery_reserve: u64,
    pub priority: Vec<eliot_context_contracts::SemanticRole>,
    pub attention_disclosure: Vec<AttentionDisclosureRule>,
    pub tie_break_revision: u32,
    pub observed_at: ClockReading,
    pub deadline_ms: Option<i64>,
    pub cancelled: bool,
}

impl ReactiveDeliveryPolicy {
    /// Compute the policy digest without including its stored digest.
    pub fn canonical_digest(&self) -> Result<String, ReactiveInputError> {
        canonical_planning_digest(&(
            (
                &self.policy_id,
                &self.policy_revision,
                &self.request_id,
                &self.operation_id,
                &self.idempotency_key,
                &self.plan_id,
                &self.target_event_id,
                &self.target_event,
                &self.delivery_profile,
                &self.delivery_contract,
                &self.allowed_modes,
                &self.max_input_bytes,
            ),
            (
                &self.max_items,
                &self.max_references,
                &self.max_work,
                &self.max_delivery_bytes,
                &self.max_delivery_stu,
                &self.fixed_reserve,
                &self.protocol_reserve,
                &self.output_reserve,
                &self.review_reserve,
                &self.delivery_reserve,
                &self.priority,
                &self.attention_disclosure,
            ),
            (
                &self.tie_break_revision,
                &self.observed_at,
                &self.deadline_ms,
                &self.cancelled,
            ),
        ))
    }

    /// Check only bounded scalar and identity fields before scanning the six
    /// retained inputs. This path intentionally avoids canonicalizing policy
    /// content or cloning operation/request identities.
    pub fn validate_preflight(&self) -> Result<(), ReactiveInputError> {
        text(self.policy_id.as_str(), "policy.policy_id")?;
        text(self.request_id.as_str(), "policy.request_id")?;
        text(self.operation_id.as_str(), "policy.operation_id")?;
        text(&self.idempotency_key, "policy.idempotency_key")?;
        text(self.plan_id.as_str(), "policy.plan_id")?;
        if let Some(event) = &self.target_event_id {
            text(event.as_str(), "policy.target_event_id")?;
        }
        text(&self.target_event, "policy.target_event")?;
        digest(&self.policy_digest, "policy.policy_digest")?;
        if self.policy_revision == 0 || self.tie_break_revision != 1 {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.revision",
                reason: "policy revision must be non-zero and tie-break revision must be 1",
            });
        }
        if self.max_input_bytes == 0
            || self.max_input_bytes > 256 * 1024
            || self.max_items == 0
            || self.max_items > 256
            || self.max_references == 0
            || self.max_references > 512
            || self.max_work == 0
            || self.max_delivery_bytes == 0
            || self.max_delivery_stu.is_some_and(|value| value == 0)
        {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.bounds",
                reason: "all scalar limits must be finite, non-zero and within the contract ceiling",
            });
        }
        if self.allowed_modes.is_empty() || self.priority.is_empty() {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.selection",
                reason: "delivery modes and priority order must be explicit",
            });
        }
        self.observed_at
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "policy.observed_at",
                reason: "invalid supplied observation clock",
            })?;
        Ok(())
    }

    /// Validate explicit identities, finite limits and policy digest.
    pub fn validate(&self) -> Result<(), ReactiveInputError> {
        eliot_context_contracts::canonical_planning_digest(self)?;
        text(self.policy_id.as_str(), "policy.policy_id")?;
        text(self.request_id.as_str(), "policy.request_id")?;
        text(self.operation_id.as_str(), "policy.operation_id")?;
        text(&self.idempotency_key, "policy.idempotency_key")?;
        text(self.plan_id.as_str(), "policy.plan_id")?;
        if let Some(event) = &self.target_event_id {
            text(event.as_str(), "policy.target_event_id")?;
        }
        text(&self.target_event, "policy.target_event")?;
        self.delivery_profile
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "policy.delivery_profile",
                reason: "invalid downstream delivery profile handle",
            })?;
        self.delivery_contract
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "policy.delivery_contract",
                reason: "invalid downstream delivery contract identity",
            })?;
        if self.policy_revision == 0 || self.tie_break_revision != 1 {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.revision",
                reason: "policy revision must be non-zero and tie-break revision must be 1",
            });
        }
        digest(&self.policy_digest, "policy.policy_digest")?;
        if self.policy_digest != self.canonical_digest()? {
            return Err(ReactiveInputError::DigestMismatch {
                field: "policy.policy_digest",
            });
        }
        self.validate_selection_and_limits()?;
        self.observed_at
            .validate()
            .map_err(|_| ReactiveInputError::InvalidField {
                field: "policy.observed_at",
                reason: "invalid supplied observation clock",
            })?;
        Ok(())
    }

    fn validate_selection_and_limits(&self) -> Result<(), ReactiveInputError> {
        if self.allowed_modes.is_empty() {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.allowed_modes",
                reason: "at least one delivery mode is required",
            });
        }
        let mut modes = Vec::new();
        for mode in &self.allowed_modes {
            if modes.contains(mode) {
                return Err(ReactiveInputError::InvalidField {
                    field: "policy.allowed_modes",
                    reason: "delivery modes must be unique",
                });
            }
            modes.push(*mode);
        }
        if self.priority.is_empty() {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.priority",
                reason: "priority order must be explicit",
            });
        }
        let mut priorities = BTreeSet::new();
        for role in &self.priority {
            if !priorities.insert(*role) {
                return Err(ReactiveInputError::InvalidField {
                    field: "policy.priority",
                    reason: "priority order must not repeat a disposition",
                });
            }
        }
        let mut attention_ids = BTreeSet::new();
        for rule in &self.attention_disclosure {
            text(
                rule.attention_id.as_str(),
                "policy.attention_disclosure.attention_id",
            )?;
            digest(
                &rule.claim_digest,
                "policy.attention_disclosure.claim_digest",
            )?;
            if !attention_ids.insert(&rule.attention_id) {
                return Err(ReactiveInputError::InvalidField {
                    field: "policy.attention_disclosure",
                    reason: "one disclosure rule per Attention identity is required",
                });
            }
        }
        if self.max_input_bytes == 0
            || self.max_input_bytes > 256 * 1024
            || self.max_items == 0
            || self.max_items > 256
            || self.max_references == 0
            || self.max_references > 512
            || self.max_work == 0
            || self.max_delivery_bytes == 0
            || self.max_delivery_stu.is_some_and(|value| value == 0)
        {
            return Err(ReactiveInputError::InvalidField {
                field: "policy.bounds",
                reason: "all scalar limits must be finite, non-zero and within the contract ceiling",
            });
        }
        Ok(())
    }

    /// Convert policy input ceilings to the existing A15 bounded handoff.
    pub fn planning_bounds(&self) -> ReactivePlanningBounds {
        ReactivePlanningBounds {
            max_input_bytes: self.max_input_bytes,
            max_items: self.max_items,
            max_references: self.max_references,
        }
    }
}

/// A10 request/result retained together; no activation algorithm is invoked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReactiveCueActivation {
    pub request: ActivationRequest,
    pub result: ActivationResult,
    pub expected_view_id: Option<ArtifactId>,
    pub expected_admitted_set_digest: Option<String>,
    pub target_bindings: Vec<ReactiveTargetBinding>,
}

impl ReactiveCueActivation {
    /// Validate the exact A10 pair and its optional A15 identity joins.
    pub fn validate_against(&self, view: &ContextPlanningView) -> Result<(), ReactiveInputError> {
        self.result.validate_against(&self.request).map_err(|_| {
            ReactiveInputError::BindingMismatch {
                field: "activation.request_result",
            }
        })?;
        if self
            .expected_view_id
            .as_ref()
            .is_some_and(|expected| expected != &view.view_id)
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "activation.view_id",
            });
        }
        if self
            .expected_admitted_set_digest
            .as_deref()
            .is_some_and(|expected| expected != view.admitted_canonical_sha256)
        {
            return Err(ReactiveInputError::BindingMismatch {
                field: "activation.admitted_set",
            });
        }
        for seed in &self.request.seeds {
            if seed.observed.context.task_id != view.view.binding.task_id
                || seed.observed.context.scope_id != view.view.binding.scope_id
                || seed.observed.context.state_fence != view.view.binding.state_fence
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "activation.seed_context",
                });
            }
        }
        if self.request.state_fence != view.view.binding.state_fence {
            return Err(ReactiveInputError::BindingMismatch {
                field: "activation.fence",
            });
        }
        if self.target_bindings.len() > 256 {
            return Err(ReactiveInputError::InvalidField {
                field: "activation.target_bindings",
                reason: "target bindings exceed the bounded collection size",
            });
        }
        let mut targets = BTreeSet::new();
        for binding in &self.target_bindings {
            if binding.target.as_str().trim().is_empty()
                || binding.item_id.as_str().trim().is_empty()
                || !targets.insert(binding.target.as_str().to_owned())
            {
                return Err(ReactiveInputError::InvalidField {
                    field: "activation.target_bindings",
                    reason: "target bindings must have unique bounded identities",
                });
            }
            let Some(atom) = view
                .view
                .rendered
                .iter()
                .find(|atom| atom.atom_id == binding.item_id)
            else {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "activation.target_bindings.item",
                });
            };
            if binding
                .source_revision
                .as_deref()
                .is_some_and(|revision| revision != atom.source_revision)
                || binding
                    .source_digest
                    .as_deref()
                    .is_some_and(|digest| digest != atom.source_digest)
            {
                return Err(ReactiveInputError::BindingMismatch {
                    field: "activation.target_bindings.source",
                });
            }
        }
        Ok(())
    }
}
