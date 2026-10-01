//! Closed canonical work-admission record and receipt join (#1678, I14.6/I10.15).
//!
//! The record is the Governor-owned semantic ADMITTED decision. It binds the
//! original durable-work semantics to the exact ORS reservation, attempt,
//! claims, fence, epoch, semantic revision, canonical operation and the
//! launch-outbox row committed by that same operation. It does not interpret
//! claim references or mint policy ceilings.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use eliot_protocol::WorkAdmissionSemanticRevision;

use crate::{
    NamedMutationOperation, OperationIdentity, OperationId, OutboxId, OutboxIntentKind,
    OrderingHeadExpectation, PreparedTransition, RequestMeta, RevisionHeadExpectation,
    StateFence, StoreError, TransitionClass, WriteReceipt, WriteReceiptStatus, canonical_json_bytes,
    sha256_hex, validate_digest, validate_text,
};

pub const WORK_ADMISSION_SCHEMA_V1: &str = "eliot.storage.work-admission.v1";
pub const WORK_ADMISSION_RECORD_NAMESPACE: &str = "work-admission-v1";
pub const CANONICAL_ADMISSION_OWNER_KEY: &str = "owner/canonical";

/// Closed set of current owner images that establish one work admission.
/// The bytes are retained with the decision so recovery can compare them to
/// the same owner readbacks instead of promoting caller-selected JSON.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAdmissionOwnerRole {
    Task,
    Plan,
    WorkScope,
    Policy,
    HumanStaffing,
    ModelCatalog,
    Grants,
    Budget,
}

/// A typed public reference to an independently read owner record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionOwnerReference {
    pub kind: String,
    pub id: String,
    pub revision: String,
    pub digest: Option<String>,
}

impl WorkAdmissionOwnerReference {
    fn validate(&self, field: &'static str) -> Result<(), StoreError> {
        validate_text(&self.kind, field)?;
        validate_text(&self.id, field)?;
        validate_text(&self.revision, field)?;
        if let Some(digest) = &self.digest {
            validate_digest(digest, "work_admission.owner_reference.digest")?;
        }
        Ok(())
    }
}

/// Exact current owner readback retained by the admission decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionOwnerReadback {
    pub role: WorkAdmissionOwnerRole,
    pub owner_ref: WorkAdmissionOwnerReference,
    pub owner_revision: u64,
    pub state_fence: StateFence,
    pub canonical_json: String,
    pub sha256: String,
}

impl WorkAdmissionOwnerReadback {
    fn validate(&self, state_fence: &StateFence) -> Result<(), StoreError> {
        self.owner_ref.validate("work_admission.owner_readback.owner_ref")?;
        if self.owner_revision == 0
            || self.owner_ref.revision != self.owner_revision.to_string()
            || self.state_fence != *state_fence
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.owner_readback",
                reason: "must carry the exact nonzero owner revision and admission fence",
            });
        }
        validate_digest(&self.sha256, "work_admission.owner_readback.sha256")?;
        if self.canonical_json.is_empty() || self.canonical_json.len() > crate::MAX_RECOVERY_RECORD_BYTES {
            return Err(StoreError::InvalidField {
                field: "work_admission.owner_readback.canonical_json",
                reason: "must be non-empty and bounded",
            });
        }
        let value: serde_json::Value = serde_json::from_str(&self.canonical_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if String::from_utf8(canonical).ok().as_deref() != Some(self.canonical_json.as_str())
            || sha256_hex(self.canonical_json.as_bytes()) != self.sha256
            || self.owner_ref.digest.as_deref().is_some_and(|digest| digest != self.sha256)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.owner_readback.canonical_json",
                reason: "must preserve the exact canonical bytes and owner digest",
            });
        }
        Ok(())
    }
}

/// Canonical `ModelCatalogueSnapshot` bytes bound to their independent
/// catalogue-owner readback. The Store API keeps the source image opaque, but
/// checks the closed snapshot envelope and its freshness window so the
/// admission record cannot silently replace it with a provider name or route
/// reference.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionModelCatalogueImage {
    pub owner_ref: WorkAdmissionOwnerReference,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub snapshot_json: String,
    pub sha256: String,
}

/// Account-axis evidence joined to the exact model catalogue observation.
/// `Unavailable` is an observation, never a positive account-readiness result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum WorkAdmissionProviderAccountObservation {
    Known {
        owner_ref: WorkAdmissionOwnerReference,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        snapshot_json: String,
        sha256: String,
    },
    Unavailable {
        schema: String,
        source: String,
        reason: WorkAdmissionProviderAccountUnavailableReason,
        model_catalogue_snapshot_id: String,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        source_contract_ref: WorkAdmissionOwnerReference,
    },
}

/// Closed reason for the one source-specific absence currently admitted into
/// the owner evidence envelope. Other absence reasons need their own routed
/// contract rather than being collapsed into this one.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAdmissionProviderAccountUnavailableReason {
    SourceExposesNoAccountMetadata,
}

/// Exact model catalogue and provider-account axis retained by the current
/// ModelCatalog owner row. This envelope records source facts only; it does
/// not grant route/account readiness.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionModelCatalogEvidence {
    pub schema: String,
    pub model_catalogue: WorkAdmissionModelCatalogueImage,
    pub provider_accounts: WorkAdmissionProviderAccountObservation,
}

impl WorkAdmissionModelCatalogEvidence {
    fn validate(&self, owner_readback: &WorkAdmissionOwnerReadback) -> Result<(), StoreError> {
        if self.schema != "eliot.work-admission.model-catalog-evidence.v1" {
            return Err(StoreError::UnknownOperation);
        }
        self.model_catalogue
            .owner_ref
            .validate("work_admission.model_catalogue.owner_ref")?;
        validate_digest(&self.model_catalogue.sha256, "work_admission.model_catalogue.sha256")?;
        validate_json_image(
            &self.model_catalogue.snapshot_json,
            &self.model_catalogue.sha256,
            "work_admission.model_catalogue.snapshot_json",
        )?;
        validate_observation_window(
            self.model_catalogue.observed_at_unix_ms,
            self.model_catalogue.expires_at_unix_ms,
            "work_admission.model_catalogue.window",
        )?;
        let model: serde_json::Value = serde_json::from_str(&self.model_catalogue.snapshot_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let model_snapshot_id = model.get("snapshot_id").and_then(serde_json::Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "work_admission.model_catalogue.snapshot_json",
                reason: "must be an exact ModelCatalogueSnapshot image",
            })?;
        if model.get("observed_at_unix_ms").and_then(serde_json::Value::as_u64)
                != Some(self.model_catalogue.observed_at_unix_ms)
            || model.get("expires_at_unix_ms").and_then(serde_json::Value::as_u64)
                != Some(self.model_catalogue.expires_at_unix_ms)
            || self.model_catalogue.owner_ref.digest.as_deref()
                .is_some_and(|digest| digest != self.model_catalogue.sha256)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.model_catalogue",
                reason: "must bind the exact catalogue source revision, digest, and observation window",
            });
        }
        match &self.provider_accounts {
            WorkAdmissionProviderAccountObservation::Known {
                owner_ref,
                observed_at_unix_ms,
                expires_at_unix_ms,
                snapshot_json,
                sha256,
            } => {
                owner_ref.validate("work_admission.provider_accounts.owner_ref")?;
                validate_digest(sha256, "work_admission.provider_accounts.sha256")?;
                validate_json_image(
                    snapshot_json,
                    sha256,
                    "work_admission.provider_accounts.snapshot_json",
                )?;
                validate_observation_window(
                    *observed_at_unix_ms,
                    *expires_at_unix_ms,
                    "work_admission.provider_accounts.window",
                )?;
                let accounts: serde_json::Value = serde_json::from_str(snapshot_json)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                if accounts.get("snapshot_id").and_then(serde_json::Value::as_str).is_none()
                    || accounts.get("observed_at_unix_ms").and_then(serde_json::Value::as_u64)
                        != Some(*observed_at_unix_ms)
                    || accounts.get("expires_at_unix_ms").and_then(serde_json::Value::as_u64)
                        != Some(*expires_at_unix_ms)
                    || owner_ref.digest.as_deref().is_some_and(|digest| digest != sha256)
                {
                    return Err(StoreError::InvalidField {
                        field: "work_admission.provider_accounts.snapshot_json",
                        reason: "must bind the exact owner-issued account catalogue image and window",
                    });
                }
            }
            WorkAdmissionProviderAccountObservation::Unavailable {
                schema,
                source,
                reason: _,
                model_catalogue_snapshot_id,
                observed_at_unix_ms,
                expires_at_unix_ms,
                source_contract_ref,
            } => {
                if schema != "eliot.provider-account-catalogue.observation.v1"
                    || source != "opencode-provider-catalogue/v1"
                    || model_catalogue_snapshot_id != model_snapshot_id
                    || observed_at_unix_ms != &self.model_catalogue.observed_at_unix_ms
                    || expires_at_unix_ms != &self.model_catalogue.expires_at_unix_ms
                {
                    return Err(StoreError::InvalidField {
                        field: "work_admission.provider_accounts",
                        reason: "Unavailable must be a source observation tied to the exact model catalogue window",
                    });
                }
                source_contract_ref.validate("work_admission.provider_accounts.source_contract_ref")?;
            }
        }
        // The entire evidence envelope must itself be the exact owner
        // readback. Its owner reference was checked by WorkAdmissionOwnerReadback.
        let value = serde_json::from_str::<serde_json::Value>(&owner_readback.canonical_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if serde_json::from_value::<Self>(value.clone()).ok().as_ref() != Some(self) {
            return Err(StoreError::InvalidField {
                field: "work_admission.model_catalog_evidence",
                reason: "must be the exact closed ModelCatalog owner-readback document",
            });
        }
        Ok(())
    }
}

fn validate_json_image(json: &str, digest: &str, field: &'static str) -> Result<(), StoreError> {
    if json.is_empty() || json.len() > crate::MAX_RECOVERY_RECORD_BYTES {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be non-empty and bounded",
        });
    }
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let bytes = canonical_json_bytes(&value).map_err(|error| StoreError::Serialization(error.to_string()))?;
    if String::from_utf8(bytes.clone()).ok().as_deref() != Some(json)
        || sha256_hex(&bytes) != digest
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must preserve exact canonical JSON bytes and SHA-256",
        });
    }
    Ok(())
}

fn validate_observation_window(observed: u64, expires: u64, field: &'static str) -> Result<(), StoreError> {
    if observed == 0 || expires < observed {
        return Err(StoreError::InvalidField {
            field,
            reason: "must have a nonzero observation and non-expired bounded window",
        });
    }
    Ok(())
}

/// Swarm attribution reported by the current staffing/budget owner.
/// `NotApplicable` is explicit and still identifies the owner readback that
/// made that determination; absence never means SoloVerified.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WorkAdmissionSwarmBudgetAttribution {
    Attributed {
        swarm_ref: WorkAdmissionOwnerReference,
        budget_ref: WorkAdmissionOwnerReference,
    },
    NotApplicable {
        owner_ref: WorkAdmissionOwnerReference,
        reason: String,
    },
}

/// Cost and swarm-budget attribution selected from the admitted owner reads.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionBudgetAttribution {
    pub owner_ref: WorkAdmissionOwnerReference,
    pub envelope_id: String,
    pub policy_snapshot_id: String,
    pub automation_policy_ref: String,
    pub cost_authority_ref: String,
    /// Exact BudgetLedger reservation retained by the original admission
    /// owner readback. This prevents a later result caller from selecting a
    /// different same-route reservation for the same work.
    pub reservation_id: String,
    pub reservation_idempotency_key: String,
    pub provider_ref: String,
    pub tool_ref: String,
    pub swarm: WorkAdmissionSwarmBudgetAttribution,
}

impl WorkAdmissionBudgetAttribution {
    fn validate(&self) -> Result<(), StoreError> {
        self.owner_ref.validate("work_admission.budget.owner_ref")?;
        for (field, value) in [
            ("work_admission.budget.envelope_id", self.envelope_id.as_str()),
            ("work_admission.budget.policy_snapshot_id", self.policy_snapshot_id.as_str()),
            ("work_admission.budget.automation_policy_ref", self.automation_policy_ref.as_str()),
            ("work_admission.budget.cost_authority_ref", self.cost_authority_ref.as_str()),
            ("work_admission.budget.reservation_id", self.reservation_id.as_str()),
            (
                "work_admission.budget.reservation_idempotency_key",
                self.reservation_idempotency_key.as_str(),
            ),
            ("work_admission.budget.provider_ref", self.provider_ref.as_str()),
            ("work_admission.budget.tool_ref", self.tool_ref.as_str()),
        ] {
            validate_text(value, field)?;
        }
        match &self.swarm {
            WorkAdmissionSwarmBudgetAttribution::Attributed { swarm_ref, budget_ref } => {
                swarm_ref.validate("work_admission.budget.swarm_ref")?;
                budget_ref.validate("work_admission.budget.swarm_budget_ref")?;
            }
            WorkAdmissionSwarmBudgetAttribution::NotApplicable { owner_ref, reason } => {
                owner_ref.validate("work_admission.budget.swarm_owner_ref")?;
                validate_text(reason, "work_admission.budget.swarm_not_applicable_reason")?;
            }
        }
        Ok(())
    }
}

/// Owner-issued inputs and independently current owner readbacks for one
/// authenticated Task Controller admission. The canonical request/plan bytes
/// are carried for exact provenance and are never treated as authority without
/// the matching owner readbacks.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionOwnerAttribution {
    pub request_id: String,
    pub task_controller_operation_id: String,
    pub task_controller_attempt_id: String,
    pub task_id: String,
    pub work_id: String,
    pub work_scope_id: String,
    pub attempt_id: String,
    pub operation_id: String,
    pub host_request: eliot_protocol::HostRequestEnvelope,
    pub canonical_requester_json: String,
    pub canonical_requester_sha256: String,
    /// Exact task goal accepted by the canonical Task owner. This is the
    /// query text source; the raw requester JSON remains provenance only.
    pub admitted_goal: String,
    pub admitted_goal_sha256: String,
    pub staffing_plan_request_json: String,
    pub staffing_plan_request_sha256: String,
    pub role_visibility_policy_ref: WorkAdmissionOwnerReference,
    pub privacy_class: eliot_security_contracts::PrivacyClass,
    pub route_privacy_evidence_refs: Vec<String>,
    pub budget_attribution: WorkAdmissionBudgetAttribution,
    pub owner_readbacks: Vec<WorkAdmissionOwnerReadback>,
}

impl WorkAdmissionOwnerAttribution {
    fn validate_for(&self, record: &WorkAdmissionRecord) -> Result<(), StoreError> {
        for (field, value) in [
            ("work_admission.attribution.request_id", self.request_id.as_str()),
            ("work_admission.attribution.task_controller_operation_id", self.task_controller_operation_id.as_str()),
            ("work_admission.attribution.task_controller_attempt_id", self.task_controller_attempt_id.as_str()),
            ("work_admission.attribution.task_id", self.task_id.as_str()),
            ("work_admission.attribution.work_id", self.work_id.as_str()),
            ("work_admission.attribution.work_scope_id", self.work_scope_id.as_str()),
            ("work_admission.attribution.attempt_id", self.attempt_id.as_str()),
            ("work_admission.attribution.operation_id", self.operation_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        self.host_request
            .validate_for_admission()
            .map_err(|_| StoreError::InvalidField {
                field: "work_admission.attribution.host_request",
                reason: "must be the exact valid authenticated invocation envelope",
            })?;
        if self.host_request.identity.request_id.as_str() != self.request_id
            || self.host_request.kind != eliot_protocol::HostRequestKind::Invocation
            || self.host_request.identity.task_id.as_deref() != Some(record.task_id.as_str())
            || self.host_request.identity.session_id.as_deref() != Some(record.session_id.as_str())
            || self.host_request.identity.work_scope_id.as_deref() != Some(record.scope_id.as_str())
            || self.host_request.state_fence != record.state_fence
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.host_request",
                reason: "must bind the exact admitted request, task, scope, and fence",
            });
        }
        if self.task_id != record.task_id
            || self.work_id != record.work_id
            || self.work_scope_id != record.scope_id
            || self.attempt_id != record.proposed_attempt_id.operation_id.as_str()
            || self.operation_id != record.admitted_operation_id.as_str()
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution",
                reason: "must match the exact admitted work, attempt, operation, and scope",
            });
        }
        validate_digest(&self.canonical_requester_sha256, "work_admission.attribution.canonical_requester_sha256")?;
        validate_text(&self.admitted_goal, "work_admission.attribution.admitted_goal")?;
        validate_digest(&self.admitted_goal_sha256, "work_admission.attribution.admitted_goal_sha256")?;
        if sha256_hex(self.admitted_goal.as_bytes()) != self.admitted_goal_sha256 {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.admitted_goal_sha256",
                reason: "must bind the exact canonical Task owner goal bytes",
            });
        }
        validate_digest(&self.staffing_plan_request_sha256, "work_admission.attribution.staffing_plan_request_sha256")?;
        let requester: serde_json::Value = serde_json::from_str(&self.canonical_requester_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let requester_bytes = canonical_json_bytes(&requester)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let plan: serde_json::Value = serde_json::from_str(&self.staffing_plan_request_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let plan_bytes = canonical_json_bytes(&plan)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if String::from_utf8(requester_bytes.clone()).ok().as_deref() != Some(self.canonical_requester_json.as_str())
            || sha256_hex(&requester_bytes) != self.canonical_requester_sha256
            || self.host_request.identity.payload_sha256 != self.canonical_requester_sha256
            || String::from_utf8(plan_bytes.clone()).ok().as_deref() != Some(self.staffing_plan_request_json.as_str())
            || sha256_hex(&plan_bytes) != self.staffing_plan_request_sha256
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.request_bytes",
                reason: "must preserve the exact canonical owner-selected request and staffing-plan bytes",
            });
        }
        self.role_visibility_policy_ref
            .validate("work_admission.attribution.role_visibility_policy_ref")?;
        if self.route_privacy_evidence_refs.is_empty() {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.route_privacy_evidence_refs",
                reason: "the admitted provider route must retain its owner privacy evidence",
            });
        }
        let mut privacy_refs = std::collections::BTreeSet::new();
        for privacy_ref in &self.route_privacy_evidence_refs {
            validate_text(privacy_ref, "work_admission.attribution.route_privacy_evidence_refs")?;
            if !privacy_refs.insert(privacy_ref) {
                return Err(StoreError::Duplicate {
                    field: "work_admission.attribution.route_privacy_evidence_refs",
                });
            }
        }
        self.budget_attribution.validate()?;
        let mut readbacks = std::collections::BTreeMap::new();
        for readback in &self.owner_readbacks {
            readback.validate(&record.state_fence)?;
            if readbacks.insert(readback.role, readback).is_some() {
                return Err(StoreError::Duplicate { field: "work_admission.owner_readbacks" });
            }
        }
        for role in [
            WorkAdmissionOwnerRole::Task,
            WorkAdmissionOwnerRole::Plan,
            WorkAdmissionOwnerRole::WorkScope,
            WorkAdmissionOwnerRole::Policy,
            WorkAdmissionOwnerRole::HumanStaffing,
            WorkAdmissionOwnerRole::ModelCatalog,
            WorkAdmissionOwnerRole::Grants,
            WorkAdmissionOwnerRole::Budget,
        ] {
            if !readbacks.contains_key(&role) {
                return Err(StoreError::InvalidField {
                    field: "work_admission.owner_readbacks",
                    reason: "all current task, plan, scope, policy, staffing, model, grant, and budget owners are required",
                });
            }
        }
        let budget_readback = readbacks
            .get(&WorkAdmissionOwnerRole::Budget)
            .ok_or(StoreError::InvalidReceipt)?;
        if budget_readback.owner_ref != self.budget_attribution.owner_ref {
            return Err(StoreError::InvalidField {
                field: "work_admission.budget_attribution.owner_ref",
                reason: "must be the exact retained Budget owner readback",
            });
        }
        let human_readback = readbacks
            .get(&WorkAdmissionOwnerRole::HumanStaffing)
            .ok_or(StoreError::InvalidReceipt)?;
        if human_readback.canonical_json != self.staffing_plan_request_json
            || human_readback.sha256 != self.staffing_plan_request_sha256
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.staffing_plan_request_json",
                reason: "must be the exact owner-issued Human Staffing readback",
            });
        }
        let model_readback = readbacks
            .get(&WorkAdmissionOwnerRole::ModelCatalog)
            .ok_or(StoreError::InvalidReceipt)?;
        let model_evidence: WorkAdmissionModelCatalogEvidence =
            serde_json::from_str(&model_readback.canonical_json)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
        model_evidence.validate(model_readback)?;
        let policy_readback = readbacks
            .get(&WorkAdmissionOwnerRole::Policy)
            .ok_or(StoreError::InvalidReceipt)?;
        if policy_readback.owner_ref != self.role_visibility_policy_ref {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.role_visibility_policy_ref",
                reason: "must identify the exact current Policy owner readback",
            });
        }
        let plan_value: serde_json::Value = serde_json::from_str(&self.staffing_plan_request_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let visibility_ref_is_in_plan = plan_value
            .pointer("/recipe/role_profiles")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|roles| {
                roles.iter().any(|role| {
                    let reference = role.get("visibility_policy");
                    reference.and_then(|value| value.get("kind")).and_then(serde_json::Value::as_str)
                        == Some(self.role_visibility_policy_ref.kind.as_str())
                        && reference.and_then(|value| value.get("id")).and_then(serde_json::Value::as_str)
                            == Some(self.role_visibility_policy_ref.id.as_str())
                        && reference.and_then(|value| value.get("revision")).and_then(serde_json::Value::as_str)
                            == Some(self.role_visibility_policy_ref.revision.as_str())
                        && reference.and_then(|value| value.get("digest")).and_then(serde_json::Value::as_str)
                            == self.role_visibility_policy_ref.digest.as_deref()
                })
            });
        let expected_plan_privacy = serde_json::to_value(self.privacy_class)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if !visibility_ref_is_in_plan
            || plan_value.get("privacy_class") != Some(&expected_plan_privacy)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.staffing_plan_request_json",
                reason: "must retain the selected role visibility policy and exact admitted privacy class",
            });
        }
        let selected_route_privacy_refs: std::collections::BTreeSet<&str> = plan_value
            .pointer("/lanes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|lane| {
                lane.pointer("route_candidates")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .flat_map(|route| {
                route.pointer("privacy_evidence_refs")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(serde_json::Value::as_str)
            .collect();
        if self
            .route_privacy_evidence_refs
            .iter()
            .any(|reference| !selected_route_privacy_refs.contains(reference.as_str()))
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.route_privacy_evidence_refs",
                reason: "must be preserved by the frozen staffing-plan route inputs",
            });
        }
        let scope_readback = readbacks
            .get(&WorkAdmissionOwnerRole::WorkScope)
            .ok_or(StoreError::InvalidReceipt)?;
        let scope_value: serde_json::Value = serde_json::from_str(&scope_readback.canonical_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let expected_privacy = serde_json::to_value(self.privacy_class)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if scope_value.pointer("/binding/scope/scope_ref").and_then(serde_json::Value::as_str)
            != Some(record.scope_id.as_str())
            || scope_value.pointer("/binding/privacy_class")
                != Some(&expected_privacy)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.privacy_class",
                reason: "must match the exact current WorkScope binding readback",
            });
        }
        let task_readback = readbacks
            .get(&WorkAdmissionOwnerRole::Task)
            .ok_or(StoreError::InvalidReceipt)?;
        let task_value: serde_json::Value = serde_json::from_str(&task_readback.canonical_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let task_fence = serde_json::to_value(&record.state_fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if task_value.get("task_id").and_then(serde_json::Value::as_str)
            != Some(record.task_id.as_str())
            || task_value.get("goal").and_then(serde_json::Value::as_str)
                != Some(self.admitted_goal.as_str())
            || task_value.get("revision").and_then(serde_json::Value::as_u64)
                != record.task_revision.parse::<u64>().ok()
            || task_value.get("state_fence") != Some(&task_fence)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.attribution.admitted_goal",
                reason: "must equal the current Task owner goal, revision, and fence",
            });
        }
        let budget_value: serde_json::Value = serde_json::from_str(&budget_readback.canonical_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let owner_revision = budget_value.get("revision").and_then(serde_json::Value::as_u64);
        let owner_fence = serde_json::to_value(&record.state_fence)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let envelope = budget_value.pointer("/state/ledger/envelope");
        let provider_tool = envelope.and_then(|value| value.get("provider_tool"));
        let reservations = budget_value
            .pointer("/state/ledger/reservations")
            .and_then(serde_json::Value::as_array);
        let matching_reservations: Vec<&serde_json::Value> = reservations
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.get("idempotency_key").and_then(serde_json::Value::as_str)
                    == Some(self.budget_attribution.reservation_idempotency_key.as_str())
            })
            .collect();
        let admitted_reservation = matching_reservations
            .first()
            .and_then(|entry| entry.get("receipt"));
        if owner_revision != Some(budget_readback.owner_revision)
            || budget_value.get("state_fence") != Some(&owner_fence)
            || envelope.and_then(|value| value.get("envelope_id")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.envelope_id.as_str())
            || envelope.and_then(|value| value.get("policy_snapshot_id")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.policy_snapshot_id.as_str())
            || envelope.and_then(|value| value.get("automation_policy_ref")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.automation_policy_ref.as_str())
            || envelope.and_then(|value| value.get("cost_authority_ref")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.cost_authority_ref.as_str())
            || provider_tool.and_then(|value| value.get("provider_ref")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.provider_ref.as_str())
            || provider_tool.and_then(|value| value.get("tool_ref")).and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.tool_ref.as_str())
            || matching_reservations.len() != 1
            || admitted_reservation
                .and_then(|value| value.get("reservation_id"))
                .and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.reservation_id.as_str())
            || admitted_reservation
                .and_then(|value| value.get("idempotency_key"))
                .and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.reservation_idempotency_key.as_str())
            || admitted_reservation
                .and_then(|value| value.get("envelope_id"))
                .and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.envelope_id.as_str())
            || admitted_reservation
                .and_then(|value| value.pointer("/provider_tool/provider_ref"))
                .and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.provider_ref.as_str())
            || admitted_reservation
                .and_then(|value| value.pointer("/provider_tool/tool_ref"))
                .and_then(serde_json::Value::as_str)
                != Some(self.budget_attribution.tool_ref.as_str())
            || admitted_reservation
                .and_then(|value| value.pointer("/operation/state_fence"))
                != Some(&owner_fence)
            || admitted_reservation
                .and_then(|value| value.pointer("/authority/state_fence"))
                != Some(&owner_fence)
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.budget_attribution",
                reason: "must match the exact current Budget envelope and one original reservation row under this fence",
            });
        }
        match &self.budget_attribution.swarm {
            WorkAdmissionSwarmBudgetAttribution::Attributed { budget_ref, .. }
                if budget_ref == &budget_readback.owner_ref => {}
            WorkAdmissionSwarmBudgetAttribution::Attributed { .. } => {
                return Err(StoreError::InvalidField {
                    field: "work_admission.budget_attribution.swarm.budget_ref",
                    reason: "must identify the exact retained Budget owner readback",
                });
            }
            WorkAdmissionSwarmBudgetAttribution::NotApplicable { owner_ref, .. }
                if owner_ref == &human_readback.owner_ref => {}
            WorkAdmissionSwarmBudgetAttribution::NotApplicable { .. } => {
                return Err(StoreError::InvalidField {
                    field: "work_admission.budget_attribution.swarm.owner_ref",
                    reason: "NotApplicable must be issued by the retained Human Staffing owner",
                });
            }
        }
        Ok(())
    }
}

/// One owner-issued dependency that must already carry accepted evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionDependency {
    pub work_id: String,
    pub evidence_digest: String,
}

impl WorkAdmissionDependency {
    fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.work_id, "work_admission.dependency.work_id")?;
        validate_digest(&self.evidence_digest, "work_admission.dependency.evidence_digest")
    }
}

/// Closed dimensions copied from the admitted durable-work definition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAdmissionBudgetDimension {
    ComputeSteps,
    CostMicrounits,
    EvidenceBytes,
}

/// One explicit budget limit from the admitted work definition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionBudget {
    pub dimension: WorkAdmissionBudgetDimension,
    pub limit: u64,
}

/// Immutable owner-defined claim identity and exact content digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionClaimRef {
    pub reference: String,
    pub sha256: String,
}

impl WorkAdmissionClaimRef {
    fn validate(&self, field: &'static str) -> Result<(), StoreError> {
        validate_text(&self.reference, field)?;
        validate_digest(&self.sha256, "work_admission.claim.sha256")
    }
}

/// Complete resource, lane, environment, effects, and quota claim set.
///
/// These are opaque owner references, not admitted ceilings. Each original
/// claim digest is retained verbatim for the Kernel reservation join.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionClaims {
    pub resources: WorkAdmissionClaimRef,
    pub lane: WorkAdmissionClaimRef,
    pub environment: WorkAdmissionClaimRef,
    pub effects: WorkAdmissionClaimRef,
    pub quota_view: WorkAdmissionClaimRef,
}

impl WorkAdmissionClaims {
    pub fn validate(&self) -> Result<(), StoreError> {
        let claims = [
            (&self.resources, "work_admission.claim.resources"),
            (&self.lane, "work_admission.claim.lane"),
            (&self.environment, "work_admission.claim.environment"),
            (&self.effects, "work_admission.claim.effects"),
            (&self.quota_view, "work_admission.claim.quota_view"),
        ];
        let mut seen = std::collections::BTreeMap::new();
        for (claim, field) in claims {
            claim.validate(field)?;
            if let Some(prior) = seen.insert(claim.reference.as_str(), claim.sha256.as_str())
                && prior != claim.sha256.as_str()
            {
                return Err(StoreError::Duplicate { field: "work_admission.claims" });
            }
        }
        Ok(())
    }
}

/// Canonical state of this immutable admission row.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkAdmissionState {
    Admitted,
}

/// Governor-owned canonical ADMITTED decision for one exact reservation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionRecord {
    pub schema: String,
    pub state: WorkAdmissionState,
    /// Durable work identity from the owner-issued admitted definition.
    pub work_id: String,
    pub parent_task_id: String,
    pub task_id: String,
    pub session_id: String,
    pub task_revision: String,
    pub cell_id: String,
    pub payload_digest: String,
    pub input_revision: String,
    pub scope_id: String,
    pub term: u64,
    pub dependencies: Vec<WorkAdmissionDependency>,
    pub budgets: Vec<WorkAdmissionBudget>,
    pub route_class: String,
    pub max_retries: u32,
    pub max_children: u32,
    pub max_depth: u32,
    pub max_pending_reviews: u32,
    pub evidence_required: bool,
    pub receipt_contract_revision: String,
    /// Exact identity tuple of the staged ORS reservation.
    pub reservation_id: OperationIdentity,
    pub work_item_id: OperationIdentity,
    pub proposed_attempt_id: OperationIdentity,
    pub stage_operation_id: OperationIdentity,
    /// Original admitted work operation dispatched by the native claim.
    /// This is distinct from the reservation-stage and canonical commit IDs.
    pub admitted_operation_id: OperationId,
    pub claims: WorkAdmissionClaims,
    /// Exact authenticated Task Controller and current owner evidence used to
    /// make this ADMITTED decision.
    pub owner_attribution: WorkAdmissionOwnerAttribution,
    pub authority_epoch: eliot_contracts::EpochId,
    pub state_fence: StateFence,
    pub expires_at_ms: i64,
    /// Original semantic-owner revision, stored first-class.
    pub semantic_admission_revision: WorkAdmissionSemanticRevision,
    /// Owner-observed predecessor of the proposed semantic admission revision.
    /// The canonical commit compares this exact value before advancing it.
    pub semantic_admission_predecessor_revision: u64,
    /// Canonical operation whose transaction commits this ADMITTED row.
    pub canonical_operation_id: OperationId,
    /// Exact idempotency key from the original canonical submission.
    /// Retries and restart reconciliation reuse this value unchanged.
    pub canonical_idempotency_key: String,
    /// Exact launch outbox row written by that same canonical operation.
    pub launch_outbox_id: OutboxId,
}

impl WorkAdmissionRecord {
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != WORK_ADMISSION_SCHEMA_V1 {
            return Err(StoreError::UnknownOperation);
        }
        if self.state != WorkAdmissionState::Admitted {
            return Err(StoreError::InvalidField {
                field: "work_admission.state",
                reason: "canonical work admission must be ADMITTED",
            });
        }
        for (field, value) in [
            ("work_admission.work_id", self.work_id.as_str()),
            ("work_admission.parent_task_id", self.parent_task_id.as_str()),
            ("work_admission.task_id", self.task_id.as_str()),
            ("work_admission.session_id", self.session_id.as_str()),
            ("work_admission.task_revision", self.task_revision.as_str()),
            ("work_admission.cell_id", self.cell_id.as_str()),
            ("work_admission.input_revision", self.input_revision.as_str()),
            ("work_admission.scope_id", self.scope_id.as_str()),
            ("work_admission.route_class", self.route_class.as_str()),
            (
                "work_admission.receipt_contract_revision",
                self.receipt_contract_revision.as_str(),
            ),
            (
                "work_admission.canonical_idempotency_key",
                self.canonical_idempotency_key.as_str(),
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(&self.payload_digest, "work_admission.payload_digest")?;
        self.reservation_id.validate()?;
        self.work_item_id.validate()?;
        self.proposed_attempt_id.validate()?;
        self.stage_operation_id.validate()?;
        if OperationId::new(self.admitted_operation_id.as_str())? != self.admitted_operation_id {
            return Err(StoreError::InvalidField {
                field: "work_admission.admitted_operation_id",
                reason: "must retain the exact original admitted-work operation identity",
            });
        }
        self.owner_attribution.validate_for(self)?;
        self.claims.validate()?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(StoreError::FenceMismatch);
        }
        if self.expires_at_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "work_admission.expires_at_ms",
                reason: "must be a positive owner-issued expiry",
            });
        }
        self.semantic_admission_revision
            .validate_owner_canonical(self.semantic_admission_predecessor_revision)
            .map_err(|_| StoreError::InvalidField {
                field: "work_admission.semantic_admission_revision",
                reason: "must be the exact next canonical owner revision after its retained predecessor",
            })?;
        let mut dependency_ids = std::collections::BTreeSet::new();
        for dependency in &self.dependencies {
            dependency.validate()?;
            if !dependency_ids.insert(dependency.work_id.as_str()) {
                return Err(StoreError::Duplicate {
                    field: "work_admission.dependencies",
                });
            }
        }
        let mut budget_dimensions = std::collections::BTreeSet::new();
        for budget in &self.budgets {
            if !budget_dimensions.insert(budget.dimension) {
                return Err(StoreError::Duplicate {
                    field: "work_admission.budgets",
                });
            }
        }
        let expected_launch = OutboxIntentKind::Launch
            .outbox_id(self.canonical_operation_id.as_str(), 0)?;
        if self.launch_outbox_id != expected_launch {
            return Err(StoreError::InvalidField {
                field: "work_admission.launch_outbox_id",
                reason: "must be the launch row derived from the canonical operation identity",
            });
        }
        Ok(())
    }

    /// Key shared by the canonical row and its exact readback.
    pub fn record_key(&self) -> String {
        format!("{}:{}", self.work_id, self.proposed_attempt_id.operation_id)
    }
}

/// Independently retained expected values copied from the original prepared
/// transition, never derived from a receipt or a receipt-shaped transport body.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedWorkAdmissionCommitment {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub state_fence: StateFence,
    pub transition_class: TransitionClass,
    pub operation_manifest_digest: crate::OperationManifestDigest,
    pub admission_digest: String,
    pub mutation_plan_digest: String,
    pub semantic_source_revisions: Vec<String>,
    pub launch_outbox_id: OutboxId,
}

impl ExpectedWorkAdmissionCommitment {
    pub fn from_prepared(transition: &PreparedTransition) -> Result<Self, StoreError> {
        validate_work_admission_transition(transition)?;
        let record = decode_work_admission_record(&transition.named_operations[0].parameters)?;
        let expected = Self {
            operation_id: transition.identity.operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: transition.identity.canonical_request_hash.clone(),
            state_fence: transition.state_fence.clone(),
            transition_class: transition.transition_class,
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            admission_digest: transition.admission_digest.clone(),
            mutation_plan_digest: transition.mutation_plan_digest.clone(),
            semantic_source_revisions: transition.semantic_source_revisions.clone(),
            launch_outbox_id: record.launch_outbox_id,
        };
        Ok(expected)
    }

    pub fn matches_receipt(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        receipt.validate()?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.operation_id != self.operation_id
            || receipt.idempotency_key != self.idempotency_key
            || receipt.canonical_request_hash != self.canonical_request_hash
            || receipt.state_fence != self.state_fence
            || receipt.transition_class != self.transition_class
            || receipt.operation_manifest_digest != self.operation_manifest_digest
            || receipt.admission_digest != self.admission_digest
            || receipt.mutation_plan_digest != self.mutation_plan_digest
            || receipt.semantic_source_revisions != self.semantic_source_revisions
        {
            return Err(StoreError::InvalidReceipt);
        }
        let launches: Vec<&OutboxId> = receipt
            .outbox_refs
            .iter()
            .filter(|id| OutboxIntentKind::of(id) == Some(OutboxIntentKind::Launch))
            .collect();
        if launches.len() != 1 || launches[0] != &self.launch_outbox_id {
            return Err(StoreError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Kernel-ready owner output retaining the exact authenticated request,
/// prepared transition and compare-and-swap heads used to create it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionSubmission {
    pub request: RequestMeta,
    pub prepared_transition: PreparedTransition,
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pub expected: ExpectedWorkAdmissionCommitment,
}

impl WorkAdmissionSubmission {
    pub fn new(
        request: RequestMeta,
        prepared_transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<Self, StoreError> {
        request.validate().map_err(StoreError::Foundation)?;
        validate_work_admission_transition(&prepared_transition)?;
        if request.state_fence != prepared_transition.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        let record = decode_work_admission_record(
            &prepared_transition.named_operations[0].parameters,
        )?;
        if prepared_transition.identity.idempotency_key != record.canonical_idempotency_key {
            return Err(StoreError::InvalidField {
                field: "work_admission.canonical_idempotency_key",
                reason: "must match the original prepared transition identity",
            });
        }
        if request.task_id.as_ref().map(|task| task.as_str()) != Some(record.task_id.as_str())
            || request.session_id.as_ref().map(|session| session.as_str())
                != Some(record.session_id.as_str())
        {
            return Err(StoreError::InvalidField {
                field: "work_admission.request_metadata",
                reason: "authenticated task and session must match admitted work",
            });
        }
        for head in &expected_revision_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for head in &expected_ordering_heads {
            head.validate()?;
            if head.state_fence != prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        let expected = ExpectedWorkAdmissionCommitment::from_prepared(&prepared_transition)?;
        Ok(Self {
            request,
            prepared_transition,
            expected_revision_heads,
            expected_ordering_heads,
            expected,
        })
    }

    pub fn validate(&self) -> Result<(), StoreError> {
        self.request.validate().map_err(StoreError::Foundation)?;
        validate_work_admission_transition(&self.prepared_transition)?;
        let record = decode_work_admission_record(
            &self.prepared_transition.named_operations[0].parameters,
        )?;
        if self.request.state_fence != self.prepared_transition.state_fence
            || self.expected
                != ExpectedWorkAdmissionCommitment::from_prepared(&self.prepared_transition)?
            || self.request.task_id.as_ref().map(|task| task.as_str())
                != Some(record.task_id.as_str())
            || self.request.session_id.as_ref().map(|session| session.as_str())
                != Some(record.session_id.as_str())
            || self.prepared_transition.identity.idempotency_key
                != record.canonical_idempotency_key
        {
            return Err(StoreError::InvalidReceipt);
        }
        for head in &self.expected_revision_heads {
            head.validate()?;
            if head.state_fence != self.prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
            if head.state_fence != self.prepared_transition.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_receipt(&self, receipt: &WriteReceipt) -> Result<(), StoreError> {
        self.validate()?;
        self.expected.matches_receipt(receipt)
    }
}

/// Decodes the sole `record` parameter under the closed work-admission schema.
pub fn decode_work_admission_record(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<WorkAdmissionRecord, StoreError> {
    let value = parameters.get("record").ok_or(StoreError::InvalidField {
        field: "work_admission.record",
        reason: "required canonical record is missing",
    })?;
    let record: WorkAdmissionRecord = serde_json::from_value(value.clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    record.validate()?;
    Ok(record)
}

/// Validates the original prepared `AdmitWork` transition and its independent
/// semantic revision binding.
pub fn validate_work_admission_transition(
    transition: &PreparedTransition,
) -> Result<(), StoreError> {
    if transition.transition_class != TransitionClass::TaskControl
        || transition.requested_effect_ceiling != crate::EffectClass::ReversibleMutation
        || transition.named_operations.len() != 1
        || transition.named_operations[0].operation != NamedMutationOperation::AdmitWork
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    crate::validate_typed_mutation_parameters(
        NamedMutationOperation::AdmitWork,
        &transition.named_operations[0].parameters,
    )?;
    let record = decode_work_admission_record(&transition.named_operations[0].parameters)?;
    let task = transition.task_id.as_deref();
    if task != Some(record.task_id.as_str())
        || transition.scope_id.as_str() != record.scope_id
        || transition.state_fence != record.state_fence
        || transition.identity.operation_id != record.canonical_operation_id
        || transition.identity.idempotency_key != record.canonical_idempotency_key
    {
        return Err(StoreError::FenceMismatch);
    }
    validate_work_admission_owner_cas(&record, &transition.named_operations[0].parameters)?;
    if record.launch_outbox_id
        != OutboxIntentKind::Launch.outbox_id(
            transition.identity.operation_id.as_str(),
            0,
        )?
    {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(())
}

/// Checks the custom canonical-owner CAS carried by the same AdmitWork
/// command. `owner/canonical` is a RecoveryRecord owner with a named CAS
/// parameter, not a generic revision-head family.
pub fn validate_work_admission_owner_cas(
    record: &WorkAdmissionRecord,
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<(), StoreError> {
    let expected_revision = parameters
        .get("expected_canonical_revision")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "work_admission.expected_canonical_revision",
            reason: "the owner-observed canonical CAS predecessor is required",
        })?;
    let predecessor = record.semantic_admission_predecessor_revision.to_string();
    if expected_revision != predecessor {
        return Err(StoreError::InvalidField {
            field: "work_admission.expected_canonical_revision",
            reason: "must equal the exact owner-observed predecessor",
        });
    }
    let snapshot_json = parameters
        .get("canonical_owner_snapshot_json")
        .and_then(serde_json::Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "work_admission.canonical_owner_snapshot_json",
            reason: "the next canonical owner image is required",
        })?;
    if snapshot_json.is_empty() || snapshot_json.len() > crate::MAX_RECOVERY_RECORD_BYTES {
        return Err(StoreError::InvalidField {
            field: "work_admission.canonical_owner_snapshot_json",
            reason: "must be a non-empty bounded canonical snapshot",
        });
    }
    let snapshot_value: serde_json::Value = serde_json::from_str(snapshot_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let canonical = canonical_json_bytes(&snapshot_value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if String::from_utf8(canonical).ok().as_deref() != Some(snapshot_json) {
        return Err(StoreError::InvalidField {
            field: "work_admission.canonical_owner_snapshot_json",
            reason: "must use canonical JSON encoding",
        });
    }
    let owner_revision = snapshot_value
        .get("owner_revision")
        .and_then(serde_json::Value::as_u64);
    let work_revision = snapshot_value.get("work_admission_revision");
    let state_fence = snapshot_value.get("state_fence");
    let expected_fence = serde_json::to_value(&record.state_fence)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let expected_next = record
        .semantic_admission_revision
        .revision
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidReceipt)?;
    let expected_work_revision = serde_json::to_value(&record.semantic_admission_revision)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if !snapshot_value.is_object()
        || owner_revision != Some(expected_next)
        || work_revision != Some(&expected_work_revision)
        || state_fence != Some(&expected_fence)
    {
        return Err(StoreError::InvalidField {
            field: "work_admission.canonical_owner_snapshot_json",
            reason: "must bind the same fence and the exact proposed owner/admission revisions",
        });
    }
    Ok(())
}

/// Confirms the transition's closed one-command contract before it is passed
/// to the normal admission gate. Kept separate so callers cannot bypass the
/// registered operation catalogue.
pub fn validate_admit_work_command(
    operation: &crate::NamedMutationRequest,
) -> Result<WorkAdmissionRecord, StoreError> {
    if operation.operation != NamedMutationOperation::AdmitWork {
        return Err(StoreError::UnknownOperation);
    }
    decode_work_admission_record(&operation.parameters)
}

/// Builds the closed named mutation consumed by the canonical Store API.
pub fn admit_work_operation(
    record: WorkAdmissionRecord,
    canonical_owner_snapshot_json: String,
) -> Result<crate::NamedMutationRequest, StoreError> {
    record.validate()?;
    let expected_canonical_revision = record.semantic_admission_predecessor_revision.to_string();
    let record_value = serde_json::to_value(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let parameters = std::collections::BTreeMap::from([
        ("record".to_owned(), record_value),
        (
            "expected_canonical_revision".to_owned(),
            serde_json::Value::String(expected_canonical_revision),
        ),
        (
            "canonical_owner_snapshot_json".to_owned(),
            serde_json::Value::String(canonical_owner_snapshot_json),
        ),
    ]);
    let operation = crate::NamedMutationRequest {
        operation: NamedMutationOperation::AdmitWork,
        parameters,
    };
    operation.validate()?;
    Ok(operation)
}

/// Computes the existing SHA-256 over canonical record bytes for the adapter's
/// `RecoveryRecord::value_digest`; no second digest format is introduced.
pub fn work_admission_value_digest(record: &WorkAdmissionRecord) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
