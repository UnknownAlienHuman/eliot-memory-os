//! Closed task-controller invocation and result transport contracts.
//!
//! The protocol carries opaque JSON values for domain-owned proposal, command,
//! recipe, and context bodies. The daemon decodes those values at the relevant
//! owner boundary and performs semantic validation; protocol shape validation
//! alone grants no Task Controller authority.

use eliot_contracts::{EpochId, StateFence, TaskId, canonical_json_bytes, epoch_identity_digest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HARD_STRUCTURED_RESPONSE_BYTES, MAX_FRAME_BYTES, ProtocolError};

/// Stable wire identity for one admitted Task Controller invocation.
pub const TASK_CONTROLLER_INVOCATION_WIRE_ID: &str = "eliot.protocol.task-controller-invocation";
/// Current Task Controller invocation wire version.
///
/// `2` adds the required `context_campaign_recipe_catalogue` member: an
/// invocation that names a Context recipe must also name the owner recipe
/// configuration that recipe is resolved from (#1724 W1/W2). A `1` payload
/// cannot decode into this shape, so the missing member is refused by version
/// and by field rather than defaulted into an instance that was compiled under
/// no approved recipe.
pub const TASK_CONTROLLER_INVOCATION_WIRE_VERSION: u16 = 2;
/// Stable wire identity for the Kernel-issued Task Controller attempt.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_ID: &str = "eliot.protocol.task-controller-attempt";
/// Current Task Controller attempt wire version.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_VERSION: u16 = 1;
/// Stable wire identity for the Task Controller result body.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_ID: &str = "eliot.protocol.task-controller-result-body";
/// Current Task Controller result-body wire version.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION: u16 = 1;
/// Stable wire identity for one authenticated Coordinate requester intent.
pub const TASK_CONTROLLER_COORDINATE_INTENT_WIRE_ID: &str =
    "eliot.protocol.task-controller-coordinate-intent";
/// Current Coordinate requester-intent wire version.
pub const TASK_CONTROLLER_COORDINATE_INTENT_WIRE_VERSION: u16 = 2;

const MAX_TASK_CONTROLLER_TEXT_BYTES: usize = 512;
const MAX_TASK_CONTROLLER_VALUE_BYTES: usize = MAX_FRAME_BYTES;

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank without surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    if value.len() > MAX_TASK_CONTROLLER_TEXT_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}

fn lowercase_sha256(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn structured_object(value: &Value, field: &'static str) -> Result<(), ProtocolError> {
    if !value.is_object() {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a JSON object",
        });
    }
    let bytes =
        canonical_json_bytes(value).map_err(|error| ProtocolError::Json(error.to_string()))?;
    if bytes.len() > MAX_TASK_CONTROLLER_VALUE_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded JSON value size",
        });
    }
    Ok(())
}

/// Closed Task Controller operation requested by the authenticated caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskControllerAction {
    /// Admit a new task proposal.
    Propose,
    /// Apply an exact command to an existing task.
    Apply,
    /// Admit one explicit human-authored Coordinate intent.
    Coordinate,
}

/// Explicit requester intent about whether this Coordinate is solo or swarm
/// work. It is never a budget-owner receipt: Governor must confirm the chosen
/// scope against current Task/plan/work-scope owners before attribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinateExecutionScopeV1 {
    /// The requester asks for one solo work attempt.
    Solo,
    /// The requester asks for a named swarm work scope.
    Swarm {
        /// Selector for independent current swarm and budget owner reads.
        swarm_id: String,
    },
}

impl CoordinateExecutionScopeV1 {
    /// Validates the requested scope selector without granting authority.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if let Self::Swarm { swarm_id } = self {
            bounded_text(swarm_id, "task_controller_coordinate_intent.swarm_id")?;
        }
        Ok(())
    }
}

/// Requester-authored Coordinate intent attached to an authenticated Task
/// Controller claim. The exact requester JSON is retained byte-for-byte;
/// staffing intent, constraints, and owner locators are semantic input only,
/// never owner readbacks or currentness evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerCoordinateIntentV1 {
    /// Coordinate intent wire identity.
    pub wire_id: String,
    /// Coordinate intent wire version.
    pub wire_version: u16,
    /// Stable identity assigned by the authenticated Task Controller owner.
    pub request_id: String,
    /// Original canonical requester JSON; these exact bytes are the source
    /// material from which the daemon parses the delegate goal.
    pub canonical_request_json: String,
    /// SHA-256 of `canonical_request_json`'s exact bytes.
    pub canonical_request_sha256: String,
    /// Explicit human staffing intent, decoded by the daemon's native owner.
    pub human_staffing_intent: Value,
    /// Explicit solo/swarm scope request, not owner-side attribution.
    pub requested_execution_scope: CoordinateExecutionScopeV1,
    /// Requested constraints; these are intent, not current owner evidence.
    pub requested_constraints: Value,
    /// Bounded owner locators that select rows for independent reads only.
    pub owner_locators: Vec<Value>,
}

impl TaskControllerCoordinateIntentV1 {
    /// Validates transport shape, exact canonical requester bytes, and bounds.
    /// Semantic staffing and owner currentness remain with the daemon owners.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_COORDINATE_INTENT_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_COORDINATE_INTENT_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_coordinate_intent.wire",
                reason: "unsupported Coordinate intent wire",
            });
        }
        bounded_text(&self.request_id, "task_controller_coordinate_intent.request_id")?;
        lowercase_sha256(
            &self.canonical_request_sha256,
            "task_controller_coordinate_intent.canonical_request_sha256",
        )?;
        if self.canonical_request_json.is_empty()
            || self.canonical_request_json.len() > MAX_TASK_CONTROLLER_VALUE_BYTES
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_coordinate_intent.canonical_request_json",
                reason: "request bytes must be non-empty and within the bounded JSON limit",
            });
        }
        let request: Value = serde_json::from_str(&self.canonical_request_json)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if !request.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_coordinate_intent.canonical_request_json",
                reason: "request bytes must encode a JSON object",
            });
        }
        let canonical = canonical_json_bytes(&request)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if canonical.as_slice() != self.canonical_request_json.as_bytes()
            || eliot_contracts::sha256_hex(&canonical) != self.canonical_request_sha256
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_coordinate_intent.canonical_request_sha256",
                reason: "digest must bind the exact original canonical requester bytes",
            });
        }
        structured_object(
            &self.human_staffing_intent,
            "task_controller_coordinate_intent.human_staffing_intent",
        )?;
        self.requested_execution_scope.validate()?;
        structured_object(
            &self.requested_constraints,
            "task_controller_coordinate_intent.requested_constraints",
        )?;
        if self.owner_locators.len() > 32 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_coordinate_intent.owner_locators",
                reason: "exceeds the bounded owner-selector count",
            });
        }
        for locator in &self.owner_locators {
            structured_object(locator, "task_controller_coordinate_intent.owner_locators")?;
        }
        Ok(())
    }
}

/// Owner-native material bundle used only for a complete campaign-owner
/// transition. The protocol keeps each owner body opaque; the daemon decodes
/// it at the owning boundary and rejects missing, detached, or unbound values.
/// An absent bundle selects the ordinary recipe-bearing Task Controller path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerCampaignOwnerMaterials {
    /// Optional selector/body slot for the Context owner. It is never used as
    /// publication authority; the daemon reads the current owner row instead.
    pub prior_delivery: Value,
    /// Optional selector/body slot for the evaluator owner. It is never used
    /// as publication authority; the daemon reads the current owner row instead.
    pub evaluation: Value,
    /// Reserved owner-head selector slot. It must be empty: the daemon reads
    /// current heads through its authenticated Kernel route.
    pub source_heads: Vec<Value>,
    /// Reserved owner-row selector slot. It must be empty: caller rows cannot
    /// become owner evidence.
    pub remaining_owner_inputs: Vec<Value>,
}

/// Authenticated, closed-shape Task Controller invocation.
///
/// Domain objects remain JSON at the protocol layer to avoid a dependency from
/// foundation protocol into governor, smart-context, or learning contracts.
/// The daemon decodes `task_input` as the action-specific native Task object,
/// `learning_state_view_recipe` as the native learning recipe,
/// `context_campaign_recipe_catalogue` as the native
/// `ApprovedRecipeCatalogue` owner configuration,
/// `context_campaign_recipe` as the rich native `ContextRecipe`, and
/// `context_input` as the exact `ContextInput`. It joins the latter three into
/// the typed Context campaign recipe body before owner publication.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerInvocation {
    /// Invocation wire identity.
    pub wire_id: String,
    /// Invocation wire version.
    pub wire_version: u16,
    /// Create or update operation selected by the admitted caller.
    pub action: TaskControllerAction,
    /// Exact native task identity from the admitted request.
    pub task_id: TaskId,
    /// Exact work scope from the admitted request identity.
    pub work_scope_id: String,
    /// Native proposal for `PROPOSE` or command-plus-context bundle for `APPLY`.
    pub task_input: Value,
    /// Owner-native `LearningStateViewRecipe` selected for this task route.
    pub learning_state_view_recipe: Value,
    /// Owner recipe configuration the Context recipe is resolved from: the
    /// approved candidate revisions, this compilation's applicability
    /// dimensions and compiler-generation profile, and the independent
    /// governing requirements they are validated against. The Context owner
    /// resolves exactly one of them; the protocol only carries it.
    pub context_campaign_recipe_catalogue: Value,
    /// Rich `ContextRecipe` selected for the current Context admission.
    pub context_campaign_recipe: Value,
    /// Exact `ContextInput` admitted for the current Context compilation.
    pub context_input: Value,
    /// Optional selector for the persisted prior delivery snapshot. This is a
    /// lookup selector only and is never evidence or source authority.
    pub prior_delivery_selector: Option<Value>,
    /// Optional complete owner-material bundle. When present, the daemon must
    /// assemble and validate every declared owner role before committing the
    /// Task Controller transition; it cannot infer any missing owner row.
    #[serde(default)]
    pub campaign_owner_materials: Option<TaskControllerCampaignOwnerMaterials>,
}

impl TaskControllerInvocation {
    /// Validates the transport envelope and bounded JSON object fields.
    /// Semantic field/identity validation remains with the daemon owners.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_INVOCATION_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_INVOCATION_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_invocation.wire",
                reason: "unsupported Task Controller invocation",
            });
        }
        bounded_text(self.task_id.as_str(), "task_controller_invocation.task_id")?;
        bounded_text(
            &self.work_scope_id,
            "task_controller_invocation.work_scope_id",
        )?;
        for (value, field) in [
            (&self.task_input, "task_controller_invocation.task_input"),
            (
                &self.learning_state_view_recipe,
                "task_controller_invocation.learning_state_view_recipe",
            ),
            (
                &self.context_campaign_recipe_catalogue,
                "task_controller_invocation.context_campaign_recipe_catalogue",
            ),
            (
                &self.context_campaign_recipe,
                "task_controller_invocation.context_campaign_recipe",
            ),
            (
                &self.context_input,
                "task_controller_invocation.context_input",
            ),
        ] {
            structured_object(value, field)?;
        }
        if self.action == TaskControllerAction::Coordinate {
            let intent: TaskControllerCoordinateIntentV1 =
                serde_json::from_value(self.task_input.clone())
                    .map_err(|error| ProtocolError::Json(error.to_string()))?;
            intent.validate()?;
        }
        if let Some(selector) = &self.prior_delivery_selector {
            structured_object(
                selector,
                "task_controller_invocation.prior_delivery_selector",
            )?;
        }
        if let Some(materials) = &self.campaign_owner_materials {
            structured_object(
                &materials.prior_delivery,
                "task_controller_invocation.campaign_owner_materials.prior_delivery",
            )?;
            structured_object(
                &materials.evaluation,
                "task_controller_invocation.campaign_owner_materials.evaluation",
            )?;
            if materials.source_heads.len() > 26 {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials.source_heads",
                    reason: "exceeds the closed owner-role denominator",
                });
            }
            for head in &materials.source_heads {
                structured_object(
                    head,
                    "task_controller_invocation.campaign_owner_materials.source_heads",
                )?;
            }
            if !materials.source_heads.is_empty() || !materials.remaining_owner_inputs.is_empty() {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials",
                    reason: "caller-supplied owner heads and rows are not authenticated evidence",
                });
            }
            if materials.remaining_owner_inputs.len() > 26 {
                return Err(ProtocolError::InvalidField {
                    field: "task_controller_invocation.campaign_owner_materials.remaining_owner_inputs",
                    reason: "exceeds the closed owner-role denominator",
                });
            }
            for input in &materials.remaining_owner_inputs {
                structured_object(
                    input,
                    "task_controller_invocation.campaign_owner_materials.remaining_owner_inputs",
                )?;
            }
        }
        Ok(())
    }
}

/// Kernel-issued fenced attempt bound to one Task Controller operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerAttempt {
    /// Attempt capability wire identity.
    pub wire_id: String,
    /// Attempt capability wire version.
    pub wire_version: u16,
    /// Opaque operation identity derived from the admitted envelope digest.
    pub operation_id: String,
    /// Unique Kernel-issued attempt identity.
    pub attempt_id: String,
    /// Monotonic generation for this operation.
    pub fencing_generation: u64,
    /// Authenticated session bound to this attempt.
    pub session_id: String,
    /// Authority epoch observed when the Kernel issued the attempt.
    pub authority_epoch: EpochId,
    /// Exact admitted work scope.
    pub scope_id: String,
    /// Absolute attempt expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Remaining result submissions permitted by the Kernel.
    pub use_budget: u32,
    /// Exact native task identity bound to the admitted operation.
    pub task_id: TaskId,
    /// Exact state fence admitted for this operation.
    pub state_fence: StateFence,
}

impl TaskControllerAttempt {
    /// Validates the bounded capability shape. Currency is still enforced by
    /// the Kernel's retained attempt record.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_ATTEMPT_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_ATTEMPT_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.wire",
                reason: "unsupported Task Controller attempt",
            });
        }
        validate_operation_id(&self.operation_id, "task_controller_attempt.operation_id")?;
        bounded_text(&self.attempt_id, "task_controller_attempt.attempt_id")?;
        if self.attempt_id == self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.attempt_id",
                reason: "attempt identity must not reuse the operation handle",
            });
        }
        if self.fencing_generation == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.fencing_generation",
                reason: "fencing generation must be positive",
            });
        }
        bounded_text(&self.session_id, "task_controller_attempt.session_id")?;
        epoch_identity_digest(&self.authority_epoch).map_err(|_| ProtocolError::InvalidField {
            field: "task_controller_attempt.authority_epoch",
            reason: "authority epoch is not valid",
        })?;
        bounded_text(&self.scope_id, "task_controller_attempt.scope_id")?;
        bounded_text(self.task_id.as_str(), "task_controller_attempt.task_id")?;
        self.state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if self.state_fence.authority_epoch != self.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.authority_epoch",
                reason: "must exactly match the State Fence authority epoch",
            });
        }
        if self.expires_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.expires_at_unix_ms",
                reason: "attempt expiry must be greater than zero",
            });
        }
        if self.use_budget == 0 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_attempt.use_budget",
                reason: "attempt use budget must be positive",
            });
        }
        Ok(())
    }
}

/// Exact bounded Task Controller response bound to its invocation and attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskControllerResultBody {
    /// Result body wire identity.
    pub wire_id: String,
    /// Result body wire version.
    pub wire_version: u16,
    /// Opaque operation identity derived from the admitted envelope digest.
    pub operation_id: String,
    /// SHA-256 of the exact admitted request envelope.
    pub request_sha256: String,
    /// Canonical digest over the exact bounded response JSON.
    pub result_digest: String,
    /// Exact Task Controller response payload.
    pub response: Value,
    /// Required current attempt for this result submission.
    pub attempt: TaskControllerAttempt,
}

impl TaskControllerResultBody {
    /// Validates wire identity, bounded result bytes, request binding and the
    /// required current-attempt shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != TASK_CONTROLLER_RESULT_BODY_WIRE_ID
            || self.wire_version != TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.wire",
                reason: "unsupported Task Controller result body",
            });
        }
        validate_operation_id(
            &self.operation_id,
            "task_controller_result_body.operation_id",
        )?;
        lowercase_sha256(
            &self.request_sha256,
            "task_controller_result_body.request_sha256",
        )?;
        let operation_digest =
            self.operation_id
                .strip_prefix("hostreq:")
                .ok_or(ProtocolError::InvalidField {
                    field: "task_controller_result_body.operation_id",
                    reason: "must be the deterministic handle for its request digest",
                })?;
        if operation_digest != self.request_sha256 {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.request_sha256",
                reason: "request digest does not match the operation handle",
            });
        }
        lowercase_sha256(
            &self.result_digest,
            "task_controller_result_body.result_digest",
        )?;
        if !self.response.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.response",
                reason: "result body must be a JSON object",
            });
        }
        let bytes = canonical_json_bytes(&self.response)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if bytes.len() > HARD_STRUCTURED_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.response",
                reason: "result body exceeds the bounded response ceiling",
            });
        }
        if eliot_contracts::sha256_hex(&bytes) != self.result_digest {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.result_digest",
                reason: "result digest does not bind the exact response bytes",
            });
        }
        self.attempt.validate()?;
        if self.attempt.operation_id != self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "task_controller_result_body.attempt",
                reason: "attempt does not bind the exact operation handle",
            });
        }
        Ok(())
    }
}

fn validate_operation_id(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    bounded_text(value, field)?;
    if !value.strip_prefix("hostreq:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a hostreq handle containing a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

#[cfg(test)]
mod coordinate_intent_tests {
    use super::*;

    fn intent() -> TaskControllerCoordinateIntentV1 {
        let request = serde_json::json!({
            "expected_result": "report",
            "goal": "summarize the accepted change",
            "operation": "delegate",
            "owned_resources": ["src/lib.rs"],
        });
        let canonical = canonical_json_bytes(&request).expect("canonical requester bytes");
        TaskControllerCoordinateIntentV1 {
            wire_id: TASK_CONTROLLER_COORDINATE_INTENT_WIRE_ID.to_owned(),
            wire_version: TASK_CONTROLLER_COORDINATE_INTENT_WIRE_VERSION,
            request_id: "coordinate-request-1".to_owned(),
            canonical_request_json: String::from_utf8(canonical.clone()).expect("UTF-8"),
            canonical_request_sha256: eliot_contracts::sha256_hex(&canonical),
            human_staffing_intent: serde_json::json!({"mode":"solo"}),
            requested_execution_scope: CoordinateExecutionScopeV1::Solo,
            requested_constraints: serde_json::json!({"max_workers":1}),
            owner_locators: vec![serde_json::json!({"task":"task:1"})],
        }
    }

    #[test]
    fn coordinate_intent_accepts_exact_original_request_and_owner_selectors() {
        intent()
            .validate()
            .expect("exact requester intent is bounded and well formed");
    }

    #[test]
    fn coordinate_intent_refuses_changed_request_bytes() {
        let mut changed = intent();
        changed.canonical_request_json.push(' ');
        assert!(
            changed.validate().is_err(),
            "changed original bytes must not retain the original digest"
        );
    }
}
