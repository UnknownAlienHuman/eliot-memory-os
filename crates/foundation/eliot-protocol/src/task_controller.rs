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
/// `3` adds the task-free initial `BIND_SCOPE` action. `PROPOSE` and `APPLY`
/// still require task, scope, and all recipe fields; only `BIND_SCOPE` may
/// omit them. Version 2 added the Context recipe catalogue required by W1/W2.
pub const TASK_CONTROLLER_INVOCATION_WIRE_VERSION: u16 = 3;
/// Stable wire identity for the Kernel-issued Task Controller attempt.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_ID: &str = "eliot.protocol.task-controller-attempt";
/// Current Task Controller attempt wire version. Version 2 permits absent
/// task/scope only for the task-free initial `BIND_SCOPE` claim.
pub const TASK_CONTROLLER_ATTEMPT_WIRE_VERSION: u16 = 2;
/// Stable wire identity for the Task Controller result body.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_ID: &str = "eliot.protocol.task-controller-result-body";
/// Current Task Controller result-body wire version.
pub const TASK_CONTROLLER_RESULT_BODY_WIRE_VERSION: u16 = 1;

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
    /// Exact native task identity from the admitted request. `None` is
    /// permitted only for the task-free initial `BIND_SCOPE` action.
    #[serde(default)]
    pub task_id: Option<TaskId>,
    /// Exact work scope from the admitted request. `None` is permitted only
    /// for the task-free initial `BIND_SCOPE` action.
    #[serde(default)]
    pub work_scope_id: Option<String>,
    /// Native proposal for `PROPOSE` or command-plus-context bundle for `APPLY`.
    pub task_input: Value,
    /// Owner-native `LearningStateViewRecipe` selected for this task route.
    #[serde(default)]
    pub learning_state_view_recipe: Option<Value>,
    /// Owner recipe configuration the Context recipe is resolved from: the
    /// approved candidate revisions, this compilation's applicability
    /// dimensions and compiler-generation profile, and the independent
    /// governing requirements they are validated against. The Context owner
    /// resolves exactly one of them; the protocol only carries it.
    #[serde(default)]
    pub context_campaign_recipe_catalogue: Option<Value>,
    /// Rich `ContextRecipe` selected for the current Context admission.
    #[serde(default)]
    pub context_campaign_recipe: Option<Value>,
    /// Exact `ContextInput` admitted for the current Context compilation.
    #[serde(default)]
    pub context_input: Option<Value>,
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
        structured_object(&self.task_input, "task_controller_invocation.task_input")?;
        match self.action {
            TaskControllerAction::BindScope => {
                if self.task_id.is_some()
                    || self.work_scope_id.is_some()
                    || self.learning_state_view_recipe.is_some()
                    || self.context_campaign_recipe_catalogue.is_some()
                    || self.context_campaign_recipe.is_some()
                    || self.context_input.is_some()
                    || self.prior_delivery_selector.is_some()
                    || self.campaign_owner_materials.is_some()
                {
                    return Err(ProtocolError::InvalidField {
                        field: "task_controller_invocation",
                        reason: "BIND_SCOPE is a task-free initial owner action",
                    });
                }
                validate_initial_scope_bind_input(&self.task_input)?;
            }
            TaskControllerAction::Propose | TaskControllerAction::Apply => {
                bounded_text(
                    self.task_id
                        .as_ref()
                        .ok_or(ProtocolError::InvalidField {
                            field: "task_controller_invocation.task_id",
                            reason: "is required for PROPOSE and APPLY",
                        })?
                        .as_str(),
                    "task_controller_invocation.task_id",
                )?;
                bounded_text(
                    self.work_scope_id.as_deref().ok_or(ProtocolError::InvalidField {
                        field: "task_controller_invocation.work_scope_id",
                        reason: "is required for PROPOSE and APPLY",
                    })?,
                    "task_controller_invocation.work_scope_id",
                )?;
                for (value, field) in [
                    (&self.learning_state_view_recipe, "task_controller_invocation.learning_state_view_recipe"),
                    (&self.context_campaign_recipe_catalogue, "task_controller_invocation.context_campaign_recipe_catalogue"),
                    (&self.context_campaign_recipe, "task_controller_invocation.context_campaign_recipe"),
                    (&self.context_input, "task_controller_invocation.context_input"),
                ] {
                    structured_object(value.as_ref().ok_or(ProtocolError::InvalidField {
                        field,
                        reason: "is required for PROPOSE and APPLY",
                    })?, field)?;
                }
            }
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

fn validate_initial_scope_bind_input(value: &Value) -> Result<(), ProtocolError> {
    let object = value.as_object().ok_or(ProtocolError::InvalidField {
        field: "task_controller_invocation.task_input",
        reason: "must be a closed BIND_SCOPE object",
    })?;
    if object.len() != 4
        || object.keys().any(|key| {
            !matches!(key.as_str(), "explicit_root" | "descriptor" | "sources" | "privacy")
        })
        || object.get("explicit_root").and_then(Value::as_str).is_none_or(|root| root.trim().is_empty())
    {
        return Err(ProtocolError::InvalidField {
            field: "task_controller_invocation.task_input",
            reason: "must contain exactly explicit_root, descriptor, sources, and privacy",
        });
    }
    for field in ["descriptor", "sources", "privacy"] {
        structured_object(object.get(field).ok_or(ProtocolError::InvalidField {
            field: "task_controller_invocation.task_input",
            reason: "is missing a required BIND_SCOPE object",
        })?, "task_controller_invocation.task_input")?;
    }
    Ok(())
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
    #[serde(default)]
    pub scope_id: Option<String>,
    /// Absolute attempt expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Remaining result submissions permitted by the Kernel.
    pub use_budget: u32,
    /// Exact native task identity bound to the admitted operation.
    #[serde(default)]
    pub task_id: Option<TaskId>,
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
        if let Some(scope_id) = &self.scope_id {
            bounded_text(scope_id, "task_controller_attempt.scope_id")?;
        }
        if let Some(task_id) = &self.task_id {
            bounded_text(task_id.as_str(), "task_controller_attempt.task_id")?;
        }
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
