//! Wire types for the admitted `eliot.finish` host-request lane (issue #1741).
//!
//! The Kernel owns admission, queue ownership and the fenced attempt
//! capability for one admitted `eliot.finish` invocation. The owner-native
//! finish draft stays opaque at this layer: the Kernel proves the presented
//! bytes are the admitted ones (envelope payload digest) and shape-checks the
//! closed strict-draft field set, while the Governor finish owner performs the
//! authoritative typed decode and evidence rehydration.

#![forbid(unsafe_code)]

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HARD_STRUCTURED_RESPONSE_BYTES, ProtocolError};

/// Stable payload schema identifier for one admitted `eliot.finish`
/// invocation presented through the invoke-read lane.
pub const FINISH_INVOKE_PAYLOAD_SCHEMA_ID: &str = "eliot.finish.invoke.v1";
/// Stable wire identity for one Kernel-issued finish attempt capability.
pub const FINISH_ATTEMPT_WIRE_ID: &str = "eliot.protocol.finish-attempt";
/// Current finish attempt capability wire version.
pub const FINISH_ATTEMPT_WIRE_VERSION: u16 = 2;
/// Stable wire identity for one finish result body.
pub const FINISH_RESULT_BODY_WIRE_ID: &str = "eliot.protocol.finish-result-body";
/// Current finish result body wire version.
pub const FINISH_RESULT_BODY_WIRE_VERSION: u16 = 1;

/// Kernel-issued fenced attempt bound to one admitted `eliot.finish`
/// operation.
///
/// The capability binds the exact operation handle and presenting session to
/// the Kernel-retained authenticated task owner tuple. The semantic task fence
/// is carried separately from the admitted envelope's transport Session
/// fence, so task revision never mutates the daemon's live transport identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FinishAttempt {
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
    /// Authenticated application principal retained by Kernel activation.
    pub principal_id: String,
    /// Owner-selected task retained by Kernel activation.
    pub task_id: String,
    /// Owner-selected `WorkScope` retained by Kernel activation.
    pub work_scope_id: String,
    /// Current `TaskContract` revision retained by Kernel activation.
    pub task_revision: u64,
    /// Semantic task fence, retained separately from the transport Session
    /// fence. Its epoch and generation must agree with the admitted envelope;
    /// its task revision is the activation owner's current revision.
    pub semantic_state_fence: StateFence,
    /// Authority epoch observed when the Kernel issued the attempt.
    pub authority_epoch: EpochId,
    /// Absolute attempt expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Remaining result submissions permitted by the Kernel.
    pub use_budget: u32,
}

impl FinishAttempt {
    /// Validates the bounded capability shape. Currency is still enforced by
    /// the Kernel's retained attempt record.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.semantic_state_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if self.wire_id != FINISH_ATTEMPT_WIRE_ID
            || self.wire_version != FINISH_ATTEMPT_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.wire",
                reason: "unsupported finish attempt",
            });
        }
        validate_operation_id(&self.operation_id, "finish_attempt.operation_id")?;
        bounded_text(&self.attempt_id, "finish_attempt.attempt_id")?;
        if self.attempt_id == self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.attempt_id",
                reason: "attempt identity must not reuse the operation handle",
            });
        }
        if self.fencing_generation == 0 {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.fencing_generation",
                reason: "fencing generation must be positive",
            });
        }
        bounded_text(&self.session_id, "finish_attempt.session_id")?;
        bounded_text(&self.principal_id, "finish_attempt.principal_id")?;
        bounded_text(&self.task_id, "finish_attempt.task_id")?;
        bounded_text(&self.work_scope_id, "finish_attempt.work_scope_id")?;
        if self.task_revision == 0
            || self
                .semantic_state_fence
                .task_revision
                .map(eliot_contracts::TaskRevision::value)
                != Some(self.task_revision)
        {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.semantic_state_fence",
                reason: "semantic fence must carry the retained positive task revision",
            });
        }
        eliot_contracts::epoch_identity_digest(&self.semantic_state_fence.authority_epoch)
            .map_err(|_| ProtocolError::InvalidField {
                field: "finish_attempt.semantic_state_fence.authority_epoch",
                reason: "semantic authority epoch is not valid",
            })?;
        if self.semantic_state_fence.authority_epoch != self.authority_epoch {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.semantic_state_fence.authority_epoch",
                reason: "semantic fence authority epoch must match the attempt epoch",
            });
        }
        if self.semantic_state_fence.resource_generation.value() == 0 {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.semantic_state_fence.resource_generation",
                reason: "semantic resource generation must be positive",
            });
        }
        eliot_contracts::epoch_identity_digest(&self.authority_epoch).map_err(|_| {
            ProtocolError::InvalidField {
                field: "finish_attempt.authority_epoch",
                reason: "authority epoch is not valid",
            }
        })?;
        if self.expires_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.expires_at_unix_ms",
                reason: "attempt expiry must be greater than zero",
            });
        }
        if self.use_budget == 0 {
            return Err(ProtocolError::InvalidField {
                field: "finish_attempt.use_budget",
                reason: "attempt use budget must be positive",
            });
        }
        Ok(())
    }
}

/// Exact bounded finish response bound to its admitted envelope and attempt.
///
/// The response carries the exact bounded `McpResponse` JSON the bridge
/// serves for the admitted operation, so the stored body is the answer the
/// waiter receives without any re-derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FinishResultBody {
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
    /// Exact finish response payload (`McpResponse` JSON).
    pub response: Value,
    /// Required current attempt for this result submission.
    pub attempt: FinishAttempt,
}

impl FinishResultBody {
    /// Validates wire identity, bounded result bytes, request binding and the
    /// required current-attempt shape.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != FINISH_RESULT_BODY_WIRE_ID
            || self.wire_version != FINISH_RESULT_BODY_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.wire",
                reason: "unsupported finish result body",
            });
        }
        validate_operation_id(&self.operation_id, "finish_result_body.operation_id")?;
        lowercase_sha256(&self.request_sha256, "finish_result_body.request_sha256")?;
        let operation_digest =
            self.operation_id
                .strip_prefix("hostreq:")
                .ok_or(ProtocolError::InvalidField {
                    field: "finish_result_body.operation_id",
                    reason: "must be the deterministic handle for its request digest",
                })?;
        if operation_digest != self.request_sha256 {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.request_sha256",
                reason: "request digest does not match the operation handle",
            });
        }
        lowercase_sha256(&self.result_digest, "finish_result_body.result_digest")?;
        if !self.response.is_object() {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.response",
                reason: "result body must be a JSON object",
            });
        }
        let bytes = canonical_json_bytes(&self.response)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        if bytes.len() > HARD_STRUCTURED_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.response",
                reason: "result body exceeds the bounded response ceiling",
            });
        }
        if eliot_contracts::sha256_hex(&bytes) != self.result_digest {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.result_digest",
                reason: "result digest does not bind the exact response bytes",
            });
        }
        self.attempt.validate()?;
        if self.attempt.operation_id != self.operation_id {
            return Err(ProtocolError::InvalidField {
                field: "finish_result_body.attempt",
                reason: "attempt does not bind the exact operation handle",
            });
        }
        Ok(())
    }
}

const MAX_FINISH_TEXT_BYTES: usize = 512;

fn text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    text(value, field)?;
    if value.len() > MAX_FINISH_TEXT_BYTES {
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
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
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
