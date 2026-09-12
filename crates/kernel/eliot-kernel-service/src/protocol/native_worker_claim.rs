//! Kernel-side native-worker claim envelope (Wave A, issue #872).
//!
//! Pure types plus validation for one Kernel-admitted native-worker process
//! generation claiming exactly one Kernel-owned execution unit. No behavior,
//! no stores, no IO: persistence, admission decisions, and lifecycle
//! transitions land in later waves. Kernel validates identity, epoch, fence,
//! and ordering only; it never interprets task semantics, provider policy,
//! or finish.
//!
//! The binding digest procedure mirrors
//! `eliot_native_worker_core::NativeWorkerClaim::compute_binding_digest`
//! byte-for-byte: the digest covers exactly the keys `attempt_id`,
//! `authority_epoch`, `budget`, `cancellation_policy_id`, `claim_id`,
//! `deadline_unix_ms`, `decision_id`, `expected_result_schema`,
//! `expected_result_schema_version`, `operation_id`, `parent_job_id`,
//! `predecessor_revision`, `registration_id`, `route_class`, `state_fence`,
//! `task_id`, `work_scope_id`, `worker_generation`, with object keys sorted
//! recursively before hashing. The worker-side transparent string newtypes
//! and the plain strings used here serialize to identical JSON, so equal
//! logical claims yield equal digests on both sides.

use eliot_contracts::{AuthorityEpoch, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

/// Stable identity for the Kernel-owned native-worker claim wire.
pub const NATIVE_WORKER_CLAIM_WIRE_ID: &str = "eliot.kernel.native-worker-claim";
/// Current version of the Kernel-owned native-worker claim wire.
pub const NATIVE_WORKER_CLAIM_WIRE_VERSION: u16 = 1;
/// Supported execution-unit schema version admitted on this wire.
pub const NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION: u16 = 1;
/// Native-worker protocol version admitted on this wire.
///
/// Must equal the worker contract `PROTOCOL_VERSION`; the envelope rejects
/// anything else as an unknown version.
pub const NATIVE_WORKER_PROTOCOL_VERSION: &str = "eliot-native-worker/v2";

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value, field)
}

/// Validates a lowercase SHA-256 wire digest.
fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if !is_lowercase_sha256(value) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Resource and context ceilings mirrored from the worker claim budget.
///
/// Field names and shapes match the worker-side budget envelope exactly so
/// the canonical binding digest agrees across the boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimBudget {
    /// Context token ceiling; nonzero.
    pub context_tokens: u64,
    /// Wall-time ceiling in milliseconds; nonzero.
    pub wall_time_ms: u64,
    /// Output byte ceiling; nonzero.
    pub output_bytes: u64,
    /// Cost ceiling in microunits; nonzero.
    pub cost_microunits: u64,
    /// Maximum delegation depth; nonzero.
    pub max_depth: u16,
    /// Maximum descendant count.
    pub max_descendants: u32,
}

impl NativeWorkerClaimBudget {
    /// Validates that every ceiling is a usable nonzero bound.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.context_tokens == 0
            || self.wall_time_ms == 0
            || self.output_bytes == 0
            || self.cost_microunits == 0
            || self.max_depth == 0
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.budget",
                reason: "budget ceilings must be non-zero",
            });
        }
        Ok(())
    }
}

/// Worker-presented claim for exactly one Kernel-owned execution unit.
///
/// Mirrors the worker-side claim field-for-field so Kernel can validate the
/// closed shape and recompute the binding digest without importing worker
/// internals. The route/provider class is an admitted label only; this
/// contour never selects a provider, model, or factory.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Distinct claim operation identity.
    pub claim_id: String,
    /// Registration the claim is presented under.
    pub registration_id: String,
    /// Claiming worker generation.
    pub worker_generation: u64,
    /// Installation that owns the worker artifact projection.
    pub installation_id: String,
    /// Lowercase SHA-256 of the exact admitted worker artifact bytes.
    pub worker_artifact_digest: String,
    /// Lowercase SHA-256 of the exact admitted worker configuration bytes.
    pub worker_config_digest: String,
    /// Native-worker protocol version presented by the worker.
    pub protocol_version: String,
    /// Supported execution-unit schema version.
    pub execution_unit_schema_version: u16,
    /// Kernel-owned parent Durable Job identity.
    pub parent_job_id: String,
    /// Governed task identity.
    pub task_id: String,
    /// Task `WorkScope` identity.
    pub work_scope_id: String,
    /// Logical decision this attempt executes.
    pub decision_id: String,
    /// Attempt identity bound to this claim.
    pub attempt_id: String,
    /// Exact external-effect operation identity.
    pub operation_id: String,
    /// Admitted route/provider class label.
    pub route_class: String,
    /// Resource and context ceilings for the unit.
    pub budget: NativeWorkerClaimBudget,
    /// Claim deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Cancellation policy governing this unit.
    pub cancellation_policy_id: String,
    /// Expected result schema name.
    pub expected_result_schema: String,
    /// Expected result schema version.
    pub expected_result_schema_version: u16,
    /// Predecessor revision this claim continues from.
    pub predecessor_revision: String,
    /// Current authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// Canonical digest over every bound work field.
    pub binding_digest: String,
    /// Canonical digest over this request envelope.
    pub request_digest: String,
}

impl NativeWorkerClaimRequest {
    /// Current claim wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_CLAIM_WIRE_VERSION;

    /// Computes the canonical binding digest over every bound work field.
    ///
    /// Covers exactly the same key set as the worker-side
    /// `compute_binding_digest`, so equal logical claims hash identically on
    /// both sides of the boundary.
    pub fn compute_binding_digest(&self) -> Result<String, KernelServiceError> {
        let canonical = serde_json::json!({
            "attempt_id": self.attempt_id,
            "authority_epoch": self.authority_epoch,
            "budget": self.budget,
            "cancellation_policy_id": self.cancellation_policy_id,
            "claim_id": self.claim_id,
            "deadline_unix_ms": self.deadline_unix_ms,
            "decision_id": self.decision_id,
            "expected_result_schema": self.expected_result_schema,
            "expected_result_schema_version": self.expected_result_schema_version,
            "operation_id": self.operation_id,
            "parent_job_id": self.parent_job_id,
            "predecessor_revision": self.predecessor_revision,
            "registration_id": self.registration_id,
            "route_class": self.route_class,
            "state_fence": self.state_fence,
            "task_id": self.task_id,
            "work_scope_id": self.work_scope_id,
            "worker_generation": self.worker_generation,
        });
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "native_worker_claim.binding_digest",
                reason: "cannot canonicalize claim",
            })
    }

    /// Returns the canonical non-circular request digest.
    pub fn canonical_request_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            claim_id: &'a str,
            registration_id: &'a str,
            worker_generation: u64,
            installation_id: &'a str,
            worker_artifact_digest: &'a str,
            worker_config_digest: &'a str,
            protocol_version: &'a str,
            execution_unit_schema_version: u16,
            parent_job_id: &'a str,
            task_id: &'a str,
            work_scope_id: &'a str,
            decision_id: &'a str,
            attempt_id: &'a str,
            operation_id: &'a str,
            route_class: &'a str,
            budget: &'a NativeWorkerClaimBudget,
            deadline_unix_ms: u64,
            cancellation_policy_id: &'a str,
            expected_result_schema: &'a str,
            expected_result_schema_version: u16,
            predecessor_revision: &'a str,
            authority_epoch: AuthorityEpoch,
            state_fence: &'a StateFence,
            binding_digest: &'a str,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            claim_id: &self.claim_id,
            registration_id: &self.registration_id,
            worker_generation: self.worker_generation,
            installation_id: &self.installation_id,
            worker_artifact_digest: &self.worker_artifact_digest,
            worker_config_digest: &self.worker_config_digest,
            protocol_version: &self.protocol_version,
            execution_unit_schema_version: self.execution_unit_schema_version,
            parent_job_id: &self.parent_job_id,
            task_id: &self.task_id,
            work_scope_id: &self.work_scope_id,
            decision_id: &self.decision_id,
            attempt_id: &self.attempt_id,
            operation_id: &self.operation_id,
            route_class: &self.route_class,
            budget: &self.budget,
            deadline_unix_ms: self.deadline_unix_ms,
            cancellation_policy_id: &self.cancellation_policy_id,
            expected_result_schema: &self.expected_result_schema,
            expected_result_schema_version: self.expected_result_schema_version,
            predecessor_revision: &self.predecessor_revision,
            authority_epoch: self.authority_epoch,
            state_fence: &self.state_fence,
            binding_digest: &self.binding_digest,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "native_worker_claim.request_digest",
                reason: "cannot canonicalize request",
            })
    }

    /// Returns this request with its canonical request digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.request_digest = self.canonical_request_digest()?;
        Ok(self)
    }

    /// Validates that the request digest equals the canonical digest.
    pub fn validate_canonical_digest(&self) -> Result<(), KernelServiceError> {
        if self.request_digest != self.canonical_request_digest()? {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.request_digest",
            });
        }
        Ok(())
    }

    /// Validates the closed claim shape and recomputes the binding digest.
    ///
    /// Rejects unknown wire/protocol/schema versions, stale epoch/fence
    /// bindings, missing owner fields, and binding digests that do not match
    /// the presented work. The request digest itself is verified separately
    /// with [`NativeWorkerClaimRequest::validate_canonical_digest`].
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != NATIVE_WORKER_CLAIM_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.wire",
                reason: "unsupported native-worker claim wire",
            });
        }
        if self.protocol_version != NATIVE_WORKER_PROTOCOL_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.protocol_version",
                reason: "unsupported native-worker protocol version",
            });
        }
        if self.execution_unit_schema_version != NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.execution_unit_schema_version",
                reason: "unsupported execution-unit schema version",
            });
        }
        for (text, field) in [
            (&self.claim_id, "native_worker_claim.claim_id"),
            (&self.registration_id, "native_worker_claim.registration_id"),
            (&self.installation_id, "native_worker_claim.installation_id"),
            (&self.parent_job_id, "native_worker_claim.parent_job_id"),
            (&self.task_id, "native_worker_claim.task_id"),
            (&self.work_scope_id, "native_worker_claim.work_scope_id"),
            (&self.decision_id, "native_worker_claim.decision_id"),
            (&self.attempt_id, "native_worker_claim.attempt_id"),
            (&self.operation_id, "native_worker_claim.operation_id"),
            (&self.route_class, "native_worker_claim.route_class"),
            (
                &self.cancellation_policy_id,
                "native_worker_claim.cancellation_policy_id",
            ),
            (
                &self.expected_result_schema,
                "native_worker_claim.expected_result_schema",
            ),
            (
                &self.predecessor_revision,
                "native_worker_claim.predecessor_revision",
            ),
        ] {
            validate_wire_text(text, field)?;
        }
        for (digest, field) in [
            (
                &self.worker_artifact_digest,
                "native_worker_claim.worker_artifact_digest",
            ),
            (
                &self.worker_config_digest,
                "native_worker_claim.worker_config_digest",
            ),
            (&self.binding_digest, "native_worker_claim.binding_digest"),
            (&self.request_digest, "native_worker_claim.request_digest"),
        ] {
            validate_wire_digest(digest, field)?;
        }
        if self.worker_generation == 0
            || self.deadline_unix_ms == 0
            || self.expected_result_schema_version == 0
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.bounded_fields",
                reason: "generation, deadline, and schema version must be non-zero",
            });
        }
        self.budget.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.state_fence",
            })?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.epoch_fence",
            });
        }
        if self.compute_binding_digest()? != self.binding_digest {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.binding_digest",
            });
        }
        Ok(())
    }
}

/// Bound receipt for one admitted claim.
///
/// Returned only after Kernel persists the claim transition (Wave B). The
/// receipt echoes the admitted binding digest; exact replay of the same
/// claim returns the same receipt identity instead of a second claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimReceipt {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Admitted claim operation identity.
    pub claim_id: String,
    /// Registration the claim was admitted under.
    pub registration_id: String,
    /// Attempt identity bound to the admitted claim.
    pub attempt_id: String,
    /// Exact external-effect operation identity.
    pub operation_id: String,
    /// Admitted worker generation.
    pub worker_generation: u64,
    /// Authority epoch at admission time.
    pub authority_epoch: AuthorityEpoch,
    /// State fence at admission time.
    pub state_fence: StateFence,
    /// Admitted binding digest.
    pub binding_digest: String,
    /// Admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Canonical digest over this receipt envelope.
    pub receipt_digest: String,
}

impl NativeWorkerClaimReceipt {
    /// Current claim wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_CLAIM_WIRE_VERSION;

    /// Computes the canonical receipt digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            claim_id: &'a str,
            registration_id: &'a str,
            attempt_id: &'a str,
            operation_id: &'a str,
            worker_generation: u64,
            authority_epoch: AuthorityEpoch,
            state_fence: &'a StateFence,
            binding_digest: &'a str,
            admitted_at_unix_ms: u64,
        }
        let canonical = Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            claim_id: &self.claim_id,
            registration_id: &self.registration_id,
            attempt_id: &self.attempt_id,
            operation_id: &self.operation_id,
            worker_generation: self.worker_generation,
            authority_epoch: self.authority_epoch,
            state_fence: &self.state_fence,
            binding_digest: &self.binding_digest,
            admitted_at_unix_ms: self.admitted_at_unix_ms,
        };
        canonical_json_bytes(&canonical)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "native_worker_claim_receipt.receipt_digest",
                reason: "cannot canonicalize receipt",
            })
    }

    /// Returns this receipt with its canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.receipt_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the receipt shape and its canonical digest.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != NATIVE_WORKER_CLAIM_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_receipt.wire",
                reason: "unsupported native-worker claim wire",
            });
        }
        for (text, field) in [
            (&self.claim_id, "native_worker_claim_receipt.claim_id"),
            (
                &self.registration_id,
                "native_worker_claim_receipt.registration_id",
            ),
            (&self.attempt_id, "native_worker_claim_receipt.attempt_id"),
            (
                &self.operation_id,
                "native_worker_claim_receipt.operation_id",
            ),
        ] {
            validate_wire_text(text, field)?;
        }
        for (digest, field) in [
            (
                &self.binding_digest,
                "native_worker_claim_receipt.binding_digest",
            ),
            (
                &self.receipt_digest,
                "native_worker_claim_receipt.receipt_digest",
            ),
        ] {
            validate_wire_digest(digest, field)?;
        }
        if self.worker_generation == 0 || self.admitted_at_unix_ms == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_receipt.bounded_fields",
                reason: "generation and admission time must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim_receipt.state_fence",
            })?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim_receipt.epoch_fence",
            });
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_receipt.receipt_digest",
                reason: "receipt digest mismatch",
            });
        }
        Ok(())
    }
}

/// Typed reason a claim was not admitted.
///
/// Every rejection names its cause; a transport connection without an exact
/// current registration and claimed unit is rejected, never parked.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeWorkerClaimRejectionReason {
    /// Unknown claim wire version.
    UnknownWireVersion,
    /// Unknown native-worker protocol version.
    UnknownProtocolVersion,
    /// Unknown execution-unit schema version.
    UnknownSchemaVersion,
    /// Registration is unknown, expired, or superseded.
    StaleRegistration,
    /// Authority epoch is stale or disagrees with the fence.
    StaleEpoch,
    /// State fence is stale or disagrees with the claim.
    StaleFence,
    /// Same claim identity carries changed bound work.
    BindingConflict,
    /// A Kernel-owned binding field is missing.
    MissingOwnerField,
    /// Readiness was asserted from transport health alone.
    TransportOnlyReadiness,
    /// Claim deadline already passed at admission time.
    ExpiredDeadline,
    /// A claim field failed bounded shape validation.
    InvalidClaimField,
}

/// Typed rejection for one refused claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimRejection {
    /// Refused claim operation identity.
    pub claim_id: String,
    /// Typed refusal cause.
    pub reason: NativeWorkerClaimRejectionReason,
    /// Bounded detail naming the failing field or binding.
    pub detail: String,
    /// Rejection time in Unix milliseconds.
    pub rejected_at_unix_ms: u64,
}

impl NativeWorkerClaimRejection {
    /// Validates the rejection shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.claim_id, "native_worker_claim_rejection.claim_id")?;
        validate_wire_text(&self.detail, "native_worker_claim_rejection.detail")?;
        if self.rejected_at_unix_ms == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_rejection.rejected_at_unix_ms",
                reason: "rejection time must be non-zero",
            });
        }
        Ok(())
    }
}

/// Changed-work conflict under one claim identity.
///
/// Mirrors the worker-side conflict report: the same claim identity was
/// presented with changed work, generation, route, budget, schema, fence,
/// or predecessor. The conflicting presentation takes no effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerClaimConflict {
    /// Claim identity both bindings were presented under.
    pub claim_id: String,
    /// Admitted binding digest.
    pub expected_digest: String,
    /// Presented binding digest.
    pub observed_digest: String,
    /// Bound dimensions that differ, in canonical field order.
    pub changed_fields: Vec<String>,
}

impl NativeWorkerClaimConflict {
    /// Maximum changed-field entries admitted in one conflict report.
    pub const MAX_CHANGED_FIELDS: usize = 32;

    /// Validates the conflict shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.claim_id, "native_worker_claim_conflict.claim_id")?;
        validate_wire_digest(
            &self.expected_digest,
            "native_worker_claim_conflict.expected_digest",
        )?;
        validate_wire_digest(
            &self.observed_digest,
            "native_worker_claim_conflict.observed_digest",
        )?;
        if self.expected_digest == self.observed_digest {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_conflict.observed_digest",
                reason: "conflicting digests must differ",
            });
        }
        if self.changed_fields.is_empty() || self.changed_fields.len() > Self::MAX_CHANGED_FIELDS {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim_conflict.changed_fields",
                reason: "must name at least one changed dimension within the bound",
            });
        }
        for field in &self.changed_fields {
            validate_wire_text(field, "native_worker_claim_conflict.changed_fields")?;
        }
        Ok(())
    }
}

/// Kernel answer to one claim request.
///
/// Exactly one variant is returned: an admission receipt, a typed rejection,
/// or a changed-work conflict. A conflicting presentation never produces a
/// second live claim under the same identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum NativeWorkerClaimResponse {
    /// The claim was admitted; the receipt is the admission proof.
    Admitted(NativeWorkerClaimReceipt),
    /// The claim was refused for the named typed reason.
    Rejected(NativeWorkerClaimRejection),
    /// The claim identity conflicts with admitted bound work.
    Conflict(NativeWorkerClaimConflict),
}

impl NativeWorkerClaimResponse {
    /// Validates the enclosed receipt, rejection, or conflict.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::Admitted(receipt) => receipt.validate(),
            Self::Rejected(rejection) => rejection.validate(),
            Self::Conflict(conflict) => conflict.validate(),
        }
    }
}
