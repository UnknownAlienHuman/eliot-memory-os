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
//! `task_id`, `work_scope_id`, `worker_generation`, plus one nested
//! `executable_binding` object carrying the T9-02 executable join. The nested
//! object is JSON `null` for wire-v1 claims (which predate the join) and
//! otherwise covers exactly the keys `adapter_id`, `adapter_revision`,
//! `authority_epoch`, `config_digest`, `deadline_unix_ms`,
//! `executable_binding_digest`, `executable_wire_version`,
//! `expires_at_unix_ms`, `facet_manifest_ref`, `generation`,
//! `grant_graph_revision`, `launch_nonce`, `process_invocation_digest`,
//! `replay_stream_id`, `route_ref`, `state_fence`, with object keys sorted
//! recursively before hashing. The worker-side transparent string newtypes
//! and the plain strings used here serialize to identical JSON, and the
//! epoch/fence/generation values on both sides come from the same
//! `eliot-contracts` types, so equal logical claims yield equal digests on
//! both sides. Wire v2 is required for executable authority: a v1 claim
//! parses (its join decodes as absent) but is explicitly refused by
//! `require_executable_binding` and never silently promotes to launch
//! authority.
//!
//! The carried `executable_binding_digest` is the opaque owner-produced
//! `NativeWorkerExecutableBinding` v1 digest (T9-01, M1): Kernel compares it
//! for equality against the current owner record supplied by the route via
//! [`NativeWorkerExecutableExpectation`] and never recomputes the Governor
//! digest domain here. Depending on `eliot-governor` from this C1 crate
//! would invert the I2.3 dependency direction (C4 → C3 → C2 → C1 → C0), so
//! the Kernel join is expressed with raw digest bytes plus explicit
//! currentness fields reusing the T9-01 field names.

use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

/// Stable identity for the Kernel-owned native-worker claim wire.
pub const NATIVE_WORKER_CLAIM_WIRE_ID: &str = "eliot.kernel.native-worker-claim";
/// Current version of the Kernel-owned native-worker claim wire.
///
/// Revision 2 carries the T9-02 executable-binding join (`executable_binding`
/// with the owner-produced executable digest plus M1 currentness inputs).
/// Revision 1 still parses — its join decodes as absent — but can never
/// satisfy [`NativeWorkerClaimRequest::require_executable_binding`].
pub const NATIVE_WORKER_CLAIM_WIRE_VERSION: u16 = 2;
/// Previous claim-wire revision, retained only to reject old-wire claims
/// explicitly at the executable gate instead of promoting them silently.
pub const NATIVE_WORKER_CLAIM_WIRE_VERSION_V1: u16 = 1;
/// Expected wire revision of the owner-produced executable binding (T9-01
/// `NativeWorkerExecutableBinding` v1).
///
/// Carried by value, never imported: this C1 crate must not depend on
/// `eliot-governor` (I2.3 dependency direction). A binding-wire drift changes
/// the owner digest as well, so this pin fails closed twice.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION: u16 = 1;
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

/// Kernel-side projection of the owner-produced executable binding (T9-02).
///
/// Carries the M1 currentness inputs Kernel needs for refusal — route,
/// adapter, config, facet, grant revision, replay stream, launch nonce,
/// invocation digest, epoch/generation/fence, and the binding window — plus
/// the opaque owner-produced `NativeWorkerExecutableBinding` v1 digest.
/// Field names reuse the T9-01 names where they exist. This is a Kernel
/// identity/epoch/fence/ordering projection only: it carries references and
/// revisions, never task meaning, plan/policy content, effective ceilings,
/// credential or resource values, or Governor composition. The full T9-01
/// record stays with its owner; Kernel compares the carried digest for
/// equality against the current owner record and refuses any stale join.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerExecutableBinding {
    /// Full canonical route label from the session owner.
    pub route_ref: String,
    /// Adapter/factory identity.
    pub adapter_id: String,
    /// Adapter revision; nonzero.
    pub adapter_revision: u64,
    /// Lowercase SHA-256 of the admitted worker configuration bytes.
    pub config_digest: String,
    /// Facet manifest reference.
    pub facet_manifest_ref: String,
    /// Grant-graph revision the binding was compiled against; nonzero.
    pub grant_graph_revision: u64,
    /// Replay stream identity bound to this claim.
    pub replay_stream_id: String,
    /// Claim-bound launch nonce (16..=256 chars, mirroring T9-01).
    pub launch_nonce: String,
    /// Lowercase SHA-256 of the exact process invocation.
    pub process_invocation_digest: String,
    /// Authority epoch; must agree with `state_fence` via
    /// `is_same_authority`, never by raw sequence comparison.
    pub authority_epoch: EpochId,
    /// Resource generation; must equal `state_fence.resource_generation`.
    pub generation: ResourceGeneration,
    /// Exact immutable fence the binding was compiled against.
    pub state_fence: StateFence,
    /// Execution deadline in Unix milliseconds; nonzero, before expiry.
    pub deadline_unix_ms: u64,
    /// Binding expiry in Unix milliseconds; nonzero, after deadline.
    pub expires_at_unix_ms: u64,
    /// Owner binding wire revision; must equal
    /// [`NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION`].
    pub executable_wire_version: u16,
    /// Opaque owner-produced executable digest (lowercase SHA-256).
    pub executable_binding_digest: String,
}

impl NativeWorkerExecutableBinding {
    /// Minimum presented launch-nonce length (mirrors T9-01).
    pub const MIN_NONCE_LEN: usize = 16;
    /// Maximum presented launch-nonce length (mirrors T9-01).
    pub const MAX_NONCE_LEN: usize = 256;

    /// Validates the closed join shape without treating it as authority.
    ///
    /// Checks bounded texts, digest shapes, nonzero revisions, the
    /// deadline-before-expiry window, and fence/epoch/generation agreement.
    /// Digest equality against the current owner record is checked by
    /// [`NativeWorkerClaimRequest::require_executable_binding`], not here.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (text, field) in [
            (
                &self.route_ref,
                "native_worker_claim.executable_binding.route_ref",
            ),
            (
                &self.adapter_id,
                "native_worker_claim.executable_binding.adapter_id",
            ),
            (
                &self.facet_manifest_ref,
                "native_worker_claim.executable_binding.facet_manifest_ref",
            ),
            (
                &self.replay_stream_id,
                "native_worker_claim.executable_binding.replay_stream_id",
            ),
        ] {
            validate_wire_text(text, field)?;
        }
        validate_wire_text(
            &self.launch_nonce,
            "native_worker_claim.executable_binding.launch_nonce",
        )?;
        if self.launch_nonce.len() < Self::MIN_NONCE_LEN
            || self.launch_nonce.len() > Self::MAX_NONCE_LEN
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.launch_nonce",
                reason: "launch nonce must be 16..=256 characters",
            });
        }
        for (digest, field) in [
            (
                &self.config_digest,
                "native_worker_claim.executable_binding.config_digest",
            ),
            (
                &self.process_invocation_digest,
                "native_worker_claim.executable_binding.process_invocation_digest",
            ),
            (
                &self.executable_binding_digest,
                "native_worker_claim.executable_binding.executable_binding_digest",
            ),
        ] {
            validate_wire_digest(digest, field)?;
        }
        if self.adapter_revision == 0 || self.grant_graph_revision == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.revisions",
                reason: "adapter and grant-graph revisions must be non-zero",
            });
        }
        if self.generation.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.generation",
                reason: "generation must be non-zero",
            });
        }
        if self.executable_wire_version != NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.executable_wire_version",
                reason: "unsupported executable binding wire version",
            });
        }
        if self.deadline_unix_ms == 0 || self.expires_at_unix_ms == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.deadlines",
                reason: "deadline and expiry must be non-zero",
            });
        }
        if self.deadline_unix_ms >= self.expires_at_unix_ms {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.deadlines",
                reason: "deadline must be strictly before expiry",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.state_fence",
            })?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.epoch_fence",
            });
        }
        if self.generation != self.state_fence.resource_generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.state_fence",
            });
        }
        Ok(())
    }
}

/// Current owner-produced executable authority one claim is checked against.
///
/// The route builds this from the live registration, admission, activation,
/// and epoch records at admission time: `current` is what the owner says the
/// binding is now, and `revoked` carries observed invalidation evidence (the
/// binding was withdrawn or superseded after publication). Kernel never
/// mints this value; it only refuses presented claims that disagree with it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerExecutableExpectation {
    /// Owner-produced current executable record.
    pub current: NativeWorkerExecutableBinding,
    /// True when current records show the binding withdrawn or superseded.
    pub revoked: bool,
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
    pub authority_epoch: EpochId,
    /// Exact immutable fence paired with the generation and epoch.
    pub state_fence: StateFence,
    /// T9-02 executable join: owner-produced digest plus M1 currentness
    /// inputs. Absent (`None`) on wire v1, which predates the join and can
    /// never carry executable authority; required on wire v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_binding: Option<NativeWorkerExecutableBinding>,
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
    /// both sides of the boundary. The nested `executable_binding` object is
    /// `null` for wire-v1 claims and otherwise carries the full T9-02 join;
    /// see the module docs for the exact key list.
    pub fn compute_binding_digest(&self) -> Result<String, KernelServiceError> {
        let canonical = serde_json::json!({
            "attempt_id": self.attempt_id,
            "authority_epoch": self.authority_epoch,
            "budget": self.budget,
            "cancellation_policy_id": self.cancellation_policy_id,
            "claim_id": self.claim_id,
            "deadline_unix_ms": self.deadline_unix_ms,
            "decision_id": self.decision_id,
            "executable_binding": self.executable_binding,
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
            authority_epoch: EpochId,
            state_fence: &'a StateFence,
            executable_binding: Option<&'a NativeWorkerExecutableBinding>,
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
            authority_epoch: self.authority_epoch.clone(),
            state_fence: &self.state_fence,
            executable_binding: self.executable_binding.as_ref(),
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
            || (self.wire_version != Self::CONTRACT_VERSION
                && self.wire_version != NATIVE_WORKER_CLAIM_WIRE_VERSION_V1)
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
        if self.wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
            if self.executable_binding.is_some() {
                return Err(KernelServiceError::InvalidField {
                    field: "native_worker_claim.executable_binding",
                    reason: "wire v1 predates the executable join and must not carry executable authority",
                });
            }
        } else {
            self.require_present_join()?;
        }
        if self.compute_binding_digest()? != self.binding_digest {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.binding_digest",
            });
        }
        Ok(())
    }

    /// Returns the validated wire-v2 executable join.
    ///
    /// Wire v1 has no join by construction; callers branch on the wire
    /// version first and only call this on v2.
    fn require_present_join(&self) -> Result<&NativeWorkerExecutableBinding, KernelServiceError> {
        let join = self
            .executable_binding
            .as_ref()
            .ok_or(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding",
                reason: "wire v2 claims must carry the owner-produced executable binding",
            })?;
        join.validate()?;
        Ok(join)
    }

    /// Validates that this claim was presented under one exact registration.
    ///
    /// Mirrors the worker-side `ClaimAdmissionRequest::validate_binding`
    /// without importing worker internals: same registration identity, same
    /// worker generation, same authority epoch, same immutable fence. A claim
    /// rewired onto a stale or foreign registration fails here before any
    /// admission owner stages it, so fresh work is never admitted merely
    /// because its digest shape is well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a registration or
    /// generation mismatch and [`KernelServiceError::HandshakeMismatch`] for
    /// epoch or fence disagreement.
    pub fn validate_presented_under_registration(
        &self,
        registration_id: &str,
        worker_generation: u64,
        authority_epoch: EpochId,
        state_fence: &StateFence,
    ) -> Result<(), KernelServiceError> {
        if self.registration_id != registration_id {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.registration_binding",
                reason: "claim registration does not match the presenting registration",
            });
        }
        if self.worker_generation != worker_generation {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.generation_binding",
                reason: "claim generation does not match the presenting registration",
            });
        }
        if self.authority_epoch != authority_epoch {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.epoch_fence",
            });
        }
        if self.state_fence != *state_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.state_fence",
            });
        }
        Ok(())
    }

    /// Enforces the owner-produced executable binding join (T9-02, M1).
    ///
    /// Compares the presented wire-v2 join against the current owner record
    /// supplied by the route from the live registration, admission,
    /// activation, and epoch records. The presented claim binding digest is
    /// recomputed (it covers the join), the carried owner digest must equal
    /// the current owner digest, and every M1 currentness input must agree.
    /// Epoch agreement always goes through `is_same_authority`, never through
    /// a raw sequence comparison. A stale binding — changed route, adapter,
    /// config, facet, grant revision, nonce, stream, invocation digest, or
    /// owner digest; advanced epoch; withdrawn authority; expired window;
    /// fence disagreement — is refused; it needs a new admission, never a
    /// local repair.
    ///
    /// Callers run [`NativeWorkerClaimRequest::validate`] first; this gate
    /// checks the join, not the full envelope shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an old-wire or
    /// malformed presentation and [`KernelServiceError::HandshakeMismatch`]
    /// for any disagreement with the current owner authority.
    pub fn require_executable_binding(
        &self,
        expected: &NativeWorkerExecutableExpectation,
        now_unix_ms: u64,
    ) -> Result<(), KernelServiceError> {
        if self.wire_version == NATIVE_WORKER_CLAIM_WIRE_VERSION_V1 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.u1_old_wire_without_executable_binding",
                reason: "wire v1 predates the executable join and cannot carry launch authority; renew admission on wire v2",
            });
        }
        if self.wire_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.wire",
                reason: "unsupported native-worker claim wire",
            });
        }
        let presented = self.require_present_join()?;
        expected.current.validate()?;
        if expected.revoked {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding_revoked",
            });
        }
        if self.compute_binding_digest()? != self.binding_digest {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.binding_digest",
            });
        }
        compare_executable_currentness(presented, &expected.current)?;
        if !presented
            .authority_epoch
            .is_same_authority(&self.authority_epoch)
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.epoch_binding",
            });
        }
        if presented.state_fence != self.state_fence {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.fence_binding",
            });
        }
        if now_unix_ms == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_claim.executable_binding.observation_time",
                reason: "binding freshness cannot be proven without an observation time",
            });
        }
        if now_unix_ms >= presented.expires_at_unix_ms {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_claim.executable_binding.expired",
            });
        }
        Ok(())
    }
}

/// Compares one well-formed presented join against the current owner record.
///
/// The carried owner digest must equal the current owner digest, and every
/// M1 currentness input must agree exactly. Epoch agreement always goes
/// through `is_same_authority`, never through a raw sequence comparison.
fn compare_executable_currentness(
    presented: &NativeWorkerExecutableBinding,
    current: &NativeWorkerExecutableBinding,
) -> Result<(), KernelServiceError> {
    if presented.executable_binding_digest != current.executable_binding_digest {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.executable_binding_digest",
        });
    }
    if presented.route_ref != current.route_ref {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.route_ref",
        });
    }
    if presented.adapter_id != current.adapter_id
        || presented.adapter_revision != current.adapter_revision
    {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.adapter",
        });
    }
    if presented.config_digest != current.config_digest {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.config_digest",
        });
    }
    if presented.facet_manifest_ref != current.facet_manifest_ref {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.facet_manifest_ref",
        });
    }
    if presented.grant_graph_revision != current.grant_graph_revision {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.grant_graph_revision",
        });
    }
    if presented.replay_stream_id != current.replay_stream_id {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.replay_stream_id",
        });
    }
    if presented.launch_nonce != current.launch_nonce {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.launch_nonce",
        });
    }
    if presented.process_invocation_digest != current.process_invocation_digest {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.process_invocation_digest",
        });
    }
    if presented.executable_wire_version != current.executable_wire_version {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.executable_wire_version",
        });
    }
    if !presented
        .authority_epoch
        .is_same_authority(&current.authority_epoch)
    {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.authority_epoch",
        });
    }
    if presented.generation != current.generation {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.generation",
        });
    }
    if presented.state_fence != current.state_fence {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_claim.executable_binding.state_fence",
        });
    }
    Ok(())
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
    pub authority_epoch: EpochId,
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
            authority_epoch: EpochId,
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
            authority_epoch: self.authority_epoch.clone(),
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

    /// Fail-closed gate proving claim admission never implies launch (stop S-X2).
    ///
    /// Even an `Admitted` receipt is admission proof only: it carries the
    /// claim/binding identity and digests, never a `ProcessRequest`, permit,
    /// grant, or dispatch authority. Positive claim-to-process launch waits
    /// on the X2 owner contract; until then every call fails closed so an
    /// absent canonical activation performs no launch and no caller can
    /// mistake a receipt for launch authority.
    ///
    /// # Errors
    ///
    /// Always returns [`KernelServiceError::InvalidField`] naming
    /// `missing_canonical_activation`.
    pub fn require_canonical_activation(&self) -> Result<(), KernelServiceError> {
        Err(KernelServiceError::InvalidField {
            field: "native_worker_claim.missing_canonical_activation",
            reason: "claim admission is not launch authority; positive launch waits on X2",
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod executable_binding_tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, TaskRevision};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const CLAIM_DEADLINE_MS: u64 = 1_700_000_500_000;
    const BINDING_DEADLINE_MS: u64 = 1_700_000_000_000;
    const BINDING_EXPIRES_MS: u64 = 1_700_000_600_000;
    const OBSERVED_NOW_MS: u64 = 1_700_000_100_000;

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("test epoch")
    }

    fn live_fence() -> StateFence {
        StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    /// Stand-in for the Governor T9-01 publish output.
    ///
    /// Deterministic SHA-256 over stable seed bytes through the real hash
    /// procedure — never hardcoded. Opaque to the Kernel join, which compares
    /// it for equality only: the true digest is produced by
    /// `publish_native_worker_binding`, which this C1 crate cannot link
    /// without inverting the I2.3 dependency direction.
    fn owner_issued_digest() -> String {
        sha256_hex(b"t9-02 w-a owner-issued executable digest stand-in")
    }

    fn valid_join() -> NativeWorkerExecutableBinding {
        NativeWorkerExecutableBinding {
            route_ref: "route://test/full-canonical-route".to_owned(),
            adapter_id: "adapter-test".to_owned(),
            adapter_revision: 3,
            config_digest: "c".repeat(64),
            facet_manifest_ref: "facet-manifest-7".to_owned(),
            grant_graph_revision: 5,
            replay_stream_id: "stream-claim-t9-02-1/gen-1".to_owned(),
            launch_nonce: "launch-nonce-0123456789abcdef".to_owned(),
            process_invocation_digest: "d".repeat(64),
            authority_epoch: test_epoch(1),
            generation: ResourceGeneration::genesis(),
            state_fence: live_fence(),
            deadline_unix_ms: BINDING_DEADLINE_MS,
            expires_at_unix_ms: BINDING_EXPIRES_MS,
            executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
            executable_binding_digest: owner_issued_digest(),
        }
    }

    struct Fixture {
        claim: NativeWorkerClaimRequest,
        expected: NativeWorkerExecutableExpectation,
        now_ms: u64,
    }

    fn valid_fixture() -> Fixture {
        let join = valid_join();
        let mut claim = NativeWorkerClaimRequest {
            wire_id: NATIVE_WORKER_CLAIM_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
            claim_id: "claim-t9-02-1".to_owned(),
            registration_id: "reg-1".to_owned(),
            worker_generation: 1,
            installation_id: "installation-1".to_owned(),
            worker_artifact_digest: "a".repeat(64),
            worker_config_digest: "b".repeat(64),
            protocol_version: NATIVE_WORKER_PROTOCOL_VERSION.to_owned(),
            execution_unit_schema_version: NATIVE_WORKER_EXECUTION_UNIT_SCHEMA_VERSION,
            parent_job_id: "parent-job-1".to_owned(),
            task_id: "task-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            decision_id: "decision-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            operation_id: "op-t9-02-1".to_owned(),
            route_class: "test-route".to_owned(),
            budget: NativeWorkerClaimBudget {
                context_tokens: 8,
                wall_time_ms: 1_000,
                output_bytes: 1_024,
                cost_microunits: 10,
                max_depth: 2,
                max_descendants: 4,
            },
            deadline_unix_ms: CLAIM_DEADLINE_MS,
            cancellation_policy_id: "cancel-1".to_owned(),
            expected_result_schema: "result-schema".to_owned(),
            expected_result_schema_version: 1,
            predecessor_revision: "rev-1".to_owned(),
            authority_epoch: test_epoch(1),
            state_fence: live_fence(),
            executable_binding: Some(join.clone()),
            binding_digest: String::new(),
            request_digest: String::new(),
        };
        claim.binding_digest = claim
            .compute_binding_digest()
            .expect("binding digest computes");
        claim.request_digest = claim
            .canonical_request_digest()
            .expect("request digest computes");
        Fixture {
            claim,
            expected: NativeWorkerExecutableExpectation {
                current: join,
                revoked: false,
            },
            now_ms: OBSERVED_NOW_MS,
        }
    }

    /// Recomputes the claim binding digest after a presented-field mutation
    /// so the gate reaches the typed currentness arm instead of stopping at
    /// a stale digest.
    fn rebind(fixture: &mut Fixture) {
        fixture.claim.binding_digest = fixture
            .claim
            .compute_binding_digest()
            .expect("rebind computes");
    }

    fn join_of(fixture: &mut Fixture) -> &mut NativeWorkerExecutableBinding {
        fixture
            .claim
            .executable_binding
            .as_mut()
            .expect("v2 fixture carries the join")
    }

    #[test]
    fn owner_record_passes_production_chain() {
        let fixture = valid_fixture();
        fixture.claim.validate().expect("shape validates");
        fixture
            .claim
            .validate_canonical_digest()
            .expect("envelope digest validates");
        fixture
            .claim
            .validate_presented_under_registration("reg-1", 1, test_epoch(1), &live_fence())
            .expect("registration binds");
        fixture
            .claim
            .require_executable_binding(&fixture.expected, fixture.now_ms)
            .expect("owner-produced join passes");
    }

    #[test]
    fn binding_mutations_reject_with_typed_reason() {
        for case in mutation_cases() {
            let mut fixture = valid_fixture();
            (case.mutate)(&mut fixture);
            if case.rebind_claim {
                rebind(&mut fixture);
            }
            let error = fixture
                .claim
                .require_executable_binding(&fixture.expected, fixture.now_ms)
                .unwrap_err();
            assert!(
                format!("{error:?}").contains(case.expected_field),
                "{}: expected typed reason {}, got {error:?}",
                case.name,
                case.expected_field
            );
        }
    }

    struct MutationCase {
        name: &'static str,
        mutate: fn(&mut Fixture),
        rebind_claim: bool,
        expected_field: &'static str,
    }

    fn mutation_cases() -> Vec<MutationCase> {
        let mut cases = presented_mutation_cases();
        cases.extend(authority_mutation_cases());
        cases
    }

    /// Mutations to the worker-presented join; the claim digest is recomputed
    /// after each so the gate reaches the typed currentness arm.
    fn presented_mutation_cases() -> Vec<MutationCase> {
        vec![
            MutationCase {
                name: "changed route",
                mutate: |fixture| {
                    join_of(fixture).route_ref = "route://test/changed".to_owned();
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.route_ref",
            },
            MutationCase {
                name: "changed adapter revision",
                mutate: |fixture| {
                    join_of(fixture).adapter_revision = 4;
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.adapter",
            },
            MutationCase {
                name: "changed config digest",
                mutate: |fixture| {
                    join_of(fixture).config_digest = "e".repeat(64);
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.config_digest",
            },
            MutationCase {
                name: "changed facet manifest",
                mutate: |fixture| {
                    join_of(fixture).facet_manifest_ref = "facet-manifest-9".to_owned();
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.facet_manifest_ref",
            },
            MutationCase {
                name: "changed grant revision",
                mutate: |fixture| {
                    join_of(fixture).grant_graph_revision = 6;
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.grant_graph_revision",
            },
            MutationCase {
                name: "changed replay stream",
                mutate: |fixture| {
                    join_of(fixture).replay_stream_id = "stream-other/gen-1".to_owned();
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.replay_stream_id",
            },
            MutationCase {
                name: "changed launch nonce",
                mutate: |fixture| {
                    join_of(fixture).launch_nonce = "changed-nonce-0123456789abcdef".to_owned();
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.launch_nonce",
            },
            MutationCase {
                name: "changed invocation digest",
                mutate: |fixture| {
                    join_of(fixture).process_invocation_digest = "e".repeat(64);
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.process_invocation_digest",
            },
            MutationCase {
                name: "changed owner digest",
                mutate: |fixture| {
                    join_of(fixture).executable_binding_digest = "e".repeat(64);
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.executable_binding_digest",
            },
            MutationCase {
                name: "join bound to a foreign claim epoch",
                mutate: |fixture| {
                    fixture.claim.authority_epoch = test_epoch(2);
                },
                rebind_claim: true,
                expected_field: "native_worker_claim.executable_binding.epoch_binding",
            },
        ]
    }

    /// Mutations to the owner-side expectation or observation; the presented
    /// claim is untouched, so no digest recompute applies.
    fn authority_mutation_cases() -> Vec<MutationCase> {
        vec![
            MutationCase {
                name: "stale epoch while owner advanced",
                mutate: |fixture| {
                    let advanced = test_epoch(2);
                    fixture.expected.current.authority_epoch = advanced.clone();
                    fixture.expected.current.state_fence =
                        StateFence::new(advanced, ResourceGeneration::genesis());
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding.authority_epoch",
            },
            MutationCase {
                name: "changed fence revisions",
                mutate: |fixture| {
                    fixture.expected.current.state_fence = StateFence {
                        authority_epoch: test_epoch(1),
                        resource_generation: ResourceGeneration::genesis(),
                        task_revision: Some(TaskRevision::new(9).expect("nonzero task revision")),
                        policy_revision: None,
                        integration_revision: None,
                    };
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding.state_fence",
            },
            MutationCase {
                name: "stale generation while owner advanced",
                mutate: |fixture| {
                    let advanced = ResourceGeneration::new(2).expect("nonzero generation");
                    fixture.expected.current.generation = advanced;
                    fixture.expected.current.state_fence = StateFence::new(test_epoch(1), advanced);
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding.generation",
            },
            MutationCase {
                name: "revoked authority",
                mutate: |fixture| {
                    fixture.expected.revoked = true;
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding_revoked",
            },
            MutationCase {
                name: "expired binding window",
                mutate: |fixture| {
                    fixture.now_ms = BINDING_EXPIRES_MS;
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding.expired",
            },
            MutationCase {
                name: "missing observation time",
                mutate: |fixture| {
                    fixture.now_ms = 0;
                },
                rebind_claim: false,
                expected_field: "native_worker_claim.executable_binding.observation_time",
            },
        ]
    }

    #[test]
    fn old_wire_v1_parses_but_never_promotes() {
        let fixture = valid_fixture();
        // A v1 payload carries no join key and must still parse: old-wire
        // rejection happens at the executable gate, not in the parser.
        let mut value = serde_json::to_value(&fixture.claim).expect("v2 encodes");
        let object = value.as_object_mut().expect("claim is an object");
        object.remove("executable_binding");
        object.insert(
            "wire_version".to_owned(),
            serde_json::json!(NATIVE_WORKER_CLAIM_WIRE_VERSION_V1),
        );
        let v1: NativeWorkerClaimRequest = serde_json::from_value(value).expect("v1 still parses");
        assert_eq!(v1.wire_version, NATIVE_WORKER_CLAIM_WIRE_VERSION_V1);
        assert!(v1.executable_binding.is_none());
        let error = v1
            .require_executable_binding(&fixture.expected, fixture.now_ms)
            .expect_err("v1 must fail closed");
        assert!(
            format!("{error:?}").contains("u1_old_wire_without_executable_binding"),
            "explicit old-wire disposition, got {error:?}"
        );
        // A v1 envelope must not smuggle a join past shape validation either.
        let mut smuggled = fixture.claim;
        smuggled.wire_version = NATIVE_WORKER_CLAIM_WIRE_VERSION_V1;
        let error = smuggled.validate().expect_err("v1 cannot carry a join");
        assert!(
            format!("{error:?}").contains("native_worker_claim.executable_binding"),
            "v1 join smuggling refused, got {error:?}"
        );
    }

    #[test]
    fn unknown_wire_stays_rejected() {
        let mut fixture = valid_fixture();
        fixture.claim.wire_version = 9;
        let error = fixture
            .claim
            .validate()
            .expect_err("unknown wire stays rejected");
        assert!(
            format!("{error:?}").contains("native_worker_claim.wire"),
            "preserved unknown-wire arm, got {error:?}"
        );
        let error = fixture
            .claim
            .require_executable_binding(&fixture.expected, fixture.now_ms)
            .expect_err("unknown wire carries no authority");
        assert!(
            format!("{error:?}").contains("native_worker_claim.wire"),
            "gate repeats the wire rejection, got {error:?}"
        );
    }

    #[test]
    fn v2_without_join_is_missing_not_silent() {
        let mut fixture = valid_fixture();
        fixture.claim.executable_binding = None;
        let error = fixture
            .claim
            .validate()
            .expect_err("v2 without join is incomplete");
        assert!(
            format!("{error:?}").contains("native_worker_claim.executable_binding"),
            "explicit missing-join disposition, got {error:?}"
        );
        let error = fixture
            .claim
            .require_executable_binding(&fixture.expected, fixture.now_ms)
            .expect_err("gate refuses the missing join");
        assert!(
            format!("{error:?}").contains("native_worker_claim.executable_binding"),
            "gate repeats the missing-join refusal, got {error:?}"
        );
    }
}
