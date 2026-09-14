//! Governor-owned native-worker executable binding projection (T9-01, M1).
//!
//! M1 (`T9.md` 3.2, accepted by #22): the Governor publishes one versioned
//! record, [`NativeWorkerExecutableBinding`] v1, through the existing canonical
//! admission path (`PreparedTransition` / `KernelTransitionPort`) when the
//! attempt is registered. The field denominator below is `T9.md` 3.2:
//! installation/principal/session; claim and registration; admitted
//! task/attempt/operation; worker and provider-process identities where
//! distinct; full canonical route; adapter/factory/artifact/configuration/
//! protocol/facet revisions; supporting introductions/grants and effective
//! ceilings; credential/resource references without values; replay stream;
//! nonce relationship; process invocation digest; generation/epoch/fence;
//! deadlines and current invalidation evidence.
//!
//! Governor hard boundary (`crates/governor/AGENTS.md`): this module composes a
//! pure projection only. It never opens a store, constructs a provider
//! adapter, executes a process, or materializes credential values. Refs-only
//! rule: `credential_refs` and `resource_refs` carry references, never secret
//! values. The Kernel stores the digest (T9-02, separate lane). A
//! route/adapter/config/facet/grant/epoch change makes the binding stale; this
//! module performs no local repair.
//!
//! Refinements decided from the docs (underspecification per `T9.md` 4, not a
//! contradiction):
//! - `worker_generation` and `process_generation` require nonzero, matching the
//!   Kernel claim contour (`native_worker_claim.rs`), where zero is reserved
//!   for absent.
//! - `attempt` is zero-based (coordination starts at 0), so 0 is admitted.
//! - `launch_nonce` requires 16..=256 characters: at least 128-bit-presented
//!   entropy without constraining the M1 supplier (hello nonce / stage-nonce
//!   derivation per `I10-08-02`).
//! - Text fields are bounded to 1024 bytes, matching the Kernel
//!   `validate_text` contour; reference vectors are bounded to 64 entries with
//!   duplicate rejection (same fail-closed shape as recovery receipt/job sets).
//! - `deadline_unix_ms` and `expires_at_unix_ms` are both nonzero with strict
//!   `deadline < expires`; equality is not a usable execution window.
//! - `authority_epoch` must equal `state_fence.authority_epoch` and
//!   `generation` must equal `state_fence.resource_generation`; the fence is
//!   the binding authority, not a parallel epoch/generation claim.

use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_store_api::EffectClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable wire identity for the Governor-owned executable binding.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID: &str =
    "eliot.governor.native-worker-executable-binding";
/// Current wire revision of the Governor-owned executable binding.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION: u16 = 1;

/// Maximum bounded text length, matching the Kernel claim `validate_text`.
const MAX_TEXT_LEN: usize = 1024;
/// Maximum references carried in one reference vector.
const MAX_REFS: usize = 64;
/// Minimum presented launch-nonce length (see module docs).
const MIN_NONCE_LEN: usize = 16;
/// Maximum presented launch-nonce length.
const MAX_NONCE_LEN: usize = 256;

fn validate_text(value: &str, field: &'static str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must be non-blank"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    if value.len() > MAX_TEXT_LEN {
        return Err(format!("{field} exceeds bounded length"));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), String> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_ref_list(values: &[String], field: &'static str) -> Result<(), String> {
    if values.len() > MAX_REFS {
        return Err(format!("{field} exceeds bounded reference count"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate reference"));
        }
    }
    Ok(())
}

/// One versioned Governor-owned executable binding projection.
///
/// Built only by
/// [`GovernorComposition::publish_native_worker_binding`](crate::GovernorComposition::publish_native_worker_binding)
/// from admitted owner records at the retained fence. The caller commits a
/// sibling `PreparedTransition` through the existing `commit_canonical` path
/// and correlates by `operation_id` / `canonical_request_hash` / `state_fence`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerExecutableBinding {
    /// Distinct claim operation identity.
    pub claim_id: String,
    /// Registration the attempt was registered under.
    pub registration_id: String,
    /// Admitted task identity.
    pub task_id: String,
    /// Admitted work-unit identity.
    pub work_unit_id: String,
    /// Admitted work-scope identity.
    pub work_scope_id: String,
    /// Zero-based attempt counter.
    pub attempt: u32,
    /// Active work lease identity.
    pub lease_id: String,
    /// Exact external-effect operation identity.
    pub operation_id: String,
    /// Canonical request hash of the admitted operation.
    pub canonical_request_hash: String,
    /// Presented installation identity (validated, never a value).
    pub installation_id: String,
    /// Presented principal reference (validated, never a value).
    pub principal_id: String,
    /// Presented session identity.
    pub session_id: String,
    /// Claiming worker generation (nonzero).
    pub worker_generation: u64,
    /// Presented provider-process tree identity.
    pub process_tree_id: String,
    /// Presented process generation (nonzero).
    pub process_generation: u64,
    /// Presented process fence label.
    pub process_fence: String,
    /// Full canonical route label from the session owner.
    pub route_ref: String,
    /// Adapter/factory identity.
    pub adapter_id: String,
    /// Adapter revision (nonzero).
    pub adapter_revision: u64,
    /// Lowercase SHA-256 of the admitted worker artifact bytes.
    pub artifact_digest: String,
    /// Lowercase SHA-256 of the admitted worker configuration bytes.
    pub config_digest: String,
    /// Lowercase SHA-256 of the admitted protocol bytes.
    pub protocol_digest: String,
    /// Command reference.
    pub command_ref: String,
    /// Facet manifest reference.
    pub facet_manifest_ref: String,
    /// Supporting introduction references (refs only).
    pub introduction_refs: Vec<String>,
    /// Supporting grant references (refs only).
    pub supporting_grant_refs: Vec<String>,
    /// Grant-graph revision the refs were compiled against (nonzero).
    pub grant_graph_revision: u64,
    /// Effective capability ceiling.
    pub effective_ceiling: EffectClass,
    /// Credential references (refs only, never values).
    pub credential_refs: Vec<String>,
    /// Resource references (refs only, never values).
    pub resource_refs: Vec<String>,
    /// Presented replay stream identity.
    pub replay_stream_id: String,
    /// Presented launch nonce (16..=256 chars).
    pub launch_nonce: String,
    /// Lowercase SHA-256 of the exact process invocation.
    pub process_invocation_digest: String,
    /// Exact fence this binding was compiled against.
    pub state_fence: StateFence,
    /// Authority epoch, must equal `state_fence.authority_epoch`.
    pub authority_epoch: EpochId,
    /// Resource generation, must equal `state_fence.resource_generation`.
    pub generation: ResourceGeneration,
    /// Execution deadline in Unix milliseconds (nonzero, before expiry).
    pub deadline_unix_ms: u64,
    /// Binding expiry in Unix milliseconds (nonzero, after deadline).
    pub expires_at_unix_ms: u64,
    /// Current canonical plan identity.
    pub plan_id: String,
    /// Current canonical plan revision.
    pub plan_revision: String,
    /// Admitted task revision (nonzero, matches task owner).
    pub task_revision: u64,
    /// Lowercase SHA-256 of the protected config snapshot.
    pub config_snapshot_digest: String,
    /// Admission revision reference.
    pub admission_revision_ref: String,
    /// Wire identity, must equal [`NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID`].
    pub wire_id: String,
    /// Wire revision, must equal [`NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION`].
    pub wire_version: u16,
    /// Canonical digest over every field except itself.
    pub binding_digest: String,
}

impl NativeWorkerExecutableBinding {
    /// Validates the closed binding shape and recomputes the digest.
    pub fn validate(&self) -> Result<(), String> {
        if self.wire_id != NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID {
            return Err(
                "wire_id must be eliot.governor.native-worker-executable-binding".to_owned(),
            );
        }
        if self.wire_version != NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION {
            return Err("wire_version must be 1".to_owned());
        }
        for (value, field) in [
            (&self.claim_id, "claim_id"),
            (&self.registration_id, "registration_id"),
            (&self.task_id, "task_id"),
            (&self.work_unit_id, "work_unit_id"),
            (&self.work_scope_id, "work_scope_id"),
            (&self.lease_id, "lease_id"),
            (&self.operation_id, "operation_id"),
            (&self.installation_id, "installation_id"),
            (&self.principal_id, "principal_id"),
            (&self.session_id, "session_id"),
            (&self.process_tree_id, "process_tree_id"),
            (&self.process_fence, "process_fence"),
            (&self.route_ref, "route_ref"),
            (&self.adapter_id, "adapter_id"),
            (&self.command_ref, "command_ref"),
            (&self.facet_manifest_ref, "facet_manifest_ref"),
            (&self.replay_stream_id, "replay_stream_id"),
            (&self.plan_id, "plan_id"),
            (&self.plan_revision, "plan_revision"),
            (&self.admission_revision_ref, "admission_revision_ref"),
        ] {
            validate_text(value, field)?;
        }
        for (value, field) in [
            (&self.canonical_request_hash, "canonical_request_hash"),
            (&self.artifact_digest, "artifact_digest"),
            (&self.config_digest, "config_digest"),
            (&self.protocol_digest, "protocol_digest"),
            (&self.process_invocation_digest, "process_invocation_digest"),
            (&self.config_snapshot_digest, "config_snapshot_digest"),
            (&self.binding_digest, "binding_digest"),
        ] {
            validate_digest(value, field)?;
        }
        validate_text(&self.launch_nonce, "launch_nonce")?;
        if self.launch_nonce.len() < MIN_NONCE_LEN || self.launch_nonce.len() > MAX_NONCE_LEN {
            return Err("launch_nonce must be 16..=256 characters".to_owned());
        }
        validate_ref_list(&self.introduction_refs, "introduction_refs")?;
        validate_ref_list(&self.supporting_grant_refs, "supporting_grant_refs")?;
        validate_ref_list(&self.credential_refs, "credential_refs")?;
        validate_ref_list(&self.resource_refs, "resource_refs")?;
        for (value, field) in [
            (self.worker_generation, "worker_generation"),
            (self.process_generation, "process_generation"),
            (self.adapter_revision, "adapter_revision"),
            (self.grant_graph_revision, "grant_graph_revision"),
            (self.task_revision, "task_revision"),
        ] {
            if value == 0 {
                return Err(format!("{field} must be nonzero"));
            }
        }
        self.state_fence
            .validate()
            .map_err(|error| format!("state_fence invalid: {error}"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err("authority_epoch must equal state_fence.authority_epoch".to_owned());
        }
        if self.generation != self.state_fence.resource_generation {
            return Err("generation must equal state_fence.resource_generation".to_owned());
        }
        if self.deadline_unix_ms == 0 || self.expires_at_unix_ms == 0 {
            return Err("deadline_unix_ms and expires_at_unix_ms must be nonzero".to_owned());
        }
        if self.deadline_unix_ms >= self.expires_at_unix_ms {
            return Err("deadline_unix_ms must be strictly before expires_at_unix_ms".to_owned());
        }
        let recomputed = self.compute_digest()?;
        if recomputed != self.binding_digest {
            return Err("binding_digest does not match canonical digest".to_owned());
        }
        Ok(())
    }

    /// Returns canonical JSON bytes over every field except `binding_digest`.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| format!("cannot encode binding: {error}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "binding must serialize as an object".to_owned())?;
        object.remove("binding_digest");
        canonical_json_bytes(&value)
            .map_err(|error| format!("cannot canonicalize binding: {error}"))
    }

    /// Computes the lowercase SHA-256 digest over [`Self::unsigned_bytes`].
    pub fn compute_digest(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.unsigned_bytes()?))
    }
}
