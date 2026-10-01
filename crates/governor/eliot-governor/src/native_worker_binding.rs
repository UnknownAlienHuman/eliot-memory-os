//! Governor-owned native-worker executable binding projection (T9-01, M1).
//!
//! M1 (`T9.md` 3.2, accepted by #22): the Governor publishes one versioned
//! record, [`NativeWorkerExecutableBinding`] v3, through the existing canonical
//! admission path (`PreparedTransition` / `KernelTransitionPort`) when the
//! attempt is registered. The field denominator below is `T9.md` 3.2:
//! installation/principal/session; claim and registration; admitted
//! task/attempt/operation; worker and provider-process identities where
//! distinct; full canonical route; adapter/factory/artifact/configuration/
//! protocol/facet revisions; supporting introductions/grants and effective
//! ceilings; credential/resource references without values; replay stream;
//! nonce relationship; process invocation digest; generation/epoch/fence;
//! deadlines and current invalidation evidence; the validated generated
//! capability-cell registry digest; Kernel execution manifest and
//! process/Job Object lineage; and resource-limit, cancellation, checkpoint,
//! drain and restart policy bindings. The admitted Module Catalog revision,
//! `FunctionalCapabilityCell` identity and lifecycle joins are explicit
//! required owner inputs; none is inferred from grant refs or package names.
//!
//! Governor hard boundary (`crates/governor/AGENTS.md`): this module composes a
//! pure projection only. It never opens a store, constructs a provider
//! adapter, executes a process, or materializes credential values. Refs-only
//! rule: `credential_refs` and `resource_refs` carry references, never secret
//! values. The Kernel stores the digest (T9-02, separate lane). A
//! route/adapter/config/facet/grant/epoch change makes the binding stale; this
//! module performs no local repair.
//!
//! The facet identity is taken from ELIOT's shared native-worker resource
//! facet contract. A caller may present the expected identity for correlation,
//! but an opaque, stale, or locally invented ref is rejected.
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

use eliot_contracts::{
    CapabilityCellId, EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_ors::{NativeWorkerClaimRecord, NativeWorkerClaimState};
use eliot_store_api::EffectClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable wire identity for the Governor-owned executable binding.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_ID: &str =
    "eliot.governor.native-worker-executable-binding";
/// Current wire revision of the Governor-owned executable binding.
pub const NATIVE_WORKER_EXECUTABLE_BINDING_WIRE_VERSION: u16 = 3;

/// Why an authenticated native-worker publication no longer admits reuse.
///
/// These are owner observations, not caller labels. In particular,
/// `GovernorOwnerRevisionChanged` means a current Governor owner was read and
/// disagreed with the revision retained in the executable binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWorkerBindingRevocationReason {
    /// ORS has durably closed the exact claim as terminal.
    TerminalClaim,
    /// The stored claim tuple or executable-binding digest differs from the
    /// owner-persisted binding supplied by the authenticated Kernel read.
    ClaimBindingMismatch,
    /// The owner-persisted binding is malformed or its digest is invalid.
    InvalidOwnerBinding,
    /// The binding's execution deadline or expiry has passed.
    BindingExpired,
    /// The retained Governor state fence changed.
    StateFenceChanged,
    /// The protected configuration snapshot changed.
    ConfigSnapshotChanged,
    /// The canonical plan identity or revision changed.
    CanonicalPlanChanged,
    /// The task revision or state fence changed.
    TaskRevisionChanged,
    /// The session route, authority epoch, or state fence changed.
    SessionRouteChanged,
    /// The current WorkScope identity no longer matches the binding.
    WorkScopeChanged,
    /// The live Module Catalog revision changed.
    ModuleCatalogChanged,
    /// The grant graph revision changed after this binding was issued.
    GrantGraphChanged,
    /// A supporting grant is no longer admitted in the current graph.
    SupportingGrantRevoked,
}

/// Why an authenticated read cannot establish a current native-worker
/// binding. These outcomes preserve the original claim identity for
/// reconciliation and never authorize a retry under a new identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWorkerBindingUnknownReason {
    /// ORS reports an unknown or reconciling durable outcome.
    ClaimOutcomeUnknown,
    /// A non-pending claim has no owner-persisted executable binding.
    OwnerBindingMissing,
    /// Governor is not ready to make a currentness observation.
    GovernorNotReady,
    /// A current owner read required to establish binding currentness failed.
    GovernorOwnerReadUnavailable,
    /// The binding relies on supporting grants but the restored owner has no
    /// current revocation-history source revision.
    RevocationHistoryUnavailable,
}

/// Non-effecting result of joining one authenticated ORS claim readback with
/// the owner-persisted Governor binding and current Governor owner state.
///
/// The record is retained in every result so a caller cannot collapse a
/// known pending or uncertain outcome into a new claim. A Governor-current
/// result is still not an admitted provider capability: the caller must join
/// the independent provider route/account revisions and Kernel process
/// lifecycle owners before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeWorkerBindingObservation {
    /// The exact claim is still REQUESTED; admission has not completed.
    Pending {
        /// Authenticated ORS claim row read by Kernel.
        claim: NativeWorkerClaimRecord,
        /// Binding, if publication has committed while the claim remains
        /// REQUESTED. It remains non-effecting in this state.
        binding: Option<NativeWorkerExecutableBinding>,
        /// Kernel owner time at the readback operation.
        observed_at_unix_ms: u64,
    },
    /// The exact claim or binding is known to be closed or stale.
    Revoked {
        /// Authenticated ORS claim row read by Kernel.
        claim: NativeWorkerClaimRecord,
        /// Full owner-persisted binding, when the Kernel read returned one.
        binding: Option<NativeWorkerExecutableBinding>,
        /// Current owner evidence that closed reuse.
        reason: NativeWorkerBindingRevocationReason,
        /// Kernel owner time at the readback operation.
        observed_at_unix_ms: u64,
    },
    /// The exact claim remains under reconciliation because its outcome or a
    /// required owner read is unknown.
    UnknownOutcome {
        /// Authenticated ORS claim row read by Kernel.
        claim: NativeWorkerClaimRecord,
        /// Full owner-persisted binding, when the Kernel read returned one.
        binding: Option<NativeWorkerExecutableBinding>,
        /// Why currentness could not be established.
        reason: NativeWorkerBindingUnknownReason,
        /// Kernel owner time at the readback operation.
        observed_at_unix_ms: u64,
    },
    /// The exact owner-persisted binding is current under Governor owners,
    /// but provider route/account revisions remain a separate required gate.
    GovernorCurrentButProviderRevisionsUnavailable {
        /// Authenticated ORS claim row read by Kernel.
        claim: NativeWorkerClaimRecord,
        /// Full owner-persisted binding read from Kernel/ORS.
        binding: NativeWorkerExecutableBinding,
        /// Kernel owner time at the readback operation.
        observed_at_unix_ms: u64,
    },
}

/// Closed classification of an ORS claim state at the native-worker use
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWorkerBindingClaimDisposition {
    /// Admission has not occurred yet.
    Requested,
    /// The claim is terminal and permanently closed.
    Terminal,
    /// The outcome is uncertain and must remain under reconciliation.
    UnknownOutcome,
    /// Governor currentness is required before any provider use.
    GovernorCurrentnessRequired,
}

impl NativeWorkerBindingObservation {
    /// Classifies a typed ORS state; no unknown string can be mapped to an
    /// effectable state.
    pub fn classify_claim_state(
        state: NativeWorkerClaimState,
    ) -> NativeWorkerBindingClaimDisposition {
        use NativeWorkerClaimState as State;

        match state {
            State::Requested => NativeWorkerBindingClaimDisposition::Requested,
            State::Terminal => NativeWorkerBindingClaimDisposition::Terminal,
            State::Unknown | State::Reconciling => {
                NativeWorkerBindingClaimDisposition::UnknownOutcome
            }
            State::Admitted | State::Ready | State::Active | State::Cancelling | State::Submitted => {
                NativeWorkerBindingClaimDisposition::GovernorCurrentnessRequired
            }
        }
    }
}

/// Internal classification returned by independent Governor owner checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeWorkerBindingCurrentnessError {
    /// A current owner disproved one or more retained binding commitments.
    Revoked(NativeWorkerBindingRevocationReason),
    /// Owner evidence was unavailable or incomplete at this readback.
    Unknown(NativeWorkerBindingUnknownReason),
}

/// Maximum bounded text length, matching the Kernel claim `validate_text`.
const MAX_TEXT_LEN: usize = 1024;
/// Maximum references carried in one reference vector.
const MAX_REFS: usize = 64;
/// Minimum presented launch-nonce length (see module docs).
const MIN_NONCE_LEN: usize = 16;
/// Maximum presented launch-nonce length.
const MAX_NONCE_LEN: usize = 256;

/// Returns the canonical reference for the ELIOT-owned native-worker facet.
///
/// This derives the ref from the validated source contract rather than
/// duplicating its identity/version/digest spelling in Governor.
pub(crate) fn canonical_native_worker_facet_ref() -> Result<String, String> {
    eliot_contracts::native_worker_resource_facet_v1()
        .and_then(|facet| facet.canonical_ref())
        .map_err(|error| format!("cannot derive canonical native-worker facet ref: {error}"))
}

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

/// Required owner-supplied lifecycle joins for a native worker generation.
///
/// Values are sourced from the validated generated capability-cell registry,
/// admitted Kernel execution manifest and native worker lifecycle owners.
/// Governor validates their bounded wire shape and carries them into the
/// executable binding; it does not derive substitutes or assert their live
/// currentness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeWorkerLifecycleBinding {
    /// Lowercase SHA-256 of the original validated generated #13 cell registry.
    pub capability_cell_registry_digest: String,
    /// Lowercase SHA-256 of the admitted Kernel execution manifest.
    pub kernel_execution_manifest_digest: String,
    /// Exact Job Object lineage reference for this process generation.
    pub job_object_lineage_ref: String,
    /// Lowercase SHA-256 of the admitted resource limits projection.
    pub resource_limits_digest: String,
    /// Owner reference for the admitted cancellation policy.
    pub cancellation_policy_ref: String,
    /// Lowercase SHA-256 of the admitted checkpoint policy.
    pub checkpoint_policy_digest: String,
    /// Owner reference for the admitted drain policy.
    pub drain_policy_ref: String,
    /// Lowercase SHA-256 of the admitted restart policy.
    pub restart_policy_digest: String,
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
    /// Kernel-owned parent Durable-Job identity from the original claim row.
    pub parent_job_id: String,
    /// Original logical decision identity from the claim row.
    pub decision_id: String,
    /// Opaque original attempt identity from the claim row. This is distinct
    /// from the numeric launch counter in `attempt`.
    pub attempt_id: String,
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
    /// Exact Job Object lineage reference for this process generation.
    pub job_object_lineage_ref: String,
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
    /// Functional capability cell admitted for this worker generation.
    pub capability_cell: CapabilityCellId,
    /// Supporting introduction references (refs only).
    pub introduction_refs: Vec<String>,
    /// Supporting grant references (refs only).
    pub supporting_grant_refs: Vec<String>,
    /// Grant-graph revision the refs were compiled against (nonzero).
    pub grant_graph_revision: u64,
    /// Admitted Module Catalog revision this generation was compiled against.
    pub module_catalog_revision: u64,
    /// Lowercase SHA-256 of the original validated generated #13 cell registry.
    pub capability_cell_registry_digest: String,
    /// Lowercase SHA-256 of the admitted Kernel execution manifest.
    pub kernel_execution_manifest_digest: String,
    /// Lowercase SHA-256 of the admitted resource limits projection.
    pub resource_limits_digest: String,
    /// Owner reference for the admitted cancellation policy.
    pub cancellation_policy_ref: String,
    /// Lowercase SHA-256 of the admitted checkpoint policy.
    pub checkpoint_policy_digest: String,
    /// Owner reference for the admitted drain policy.
    pub drain_policy_ref: String,
    /// Lowercase SHA-256 of the admitted restart policy.
    pub restart_policy_digest: String,
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
            return Err("wire_version must be 3".to_owned());
        }
        let canonical_facet_ref = canonical_native_worker_facet_ref()?;
        if self.facet_manifest_ref != canonical_facet_ref {
            return Err(
                "facet_manifest_ref must equal the canonical ELIOT native-worker facet ref"
                    .to_owned(),
            );
        }
        for (value, field) in [
            (&self.claim_id, "claim_id"),
            (&self.parent_job_id, "parent_job_id"),
            (&self.decision_id, "decision_id"),
            (&self.attempt_id, "attempt_id"),
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
            (&self.job_object_lineage_ref, "job_object_lineage_ref"),
            (&self.process_fence, "process_fence"),
            (&self.route_ref, "route_ref"),
            (&self.adapter_id, "adapter_id"),
            (&self.command_ref, "command_ref"),
            (&self.facet_manifest_ref, "facet_manifest_ref"),
            (&self.replay_stream_id, "replay_stream_id"),
            (&self.plan_id, "plan_id"),
            (&self.plan_revision, "plan_revision"),
            (&self.admission_revision_ref, "admission_revision_ref"),
            (&self.cancellation_policy_ref, "cancellation_policy_ref"),
            (&self.drain_policy_ref, "drain_policy_ref"),
        ] {
            validate_text(value, field)?;
        }
        self.validate_digests()?;
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
            (self.module_catalog_revision, "module_catalog_revision"),
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

    fn validate_digests(&self) -> Result<(), String> {
        for (value, field) in [
            (&self.canonical_request_hash, "canonical_request_hash"),
            (&self.artifact_digest, "artifact_digest"),
            (&self.config_digest, "config_digest"),
            (&self.protocol_digest, "protocol_digest"),
            (
                &self.capability_cell_registry_digest,
                "capability_cell_registry_digest",
            ),
            (
                &self.kernel_execution_manifest_digest,
                "kernel_execution_manifest_digest",
            ),
            (&self.resource_limits_digest, "resource_limits_digest"),
            (&self.checkpoint_policy_digest, "checkpoint_policy_digest"),
            (&self.restart_policy_digest, "restart_policy_digest"),
            (&self.process_invocation_digest, "process_invocation_digest"),
            (&self.config_snapshot_digest, "config_snapshot_digest"),
            (&self.binding_digest, "binding_digest"),
        ] {
            validate_digest(value, field)?;
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

/// Computes the R1 production `process_invocation_digest` over the exact
/// process invocation value.
///
/// Pure projection helper for the T9-01 production caller
/// (`GovernorComposition::publish_native_worker_binding_for_invocation`,
/// which forwards into `publish_native_worker_binding`): canonicalizes the
/// exact invocation JSON with the same `canonical_json_bytes` + `sha256_hex`
/// the wire uses, so the published binding carries the real invocation
/// digest, never a placeholder. This changes no signing, no authority, and
/// no digest scheme; it only gives production callers the one correct way to
/// derive the field.
pub fn process_invocation_digest_for(invocation: &serde_json::Value) -> Result<String, String> {
    let bytes = canonical_json_bytes(invocation)
        .map_err(|error| format!("cannot canonicalize process invocation: {error}"))?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests use expects for fixed-valid binding fixtures"
    )]

    use super::*;

    #[test]
    fn invocation_digest_is_stable_and_lowercase_sha256() {
        let invocation = serde_json::json!({
            "operation": "op-1",
            "argv": ["--check"],
            "fence": {"generation": 1},
        });
        let first = process_invocation_digest_for(&invocation).expect("digest");
        let second = process_invocation_digest_for(&invocation).expect("digest");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "digest must be lowercase SHA-256"
        );
    }

    #[test]
    fn invocation_digest_changes_when_invocation_changes() {
        let base = serde_json::json!({"operation": "op-1", "argv": ["--check"]});
        let changed = serde_json::json!({"operation": "op-1", "argv": ["--other"]});
        let base_digest = process_invocation_digest_for(&base).expect("digest");
        let changed_digest = process_invocation_digest_for(&changed).expect("digest");
        assert_ne!(base_digest, changed_digest);
    }
}
