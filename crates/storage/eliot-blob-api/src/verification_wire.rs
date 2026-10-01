//! Closed Kernel IPC for admitted Instrument verification-stage Blob streams.
//!
//! This protocol has its own profile-stage capability and deliberately does
//! not reuse the TestD process-stream identity. The caller names an admitted
//! profile/stage and the exact process binding; Kernel authenticates the
//! caller, rechecks current admission and owner facts, selects the current
//! fence, and retains every one-use call before forwarding it to Store.

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::{
    DurableStreamLocatorKind, ProcessStreamKind, ProcessStreamSinkBindingRef,
    ProcessStreamSinkWireResponse, ProcessStreamSourceReadbackResponse,
    PROCESS_STREAM_SINK_MAX_BODY_BYTES, PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
};
use crate::{
    BlobProcessStreamStageFinalizeRequest,
    BlobProcessStreamStageAppendReceipt, BlobProcessStreamStageAppendRequest,
    BlobProcessStreamStageSnapshot, BlobProcessStreamStageTerminal,
};

/// Selector for opening one authenticated profile-stage stream capability.
pub const VERIFICATION_STAGE_OPEN_WIRE_ID: &str = "eliot.kernel.verification-stage-open";
/// Selector for one retained profile-stage Blob operation.
pub const VERIFICATION_STAGE_CALL_WIRE_ID: &str = "eliot.kernel.verification-stage-call";
/// Selector for read-only reconciliation of one consumed operation token.
pub const VERIFICATION_STAGE_RECONCILE_WIRE_ID: &str =
    "eliot.kernel.verification-stage-reconcile";
/// Selector for one Kernel-owned profile-stage tool-version observation.
pub const VERIFICATION_STAGE_TOOL_PROBE_WIRE_ID: &str =
    "eliot.kernel.verification-stage-tool-probe";
/// Selector for one Kernel-owned profile-stage process launch.
pub const VERIFICATION_STAGE_LAUNCH_WIRE_ID: &str = "eliot.kernel.verification-stage-launch";
/// Selector for one retained profile-stage process lifecycle operation.
pub const VERIFICATION_STAGE_LIFECYCLE_WIRE_ID: &str =
    "eliot.kernel.verification-stage-lifecycle";
/// Selector for one chunk of a retained profile-stage process source.
pub const VERIFICATION_STAGE_READBACK_WIRE_ID: &str =
    "eliot.kernel.verification-stage-readback";
/// Selector for one Store-owned ProfileStage source operation over Blob EBP.
pub const VERIFICATION_STAGE_SOURCE_WIRE_ID: &str = "eliot.blob.verification-stage-source";
/// Current revision for the closed profile-stage Blob IPC.
pub const VERIFICATION_STAGE_WIRE_REVISION: u16 = 1;
/// Maximum encoded profile-stage JSON IPC frame.
pub const VERIFICATION_STAGE_MAX_FRAME_BYTES: usize = 3 * 1024 * 1024;
/// Maximum process wall time admitted for one profile stage.
pub const VERIFICATION_STAGE_WALL_TIMEOUT_MS: u64 = 3_600_000;
/// Maximum stdout bytes admitted for one profile stage.
pub const VERIFICATION_STAGE_STDOUT_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum stderr bytes admitted for one profile stage.
pub const VERIFICATION_STAGE_STDERR_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum descendants admitted for one profile stage.
pub const VERIFICATION_STAGE_MAX_DESCENDANTS: u32 = 256;

/// Exact profile, stage, tool, argv, environment and source-root identity
/// admitted for one profile-stage launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageBinding {
    /// Closed profile alias selected by the shared resolver.
    pub profile_id: String,
    /// Admitted profile revision.
    pub profile_revision: u64,
    /// Digest of the full admitted profile.
    pub profile_sha256: String,
    /// Digest of the admitted stage DAG.
    pub dag_sha256: String,
    /// Exact stage identity inside the admitted DAG.
    pub stage_id: String,
    /// Digest of the exact admitted stage record.
    pub stage_sha256: String,
    /// Digest of the executable that the stage is authorized to run.
    pub tool_sha256: String,
    /// Digest of the exact argv supplied to the process launch.
    pub argv_sha256: String,
    /// Digest of the exact non-secret environment projection.
    pub environment_sha256: String,
    /// Digest of the exact admitted source-root identity.
    pub source_root_identity_sha256: String,
}

impl VerificationStageBinding {
    /// Validates closed identities and their versioned profile/stage digests.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("profile_id", &self.profile_id)?;
        validate_text("stage_id", &self.stage_id)?;
        if self.profile_id.len() > 128 || self.stage_id.len() > 128 {
            return Err(VerificationStageWireError::InvalidField("stage_identity"));
        }
        if self.profile_revision == 0 {
            return Err(VerificationStageWireError::InvalidField("profile_revision"));
        }
        for (field, value) in [
            ("profile_sha256", self.profile_sha256.as_str()),
            ("dag_sha256", self.dag_sha256.as_str()),
            ("stage_sha256", self.stage_sha256.as_str()),
            ("tool_sha256", self.tool_sha256.as_str()),
            ("argv_sha256", self.argv_sha256.as_str()),
            ("environment_sha256", self.environment_sha256.as_str()),
            (
                "source_root_identity_sha256",
                self.source_root_identity_sha256.as_str(),
            ),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }

    /// Deterministic digest over the complete admitted stage binding.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| VerificationStageWireError::InvalidField("stage_binding"))
    }
}

/// Shared digest helper for the exact canonical absolute source-root string.
///
/// Callers canonicalize and independently admit the path before using this
/// helper. The digest domain is the UTF-8 bytes of that exact string, matching
/// the profile-runner's previously admitted source-root identity convention.
pub fn source_root_identity_sha256(
    canonical_absolute_source_root: &str,
) -> Result<String, VerificationStageWireError> {
    validate_text("source_root", canonical_absolute_source_root)?;
    Ok(sha256_hex(canonical_absolute_source_root.as_bytes()))
}

/// Bounded inert command projection supplied by a resolver launch request.
///
/// Kernel independently resolves and hashes `executable_path`, rebuilds the
/// admitted profile/stage command, checks the three roots against its current
/// owner scope, and enforces these exact fixed resource ceilings. None of the
/// projection's strings grant process authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageLaunchProjection {
    /// Canonical absolute source root selected for this run.
    pub source_root: String,
    /// Canonical absolute build output root selected for this run.
    pub target_root: String,
    /// Canonical absolute tool cache root selected for this run.
    pub cache_root: String,
    /// Canonical absolute selected-toolchain executable path.
    pub executable_path: String,
    /// Exact admitted argument vector.
    pub argv: Vec<String>,
    /// Canonical absolute working directory.
    pub working_directory: String,
    /// Exact non-secret, non-inherited process environment projection.
    pub environment: BTreeMap<String, String>,
    /// Fixed Kernel profile-stage resource ceiling.
    pub wall_timeout_ms: u64,
    /// Fixed stdout byte ceiling.
    pub stdout_bytes: u64,
    /// Fixed stderr byte ceiling.
    pub stderr_bytes: u64,
    /// Fixed process-descendant ceiling.
    pub max_descendants: u32,
}

impl VerificationStageLaunchProjection {
    /// Validates the bounded projection and exact shared resource limits.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        for (field, value) in [
            ("source_root", self.source_root.as_str()),
            ("target_root", self.target_root.as_str()),
            ("cache_root", self.cache_root.as_str()),
            ("executable_path", self.executable_path.as_str()),
            ("working_directory", self.working_directory.as_str()),
        ] {
            validate_text(field, value)?;
            if value.len() > 4_096 {
                return Err(VerificationStageWireError::InvalidField(field));
            }
        }
        if self.argv.is_empty()
            || self.argv.len() > 64
            || self.argv.iter().any(|argument| {
                argument.is_empty()
                    || argument.len() > 32 * 1024
                    || argument.chars().any(char::is_control)
            })
            || self.environment.len() > 32
            || self.environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > 256
                    || value.len() > 8 * 1024
                    || name.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
                    || name.to_ascii_uppercase().contains("SECRET")
                    || name.to_ascii_uppercase().contains("TOKEN")
                    || name.to_ascii_uppercase().contains("PASSWORD")
            })
        {
            return Err(VerificationStageWireError::InvalidField("launch_projection"));
        }
        if self.wall_timeout_ms != VERIFICATION_STAGE_WALL_TIMEOUT_MS
            || self.stdout_bytes != VERIFICATION_STAGE_STDOUT_BYTES
            || self.stderr_bytes != VERIFICATION_STAGE_STDERR_BYTES
            || self.max_descendants != VERIFICATION_STAGE_MAX_DESCENDANTS
        {
            return Err(VerificationStageWireError::InvalidField("resource_limits"));
        }
        Ok(())
    }
}

/// Closed request to have Kernel run the exact admitted tool's version probe.
///
/// The probe is a separately retained process operation. It is not itself a
/// profile stage, and a resolver cannot assert its result: Kernel launches
/// `--version`, observes the terminal evidence, and returns the extracted
/// nonblank version string with the owner-issued process evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageToolProbeRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Closed profile/stage/tool identity whose executable is being observed.
    pub binding: VerificationStageBinding,
    /// Exact selected-toolchain path, scope roots and isolated environment.
    pub projection: VerificationStageToolProbeProjection,
    /// Caller idempotency key; Kernel binds it to the authenticated session.
    pub probe_id: String,
    /// Unix-millisecond probe deadline.
    pub deadline_ms: u64,
}

/// Bounded tool identity projection for the Kernel-owned version probe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageToolProbeProjection {
    /// Canonical absolute source root selected for this run.
    pub source_root: String,
    /// Canonical absolute build output root selected for this run.
    pub target_root: String,
    /// Canonical absolute tool cache root selected for this run.
    pub cache_root: String,
    /// Canonical absolute selected-toolchain executable path.
    pub executable_path: String,
    /// Canonical absolute working directory for the probe.
    pub working_directory: String,
    /// Exact non-secret, non-inherited process environment projection.
    pub environment: BTreeMap<String, String>,
}

impl VerificationStageToolProbeProjection {
    /// Validates bounded text and non-secret environment values.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        for (field, value) in [
            ("source_root", self.source_root.as_str()),
            ("target_root", self.target_root.as_str()),
            ("cache_root", self.cache_root.as_str()),
            ("executable_path", self.executable_path.as_str()),
            ("working_directory", self.working_directory.as_str()),
        ] {
            validate_text(field, value)?;
            if value.len() > 4_096 {
                return Err(VerificationStageWireError::InvalidField(field));
            }
        }
        if self.environment.len() > 32
            || self.environment.iter().any(|(name, value)| {
                name.is_empty()
                    || name.len() > 256
                    || value.len() > 8 * 1024
                    || name.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
                    || name.to_ascii_uppercase().contains("SECRET")
                    || name.to_ascii_uppercase().contains("TOKEN")
                    || name.to_ascii_uppercase().contains("PASSWORD")
            })
        {
            return Err(VerificationStageWireError::InvalidField("probe_projection"));
        }
        Ok(())
    }
}

impl VerificationStageToolProbeRequest {
    /// Validates the closed request before authenticated Kernel admission.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_TOOL_PROBE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.binding.validate()?;
        self.projection.validate()?;
        validate_text("probe_id", &self.probe_id)?;
        if self.probe_id.len() > 128 || self.deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("probe_request"));
        }
        if source_root_identity_sha256(&self.projection.source_root)?
            != self.binding.source_root_identity_sha256
        {
            return Err(VerificationStageWireError::InvalidField("source_root_identity_sha256"));
        }
        validate_frame(self)
    }
}

/// Exact terminal result of the separate Kernel-owned version probe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageToolProbeOutcome {
    /// Kernel observed terminal evidence and a nonblank version.
    Observed {
        /// Kernel-retained opaque probe reference.
        probe_ref: String,
        /// Canonical commitment to the exact Kernel probe evidence.
        probe_sha256: String,
        /// Canonical actual ProcessExecutionBinding for the probe process.
        process_binding_json: String,
        /// SHA-256 of the exact binding bytes.
        process_binding_sha256: String,
        /// Actual Kernel operation identity from that process binding.
        process_operation_id: String,
        /// Version text parsed from the exact Kernel-observed terminal stdout.
        tool_version: String,
        /// Canonical original ProcessEvidence JSON from Kernel's process gateway.
        process_evidence_json: String,
        /// SHA-256 of the canonical ProcessEvidence JSON bytes.
        process_evidence_sha256: String,
        /// Kernel observation time for the exact terminal result.
        observed_at_unix_ms: u64,
    },
    /// Probe effect may have started but its terminal outcome is unresolved.
    Unknown {
        /// Kernel-retained opaque probe reference for exact follow-up.
        probe_ref: String,
        /// Exact predicted process binding digest retained before launch.
        process_binding_sha256: String,
        /// Kernel observation time for the unresolved result.
        observed_at_unix_ms: u64,
    },
    /// Kernel refused before creating a version-probe process.
    Unavailable {
        /// Stable refusal category only.
        reason: VerificationStageUnavailableReason,
    },
}

/// Kernel-owned response for one exact tool-version probe request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageToolProbeResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact admitted binding submitted by the resolver.
    pub binding: VerificationStageBinding,
    /// Exact idempotency identity submitted by the resolver.
    pub probe_id: String,
    /// Typed outcome of the actual Kernel probe.
    pub outcome: VerificationStageToolProbeOutcome,
}

/// Read-only Kernel-issued proof identity for one exact version observation.
///
/// The process binding and evidence are separately returned in the probe
/// outcome; this compact canonical projection commits their digests together
/// with the selected stage and observed tool version for later launch grants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageToolProbeIdentity {
    /// Exact admitted profile-stage/tool binding used for the probe.
    pub binding: VerificationStageBinding,
    /// Original caller idempotency identity retained by Kernel.
    pub probe_id: String,
    /// Opaque Kernel-retained probe reference.
    pub probe_ref: String,
    /// Actual Kernel process operation identity.
    pub process_operation_id: String,
    /// Exact canonical probe ProcessExecutionBinding digest.
    pub process_binding_sha256: String,
    /// Observed tool version parsed from original Kernel terminal evidence.
    pub tool_version: String,
    /// Exact original Kernel ProcessEvidence digest.
    pub process_evidence_sha256: String,
    /// Kernel observation time of the completed probe.
    pub observed_at_unix_ms: u64,
}

impl VerificationStageToolProbeIdentity {
    /// Validates all probe identity fields and hashes.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        self.binding.validate()?;
        for (field, value) in [
            ("probe_id", self.probe_id.as_str()),
            ("probe_ref", self.probe_ref.as_str()),
            ("process_operation_id", self.process_operation_id.as_str()),
        ] {
            validate_text(field, value)?;
            if value.len() > 256 {
                return Err(VerificationStageWireError::InvalidField(field));
            }
        }
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_digest("process_evidence_sha256", &self.process_evidence_sha256)?;
        if self.tool_version.trim().is_empty()
            || self.tool_version.len() > 512
            || self.tool_version.chars().any(char::is_control)
            || self.observed_at_unix_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("probe_identity"));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment to this exact completed probe identity.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        self.validate()?;
        canonical_sha256(self)
    }
}

impl VerificationStageToolProbeResponse {
    /// Validates exact request echoes and all returned evidence commitments.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageToolProbeRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_TOOL_PROBE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.binding != request.binding
            || self.probe_id != request.probe_id
        {
            return Err(VerificationStageWireError::InvalidField("probe_response"));
        }
        match &self.outcome {
            VerificationStageToolProbeOutcome::Observed {
                probe_ref,
                probe_sha256,
                process_binding_json,
                process_binding_sha256,
                process_operation_id,
                tool_version,
                process_evidence_json,
                process_evidence_sha256,
                observed_at_unix_ms,
            } => {
                validate_text("probe_ref", probe_ref)?;
                validate_process_binding(process_binding_json, process_binding_sha256)?;
                validate_text("process_operation_id", process_operation_id)?;
                if process_operation_id.len() > 256
                    || process_operation_id_from_binding(process_binding_json)?
                        != *process_operation_id
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "process_operation_id",
                    ));
                }
                validate_digest("probe_sha256", probe_sha256)?;
                validate_canonical_json_digest(
                    "process_evidence",
                    process_evidence_json,
                    process_evidence_sha256,
                    2 * 1024 * 1024,
                )?;
                let identity = VerificationStageToolProbeIdentity {
                    binding: self.binding.clone(),
                    probe_id: self.probe_id.clone(),
                    probe_ref: probe_ref.clone(),
                    process_operation_id: process_operation_id.clone(),
                    process_binding_sha256: process_binding_sha256.clone(),
                    tool_version: tool_version.clone(),
                    process_evidence_sha256: process_evidence_sha256.clone(),
                    observed_at_unix_ms: *observed_at_unix_ms,
                };
                if identity.digest()? != *probe_sha256 {
                    return Err(VerificationStageWireError::InvalidField("probe_sha256"));
                }
                if tool_version.trim().is_empty()
                    || tool_version.len() > 512
                    || *observed_at_unix_ms == 0
                {
                    return Err(VerificationStageWireError::InvalidField("probe_observation"));
                }
            }
            VerificationStageToolProbeOutcome::Unknown {
                probe_ref,
                process_binding_sha256,
                observed_at_unix_ms,
            } => {
                validate_text("probe_ref", probe_ref)?;
                validate_digest("process_binding_sha256", process_binding_sha256)?;
                if *observed_at_unix_ms == 0 {
                    return Err(VerificationStageWireError::InvalidField("probe_observation"));
                }
            }
            VerificationStageToolProbeOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }
}

/// Exact profile-stage launch request; all process authority is derived by Kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageLaunchRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact caller-selected idempotency key, scoped by Kernel to this session.
    pub launch_id: String,
    /// Exact closed profile/stage identity from the shared compiler.
    pub binding: VerificationStageBinding,
    /// Exact untrusted command projection Kernel independently checks.
    pub projection: VerificationStageLaunchProjection,
    /// Retained Kernel tool-probe identity that proves the observed version.
    pub probe_ref: String,
    /// Canonical digest of that exact Kernel tool-probe identity.
    pub probe_sha256: String,
    /// Unix-millisecond launch deadline.
    pub deadline_ms: u64,
}

impl VerificationStageLaunchRequest {
    /// Validates the closed request without treating its projection as authority.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_LAUNCH_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.binding.validate()?;
        self.projection.validate()?;
        validate_text("launch_id", &self.launch_id)?;
        validate_text("probe_ref", &self.probe_ref)?;
        if self.launch_id.len() > 128 || self.deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("launch_request"));
        }
        validate_digest("probe_sha256", &self.probe_sha256)?;
        if source_root_identity_sha256(&self.projection.source_root)?
            != self.binding.source_root_identity_sha256
        {
            return Err(VerificationStageWireError::InvalidField("source_root_identity_sha256"));
        }
        if sha256_hex(&canonical_json_bytes(&self.projection.argv)
            .map_err(|_| VerificationStageWireError::InvalidField("argv"))?)
            != self.binding.argv_sha256
        {
            return Err(VerificationStageWireError::InvalidField("argv_sha256"));
        }
        validate_frame(self)
    }
}

/// Read-only immutable profile-stage grant retained from Kernel admission/ORS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageGrantProjection {
    /// Kernel-issued reservation row identity.
    pub reservation_id: String,
    /// Kernel-issued profile stage job identity (never a TestD job).
    pub profile_job_id: String,
    /// Kernel-issued action lease identity retained for the exact process.
    pub action_lease_ref: String,
    /// Kernel opaque process execution reference.
    pub execution_ref: String,
    /// Exact profile/stage/tool/root binding admitted by Kernel.
    pub binding: VerificationStageBinding,
    /// Exact Kernel operation identity admitted for the process.
    pub process_operation_id: String,
    /// SHA-256 of the exact canonical ProcessExecutionBinding bytes.
    pub process_binding_sha256: String,
    /// Digest of the authenticated ProfileResolver owner/session binding.
    pub owner_session_sha256: String,
    /// Exact Kernel-issued version observation retained before this launch.
    pub tool_probe: VerificationStageToolProbeIdentity,
    /// Canonical commitment to `tool_probe`.
    pub tool_probe_sha256: String,
    /// Canonical current WorkScope projection from its owner read.
    pub scope_binding_json: String,
    /// SHA-256 of the exact scope projection bytes.
    pub scope_binding_sha256: String,
    /// Canonical current policy projection from its owner read.
    pub policy_binding_json: String,
    /// SHA-256 of the exact policy projection bytes.
    pub policy_binding_sha256: String,
    /// Exact current process authority fence retained for the grant.
    pub state_fence: StateFence,
    /// Issue time from the Kernel-owned authority clock.
    pub issued_at_unix_ms: u64,
    /// Expiry time from the Kernel-owned authority clock.
    pub expires_at_unix_ms: u64,
}

impl VerificationStageGrantProjection {
    /// Validates every stable grant binding and canonical owner projection.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        self.binding.validate()?;
        for (field, value) in [
            ("reservation_id", self.reservation_id.as_str()),
            ("profile_job_id", self.profile_job_id.as_str()),
            ("action_lease_ref", self.action_lease_ref.as_str()),
            ("execution_ref", self.execution_ref.as_str()),
            ("process_operation_id", self.process_operation_id.as_str()),
        ] {
            validate_text(field, value)?;
            if value.len() > 256 {
                return Err(VerificationStageWireError::InvalidField(field));
            }
        }
        for (field, digest) in [
            ("process_binding_sha256", self.process_binding_sha256.as_str()),
            ("owner_session_sha256", self.owner_session_sha256.as_str()),
            ("scope_binding_sha256", self.scope_binding_sha256.as_str()),
            ("policy_binding_sha256", self.policy_binding_sha256.as_str()),
            ("tool_probe_sha256", self.tool_probe_sha256.as_str()),
        ] {
            validate_digest(field, digest)?;
        }
        validate_canonical_json_digest(
            "scope_binding",
            &self.scope_binding_json,
            &self.scope_binding_sha256,
            64 * 1024,
        )?;
        self.tool_probe.validate()?;
        if self.tool_probe.binding != self.binding
            || self.tool_probe.digest()? != self.tool_probe_sha256
        {
            return Err(VerificationStageWireError::InvalidField("tool_probe_binding"));
        }
        validate_canonical_json_digest(
            "policy_binding",
            &self.policy_binding_json,
            &self.policy_binding_sha256,
            64 * 1024,
        )?;
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        if self.issued_at_unix_ms == 0 || self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(VerificationStageWireError::InvalidField("grant_lifetime"));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment over the complete immutable grant.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        self.validate()?;
        canonical_sha256(self)
    }
}

/// Typed result of a real Kernel process launch and source pre-admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageLaunchOutcome {
    /// Kernel retained the real process start and both stream source grants.
    Started {
        /// Opaque Kernel operation handle.
        execution_ref: String,
        /// Canonical real ProcessExecutionBinding.
        process_binding_json: String,
        /// SHA-256 of the exact process-binding JSON bytes.
        process_binding_sha256: String,
        /// Canonical original ProcessStartReceipt JSON.
        process_start_receipt_json: String,
        /// SHA-256 of the exact process receipt JSON bytes.
        process_start_receipt_sha256: String,
        /// Kernel-owned retained grant projection.
        grant: Box<VerificationStageGrantProjection>,
        /// Canonical grant projection commitment.
        grant_sha256: String,
        /// Kernel observation time after the start receipt was retained.
        observed_at_unix_ms: u64,
    },
    /// Physical launch may have occurred but its outcome is unresolved.
    Unknown {
        /// Opaque Kernel operation handle for exact reconciliation.
        execution_ref: String,
        /// Exact Kernel-predicted process binding from the retained request.
        process_binding_json: String,
        /// SHA-256 of the exact process-binding JSON bytes.
        process_binding_sha256: String,
        /// Kernel-owned grant projection retained before process effect.
        grant: Box<VerificationStageGrantProjection>,
        /// Canonical grant projection commitment.
        grant_sha256: String,
        /// Kernel observation time for the unknown outcome.
        observed_at_unix_ms: u64,
    },
    /// Kernel refused before the child effect and no execution handle exists.
    Unavailable {
        /// Stable refusal category only.
        reason: VerificationStageUnavailableReason,
    },
}

/// Authenticated Kernel reply to one exact profile-stage launch request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageLaunchResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact idempotency key submitted by the resolver.
    pub launch_id: String,
    /// Exact profile-stage identity submitted by the resolver.
    pub binding: VerificationStageBinding,
    /// Kernel owner outcome retained before response publication.
    pub outcome: VerificationStageLaunchOutcome,
}

impl VerificationStageLaunchResponse {
    /// Validates exact request correlation and all returned owner commitments.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageLaunchRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_LAUNCH_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.launch_id != request.launch_id
            || self.binding != request.binding
        {
            return Err(VerificationStageWireError::InvalidField("launch_response_binding"));
        }
        match &self.outcome {
            VerificationStageLaunchOutcome::Started {
                execution_ref,
                process_binding_json,
                process_binding_sha256,
                process_start_receipt_json,
                process_start_receipt_sha256,
                grant,
                grant_sha256,
                observed_at_unix_ms,
            } => {
                validate_text("execution_ref", execution_ref)?;
                validate_process_binding(process_binding_json, process_binding_sha256)?;
                validate_canonical_json_digest(
                    "process_start_receipt",
                    process_start_receipt_json,
                    process_start_receipt_sha256,
                    64 * 1024,
                )?;
                validate_grant_for_launch(
                    grant,
                    grant_sha256,
                    &self.binding,
                    execution_ref,
                    process_binding_sha256,
                    &request.probe_ref,
                    &request.probe_sha256,
                )?;
                if *observed_at_unix_ms == 0 {
                    return Err(VerificationStageWireError::InvalidField("observed_at_unix_ms"));
                }
            }
            VerificationStageLaunchOutcome::Unknown {
                execution_ref,
                process_binding_json,
                process_binding_sha256,
                grant,
                grant_sha256,
                observed_at_unix_ms,
            } => {
                validate_text("execution_ref", execution_ref)?;
                validate_process_binding(process_binding_json, process_binding_sha256)?;
                validate_grant_for_launch(
                    grant,
                    grant_sha256,
                    &self.binding,
                    execution_ref,
                    process_binding_sha256,
                    &request.probe_ref,
                    &request.probe_sha256,
                )?;
                if *observed_at_unix_ms == 0 {
                    return Err(VerificationStageWireError::InvalidField("observed_at_unix_ms"));
                }
            }
            VerificationStageLaunchOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }
}

fn validate_grant_for_launch(
    grant: &VerificationStageGrantProjection,
    grant_sha256: &str,
    binding: &VerificationStageBinding,
    execution_ref: &str,
    process_binding_sha256: &str,
    probe_ref: &str,
    probe_sha256: &str,
) -> Result<(), VerificationStageWireError> {
    grant.validate()?;
    validate_digest("grant_sha256", grant_sha256)?;
    if &grant.binding != binding
        || grant.execution_ref != execution_ref
        || grant.process_binding_sha256 != process_binding_sha256
        || grant.tool_probe.probe_ref != probe_ref
        || grant.tool_probe_sha256 != probe_sha256
        || grant.digest()? != grant_sha256
    {
        return Err(VerificationStageWireError::InvalidField("grant_binding"));
    }
    Ok(())
}

/// A Kernel-observed process lifecycle operation on one retained execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStageLifecycleAction {
    /// Observe the exact current process view without a physical effect.
    Inspect,
    /// Request cancellation through the retained process authority.
    Cancel,
    /// Reconcile the exact process and its physical evidence.
    Reconcile,
}

/// Exact lifecycle operation request for a retained Kernel stage execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageLifecycleRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Kernel-issued opaque retained execution reference.
    pub execution_ref: String,
    /// Exact original Kernel ProcessExecutionBinding digest.
    pub process_binding_sha256: String,
    /// One admitted lifecycle action.
    pub action: VerificationStageLifecycleAction,
    /// Unix-millisecond operation deadline.
    pub deadline_ms: u64,
}

impl VerificationStageLifecycleRequest {
    /// Validates the bounded exact retained operation selector.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_LIFECYCLE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        validate_text("execution_ref", &self.execution_ref)?;
        if self.execution_ref.len() > 256 || self.deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("lifecycle_request"));
        }
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_frame(self)
    }
}

/// Typed owner result of one lifecycle operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageLifecycleOutcome {
    /// Exact original ProcessExecutionView observed by Kernel.
    Inspected {
        /// Canonical original ProcessExecutionView JSON.
        process_view_json: String,
        /// SHA-256 of the exact JSON bytes.
        process_view_sha256: String,
    },
    /// Exact original CancellationReceipt returned by Kernel's gateway.
    Cancelled {
        /// Canonical original CancellationReceipt JSON.
        cancellation_receipt_json: String,
        /// SHA-256 of the exact JSON bytes.
        cancellation_receipt_sha256: String,
    },
    /// Exact original ProcessEvidence returned by Kernel's gateway.
    Reconciled {
        /// Canonical original ProcessEvidence JSON.
        process_evidence_json: String,
        /// SHA-256 of the exact JSON bytes.
        process_evidence_sha256: String,
    },
    /// Kernel retains the operation but its physical outcome remains unknown.
    Unknown,
    /// Closed pre-effect refusal.
    Unavailable {
        /// Stable refusal category only.
        reason: VerificationStageUnavailableReason,
    },
}

/// Authenticated Kernel response correlated to one exact stage lifecycle request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageLifecycleResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact retained execution reference submitted by the resolver.
    pub execution_ref: String,
    /// Exact process-binding digest submitted by the resolver.
    pub process_binding_sha256: String,
    /// Kernel owner result observed at this exact time.
    pub observed_at_unix_ms: u64,
    /// Typed lifecycle outcome.
    pub outcome: VerificationStageLifecycleOutcome,
}

/// Exact current source-owner evidence returned with every readback chunk.
///
/// These canonical projections are copied from the Store's independent owner
/// reads and committed writes. They are not accepted as authority on a later
/// call; Kernel and Store retain and revalidate their original rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceOwnerProof {
    /// Canonical commitment to the exact Kernel-issued ProfileStage grant.
    pub stage_grant_sha256: String,
    /// Exact source session selector retained in Store's owner row.
    pub source_key: VerificationStageSourceKey,
    /// Original Kernel process binding digest for this source.
    pub process_binding_sha256: String,
    /// Canonical current owner-facts projection.
    pub owner_facts_json: String,
    /// SHA-256 of the exact owner-facts bytes.
    pub owner_facts_sha256: String,
    /// Canonical WorkScope projection independently read by Store.
    pub scope_binding_json: String,
    /// SHA-256 of the exact WorkScope projection bytes.
    pub scope_binding_sha256: String,
    /// Canonical Policy projection independently read by Store.
    pub policy_binding_json: String,
    /// SHA-256 of the exact Policy projection bytes.
    pub policy_binding_sha256: String,
    /// Fresh Ready source-admission row read from canonical Store.
    pub source_admission_json: String,
    /// SHA-256 of the exact Ready source-admission bytes.
    pub source_admission_sha256: String,
    /// Committed Store WriteReceipt for the Ready source-admission CAS.
    pub source_admission_write_receipt_json: String,
    /// SHA-256 of the exact committed WriteReceipt bytes.
    pub source_admission_write_receipt_sha256: String,
    /// Exact BlobReady receipt for the immutable source.
    pub ready_receipt_json: String,
    /// SHA-256 of the exact BlobReady receipt bytes.
    pub ready_receipt_sha256: String,
    /// Blob source-owner generation that served this readback.
    pub source_owner_generation: u64,
    /// Exact current state fence observed for this read.
    pub observed_fence: StateFence,
    /// Owner-issued immutable source readback receipt identity.
    pub readback_receipt_id: String,
    /// Store observation time for this exact readback.
    pub observed_at_unix_ms: u64,
}

impl VerificationStageSourceOwnerProof {
    /// Validates all canonical owner projections and exact receipt bindings.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        self.source_key.validate()?;
        validate_digest("stage_grant_sha256", &self.stage_grant_sha256)?;
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        for (field, json, digest) in [
            (
                "owner_facts",
                self.owner_facts_json.as_str(),
                self.owner_facts_sha256.as_str(),
            ),
            (
                "scope_binding",
                self.scope_binding_json.as_str(),
                self.scope_binding_sha256.as_str(),
            ),
            (
                "policy_binding",
                self.policy_binding_json.as_str(),
                self.policy_binding_sha256.as_str(),
            ),
            (
                "source_admission",
                self.source_admission_json.as_str(),
                self.source_admission_sha256.as_str(),
            ),
            (
                "source_admission_write_receipt",
                self.source_admission_write_receipt_json.as_str(),
                self.source_admission_write_receipt_sha256.as_str(),
            ),
            (
                "ready_receipt",
                self.ready_receipt_json.as_str(),
                self.ready_receipt_sha256.as_str(),
            ),
        ] {
            validate_canonical_json_digest(field, json, digest, 128 * 1024)?;
        }
        self.observed_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("observed_fence"))?;
        validate_text("readback_receipt_id", &self.readback_receipt_id)?;
        if self.readback_receipt_id.len() > 256
            || self.source_owner_generation == 0
            || self.observed_at_unix_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("source_owner_proof"));
        }
        Ok(())
    }

    /// Canonical SHA-256 commitment over this complete owner proof.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        self.validate()?;
        canonical_sha256(self)
    }
}

/// Closed selector for one Store-owned profile-stage source session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceKey {
    /// Kernel execution identity to which this source belongs.
    pub execution_ref: String,
    /// The single process stream represented by this source.
    pub stream: ProcessStreamKind,
    /// Stable Blob staging-session identity.
    pub session_id: String,
    /// Stable immutable source identity.
    pub source_id: String,
    /// Stable source terminal identity.
    pub terminal_id: String,
    /// Commitment to the original Store-owner Open request.
    pub open_request_sha256: String,
}

impl VerificationStageSourceKey {
    /// Validates the immutable source selector independent of authority.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        for (field, value) in [
            ("execution_ref", self.execution_ref.as_str()),
            ("session_id", self.session_id.as_str()),
            ("source_id", self.source_id.as_str()),
            ("terminal_id", self.terminal_id.as_str()),
        ] {
            validate_text(field, value)?;
            if value.len() > 256 {
                return Err(VerificationStageWireError::InvalidField(field));
            }
        }
        validate_digest("open_request_sha256", &self.open_request_sha256)
    }

    /// Validates the closed source-session key and its original grant match.
    pub fn validate_for_grant(
        &self,
        grant: &VerificationStageGrantProjection,
        grant_sha256: &str,
    ) -> Result<(), VerificationStageWireError> {
        grant.validate()?;
        validate_digest("stage_grant_sha256", grant_sha256)?;
        self.validate()?;
        if self.execution_ref != grant.execution_ref || grant.digest()? != grant_sha256 {
            return Err(VerificationStageWireError::InvalidField("source_grant"));
        }
        Ok(())
    }
}

/// Store-owned proof that the original ProfileStage source-admission CAS was
/// committed under current independently read scope and policy authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceAdmissionProof {
    /// Exact source session selector retained in the canonical owner row.
    pub source_key: VerificationStageSourceKey,
    /// Canonical commitment to the original Kernel stage grant.
    pub stage_grant_sha256: String,
    /// Fresh owner-facts projection independently read by Store.
    pub owner_facts_json: String,
    /// SHA-256 of exact owner-facts bytes.
    pub owner_facts_sha256: String,
    /// Fresh canonical WorkScope projection independently read by Store.
    pub scope_binding_json: String,
    /// SHA-256 of exact WorkScope bytes.
    pub scope_binding_sha256: String,
    /// Fresh canonical Policy projection independently read by Store.
    pub policy_binding_json: String,
    /// SHA-256 of exact Policy bytes.
    pub policy_binding_sha256: String,
    /// Committed canonical Pending/Ready source-admission row.
    pub source_admission_json: String,
    /// SHA-256 of exact admission row bytes.
    pub source_admission_sha256: String,
    /// Original committed Store WriteReceipt for admission CAS.
    pub write_receipt_json: String,
    /// SHA-256 of exact WriteReceipt bytes.
    pub write_receipt_sha256: String,
    /// Exact state fence observed and committed by Store.
    pub state_fence: StateFence,
    /// Generation of the one retained Blob owner serving the source.
    pub source_owner_generation: u64,
    /// Store's observation time for this exact admission result.
    pub observed_at_unix_ms: u64,
}

impl VerificationStageSourceAdmissionProof {
    /// Validates owner-issued canonical projections and source correlation.
    pub fn validate_for_grant(
        &self,
        grant: &VerificationStageGrantProjection,
        grant_sha256: &str,
    ) -> Result<(), VerificationStageWireError> {
        self.source_key.validate_for_grant(grant, grant_sha256)?;
        if self.stage_grant_sha256 != grant_sha256
            || self.scope_binding_json != grant.scope_binding_json
            || self.scope_binding_sha256 != grant.scope_binding_sha256
            || self.policy_binding_json != grant.policy_binding_json
            || self.policy_binding_sha256 != grant.policy_binding_sha256
            || self.state_fence != grant.state_fence
            || self.source_owner_generation == 0
            || self.observed_at_unix_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("source_admission_binding"));
        }
        for (field, json, digest) in [
            (
                "owner_facts",
                self.owner_facts_json.as_str(),
                self.owner_facts_sha256.as_str(),
            ),
            (
                "scope_binding",
                self.scope_binding_json.as_str(),
                self.scope_binding_sha256.as_str(),
            ),
            (
                "policy_binding",
                self.policy_binding_json.as_str(),
                self.policy_binding_sha256.as_str(),
            ),
            (
                "source_admission",
                self.source_admission_json.as_str(),
                self.source_admission_sha256.as_str(),
            ),
            (
                "source_admission_write_receipt",
                self.write_receipt_json.as_str(),
                self.write_receipt_sha256.as_str(),
            ),
        ] {
            validate_canonical_json_digest(field, json, digest, 128 * 1024)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        Ok(())
    }

    /// Canonical SHA-256 commitment to this exact source admission evidence.
    pub fn digest(&self) -> Result<String, VerificationStageWireError> {
        canonical_sha256(self)
    }
}

/// Exact ProfileStage-to-Store source-owner request carried on the existing
/// authenticated Blob process-stream EBP channel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceRequest {
    /// Closed ProfileStage source selector.
    pub wire_id: String,
    /// Closed ProfileStage source revision.
    pub wire_revision: u16,
    /// Immutable Kernel-issued stage grant retained in ORS.
    pub stage_grant: Box<VerificationStageGrantProjection>,
    /// Canonical commitment to the exact stage grant above.
    pub stage_grant_sha256: String,
    /// One exact source-owner operation.
    pub operation: VerificationStageSourceOperation,
}

/// Inert open projection for one ProfileStage source session.
///
/// Store-owned lease, receipt context, policy, residency, and Blob staging
/// limits are intentionally absent. The authenticated Store owner reconstructs
/// those values from its current independent scope and policy reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceOpenRequest {
    /// Exact canonical original Kernel ProcessExecutionBinding JSON.
    pub process_binding_json: String,
    /// SHA-256 of the exact canonical binding JSON bytes.
    pub process_binding_sha256: String,
}

impl VerificationStageSourceOpenRequest {
    /// Validates the exact process binding and computes the immutable Open
    /// commitment for its source key and retained stage grant.
    pub fn commitment_for(
        &self,
        source_key: &VerificationStageSourceKey,
        stage_grant_sha256: &str,
    ) -> Result<String, VerificationStageWireError> {
        validate_process_binding(&self.process_binding_json, &self.process_binding_sha256)?;
        validate_digest("stage_grant_sha256", stage_grant_sha256)?;
        canonical_sha256(&(
            stage_grant_sha256,
            &source_key.execution_ref,
            source_key.stream,
            &source_key.session_id,
            &source_key.source_id,
            &source_key.terminal_id,
            &self.process_binding_json,
            &self.process_binding_sha256,
        ))
    }

    /// Requires the key to commit to this exact request and original grant.
    pub fn validate_for(
        &self,
        source_key: &VerificationStageSourceKey,
        stage_grant_sha256: &str,
    ) -> Result<(), VerificationStageWireError> {
        source_key.validate()?;
        if self.commitment_for(source_key, stage_grant_sha256)?
            != source_key.open_request_sha256
        {
            return Err(VerificationStageWireError::InvalidField(
                "source_open_commitment",
            ));
        }
        Ok(())
    }
}

/// Closed typed operations against one original ProfileStage source session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageSourceOperation {
    /// Create the distinct ProfileStage source admission and Blob staging row.
    Open {
        /// Exact Kernel-selected stable source identity.
        source_key: VerificationStageSourceKey,
        /// Inert original process-binding projection. Store rebuilds all Blob
        /// owner authority and bounded staging fields itself.
        request: Box<VerificationStageSourceOpenRequest>,
    },
    /// Persist one ordered exact-byte append to an admitted source.
    Append {
        /// Exact source identity retained by Open.
        source_key: VerificationStageSourceKey,
        /// Typed immutable append request.
        request: Box<BlobProcessStreamStageAppendRequest>,
    },
    /// Commit the exact Kernel terminal and promote the finalized Blob source.
    Finalize {
        /// Exact source identity retained by Open.
        source_key: VerificationStageSourceKey,
        /// Typed terminal identity and admitted complete-stream commitment.
        request: Box<BlobProcessStreamStageFinalizeRequest>,
    },
    /// Resolve and read one bounded chunk from the exact completed source.
    Readback {
        /// Exact source identity retained by Open.
        source_key: VerificationStageSourceKey,
        /// Exact immutable locator and complete source identity from Kernel
        /// process evidence, plus the next contiguous chunk range.
        request: Box<VerificationStageReadbackRequest>,
    },
}

impl VerificationStageSourceRequest {
    /// Validates the selector, retained grant and operation-specific payload.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_SOURCE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.stage_grant.validate()?;
        validate_digest("stage_grant_sha256", &self.stage_grant_sha256)?;
        if self.stage_grant.digest()? != self.stage_grant_sha256 {
            return Err(VerificationStageWireError::InvalidField("stage_grant_sha256"));
        }
        match &self.operation {
            VerificationStageSourceOperation::Open { source_key, request } => {
                source_key.validate_for_grant(&self.stage_grant, &self.stage_grant_sha256)?;
                request.validate_for(source_key, &self.stage_grant_sha256)?;
                if request.process_binding_sha256 != self.stage_grant.process_binding_sha256 {
                    return Err(VerificationStageWireError::InvalidField("source_open_binding"));
                }
            }
            VerificationStageSourceOperation::Append { source_key, request } => {
                source_key.validate_for_grant(&self.stage_grant, &self.stage_grant_sha256)?;
                request
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_append"))?;
                if request.session_id != source_key.session_id
                    || request.source_id != source_key.source_id
                    || request.terminal_id != source_key.terminal_id
                    || request.open_request_sha256 != source_key.open_request_sha256
                {
                    return Err(VerificationStageWireError::InvalidField("source_append_binding"));
                }
            }
            VerificationStageSourceOperation::Finalize { source_key, request } => {
                source_key.validate_for_grant(&self.stage_grant, &self.stage_grant_sha256)?;
                request
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_finalize"))?;
                validate_digest("admitted_sha256", &request.admitted_sha256)?;
                validate_digest("terminal_command_sha256", &request.terminal_command_sha256)?;
                if request.session.session_id != source_key.session_id
                    || request.session.source_id != source_key.source_id
                    || request.session.terminal_id != source_key.terminal_id
                    || request.session.open_request_sha256 != source_key.open_request_sha256
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "source_finalize_binding",
                    ));
                }
            }
            VerificationStageSourceOperation::Readback { source_key, request } => {
                source_key.validate_for_grant(&self.stage_grant, &self.stage_grant_sha256)?;
                request.validate()?;
                if request.execution_ref != source_key.execution_ref
                    || request.stream != source_key.stream
                    || request.stage_grant_sha256 != self.stage_grant_sha256
                    || request.process_binding_sha256
                        != self.stage_grant.process_binding_sha256
                {
                    return Err(VerificationStageWireError::InvalidField("source_readback_binding"));
                }
            }
        }
        validate_frame(self)
    }
}

/// Typed Store result for one ProfileStage source-owner operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageSourceOutcome {
    /// Open was durably admitted and the exact staging session is present.
    Opened {
        /// Store-retained pending admission proof and committed write receipt.
        admission: Box<VerificationStageSourceAdmissionProof>,
        /// Exact owner-reconstructed durable staging state.
        snapshot: Box<BlobProcessStreamStageSnapshot>,
    },
    /// Append receipt committed by the one retained Blob owner.
    Appended {
        /// Exact owner disposition for this request sequence and byte range.
        receipt: BlobProcessStreamStageAppendReceipt,
    },
    /// Finalization and BlobReady promotion both committed by Store/Blob owner.
    Finalized {
        /// Exact owner terminal including its original BlobReady receipt.
        terminal: Box<BlobProcessStreamStageTerminal>,
        /// Exact Pending-to-Ready source admission proof and WriteReceipt.
        admission: Box<VerificationStageSourceAdmissionProof>,
    },
    /// One exact immutable source chunk and current owner proof.
    Readback {
        /// Bounded bytes, immutable source identity, and fresh owner evidence.
        chunk: Box<VerificationStageReadbackChunk>,
    },
    /// Store proves the exact original source operation never started.
    NotStarted,
    /// Store retains the source operation but cannot resolve it yet.
    Unknown,
    /// Store refused before this operation could have an effect.
    Unavailable {
        /// Closed non-sensitive refusal category.
        reason: VerificationStageUnavailableReason,
    },
}

/// Authenticated Store reply correlated to one exact ProfileStage source call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageSourceResponse {
    /// Closed ProfileStage source selector.
    pub wire_id: String,
    /// Closed ProfileStage source revision.
    pub wire_revision: u16,
    /// Exact Kernel-issued grant commitment submitted by the caller.
    pub stage_grant_sha256: String,
    /// Exact source key submitted by the caller.
    pub source_key: VerificationStageSourceKey,
    /// Typed source-owner disposition.
    pub outcome: VerificationStageSourceOutcome,
}

impl VerificationStageSourceResponse {
    /// Validates the closed response shape and bounded canonical evidence
    /// without relying on the corresponding request object.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_SOURCE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        validate_digest("stage_grant_sha256", &self.stage_grant_sha256)?;
        self.source_key.validate()?;
        match &self.outcome {
            VerificationStageSourceOutcome::Opened { admission, snapshot } => {
                snapshot
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_snapshot"))?;
                if admission.source_key != self.source_key
                    || admission.stage_grant_sha256 != self.stage_grant_sha256
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "source_open_admission",
                    ));
                }
                validate_digest(
                    "source_admission_sha256",
                    &admission.source_admission_sha256,
                )?;
            }
            VerificationStageSourceOutcome::Appended { receipt } => {
                if receipt.byte_length == 0
                    || receipt.next_sequence != receipt.sequence.saturating_add(1)
                    || receipt.next_offset
                        != receipt.offset.saturating_add(receipt.byte_length)
                {
                    return Err(VerificationStageWireError::InvalidField("append_receipt"));
                }
                validate_digest("chunk_sha256", &receipt.chunk_sha256)?;
                validate_digest(
                    "request_commitment_sha256",
                    &receipt.request_commitment_sha256,
                )?;
                validate_digest("session_key_sha256", &receipt.session_key_sha256)?;
            }
            VerificationStageSourceOutcome::Finalized { terminal, admission } => {
                terminal
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_terminal"))?;
                if admission.source_key != self.source_key
                    || admission.stage_grant_sha256 != self.stage_grant_sha256
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "source_finalize_admission",
                    ));
                }
                validate_digest(
                    "source_admission_sha256",
                    &admission.source_admission_sha256,
                )?;
            }
            VerificationStageSourceOutcome::Readback { chunk } => {
                if chunk.owner_proof.source_key != self.source_key
                    || chunk.owner_proof.stage_grant_sha256 != self.stage_grant_sha256
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "source_readback_identity",
                    ));
                }
                validate_digest("chunk_sha256", &chunk.chunk_sha256)?;
                validate_digest("owner_proof_sha256", &chunk.owner_proof_sha256)?;
                chunk.owner_proof.validate()?;
            }
            VerificationStageSourceOutcome::NotStarted
            | VerificationStageSourceOutcome::Unknown
            | VerificationStageSourceOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }

    /// Validates the exact original Store request and committed owner result.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageSourceRequest,
    ) -> Result<(), VerificationStageWireError> {
        self.validate()?;
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_SOURCE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.stage_grant_sha256 != request.stage_grant_sha256
        {
            return Err(VerificationStageWireError::InvalidField("source_response_binding"));
        }
        let expected_key = match &request.operation {
            VerificationStageSourceOperation::Open { source_key, .. }
            | VerificationStageSourceOperation::Append { source_key, .. }
            | VerificationStageSourceOperation::Finalize { source_key, .. }
            | VerificationStageSourceOperation::Readback { source_key, .. } => source_key,
        };
        if &self.source_key != expected_key {
            return Err(VerificationStageWireError::InvalidField("source_response_key"));
        }
        match (&request.operation, &self.outcome) {
            (
                VerificationStageSourceOperation::Open { request: open, .. },
                VerificationStageSourceOutcome::Opened { admission, snapshot },
            ) => {
                admission.validate_for_grant(&request.stage_grant, &request.stage_grant_sha256)?;
                snapshot
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_snapshot"))?;
                if snapshot.session.session_id != self.source_key.session_id
                    || snapshot.session.source_id != self.source_key.source_id
                    || snapshot.session.terminal_id != self.source_key.terminal_id
                    || snapshot.session.open_request_sha256 != self.source_key.open_request_sha256
                    || snapshot.session.process_source_binding.process_binding_sha256
                        != open.process_binding_sha256
                    || snapshot.session.process_source_binding.process_binding_json
                        != open.process_binding_json
                    || snapshot.session.process_source_binding.stream_kind
                        != process_stream_label(self.source_key.stream)
                {
                    return Err(VerificationStageWireError::InvalidField("source_snapshot_binding"));
                }
            }
            (
                VerificationStageSourceOperation::Append { request: append, .. },
                VerificationStageSourceOutcome::Appended { receipt },
            ) if receipt.sequence == append.sequence
                && receipt.offset == append.offset
                && receipt.byte_length == append.bytes.len() as u64
                && receipt.chunk_sha256 == append.chunk_sha256 => {}
            (
                VerificationStageSourceOperation::Finalize { request: finalize, .. },
                VerificationStageSourceOutcome::Finalized { terminal, admission },
            ) => {
                terminal
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("source_terminal"))?;
                admission.validate_for_grant(&request.stage_grant, &request.stage_grant_sha256)?;
                if terminal
                    .ready_receipt
                    .as_ref()
                    .map_or(true, |ready| {
                        ready.plaintext_sha256() != finalize.admitted_sha256
                            || ready.plaintext_length() != finalize.final_offset
                    })
                {
                    return Err(VerificationStageWireError::InvalidField("source_ready_receipt"));
                }
            }
            (
                VerificationStageSourceOperation::Readback { request: readback, .. },
                VerificationStageSourceOutcome::Readback { chunk },
            ) => {
                chunk.validate_for_request(readback)?;
                if chunk.owner_proof.stage_grant_sha256 != self.stage_grant_sha256
                    || chunk.owner_proof.source_key != self.source_key
                    || chunk.owner_proof.scope_binding_json
                        != request.stage_grant.scope_binding_json
                    || chunk.owner_proof.scope_binding_sha256
                        != request.stage_grant.scope_binding_sha256
                    || chunk.owner_proof.policy_binding_json
                        != request.stage_grant.policy_binding_json
                    || chunk.owner_proof.policy_binding_sha256
                        != request.stage_grant.policy_binding_sha256
                    || chunk.owner_proof.observed_fence != request.stage_grant.state_fence
                {
                    return Err(VerificationStageWireError::InvalidField(
                        "source_readback_owner_binding",
                    ));
                }
            }
            (_, VerificationStageSourceOutcome::NotStarted)
            | (_, VerificationStageSourceOutcome::Unknown)
            | (_, VerificationStageSourceOutcome::Unavailable { .. }) => {}
            _ => return Err(VerificationStageWireError::InvalidField("source_result_operation")),
        }
        validate_frame(self)
    }
}

/// One bounded request to read the exact source retained for a stage stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageReadbackRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Kernel-issued opaque execution reference.
    pub execution_ref: String,
    /// Canonical commitment to the exact Kernel-issued stage grant.
    pub stage_grant_sha256: String,
    /// Exact process binding digest returned by launch.
    pub process_binding_sha256: String,
    /// Stdout or stderr selected from Kernel-retained process evidence.
    pub stream: ProcessStreamKind,
    /// Immutable locator kind from the exact Kernel-retained ProcessEvidence.
    pub locator_kind: DurableStreamLocatorKind,
    /// Immutable locator value from the exact Kernel-retained ProcessEvidence.
    pub locator: String,
    /// Ready receipt reference from the exact Kernel-retained ProcessEvidence.
    pub ready_receipt_ref: String,
    /// Whole-source SHA-256 from the exact Kernel-retained ProcessEvidence.
    pub expected_source_sha256: String,
    /// Whole-source length from the exact Kernel-retained ProcessEvidence.
    pub expected_source_byte_length: u64,
    /// Next contiguous byte offset; zero selects the first chunk.
    pub offset: u64,
    /// Fixed maximum source chunk size.
    pub chunk_limit: u32,
    /// Unix-millisecond readback deadline.
    pub deadline_ms: u64,
}

impl VerificationStageReadbackRequest {
    /// Validates the bounded selector and immutable-source identity.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_READBACK_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        validate_text("execution_ref", &self.execution_ref)?;
        validate_text("locator", &self.locator)?;
        validate_text("ready_receipt_ref", &self.ready_receipt_ref)?;
        if self.execution_ref.len() > 256
            || self.locator.len() > 4_096
            || self.ready_receipt_ref.len() > 256
            || self.expected_source_byte_length > 512 * 1024 * 1024
            || self.offset > self.expected_source_byte_length
            || self.chunk_limit != PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES
            || self.deadline_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("readback_request"));
        }
        validate_digest("process_binding_sha256", &self.process_binding_sha256)?;
        validate_digest("stage_grant_sha256", &self.stage_grant_sha256)?;
        validate_digest("expected_source_sha256", &self.expected_source_sha256)?;
        validate_frame(self)
    }
}

/// Exact immutable source bytes and owner proof for one readback chunk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageReadbackChunk {
    /// Exact chunk bytes; callers must not persist these bytes in run receipts.
    pub bytes: Vec<u8>,
    /// Original whole-source SHA-256 commitment.
    pub whole_source_sha256: String,
    /// Original whole-source length.
    pub whole_source_byte_length: u64,
    /// Offset of this contiguous chunk.
    pub chunk_offset: u64,
    /// SHA-256 over these exact returned bytes.
    pub chunk_sha256: String,
    /// Exact returned chunk length.
    pub chunk_byte_length: u64,
    /// Original immutable locator kind.
    pub locator_kind: DurableStreamLocatorKind,
    /// Original immutable locator value.
    pub locator: String,
    /// Original BlobReady reference.
    pub ready_receipt_ref: String,
    /// Complete current Store source-owner proof.
    pub owner_proof: Box<VerificationStageSourceOwnerProof>,
    /// Canonical commitment over the complete owner proof.
    pub owner_proof_sha256: String,
}

impl VerificationStageReadbackChunk {
    /// Validates source, chunk, and owner proof integrity against the request.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageReadbackRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.whole_source_sha256 != request.expected_source_sha256
            || self.whole_source_byte_length != request.expected_source_byte_length
            || self.chunk_offset != request.offset
            || self.locator_kind != request.locator_kind
            || self.locator != request.locator
            || self.ready_receipt_ref != request.ready_receipt_ref
            || self.chunk_byte_length != self.bytes.len() as u64
            || self.chunk_byte_length > u64::from(request.chunk_limit)
            || self.chunk_offset.saturating_add(self.chunk_byte_length)
                > self.whole_source_byte_length
            || sha256_hex(&self.bytes) != self.chunk_sha256
        {
            return Err(VerificationStageWireError::InvalidField("readback_chunk"));
        }
        validate_digest("whole_source_sha256", &self.whole_source_sha256)?;
        validate_digest("chunk_sha256", &self.chunk_sha256)?;
        self.owner_proof.validate()?;
        if self.owner_proof.digest()? != self.owner_proof_sha256
            || self.owner_proof.stage_grant_sha256 != request.stage_grant_sha256
            || self.owner_proof.source_key.execution_ref != request.execution_ref
            || self.owner_proof.source_key.stream != request.stream
            || self.owner_proof.process_binding_sha256 != request.process_binding_sha256
            || self.owner_proof.ready_receipt_sha256.len() != 64
        {
            return Err(VerificationStageWireError::InvalidField("owner_proof_sha256"));
        }
        validate_digest("owner_proof_sha256", &self.owner_proof_sha256)?;
        validate_frame(self)
    }
}

/// Typed readback outcome; Unknown never means an empty source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageReadbackOutcome {
    /// One exact verified source chunk and current owner proof.
    Ready {
        /// Immutable source bytes and owner proof.
        chunk: Box<VerificationStageReadbackChunk>,
    },
    /// Original source operation was durably not started.
    NotStarted,
    /// Exact source result remains unknown or unresolved.
    Unknown,
    /// Kernel refused the owner read before Store effects.
    Unavailable {
        /// Stable refusal category only.
        reason: VerificationStageUnavailableReason,
    },
}

/// Authenticated Kernel reply to one exact stage source readback chunk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageReadbackResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact execution reference submitted by the resolver.
    pub execution_ref: String,
    /// Exact process binding digest submitted by the resolver.
    pub process_binding_sha256: String,
    /// Exact retained Kernel stage-grant commitment for the process.
    pub stage_grant_sha256: String,
    /// Exact stream and source identity submitted by the resolver.
    pub stream: ProcessStreamKind,
    /// Kernel observation time for this readback decision.
    pub observed_at_unix_ms: u64,
    /// Typed immutable source result.
    pub outcome: VerificationStageReadbackOutcome,
}

impl VerificationStageReadbackResponse {
    /// Validates exact source correlation and every returned chunk commitment.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageReadbackRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_READBACK_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.execution_ref != request.execution_ref
            || self.process_binding_sha256 != request.process_binding_sha256
            || self.stage_grant_sha256 != request.stage_grant_sha256
            || self.stream != request.stream
            || self.observed_at_unix_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("readback_response_binding"));
        }
        if let VerificationStageReadbackOutcome::Ready { chunk } = &self.outcome {
            chunk.validate_for_request(request)?;
        }
        validate_frame(self)
    }

    /// Validates each owner proof against the immutable retained Kernel grant.
    pub fn validate_for_grant(
        &self,
        request: &VerificationStageReadbackRequest,
        grant: &VerificationStageGrantProjection,
    ) -> Result<(), VerificationStageWireError> {
        self.validate_for_request(request)?;
        grant.validate()?;
        let grant_sha256 = grant.digest()?;
        if grant_sha256 != request.stage_grant_sha256
            || grant.execution_ref != request.execution_ref
            || grant.process_binding_sha256 != request.process_binding_sha256
        {
            return Err(VerificationStageWireError::InvalidField("readback_grant_binding"));
        }
        if let VerificationStageReadbackOutcome::Ready { chunk } = &self.outcome {
            let owner = &chunk.owner_proof;
            if owner.stage_grant_sha256 != grant_sha256
                || owner.scope_binding_json != grant.scope_binding_json
                || owner.scope_binding_sha256 != grant.scope_binding_sha256
                || owner.policy_binding_json != grant.policy_binding_json
                || owner.policy_binding_sha256 != grant.policy_binding_sha256
                || owner.observed_fence != grant.state_fence
            {
                return Err(VerificationStageWireError::InvalidField(
                    "readback_owner_proof_grant_binding",
                ));
            }
        }
        Ok(())
    }
}

/// Shared synchronous authenticated ProfileResolver transport seam.
///
/// `eliot-cli::KernelClient` implements this trait. The runner depends only on
/// this provider-neutral contract, avoiding a runner/CLI dependency cycle.
pub trait VerificationStageExecutionPort: Send + Sync {
    /// Runs the exact Kernel-owned `--version` preflight.
    fn probe_tool_version(
        &self,
        request: &VerificationStageToolProbeRequest,
    ) -> Result<VerificationStageToolProbeResponse, VerificationStagePortError>;

    /// Starts one exact admitted Kernel-owned profile stage.
    fn launch_stage(
        &self,
        request: &VerificationStageLaunchRequest,
    ) -> Result<VerificationStageLaunchResponse, VerificationStagePortError>;

    /// Inspects, cancels, or reconciles one retained stage process.
    fn lifecycle(
        &self,
        request: &VerificationStageLifecycleRequest,
    ) -> Result<VerificationStageLifecycleResponse, VerificationStagePortError>;

    /// Reads one contiguous chunk from the exact Kernel-retained process source.
    fn readback_source(
        &self,
        request: &VerificationStageReadbackRequest,
    ) -> Result<VerificationStageReadbackResponse, VerificationStagePortError>;
}

/// Transport/protocol errors for the shared ProfileResolver port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationStagePortError {
    /// Authenticated Kernel transport is unavailable.
    #[error("authenticated ProfileResolver Kernel transport is unavailable")]
    Unavailable,
    /// The request may have reached Kernel but no exact owner result arrived.
    #[error("ProfileResolver Kernel operation outcome remains unknown")]
    UnknownOutcome,
    /// Kernel response failed the closed wire validation.
    #[error("ProfileResolver Kernel response failed validation")]
    InvalidResponse,
}

impl VerificationStageLifecycleResponse {
    /// Validates exact correlation and canonical evidence values.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageLifecycleRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_LIFECYCLE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.execution_ref != request.execution_ref
            || self.process_binding_sha256 != request.process_binding_sha256
            || self.observed_at_unix_ms == 0
        {
            return Err(VerificationStageWireError::InvalidField("lifecycle_response_binding"));
        }
        match &self.outcome {
            VerificationStageLifecycleOutcome::Inspected {
                process_view_json,
                process_view_sha256,
            } => validate_canonical_json_digest(
                "process_view",
                process_view_json,
                process_view_sha256,
                2 * 1024 * 1024,
            )?,
            VerificationStageLifecycleOutcome::Cancelled {
                cancellation_receipt_json,
                cancellation_receipt_sha256,
            } => validate_canonical_json_digest(
                "cancellation_receipt",
                cancellation_receipt_json,
                cancellation_receipt_sha256,
                2 * 1024 * 1024,
            )?,
            VerificationStageLifecycleOutcome::Reconciled {
                process_evidence_json,
                process_evidence_sha256,
            } => validate_canonical_json_digest(
                "process_evidence",
                process_evidence_json,
                process_evidence_sha256,
                2 * 1024 * 1024,
            )?,
            VerificationStageLifecycleOutcome::Unknown
            | VerificationStageLifecycleOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }
}

/// Runner request to open one profile-stage capability.
///
/// `process_binding_json` is the canonical serialization of the real
/// `ProcessExecutionBinding` emitted by the sealed launch request. It is
/// decoded and checked by Kernel against the authenticated stage admission;
/// it is not authority by itself. The request contains no caller-selected
/// fence, epoch, WorkScope, Policy, owner facts or source-admission receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageOpenRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact profile-stage/tool/source-root admission identity.
    pub binding: VerificationStageBinding,
    /// Canonical exact process binding emitted by the sealed launch request.
    pub process_binding_json: String,
    /// SHA-256 of the exact process-binding JSON bytes.
    pub process_binding_sha256: String,
    /// Request deadline in Unix milliseconds.
    pub deadline_ms: u64,
}

impl VerificationStageOpenRequest {
    /// Validates the closed selector and exact stage/process bindings.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_OPEN_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.binding.validate()?;
        validate_process_binding(
            &self.process_binding_json,
            &self.process_binding_sha256,
        )?;
        if self.deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("deadline_ms"));
        }
        validate_frame(self)
    }
}

/// Exact result of the authenticated Kernel stage-capability admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageOpenResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact profile-stage identity submitted by the caller.
    pub binding: VerificationStageBinding,
    /// Exact process-binding digest submitted by the caller.
    pub process_binding_sha256: String,
    /// Kernel's current authenticated fence observed for this decision.
    pub state_fence: StateFence,
    /// Typed capability result.
    pub outcome: VerificationStageOpenOutcome,
}

impl VerificationStageOpenResponse {
    /// Validates the exact request echo and the granted capability.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageOpenRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_OPEN_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.binding != request.binding
            || self.process_binding_sha256 != request.process_binding_sha256
        {
            return Err(VerificationStageWireError::InvalidField("open_response_binding"));
        }
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        if let VerificationStageOpenOutcome::Granted { grant } = &self.outcome {
            grant.validate_for_request(request)?;
            if grant.state_fence != self.state_fence {
                return Err(VerificationStageWireError::InvalidField("grant_state_fence"));
            }
        }
        validate_frame(self)
    }
}

/// Closed capability result; an unavailable grant has no token or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageOpenOutcome {
    /// Kernel retained a separate checked profile-stage capability.
    Granted {
        /// Exact profile-stage grant and first one-use token.
        grant: Box<VerificationStageGrant>,
    },
    /// Kernel refused admission before any Store effect.
    Unavailable {
        /// Closed non-sensitive refusal category.
        reason: VerificationStageUnavailableReason,
    },
}

/// Opaque Kernel-retained profile-stage capability reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCapabilityRef {
    /// Bounded opaque lookup identity.
    pub reference: String,
}

impl VerificationStageCapabilityRef {
    /// Validates a bounded capability lookup reference.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("capability_ref", &self.reference)?;
        if self.reference.len() > 128 {
            return Err(VerificationStageWireError::InvalidField("capability_ref"));
        }
        Ok(())
    }
}

/// One-use Kernel-issued operation token retained before any Store exchange.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallToken {
    /// Opaque Kernel-retained token reference.
    pub reference: String,
    /// Exact one-based operation ordinal.
    pub ordinal: u32,
}

impl VerificationStageCallToken {
    /// Validates the bounded one-use token.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        validate_text("call_token", &self.reference)?;
        if self.reference.len() > 128 || self.ordinal == 0 {
            return Err(VerificationStageWireError::InvalidField("call_token"));
        }
        Ok(())
    }
}

/// Kernel-issued grant for one exact admitted profile stage.
///
/// `state_fence` is selected by Kernel from the authenticated current session.
/// Its Authority Epoch is part of the fence and is independently checked on
/// every later call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageGrant {
    /// Exact granted profile-stage binding.
    pub binding: VerificationStageBinding,
    /// Opaque Kernel-retained call capability.
    pub capability: VerificationStageCapabilityRef,
    /// First one-use call token.
    pub first_call_token: VerificationStageCallToken,
    /// Exact launched process binding digest.
    pub process_binding_sha256: String,
    /// Current authenticated Kernel fence selected at grant time.
    pub state_fence: StateFence,
    /// Grant expiration in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl VerificationStageGrant {
    /// Validates a grant against the request it answers.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageOpenRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        self.binding.validate()?;
        if self.binding != request.binding
            || self.process_binding_sha256 != request.process_binding_sha256
            || self.expires_at_unix_ms < request.deadline_ms
        {
            return Err(VerificationStageWireError::InvalidField("grant_binding"));
        }
        self.capability.validate()?;
        self.first_call_token.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        validate_frame(self)
    }
}

/// Exact operation passed after a profile-stage grant. It deliberately omits
/// Store request identities, State Fences, owner facts and source-admission
/// proofs; Kernel creates those from retained authority and fresh owner reads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageOperationRequest {
    /// Open one stdout/stderr stream under the retained process binding.
    SinkOpen {
        /// Exact closed `ProcessStreamSinkOpenRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Append a bounded byte chunk to one Store-retained stream.
    SinkAppend {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkAppend` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Finalize one Store-retained stream under its original terminal identity.
    SinkFinalize {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkFinalizeRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Abort one Store-retained stream under its original terminal identity.
    SinkAbort {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact closed `ProcessStreamSinkAbortRequest` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read the retained sink state without replaying an effect.
    SinkReadback {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Reconcile an uncertain original sink command without repeating it.
    SinkReconcile {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Exact original `ProcessStreamSinkUnknownOutcome` JSON object.
        body: Box<serde_json::Value>,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
    /// Read one bounded chunk from the exact finalized immutable source.
    SourceReadback {
        /// Store-issued reference to the exact original Open session.
        binding: ProcessStreamSinkBindingRef,
        /// Stdout or stderr selected by the exact sink session.
        stream: ProcessStreamKind,
        /// Immutable source locator class from the finalized terminal.
        locator_kind: DurableStreamLocatorKind,
        /// Immutable source locator from the finalized terminal.
        locator: String,
        /// Owner-issued ready receipt reference from the finalized terminal.
        ready_receipt_ref: String,
        /// Whole-source SHA-256 from the finalized terminal.
        expected_sha256: String,
        /// Whole-source byte length from the finalized terminal.
        expected_byte_length: u64,
        /// Exact byte offset requested from the source.
        offset: u64,
        /// Caller size ceiling; never widens the fixed wire chunk bound.
        max_bytes: u64,
        /// Exact fixed chunk limit required by the Store readback contract.
        chunk_limit: u32,
        /// Absolute operation deadline.
        deadline_ms: u64,
    },
}

impl VerificationStageOperationRequest {
    /// Validates operation-specific identities and fixed bounds.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        let (binding, body, deadline_ms) = match self {
            Self::SinkOpen { body, deadline_ms } => (None, Some(body), *deadline_ms),
            Self::SinkAppend {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkFinalize {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkAbort {
                binding,
                body,
                deadline_ms,
            }
            | Self::SinkReconcile {
                binding,
                body,
                deadline_ms,
            } => (Some(binding), Some(body), *deadline_ms),
            Self::SinkReadback {
                binding,
                deadline_ms,
            } => (Some(binding), None, *deadline_ms),
            Self::SourceReadback {
                binding,
                locator,
                ready_receipt_ref,
                expected_sha256,
                expected_byte_length,
                offset,
                max_bytes,
                chunk_limit,
                deadline_ms,
                ..
            } => {
                binding
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("binding"))?;
                validate_text("locator", locator)?;
                validate_text("ready_receipt_ref", ready_receipt_ref)?;
                validate_digest("expected_sha256", expected_sha256)?;
                if *offset > *expected_byte_length
                    || *max_bytes < *expected_byte_length
                    || *chunk_limit != PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES
                {
                    return Err(VerificationStageWireError::InvalidField("source_range"));
                }
                (Some(binding), None, *deadline_ms)
            }
        };
        if let Some(binding) = binding {
            binding
                .validate()
                .map_err(|_| VerificationStageWireError::InvalidField("binding"))?;
        }
        if let Some(body) = body {
            let encoded = serde_json::to_vec(body)
                .map_err(|_| VerificationStageWireError::InvalidField("body"))?;
            if !body.is_object() || encoded.len() > PROCESS_STREAM_SINK_MAX_BODY_BYTES {
                return Err(VerificationStageWireError::InvalidField("body"));
            }
        }
        if deadline_ms == 0 {
            return Err(VerificationStageWireError::InvalidField("deadline_ms"));
        }
        Ok(())
    }
}

/// One-use operation sent over the authenticated existing Kernel front door.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Opaque retained stage capability.
    pub capability: VerificationStageCapabilityRef,
    /// Exact one-use Kernel token.
    pub call_token: VerificationStageCallToken,
    /// Digest of the exact operation envelope below.
    pub operation_sha256: String,
    /// One exact semantic operation without caller-selected Kernel authority.
    pub operation: VerificationStageOperationRequest,
}

impl VerificationStageCallRequest {
    /// Validates the selector, token, operation and canonical operation digest.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_CALL_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        self.operation.validate()?;
        let operation_json = canonical_json_bytes(&self.operation)
            .map_err(|_| VerificationStageWireError::InvalidField("operation"))?;
        if sha256_hex(&operation_json) != self.operation_sha256 {
            return Err(VerificationStageWireError::InvalidField("operation_sha256"));
        }
        validate_frame(self)
    }
}

/// Typed result returned after Kernel has retained the exact call outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageCallOutcome {
    /// Exact Store owner result was validated and retained by Kernel.
    Completed {
        /// Closed typed result for the matching operation family.
        result: VerificationStageStoreResult,
    },
    /// Kernel proves the exact original operation was never dispatched.
    NotStarted,
    /// Outcome is unresolved; caller must reconcile this exact token and digest.
    Unknown,
    /// Closed pre-effect refusal.
    Unavailable {
        /// Stable refusal category, with no provider prose.
        reason: VerificationStageUnavailableReason,
    },
}

/// Exact Store-side result family wrapped by the Kernel response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerificationStageStoreResult {
    /// Process-stream sink result.
    Sink {
        /// Closed Store owner response.
        response: ProcessStreamSinkWireResponse,
    },
    /// Immutable source readback result.
    SourceReadback {
        /// Closed Store owner response, including fresh owner readback proof.
        response: ProcessStreamSourceReadbackResponse,
    },
}

/// Kernel response bound to the exact admitted call and current fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageCallResponse {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Exact capability that admitted the operation.
    pub capability: VerificationStageCapabilityRef,
    /// Exact one-use token consumed by this response.
    pub call_token: VerificationStageCallToken,
    /// Exact original operation digest.
    pub operation_sha256: String,
    /// Kernel current fence observed for the response.
    pub state_fence: StateFence,
    /// Successor token when this outcome safely advanced the stream sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_call_token: Option<VerificationStageCallToken>,
    /// Retained typed result.
    pub outcome: VerificationStageCallOutcome,
}

impl VerificationStageCallResponse {
    /// Validates the response against the exact original request.
    pub fn validate_for_request(
        &self,
        request: &VerificationStageCallRequest,
    ) -> Result<(), VerificationStageWireError> {
        request.validate()?;
        if self.wire_id != VERIFICATION_STAGE_CALL_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
            || self.capability != request.capability
            || self.call_token != request.call_token
            || self.operation_sha256 != request.operation_sha256
        {
            return Err(VerificationStageWireError::InvalidField("response_binding"));
        }
        self.state_fence
            .validate()
            .map_err(|_| VerificationStageWireError::InvalidField("state_fence"))?;
        if let Some(token) = &self.successor_call_token {
            token.validate()?;
            if token.ordinal != request.call_token.ordinal.saturating_add(1) {
                return Err(VerificationStageWireError::InvalidField("successor_call_token"));
            }
        }
        match &self.outcome {
            VerificationStageCallOutcome::Completed { result } => {
                result.validate_for_operation(&request.operation)?;
                if self.successor_call_token.is_none() {
                    return Err(VerificationStageWireError::InvalidField("successor_call_token"));
                }
            }
            VerificationStageCallOutcome::NotStarted
            | VerificationStageCallOutcome::Unknown
            | VerificationStageCallOutcome::Unavailable { .. }
                if self.successor_call_token.is_some() =>
            {
                return Err(VerificationStageWireError::InvalidField("successor_call_token"));
            }
            VerificationStageCallOutcome::NotStarted
            | VerificationStageCallOutcome::Unknown
            | VerificationStageCallOutcome::Unavailable { .. } => {}
        }
        validate_frame(self)
    }
}

impl VerificationStageStoreResult {
    fn validate_for_operation(
        &self,
        operation: &VerificationStageOperationRequest,
    ) -> Result<(), VerificationStageWireError> {
        match (operation, self) {
            (VerificationStageOperationRequest::SourceReadback { .. }, Self::SourceReadback { response }) => response
                .validate()
                .map_err(|_| VerificationStageWireError::InvalidField("source_readback")),
            (VerificationStageOperationRequest::SourceReadback { .. }, Self::Sink { .. })
            | (VerificationStageOperationRequest::SinkOpen { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkAppend { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkFinalize { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkAbort { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkReadback { .. }, Self::SourceReadback { .. })
            | (VerificationStageOperationRequest::SinkReconcile { .. }, Self::SourceReadback { .. }) => {
                Err(VerificationStageWireError::InvalidField("result_operation"))
            }
            (VerificationStageOperationRequest::SinkOpen { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Opened { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkAppend { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::AppendDisposition { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkFinalize { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Finalized { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkAbort { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Aborted { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkReadback { .. }, Self::Sink { response })
                if matches!(response, ProcessStreamSinkWireResponse::Readback { .. }) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (VerificationStageOperationRequest::SinkReconcile { .. }, Self::Sink { response })
                if matches!(
                    response,
                    ProcessStreamSinkWireResponse::Opened { .. }
                        | ProcessStreamSinkWireResponse::AppendDisposition { .. }
                        | ProcessStreamSinkWireResponse::Finalized { .. }
                        | ProcessStreamSinkWireResponse::Aborted { .. }
                        | ProcessStreamSinkWireResponse::Readback { .. }
                ) => response
                    .validate()
                    .map_err(|_| VerificationStageWireError::InvalidField("sink_response")),
            (_, Self::Sink { .. }) => {
                Err(VerificationStageWireError::InvalidField("result_operation"))
            }
        }
    }
}

/// Read-only reconciliation query for a consumed call token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationStageReconcileRequest {
    /// Closed selector.
    pub wire_id: String,
    /// Closed selector revision.
    pub wire_revision: u16,
    /// Original retained capability.
    pub capability: VerificationStageCapabilityRef,
    /// Exact consumed one-use token.
    pub call_token: VerificationStageCallToken,
    /// Digest of the exact original operation.
    pub operation_sha256: String,
}

impl VerificationStageReconcileRequest {
    /// Validates a no-effect reconciliation request.
    pub fn validate(&self) -> Result<(), VerificationStageWireError> {
        if self.wire_id != VERIFICATION_STAGE_RECONCILE_WIRE_ID
            || self.wire_revision != VERIFICATION_STAGE_WIRE_REVISION
        {
            return Err(VerificationStageWireError::UnsupportedRevision);
        }
        self.capability.validate()?;
        self.call_token.validate()?;
        validate_digest("operation_sha256", &self.operation_sha256)?;
        validate_frame(self)
    }
}

/// Closed non-sensitive pre-effect refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStageUnavailableReason {
    AdmissionMissing,
    ProfileBindingMismatch,
    ProcessBindingMismatch,
    OwnerFactsUnavailable,
    StaleFence,
    StaleCapability,
    Capacity,
    StoreUnavailable,
    RequestRejected,
}

/// Typed validation failures for the closed profile-stage IPC.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationStageWireError {
    /// Selector revision or wire ID is not admitted.
    #[error("unsupported verification-stage IPC revision")]
    UnsupportedRevision,
    /// A closed field failed validation.
    #[error("invalid verification-stage IPC field: {0}")]
    InvalidField(&'static str),
}

fn validate_text(field: &'static str, value: &str) -> Result<(), VerificationStageWireError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), VerificationStageWireError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    Ok(())
}

fn validate_process_binding(
    json: &str,
    digest: &str,
) -> Result<(), VerificationStageWireError> {
    validate_canonical_json_digest("process_binding", json, digest, 16 * 1024)?;
    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| VerificationStageWireError::InvalidField("process_binding"))?;
    if !parsed.is_object() {
        return Err(VerificationStageWireError::InvalidField("process_binding"));
    }
    Ok(())
}

fn process_operation_id_from_binding(
    json: &str,
) -> Result<String, VerificationStageWireError> {
    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| VerificationStageWireError::InvalidField("process_binding"))?;
    let operation_id = parsed
        .get("operation_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerificationStageWireError::InvalidField("process_operation_id"))?;
    validate_text("process_operation_id", operation_id)?;
    Ok(operation_id.to_owned())
}

fn process_stream_label(stream: ProcessStreamKind) -> &'static str {
    match stream {
        ProcessStreamKind::Stdout => "STDOUT",
        ProcessStreamKind::Stderr => "STDERR",
    }
}

fn validate_canonical_json_digest(
    field: &'static str,
    json: &str,
    digest: &str,
    max_bytes: usize,
) -> Result<(), VerificationStageWireError> {
    validate_digest("json_sha256", digest)?;
    if json.is_empty() || json.len() > max_bytes {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| VerificationStageWireError::InvalidField(field))?;
    let canonical = canonical_json_bytes(&parsed)
        .map_err(|_| VerificationStageWireError::InvalidField(field))?;
    if canonical.as_slice() != json.as_bytes() || sha256_hex(json.as_bytes()) != digest {
        return Err(VerificationStageWireError::InvalidField(field));
    }
    Ok(())
}

fn canonical_sha256<T: Serialize + ?Sized>(value: &T) -> Result<String, VerificationStageWireError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|_| VerificationStageWireError::InvalidField("canonical_json"))?;
    Ok(sha256_hex(&bytes))
}

fn validate_frame<T: Serialize>(value: &T) -> Result<(), VerificationStageWireError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| VerificationStageWireError::InvalidField("frame"))?;
    if encoded.len() > VERIFICATION_STAGE_MAX_FRAME_BYTES {
        return Err(VerificationStageWireError::InvalidField("frame"));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> VerificationStageBinding {
        VerificationStageBinding {
            profile_id: "package-verification-compile-only".to_owned(),
            profile_revision: 1,
            profile_sha256: "a".repeat(64),
            dag_sha256: "b".repeat(64),
            stage_id: "package-compile".to_owned(),
            stage_sha256: "c".repeat(64),
            tool_sha256: "d".repeat(64),
            argv_sha256: "e".repeat(64),
            environment_sha256: "f".repeat(64),
            source_root_identity_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn verification_stage_open_accepts_exact_canonical_process_binding() {
        let process_binding = serde_json::json!({
            "operation_id": "stage-op-1",
            "process_tree_id": "stage-tree-1"
        });
        let process_binding_json = String::from_utf8(
            canonical_json_bytes(&process_binding).expect("canonical process binding"),
        )
        .expect("UTF-8 canonical process binding");
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: binding(),
            process_binding_sha256: sha256_hex(process_binding_json.as_bytes()),
            process_binding_json,
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(request.validate(), Ok(()));
    }

    #[test]
    fn verification_stage_open_refuses_a_process_binding_digest_mismatch() {
        let process_binding_json = "{\"operation_id\":\"stage-op-1\"}".to_owned();
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: binding(),
            process_binding_json,
            process_binding_sha256: "1".repeat(64),
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(
            request.validate(),
            Err(VerificationStageWireError::InvalidField("process_binding"))
        );
    }

    #[test]
    fn verification_stage_open_refuses_an_unbound_stage_digest() {
        let process_binding_json = "{\"operation_id\":\"stage-op-1\"}".to_owned();
        let mut stage = binding();
        stage.stage_sha256 = "not-a-digest".to_owned();
        let request = VerificationStageOpenRequest {
            wire_id: VERIFICATION_STAGE_OPEN_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            binding: stage,
            process_binding_sha256: sha256_hex(process_binding_json.as_bytes()),
            process_binding_json,
            deadline_ms: 1_800_000_000_000,
        };

        assert_eq!(
            request.validate(),
            Err(VerificationStageWireError::InvalidField("stage_sha256"))
        );
    }
}
